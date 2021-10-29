#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.

"""This sub-module contains the parser for nmap's XML output files.

"""


import datetime
import hashlib
import json
import os
import re
import struct
import sys
from textwrap import wrap
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from xml.sax.handler import ContentHandler, EntityResolver


from ivre.active.cpe import cpe2dict
from ivre.active.data import (
    ALIASES_TABLE_ELEMS,
    cleanup_synack_honeypot_host,
    create_ssl_output,
    handle_http_headers,
)
from ivre.analyzer import dicom, ike, ja3
from ivre.data.microsoft.windows import WINDOWS_VERSION_TO_BUILD
from ivre.types import ParsedCertificate, NmapServiceMatch
from ivre.types.active import NmapHostname, NmapScript
from ivre import utils


SCHEMA_VERSION = 19

# Scripts that mix elem/table tags with and without key attributes,
# which is not supported for now
IGNORE_TABLE_ELEMS = set(["xmpp-info", "sslv2", "sslv2-drown"])

SCREENSHOT_PATTERN = re.compile("^ *Saved to (.*)$", re.MULTILINE)
RTSP_SCREENSHOT_PATTERN = re.compile("^ *Saved [^ ]* to (.*)$", re.MULTILINE)


def screenshot_extract(script):
    fname = (
        RTSP_SCREENSHOT_PATTERN
        if script["id"] == "rtsp-screenshot"
        else SCREENSHOT_PATTERN
    ).search(script["output"])
    return None if fname is None else fname.groups()[0]


SCREENSHOTS_SCRIPTS = {
    "http-screenshot": screenshot_extract,
    "mainframe-screenshot": screenshot_extract,
    "rtsp-screenshot": screenshot_extract,
    "vnc-screenshot": screenshot_extract,
    "x11-screenshot": screenshot_extract,
}

_MONGODB_DATABASES_CONVERTS = {"false": False, "true": True, "nil": None}

_MONGODB_DATABASES_TYPES = {
    "totalSize": float,
    "totalSizeMb": float,
    "empty": lambda x: _MONGODB_DATABASES_CONVERTS.get(x, x),
    "sizeOnDisk": float,
    "code": lambda x: (
        _MONGODB_DATABASES_CONVERTS.get(x, x) if isinstance(x, str) else float(x)
    ),
    "ok": lambda x: (
        _MONGODB_DATABASES_CONVERTS.get(x, x) if isinstance(x, str) else float(x)
    ),
}


def _parse_mongodb_databases_kv(
    line, out, prefix=None, force_type=None, value_name=None
):
    """Parse 'key = value' lines from mongodb-databases output"""
    try:
        # Line can be 'key =' or 'key = value'
        key, value = line.split(" =", 1)
        value = value[1:]
    except ValueError:
        utils.LOGGER.warning("Unknown keyword %r", line)
        return

    if key == "$err":
        key = "errmsg"
    if prefix is not None:
        key = "%s_%s" % (prefix, key)

    if force_type is not None:
        value = force_type(value)
    else:
        value = _MONGODB_DATABASES_TYPES.get(key, lambda x: x)(value)

    if isinstance(out, dict):
        assert key not in out
        out[key] = value
    elif isinstance(out, list):
        out.append({"name": key, value_name: value})


def add_mongodb_databases_data(script):
    """This function converts output from mongodb-databases to a structured one.
    For instance, the output:

    totalSizeMb = 123456
    totalSize = 123456123
    databases
      1
        name = test
        empty = false
        sizeOnDisk = 112233
      0
        sizeOnDisk = 445566
        name = test_prod
        empty = false
        shards
          my_shard_0001 = 778899
          my_shard_0000 = 778877
    ok = 1

    is converted to:

    {'databases': [{'empty': False, 'name': 'test', 'sizeOnDisk': 112233},
                   {'empty': False,
                    'name': 'test_prod',
                    'shards': [{'name': 'my_shard_0000',
                                'size': 778877},
                               {'name': 'my_shard_0001',
                                'size': 778899}],
                    'sizeOnDisk': 445566}],
     'ok': '1',
     'totalSize': 123456123,
     'totalSizeMb': 123456}
    """

    out = {}
    # Global modes, see MODES[1]
    cur_key = None
    MODES = {
        1: {"databases": list, "bad cmd": dict},
        3: {"shards": list},
    }

    for line in script["output"].split("\n"):
        # Handle mode based on indentation
        line = line.rstrip()
        if not line:
            continue
        length = len(line)
        line = line.lstrip()
        indent = (length - len(line)) // 2

        # Parse structure
        if indent == 1:
            # Global
            if line in MODES[indent]:
                out[line] = MODES[indent][line]()
                cur_key = line
                continue
            cur_dict = out

        elif indent == 2:
            if isinstance(out[cur_key], list):
                # Databases enumeration, looks like:
                #
                # 0
                #   name = XXX
                # 1
                #   name = XXX
                #   size = 123
                # code = 0

                if line.isdigit():
                    out[cur_key].append({})
                else:
                    _parse_mongodb_databases_kv(line, out, prefix=cur_key)
                continue

            if isinstance(out[cur_key], dict):
                # Bad command, looks like:
                #
                # bad cmd
                #   listDatabases = 1

                cur_dict = out[cur_key]

        elif indent == 3:
            # Database information
            if line in MODES[indent]:
                out["databases"][-1][line] = MODES[indent][line]()
                continue
            cur_dict = out["databases"][-1]

        elif indent == 4:
            # Shards information, values are always float
            _parse_mongodb_databases_kv(
                line,
                out["databases"][-1]["shards"],
                force_type=float,
                value_name="size",
            )
            continue

        else:
            raise ValueError("Unable to parse %s" % line)

        # Handle a "key = value" line
        _parse_mongodb_databases_kv(line, cur_dict)

    return out


def add_ls_data(script):
    """This function calls the appropriate `add_*_data()` function to
    convert output from scripts that do not include a structured
    output to a structured output similar to the one provided by the
    "ls" NSE module.

    See https://nmap.org/nsedoc/lib/ls.html

    """

    def notimplemented(script):
        utils.LOGGER.warning("Migration not implemented for script %r", script["id"])
        raise NotImplementedError

    return {
        "smb-ls": add_smb_ls_data,
        "nfs-ls": add_nfs_ls_data,
        "afp-ls": add_afp_ls_data,
        "ftp-anon": add_ftp_anon_data,
        # http-ls has used the "ls" module since the beginning
    }.get(script["id"], notimplemented)(script)


def add_smb_ls_data(script):
    """This function converts output from smb-ls that do not include a
    structured output to a structured output similar to the one
    provided by the "ls" NSE module.

    This function is not perfect but should do the job in most
    cases.

    """
    assert script["id"] == "smb-ls"
    result = {"total": {"files": 0, "bytes": 0}, "volumes": []}
    state = 0  # outside a volume
    cur_vol = None
    for line in script["output"].splitlines():
        line = line.lstrip()
        if state == 0:  # outside a volume
            if line.startswith("Directory of "):
                if cur_vol is not None:
                    utils.LOGGER.warning(
                        "cur_vol should be None here [got %r]",
                        cur_vol,
                    )
                cur_vol = {"volume": line[13:], "files": []}
                state = 1  # listing
            elif line:
                utils.LOGGER.warning("Unexpected line [%r] outside a volume", line)
        elif state == 1:  # listing
            if line == "Total Files Listed:":
                state = 2  # total values
            elif line:
                date, time, size, fname = line.split(None, 3)
                if size.isdigit():
                    size = int(size)
                    result["total"]["bytes"] += size
                cur_vol["files"].append(
                    {"size": size, "filename": fname, "time": "%s %s" % (date, time)}
                )
                result["total"]["files"] += 1
        elif state == 2:  # total values
            if line:
                # we do not use this data
                pass
            else:
                state = 0  # outside a volume
                result["volumes"].append(cur_vol)
                cur_vol = None
    if state != 0:
        utils.LOGGER.warning("Expected state == 0, got %r", state)
    return result if result["volumes"] else None


def add_nfs_ls_data(script):
    """This function converts output from nfs-ls that do not include a
    structured output to a structured output similar to the one
    provided by the "ls" NSE module.

    This function is not perfect but should do the job in most
    cases.

    """
    assert script["id"] == "nfs-ls"
    result = {"total": {"files": 0, "bytes": 0}, "volumes": []}
    state = 0  # outside a volume
    cur_vol = None
    for line in script["output"].splitlines():
        line = line.lstrip()
        if state == 0:  # outside a volume
            if line.startswith("NFS Export: "):
                if cur_vol is not None:
                    utils.LOGGER.warning(
                        "cur_vol should be None here [got %r]",
                        cur_vol,
                    )
                cur_vol = {"volume": line[12:], "files": []}
                state = 1  # volume info
            # We silently discard any other lines
        elif state == 1:  # volume info
            if line.startswith("NFS "):
                cur_vol.setdefault("info", []).append(line[4].lower() + line[5:])
            elif line.startswith("PERMISSION"):
                state = 2  # listing
            # We silently discard any other lines
        elif state == 2:  # listing
            if line:
                permission, uid, gid, size, time, fname = line.split(None, 5)
                if size.isdigit():
                    size = int(size)
                    result["total"]["bytes"] += size
                cur_vol["files"].append(
                    {
                        "permission": permission,
                        "uid": uid,
                        "gid": gid,
                        "size": size,
                        "time": time,
                        "filename": fname,
                    }
                )
                result["total"]["files"] += 1
            else:
                state = 0  # outside a volume
                result["volumes"].append(cur_vol)
                cur_vol = None
    if state == 2:
        state = 0  # outside a volume
        result["volumes"].append(cur_vol)
        cur_vol = None
    if state != 0:
        utils.LOGGER.warning("Expected state == 0, got %r", state)
    return result if result["volumes"] else None


def add_afp_ls_data(script):
    """This function converts output from afp-ls that do not include a
    structured output to a structured output similar to the one
    provided by the "ls" NSE module.

    This function is not perfect but should do the job in most
    cases.

    """
    assert script["id"] == "afp-ls"
    result = {"total": {"files": 0, "bytes": 0}, "volumes": []}
    state = 0  # volumes / listings
    cur_vol = None
    for line in script["output"].splitlines():
        if state == 0:
            if line.startswith("    PERMISSION"):
                pass
            elif line.startswith("    "):
                if cur_vol is None:
                    utils.LOGGER.warning(
                        "Skip file entry outside a " "volume [%r]", line[4:]
                    )
                else:
                    (permission, uid, gid, size, date, time, fname) = line[4:].split(
                        None, 6
                    )
                    if size.isdigit():
                        size = int(size)
                        result["total"]["bytes"] += size
                    cur_vol["files"].append(
                        {
                            "permission": permission,
                            "uid": uid,
                            "gid": gid,
                            "size": size,
                            "filename": fname,
                            "time": "%s %s" % (date, time),
                        }
                    )
                    result["total"]["files"] += 1
            elif line.startswith("  ERROR: "):
                # skip error messages, same as when running without
                # setting ls.errors=true
                pass
            elif line == "  ":
                state = 1  # end of volumes
            elif line.startswith("  "):
                result["volumes"].append(cur_vol)
                cur_vol = {"volume": line[2:], "files": []}
        elif state == 1:
            if line.startswith("  "):
                result.setdefault("info", []).append(line[3].lower() + line[4:])
            else:
                utils.LOGGER.warning("Skip not understood line [%r]", line)
    return result if result["volumes"] else None


def add_ftp_anon_data(script):
    """This function converts output from ftp-anon that do not include a
    structured output to a structured output similar to the one
    provided by the "ls" NSE module.

    This function is not perfect but should do the job in most
    cases.

    Unlike the other add_*_data() functions related to the "ls" NSE
    module, the ftp-anon is still not using the "ls" NSE module and
    does not provide structured output. This is because the output of
    the LIST FTP command is not standardized and is meant to be read
    by humans.

    """
    assert script["id"] == "ftp-anon"
    # expressions that match lines, based on large data collection
    subexprs = {
        "user": (
            "(?:[a-zA-Z0-9\\._-]+(?:\\s+[NLOPQS])?|\\\\x[0-9A-F]{2}|" "\\*|\\(\\?\\))"
        ),
        "fname": "[A-Za-z0-9%s]+" % re.escape(" ?._@[](){}~#'&$%!+\\-/,|`="),
        "perm": "[a-zA-Z\\?-]{10}",
        "day": "[0-3]?[0-9]",
        "year": "[0-9]{2,4}",
        "month": "(?:[0-1]?[0-9]|[A-Z][a-z]{2}|[A-Z]{3})",
        "time": "[0-9]{1,2}\\:[0-9]{2}(?:\\:[0-9]{1,2})?",
        "windate": "[0-9]{2}-[0-9]{2}-[0-9]{2,4} +[0-9]{2}:[0-9]{2}(?:[AP]M)?",
        "vxworksdate": (
            "[A-Z][a-z]{2}-[0-9]{2}-[0-9]{2,4}\\s+" "[0-9]{2}:[0-9]{2}:[0-9]{2}"
        ),
    }
    subexprs["date"] = "(?:%s)" % "|".join(
        [
            "%(month)s\\s+%(day)s\\s+(?:%(year)s|%(time)s)" % subexprs,
            "%(day)s\\.\\s+%(month)s\\s+%(time)s" % subexprs,
        ]
    )
    exprs = re.compile(
        "^(?:"
        + "|".join(
            [
                # unix
                "(?P<unix_permission>%(perm)s)\\s+(?:[0-9]+\\s+)?"
                "(?P<unix_uid>%(user)s)\\s+(?P<unix_gid>%(user)s)\\s+"
                "(?P<unix_size>[0-9]+)\\s+(?P<unix_time>%(date)s)\\s+"
                "(?P<unix_filename>%(fname)s)(?:\\ \\-\\>\\ "
                "(?P<unix_linktarget>%(fname)s))?" % subexprs,
                # windows
                "(?P<win_time>%(windate)s)\\s+(?P<win_size>\\<DIR\\>|[0-9]+)\\s+"
                "(?P<win_filename>%(fname)s)" % subexprs,
                # vxworks
                "\\s+(?P<vxw_size>[0-9]+)\\s+(?P<vxw_time>%(vxworksdate)s)\\s+"
                "(?P<vxw_filename>%(fname)s)\\s+(?:\\<DIR\\>)?" % subexprs,
            ]
        )
        + ")(?: \\[NSE: writeable\\])?$",
        re.MULTILINE,
    )
    result = {"total": {"files": 0, "bytes": 0}, "volumes": []}
    cur_vol = {"volume": "/", "files": []}
    for fileentry in exprs.finditer(script["output"]):
        fileentry = {
            key.split("_", 1)[1]: value
            for key, value in fileentry.groupdict().items()
            if value is not None
        }
        size = fileentry.get("size")
        if size is not None and size.isdigit():
            size = int(size)
            fileentry["size"] = size
            result["total"]["bytes"] += size
        result["total"]["files"] += 1
        cur_vol["files"].append(fileentry)
    if cur_vol["files"]:
        result["volumes"].append(cur_vol)
        return result
    return None


def add_http_headers_data(script):
    result = []
    output = script.get("output", "").splitlines()
    if not output:
        return None
    if not output[0]:
        output = output[1:]
    for line in output:
        line = line.strip()
        if not line:
            return result
        try:
            field, value = (elt.strip() for elt in line.split(":", 1))
        except ValueError:
            field, value = line, None
        result.append({"name": field.lower(), "value": value})
    return result


ADD_TABLE_ELEMS = {
    "modbus-discover": re.compile(
        "^ *DEVICE IDENTIFICATION: *(?P<deviceid>.*?) *$", re.M
    ),
    "ls": add_ls_data,
    "mongodb-databases": add_mongodb_databases_data,
    "http-headers": add_http_headers_data,
}


def change_s7_info_keys(table):
    """Change key names in s7-info structured output"""
    for key in list(table or []):
        if key in NMAP_S7_INDEXES:
            table[NMAP_S7_INDEXES[key]] = table.pop(key)
    return table


def _smb_enum_shares_fix_share_name(name):
    if not (name.startswith("\\\\") and "\\" in name[2:]):
        utils.LOGGER.warning("Incorrect share name [%r]", name)
        return name
    server, share = name[2:].split("\\", 1)
    return "\\\\%s\\%s" % (server.replace("_", "."), share)


def change_smb_enum_shares(table):
    """Adapt structured data from script smb-enum-shares so that it is
    easy to query when inserted in DB.

    """
    if not table:
        return table
    result = {}
    for field in list(table):
        if field == "shares":
            continue
        if not (field.startswith("\\\\") and isinstance(table[field], dict)):
            result[field] = table.pop(field)
    if "shares" in table:
        # We just need to fix the share names
        result["shares"] = sorted(
            [
                dict(elt, Share=_smb_enum_shares_fix_share_name(elt["Share"]))
                for elt in table["shares"]
            ],
            key=lambda elt: elt["Share"],
        )
    else:
        # We need to update the structured output to avoid data in field names:
        #
        # Old:
        # {"\\ServerName\ShareName": {XXX}, ...}
        # New:
        # [{"Share": "\\ServerName\ShareName", XXX}, ...]
        result["shares"] = sorted(
            [
                dict(value, Share=_smb_enum_shares_fix_share_name(key))
                for key, value in table.items()
            ],
            key=lambda elt: elt["Share"],
        )
    return result


def change_ls(table):
    """Adapt structured data from "ls" NSE module to convert some
        fields to integers.

    New in SCHEMA_VERSION == 14: special file size '<DIR>' is removed from
    the document.

    """
    if "total" in table:
        for field in ["files", "bytes"]:
            if field in table["total"] and table["total"][field].isdigit():
                table["total"][field] = int(table["total"][field])
    for volume in table.get("volumes", []):
        for fileentry in volume.get("files", []):
            if "size" in fileentry:
                if fileentry["size"].isdigit():
                    fileentry["size"] = int(fileentry["size"])
                elif fileentry["size"] == "<DIR>":
                    del fileentry["size"]
    return table


def change_ls_migrate(table):
    """Adapt structured data from "ls" NSE module to convert some
        fields to integers.

    New in SCHEMA_VERSION == 14: special file size '<DIR>' is removed from
    the document.

    """
    for volume in table.get("volumes", []):
        for fileentry in volume.get("files", []):
            if "size" in fileentry and fileentry["size"] == "<DIR>":
                del fileentry["size"]
    return table


def change_vulns(table):
    """Adapt structured output generated by "vulns" NSE module."""
    return [dict(tab, id=vulnid) for vulnid, tab in table.items()]


def change_fcrdns(table):
    """Adapt structured output generated by the "fcrdns" Nmap script. The
    structured output uses hostnames (hence, data) as keys, which is
    undesirable in the databases.

    New in SCHEMA_VERSION == 12.

    """
    return [dict(result, name=name) for name, result in table.items()]


def change_fcrdns_migrate(table):
    """Adapt structured output generated by the "fcrdns" Nmap script. The
    structured output uses hostnames (hence, data) as keys, which is
    undesirable in the databases.

    New in SCHEMA_VERSION == 12.

    Use this function when migrating existing records.

    In previous schema versions, hostnames were used has keys; in keys,
    dots are replaced by underscores; this function reverts this change by
    replacing underscores by dots. This is OK because underscores are not
    allowed in FQDNs.

    """
    return [dict(result, name=name.replace("_", ".")) for name, result in table.items()]


def change_rpcinfo(table):
    """Adapt structured output generated by the "rpcinfo" Nmap script. The
    structured output uses program numbers (hence, data) as keys, which is
    undesirable in the databases. Also, some elements can be converted to
    integers.

    New in SCHEMA_VERSION == 12.

    """
    result = []
    for program, protores in table.items():
        for proto, data in protores.items():
            data["program"] = int(program)
            data["protocol"] = proto
            try:
                data["port"] = int(data["port"])
            except (KeyError, ValueError):
                pass
            result.append(data)
    return result


def change_ms_sql_info(table):
    """Adapt structured output generated by the "ms-sql-info" Nmap script. The
    structured output uses instances (hence, data) as keys, which is
    undesirable in the databases.

    New in SCHEMA_VERSION == 13.

    Use this function when migrating existing records.

    In previous schema versions, shares were used has keys; in keys,
    dots are replaced by underscores; this function reverts this change by
    replacing underscores by dots.

    """
    newlist = []
    for key in list(table):
        value = table[key]
        if not isinstance(value, dict):
            continue
        newlist.append(dict(value, Instance=key.replace("_", ".")))
        del table[key]
    return newlist


def change_ssh_hostkey(table):
    """Adapt structured output generated by the "ssh-hostkey" Nmap script.

    New in SCHEMA_VERSION == 14.

    """
    for key in table:
        if "bits" in key:
            # int(float()): a (now fixed) bug in Nmap reports 2048.0.
            key["bits"] = int(float(key["bits"]))
    return table


def change_http_git(table):
    """Adapt structured output generated by the "http-git" Nmap script.

    New in SCHEMA_VERSION == 15.

    """
    if not isinstance(table, dict):
        return table
    result = []
    for key, value in table.items():
        if isinstance(value.get("files-found"), dict):
            value["files-found"] = [
                ".git%s" % k[4:] if k.startswith("_git") else k
                for k, v in value["files-found"].items()
                if v == "true"
            ]
        if isinstance(value.get("interesting-matches"), dict):
            value["interesting-matches"] = [
                {
                    "file": ".git%s" % k[4:] if k.startswith("_git") else k,
                    "matches": v,
                }
                for k, v in value["interesting-matches"].items()
            ]
        result.append(dict(value, repository=key.replace("_", ".")))
    return result


def change_http_server_header(table):
    if isinstance(table, dict):
        if "Server" in table:
            return [table["Server"]]
        return []
    return table


CHANGE_TABLE_ELEMS = {
    "smb-enum-shares": change_smb_enum_shares,
    "s7-info": change_s7_info_keys,
    "ls": change_ls,
    "vulns": change_vulns,
    "fcrdns": change_fcrdns,
    "rpcinfo": change_rpcinfo,
    "ms-sql-info": change_ms_sql_info,
    "ssh-hostkey": change_ssh_hostkey,
    "http-git": change_http_git,
    "http-server-header": change_http_server_header,
}


def change_ssl_cert(out, table):
    """Fix modulus and exponent value in "ssl-cert" Nmap script. A bug
    exists in some Nmap versions that reports "BIGNUM: 0x<memory address>"
    instead of the value for fields `.modulus` and `.exponent` of
    `.pubkey`.

    In newer versions, the output has been fixed, **but** the exponent is
    written as a decimal number and the modulus as an hexadecimal number
    (see comments there: <https://github.com/nmap/nmap/commit/0f3a8a7>.

    Anyway, we first try to use our own parser, to get more information
    than Nmap would report.

    """
    if not isinstance(table, dict):
        return out, [table]
    if "pem" in table:
        # Let's try out own parser first
        data = "".join(table["pem"].splitlines()[1:-1]).encode()
        try:
            return create_ssl_cert(data)
        except Exception:
            utils.LOGGER.warning("Cannot parse certificate %r", data, exc_info=True)
    if "pubkey" not in table:
        return out, [table]
    pubkey = table["pubkey"]
    for key in ["modulus", "exponent"]:
        if isinstance(pubkey.get(key), str) and pubkey[key].startswith("BIGNUM: "):
            del pubkey[key]
    if isinstance(pubkey.get("modulus"), str):
        try:
            pubkey["modulus"] = str(int(pubkey["modulus"], 16))
        except ValueError:
            utils.LOGGER.warning(
                "Cannot convert modulus to decimal [%r]", pubkey["modulus"]
            )
    return out, [table]


def change_ssh2_enum_algos(out, table):
    """Adapt human readable and structured outputs generated by the
    "ssh2-enum-algos" Nmap script to add the HASSH value.

    New in SCHEMA_VERSION == 18.

    """
    hasshval = ";".join(
        ",".join(table.get(key, []))
        for key in [
            "kex_algorithms",
            "encryption_algorithms",
            "mac_algorithms",
            "compression_algorithms",
        ]
    )
    hassh = {
        "version": "1.1",
        "raw": hasshval,
    }
    hasshval = hasshval.encode()
    hassh.update(
        (hashtype, hashlib.new(hashtype, hasshval).hexdigest())
        for hashtype in ["md5", "sha1", "sha256"]
    )
    table["hassh"] = hassh
    new_out = ["", "  HASSH"]
    new_out.extend(
        "    %s: %s" % (key, hassh[key])
        for key in ["version", "raw", "md5", "sha1", "sha256"]
    )
    out += "\n".join(new_out)
    return out, table


CHANGE_OUTPUT_TABLE_ELEMS = {
    "ssh2-enum-algos": change_ssh2_enum_algos,
    "ssl-cert": change_ssl_cert,
}


def post_smb_os_discovery(script, port, host):
    if "smb-os-discovery" not in script:
        return
    data = script["smb-os-discovery"]
    if "DNS_Computer_Name" not in data:
        return
    add_hostname(data["DNS_Computer_Name"], "smb", host.setdefault("hostnames", []))


def post_ssl_cert(script, port, host):
    # We do not want to add hostnames from ssl-cacert results
    if script["id"] != "ssl-cert":
        return
    for cert in script.get("ssl-cert", []):
        add_cert_hostnames(cert, host.setdefault("hostnames", []))


def post_ntlm_info(script, port, host):
    if script["id"] != "ntlm-info":
        if script["id"] in script:
            script["ntlm-info"] = script.pop(script["id"])
        proto = script["id"].rsplit("-", 2)[0]
        if "ntlm-info" in script:
            script["ntlm-info"]["protocol"] = proto
        script["id"] = "ntlm-info"
    if "ntlm-info" not in script:
        return
    data = script["ntlm-info"]
    if "DNS_Computer_Name" not in data:
        return
    add_hostname(data["DNS_Computer_Name"], "ntlm", host.setdefault("hostnames", []))


def post_http_headers(script, port, host):
    if "http-headers" not in script:
        return
    handle_http_headers(host, port, script["http-headers"], handle_server=False)


_MACADDR_OCTETS = re.compile("^[0-9a-f]{12}33", re.I)


def post_snmp_info(script, _, host):
    if "snmp-info" not in script:
        return
    data_type = script["snmp-info"].get("engineIDFormat")
    data = script["snmp-info"].get("engineIDData")
    if data_type == "mac":
        if utils.MACADDR.search(data):
            mac = data.lower()
        else:
            return
    elif data_type == "octets":
        if _MACADDR_OCTETS.search(data):
            mac = ":".join(wrap(data.lower()[:12], 2))
        else:
            return
    else:
        return
    cur_macs = host.setdefault("addresses", {}).setdefault("mac", [])
    if mac not in cur_macs:
        cur_macs.append(mac)


POST_PROCESS = {
    "http-headers": post_http_headers,
    "ntlm-info": post_ntlm_info,
    "smb-os-discovery": post_smb_os_discovery,
    "snmp-info": post_snmp_info,
    "ssl-cert": post_ssl_cert,
}


def split_smb_os_discovery(script):
    try:
        value = script["smb-os-discovery"]
    except KeyError:
        # This may happen when an error occurs in Masscan
        yield script
        yield {}
        return
    if "ntlm-version" not in value:
        value["ntlm-version"] = "15"
    if "os" in value:
        if value["os"] not in WINDOWS_VERSION_TO_BUILD:
            utils.LOGGER.info(
                "New OS not yet registered in WINDOWS_VERSION_TO_BUILD %r",
                value["os"],
            )
        else:
            value["ntlm-os"] = WINDOWS_VERSION_TO_BUILD.get(value["os"])
    smb_values = {
        "os": "OS",
        "lanmanager": "LAN Manager",
        "date": "System Time",
        "cpe": "OS CPE",
        "smb-version": "SMB Version",
        "guid": "GUID",
    }
    smb = {
        "id": "smb-os-discovery",
        "smb-os-discovery": {k: value.get(k) for k in smb_values if k in value},
        "output": "\n".join(
            "  {}: {}".format(f, value.get(k))
            for k, f in smb_values.items()
            if k in value
        ),
    }
    if "masscan" in script:
        smb["masscan"] = script["masscan"]
    yield smb
    ntlm_values = {
        "domain": "NetBIOS_Domain_Name",
        "server": "NetBIOS_Computer_Name",
        "fqdn": "DNS_Computer_Name",
        "domain_dns": "DNS_Domain_Name",
        "forest_dns": "DNS_Tree_Name",
        "workgroup": "Workgroup",
        "ntlm-os": "Product_Version",
        "ntlm-version": "NTLM_Version",
    }
    ntlm = {
        "id": "ntlm-info",
        "ntlm-info": {f: value.get(k) for k, f in ntlm_values.items() if k in value},
        "output": "\n".join(
            "  {}: {}".format(f, value.get(k))
            for k, f in ntlm_values.items()
            if k in value
        ),
    }
    ntlm["ntlm-info"]["protocol"] = "smb"
    yield ntlm


SPLIT_SCRIPTS = {
    "smb-os-discovery": split_smb_os_discovery,
}


IGNORE_SCRIPTS = {
    "mcafee-epo-agent": set(["ePO Agent not found"]),
    "ftp-bounce": set(["no banner"]),
    "telnet-encryption": set(["\n  ERROR: Failed to send packet: TIMEOUT"]),
    "http-mobileversion-checker": set(["No mobile version detected."]),
    "http-referer-checker": set(["Couldn't find any cross-domain scripts."]),
    "http-default-accounts": set(
        [
            "[ERROR] HTTP request table is empty. This should not happen "
            "since we at least made one request.",
        ]
    ),
    "http-headers": set(["\n  (Request type: GET)\n"]),
    "http-cisco-anyconnect": set(
        [
            "\n  ERROR: Not a Cisco ASA or unsupported version",
        ]
    ),
    "ndmp-fs-info": set(
        [
            "\n  ERROR: Failed to get filesystem information from server",
        ]
    ),
    "ndmp-version": set(
        [
            "\n  ERROR: Failed to get host information from server",
        ]
    ),
    "ajp-auth": set(["\n  ERROR: Failed to connect to AJP server"]),
    "ajp-headers": set(["\n  ERROR: Failed to retrieve server headers"]),
    "ajp-methods": set(
        [
            "Failed to get a valid response for the OPTION request",
        ]
    ),
    "ajp-request": set(
        [
            "\n  ERROR: Failed to retrieve response for request",
            "\n  ERROR: Failed to connect to AJP server",
        ]
    ),
    "giop-info": set(["  \n  ERROR: Failed to read Packet.GIOP"]),
    "rsync-list-modules": set(
        [
            "\n  ERROR: Failed to connect to rsync server",
            "\n  ERROR: Failed to retrieve a list of modules",
        ]
    ),
    "sip-methods": set(["ERROR: Failed to connect to the SIP server."]),
    "sip-call-spoof": set(["ERROR: Failed to connect to the SIP server."]),
    "rpcap-info": set(["\n  ERROR: EOF"]),
    "rmi-dumpregistry": set(["Registry listing failed (Handshake failed)"]),
    "voldemort-info": set(["\n  ERROR: Unsupported protocol"]),
    "irc-botnet-channels": set(["\n  ERROR: EOF\n"]),
    "bitcoin-getaddr": set(
        [
            "\n  ERROR: Failed to extract address information",
            "\n  ERROR: Failed to extract version information",
        ]
    ),
    "bitcoin-info": set(["\n  ERROR: Failed to extract version information"]),
    "drda-info": set(["The response contained no EXCSATRD"]),
    "rdp-enum-encryption": set(["Received unhandled packet"]),
    "ldap-search": set(["ERROR: Failed to bind as the anonymous user"]),
    "mongodb-databases": set(
        [
            "No Bson data returned",
        ]
    ),
    # fixed in nmap commit 95f7b76d9f12d10832523e6f3db0e602a04b3a12
    # https://github.com/nmap/nmap/commit/95f7b76d9f12d10832523e6f3db0e602a04b3a12
    "snmp-hh3c-logins": set(["\n  baseoid: 1.3.6.1.4.1.25506.2.12.1.1.1"]),
    "dns-nsec-enum": set(["\n  No NSEC records found\n"]),
    "dns-nsec3-enum": set(["\n  DNSSEC NSEC3 not supported\n"]),
    "http-csrf": set(["Couldn't find any CSRF vulnerabilities."]),
    "http-devframework": set(
        [
            "Couldn't determine the underlying framework or CMS. Try increasing "
            "'httpspider.maxpagecount' value to spider more pages.",
        ]
    ),
    "http-dombased-xss": set(["Couldn't find any DOM based XSS."]),
    "http-drupal-enum": set(
        [
            "Nothing found amongst the top 100 resources,use "
            "--script-args number=<number|all> for deeper analysis)",
        ]
    ),
    "http-errors": set(["Couldn't find any error pages."]),
    "http-feed": set(["Couldn't find any feeds."]),
    "http-litespeed-sourcecode-download": set(
        [
            "Request with null byte did not work. This web server might not be "
            "vulnerable",
            "Page: /index.php was not found. Try with an existing file.",
        ]
    ),
    "http-sitemap-generator": set(
        [
            "\n  Directory structure:\n    /\n      Other: 1\n  Longest directory "
            "structure:\n    Depth: 0\n    Dir: /\n  Total files found (by "
            "extension):\n    Other: 1\n",
            "\n  Directory structure:\n  Longest directory structure:\n    "
            "Depth: 0\n    Dir: /\n  Total files found (by extension):\n    \n",
        ]
    ),
    "http-stored-xss": set(["Couldn't find any stored XSS vulnerabilities."]),
    "http-wordpress-enum": set(
        [
            "Nothing found amongst the top 100 resources,use "
            "--script-args search-limit=<number|all> for deeper analysis)",
        ]
    ),
    "http-wordpress-users": set(
        [
            "[Error] Wordpress installation was not found"
            ". We couldn't find wp-login.php"
        ]
    ),
    "ssl-date": set(["TLS randomness does not represent time"]),
    "http-comments-displayer": set(["Couldn't find any comments."]),
    "http-jsonp-detection": set(["Couldn't find any JSONP endpoints."]),
    # host scripts
    "firewalk": set(["None found"]),
    "ipidseq": set(["Unknown"]),
    "fcrdns": set(["FAIL (No PTR record)"]),
    "msrpc-enum": set(["SMB: ERROR: Server disconnected the connection"]),
    "smb-mbenum": set(
        [
            "\n  ERROR: Failed to connect to browser service: "
            "SMB: ERROR: Server disconnected the connection"
        ]
    ),
}

IGNORE_SCRIPTS_IDS = set(
    [
        "http-screenshot",
        "mainframe-screenshot",
        "rtsp-screenshot",
        "vnc-screenshot",
        "x11-screenshot",
    ]
)

MSSQL_ERROR = re.compile(
    "^ *(ERROR: )?("
    "No login credentials|"
    "TCP: Socket connection failed, Named Pipes: "
    "No named pipe for this instance"
    ")\\.?$",
    re.MULTILINE,
)

IGNORE_SCRIPTS_REGEXP = {
    "smtp-commands": re.compile(
        "^" + re.escape("Couldn't establish connection on port ") + "[0-9]+$"
    ),
    "ms-sql-config": MSSQL_ERROR,
    "ms-sql-dump-hashes": MSSQL_ERROR,
    "ms-sql-hasdbaccess": MSSQL_ERROR,
    "ms-sql-query": MSSQL_ERROR,
    "ms-sql-tables": MSSQL_ERROR,
    "irc-botnet-channels": re.compile("^" + re.escape("\n  ERROR: Closing Link: ")),
    "http-php-version": re.compile(
        "^(Logo query returned unknown hash [0-9a-f]{32}\\\n"
        "Credits query returned unknown hash [0-9a-f]{32}|"
        "(Logo|Credits) query returned unknown hash "
        "[0-9a-f]{32})$"
    ),
    "p2p-conficker": re.compile(re.escape("Host is CLEAN or ports are blocked")),
    "dns-nsec-enum": re.compile(
        "^"
        + re.escape("Can't determine domain for host ")
        + ".*"
        + re.escape("; use dns-nsec-enum.domains script arg.")
        + "$"
    ),
    "dns-nsec3-enum": re.compile(
        "^"
        + re.escape("Can't determine domain for host ")
        + ".*"
        + re.escape("; use dns-nsec3-enum.domains script arg.")
        + "$"
    ),
    "http-vhosts": re.compile(
        "^\\\n[0-9]+" + re.escape(" names had status ") + ("(?:[0-9]{3}|ERROR)")
    ),
    "http-fileupload-exploiter": re.compile(
        "^(" + re.escape("\n  \n    Couldn't find a file-type field.") + ")*$"
    ),
}

IGNORE_SCRIPT_OUTPUTS = set(
    [
        "Unable to open connection",
        "false",
        "TIMEOUT",
        "ERROR",
        "\n",
        "\r\n",
    ]
)

IGNORE_SCRIPT_OUTPUTS_REGEXP = set(
    [
        # MD5(<empty>)
        re.compile("d41d8cd98f00b204e9800998ecf8427e", re.IGNORECASE),
        re.compile(
            "^ *ERROR\\:\\ ("
            "Failed\\ to\\ (connect\\ to|receive\\ response\\ from)\\ server|"
            "Script\\ execution\\ failed\\ \\(use\\ \\-d\\ to\\ debug\\)|"
            "Receiving\\ packet\\:\\ (ERROR|EOF)|"
            "Failed\\ to\\ send\\ packet\\:\\ ERROR|"
            "ERROR)",
            re.MULTILINE,
        ),
        re.compile("^ *(SMB|ERROR):.*TIMEOUT", re.MULTILINE),
    ]
)

MASSCAN_S7_INDEXES = {
    0x11: {
        1: "module",  # "Module"
        6: "hardware",  # "Basic Hardware"
        7: "firmware",  # "Basic Firmware"
        0x81: "vipa_firmware",  # "Identification data of the VIPA Firmware"
        0x82: "svn_cpu",  # "Identification of the SVN version CPU"
        # 0x83: "Identification of the version CP",
    },
    0x1C: {
        1: "system_name",  # "Name of the PLC"
        2: "module_name",  # "Name of the module"
        3: "plant",  # "Plant identification"
        4: "copyright",  # "Copyright"
        5: "module_sn",  # "Serial number of module"
        6: "reserved",  # "Reserved for operating system"
        7: "module_type",  # "Module type name"
        8: "memory_card_sn",  # "Serial number of memory card"
        # 9: "Manufacturer and profile of a CPU module",
        # 10: "OEM ID of a module",
        11: "location",  # "Location designation of a module"
    },
}

NMAP_S7_INDEXES = {
    # 0x11
    "Module": MASSCAN_S7_INDEXES[0x11][1],
    "Basic Hardware": MASSCAN_S7_INDEXES[0x11][6],
    "Version": "version",
    # 0x1c
    "System Name": MASSCAN_S7_INDEXES[0x1C][1],
    "Module Type": MASSCAN_S7_INDEXES[0x1C][2],
    "Serial Number": MASSCAN_S7_INDEXES[0x1C][5],
    "Plant Identification": MASSCAN_S7_INDEXES[0x1C][3],
    "Copyright": MASSCAN_S7_INDEXES[0x1C][4],
}

MASSCAN_SERVICES_NMAP_SCRIPTS = {
    "http": "http-headers",
    "title": "http-title",
    "html": "http-content",
    "ftp": "banner",
    "unknown": "banner",
    "ssh": "ssh-banner",
    "vnc": "banner",
    "imap": "banner",
    "pop": "banner",
    "smtp": "banner",
    "X509": "ssl-cert",
    "X509CA": "ssl-cacert",
    "s7comm": "s7-info",
    "telnet": "banner",
    "rdp": "rdp-nla-support",
}

MASSCAN_NMAP_SCRIPT_NMAP_PROBES = {
    "tcp": {
        "banner": ["NULL"],
        "ssh-banner": ["NULL"],
        "http-headers": ["GetRequest"],
    },
}

MASSCAN_SERVICES_NMAP_SERVICES = {
    "ftp": "ftp",
    "http": "http",
    "ssh": "ssh",
    "vnc": "vnc",
    "imap": "imap",
    "pop": "pop3",
    "smtp": "smtp",
    "s7comm": "iso-tsap",
    "telnet": "telnet",
    "rdp": "ms-wbt-server",
}


MASSCAN_ENCODING = re.compile(re.escape(b"\\x") + b"([0-9a-f]{2})")
_HTTP_HEADER = re.compile(
    b"^([!\\#\\$%\\&'\\*\\+\\-\\.\\^_`\\|\\~A-Z0-9]+):[ \\\t]*([^\\\r]*)"
    b"[ \\\t\\\r]*$",
    re.I,
)


def _masscan_decode_print(match):
    char = utils.decode_hex(match.groups()[0])
    return char if (32 <= ord(char) <= 126 or char in b"\t\r\n") else match.group()


def _masscan_decode_raw(match):
    return utils.decode_hex(match.groups()[0])


def masscan_parse_s7info(data):
    fulldata = data
    output_data = {}
    output_text = [""]
    state = 0
    service_info = {
        "service_name": "iso-tsap",
        "service_devicetype": "specialized",
    }
    while data:
        if data[:1] != b"\x03":
            utils.LOGGER.warning("Masscan s7-info: invalid data [%r]", data)
            return None
        length = struct.unpack(">H", data[2:4])[0]
        curdata, data = data[4:length], data[length:]
        if len(curdata) < length - 4:
            utils.LOGGER.warning(
                "Masscan s7-info: record too short [%r] length %d, should be " "%d",
                curdata,
                len(curdata),
                length - 4,
            )
        datatype = curdata[1:2]
        if state == 0:  # Connect Confirm
            if datatype == b"\xd0":  # OK
                state += 1
                continue
            utils.LOGGER.warning(
                "Masscan s7-info: invalid data type in Connect Confirm " "[%r]",
                curdata,
            )
            return None
        if datatype != b"\xf0":
            utils.LOGGER.warning(
                "Masscan s7-info: invalid data type [%r]",
                curdata,
            )
            return None
        if curdata[3:4] != b"2":
            utils.LOGGER.warning(
                "Masscan s7-info: invalid magic [%r]",
                curdata,
            )
            return None
        if state == 1:  # ROSCTR setup response
            state += 1
            continue
        # state in [2, 3]: first or second SZL request response
        state += 1
        try:
            hdrlen = struct.unpack(">H", curdata[9:11])[0]
            szl_id, reclen = struct.unpack(">H2xH", curdata[17 + hdrlen : 23 + hdrlen])
        except struct.error:
            utils.LOGGER.warning("Not enough data to parse [%r]", curdata)
            continue
        if reclen not in [28, 34]:
            utils.LOGGER.info(
                "STRANGE LEN szl_id=%04x, reclen=%d [%r] [%r]",
                szl_id,
                reclen,
                curdata,
                fulldata,
            )
        if szl_id not in [0x11, 0x1C]:
            utils.LOGGER.warning(
                "Do not know how to parse szl_id %04x [%r]", szl_id, curdata
            )
            continue
        values = []
        curdata = curdata[25 + hdrlen :]
        curdata_len = min(reclen, len(curdata))
        while curdata_len > 2:
            if curdata_len < reclen:
                utils.LOGGER.warning(
                    "Masscan s7-info: record too short at szl_id=%04x [%r], "
                    "length %d, should be %d",
                    szl_id,
                    curdata[:reclen],
                    curdata_len,
                    reclen,
                )
            curvalues = struct.unpack(
                ">H%ds%dB"
                % (min(curdata_len - 2, reclen - 8), max(curdata_len - reclen + 6, 0)),
                curdata[:reclen],
            )
            utils.LOGGER.debug(
                "Masscan s7-info: szl_id=%04x index=%04x values=%r",
                szl_id,
                curvalues[0],
                curvalues[1:],
            )
            values.append(curvalues[:2])
            curdata = curdata[reclen:]
            curdata_len = min(reclen, len(curdata))
        indexes = MASSCAN_S7_INDEXES.get(szl_id, {})
        for index, value in values:
            try:
                key = indexes[index]
            except KeyError:
                utils.LOGGER.info(
                    "Masscan s7-info: cannot find key "
                    "(szl_id=%04x, index=%04x, value=%r)",
                    szl_id,
                    index,
                    value,
                )
                key = "UNK-%04x-%04x" % (szl_id, index)
            value = value.rstrip(b" \x00")
            try:
                value = value.decode()
            except UnicodeDecodeError:
                utils.LOGGER.info(
                    "Masscan s7-info: cannot decode value "
                    "(szl_id=%04x, index=%04x, key=%s, value=%r). "
                    "Using latin-1.",
                    szl_id,
                    index,
                    key,
                    value,
                )
                value = value.decode("latin-1")
            else:
                output_data[key] = value
                output_text.append("  %s: %s" % (key, value))
    if output_data.get("system_name") == "Technodrome":
        service_info = {
            "service_name": "honeypot",
            "service_product": "MushMush Conpot",
        }
    else:
        product = {
            "Original Siemens Equipment": "Siemens S7 PLC",
            "Original INSEVIS equipment": "Insevis S7 PLC",
        }.get(output_data.get("copyright"))
        if product:
            service_info["service_product"] = product
    output_text.append("\n")
    return service_info, output_text, output_data


def create_ssl_cert(
    data: bytes, b64encoded: bool = True
) -> Tuple[str, List[ParsedCertificate]]:
    """Produces an output similar to Nmap script ssl-cert from Masscan
    X509 "service" tag.

    """
    if b64encoded:
        cert = utils.decode_b64(data)
    else:
        cert = data
        data = utils.encode_b64(cert)
    info = utils.get_cert_info(cert)
    b64cert = data.decode()
    pem = []
    pem.append("-----BEGIN CERTIFICATE-----")
    pem.extend(wrap(b64cert, 64))
    pem.append("-----END CERTIFICATE-----")
    pem.append("")
    info["pem"] = "\n".join(pem)
    return "\n".join(create_ssl_output(info)), [info]


_EXPR_INDEX_OF = re.compile(
    "<title[^>]*> *(?:index +of|directory +listing +(?:of|for))",
    re.I,
)
_EXPR_FILES = [
    re.compile(
        '<a href="(?P<filename>[^"]+)">[^<]+</a></td><td[^>]*> *'
        "(?P<time>[0-9]+-[a-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *"
        "</td><td[^>]*> *(?P<size>[^<]+)</td>",
        re.I,
    ),
    re.compile(
        '<a href="(?P<filename>[^"]+)">[^<]+</a> *'
        "(?P<time>[0-9]+-[a-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *"
        "(?P<size>[^ \r\n]+)",
        re.I,
    ),
    re.compile('<li><a href="(?P<filename>[^"]+)">(?P=filename)</a>'),
]


def create_http_ls(data: str, url: Optional[str] = None) -> NmapScript:
    """Produces an http-ls script output (both structured and human
    readable) from the content of an HTML page. Used for Zgrab and Masscan
    results.

    """
    match = _EXPR_INDEX_OF.search(data)
    if match is None:
        return None
    files = []
    for pattern in _EXPR_FILES:
        for match in pattern.finditer(data):
            files.append(match.groupdict())
    if not files:
        return None
    output = []
    if url is None or "path" not in url:
        volname = "???"
    else:
        volname = url["path"]
    output.append("Volume %s" % volname)
    title = ["size", "time", "filename"]
    column_width = [len(t) for t in title[:-1]]
    for fobj in files:
        for i, t in enumerate(title[:-1]):
            column_width[i] = max(column_width[i], len(fobj.get(t, "-")))
    line_fmt = "%%(size)-%ds  %%(time)-%ds  %%(filename)s" % tuple(column_width)
    output.append(line_fmt % dict((t, t.upper()) for t in title))
    for fobj in files:
        output.append(line_fmt % dict({"size": "-", "time": "-"}, **fobj))
    output.append("")
    return {
        "id": "http-ls",
        "output": "\n".join(output),
        "ls": {"volumes": [{"volume": volname, "files": files}]},
    }


def create_elasticsearch_service(data: str) -> Optional[NmapServiceMatch]:
    """Produces the service_* attributes from the (JSON) content of an
    HTTP response. Used for Zgrab and Masscan results.

    """
    try:
        data = json.loads(data)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if "tagline" not in data:
        if "error" not in data:
            return None
        error = data["error"]
        if isinstance(error, str):
            if data.get("status") == 401 and error.startswith(
                "AuthenticationException"
            ):
                return {
                    "service_name": "http",
                    "service_product": "Elasticsearch REST API",
                    "service_extrainfo": "Authentication required",
                    "cpe": ["cpe:/a:elasticsearch:elasticsearch"],
                }
            return None
        if not isinstance(error, dict):
            return None
        if not (data.get("status") == 401 or error.get("status") == 401):
            return None
        if "root_cause" in error:
            return {
                "service_name": "http",
                "service_product": "Elasticsearch REST API",
                "service_extrainfo": "Authentication required",
                "cpe": ["cpe:/a:elasticsearch:elasticsearch"],
            }
        return None
    if data["tagline"] != "You Know, for Search":
        return None
    result = {"service_name": "http", "service_product": "Elasticsearch REST API"}
    cpe = []
    if "version" in data and "number" in data["version"]:
        result["service_version"] = data["version"]["number"]
        cpe.append("cpe:/a:elasticsearch:elasticsearch:%s" % data["version"]["number"])
    extrainfo = []
    if "name" in data:
        extrainfo.append("name: %s" % data["name"])
        result["service_hostname"] = data["name"]
    if "cluster_name" in data:
        extrainfo.append("cluster: %s" % data["cluster_name"])
    if "version" in data and "lucene_version" in data["version"]:
        extrainfo.append("Lucene %s" % data["version"]["lucene_version"])
        cpe.append("cpe:/a:apache:lucene:%s" % data["version"]["lucene_version"])
    if extrainfo:
        result["service_extrainfo"] = "; ".join(extrainfo)
    if cpe:
        result["cpe"] = cpe
    return result


def ignore_script(script):
    """Predicate that decides whether an Nmap script should be ignored
    or not, based on IGNORE_* constants. Nmap scripts are ignored when
    their output is known to be irrelevant.

    """
    sid = script.get("id")
    output = script.get("output")
    if sid in IGNORE_SCRIPTS_IDS:
        return True
    if output in IGNORE_SCRIPTS.get(sid, []):
        return True
    if output in IGNORE_SCRIPT_OUTPUTS:
        return True
    if (
        IGNORE_SCRIPTS_REGEXP.get(sid)
        and output is not None
        and IGNORE_SCRIPTS_REGEXP[sid].search(output)
    ):
        return True
    if output is not None and any(
        expr.search(output) for expr in IGNORE_SCRIPT_OUTPUTS_REGEXP
    ):
        return True
    return False


# This is not a real hostname regexp, but a simple way to exclude
# obviously wrong values. Underscores should not exist in (DNS)
# hostnames, but since they happen to exist anyway, we allow them
# here.
_HOSTNAME = re.compile("^[a-z0-9_\\.\\*\\-]+$", re.I)


def add_hostname(name: str, name_type: str, hostnames: List[NmapHostname]) -> None:
    name = name.rstrip(".").lower()
    if not _HOSTNAME.search(name):
        return
    # exclude IPv4 addresses
    if utils.IPV4ADDR.search(name):
        return
    if any(hn["name"] == name and hn["type"] == name_type for hn in hostnames):
        return
    hostnames.append(
        {
            "type": name_type,
            "name": name,
            "domains": list(utils.get_domains(name)),
        }
    )


def add_service_hostname(service_info, hostnames):
    if "service_hostname" not in service_info:
        return
    name = service_info["service_hostname"]
    if "service_extrainfo" in service_info:
        for data in service_info["service_extrainfo"].lower().split(", "):
            if data.startswith("domain:"):
                name += "." + data[7:].strip()
                break
    add_hostname(name, "service", hostnames)


def add_cert_hostnames(cert: ParsedCertificate, hostnames: List[NmapHostname]) -> None:
    if "commonName" in cert.get("subject", {}):
        add_hostname(cert["subject"]["commonName"], "cert-subject-cn", hostnames)
    for san in cert.get("san", []):
        if san.startswith("DNS:"):
            add_hostname(san[4:], "cert-san-dns", hostnames)
            continue
        if san.startswith("URI:"):
            try:
                netloc = urlparse(san[4:]).netloc
            except Exception:
                utils.LOGGER.warning("Invalid URL in SAN %r", san, exc_info=True)
                continue
            if not netloc:
                continue
            if netloc.startswith("["):
                # IPv6
                continue
            if ":" in netloc:
                netloc = netloc.split(":", 1)[0]
            add_hostname(netloc, "cert-san-uri", hostnames)


class NoExtResolver(EntityResolver):

    """A simple EntityResolver that will prevent any external
    resolution.

    """

    def resolveEntity(self, *_):
        return "file://%s" % os.devnull


class NmapHandler(ContentHandler):

    """The handler for Nmap's XML documents. An abstract class for
    database specific implementations.

    """

    def __init__(
        self,
        fname,
        filehash,
        needports=False,
        needopenports=False,
        masscan_probes=None,
        **_,
    ):
        ContentHandler.__init__(self)
        self._needports = needports
        self._needopenports = needopenports
        self._curscan = None
        self._curscript = None
        self._curhost = None
        self._curextraports = None
        self._curport = None
        self._curtrace = None
        self._curdata = None
        self._curtable = {}
        self._curtablepath = []
        self._curhostnames = None
        self._fname = fname
        self._filehash = filehash
        self.scanner = "nmap"
        self.scan_doc_saved = False
        self.masscan_probes = [] if masscan_probes is None else masscan_probes
        utils.LOGGER.debug("READING %r (%r)", fname, self._filehash)

    @staticmethod
    def _to_binary(data):
        """Prepare binary data. Subclasses may want to do some kind
        of conversion here.

        """
        return data

    @staticmethod
    def _from_binary(data):
        """Reverse ._to_binary() transformation."""
        return data

    def _pre_addhost(self):
        """Executed before _addhost for host object post-treatment"""
        if "cpes" in self._curhost:
            self._curhost["cpes"] = list(self._curhost["cpes"].values())
            for cpe in self._curhost["cpes"]:
                cpe["origins"] = sorted(cpe["origins"])
            if not self._curhost["cpes"]:
                del self._curhost["cpes"]

    def _addhost(self):
        """Subclasses may store self._curhost here."""

    def _storescan(self):
        """Subclasses may store self._curscan here."""

    def _updatescan(self, _):
        """Subclasses may update the scan record here, based on the first
        argument (a dict object).

        """

    def _addscaninfo(self, _):
        """Subclasses may add scan information (first argument) to
        self._curscan here.

        """

    def startElement(self, name, attrs):
        if name == "nmaprun":
            if self._curscan is not None:
                utils.LOGGER.warning(
                    "self._curscan should be None at " "this point (got %r)",
                    self._curscan,
                )
            self._curscan = dict(attrs)
            self.scanner = self._curscan.get("scanner", self.scanner)
            self._curscan["_id"] = self._filehash
        elif name == "finished":
            curscan_more = dict(attrs)
            if "time" in curscan_more:
                curscan_more["end"] = curscan_more.pop("time")
            if "timestr" in curscan_more:
                curscan_more["endstr"] = curscan_more.pop("timestr")
            self._updatescan(curscan_more)
        elif name == "scaninfo" and self._curscan is not None:
            self._addscaninfo(dict(attrs))
        elif name == "host":
            if self._curhost is not None:
                utils.LOGGER.warning(
                    "self._curhost should be None at " "this point (got %r)",
                    self._curhost,
                )
            self._curhost = {"schema_version": SCHEMA_VERSION}
            if self._curscan:
                self._curhost["scanid"] = self._curscan["_id"]
            for attr in attrs.keys():
                self._curhost[attr] = attrs[attr]
            for field in ["starttime", "endtime"]:
                if field in self._curhost:
                    self._curhost[field] = datetime.datetime.utcfromtimestamp(
                        int(self._curhost[field])
                    )
            if "starttime" not in self._curhost and "endtime" in self._curhost:
                # Masscan
                self._curhost["starttime"] = self._curhost["endtime"]
        elif name == "address" and self._curhost is not None:
            if attrs["addrtype"] in ["ipv4", "ipv6"] and "addr" not in self._curhost:
                self._curhost["addr"] = attrs["addr"]
            else:
                self._curhost.setdefault("addresses", {}).setdefault(
                    attrs["addrtype"], []
                ).append(attrs["addr"].lower())
        elif name == "hostnames":
            if self._curhost is None:
                # We do not want to handle hostnames in hosthint tags,
                # as they will be repeated inside an host tag
                return
            if self._curhostnames is not None:
                utils.LOGGER.warning(
                    "self._curhostnames should be None at " "this point (got %r)",
                    self._curhostnames,
                )
            self._curhostnames = []
        elif name == "hostname":
            if self._curhost is None:
                return
            if self._curhostnames is None:
                utils.LOGGER.warning(
                    "self._curhostnames should NOT be " "None at this point"
                )
                self._curhostnames = []
            hostname = dict(attrs)
            if "name" in attrs:
                hostname["domains"] = list(utils.get_domains(attrs["name"]))
            self._curhostnames.append(hostname)
        elif name == "status" and self._curhost is not None:
            self._curhost["state"] = attrs["state"]
            if "reason" in attrs:
                self._curhost["state_reason"] = attrs["reason"]
            if "reason_ttl" in attrs:
                self._curhost["state_reason_ttl"] = int(attrs["reason_ttl"])
        elif name == "extraports":
            if self._curextraports is not None:
                utils.LOGGER.warning(
                    "self._curextraports should be None at " "this point (got %r)",
                    self._curextraports,
                )
            self._curextraports = {
                attrs["state"]: {"total": int(attrs["count"]), "reasons": {}},
            }
        elif name == "extrareasons" and self._curextraports is not None:
            self._curextraports[next(iter(self._curextraports))]["reasons"][
                attrs["reason"]
            ] = int(attrs["count"])
        elif name == "port":
            if self._curport is not None:
                utils.LOGGER.warning(
                    "self._curport should be None at this " "point (got %r)",
                    self._curport,
                )
            self._curport = {
                "protocol": attrs["protocol"],
                "port": int(attrs["portid"]),
            }
        elif name == "state" and self._curport is not None:
            for attr in attrs.keys():
                self._curport["state_%s" % attr] = attrs[attr]
            for field in ["state_reason_ttl"]:
                if field in self._curport:
                    self._curport[field] = int(self._curport[field])
        elif name == "service" and self._curport is not None:
            if attrs.get("method") == "table":
                # discard information from nmap-services
                return
            if self.scanner == "masscan":
                banner = attrs["banner"]
                if attrs["name"] == "vnc" and "=" in attrs["banner"]:
                    # See also
                    # https://github.com/robertdavidgraham/masscan/pull/250
                    banner = banner.split(" ")
                    banner, vncinfo = ("%s\\x0a" % " ".join(banner[:2]), banner[2:])
                    if vncinfo:
                        output = []
                        while vncinfo:
                            info = vncinfo.pop(0)
                            if info.startswith("ERROR="):
                                info = "ERROR: " + " ".join(vncinfo)
                                vncinfo = []
                            elif "=[" in info:
                                while vncinfo and not info.endswith("]"):
                                    info += " " + vncinfo.pop(0)
                                info = info.replace("=[", ": ", 1)
                                if info.endswith("]"):
                                    info = info[:-1]
                            else:
                                info = info.replace("=", ": ", 1)
                            output.append(info)
                        self._curport.setdefault("scripts", []).append(
                            {
                                "id": "vnc-info",
                                "output": "\n".join(output),
                            }
                        )
                elif attrs["name"] == "smb":
                    # smb has to be handled differently: we build host
                    # scripts to match Nmap behavior
                    self._curport["service_name"] = (
                        "netbios-ssn"
                        if self._curport.get("port") == 139
                        else "microsoft-ds"
                        if self._curport.get("port") == 445
                        else "smb"
                    )
                    raw_output = MASSCAN_ENCODING.sub(
                        _masscan_decode_raw, banner.encode()
                    )
                    masscan_data = {
                        "raw": self._to_binary(raw_output),
                        "encoded": banner,
                    }
                    if banner.startswith("ERR unknown response"):
                        # skip this part of the banner, which gets stored as:
                        # "ERR unknown responseERROR(UNKNOWN)"
                        banner = banner[20:]
                    if banner.startswith("ERROR"):
                        self._curport.setdefault("scripts", []).append(
                            {
                                "id": "smb-os-discovery",
                                "output": banner,
                                "masscan": masscan_data,
                            }
                        )
                        return
                    data = {}
                    while True:
                        banner = banner.strip()
                        if not banner:
                            break
                        if banner.startswith("SMBv"):
                            try:
                                idx = banner.index(" ")
                            except ValueError:
                                data["smb-version"] = banner
                                banner = ""
                            else:
                                data["smb-version"] = banner[:idx]
                                banner = banner[idx:]
                            continue
                        # os values may contain spaces
                        if (
                            banner.startswith("os=")
                            or banner.startswith("ver=")
                            or banner.startswith("domain=")
                            or banner.startswith("name=")
                            or banner.startswith("domain-dns=")
                            or banner.startswith("name-dns=")
                        ):
                            key, banner = banner.split("=", 1)
                            value = []
                            while banner and not re.compile("^[a-z-]+=", re.I).search(
                                banner
                            ):
                                try:
                                    idx = banner.index(" ")
                                except ValueError:
                                    value.append(banner)
                                    banner = ""
                                    break
                                else:
                                    value.append(banner[:idx])
                                    banner = banner[idx + 1 :]
                            data[key] = " ".join(value)
                            continue
                        if banner.startswith("time=") or banner.startswith("boottime="):
                            key, banner = banner.split("=", 1)
                            idx = (
                                re.compile("\\d+-\\d+\\d+ \\d+:\\d+:\\d+")
                                .search(banner)
                                .end()
                            )
                            tstamp = banner[:idx]
                            banner = banner[idx:]
                            if banner.startswith(" TZ="):
                                banner = banner[4:]
                                try:
                                    idx = banner.index(" ")
                                except ValueError:
                                    tzone = banner
                                    banner = ""
                                else:
                                    tzone = banner[:idx]
                                    banner = banner[idx:]
                                tzone = int(tzone)
                                tzone = "%+03d%02d" % (tzone // 60, tzone % 60)
                            else:
                                tzone = ""
                            if not utils.STRPTIME_SUPPORTS_TZ:
                                # %z is not supported with strptime()
                                tzone = ""
                            if tstamp.startswith("1601-01-01 ") or tstamp.startswith(
                                "60056-05-28 "
                            ):
                                # minimum / maximum windows timestamp value
                                continue
                            try:
                                data[key] = datetime.datetime.strptime(
                                    tstamp + tzone,
                                    "%Y-%m-%d %H:%M:%S" + ("%z" if tzone else ""),
                                )
                                # data[key] = utils.all2datetime(tstamp)
                            except ValueError:
                                utils.LOGGER.warning(
                                    "Invalid timestamp from Masscan SMB " "result %r",
                                    tstamp,
                                    exc_info=True,
                                )
                            continue
                        try:
                            idx = banner.index(" ")
                        except ValueError:
                            key, value = banner.split("=", 1)
                            banner = ""
                        else:
                            key, value = banner[:idx].split("=", 1)
                            banner = banner[idx:]
                        data[key] = value
                    smb_os_disco = {}
                    smb_os_disco_output = [""]
                    if "os" in data:
                        smb_os_disco["os"] = data["os"]
                        if "ver" in data:
                            smb_os_disco_output.append(
                                "  OS: %s (%s)" % (data["os"], data["ver"])
                            )
                            smb_os_disco["lanmanager"] = data["ver"]
                        else:
                            smb_os_disco_output.append("  OS: %s" % data["os"])
                    elif "ver" in data:
                        smb_os_disco_output.append("  OS: - (%s)" % data["ver"])
                        smb_os_disco["lanmanager"] = data["ver"]
                    for masscankey, nmapkey, humankey in [
                        ("smb-version", "smb-version", "SMB Version"),
                        ("guid", "guid", "GUID"),
                    ]:
                        if masscankey in data:
                            smb_os_disco[nmapkey] = data[masscankey]
                            if humankey is not None:
                                smb_os_disco_output.append(
                                    "  %s: %s"
                                    % (
                                        humankey,
                                        data[masscankey],
                                    )
                                )
                    ntlm_info = {}
                    ntlm_info_output = [""]
                    for masscankey, humankey in [
                        ("name", "NetBIOS_Computer_Name"),
                        ("domain", "Workgroup"),
                        ("name-dns", "DNS_Computer_Name"),
                        ("domain-dns", "DNS_Domain_Name"),
                        ("forest", "DNS_Tree_Name"),
                        ("version", "Product_Version"),
                        ("ntlm-ver", "NTLM_Version"),
                    ]:
                        if masscankey in data:
                            ntlm_info[humankey] = data[masscankey]
                            if humankey is not None:
                                ntlm_info_output.append(
                                    "  %s: %s"
                                    % (
                                        humankey,
                                        data[masscankey],
                                    )
                                )
                    if "DNS_Computer_Name" in ntlm_info:
                        add_hostname(
                            ntlm_info["DNS_Computer_Name"],
                            "smb",
                            self._curhost.setdefault("hostnames", []),
                        )
                    scripts = self._curport.setdefault("scripts", [])
                    if "time" in data:
                        smb2_time = {}
                        smb2_time_out = [""]
                        try:
                            # FIXME TIME ZONE
                            smb_os_disco["date"] = data["time"].strftime(
                                "%Y-%m-%dT%H:%M:%S"
                            )
                        except ValueError:
                            # year == 1601
                            pass
                        else:
                            smb_os_disco_output.append(
                                "  System time: %s" % smb_os_disco["date"]
                            )
                            smb2_time["date"] = str(data["time"])
                            smb2_time_out.append("  date: %s" % data["time"])
                        if "boottime" in data:
                            # Masscan has to be patched to report this.
                            smb2_time["start_time"] = str(data["boottime"])
                            smb2_time_out.append("  start_time: %s" % data["boottime"])
                        if smb2_time:
                            scripts.append(
                                {
                                    "id": "smb2-time",
                                    "smb2-time": smb2_time,
                                    "output": "\n".join(smb2_time_out),
                                }
                            )
                    smb_os_disco_output.append("")
                    scripts.append(
                        {
                            "id": "smb-os-discovery",
                            "smb-os-discovery": smb_os_disco,
                            "output": "\n".join(smb_os_disco_output),
                            "masscan": masscan_data,
                        }
                    )
                    ntlm_info["protocol"] = "smb"
                    scripts.append(
                        {
                            "id": "ntlm-info",
                            "ntlm-info": ntlm_info,
                            "output": "\n".join(ntlm_info_output),
                        }
                    )
                    return
                # create fake scripts from masscan "service" tags
                raw_output = MASSCAN_ENCODING.sub(_masscan_decode_raw, banner.encode())
                scriptid = MASSCAN_SERVICES_NMAP_SCRIPTS.get(
                    attrs["name"], attrs["name"]
                )
                script = {
                    "id": scriptid,
                    "output": MASSCAN_ENCODING.sub(
                        _masscan_decode_print, banner.encode()
                    ).decode(),
                    "masscan": {
                        "raw": self._to_binary(raw_output),
                        "encoded": banner,
                    },
                }
                self._curport.setdefault("scripts", []).append(script)
                # get service name
                try:
                    self._curport["service_name"] = MASSCAN_SERVICES_NMAP_SERVICES[
                        attrs["name"]
                    ]
                except KeyError:
                    pass
                if attrs["name"] in ["ssl", "X509"]:
                    self._curport["service_tunnel"] = "ssl"
                self.masscan_post_script(script)
                # attempt to use Nmap service fingerprints
                probes = self.masscan_probes[:]
                probes.extend(
                    MASSCAN_NMAP_SCRIPT_NMAP_PROBES.get(
                        self._curport["protocol"], {}
                    ).get(scriptid, [])
                )
                match = {}
                for probe in probes:
                    # udp/ike: let's use ike-scan FP
                    if self._curport["protocol"] == "udp" and probe in [
                        "ike",
                        "ike-ipsec-nat-t",
                    ]:
                        masscan_data = script["masscan"]
                        self._curport.update(
                            ike.analyze_ike_payload(
                                raw_output,
                                probe=probe,
                            )
                        )
                        if self._curport.get("service_name") == "isakmp":
                            self._curport["scripts"][0]["masscan"] = masscan_data
                        return
                    # tcp/dicom: use our own parser
                    if self._curport["protocol"] == "tcp" and probe == "dicom":
                        masscan_data = script["masscan"]
                        self._curport.update(dicom.parse_message(raw_output))
                        if self._curport.get("service_name") == "dicom":
                            self._curport["scripts"][0]["masscan"] = masscan_data
                        return
                    if self._curport.get("service_name") in [
                        "ftp",
                        "imap",
                        "pop3",
                        "smtp",
                        "ssh",
                    ]:
                        raw_output = raw_output.split(b"\n", 1)[0].rstrip(b"\r")
                    new_match = utils.match_nmap_svc_fp(
                        output=raw_output,
                        proto=self._curport["protocol"],
                        probe=probe,
                        soft=True,
                    )
                    if new_match and (
                        not match or (match.get("soft") and not new_match.get("soft"))
                    ):
                        match = new_match
                if match:
                    try:
                        del match["soft"]
                    except KeyError:
                        pass
                    for cpe in match.pop("cpe", []):
                        self._add_cpe_to_host(cpe=cpe)
                    self._curport.update(match)
                    add_service_hostname(
                        match,
                        self._curhost.setdefault("hostnames", []),
                    )
                    if match.get("service_name") == "reverse-ssl":
                        # Attempt to compute the JA3c value
                        script = ja3.banner2script(raw_output)
                        if script:
                            self._curport.setdefault("scripts", []).append(script)
                return
            for attr in attrs.keys():
                self._curport["service_%s" % attr] = attrs[attr]
            for field in [
                "service_conf",
                "service_rpcnum",
                "service_lowver",
                "service_highver",
            ]:
                if field in self._curport:
                    self._curport[field] = int(self._curport[field])
            add_service_hostname(
                self._curport, self._curhost.setdefault("hostnames", [])
            )
        elif name == "script":
            if self._curscript is not None:
                utils.LOGGER.warning(
                    "self._curscript should be None at this " "point (got %r)",
                    self._curscript,
                )
            self._curscript = dict([attr, attrs[attr]] for attr in attrs.keys())
        elif name in ["table", "elem"]:
            if self._curscript.get("id") in IGNORE_TABLE_ELEMS:
                return
            if name == "elem":
                # start recording characters
                if self._curdata is not None:
                    utils.LOGGER.warning(
                        "self._curdata should be None at " "this point (got %r)",
                        self._curdata,
                    )
                self._curdata = ""
            if "key" in attrs:
                key = attrs["key"].replace(".", "_")
                obj = {key: {}}
            else:
                key = None
                obj = []
            if not self._curtablepath:
                if not self._curtable:
                    self._curtable = obj
                elif key is not None:
                    self._curtable.update(obj)
                if key is None:
                    key = len(self._curtable)
                self._curtablepath.append(key)
                return
            lastlevel = self._curtable
            for k in self._curtablepath[:-1]:
                lastlevel = lastlevel[k]
            k = self._curtablepath[-1]
            if isinstance(k, int):
                if k < len(lastlevel):
                    if key is not None:
                        lastlevel[k].update(obj)
                else:
                    lastlevel.append(obj)
                if key is None:
                    key = len(lastlevel[k])
            else:
                if key is None:
                    if lastlevel[k]:
                        key = len(lastlevel[k])
                    else:
                        key = 0
                        lastlevel[k] = obj
                else:
                    lastlevel[k].update(obj)
            self._curtablepath.append(key)
        elif name == "os":
            self._curhost["os"] = {}
        elif name == "portused" and "os" in self._curhost:
            self._curhost["os"]["portused"] = {
                "port": "%s_%s" % (attrs["proto"], attrs["portid"]),
                "state": attrs["state"],
            }
        elif name in ["osclass", "osmatch"] and "os" in self._curhost:
            self._curhost["os"].setdefault(name, []).append(dict(attrs))
        elif name == "osfingerprint" and "os" in self._curhost:
            self._curhost["os"]["fingerprint"] = attrs["fingerprint"]
        elif name == "trace":
            if self._curtrace is not None:
                utils.LOGGER.warning(
                    "self._curtrace should be None at this " "point (got %r)",
                    self._curtrace,
                )
            if "proto" not in attrs:
                self._curtrace = {"protocol": None}
            elif attrs["proto"] in ["tcp", "udp"]:
                self._curtrace = {
                    "protocol": attrs["proto"],
                    "port": int(attrs["port"]),
                }
            else:
                self._curtrace = {"protocol": attrs["proto"]}
            self._curtrace["hops"] = []
        elif name == "hop" and self._curtrace is not None:
            attrsdict = dict(attrs)
            try:
                attrsdict["rtt"] = float(attrs["rtt"])
            except ValueError:
                pass
            try:
                attrsdict["ttl"] = int(attrs["ttl"])
            except ValueError:
                pass
            if "host" in attrsdict:
                attrsdict["domains"] = list(utils.get_domains(attrsdict["host"]))
            self._curtrace["hops"].append(attrsdict)
        elif name == "cpe":
            # start recording
            self._curdata = ""

    def endElement(self, name):
        if name == "nmaprun":
            self._curscan = None
        elif name == "host":
            # masscan -oX output has no "state" tag
            if (
                self._curhost.get("state", "up") == "up"
                and (not self._needports or "ports" in self._curhost)
                and (
                    not self._needopenports
                    or self._curhost.get("openports", {}).get("count")
                )
            ):
                if "openports" not in self._curhost:
                    self._curhost["openports"] = {"count": 0}
                elif "state" not in self._curhost:
                    # hosts with an open port are marked as up by
                    # default (masscan)
                    self._curhost["state"] = "up"
                cleanup_synack_honeypot_host(self._curhost)
                self._pre_addhost()
                self._addhost()
            self._curhost = None
        elif name == "hostnames":
            if self._curhost is None:
                return
            self._curhost["hostnames"] = self._curhostnames
            self._curhostnames = None
        elif name == "extraports":
            self._curhost.setdefault("extraports", {}).update(self._curextraports)
            self._curextraports = None
        elif name == "port":
            self._curhost.setdefault("ports", []).append(self._curport)
            if self._curport.get("state_state") == "open":
                openports = self._curhost.setdefault("openports", {})
                openports["count"] = openports.get("count", 0) + 1
                protoopenports = openports.setdefault(self._curport["protocol"], {})
                protoopenports["count"] = protoopenports.get("count", 0) + 1
                protoopenports.setdefault("ports", []).append(self._curport["port"])
            self._curport = None
        elif name == "script":
            if self._curport is not None:
                current = self._curport
            elif self._curhost is not None:
                current = self._curhost
            else:
                # We do not want to handle script tags outside host or
                # port tags (usually scripts running on prerule /
                # postrule)
                self._curscript = None
                if self._curtablepath:
                    utils.LOGGER.warning(
                        "self._curtablepath should be empty, " "got [%r]",
                        self._curtablepath,
                    )
                self._curtable = {}
                return
            if self._curscript["id"] in SCREENSHOTS_SCRIPTS:
                fname = SCREENSHOTS_SCRIPTS[self._curscript["id"]](self._curscript)
                if fname is not None:
                    exceptions = []
                    for full_fname in [
                        fname,
                        os.path.join(os.path.dirname(self._fname), fname),
                    ]:
                        try:
                            with open(full_fname, "rb") as fdesc:
                                data = fdesc.read()
                                trim_result = utils.trim_image(data)
                                if trim_result:
                                    # When trim_result is False, the image no
                                    # longer exists after trim
                                    if trim_result is not True:
                                        # Image has been trimmed
                                        data = trim_result
                                    current["screenshot"] = "field"
                                    current["screendata"] = self._to_binary(data)
                                    screenwords = utils.screenwords(data)
                                    if screenwords is not None:
                                        current["screenwords"] = screenwords
                                else:
                                    current["screenshot"] = "empty"
                        except Exception:
                            exceptions.append((sys.exc_info(), full_fname))
                        else:
                            exceptions = []
                            break
                    for exc_info, full_fname in exceptions:
                        utils.LOGGER.warning(
                            "Screenshot: exception (scanfile %r, file %r)",
                            self._fname,
                            full_fname,
                            exc_info=exc_info,
                        )
            if ignore_script(self._curscript):
                if self._curtablepath:
                    utils.LOGGER.warning(
                        "self._curtablepath should be empty," " got [%r]",
                        self._curtablepath,
                    )
                self._curtable = {}
                self._curscript = None
                return
            key = self._curscript.get("id", None)
            infokey = ALIASES_TABLE_ELEMS.get(key, key)
            if self._curtable:
                if self._curtablepath:
                    utils.LOGGER.warning(
                        "self._curtablepath should be empty, " "got [%r]",
                        self._curtablepath,
                    )
                if infokey in CHANGE_TABLE_ELEMS:
                    self._curtable = CHANGE_TABLE_ELEMS[infokey](self._curtable)
                elif infokey in CHANGE_OUTPUT_TABLE_ELEMS:
                    (
                        self._curscript["output"],
                        self._curtable,
                    ) = CHANGE_OUTPUT_TABLE_ELEMS[infokey](
                        self._curscript.get("output", ""), self._curtable
                    )
                self._curscript[infokey] = self._curtable
                self._curtable = {}
            elif infokey in ADD_TABLE_ELEMS:
                infos = ADD_TABLE_ELEMS[infokey]
                if isinstance(infos, utils.REGEXP_T):
                    infos = infos.search(self._curscript.get("output", ""))
                    if infos is not None:
                        infosdict = infos.groupdict()
                        if infosdict:
                            self._curscript[infokey] = infosdict
                        else:
                            infos = list(infos.groups())
                            if infos:
                                self._curscript[infokey] = infos
                elif hasattr(infos, "__call__"):
                    infos = infos(self._curscript)
                    if infos is not None:
                        self._curscript[infokey] = infos
            if infokey in POST_PROCESS:
                POST_PROCESS[infokey](self._curscript, current, self._curhost)
            if infokey in SPLIT_SCRIPTS:
                for scr in SPLIT_SCRIPTS[infokey](self._curscript):
                    if scr:
                        current.setdefault("scripts", []).append(scr)
            else:
                current.setdefault("scripts", []).append(self._curscript)
            self._curscript = None
        elif name in ["table", "elem"]:
            if self._curscript.get("id") in IGNORE_TABLE_ELEMS:
                return
            if name == "elem":
                lastlevel = self._curtable
                for k in self._curtablepath[:-1]:
                    if k is None:
                        lastlevel = lastlevel[-1]
                    else:
                        lastlevel = lastlevel[k]
                k = self._curtablepath[-1]
                if isinstance(k, int):
                    lastlevel.append(self._curdata)
                else:
                    lastlevel[k] = self._curdata
                if k == "cpe":
                    self._add_cpe_to_host()
                # stop recording characters
                self._curdata = None
            self._curtablepath.pop()
        elif name == "hostscript" and "scripts" in self._curhost:
            # "fake" port element, without a "protocol" key and with the
            # magic value -1 for the "port" key.
            self._curhost.setdefault("ports", []).append(
                {"port": -1, "scripts": self._curhost.pop("scripts")}
            )
        elif name == "trace":
            self._curhost.setdefault("traces", []).append(self._curtrace)
            self._curtrace = None
        elif name == "cpe":
            self._add_cpe_to_host()

    def masscan_post_script(self, script):
        try:
            function = {
                "http-headers": self.masscan_post_http,
                "http-content": self.masscan_post_http_content,
                "s7-info": self.masscan_post_s7info,
                "ssl-cert": self.masscan_post_x509,
                "ssl-cacert": self.masscan_post_x509,
                "ssh-banner": self.masscan_post_ssh,
            }[script["id"]]
        except KeyError:
            return None
        return function(script)

    def masscan_post_s7info(self, script):
        try:
            data = self._from_binary(script["masscan"]["raw"])
        except KeyError:
            return
        try:
            service_info, output_text, output_data = masscan_parse_s7info(data)
        except TypeError:
            script["id"] = "banner"
            return
        self._curport.update(service_info)
        if output_data:
            script["output"] = "\n".join(output_text)
            script[script["id"]] = output_data

    @staticmethod
    def _read_ssh_msgs(data):
        while data:
            if len(data) < 4:
                utils.LOGGER.warning("Incomplete SSH message [%r]", data)
                return
            length = struct.unpack(">I", data[:4])[0]
            data = data[4:]
            if len(data) < length:
                utils.LOGGER.warning(
                    "Incomplete SSH message [%r] expected " "length %d", data, length
                )
                return
            curdata, data = data[:length], data[length:]
            if length < 2:
                utils.LOGGER.warning("SSH message too short (%d < 2)", length)
                continue
            padlen = struct.unpack("B", curdata[:1])[0]
            if len(curdata) < padlen + 1:
                utils.LOGGER.warning(
                    "Incomplete SSH message [%r] padding " "length %d", curdata, padlen
                )
                continue
            curdata = curdata[1:-padlen]
            if not curdata:
                utils.LOGGER.warning("Empty SSH message")
                continue
            msgtype, curdata = struct.unpack("B", curdata[:1])[0], curdata[1:]
            if msgtype == 21:
                # new keys, messages after this will be encrypted
                if curdata:
                    utils.LOGGER.warning("Non-empty SSH message [%r]", curdata)
                return
            yield msgtype, curdata

    _ssh_key_exchange_data = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ]

    _ssh_key_exchange_data_pairs = [
        "encryption_algorithms",
        "mac_algorithms",
        "compression_algorithms",
        "languages",
    ]

    @classmethod
    def _read_ssh_key_exchange_init(cls, data):
        # cookie
        if len(data) < 16:
            utils.LOGGER.warning(
                "SSH key exchange init message too " "short [%r] (len == %d < 16)",
                data,
                len(data),
            )
            return
        data = data[16:]
        keys = cls._ssh_key_exchange_data[::-1]
        while data and keys:
            if len(data) < 4:
                utils.LOGGER.warning(
                    "Incomplete SSH key exchange init message" " part [%r]", data
                )
                return
            length = struct.unpack(">I", data[:4])[0]
            data = data[4:]
            curdata, data = data[:length], data[length:]
            if curdata:
                yield keys.pop(), utils.nmap_encode_data(curdata).split(",")
            else:
                yield keys.pop(), []

    def masscan_post_ssh(self, script):
        script["id"] = "banner"
        try:
            data = self._from_binary(script["masscan"]["raw"])
        except KeyError:
            return
        try:
            idx = data.index(b"\n")
        except ValueError:
            return
        script["output"] = utils.nmap_encode_data(data[:idx].rstrip(b"\r"))
        if "service_product" not in self._curport:
            # some Nmap fingerprints won't match with data after the
            # banner
            match = utils.match_nmap_svc_fp(
                output=data[: idx + 1], proto=self._curport["protocol"], probe="NULL"
            )
            if match:
                for cpe in match.pop("cpe", []):
                    self._add_cpe_to_host(cpe=cpe)
                self._curport.update(match)
        # this requires a patched version of masscan
        for msgtype, msg in self._read_ssh_msgs(data[idx + 1 :]):
            if msgtype == 20:  # key exchange init
                ssh2_enum_out = [""]
                ssh2_enum = dict(self._read_ssh_key_exchange_init(msg))
                for key in self._ssh_key_exchange_data_pairs:
                    keyc2s, keys2c = (
                        "%s_client_to_server" % key,
                        "%s_server_to_client" % key,
                    )
                    if keyc2s in ssh2_enum and ssh2_enum[keyc2s] == ssh2_enum.get(
                        keys2c
                    ):
                        ssh2_enum[key] = ssh2_enum.pop(keyc2s)
                        del ssh2_enum[keys2c]
                # preserve output order
                for key in [
                    "kex_algorithms",
                    "server_host_key_algorithms",
                    "encryption_algorithms",
                    "encryption_algorithms_client_to_server",
                    "encryption_algorithms_server_to_client",
                    "mac_algorithms",
                    "mac_algorithms_client_to_server",
                    "mac_algorithms_server_to_client",
                    "compression_algorithms",
                    "compression_algorithms_client_to_server",
                    "compression_algorithms_server_to_client",
                    "languages",
                    "languages_client_to_server",
                    "languages_server_to_client",
                ]:
                    if key in ssh2_enum:
                        value = ssh2_enum[key]
                        ssh2_enum_out.append("  %s (%d)" % (key, len(value)))
                        ssh2_enum_out.extend("      %s" % v for v in value)
                ssh2_enum_out, ssh2_enum = change_ssh2_enum_algos(
                    "\n".join(ssh2_enum_out),
                    ssh2_enum,
                )
                self._curport.setdefault("scripts", []).append(
                    {
                        "id": "ssh2-enum-algos",
                        "output": ssh2_enum_out,
                        "ssh2-enum-algos": ssh2_enum,
                    }
                )
                continue
            if msgtype == 31:
                host_key_length = struct.unpack(">I", msg[:4])[0]
                host_key_length_data = msg[4 : 4 + host_key_length]
                info = utils.parse_ssh_key(host_key_length_data)
                # TODO this might be somehow factorized with
                # view.py:_extract_passive_SSH_SERVER_HOSTKEY()
                value = utils.encode_b64(host_key_length_data).decode()
                try:
                    ssh_hostkey = {"type": info["algo"], "key": value}
                except KeyError:
                    continue
                if "bits" in info:
                    ssh_hostkey["bits"] = info["bits"]
                ssh_hostkey["fingerprint"] = info["md5"]
                fingerprint = utils.decode_hex(info["md5"])
                self._curport.setdefault("scripts", []).append(
                    {
                        "id": "ssh-hostkey",
                        "ssh-hostkey": [ssh_hostkey],
                        "output": "\n  %s %s (%s)\n%s %s"
                        % (
                            ssh_hostkey.get("bits", "-"),
                            ":".join(
                                "%02x" % (ord(i) if isinstance(i, (bytes, str)) else i)
                                for i in fingerprint
                            ),
                            {"ecdsa-sha2-nistp256": "ECDSA"}.get(
                                ssh_hostkey["type"],
                                (
                                    ssh_hostkey["type"][4:]
                                    if ssh_hostkey["type"][:4] == "ssh-"
                                    else ssh_hostkey["type"]
                                ).upper(),
                            ),
                            ssh_hostkey["type"],
                            value,
                        ),
                    }
                )
                continue

    def masscan_post_x509(self, script):
        try:
            data = self._from_binary(script["masscan"]["raw"])
        except KeyError:
            return
        try:
            output_text, output_data = create_ssl_cert(data)
        except Exception:
            utils.LOGGER.warning("Cannot parse certificate %r", data, exc_info=True)
            return
        if output_data:
            script["output"] = output_text
            script["ssl-cert"] = output_data
            if script["id"] == "ssl-cert":
                for cert in output_data:
                    add_cert_hostnames(
                        cert,
                        self._curhost.setdefault("hostnames", []),
                    )

    def masscan_post_http(self, script):
        raw = self._from_binary(script["masscan"]["raw"])
        self._curport["service_name"] = "http"
        match = utils.match_nmap_svc_fp(
            raw,
            proto="tcp",
            probe="GetRequest",
        )
        if match:
            for cpe in match.pop("cpe", []):
                self._add_cpe_to_host(cpe=cpe)
        self._curport.update(match)
        try:
            script["http-headers"] = [
                {
                    "name": "_status",
                    "value": utils.nmap_encode_data(raw.split(b"\n", 1)[0].strip()),
                }
            ]
        except IndexError:
            script["http-headers"] = []
        script["http-headers"].extend(
            {
                "name": utils.nmap_encode_data(hdrname).lower(),
                "value": utils.nmap_encode_data(hdrval),
            }
            for hdrname, hdrval in (
                m.groups()
                for m in (
                    _HTTP_HEADER.search(part.strip()) for part in raw.split(b"\n")
                )
                if m
            )
        )
        handle_http_headers(self._curhost, self._curport, script["http-headers"])

    def masscan_post_http_content(self, script):
        self._curport["service_name"] = "http"
        raw = self._from_binary(script["masscan"]["raw"])
        script_http_ls = create_http_ls(script["output"])
        service_elasticsearch = create_elasticsearch_service(script["output"])
        script["output"] = utils.nmap_encode_data(raw)
        if script_http_ls:
            self._curport.setdefault("scripts", []).append(script_http_ls)
        if service_elasticsearch:
            if "hostname" in service_elasticsearch:
                add_hostname(
                    service_elasticsearch.pop("hostname"),
                    "service",
                    self._curhost.setdefault("hostnames", []),
                )
            for cpe in service_elasticsearch.pop("cpe", []):
                self._add_cpe_to_host(cpe=cpe)
            self._curport.update(service_elasticsearch)

    def _add_cpe_to_host(self, cpe=None):
        """Adds the cpe (from `cpe` or from self._curdata) to the host-wide
        cpe list, taking port/script/osmatch context into account.

        """
        if cpe is None:
            cpe = self._curdata
            self._curdata = None
        path = None

        # What is the path to reach this CPE?
        if self._curport is not None:
            if self._curscript is not None and "id" in self._curscript:
                # Should not happen, but handle the case anyway
                path = "ports{port:%s, scripts.id:%s}" % (
                    self._curport["port"],
                    self._curscript["id"],
                )
            else:
                path = "ports.port:%s" % self._curport["port"]

        elif self._curscript is not None and "id" in self._curscript:
            # Host-wide script
            path = "scripts.id:%s" % self._curscript["id"]

        elif "os" in self._curhost and self._curhost["os"].get(
            "osmatch", []
        ):  # Host-wide
            lastosmatch = self._curhost["os"]["osmatch"][-1]
            line = lastosmatch["line"]
            path = "os.osmatch.line:%s" % line

        # CPEs are indexed in a dictionary to agglomerate origins, but
        # this dict is replaced with its values() in _pre_addhost.
        cpes = self._curhost.setdefault("cpes", {})
        if cpe not in cpes:
            try:
                cpeobj = cpe2dict(cpe)
            except ValueError:
                utils.LOGGER.warning("Invalid cpe format (%s)", cpe)
                return
            cpes[cpe] = cpeobj
        else:
            cpeobj = cpes[cpe]
        cpeobj.setdefault("origins", set()).add(path)

    def characters(self, content):
        if self._curdata is not None:
            self._curdata += content


class Nmap2Txt(NmapHandler):

    """Simple "test" handler, outputs resulting JSON as text."""

    def __init__(self, fname, _, **kargs):
        # db argument is given for compatibility with Nmap2DB but
        # unused here
        self._db = []
        super().__init__(fname, **kargs)

    @staticmethod
    def _to_binary(data):
        return utils.encode_b64(data)

    @staticmethod
    def _from_binary(data):
        return utils.decode_b64(data)

    def _addhost(self):
        self._db.append(self._curhost)


class Nmap2DB(NmapHandler):

    """Specific handler for MongoDB backend."""

    def __init__(
        self,
        fname,
        db,
        categories=None,
        source=None,
        callback=None,
        add_addr_infos=True,
        **kargs,
    ):
        self._db = db
        if categories is None:
            self.categories = []
        else:
            self.categories = categories
        self._add_addr_infos = add_addr_infos
        self.source = source
        self.callback = callback
        NmapHandler.__init__(
            self,
            fname,
            categories=categories,
            source=source,
            add_addr_infos=add_addr_infos,
            **kargs,
        )

    def _to_binary(self, data):
        return self._db.nmap.to_binary(data)

    def _from_binary(self, data):
        return self._db.nmap.from_binary(data)

    def _addhost(self):
        if self.categories:
            self._curhost["categories"] = self.categories[:]
        if self._add_addr_infos:
            self._curhost["infos"] = {}
            for func in [
                self._db.data.country_byip,
                self._db.data.as_byip,
                self._db.data.location_byip,
            ]:
                self._curhost["infos"].update(func(self._curhost["addr"]) or {})
        if self.source:
            self._curhost["source"] = self.source
        # We are about to insert data based on this file, so we want
        # to save the scan document
        if not self.scan_doc_saved:
            self.scan_doc_saved = True
            self._storescan()
        self._db.nmap.store_or_merge_host(self._curhost)
        if self.callback is not None:
            self.callback(self._curhost)

    def _storescan(self):
        ident = self._db.nmap.store_scan_doc(self._curscan)
        return ident

    def _updatescan(self, curscan_more):
        self._db.nmap.update_scan_doc(self._filehash, curscan_more)

    def _addscaninfo(self, i):
        if "numservices" in i:
            i["numservices"] = int(i["numservices"])
        self._curscan.setdefault("scaninfos", []).append(i)
