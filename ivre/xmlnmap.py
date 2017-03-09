#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
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

"""
This module is part of IVRE.
Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains the parser for nmap's XML output files.

"""

from ivre import utils, config, nmapout
from ivre.analyzer import ike

from xml.sax.handler import ContentHandler, EntityResolver
import datetime
import sys
import os
import re

SCHEMA_VERSION = 8

# Scripts that mix elem/table tags with and without key attributes,
# which is not supported for now
IGNORE_TABLE_ELEMS = set(['xmpp-info', 'sslv2'])

ALIASES_TABLE_ELEMS = {
    # ls unified output (ls NSE module)
    "afp-ls": "ls",
    "http-ls": "ls",
    "nfs-ls": "ls",
    "smb-ls": "ls",
    "ftp-anon": "ls",
    # vulns unified output (vulns NSE module)
    "afp-path-vuln": "vulns",
    "distcc-cve2004-2687": "vulns",
    "ftp-libopie": "vulns",
    "ftp-vsftpd-backdoor": "vulns",
    "ftp-vuln-cve2010-4221": "vulns",
    "http-avaya-ipoffice-users": "vulns",
    "http-cross-domain-policy": "vulns",
    "http-dlink-backdoor": "vulns",
    "http-frontpage-login": "vulns",
    "http-huawei-hg5xx-vuln": "vulns",
    "http-iis-short-name-brute": "vulns",
    "http-method-tamper": "vulns",
    "http-phpmyadmin-dir-traversal": "vulns",
    "http-phpself-xss": "vulns",
    "http-shellshock": "vulns",
    "http-slowloris-check": "vulns",
    "http-tplink-dir-traversal": "vulns",
    "http-vuln-cve2006-3392": "vulns",
    "http-vuln-cve2009-3960": "vulns",
    "http-vuln-cve2010-2861": "vulns",
    "http-vuln-cve2011-3192": "vulns",
    "http-vuln-cve2011-3368": "vulns",
    "http-vuln-cve2012-1823": "vulns",
    "http-vuln-cve2013-0156": "vulns",
    "http-vuln-cve2013-6786": "vulns",
    "http-vuln-cve2013-7091": "vulns",
    "http-vuln-cve2014-2126": "vulns",
    "http-vuln-cve2014-2127": "vulns",
    "http-vuln-cve2014-2128": "vulns",
    "http-vuln-cve2014-2129": "vulns",
    "http-vuln-cve2014-3704": "vulns",
    "http-vuln-cve2014-8877": "vulns",
    "http-vuln-cve2015-1427": "vulns",
    "http-vuln-cve2015-1635": "vulns",
    "http-vuln-misfortune-cookie": "vulns",
    "http-vuln-wnr1000-creds": "vulns",
    "mysql-vuln-cve2012-2122": "vulns",
    "qconn-exec": "vulns",
    "rdp-vuln-ms12-020": "vulns",
    "rmi-vuln-classloader": "vulns",
    "samba-vuln-cve-2012-1182": "vulns",
    "smb-vuln-conficker": "vulns",
    "smb-vuln-cve2009-3103": "vulns",
    "smb-vuln-ms06-025": "vulns",
    "smb-vuln-ms07-029": "vulns",
    "smb-vuln-ms08-067": "vulns",
    "smb-vuln-ms10-054": "vulns",
    "smb-vuln-ms10-061": "vulns",
    "smb-vuln-regsvc-dos": "vulns",
    "smtp-vuln-cve2011-1720": "vulns",
    "smtp-vuln-cve2011-1764": "vulns",
    "ssl-ccs-injection": "vulns",
    "ssl-dh-params": "vulns",
    "ssl-heartbleed": "vulns",
    "ssl-poodle": "vulns",
    "supermicro-ipmi-conf": "vulns",
}

SCREENSHOT_PATTERN = re.compile('^ *Saved to (.*)$', re.MULTILINE)
RTSP_SCREENSHOT_PATTERN = re.compile('^ *Saved [^ ]* to (.*)$', re.MULTILINE)

def screenshot_extract(script):
    fname = (RTSP_SCREENSHOT_PATTERN if script['id'] == 'rtsp-screenshot'
             else SCREENSHOT_PATTERN).search(script['output'])
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
    "code": lambda x: (_MONGODB_DATABASES_CONVERTS.get(x, x)
                       if isinstance(x, basestring) else float(x)),
    "ok": lambda x: (_MONGODB_DATABASES_CONVERTS.get(x, x)
                     if isinstance(x, basestring) else float(x)),
}

def _parse_mongodb_databases_kv(line, out, prefix=None, force_type=None,
                                value_name=None):
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
        out.append({"name": key,
                    value_name: value})


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
        indent = (length - len(line)) / 2

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
            _parse_mongodb_databases_kv(line, out["databases"][-1]["shards"],
                                        force_type=float, value_name="size")
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
        utils.LOGGER.warning("Migration not implemented for script %r",
                             script['id'])
        raise NotImplementedError
    return {
        "smb-ls": add_smb_ls_data,
        "nfs-ls": add_nfs_ls_data,
        "afp-ls": add_afp_ls_data,
        "ftp-anon": add_ftp_anon_data,
        # http-ls has used the "ls" module since the beginning
    }.get(script['id'], notimplemented)(script)

def add_smb_ls_data(script):
    """This function converts output from smb-ls that do not include a
    structured output to a structured output similar to the one
    provided by the "ls" NSE module.

    This function is not perfect but should do the job in most
    cases.

    """
    assert script["id"] == "smb-ls"
    result = {"total": {"files": 0, "bytes": 0}, "volumes": []}
    state = 0 # outside a volume
    cur_vol = None
    for line in script["output"].splitlines():
        line = line.lstrip()
        if state == 0: # outside a volume
            if line.startswith('Directory of '):
                if cur_vol is not None:
                    utils.LOGGER.warning("cur_vol should be None here [got %r]",
                                         cur_vol)
                cur_vol = {"volume": line[13:], "files": []}
                state = 1 # listing
            elif line:
                utils.LOGGER.warning("Unexpected line [%r] outside a volume",
                                     line)
        elif state == 1: # listing
            if line == "Total Files Listed:":
                state = 2 # total values
            elif line:
                date, time, size, fname = line.split(None, 3)
                if size.isdigit():
                    size = int(size)
                    result["total"]["bytes"] += size
                cur_vol["files"].append({"size": size, "filename": fname,
                                         'time': "%s %s" % (date, time)})
                result["total"]["files"] += 1
        elif state == 2: # total values
            if line:
                # we do not use this data
                pass
            else:
                state = 0 # outside a volume
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
    state = 0 # outside a volume
    cur_vol = None
    for line in script["output"].splitlines():
        line = line.lstrip()
        if state == 0: # outside a volume
            if line.startswith('NFS Export: '):
                if cur_vol is not None:
                    utils.LOGGER.warning("cur_vol should be None here [got %r]",
                                         cur_vol)
                cur_vol = {"volume": line[12:], "files": []}
                state = 1 # volume info
            # We silently discard any other lines
        elif state == 1: # volume info
            if line.startswith('NFS '):
                cur_vol.setdefault('info', []).append(
                    line[4].lower() + line[5:])
            elif line.startswith('PERMISSION'):
                state = 2 # listing
            # We silently discard any other lines
        elif state == 2: # listing
            if line:
                permission, uid, gid, size, time, fname = line.split(None, 5)
                if size.isdigit():
                    size = int(size)
                    result["total"]["bytes"] += size
                cur_vol["files"].append({"permission": permission,
                                         "uid": uid, "gid": gid,
                                         "size": size, "time": time,
                                         "filename": fname})
                result["total"]["files"] += 1
            else:
                state = 0 # outsize a volume
                result["volumes"].append(cur_vol)
                cur_vol = None
    if state == 2:
        state = 0 # outsize a volume
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
    state = 0 # volumes / listings
    cur_vol = None
    for line in script["output"].splitlines():
        if state == 0:
            if line.startswith('    PERMISSION'):
                pass
            elif line.startswith('    '):
                if cur_vol is None:
                    utils.LOGGER.warning("Skip file entry outside a "
                                         "volume [%r]", line[4:])
                else:
                    (permission, uid, gid, size, date, time,
                     fname) = line[4:].split(None, 6)
                    if size.isdigit():
                        size = int(size)
                        result["total"]["bytes"] += size
                    cur_vol["files"].append({"permission": permission,
                                             "uid": uid, "gid": gid,
                                             "size": size, "filename": fname,
                                             'time': "%s %s" % (date, time)})
                    result["total"]["files"] += 1
            elif line.startswith("  ERROR: "):
                # skip error messages, same as when running without
                # setting ls.errors=true
                pass
            elif line == "  ":
                state = 1 # end of volumes
            elif line.startswith("  "):
                result["volumes"].append(cur_vol)
                cur_vol = {"volume": line[2:], "files": []}
        elif state == 1:
            if line.startswith("  "):
                result.setdefault("info", []).append(line[3].lower()
                                                     + line[4:])
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
        "user": ('(?:[a-zA-Z0-9\\._-]+(?:\\s+[NLOPQS])?|\\\\x[0-9A-F]{2}|'
                 '\\*|\\(\\?\\))'),
        "fname": '[A-Za-z0-9%s]+' % re.escape(" ?._@[](){}~#'&$%!+\\-/,|`="),
        "perm": '[a-zA-Z\\?-]{10}',
        "day": '[0-3]?[0-9]',
        "year": "[0-9]{2,4}",
        "month": "(?:[0-1]?[0-9]|[A-Z][a-z]{2}|[A-Z]{3})",
        "time": "[0-9]{1,2}\\:[0-9]{2}(?:\\:[0-9]{1,2})?",
        "windate": "[0-9]{2}-[0-9]{2}-[0-9]{2,4} +[0-9]{2}:[0-9]{2}(?:[AP]M)?",
        "vxworksdate": ("[A-Z][a-z]{2}-[0-9]{2}-[0-9]{2,4}\\s+"
                        "[0-9]{2}:[0-9]{2}:[0-9]{2}"),
    }
    subexprs["date"] = "(?:%s)" % "|".join([
        "%(month)s\\s+%(day)s\\s+(?:%(year)s|%(time)s)" % subexprs,
        "%(day)s\\.\\s+%(month)s\\s+%(time)s" % subexprs,
    ])
    exprs = re.compile("^(?:" + "|".join([
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
    ]) + ")(?: \\[NSE: writeable\\])?$", re.MULTILINE)
    result = {"total": {"files": 0, "bytes": 0}, "volumes": []}
    cur_vol = {"volume": "/", "files": []}
    for fileentry in exprs.finditer(script["output"]):
        fileentry = dict([key.split('_', 1)[1], value]
                         for key, value in fileentry.groupdict().iteritems()
                         if value is not None)
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

ADD_TABLE_ELEMS = {
    'modbus-discover':
    re.compile('^ *DEVICE IDENTIFICATION: *(?P<deviceid>.*?) *$', re.M),
    'ls': add_ls_data,
    'mongodb-databases': add_mongodb_databases_data,
}

def change_smb_enum_shares(table):
    """Adapt structured data from script smb-enum-shares so that it is
    easy to query when inserted in DB.

    """
    if not table:
        return table
    result = {}
    for field in ["account_used", "note"]:
        if field in table:
            result[field] = table.pop(field)
    result["shares"] = []
    for key, value in table.iteritems():
        value.update({"Share": key})
        result["shares"].append(value)
    return result

def change_ls(table):
    """Adapt structured data from "ls" NSE module to convert some
    fields to integers.

    """
    if 'total' in table:
        for field in ['files', 'bytes']:
            if field in table['total'] and table['total'][field].isdigit():
                table['total'][field] = int(table['total'][field])
    for volume in table.get('volumes', []):
        for fileentry in volume.get('files', []):
            if 'size' in fileentry and fileentry['size'].isdigit():
                fileentry['size'] = int(fileentry['size'])
    return table

def change_vulns(table):
    """Adapt structured output generated by "vulns" NSE module."""
    return [dict(tab, id=vulnid) for vulnid, tab in table.iteritems()]

CHANGE_TABLE_ELEMS = {
    'smb-enum-shares': change_smb_enum_shares,
    'ls': change_ls,
    'vulns': change_vulns,
}

IGNORE_SCRIPTS = {
    'mcafee-epo-agent': set(['ePO Agent not found']),
    'ftp-bounce': set(['no banner']),
    'telnet-encryption': set(['\n  ERROR: Failed to send packet: TIMEOUT']),
    'http-mobileversion-checker': set(['No mobile version detected.']),
    'http-referer-checker': set(["Couldn't find any cross-domain scripts."]),
    'http-default-accounts': set([
        '[ERROR] HTTP request table is empty. This should not happen '
        'since we at least made one request.',
    ]),
    'http-headers': set(['\n  (Request type: GET)\n']),
    'http-cisco-anyconnect': set([
        '\n  ERROR: Not a Cisco ASA or unsupported version',
    ]),
    'ndmp-fs-info': set([
        '\n  ERROR: Failed to get filesystem information from server',
    ]),
    'ndmp-version': set([
        '\n  ERROR: Failed to get host information from server',
    ]),
    'ajp-auth': set(['\n  ERROR: Failed to connect to AJP server']),
    'ajp-headers': set(['\n  ERROR: Failed to retrieve server headers']),
    'ajp-methods': set([
        'Failed to get a valid response for the OPTION request',
    ]),
    'ajp-request': set([
        '\n  ERROR: Failed to retrieve response for request',
        '\n  ERROR: Failed to connect to AJP server',
    ]),
    'giop-info': set(['  \n  ERROR: Failed to read Packet.GIOP']),
    'rsync-list-modules': set([
        '\n  ERROR: Failed to connect to rsync server',
        '\n  ERROR: Failed to retrieve a list of modules',
    ]),
    'sip-methods': set(['ERROR: Failed to connect to the SIP server.']),
    'sip-call-spoof': set(['ERROR: Failed to connect to the SIP server.']),
    'rpcap-info': set(['\n  ERROR: EOF']),
    'rmi-dumpregistry': set(['Registry listing failed (Handshake failed)']),
    'voldemort-info': set(['\n  ERROR: Unsupported protocol']),
    'irc-botnet-channels': set(['\n  ERROR: EOF\n']),
    'bitcoin-getaddr': set([
        '\n  ERROR: Failed to extract address information',
        '\n  ERROR: Failed to extract version information',
    ]),
    'bitcoin-info': set(['\n  ERROR: Failed to extract version information']),
    'drda-info': set(['The response contained no EXCSATRD']),
    'rdp-enum-encryption': set(['Received unhandled packet']),
    'ldap-search': set(['ERROR: Failed to bind as the anonymous user']),
    'mongodb-databases': set([
        'No Bson data returned',
    ]),
    # fixed in nmap commit 95f7b76d9f12d10832523e6f3db0e602a04b3a12
    # https://github.com/nmap/nmap/commit/95f7b76d9f12d10832523e6f3db0e602a04b3a12
    'snmp-hh3c-logins': set(['\n  baseoid: 1.3.6.1.4.1.25506.2.12.1.1.1']),
    'dns-nsec-enum': set(['\n  No NSEC records found\n']),
    'dns-nsec3-enum': set(['\n  DNSSEC NSEC3 not supported\n']),
    'http-csrf': set(["Couldn't find any CSRF vulnerabilities."]),
    'http-devframework': set([
        "Couldn't determine the underlying framework or CMS. Try increasing "
        "'httpspider.maxpagecount' value to spider more pages.",
    ]),
    'http-dombased-xss': set(["Couldn't find any DOM based XSS."]),
    'http-drupal-enum': set([
        'Nothing found amongst the top 100 resources,use '
        '--script-args number=<number|all> for deeper analysis)',
    ]),
    'http-errors': set(["Couldn't find any error pages."]),
    'http-feed': set(["Couldn't find any feeds."]),
    'http-litespeed-sourcecode-download': set([
        'Request with null byte did not work. This web server might not be '
        'vulnerable',
        'Page: /index.php was not found. Try with an existing file.',
    ]),
    'http-sitemap-generator': set([
        '\n  Directory structure:\n    /\n      Other: 1\n  Longest directory '
        'structure:\n    Depth: 0\n    Dir: /\n  Total files found (by '
        'extension):\n    Other: 1\n',
        '\n  Directory structure:\n  Longest directory structure:\n    '
        'Depth: 0\n    Dir: /\n  Total files found (by extension):\n    \n',
    ]),
    'http-stored-xss': set(["Couldn't find any stored XSS vulnerabilities."]),
    'http-wordpress-enum': set([
        'Nothing found amongst the top 100 resources,use '
        '--script-args search-limit=<number|all> for deeper analysis)',
    ]),
    'http-wordpress-users': set(["[Error] Wordpress installation was not found"
                                 ". We couldn't find wp-login.php"]),
    'ssl-date': set(['TLS randomness does not represent time']),
    # host scripts
    'firewalk': set(['None found']),
    'ipidseq': set(['Unknown']),
    'fcrdns': set(['FAIL (No PTR record)']),
    'msrpc-enum': set(['SMB: ERROR: Server disconnected the connection']),
    'smb-mbenum': set(['\n  ERROR: Failed to connect to browser service: '
                       'SMB: ERROR: Server disconnected the connection']),
}

IGNORE_SCRIPTS_IDS = set(["http-screenshot", "mainframe-screenshot",
                          "rtsp-screenshot", "vnc-screenshot",
                          "x11-screenshot"])

MSSQL_ERROR = re.compile('^ *(ERROR: )?('
                         'No login credentials|'
                         'TCP: Socket connection failed, Named Pipes: '
                         'No named pipe for this instance'
                         ')\\.?$',
                         re.MULTILINE)

IGNORE_SCRIPTS_REGEXP = {
    'smtp-commands': re.compile(
        "^" + re.escape("Couldn't establish connection on port ") + "[0-9]+$"
    ),
    'ms-sql-config': MSSQL_ERROR,
    'ms-sql-dump-hashes': MSSQL_ERROR,
    'ms-sql-hasdbaccess': MSSQL_ERROR,
    'ms-sql-query': MSSQL_ERROR,
    'ms-sql-tables': MSSQL_ERROR,
    'irc-botnet-channels': re.compile(
        "^" + re.escape("\n  ERROR: Closing Link: ")
    ),
    'http-php-version': re.compile(
        '^(Logo query returned unknown hash [0-9a-f]{32}\\\n'
        'Credits query returned unknown hash [0-9a-f]{32}|'
        '(Logo|Credits) query returned unknown hash '
        '[0-9a-f]{32})$'
    ),
    'p2p-conficker': re.compile(
        re.escape('Host is CLEAN or ports are blocked')
    ),
    'dns-nsec-enum': re.compile(
        "^" + re.escape("Can't determine domain for host ") + ".*" +
        re.escape("; use dns-nsec-enum.domains script arg.") + "$"
    ),
    'dns-nsec3-enum': re.compile(
        "^" + re.escape("Can't determine domain for host ") + ".*" +
        re.escape("; use dns-nsec3-enum.domains script arg.") + "$"
    ),
    'http-vhosts': re.compile(
        "^\\\n[0-9]+" + re.escape(" names had status ") +
        ("(?:[0-9]{3}|ERROR)")
    ),
    'http-fileupload-exploiter': re.compile(
        "^(" + re.escape("\n  \n    Couldn't find a file-type field.") + ")*$"
    ),
}

IGNORE_SCRIPT_OUTPUTS = set([
    'Unable to open connection',
    'false',
    'TIMEOUT',
    'ERROR',
    '\n',
    '\r\n',
])

IGNORE_SCRIPT_OUTPUTS_REGEXP = set([
    # MD5(<empty>)
    re.compile('d41d8cd98f00b204e9800998ecf8427e', re.IGNORECASE),
    re.compile(
        '^ *ERROR\\:\\ ('
        'Failed\\ to\\ (connect\\ to|receive\\ response\\ from)\\ server|'
        'Script\\ execution\\ failed\\ \\(use\\ \\-d\\ to\\ debug\\)|'
        'Receiving\\ packet\\:\\ (ERROR|EOF)|'
        'Failed\\ to\\ send\\ packet\\:\\ ERROR|'
        'ERROR)', re.MULTILINE
    ),
    re.compile('^ *(SMB|ERROR):.*TIMEOUT', re.MULTILINE)
])

MASSCAN_SERVICES_NMAP_SCRIPTS = {
    "http": "http-headers",
    "title": "http-title",
    "ftp": "banner",
    "unknown": "banner",
    "ssh": "banner",
    "vnc": "banner",
    "imap": "banner",
    "pop": "banner",
    "X509": "ssl-cert"
}

MASSCAN_NMAP_SCRIPT_NMAP_PROBES = {
    "tcp": {
        "banner": ["NULL"],
        "http-headers": ["GetRequest"],
    },
}

NMAP_FINGERPRINT_IVRE_KEY = {
    # TODO: cpe
    'd': 'service_devicetype',
    'h': 'service_hostname',
    'i': 'service_extrainfo',
    'o': 'service_ostype',
    'p': 'service_product',
    'v': 'service_version',
}

MASSCAN_SERVICES_NMAP_SERVICES = {
    "ftp": "ftp",
    "http": "http",
    "ssh": "ssh",
    "vnc": "vnc",
    "imap": "imap",
    "pop": "pop3",
}

MASSCAN_ENCODING = re.compile(re.escape("\\x") + "([0-9a-f]{2})")

def _masscan_decode_print(match):
    char = match.groups()[0].decode('hex')
    return (char if (32 <= ord(char) <= 126 or char in "\t\r\n")
            else match.group())

def _masscan_decode_raw(match):
    return match.groups()[0].decode('hex')

def masscan_x509(output):
    """Produces an output similar to Nmap script ssl-cert from Masscan
X509 "service" tag.

    XXX WORK IN PROGRESS"""
    certificate = output.decode('base64')
    newout = []
    for hashtype, hashname in [('md5', 'MD5:'), ('sha1', 'SHA-1:')]:
        hashvalue = hashlib.new(hashtype, cert).hexdigest()
        newout.append('%-7s%s\n' % (
            hashname,
            ' '.join(hashvalue[i:i + 4] for i in xrange(0, len(hashvalue), 4))),
        )
    b64cert = certificate.encode('base64')
    newout.append('-----BEGIN CERTIFICATE-----\n')
    newout.extend('%s\n' % b64cert[i:i + 64] for i in xrange(0, len(b64cert), 64))
    newout.append('-----END CERTIFICATE-----\n')
    return "".join(newout)


def ignore_script(script):
    """Predicate that decides whether an Nmap script should be ignored
    or not, based on IGNORE_* constants. Nmap scripts are ignored when
    their output is known to be irrelevant.

    """
    sid = script.get('id')
    output = script.get('output')
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
    if output is not None and any(expr.search(output)
                                  for expr in IGNORE_SCRIPT_OUTPUTS_REGEXP):
        return True
    return False


def cpe2dict(cpe_str):
    """Helper function to parse CPEs. This is a very partial/simple parser.

    Raises:
        ValueError if the cpe string is not parsable.

    """
    # Remove prefix
    if not cpe_str.startswith("cpe:/"):
        raise ValueError("invalid cpe format (%s)\n" % cpe_str)
    cpe_body = cpe_str[5:]
    parts = cpe_body.split(":", 3)
    nparts = len(parts)
    if nparts < 2:
        raise ValueError("invalid cpe format (%s)\n" % cpe_str)
    cpe_type = parts[0]
    cpe_vend = parts[1]
    cpe_prod = parts[2] if nparts > 2 else ""
    cpe_vers = parts[3] if nparts > 3 else ""

    ret = {
        "type": cpe_type,
        "vendor": cpe_vend,
        "product": cpe_prod,
        "version": cpe_vers,
    }
    return ret


class NoExtResolver(EntityResolver):

    """A simple EntityResolver that will prevent any external
    resolution.

    """

    def resolveEntity(self, *_):
        return 'file://%s' % os.devnull


class NmapHandler(ContentHandler):

    """The handler for Nmap's XML documents. An abstract class for
    database specific implementations.

    """

    def __init__(self, fname, filehash, needports=False, needopenports=False,
                 masscan_probes=None, **_):
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
        utils.LOGGER.debug("READING %r (%r)", (fname, self._filehash))

    @staticmethod
    def _to_binary(data):
        """Prepare binary data. Subclasses may want to do some kind
        of conversion here.

        """
        return data

    def _pre_addhost(self):
        """Executed before _addhost for host object post-treatment"""
        if 'cpes' in self._curhost:
            cpes = self._curhost['cpes']
            self._curhost['cpes'] = cpes.values()

    def _addhost(self):
        """Subclasses may store self._curhost here."""
        pass

    def _storescan(self):
        """Subclasses may store self._curscan here."""
        pass

    def _addscaninfo(self, _):
        """Subclasses may add scan information (first argument) to
        self._curscan here.

        """
        pass

    def startElement(self, name, attrs):
        if name == 'nmaprun':
            if self._curscan is not None:
                utils.LOGGER.warning("self._curscan should be None at "
                                     "this point (got %r)", self._curscan)
            self._curscan = dict(attrs)
            self.scanner = self._curscan.get("scanner", self.scanner)
            if self.scanner == "masscan":
                # We need to force "merge" mode due to the nature of
                # Masscan results
                self.merge = True
            self._curscan['_id'] = self._filehash
        elif name == 'scaninfo' and self._curscan is not None:
            self._addscaninfo(dict(attrs))
        elif name == 'host':
            if self._curhost is not None:
                utils.LOGGER.warning("self._curhost should be None at "
                                     "this point (got %r)", self._curhost)
            self._curhost = {"schema_version": SCHEMA_VERSION}
            if self._curscan:
                self._curhost['scanid'] = self._curscan['_id']
            for attr in attrs.keys():
                self._curhost[attr] = attrs[attr]
            for field in ['starttime', 'endtime']:
                if field in self._curhost:
                    self._curhost[field] = datetime.datetime.utcfromtimestamp(
                        int(self._curhost[field])
                    )
            if 'starttime' not in self._curhost and 'endtime' in self._curhost:
                # Masscan
                self._curhost['starttime'] = self._curhost['endtime']
        elif name == 'address' and self._curhost is not None:
            if attrs['addrtype'] != 'ipv4':
                self._curhost.setdefault(
                    'addresses', {}).setdefault(
                        attrs['addrtype'], []).append(attrs['addr'])
            else:
                try:
                    self._curhost['addr'] = utils.ip2int(attrs['addr'])
                except utils.socket.error:
                    self._curhost['addr'] = attrs['addr']
        elif name == 'hostnames':
            if self._curhostnames is not None:
                utils.LOGGER.warning("self._curhostnames should be None at this"
                                     "point (got %r)", self._curhostnames)
            self._curhostnames = []
        elif name == 'hostname':
            if self._curhostnames is None:
                utils.LOGGER.warning("self._curhostnames should NOT be "
                                     "None at this point")
                self._curhostnames = []
            hostname = dict(attrs)
            if 'name' in attrs:
                hostname['domains'] = list(utils.get_domains(attrs['name']))
            self._curhostnames.append(hostname)
        elif name == 'status' and self._curhost is not None:
            self._curhost['state'] = attrs['state']
            if 'reason' in attrs:
                self._curhost['state_reason'] = attrs['reason']
            if 'reason_ttl' in attrs:
                self._curhost['state_reason_ttl'] = int(attrs['reason_ttl'])
        elif name == 'extraports':
            if self._curextraports is not None:
                utils.LOGGER.warning("self._curextraports should be None at "
                                     "this point (got %r)", self._curextraports)
            self._curextraports = {
                attrs['state']: {"total": int(attrs['count']), "reasons": {}},
            }
        elif name == 'extrareasons' and self._curextraports is not None:
            self._curextraports[next(iter(self._curextraports))]["reasons"][
                attrs['reason']] = int(attrs['count'])
        elif name == 'port':
            if self._curport is not None:
                utils.LOGGER.warning("self._curport should be None at this "
                                     "point (got %r)", self._curport)
            self._curport = {'protocol': attrs['protocol'],
                             'port': int(attrs['portid'])}
        elif name == 'state' and self._curport is not None:
            for attr in attrs.keys():
                self._curport['state_%s' % attr] = attrs[attr]
            for field in ['state_reason_ttl']:
                if field in self._curport:
                    self._curport[field] = int(self._curport[field])
            for field in ['state_reason_ip']:
                if field in self._curport:
                    try:
                        self._curport[field] = utils.ip2int(
                            self._curport[field])
                    except utils.socket.error:
                        pass
        elif name == 'service' and self._curport is not None:
            if attrs.get("method") == "table":
                # discard information from nmap-services
                return
            if self.scanner == "masscan":
                banner = attrs["banner"]
                if attrs['name'] == 'vnc' and "=" in attrs["banner"]:
                    # See also https://github.com/robertdavidgraham/masscan/pull/250
                    banner = banner.split(' ')
                    banner, vncinfo = '%s\\x0a' % ' '.join(banner[:2]), banner[2:]
                    if vncinfo:
                        output = []
                        while vncinfo:
                            info = vncinfo.pop(0)
                            if info.startswith('ERROR='):
                                info = 'ERROR: ' + ' '.join(vncinfo)
                                vncinfo = []
                            elif '=[' in info:
                                while vncinfo and not info.endswith(']'):
                                    info += ' ' + vncinfo.pop(0)
                                info = info.replace('=[', ': ', 1)
                                if info.endswith(']'):
                                    info = info[:-1]
                            else:
                                info = info.replace('=', ': ', 1)
                            output.append(info)
                        self._curport.setdefault('scripts', []).append({
                            'id': 'vnc-info', 'output': '\n'.join(output),
                        })
                # create fake scripts from masscan "service" tags
                raw_output = MASSCAN_ENCODING.sub(_masscan_decode_raw,
                                                  str(banner))
                scriptid = MASSCAN_SERVICES_NMAP_SCRIPTS.get(attrs['name'],
                                                             attrs['name'])
                script = {
                    "id": scriptid,
                    "output": MASSCAN_ENCODING.sub(_masscan_decode_print,
                                                   banner),
                    "masscan": {
                        "raw": self._to_binary(raw_output),
                        "encoded": banner,
                    },
                }
                self._curport.setdefault('scripts', []).append(script)
                # get service name
                try:
                    self._curport[
                        'service_name'
                    ] = MASSCAN_SERVICES_NMAP_SERVICES[attrs['name']]
                except KeyError:
                    pass
                if attrs['name'] in ["ssl", "X509"]:
                    self._curport['service_tunnel'] = "ssl"
                self.masscan_post_script(script)
                # attempt to use Nmap service fingerprints
                probes = self.masscan_probes[:]
                probes.extend(MASSCAN_NMAP_SCRIPT_NMAP_PROBES\
                              .get(self._curport['protocol'], {})\
                              .get(scriptid, []))
                softmatch = {}
                for probe in probes:
                    # udp/ike: let's use ike-scan FP
                    if self._curport['protocol'] == 'udp' and \
                       probe in ['ike', 'ike-ipsec-nat-t']:
                        masscan_data = script["masscan"]
                        self._curport.update(ike.analyze_ike_payload(
                            raw_output, probe=probe,
                        ))
                        if self._curport.get('service_name') == 'isakmp':
                            self._curport['scripts'][0]['masscan'] = masscan_data
                        return
                    try:
                        fingerprints = utils.get_nmap_svc_fp(
                            proto=self._curport['protocol'],
                            probe=probe,
                        )['fp']
                    except KeyError:
                        pass
                    else:
                        for service, fingerprint in fingerprints:
                            match = fingerprint['m'][0].search(raw_output)
                            if match is not None:
                                doc = softmatch if fingerprint['soft'] else self._curport
                                doc['service_name'] = service
                                for elt, key in NMAP_FINGERPRINT_IVRE_KEY.iteritems():
                                    if elt in fingerprint:
                                        doc[key] = utils.nmap_svc_fp_format_data(
                                            fingerprint[elt][0], match
                                        )
                                if not fingerprint['soft']:
                                    return
                if softmatch:
                    self._curport.update(softmatch)
                return
            for attr in attrs.keys():
                self._curport['service_%s' % attr] = attrs[attr]
            for field in ['service_conf', 'service_rpcnum',
                          'service_lowver', 'service_highver']:
                if field in self._curport:
                    self._curport[field] = int(self._curport[field])
        elif name == 'script':
            if self._curscript is not None:
                utils.LOGGER.warning("self._curscript should be None at this "
                                     "point (got %r)", self._curscript)
            self._curscript = dict([attr, attrs[attr]]
                                   for attr in attrs.keys())
        elif name in ['table', 'elem']:
            if self._curscript.get('id') in IGNORE_TABLE_ELEMS:
                return
            if name == 'elem':
                # start recording characters
                if self._curdata is not None:
                    utils.LOGGER.warning("self._curdata should be None at this "
                                         "point (got %r)" % self._curdata)
                self._curdata = ''
            if 'key' in attrs:
                key = attrs['key'].replace('.', '_')
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
            if type(k) is int:
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
        elif name == 'os':
            self._curhost['os'] = {}
        elif name == 'portused' and 'os' in self._curhost:
            self._curhost['os']['portused'] = {
                'port': '%s_%s' % (attrs['proto'], attrs['portid']),
                'state': attrs['state'],
            }
        elif name in ['osclass', 'osmatch'] and 'os' in self._curhost:
            self._curhost['os'].setdefault(name, []).append(dict(attrs))
        elif name == 'osfingerprint' and 'os' in self._curhost:
            self._curhost['os']['fingerprint'] = attrs['fingerprint']
        elif name == 'trace':
            if self._curtrace is not None:
                utils.LOGGER.warning("self._curtrace should be None at this "
                                     "point (got %r)", self._curtrace)
            if 'proto' not in attrs:
                self._curtrace = {'protocol': None}
            elif attrs['proto'] in ['tcp', 'udp']:
                self._curtrace = {'protocol': attrs['proto'],
                                  'port': int(attrs['port'])}
            else:
                self._curtrace = {'protocol': attrs['proto']}
            self._curtrace['hops'] = []
        elif name == 'hop' and self._curtrace is not None:
            attrsdict = dict(attrs)
            try:
                attrsdict['ipaddr'] = utils.ip2int(attrs['ipaddr'])
            except utils.socket.error:
                pass
            try:
                attrsdict['rtt'] = float(attrs['rtt'])
            except ValueError:
                pass
            try:
                attrsdict['ttl'] = int(attrs['ttl'])
            except ValueError:
                pass
            if 'host' in attrsdict:
                attrsdict['domains'] = list(
                    utils.get_domains(attrsdict['host']))
            self._curtrace['hops'].append(attrsdict)
        elif name == 'cpe':
            # start recording
            self._curdata = ''

    def endElement(self, name):
        if name == 'nmaprun':
            self._curscan = None
        elif name == 'host':
            # masscan -oX output has no "state" tag
            if self._curhost.get('state', 'up') == 'up' and (
                    not self._needports
                    or 'ports' in self._curhost) and (
                        not self._needopenports
                        or self._curhost.get('openports', {}).get('count')):
                if 'openports' not in self._curhost:
                    self._curhost['openports'] = {'count': 0}
                self._pre_addhost()
                self._addhost()
            self._curhost = None
        elif name == 'hostnames':
            self._curhost['hostnames'] = self._curhostnames
            self._curhostnames = None
        elif name == 'extraports':
            self._curhost.setdefault(
                'extraports', {}).update(self._curextraports)
            self._curextraports = None
        elif name == 'port':
            self._curhost.setdefault('ports', []).append(self._curport)
            if self._curport.get("state_state") == 'open':
                openports = self._curhost.setdefault('openports', {})
                openports['count'] = openports.get('count', 0) + 1
                protoopenports = openports.setdefault(
                    self._curport['protocol'], {})
                protoopenports['count'] = protoopenports.get('count', 0) + 1
                protoopenports.setdefault('ports', []).append(
                    self._curport['port'])
            self._curport = None
        elif name == 'script':
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
                    utils.LOGGER.warning("self._curtablepath should be empty, "
                                         "got [%r]", self._curtablepath)
                self._curtable = {}
                return
            if self._curscript['id'] in SCREENSHOTS_SCRIPTS:
                fname = SCREENSHOTS_SCRIPTS[self._curscript['id']](
                    self._curscript
                )
                if fname is not None:
                    exceptions = []
                    for full_fname in [fname,
                                       os.path.join(
                                           os.path.dirname(self._fname),
                                           fname)]:
                        try:
                            with open(full_fname) as fdesc:
                                data = fdesc.read()
                                trim_result = utils.trim_image(data)
                                if trim_result:
                                    # When trim_result is False, the image no
                                    # longer exists after trim
                                    if trim_result is not True:
                                        # Image has been trimmed
                                        data = trim_result
                                    current['screenshot'] = "field"
                                    current['screendata'] = self._to_binary(
                                        data
                                    )
                                    screenwords = utils.screenwords(data)
                                    if screenwords is not None:
                                        current['screenwords'] = screenwords
                        except Exception:
                            exceptions.append((sys.exc_info(), full_fname))
                        else:
                            exceptions = []
                            break
                    for exc_info, full_fname in exceptions:
                        utils.LOGGER.warning(
                            "Screenshot: exception (scanfile %r, file %r)",
                            self._fname, full_fname, exc_info=exc_info,
                        )
            if ignore_script(self._curscript):
                self._curscript = None
                return
            infokey = self._curscript.get('id', None)
            infokey = ALIASES_TABLE_ELEMS.get(infokey, infokey)
            if self._curtable:
                if self._curtablepath:
                    utils.LOGGER.warning("self._curtablepath should be empty, "
                                         "got [%r]", self._curtablepath)
                if infokey in CHANGE_TABLE_ELEMS:
                    self._curtable = CHANGE_TABLE_ELEMS[infokey](self._curtable)
                self._curscript[infokey] = self._curtable
                self._curtable = {}
            elif infokey in ADD_TABLE_ELEMS:
                infos = ADD_TABLE_ELEMS[infokey]
                if isinstance(infos, utils.REGEXP_T):
                    infos = infos.search(self._curscript.get('output', ''))
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
            current.setdefault('scripts', []).append(self._curscript)
            self._curscript = None
        elif name in ['table', 'elem']:
            if self._curscript.get('id') in IGNORE_TABLE_ELEMS:
                return
            if name == 'elem':
                lastlevel = self._curtable
                for k in self._curtablepath[:-1]:
                    if k is None:
                        lastlevel = lastlevel[-1]
                    else:
                        lastlevel = lastlevel[k]
                k = self._curtablepath[-1]
                if type(k) is int:
                    lastlevel.append(self._curdata)
                else:
                    lastlevel[k] = self._curdata
                if k == 'cpe':
                    self._add_cpe_to_host()
                # stop recording characters
                self._curdata = None
            self._curtablepath.pop()
        elif name == 'hostscript' and 'scripts' in self._curhost:
            # "fake" port element, without a "protocol" key and with the
            # magic value -1 for the "port" key.
            self._curhost.setdefault('ports', []).append({
                "port": -1,
                "scripts": self._curhost.pop('scripts')
            })
        elif name == 'trace':
            self._curhost.setdefault('traces', []).append(self._curtrace)
            self._curtrace = None
        elif name == 'cpe':
            self._add_cpe_to_host()

    def masscan_post_script(self, script):
        try:
            function = {
                "http-headers": self.masscan_post_http,
            }[script['id']]
        except KeyError:
            pass
        else:
            return function(script)

    def masscan_post_http(self, script):
        header = re.search(re.escape('\nServer:') + '[ \\\t]*([^\\\r\\\n]+)\\\r?(?:\\\n|$)',
                           script['masscan']['raw'])
        if header is None:
            return
        header = header.groups()[0]
        self._curport.setdefault('scripts', []).append({
            "id": "http-server-header",
            "output": utils.nmap_encode_data(header),
            "masscan": {
                "raw": self._to_binary(header),
            },
        })
        self._curport['service_product'] = utils.nmap_encode_data(header)


    def _add_cpe_to_host(self):
        """Adds the cpe in self._curdata to the host-wide cpe list, taking
        port/script/osmatch context into account.

        """
        cpe = self._curdata
        self._curdata = None
        path = None

        # What is the path to reach this CPE?
        if self._curport is not None:
            if self._curscript is not None and 'id' in self._curscript:
                # Should not happen, but handle the case anyway
                path = 'ports{port:%s, scripts.id:%s}'\
                        % (self._curport['port'], self._curscript['id'])
            else:
                path = 'ports.port:%s' % self._curport['port']

        elif self._curscript is not None and 'id' in self._curscript:
            # Host-wide script
            path = 'scripts.id:%s' % self._curscript['id']

        elif 'os' in self._curhost and\
                self._curhost['os'].get('osmatch', []): # Host-wide
            lastosmatch = self._curhost['os']['osmatch'][-1]
            line = lastosmatch['line']
            path = "os.osmatch.line:%s" % line

        # CPEs are indexed in a dictionnary to agglomerate origins,
        # but this dict is replaced with its values() in _pre_addhost.
        cpes = self._curhost.setdefault('cpes', {})
        if cpe not in cpes:
            try:
                cpeobj = cpe2dict(cpe)
            except ValueError:
                utils.LOGGER.warning("Invalid cpe format (%s)", cpe)
                return
            cpes[cpe] = cpeobj
        else:
            cpeobj = cpes[cpe]
        cpeobj.setdefault('origins', []).append(path)


    def characters(self, content):
        if self._curdata is not None:
            self._curdata += content


class Nmap2Txt(NmapHandler):

    """Simple "test" handler, outputs resulting JSON as text."""

    def __init__(self, fname, **kargs):
        self._db = []
        NmapHandler.__init__(self, fname, **kargs)

    @staticmethod
    def _to_binary(data):
        return data.encode('base64').replace('\n', '')

    def _addhost(self):
        self._db.append(self._curhost)


class Nmap2DB(NmapHandler):

    """Specific handler for MongoDB backend."""

    def __init__(self, fname, categories=None, source=None,
                 gettoarchive=None, add_addr_infos=True, merge=False,
                 **kargs):
        from ivre import db
        self._db = db.db
        if categories is None:
            self.categories = []
        else:
            self.categories = categories
        self._add_addr_infos = add_addr_infos
        self.source = source
        if gettoarchive is None:
            self._gettoarchive = lambda a, s: []
        else:
            self._gettoarchive = gettoarchive
        self.merge = merge
        NmapHandler.__init__(self, fname, categories=categories,
                             source=source, gettoarchive=gettoarchive,
                             add_addr_infos=add_addr_infos, merge=merge,
                             **kargs)

    def _addhost(self):
        if self.categories:
            self._curhost['categories'] = self.categories[:]
        if self._add_addr_infos:
            self._curhost['infos'] = {}
            for func in [self._db.data.country_byip,
                         self._db.data.as_byip,
                         self._db.data.location_byip]:
                data = func(self._curhost['addr'])
                if data:
                    self._curhost['infos'].update(data)
        if self.source:
            self._curhost['source'] = self.source
        # We are about to insert data based on this file, so we want
        # to save the scan document
        if not self.scan_doc_saved:
            self.scan_doc_saved = True
            self._storescan()
        self._db.nmap.store_or_merge_host(self._curhost, self._gettoarchive,
                                          merge=self.merge)

    def _storescan(self):
        ident = self._db.nmap.store_scan_doc(self._curscan)
        return ident

    def _addscaninfo(self, i):
        if 'numservices' in i:
            i['numservices'] = int(i['numservices'])
        if 'scaninfos' in self._curscan:
            self._curscan['scaninfos'].append(i)
        else:
            self._curscan['scaninfos'] = [i]


class Nmap2Posgres(Nmap2DB):
    @staticmethod
    def _to_binary(data):
        return data.encode('base64')
