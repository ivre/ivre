#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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
Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains the parser for nmap's XML output files.

"""

from ivre import utils, config, nmapout

from xml.sax.handler import ContentHandler, EntityResolver
import datetime
import sys
import os
import re
import bson

SCHEMA_VERSION = 6

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

HTTP_SCREENSHOT_PATTERN = re.compile('^ *Saved to (.*)$', re.MULTILINE)

def http_screenshot_extract(script):
    fname = HTTP_SCREENSHOT_PATTERN.search(script['output'])
    return None if fname is None else fname.groups()[0]

SCREENSHOTS_SCRIPTS = {
    "http-screenshot": http_screenshot_extract,
}

def add_ls_data(script):
    """This function calls the appropriate `add_*_data()` function to
    convert output from scripts that do not include a structured
    output to a structured output similar to the one provided by the
    "ls" NSE module.

    See https://nmap.org/nsedoc/lib/ls.html

    """
    def notimplemented(script):
        sys.stderr.write(
            "WARNING: migration not implemented for script %(id)r\n" % script
        )
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
                    sys.stderr.write(
                        "WARNING: cur_vol should be None here [got %r] "
                        "[fname=%s]\n" % cur_vol
                    )
                cur_vol = {"volume": line[13:], "files": []}
                state = 1 # listing
            elif line:
                sys.stderr.write(
                    "WARNING: unexpected line [%r] outside a volume"
                    "\n" % line
                )
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
        sys.stderr.write(
            "WARNING: expected state == 0, got %r\n" % state
        )
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
                    sys.stderr.write(
                        "WARNING: cur_vol should be None here [got %r] "
                        "[fname=%s]\n" % cur_vol
                    )
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
        sys.stderr.write(
            "WARNING: expected state == 0, got %r\n" % state
        )
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
                    sys.stderr.write("WARNING: skip file entry outside a "
                                     "volume [%r]\n" % line[4:])
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
                sys.stderr.write("WARNING: skip not understood line "
                                 "[%r]\n" % line)
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
    if len(table) == 1:
        vulnid, tab = table.popitem()
        return dict(tab, **{"id": vulnid})
    return table

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
    # host scripts
    'firewalk': set(['None found']),
    'ipidseq': set(['Unknown']),
    'fcrdns': set(['FAIL (No PTR record)']),
    'msrpc-enum': set(['SMB: ERROR: Server disconnected the connection']),
    'smb-mbenum': set(['\n  ERROR: Failed to connect to browser service: '
                       'SMB: ERROR: Server disconnected the connection']),
}

IGNORE_SCRIPTS_IDS = set(["http-screenshot"])

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
}

MASSCAN_SERVICES_NMAP_SERVICES = {
    "ftp": "ftp", # masscan can confuse smtp (for example) for ftp
    "http": "http",
    "ssh": "ssh",
    "vnc": "vnc",
}

MASSCAN_ENCODING = re.compile(re.escape("\\x") + "([0-9a-f]{2})")

def _masscan_decode(match):
    char = match.groups()[0].decode('hex')
    return (char if (32 <= ord(char) <= 126 or char in "\t\r\n")
            else match.group())

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
    if any(output is not None and expr.search(output)
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
                 **_):
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
        self.need_scan_doc = False
        if config.DEBUG:
            sys.stderr.write("READING %r (%r)\n" % (fname, self._filehash))

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
                sys.stderr.write("WARNING, self._curscan should be None at "
                                 "this point (got %r)\n" % self._curscan)
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
                sys.stderr.write("WARNING, self._curhost should be None at "
                                 "this point (got %r)\n" % self._curhost)
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
                sys.stderr.write("WARNING, self._curhostnames should be None "
                                 "at this point "
                                 "(got %r)\n" % self._curhostnames)
            self._curhostnames = []
        elif name == 'hostname':
            if self._curhostnames is None:
                sys.stderr.write("WARNING, self._curhostnames should NOT be "
                                 "None at this point\n")
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
                sys.stderr.write("WARNING, self._curextraports should be None"
                                 " at this point "
                                 "(got %r)\n" % self._curextraports)
            self._curextraports = {
                attrs['state']: {"total": int(attrs['count']), "reasons": {}},
            }
        elif name == 'extrareasons' and self._curextraports is not None:
            self._curextraports[next(iter(self._curextraports))]["reasons"][
                attrs['reason']] = int(attrs['count'])
        elif name == 'port':
            if self._curport is not None:
                sys.stderr.write("WARNING, self._curport should be None at "
                                 "this point (got %r)\n" % self._curport)
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
                # create fake scripts from masscan "service" tags
                self._curport.setdefault('scripts', []).append({
                    "id": MASSCAN_SERVICES_NMAP_SCRIPTS.get(attrs['name'],
                                                            attrs['name']),
                    "output": MASSCAN_ENCODING.sub(
                        _masscan_decode,
                        attrs["banner"],
                    )
                })
                # get service name
                service = MASSCAN_SERVICES_NMAP_SERVICES.get(attrs['name'])
                if service is not None:
                    self._curport['service_name'] = service
                return
            for attr in attrs.keys():
                self._curport['service_%s' % attr] = attrs[attr]
            for field in ['service_conf', 'service_rpcnum',
                          'service_lowver', 'service_highver']:
                if field in self._curport:
                    self._curport[field] = int(self._curport[field])
        elif name == 'script':
            if self._curscript is not None:
                sys.stderr.write("WARNING, self._curscript should be None "
                                 "at this point (got %r)\n" % self._curscript)
            self._curscript = dict([attr, attrs[attr]]
                                   for attr in attrs.keys())
        elif name in ['table', 'elem']:
            if self._curscript.get('id') in IGNORE_TABLE_ELEMS:
                return
            if name == 'elem':
                # start recording characters
                if self._curdata is not None:
                    sys.stderr.write("WARNING, self._curdata should be None"
                                     " at this point "
                                     "(got %r)\n" % self._curdata)
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
                sys.stderr.write("WARNING, self._curtrace should be None "
                                 "at this point (got %r)\n" % self._curtrace)
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
            if self.need_scan_doc:
                self._storescan()
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
                sys.stderr.write("WARNING, script element without port or "
                                 "host\n")
                self._curscript = None
                if self._curtablepath:
                    sys.stderr.write("WARNING, self._curtablepath should be "
                                     "empty, got [%r]\n" % self._curtablepath)
                self._curtable = {}
                return
            infokey = self._curscript.get('id', None)
            infokey = ALIASES_TABLE_ELEMS.get(infokey, infokey)
            if self._curtable:
                if self._curtablepath:
                    sys.stderr.write("WARNING, self._curtablepath should be "
                                     "empty, got [%r]\n" % self._curtablepath)
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
                        except Exception as exc:
                            exceptions.append(exc)
                        else:
                            break
                    for exc in exceptions:
                        sys.stderr.write(
                            utils.warn_exception(
                                exc,
                                scanfile=self._fname,
                                fname=full_fname,
                            )
                        )
            if ignore_script(self._curscript):
                self._curscript = None
                return
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
                sys.stderr.write("WARNING, invalid cpe format (%s)" % cpe)
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


class Nmap2Mongo(NmapHandler):

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
        # FIXME we should use self._db methods instead of that and
        # rename this class as Nmap2DB
        self._collection = self._db.nmap.db[self._db.nmap.colname_hosts]
        self._scancollection = self._db.nmap.db[self._db.nmap.colname_scans]
        if gettoarchive is None:
            self._gettoarchive = lambda c, a, s: []
        else:
            self._gettoarchive = gettoarchive
        self.merge = merge
        NmapHandler.__init__(self, fname, categories=categories,
                             source=source, gettoarchive=gettoarchive,
                             add_addr_infos=add_addr_infos, merge=merge,
                             **kargs)

    @staticmethod
    def _to_binary(data):
        return bson.Binary(data)

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
        self.need_scan_doc = True
        if self.merge and self._db.nmap.merge_host(self._curhost):
            return
        self._db.nmap.archive_from_func(self._curhost, self._gettoarchive)
        self._db.nmap.store_host(self._curhost)

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
