#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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

from ivre import utils

from xml.sax.handler import ContentHandler, EntityResolver
import datetime
import sys
import os
import re
import json

# Scripts that mix elem/table tags with and without key attributes,
# which is not supported for now
IGNORE_TABLE_ELEMS = set(['xmpp-info', 'sslv2'])

ADD_TABLE_ELEMS = {
    'modbus-discover':
    re.compile('^ *DEVICE IDENTIFICATION: *(?P<deviceid>.*?) *$', re.M),
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

CHANGE_TABLE_ELEMS = {
    'smb-enum-shares': change_smb_enum_shares,
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


def ignore_script(script):
    """Predicate that decides whether an Nmap script should be ignored
    or not, based on IGNORE_* constants. Nmap scripts are ignored when
    their output is known to be irrelevant.

    """
    sid = script.get('id')
    output = script.get('output')
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

    def __init__(self, fname, filehash, needports=False, **_):
        ContentHandler.__init__(self)
        self._needports = needports
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
        self._filehash = filehash
        print "READING %r (%r)" % (fname, self._filehash)

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

    def outputresults(self):
        """Subclasses may display any results here."""
        pass

    def startElement(self, name, attrs):
        if name == 'nmaprun':
            if self._curscan is not None:
                sys.stderr.write("WARNING, self._curscan should be None at "
                                 "this point(got %r)\n" % self._curscan)
            self._curscan = dict(attrs)
            self._curscan['_id'] = self._filehash
        elif name == 'scaninfo' and self._curscan is not None:
            self._addscaninfo(dict(attrs))
        elif name == 'host':
            if self._curhost is not None:
                sys.stderr.write("WARNING, self._curhost should be None at "
                                 "this point (got %r)\n" % self._curhost)
            self._curhost = {"schema_version": 1}
            if self._curscan:
                self._curhost['scanid'] = self._curscan['_id']
            for attr in attrs.keys():
                self._curhost[attr] = attrs[attr]
            for field in ['starttime', 'endtime']:
                if field in self._curhost:
                    self._curhost[field] = datetime.datetime.utcfromtimestamp(
                        int(self._curhost[field])
                    )
        elif name == 'address' and self._curhost is not None:
            if attrs['addrtype'] != 'ipv4':
                if 'addresses' not in self._curhost:
                    self._curhost['addresses'] = {
                        attrs['addrtype']: [attrs['addr']]
                    }
                elif attrs['addrtype'] not in self._curhost:
                    self._curhost['addresses'].update({
                        attrs['addrtype']: [attrs['addr']]
                    })
                else:
                    addresses = self._curhost['addresses'][attrs['addrtype']]
                    addresses.append(attrs['addr'])
                    self._curhost['addresses'][attrs['addrtype']] = addresses
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
            self._curextraports = {attrs['state']: [int(attrs['count']), {}]}
        elif name == 'extrareasons' and self._curextraports is not None:
            self._curextraports[self._curextraports.keys()[0]][1][
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
            if name not in self._curhost['os']:
                self._curhost['os'][name] = [dict(attrs)]
            else:
                self._curhost['os'][name].append(dict(attrs))
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
            self._storescan()
            self._curscan = None
        elif name == 'host':
            if self._curhost['state'] == 'up' and ('ports' in self._curhost
                                                   or not self._needports):
                if 'openports' not in self._curhost:
                    self._curhost['openports'] = {'count': 0}
                self._pre_addhost()
                self._addhost()
            self._curhost = None
        elif name == 'hostnames':
            self._curhost['hostnames'] = self._curhostnames
            self._curhostnames = None
        elif name == 'extraports':
            if 'extraports' not in self._curhost:
                self._curhost['extraports'] = self._curextraports
            else:
                self._curhost['extraports'].update(self._curextraports)
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
            infokey = self._curscript.get('id', 'infos')
            if self._curtable:
                if self._curtablepath:
                    sys.stderr.write("WARNING, self._curtablepath should be "
                                     "empty, got [%r]\n" % self._curtablepath)
                if infokey in CHANGE_TABLE_ELEMS:
                    self._curtable = CHANGE_TABLE_ELEMS[infokey](self._curtable)
                self._curscript[infokey] = self._curtable
                self._curtable = {}
            elif infokey != 'infos' and infokey in ADD_TABLE_ELEMS:
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
            if ignore_script(self._curscript):
                self._curscript = None
                return
            if 'scripts' not in current:
                current['scripts'] = [self._curscript]
            else:
                current['scripts'].append(self._curscript)
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
        elif name == 'trace':
            if 'traces' not in self._curhost:
                self._curhost['traces'] = [self._curtrace]
            else:
                self._curhost['traces'].append(self._curtrace)
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

    def __init__(self, fname, needports=False, **kargs):
        self._db = []
        NmapHandler.__init__(self, fname, needports=needports,
                             **kargs)

    def _addhost(self):
        self._db.append(self._curhost)

    def outputresults(self):
        print json.dumps(self._db, default=utils.serialize)


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
