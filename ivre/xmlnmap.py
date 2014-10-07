#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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
Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains the parser for nmap's XML output files.

"""

from ivre import utils

from xml.sax.handler import ContentHandler, EntityResolver
import hashlib
import datetime
import sys
import re

# Scripts that mix elem/table tags with and without key attributes,
# which is not supported for now
IGNORE_TABLE_ELEMS = set(['xmpp-info', 'sslv2'])

ADD_TABLE_ELEMS = {
    'modbus-discover':
    re.compile('^ *DEVICE IDENTIFICATION: *(?P<deviceid>.*?) *$', re.M),
}

IGNORE_SCRIPTS = {
    'mcafee-epo-agent': set(['ePO Agent not found']),
    'ftp-bounce': set(['no banner']),
    'telnet-encryption': set(['\n  ERROR: Failed to send packet: TIMEOUT']),
    'ssh-hostkey': set(['\n']),
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
    # host scripts
    'firewalk': set(['None found']),
    'ipidseq': set(['Unknown']),
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
}

IGNORE_SCRIPT_OUTPUTS = set([
    'ERROR: Script execution failed (use -d to debug)',
    'Unable to open connection',
    'ERROR: Failed to connect to server',
    '\n  ERROR: Failed to connect to server',
    '\n  ERROR: Failed to receive response from server',
    '  \n  ERROR: ERROR',
    'false',
])

IGNORE_SCRIPT_OUTPUTS_REGEXP = set([
    # MD5(<empty>)
    re.compile('d41d8cd98f00b204e9800998ecf8427e', re.I)
])


def ignore_script(script):
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


class NoExtResolver(EntityResolver):

    """A simple EntityResolver that will prevent any external
    resolution.

    """

    def resolveEntity(self, *_):
        return '/dev/null'


class NmapHandler(ContentHandler):

    """The handler for Nmap's XML documents. An abstract class for
    database specific implementations.

    """

    def __init__(self, fname, needports=False, **_):
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
        with open(fname) as fdesc:
            self._filehash = hashlib.sha256(fdesc.read()).hexdigest()
        print "READING %r (%r)" % (fname, self._filehash)
        if self._isscanpresent():
            raise Exception('Scan already present in Database.')

    def _addhost(self, _):
        """Subclasses may store host (first argument) here."""
        pass

    def _storescan(self):
        """Subclasses may store self._curscan here."""
        pass

    def _addscaninfo(self, _):
        """Subclasses may add scan information (first argument) to
        self._curscan here.

        """
        pass

    def _isscanpresent(self):
        """Subclasses may check whether a scan is already present in
        the database here.

        """
        pass

    def outputresults(self):
        """Subclasses may display any results here."""
        return

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
            self._curhost = {}
            if self._curscan:
                self._curhost['scanid'] = self._curscan['_id']
            for attr in attrs.keys():
                self._curhost[attr] = attrs[attr]
            for field in ['starttime', 'endtime']:
                if field in self._curhost:
                    self._curhost[
                        field] = datetime.datetime.fromtimestamp(
                            int(self._curhost[field]))
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

    def endElement(self, name):
        if name == 'nmaprun':
            self._storescan()
            self._curscan = None
        elif name == 'host':
            if self._curhost['state'] == 'up' and ('ports' in self._curhost
                                                   or not self._needports):
                self._addhost(self._curhost)
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
            if 'ports' not in self._curhost:
                self._curhost['ports'] = [self._curport]
            else:
                self._curhost['ports'].append(self._curport)
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
                self._curscript[infokey] = self._curtable
                self._curtable = {}
            elif infokey != 'infos' and infokey in ADD_TABLE_ELEMS:
                infos = ADD_TABLE_ELEMS[infokey]
                if type(infos) is utils.REGEXP_T:
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
                # stop recording characters
                self._curdata = None
            self._curtablepath.pop()
        elif name == 'trace':
            if 'traces' not in self._curhost:
                self._curhost['traces'] = [self._curtrace]
            else:
                self._curhost['traces'].append(self._curtrace)
            self._curtrace = None

    def characters(self, content):
        if self._curdata is not None:
            self._curdata += content


class Nmap2Txt(NmapHandler):

    """Simple "test" handler, outputs resulting JSON as text."""

    def __init__(self, fname, needports=False, **kargs):
        self._db = {}
        NmapHandler.__init__(self, fname, needports=needports,
                             **kargs)

    def _addhost(self, host):
        self._db[host['addr']] = host

    def outputresults(self):
        print self._db


class Nmap2Mongo(NmapHandler):

    """Specific handler for MongoDB backend."""

    def __init__(self, fname, needports=False, categories=None,
                 source=None, gettoarchive=None, add_addr_infos=True):
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
        self._archivescollection = self._db.nmap.db[
            self._db.nmap.colname_oldhosts]
        self._archivesscancollection = self._db.nmap.db[
            self._db.nmap.colname_oldscans]
        if gettoarchive is None:
            self._gettoarchive = lambda c, a, s: []
        else:
            self._gettoarchive = gettoarchive
        NmapHandler.__init__(self, fname, needports=needports,
                             categories=categories, source=source,
                             gettoarchive=gettoarchive,
                             add_addr_infos=add_addr_infos)

    def _addhost(self, host):
        if self.categories:
            host['categories'] = self.categories[:]
        if self._add_addr_infos:
            host['infos'] = {}
            for func in [self._db.data.country_byip,
                         self._db.data.as_byip,
                         self._db.data.location_byip]:
                data = func(host['addr'])
                if data:
                    host['infos'].update(data)
        if self.source:
            host['source'] = self.source
        for rec in self._gettoarchive(self._collection, host['addr'],
                                      self.source):
            self._archiverecord(rec)
        ident = self._collection.insert(host)
        print "HOST STORED: %r in %r" % (ident, self._collection)

    def _archiverecord(self, host):
        """Archives a given host record. Also archives the
        corresponding scan and removes the scan from the "not
        archived" scan collection if not there is no host left in the
        "not archived" host collumn.

        """
        # store the host in the archive hosts collection
        self._archivescollection.insert(host)
        print "HOST ARCHIVED: %r in %r" % (host['_id'],
                                           self._archivescollection)
        scanid = host['scanid']
        # store the scan in the archive scans collection if it is not there yet
        if self._archivesscancollection.find_one(
                {'_id': host['scanid']}) is None:
            self._archivesscancollection.insert(
                self._scancollection.find({'_id': scanid})[0])
            print "SCAN ARCHIVED: %r in %r" % (scanid,
                                               self._archivesscancollection)
        # remove the host from the hosts collection
        self._collection.remove(spec_or_id=host['_id'])
        print "HOST REMOVED: %r from %r" % (host['_id'], self._collection)
        # remove the scan from the scans collection if there is no
        # more hosts related to this scan in the hosts collection
        if self._collection.find({'scanid': scanid}).count() == 0:
            self._scancollection.remove(spec_or_id=scanid)
            print "SCAN REMOVED: %r from %r" % (scanid, self._scancollection)

    def _storescan(self):
        res = self._scancollection.insert(self._curscan)
        print "SCAN STORED: %r in %r" % (res, self._scancollection)
        return res

    def _addscaninfo(self, i):
        if 'numservices' in i:
            i['numservices'] = int(i['numservices'])
        if 'scaninfos' in self._curscan:
            self._curscan['scaninfos'].append(i)
        else:
            self._curscan['scaninfos'] = [i]

    def _isscanpresent(self):
        return self._scancollection.find({'_id': self._filehash}).count() > 0
