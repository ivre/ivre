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

This sub-module contains functions to interact with the
MongoDB databases.
"""

from ivre.db import DB, DBNmap, DBPassive, DBData
from ivre import utils, xmlnmap

import pymongo
import bson
import json

import re
import datetime


class MongoDB(DB):

    def __init__(self, host, dbname,
                 username=None, password=None, mechanism=None):
        self.host = host
        self.dbname = dbname
        self.username = username
        self.password = password
        self.mechanism = mechanism
        self.indexes = {}
        self.specialindexes = {}

    def _get_db(self):
        try:
            return self._db
        except AttributeError:
            self._db = pymongo.MongoClient(
                host=self.host,
                read_preference=pymongo.ReadPreference.SECONDARY_PREFERRED
            )[self.dbname]
            if self.username is not None:
                if self.password is not None:
                    self.db.authenticate(self.username, self.password)
                elif self.mechanism is not None:
                    self.db.authenticate(self.username,
                                         mechanism=self.mechanism)
                else:
                    raise TypeError("provide either 'password' or 'mechanism'"
                                    " with 'username'")
            return self._db

    db = property(fget=_get_db)

    def getid(self, record):
        return record['_id']

    def serialize(self, obj):
        if type(obj) is utils.REGEXP_T:
            return '/%s/%s' % (
                obj.pattern,
                ''.join(x.lower() for x in 'ILMSXU'
                        if getattr(re, x) & obj.flags),
                )
        if type(obj) is datetime.datetime:
            return str(obj)
        if type(obj) is bson.ObjectId:
            return obj.binary.encode('hex')
        raise TypeError("Don't know what to do with %r (%r)" % (
            obj, type(obj)))

    def explain(self, cursor, indent=None):
        return json.dumps(cursor.explain(), indent=indent,
                          default=self.serialize)

    def distinct(self, cursor, fieldname):
        return cursor.distinct(fieldname)

    def create_indexes(self):
        for colname, indexes in self.indexes.iteritems():
            for index in indexes:
                self.db[colname].create_index(index)
        for colname, indexes in self.specialindexes.iteritems():
            for index in indexes:
                self.db[colname].create_index(index[0], **index[1])

    def ensure_indexes(self):
        for colname, indexes in self.indexes.iteritems():
            for index in indexes:
                self.db[colname].ensure_index(index)
        for colname, indexes in self.specialindexes.iteritems():
            for index in indexes:
                self.db[colname].ensure_index(index[0], **index[1])
    # filters
    flt_empty = {}

    def str2flt(self, string):
        return json.loads(string)

    def flt2str(self, flt):
        return json.dumps(flt)

    def _flt_and(self, cond1, cond2):
        """Returns a filter which will accept results if and only if
        they are accepted by both cond1 and cond2.

        """
        cond1k = set(cond1.keys())
        cond2k = set(cond2.keys())
        cond = {}
        if '$and' in cond1:
            cond1k.remove('$and')
            cond['$and'] = cond1['$and']
        if '$and' in cond2:
            cond2k.remove('$and')
            cond['$and'] = cond.get('$and', []) + cond2['$and']
        for k in cond1k.difference(cond2k):
            cond[k] = cond1[k]
        for k in cond2k.difference(cond1k):
            cond[k] = cond2[k]
        for k in cond1k.intersection(cond2k):
            if cond1[k] == cond2[k]:
                cond[k] = cond1[k]
            else:
                cond['$and'] = cond.get('$and', []) + [{k: cond1[k]},
                                                       {k: cond2[k]}]
        return cond

    def flt_or(self, *args):
        return {'$or': args}

    def searchid(self, idval, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        record, given its id.

        """
        return {"_id": idval}

    def searchhost(self, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        try:
            addr = utils.ip2int(addr)
        except (TypeError, utils.socket.error):
            pass
        return {'addr': {'$ne': addr} if neg else addr}

    def searchhosts(self, hosts, neg=False):
        return {'addr': {'$nin' if neg else '$in': hosts}}

    def searchrange(self, start, stop, neg=False):
        """Filters (if `neg` == True, filters out) one particular IP
        address range.

        """
        try:
            start = utils.ip2int(start)
        except (TypeError, utils.socket.error):
            pass
        try:
            stop = utils.ip2int(stop)
        except (TypeError, utils.socket.error):
            pass
        if neg:
            return {'$or': [
                {'addr': {'$lt': start}},
                {'addr': {'$gt': stop}}
            ]}
        return {'addr': {'$gte': start,
                         '$lte': stop}}

    def searchval(self, key, val):
        return {key: val}

    def searchcmp(self, key, val, cmpop):
        if cmpop == '<':
            return {key: {'$lt': val}}
        elif cmpop == '<=':
            return {key: {'$lte': val}}
        elif cmpop == '>':
            return {key: {'$gt': val}}
        elif cmpop == '>=':
            return {key: {'$gte': val}}


class MongoDBNmap(MongoDB, DBNmap):

    content_handler = xmlnmap.Nmap2Mongo

    def __init__(self, host, dbname,
                 colname_scans="scans", colname_hosts="hosts",
                 colname_oldscans="archivesscans",
                 colname_oldhosts="archiveshosts",
                 username=None, password=None, mechanism=None, **_):
        MongoDB.__init__(self, host, dbname,
                         username=username,
                         password=password,
                         mechanism=mechanism)
        DBNmap.__init__(self)
        self.colname_scans = colname_scans
        self.colname_hosts = colname_hosts
        self.colname_oldscans = colname_oldscans
        self.colname_oldhosts = colname_oldhosts
        self.indexes = {
            self.colname_hosts: [
                [('scanid', pymongo.ASCENDING)],
                [('addr', pymongo.ASCENDING)],
                [('starttime', pymongo.ASCENDING)],
                [('endtime', pymongo.ASCENDING)],
                [('source', pymongo.ASCENDING)],
                [('categories', pymongo.ASCENDING)],
                [('hostnames.domains', pymongo.ASCENDING)],
                [('traces.hops.domains', pymongo.ASCENDING)],
                [('ports.port', pymongo.ASCENDING)],
                [('ports.state_state', pymongo.ASCENDING)],
                [('ports.service_name', pymongo.ASCENDING)],
                [('ports.scripts.id', pymongo.ASCENDING)],
                [('scripts.id', pymongo.ASCENDING)],
                [('infos.as_num', pymongo.ASCENDING)],
                [
                    ('traces.hops.ipaddr', pymongo.ASCENDING),
                    ('traces.hops.ttl', pymongo.ASCENDING),
                ],
                [
                    ('infos.country', pymongo.ASCENDING),
                    ('infos.city', pymongo.ASCENDING),
                ],
                [('infos.loc', pymongo.GEOSPHERE)],
            ],
            self.colname_oldhosts: [
                [('scanid', pymongo.ASCENDING)],
                [('addr', pymongo.ASCENDING)],
                [('starttime', pymongo.ASCENDING)],
                [('source', pymongo.ASCENDING)],
            ],
        }
        self.specialindexes = {}

    def init(self):
        """Initializes the "active" columns, i.e., drops those columns and
creates the default indexes."""
        self.db[self.colname_scans].drop()
        self.db[self.colname_hosts].drop()
        self.db[self.colname_oldscans].drop()
        self.db[self.colname_oldhosts].drop()
        self.create_indexes()

    def get(self, flt, archive=False, **kargs):
        """Queries the active column (the old one if "archive" is set to True)
with the provided filter "flt", and returns a MongoDB cursor.

This should be very fast, as no operation is done (the cursor is only
returned). Next operations (e.g., .count(), enumeration, etc.) might
take a long time, depending on both the operations and the filter.

Any keyword argument other than "archive" is passed to the .find()
method of the Mongodb column object, without any validation (and might
have no effect if it is not expected)."""
        if archive:
            return self.db[self.colname_oldhosts].find(flt, **kargs)
        return self.db[self.colname_hosts].find(flt, **kargs)

    def getscan(self, scanid, archive=False, **kargs):
        if archive:
            return self.db[self.colname_oldscans].find_one(
                {'_id': scanid}, **kargs)
        return self.db[self.colname_scans].find_one(
            {'_id': scanid}, **kargs)

    def getlocations(self, flt, archive=False):
        if archive:
            col = self.db[self.colname_oldhosts]
        else:
            col = self.db[self.colname_hosts]
        aggr = [
            {"$match": self.flt_and(flt, self.searchhaslocation())},
            {"$project": {"_id": 0, "coords": "$infos.loc.coordinates"}},
            {"$group": {"_id": "$coords", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return col.aggregate(aggr)['result']

    def remove(self, host, archive=False):
        """Removes the host "host" from the active (the old one if
        "archive" is set to True) column. "host" must be the host
        record as returned by MongoDB.

        If "host" has a "scanid" attribute, and if it refers to a scan
        that have no more host record after the deletion of "host",
        then the scan record is also removed.

        """
        if archive:
            colname_hosts = self.colname_oldhosts
            colname_scans = self.colname_oldscans
        else:
            colname_hosts = self.colname_hosts
            colname_scans = self.colname_scans
        self.db[colname_hosts].remove(spec_or_id=host['_id'])
        scanid = host.get('scanid', None)
        if scanid is not None and self.get({'scanid': scanid},
                                           archive=archive).count() == 0:
            self.db[colname_scans].remove(spec_or_id=scanid)

    def get_mean_open_ports(self, flt, archive=False):
        """This method returns for a specific query `flt` a list of
        dictionary objects whose keys are `id` and `mean`; the value
        for `id` is a backend-dependant and uniquely identifies a
        record, and the value for `mean` is given by:

        (number of open ports) * sum(port number for each open port)

        This MongoDB specific implementation uses the aggregation
        framework to have most of the work done within the DB
        server.

        However, it is broken for now as it does not handle hosts with
        no open port but with a ports attribute.

        See
          * https://stackoverflow.com/questions/23636175
          * https://stackoverflow.com/questions/22114748
        """
        aggr = []
        if flt:
            aggr += [{"$match": flt}]
        aggr += [
            {"$project": {"ports.port": 1, "ports.state_state": 1}},
            # if the host has no ports attribute, we create an empty list
            {"$project": {"ports": {"$ifNull": ["$ports", []]}}},
            {"$redact": {"$cond": {"if": {"$eq": [{"$ifNull": ["$ports",
                                                               None]},
                                                  None]},
                                   "then": {
                                       "$cond": {"if": {"$eq": ["$state_state",
                                                                "open"]},
                                                 "then": "$$KEEP",
                                                 "else": "$$PRUNE"}},
                                   "else": "$$DESCEND"}}},
            {"$project": {"ports": {"$cond": [{"$eq": ["$ports", []]},
                                              [0],
                                              "$ports.port"]}}},
            {"$unwind": "$ports"},
            {"$group": {"_id": "$_id",
                        "count": {"$sum": 1},
                        "ports": {"$sum": "$ports"}}},
            {"$project": {"_id": 0,
                          "id": "$_id",
                          "mean": {"$multiply": ["$count", "$ports"]}}},
        ]
        return self.db[
            self.colname_oldhosts if archive
            else self.colname_hosts
        ].aggregate(aggr)['result']

    def group_by_port(self, flt, archive=False):
        """Work-in-progress function to get scan results grouped by
        common open ports

        """
        aggr = []
        if flt:
            aggr += [{"$match": flt}]
        aggr += [
            {"$project": {"ports.port": 1, "ports.state_state": 1}},
            # if the host has no ports attribute, we create an empty list
            {"$project": {"ports": {"$ifNull": ["$ports", []]}}},
            {"$redact": {"$cond": {"if": {"$eq": [{"$ifNull": ["$ports",
                                                               None]},
                                                  None]},
                                   "then": {
                                       "$cond": {"if": {"$eq": ["$state_state",
                                                                "open"]},
                                                 "then": "$$KEEP",
                                                 "else": "$$PRUNE"}},
                                   "else": "$$DESCEND"}}},
            {"$project": {"ports": {"$cond": [{"$eq": ["$ports", []]},
                                              [0],
                                              "$ports.port"]}}},
            {"$group": {"_id": "$ports",
                        "ids": {"$addToSet": "$_id"}}},
        ]
        return self.db[
            self.colname_oldhosts if archive
            else self.colname_hosts
        ].aggregate(aggr)['result']

    def searchdomain(self, name, neg=False):
        if neg:
            if type(name) is utils.REGEXP_T:
                return {"hostnames.domains": {"$not": name}}
            return {"hostnames.domains": {"$ne": name}}
        return {"hostnames.domains": name}

    def searchhostname(self, name, neg=False):
        if neg:
            if type(name) is utils.REGEXP_T:
                return {"hostnames.name": {"$not": name}}
            return {"hostnames.name": {"$ne": name}}
        return self.flt_and(
            # This is indexed
            self.searchdomain(name, neg=neg),
            # This is not
            {"hostnames.name": name},
        )

    def searchcategory(self, cat, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular category
        (records may have zero, one or more categories).
        """
        if neg:
            if type(cat) is utils.REGEXP_T:
                return {'categories': {'$not': cat}}
            return {'categories': {'$ne': cat}}
        return {'categories': cat}

    def searchcountry(self, country, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular country.
        """
        if type(country) in [str, unicode]:
            country = utils.str2list(country)
        if type(country) not in [str, unicode] and hasattr(
                country, '__iter__'):
            return {'infos.country_code':
                    {'$nin' if neg else '$in': list(country)}}
        return {'infos.country_code':
                {'$ne': country} if neg else country}

    def searchhaslocation(self, neg=False):
        return {'infos.loc': {"$exists": not neg}}

    def searchcity(self, city, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular city.
        """
        if neg:
            if type(city) is utils.REGEXP_T:
                return {'infos.city': {'$not': city}}
            return {'infos.city': {'$ne': city}}
        return {'infos.city': city}

    def searchasnum(self, asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        if type(asnum) in [str, unicode]:
            asnum = utils.str2list(asnum)
        if type(asnum) not in [str, unicode] and hasattr(asnum, '__iter__'):
            return {'infos.as_num':
                    {'$nin' if neg else '$in': map(int, asnum)}}
        asnum = int(asnum)
        return {'infos.as_num': {'$ne': asnum} if neg else asnum}

    def searchsource(self, src, neg=False):
        "Filters (if `neg` == True, filters out) one particular source."
        if neg:
            if type(src) is utils.REGEXP_T:
                return {'source': {'$not': src}}
            return {'source': {'$ne': src}}
        return {'source': src}

    def searchport(self, port, protocol='tcp', state='open', neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        if neg:
            return {
                '$or': [
                    {'ports': {'$elemMatch': {
                        'port': port,
                        'protocol': protocol,
                        'state_state': {'$ne': state}
                    }}},
                    {'ports': {'$not': {'$elemMatch': {'port': port}}}}
                ]
            }
        return {'ports': {'$elemMatch': {
            'port': port,
            'protocol': protocol,
            'state_state': state
        }}}

    def searchports(self, ports, protocol='tcp', state='open', neg=False):
        return self.flt_and(*(self.searchport(p, protocol=protocol,
                                              state=state, neg=neg)
                              for p in ports))

    def searchopenport(self):
        "Filters records with at least one open port."
        return {'ports.state_state': 'open'}

    def searchservice(self, srv, port=None, probed=False):
        """Search an open port with a particular regular expression in the
service_* tags."""
        # service_method
        res = {
            'ports': {'$elemMatch': {
                'state_state': 'open',
                '$or': [
                    {'service_name': srv},
                    {'service_product': srv},
                    {'service_version': srv},
                    {'service_extrainfo': srv},
                    {'service_hostname': srv}
                ]
            }}}
        if port is not None:
            res['ports']['$elemMatch']['port'] = port
        if probed:
            res['ports']['$elemMatch']['service_method'] = 'probed'
        return res

    def searchscript(self, srv, port=None):
        """Search a particular content in the scripts names and outputs.
"""
        if port is None:
            return {'$or': [
                {'ports.scripts.id': srv},
                {'ports.scripts.output': srv}
            ]}
        return {
            'ports': {'$elemMatch': {
                'port': port,
                '$or': [
                    {'scripts.id': srv},
                    {'scripts.output': srv}
                ]}}}

    def searchscriptidout(self, name, output):
        """Search a particular content in the scripts names and
        outputs.

        """
        return {
            'ports.scripts': {'$elemMatch': {
                'id': name,
                'output': output
            }}}

    def searchscriptid(self, name):
        """Search a script name."""
        return {'ports.scripts.id': name}

    def searchscriptoutput(self, expr):
        """Search a particular content in the scripts names and
        outputs.

        """
        return {'ports.scripts.output': expr}

    def searchsvchostname(self, srv):
        return {'ports.service_hostname': srv}

    def searchhttpauth(self, newscript=True, oldscript=False):
        # $or queries are too slow, by default support only new script
        # output.
        res = []
        if newscript:
            res.append(self.searchscriptidout(
                'http-default-accounts',
                re.compile('credentials\\ found')))
        if oldscript:
            res.append(self.searchscriptidout(
                'http-auth',
                re.compile('HTTP\\ server\\ may\\ accept')))
        if not res:
            raise Exception('"newscript" and "oldscript" are both False')
        if len(res) == 1:
            return res[0]
        return {'$or': res}

    def searchwebmin(self):
        return {
            'ports': {
                '$elemMatch': {
                    'service_name': 'http',
                    'service_method': 'probed',
                    'service_product': 'MiniServ',
                    'service_extrainfo': {'$ne': 'Webmin httpd'},
                }}}

    def searchx11(self):
        return {
            'ports': {'$elemMatch': {
                'service_name': 'X11',
                'service_method': 'probed',
                'service_extrainfo': {'$ne': 'access denied'}
            }}}

    def searchowa(self):
        return {
            '$or': [
                self.searchscriptidout(
                    'http-headers',
                    re.compile('^ *(Location:.*(owa|exchweb)|X-OWA-Version)',
                               flags=re.MULTILINE | re.I)),
                self.searchscriptidout(
                    'http-auth-finder',
                    re.compile('/(owa|exchweb)',
                               flags=re.I)),
                self.searchscriptidout(
                    'http-title',
                    re.compile('Outlook Web A|(Requested resource was|'
                               'Did not follow redirect to ).*/(owa|exchweb)',
                               flags=re.I)),
                self.searchscriptidout(
                    'html-title',
                    re.compile('Outlook Web A|(Requested resource was|'
                               'Did not follow redirect to ).*/(owa|exchweb)',
                               flags=re.I))
            ]}

    def searchfile(self, fname):
        return self.searchscriptidout(
            {'$in': ['ftp-anon', 'afp-ls', 'gopher-ls',
                     'http-vlcstreamer-ls', 'nfs-ls', 'smb-ls']},
            fname)

    def searchhttptitle(self, title):
        return {'$or': [
            # new script name
            self.searchscriptidout('http-title', title),
            # old script name
            self.searchscriptidout('html-title', title)
        ]}

    def searchservicescript(self, srv, port=None):
        if port is None:
            return {
                'ports': {
                    '$elemMatch': {
                        'state_state': 'open',
                        '$or': [
                            {'service_name': srv},
                            {'service_product': srv},
                            {'service_version': srv},
                            {'service_extrainfo': srv},
                            {'service_hostname': srv},
                            {'scripts.id': srv},
                            {'scripts.output': srv}
                        ]
                    }}}
        return {
            'ports': {
                '$elemMatch': {
                    'state_state': 'open',
                    'port': port,
                    '$or': [
                        {'service_name': srv},
                        {'service_product': srv},
                        {'service_version': srv},
                        {'service_extrainfo': srv},
                        {'service_hostname': srv},
                        {'scripts.id': srv},
                        {'scripts.output': srv}
                    ]
                }}}

    def searchhostscript(self, txt):
        return {'scripts.output': txt}

    def searchhostscriptid(self, name):
        return {'scripts.id': name}

    def searchhostscriptidout(self, name, out):
        return {
            'scripts': {
                '$elemMatch': {
                    'id': name,
                    'output': out
                }}}

    def searchos(self, txt):
        return {
            '$or': [
                {'os.osclass.vendor': txt},
                {'os.osclass.osfamily': txt},
                {'os.osclass.osgen': txt}
            ]}

    def searchvsftpdbackdoor(self):
        return {
            'ports': {
                '$elemMatch': {
                    'protocol': 'tcp',
                    'state_state': 'open',
                    'service_product': 'vsftpd',
                    'service_version': '2.3.4',
                }}}

    def searchvulnintersil(self):
        # See MSF modules/auxiliary/admin/http/intersil_pass_reset.rb
        return {
            'ports': {
                '$elemMatch': {
                    'protocol': 'tcp',
                    'state_state': 'open',
                    'service_product': 'Boa HTTPd',
                    'service_version': re.compile('^0\\.9(3([^0-9]|$)|'
                                                  '4\\.([0-9]|0[0-9]|'
                                                  '1[0-1])([^0-9]|$))')
                }}}

    def searchproduct(self, product):
        return {'ports.service_product': product}

    def searchdevicetype(self, devtype):
        return {'ports.service_devicetype': devtype}

    def searchnetdev(self):
        return self.searchdevicetype({
            '$in': [
                'bridge',
                'broadband router',
                'firewall',
                'hub',
                'load balancer',
                'proxy server',
                'router',
                'switch',
                'WAP',
            ]})

    def searchphonedev(self):
        return self.searchdevicetype({
            '$in': [
                'PBX',
                'phone',
                'telecom-misc',
                'VoIP adapter',
                'VoIP phone',
            ]})

    def searchldapanon(self):
        return {'ports.service_extrainfo': 'Anonymous bind OK'}

    def searchtimeago(self, delta, neg=False):
        if not isinstance(delta, datetime.timedelta):
            delta = datetime.timedelta(seconds=delta)
        return {'endtime': {'$lt' if neg else '$gte':
                            datetime.datetime.now() - delta}}

    def searchtimerange(self, start, stop, neg=False):
        if not isinstance(start, datetime.datetime):
            start = datetime.datetime.fromtimestamp(start)
        if not isinstance(stop, datetime.datetime):
            stop = datetime.datetime.fromtimestamp(stop)
        if neg:
            return self.flt_or(
                {'endtime': {'$lt': start}},
                {'starttime': {'$gt': stop}}
            )
        return {'endtime': {'$gte': start}, 'starttime': {'$lte': stop}}

    def searchhop(self, hop, neg=False):
        try:
            hop = utils.ip2int(hop)
        except (TypeError, utils.socket.error):
            pass
        return {'traces.hops.ipaddr': {'$ne': hop} if neg else hop}

    def searchhopdomain(self, hop, neg=False):
        if neg:
            if type(hop) is utils.REGEXP_T:
                return {'traces.hops.domains': {'$not': hop}}
            return {'traces.hops.domains': {'$ne': hop}}
        return {'traces.hops.domains': hop}

    def searchhopname(self, hop, neg=False):
        if neg:
            if type(hop) is utils.REGEXP_T:
                return {'traces.hops.host': {'$not': hop}}
            return {'traces.hops.host': {'$ne': hop}}
        return self.flt_and(
            # This is indexed
            self.searchhopdomain(hop, neg=neg),
            # This is not
            {'traces.hops.host': hop},
        )

    def topvalues(self, field, flt, topnbr=10,
                  sortby=None, limit=None, skip=None,
                  least=False, archive=False):
        """
        This method makes use of the aggregation framework to produce
        top values for a given field or pseudo-field. Pseudo-fields are:
          - category / asnum / country
          - port
          - port:open / :closed / :filtered
          - portlist:open / :closed / :filtered
          - countports:open / :closed / :filtered
          - service / service:<portnbr>
          - probedservice / probedservice:<portnbr>
          - product / product:<portnbr>
          - devicetype / devicetype:<portnbr>
          - [port]script:<scriptid> / hostscript:<scriptid>
          - hop
        """
        aggrflt = {}
        specialproj = None
        specialflt = []
        outputproc = None
        # pseudo-fields
        if field == "category":
            field = "categories"
        elif field == "country":
            field = "infos.country_code"
        elif field == "city":
            flt = self.flt_and(
                flt,
                {"infos.country_code": {"$exists": True}},
                {"infos.city": {"$exists": True}}
            )
            specialproj = {"_id": 0,
                           "city": {"$concat": [
                               "$infos.country_code",
                               "###",
                               "$infos.city",
                           ]}}
            field = "city"
            outputproc = lambda x: {'count': x['count'],
                                    '_id': x['_id'].split('###')}
        elif field == "asnum":
            field = "infos.as_num"
        elif field == "as":
            flt = self.flt_and(
                flt,
                {"infos.as_num": {"$exists": True}},
            )
            specialproj = {
                "_id": 0,
                "as": {"$concat": [
                    # hack to convert the integer to a string and
                    # prevent the exception "$concat only supports
                    # strings, not NumberInt32"
                    {"$toLower": "$infos.as_num"},
                    "###",
                    "$infos.as_name",
                ]}}
            field = "as"
            outputproc = lambda x: {'count': x['count'],
                                    '_id': x['_id'].split('###')}
        elif field == "port":
            field = "ports.port"
        elif field.startswith("port:"):
            state = field.split(':', 1)[1]
            if state == "open":
                flt = self.flt_and(
                    flt,
                    self.searchopenport()
                )
            specialproj = {"_id": 0, "ports.port": 1, "ports.state_state": 1}
            specialflt = [
                {"$match": {"ports.state_state": state}},
                {"$project": {"ports.port": 1}}
            ]
            field = "ports.port"
        elif field.startswith("portlist:"):
            specialproj = {"ports.port": 1, "ports.state_state": 1}
            specialflt = [
                {"$project": {"ports.port": 1, "ports.state_state": 1}},
                # if the host has no ports attribute, we create an empty list
                {"$project": {"ports": {"$ifNull": ["$ports", []]}}},
                # we use $redact instead of $match to keep an empty
                # list when no port matches
                {"$redact": {"$cond": {"if": {"$eq": [{"$ifNull": ["$ports",
                                                                   None]},
                                                      None]},
                                       "then": {
                                           "$cond": {
                                               "if": {"$eq": [
                                                   "$state_state",
                                                   field.split(':', 1)[1]]},
                                               "then": "$$KEEP",
                                               "else": "$$PRUNE"}},
                                       "else": "$$DESCEND"}}},
                {"$project": {"portlist": {"$cond": [{"$eq": ["$ports", []]},
                                                     [0],
                                                     "$ports.port"]}}},
            ]
            field = "portlist"
        elif field.startswith('countports:'):
            # specialproj = {"_id": 0, "ports.port": 1,
            #                "ports.state_state": 1}
            # specialflt = [
            #     {"$match": {"ports.state_state":
            #                 field.split(':', 1)[1]}},
            #     {"$project": {"ports.port": 1}},
            #     {"$group": {"_id": "$ports.port",
            #                 "countports": {"$sum": 1}}},
            # ]
            # field = "countports"
            pass
        elif field == "service":
            field = "ports.service_name"
        elif field.startswith("service:"):
            port = int(field.split(':', 1)[1])
            flt = self.flt_and(flt, self.searchport(port))
            specialproj = {"_id": 0, "ports.port": 1, "ports.service_name": 1}
            specialflt = [
                {"$match": {"ports.port": port}},
                {"$project": {"ports.service_name": 1}}
            ]
            field = "ports.service_name"
        elif field == "probedservice":
            specialproj = {"_id": 0,
                           "ports.service_name": 1,
                           "ports.service_method": 1}
            specialflt = [
                {"$match": {"ports.service_method": "probed"}},
                {"$project": {"ports.service_name": 1}}
            ]
            field = "ports.service_name"
        elif field.startswith("probedservice:"):
            port = int(field.split(':', 1)[1])
            flt = self.flt_and(flt, self.searchport(port))
            specialproj = {"_id": 0, "ports.port": 1,
                           "ports.service_name": 1,
                           "ports.service_method": 1}
            specialflt = [
                {"$match": {"ports.port": port,
                            "ports.service_method": "probed"}},
                {"$project": {"ports.service_name": 1}}
            ]
            field = "ports.service_name"
        elif field == 'product':
            field = "ports.service_product"
        elif field.startswith('product:'):
            port = int(field.split(':', 1)[1])
            flt = self.flt_and(flt, self.searchport(port))
            specialproj = {"_id": 0, "ports.port": 1,
                           "ports.service_product": 1}
            specialflt = [
                {"$match": {"ports.port": port}},
                {"$project": {"ports.service_product": 1}}
            ]
            field = "ports.service_product"
        elif field == 'devicetype':
            field = "ports.service_devicetype"
        elif field.startswith('devicetype:'):
            port = int(field.split(':', 1)[1])
            flt = self.flt_and(flt, self.searchport(port))
            specialproj = {"_id": 0, "ports.port": 1,
                           "ports.service_devicetype": 1}
            specialflt = [
                {"$match": {"ports.port": port}},
                {"$project": {"ports.service_devicetype": 1}}
            ]
            field = "ports.service_devicetype"
        elif field == 'smb.dnsdomain':
            field = 'scripts.smb-os-discovery.domain_dns'
        elif field == 'smb.forest':
            field = 'scripts.smb-os-discovery.forest_dns'
        elif field.startswith('smb.'):
            field = 'scripts.smb-os-discovery.' + field[4:]
        elif (field.startswith('script:') or
              field.startswith('portscript:') or
              field.startswith('hostscript:')):
            scriptid = field.split(':', 1)[1]
            if ':' in scriptid:
                base = 'ports.scripts'
                port, scriptid = scriptid.split(':', 1)
                port = int(port)
            else:
                base = ("scripts"
                        if field.startswith('hostscript:')
                        else "ports.scripts")
                port, scriptid = None, field.split(':', 1)[1]
            specialproj = {"_id": 0, "%s.id" % base: 1, "%s.output" % base: 1}
            if port is not None:
                specialproj.update({'ports.port': 1})
            specialflt = [
                {"$match": ({"%s.id" % base: scriptid}
                            if port is None else
                            {"ports.scripts.id": scriptid,
                             "ports.port": port})},
                {"$project": {"%s.output" % base: 1}}
            ]
            field = "%s.output" % base
        elif field == 'domains':
            field = 'hostnames.domains'
        elif field.startswith('domains:'):
            level = int(field[8:]) - 1
            field = 'hostnames.domains'
            aggrflt = {
                "field": re.compile('^([^\\.]+\\.){%d}[^\\.]+$' % level)}
        elif field.startswith('cert.'):
            subfield = field[5:]
            field = 'ports.scripts.ssl-cert.' + subfield
        elif field.startswith('modbus.'):
            subfield = field[7:]
            field = 'ports.scripts.modbus-discover.' + subfield
        elif field.startswith('enip.'):
            subfield = field[5:]
            subfield = {
                "vendor": "Vendor",
                "product": "Product Name",
                "serial": "Serial Number",
                "devtype": "Device Type",
                "prodcode": "Product Code",
                "rev": "Revision",
                "ip": "Device IP",
            }.get(subfield, subfield)
            field = 'ports.scripts.enip-info.' + subfield
        elif field == 'hop':
            field = 'traces.hops.ipaddr'
            outputproc = lambda x: {'count': x['count'],
                                    '_id': utils.int2ip(x['_id'])}
        elif field.startswith('hop') and field[3] in ':>':
            specialproj = {"_id": 0,
                           "traces.hops.ipaddr": 1,
                           "traces.hops.ttl": 1}
            specialflt = [
                {"$match": {
                    "traces.hops.ttl": (
                        int(field[4:])
                        if field[3] == ':' else
                        {"$gt": int(field[4:])}
                    )}},
                {"$project": {"traces.hops.ipaddr": 1}}
            ]
            field = 'traces.hops.ipaddr'
            outputproc = lambda x: {'count': x['count'],
                                    '_id': utils.int2ip(x['_id'])}
        needunwind = ["categories", "ports", "ports.scripts", "scripts",
                      "extraports.filtered", "traces", "traces.hops",
                      "os.osmatch", "os.osclass", "hostnames",
                      "hostnames.domains"]
        aggr = []
        if flt:
            aggr += [{"$match": flt}]
        if sortby is not None and ((limit is not None) or (skip is not None)):
            aggr += [{"$sort": dict(sortby)}]
        if skip is not None:
            aggr += [{"$skip": skip}]
        if limit is not None:
            aggr += [{"$limit": limit}]
        if specialproj is None:
            aggr += [{"$project": {"_id": 0, field: 1}}]
        else:
            aggr += [{"$project": specialproj}]
        # hack to allow nested values as field
        # see <http://stackoverflow.com/questions/13708857/
        # mongodb-aggregation-framework-nested-arrays-subtract-expression>
        for i in xrange(field.count('.'), -1, -1):
            subfield = field.rsplit('.', i)[0]
            if subfield in needunwind:
                aggr += [{"$unwind": "$" + subfield}]
        aggr += specialflt
        # next step for previous hack
        aggr += [{"$project": {"field": "$" + field}}]
        if aggrflt:
            aggr += [{"$match": aggrflt}]
        else:
            # avoid null results
            aggr += [{"$match": {"field": {"$exists": True}}}]
        aggr += [{"$group": {"_id": "$field", "count": {"$sum": 1}}}]
        if least:
            aggr += [{"$sort": {"count": 1}}]
        else:
            aggr += [{"$sort": {"count": -1}}]
        if topnbr is not None:
            aggr += [{"$limit": topnbr}]
        if archive:
            res = self.db[self.colname_oldhosts].aggregate(aggr)['result']
        else:
            res = self.db[self.colname_hosts].aggregate(aggr)['result']
        if outputproc is not None:
            return map(outputproc, res)
        return res

    def parse_args(self, args, flt=None):
        if flt is None:
            flt = self.flt_empty
        if args.category is not None:
            flt = self.flt_and(flt, self.searchcategory(args.category))
        if args.country is not None:
            flt = self.flt_and(flt, self.searchcountry(args.country))
        if args.source is not None:
            flt = self.flt_and(flt, self.searchsource(args.source))
        if args.timeago is not None:
            flt = self.flt_and(flt, self.searchtimeago(args.timeago))
        if args.host is not None:
            flt = self.flt_and(flt, self.searchhost(args.host))
        if args.hostname is not None:
            flt = self.flt_and(
                flt,
                self.searchhostname(utils.str2regexp(args.hostname))
            )
        if args.domain is not None:
            flt = self.flt_and(
                flt,
                self.searchdomain(utils.str2regexp(args.domain))
            )
        if args.net is not None:
            flt = self.flt_and(flt, self.searchnet(args.net))
        if args.hop is not None:
            flt = self.flt_and(flt, self.searchhop(args.hop))
        if args.port is not None:
            port = args.port.replace('_', '/')
            if '/' in port:
                proto, port = port.split('/', 1)
            else:
                proto = 'tcp'
            port = int(port)
            flt = self.flt_and(
                flt,
                self.searchport(port=port, protocol=proto))
        if args.openport:
            flt = self.flt_and(flt, self.searchopenport())
        if args.service is not None:
            flt = self.flt_and(
                flt,
                self.searchservicescript(utils.str2regexp(args.service)))
        if args.script is not None:
            flt = self.flt_and(
                flt,
                self.searchscript(utils.str2regexp(args.script)))
        if args.hostscript is not None:
            flt = self.flt_and(
                flt,
                self.searchhostscript(utils.str2regexp(args.hostscript)))
        if args.svchostname is not None:
            flt = self.flt_and(
                flt,
                self.searchsvchostname(utils.str2regexp(args.svchostname)))
        if args.os is not None:
            flt = self.flt_and(
                flt,
                self.searchos(utils.str2regexp(args.os)))
        if args.anonftp:
            flt = self.flt_and(flt, self.searchftpanon())
        if args.anonldap:
            flt = self.flt_and(flt, self.searchldapanon())
        if args.authhttp:
            flt = self.flt_and(flt, self.searchhttpauth())
        if args.authbypassvnc:
            flt = self.flt_and(flt, self.searchvncauthbypass())
        if args.ypserv:
            flt = self.flt_and(flt, self.searchypserv())
        if args.nfs:
            flt = self.flt_and(flt, self.searchnfs())
        if args.x11:
            flt = self.flt_and(flt, self.searchx11access())
        if args.xp445:
            flt = self.flt_and(flt, self.searchxp445())
        if args.owa:
            flt = self.flt_and(flt, self.searchowa())
        if args.vuln_boa:
            flt = self.flt_and(flt, self.searchvulnintersil())
        if args.torcert:
            flt = self.flt_and(flt, self.searchtorcert())
        if args.sshkey is not None:
            flt = self.flt_and(flt, self.searchsshkey(args.sshkey))
        return flt


class MongoDBPassive(MongoDB, DBPassive):

    def __init__(self, host, dbname,
                 colname_passive="passive",
                 colname_ipdata="ipdata",
                 username=None, password=None, mechanism=None, **_):
        MongoDB.__init__(self, host, dbname,
                         username=username,
                         password=password,
                         mechanism=mechanism)
        self.colname_passive = colname_passive
        self.colname_ipdata = colname_ipdata
        self.indexes = {
            self.colname_passive: [
                [('port', pymongo.ASCENDING)],
                [('value', pymongo.ASCENDING)],
                [('targetval', pymongo.ASCENDING)],
                [('recontype', pymongo.ASCENDING)],
                [('firstseen', pymongo.ASCENDING)],
                [('lastseen', pymongo.ASCENDING)],
                [('sensor', pymongo.ASCENDING)],
                [
                    ('addr', pymongo.ASCENDING),
                    ('recontype', pymongo.ASCENDING),
                    ('port', pymongo.ASCENDING),
                ],
            ],
            self.colname_ipdata: [
                [('country_code', pymongo.ASCENDING)],
                [('location_id', pymongo.ASCENDING)],
                [('as_num', pymongo.ASCENDING)],
            ],
        }
        self.specialindexes = {
            self.colname_passive: [
                # HTTP Auth basic
                ([('infos.username', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.password', pymongo.ASCENDING)],
                 {"sparse": True}),
                # DNS
                ([('infos.domain', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.domaintarget', pymongo.ASCENDING)],
                 {"sparse": True}),
                # SSL
                ([('infos.md5hash', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.sha1hash', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.issuer', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.subject', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.pubkeyalgo', pymongo.ASCENDING)],
                 {"sparse": True}),
            ],
            self.colname_ipdata: [
                ([('addr', pymongo.ASCENDING)],
                 {'unique': True}),
            ],
        }

    def init(self):
        """Initializes the "passive" columns, i.e., drops the columns, and
creates the default indexes."""
        self.db[self.colname_passive].drop()
        self.db[self.colname_ipdata].drop()
        self.create_indexes()

    def get(self, spec, **kargs):
        """Queries the passive column with the provided filter "spec", and
returns a MongoDB cursor.

This should be very fast, as no operation is done (the cursor is only
returned). Next operations (e.g., .count(), enumeration, etc.) might
take a long time, depending on both the operations and the filter.

Any keyword argument is passed to the .find() method of the Mongodb
column object, without any validation (and might have no effect if it
is not expected)."""
        return self.db[self.colname_passive].find(spec, **kargs)

    def get_one(self, spec, **kargs):
        """Same function as get, except .find_one() method is called
instead of .find(), so the first record matching "spec" (or None) is
returned.

Unlike get(), this function might take a long time, depending
on "spec" and the indexes set on COLNAME_PASSIVE column."""
        return self.db[self.colname_passive].find_one(spec, **kargs)

    def update(self, spec, **kargs):
        """Updates the first record matching "spec" in the "passive" column,
setting values according to the keyword arguments.
"""
        self.db[self.colname_passive].update(spec, {'$set': kargs})

    def update_incr(self, spec, **kargs):
        """Updates the first record matching "spec" in the "passive" column,
setting values according to the keyword arguments, and increment the
field "count" by one.
"""
        self.db[self.colname_passive].update(spec, {'$set': kargs,
                                                    '$inc': {'count': 1}})

    def insert(self, spec, getinfos=None):
        """Inserts the record "spec" into the passive column."""
        if getinfos is not None:
            spec.update(getinfos(spec))
        self.db[self.colname_passive].insert(spec)
        if 'addr' in spec:
            self.set_data(spec['addr'])

    def insert_or_update(self, timestamp, spec, getinfos=None):
        current = self.get_one(spec, fields=['firstseen', 'lastseen'])
        if current:
            firstseen = min(timestamp, current['firstseen'])
            lastseen = max(timestamp, current['lastseen'])
            self.update_incr({'_id': current['_id']},
                             firstseen=firstseen,
                             lastseen=lastseen)
        else:
            spec.update({'firstseen': timestamp, 'lastseen': timestamp,
                         'count': 1})
            self.insert(spec, getinfos=getinfos)

    def insert_or_update_mix(self, spec, getinfos=None):
        """Updates the first record matching "spec" (without
        "firstseen", "lastseen" and "count") by mixing "firstseen",
        "lastseen" and "count" from "spec" and from the database.

        This is usefull to mix records from different databases.

        """
        if 'firstseen' in spec:
            firstseen = spec['firstseen']
            del spec['firstseen']
        else:
            firstseen = None
        if 'lastseen' in spec:
            lastseen = spec['lastseen']
            del spec['lastseen']
        else:
            lastseen = None
        if 'count' in spec:
            count = spec['count']
            del spec['count']
        else:
            count = None
        if 'infos' in spec:
            infos = spec['infos']
            del spec['infos']
        else:
            infos = None
        current = self.get_one(spec,
                               fields=['firstseen', 'lastseen', 'count'])
        if current:
            if firstseen is not None:
                firstseen = min(firstseen, current['firstseen'])
            else:
                firstseen = current['firstseen']
            if lastseen is not None:
                lastseen = max(lastseen, current['lastseen'])
            else:
                lastseen = current['lastseen']
            if count is not None:
                count += current['count']
            else:
                count = current['count'] + 1  # at least...
            self.update({'_id': current['_id']},
                        firstseen=firstseen,
                        lastseen=lastseen,
                        count=count)
        else:
            if firstseen is not None:
                spec.update({'firstseen': firstseen})
            if lastseen is not None:
                spec.update({'lastseen': lastseen})
            if count is None:
                spec.update({'count': 1})
            else:
                spec.update({'count': count})
            if infos is not None:
                spec.update({'infos': infos})
            elif getinfos is not None:
                spec.update(getinfos(spec))
            self.insert(spec)

    def remove(self, spec):
        self.db[self.colname_passive].remove(spec)

    def searchsensor(self, sensor, neg=False):
        if neg:
            if type(sensor) is utils.REGEXP_T:
                return {'sensor': {'$not': sensor}}
            return {'sensor': {'$ne': sensor}}
        return {'sensor': sensor}

    def searchuseragent(self, useragent):
        return {
            'recontype': 'HTTP_CLIENT_HEADER',
            'source': 'USER-AGENT',
            'value': useragent
        }

    def searchdns(self, name, reverse=False, subdomains=False):
        return {
            'recontype': 'DNS_ANSWER',
            (('infos.domaintarget' if reverse else 'infos.domain')
             if subdomains else ('targetval' if reverse else 'value')): name,
        }

    def searchcert(self):
        return {'recontype': 'SSL_SERVER',
                'source': 'cert'}

    def searchcertsubject(self, expr):
        return {'recontype': 'SSL_SERVER',
                'source': 'cert',
                'infos.subject': expr}

    def searchcertissuer(self, expr):
        return {'recontype': 'SSL_SERVER',
                'source': 'cert',
                'infos.issuer': expr}

    def searchbasicauth(self):
        return {
            'recontype': {'$in': ['HTTP_CLIENT_HEADER',
                                  'HTTP_CLIENT_HEADER_SERVER']},
            'source': {'$in': ['AUTHORIZATION',
                               'PROXY-AUTHORIZATION']},
            'value': re.compile('^Basic'),
        }

    def searchhttpauth(self):
        return {
            'recontype': {'$in': ['HTTP_CLIENT_HEADER',
                                  'HTTP_CLIENT_HEADER_SERVER']},
            'source': {'$in': ['AUTHORIZATION',
                               'PROXY-AUTHORIZATION']},
        }

    def searchftpauth(self):
        return {'recontype': {'$in': ['FTP_CLIENT', 'FTP_SERVER']}}

    def searchpopauth(self):
        return {'recontype': {'$in': ['POP_CLIENT', 'POP_SERVER']}}

    def searchcountry(self, code, neg=False):
        return {'addr': {'$nin' if neg else '$in':
                         self.knownip_bycountry(code)}}

    def searchasnum(self, asnum, neg=False):
        return {'addr': {'$nin' if neg else '$in': self.knownip_byas(asnum)}}

    def searchtimeago(self, delta, neg=False, new=False):
        field = 'lastseen' if new else 'firstseen'
        if isinstance(delta, datetime.timedelta):
            delta = delta.total_seconds()
        now = datetime.datetime.now()
        now = int(now.strftime('%s')) + now.microsecond * 1e-6
        return {field: {'$lt' if neg else '$gte': now - delta}}

    def knownip_bycountry(self, code):
        return self.db[self.colname_ipdata].find(
            {'country_code': code}).distinct('addr')

    def knownip_byas(self, asnum):
        if type(asnum) is str:
            if asnum.startswith('AS'):
                asnum = asnum[2:]
            asnum = int(asnum)
        return self.db[self.colname_ipdata].find(
            {'as_num': asnum}).distinct('addr')

    def set_data(self, addr, force=False):
        """Sets IP information in colname_ipdata."""
        if not force and self.get_data(addr) is not None:
            return
        for data in [self.globaldb.data.country_byip(addr),
                     self.globaldb.data.as_byip(addr),
                     self.globaldb.data.location_byip(addr)]:
            if data is not None:
                self.db[self.colname_ipdata].update(
                    {'addr': addr},
                    {'$set': data},
                    upsert=True)

    def update_country(self, start, stop, code, create=False):
        # we first update existing records
        self.db[self.colname_ipdata].update(
            self.searchrange(start, stop),
            {'$set': {'country_code': code}})
        # then (if requested), we add a record for addresses we
        # have in database (first the active one, then the
        # passive)
        if create:
            for addr in self.get_known_ips(start, stop):
                self.db[self.colname_ipdata].update(
                    {'addr': addr},
                    {'$set': {'country_code': code}},
                    upsert=True)

    def update_city(self, start, stop, locid, create=False):
        # we first update existing records
        self.db[self.colname_ipdata].update(
            self.searchrange(start, stop),
            {'$set': {'location_id': locid}})
        # then (if requested), we add a record for addresses we
        # have in database (first the active one, then the
        # passive)
        if create:
            for addr in self.get_known_ips(start, stop):
                self.db[self.colname_ipdata].update(
                    {'addr': addr},
                    {'$set': {'location_id': locid}},
                    upsert=True)

    def update_as(self, start, stop, asnum, asname, create=False):
        if asname is None:
            updatespec = {'as_num': asnum}
        else:
            updatespec = {'as_num': asnum, 'as_name': asname}
        # we first update existing records
        self.db[self.colname_ipdata].update(
            self.searchrange(start, stop),
            {'$set': updatespec})
        # then (if requested), we add a record for addresses we
        # have in database (first the active one, then the
        # passive)
        if create:
            for addr in self.get_known_ips(start, stop):
                self.db[self.colname_ipdata].update(
                    {'addr': addr},
                    {'$set': updatespec},
                    upsert=True)

    def get_data(self, addr):
        """Gets IP information in colname_ipdata."""
        data = self.db[self.colname_ipdata].find_one({'addr': addr})
        if data is not None:
            del data['_id']
        return data

    def get_known_ips(self, start, stop):
        self.get(self.searchrange(start, stop)).distinct('addr')


class MongoDBData(MongoDB, DBData):

    def __init__(self, host, dbname,
                 colname_geoip_country="geoipcountry",
                 colname_geoip_as="geoipas",
                 colname_geoip_city="geoipcity",
                 colname_country_codes="countries",
                 colname_city_locations="cities",
                 username=None, password=None, mechanism=None, **_):
        MongoDB.__init__(self, host, dbname,
                         username=username,
                         password=password,
                         mechanism=mechanism)
        self.colname_geoip_country = colname_geoip_country
        self.colname_geoip_as = colname_geoip_as
        self.colname_geoip_city = colname_geoip_city
        self.colname_country_codes = colname_country_codes
        self.colname_city_locations = colname_city_locations
        self.indexes = {
            self.colname_geoip_country: [
                [('start', pymongo.ASCENDING)],
                [('country_code', pymongo.ASCENDING)],
            ],
            self.colname_geoip_as: [
                [('start', pymongo.ASCENDING)],
                [('as_num', pymongo.ASCENDING)],
            ],
            self.colname_geoip_city: [
                [('start', pymongo.ASCENDING)],
                [('location_id', pymongo.ASCENDING)],
            ],
            self.colname_city_locations: [
                [('location_id', pymongo.ASCENDING)],
                [('country_code', pymongo.ASCENDING)],
                [('region_code', pymongo.ASCENDING)],
                [('city', pymongo.ASCENDING)],
                [('loc', pymongo.GEOSPHERE)],
            ],
        }
        self.specialindexes = {
            self.colname_country_codes: [
                ([('country_code', pymongo.ASCENDING)],
                 {'unique': True}),
            ],
        }

    def init(self):
        """Initializes the data columns, and creates the default indexes."""
        self.db[self.colname_geoip_country].drop()
        self.db[self.colname_geoip_as].drop()
        self.db[self.colname_geoip_city].drop()
        self.db[self.colname_country_codes].drop()
        self.db[self.colname_city_locations].drop()
        self.create_indexes()

    def feed_geoip_country(self, fname, feedipdata=None,
                           createipdata=False):
        codes = {}
        with open(fname) as fdesc:
            for line in fdesc:
                if line.endswith('\n'):
                    line = line[:-1]
                if line.endswith('"'):
                    line = line[:-1]
                if line.startswith('"'):
                    line = line[1:]
                line = line.split('","')
                self.db[self.colname_geoip_country].insert({
                    'start': int(line[2]),
                    'stop': int(line[3]),
                    'country_code': line[4]
                })
                if feedipdata is not None:
                    for dbinst in feedipdata:
                        dbinst.update_country(
                            int(line[2]), int(line[3]), line[4],
                            create=createipdata)
                if line[4] not in codes:
                    codes[line[4]] = line[5]
        for code, name in codes.iteritems():
            self.db[self.colname_country_codes].insert({
                'country_code': code,
                'name': name})

    def feed_geoip_city(self, fname, feedipdata=None,
                        createipdata=False):
        with open(fname) as fdesc:
            # Skip the two first lines
            fdesc.readline()
            fdesc.readline()
            for line in fdesc:
                if line.endswith('\n'):
                    line = line[:-1]
                if line.endswith('"'):
                    line = line[:-1]
                if line.startswith('"'):
                    line = line[1:]
                line = line.split('","')
                self.db[self.colname_geoip_city].insert({
                    'start': int(line[0]),
                    'stop': int(line[1]),
                    'location_id': int(line[2])
                })
                if feedipdata is not None:
                    for dbinst in feedipdata:
                        dbinst.update_city(
                            int(line[0]), int(line[1]), line[2],
                            create=createipdata)

    def feed_city_location(self, fname):
        with open(fname) as fdesc:
            # Skip the two first lines
            fdesc.readline()
            fdesc.readline()
            for line in fdesc:
                if line.endswith('\n'):
                    line = line[:-1]
                # Pop an integer
                i = line.index(',')
                parsedline = [int(line[:i])]
                line = line[i + 1:]
                # Pop 4 strings or None
                for i in xrange(4):
                    i = line.index('",')
                    curval = line[1:i]
                    if curval:
                        parsedline.append(curval.decode('latin-1'))
                    else:
                        parsedline.append(None)
                    line = line[i + 2:]
                # Pop 2 floats or None
                for i in xrange(2):
                    i = line.index(',')
                    curval = line[:i]
                    if curval:
                        parsedline.append(float(curval))
                    else:
                        parsedline.append(None)
                    line = line[i + 1:]
                # Pop 1 int or None
                i = line.index(',')
                curval = line[:i]
                if curval:
                    parsedline.append(int(curval))
                else:
                    parsedline.append(None)
                line = line[i + 1:]
                # Pop 1 int or None (at the end of the line)
                if line:
                    parsedline.append(int(line))
                else:
                    parsedline.append(None)
                try:
                    infos = {}
                    for i, k in [(0, 'location_id'),
                                 (1, 'country_code'),
                                 (2, 'region_code'),
                                 (3, 'city'),
                                 (4, 'postal_code'),
                                 (7, 'metro_code'),
                                 (8, 'area_code')]:
                        if parsedline[i] is not None:
                            infos[k] = parsedline[i]
                    if parsedline[5] is not None and \
                       parsedline[6] is not None and \
                       (parsedline[5], parsedline[6]) != (0., 0.):
                        infos['loc'] = {
                            'type': 'Point',
                            'coordinates': [parsedline[6], parsedline[5]],
                        }
                    self.db[self.colname_city_locations].insert(infos)
                except Exception as exc:
                    # FIXME Error message
                    print exc
                    print line
                    raise exc

    def feed_geoip_asnum(self, fname, feedipdata=None,
                         createipdata=False):
        with open(fname) as fdesc:
            for line in fdesc:
                if line.endswith('\n'):
                    line = line[:-1]
                line = line.split(',', 2)
                spec = {
                    'start': int(line[0]),
                    'stop': int(line[1]),
                }
                data = line[2]
                if data.endswith('"'):
                    data = data[:-1]
                if data.startswith('"'):
                    data = data[1:]
                if data.startswith('AS'):
                    data = data.split(None, 1)
                    spec['as_num'] = int(data[0][2:])
                    if len(data) == 2:
                        spec['as_name'] = data[1].decode('latin-1')
                else:
                    spec['as_num'] = -1
                    spec['as_name'] = data.decode('latin-1')
                self.db[self.colname_geoip_as].insert(spec)
                if feedipdata is not None:
                    for dbinst in feedipdata:
                        dbinst.update_as(spec['start'], spec['stop'],
                                         spec['as_num'],
                                         spec.get('as_name'),
                                         create=createipdata)

    def country_name_by_code(self, code):
        rec = self.db[self.colname_country_codes].find_one(
            {'country_code': code},
            fields=['name'])
        if rec:
            return rec['name']
        return rec

    def country_codes_by_name(self, name):
        return self.db[self.colname_country_codes].find({
            'name': name}).distinct('country_code')

    def find_data_byip(self, addr, column):
        try:
            addr = utils.ip2int(addr)
        except (TypeError, utils.socket.error):
            pass
        rec = self.db[column].find_one({'start': {'$lte': addr}},
                                       sort=[('start', -1)])
        if rec and addr <= rec['stop']:
            del rec['_id'], rec['start'], rec['stop']
            return rec

    def country_byip(self, addr):
        rec = self.find_data_byip(addr, self.colname_geoip_country)
        if rec:
            name = self.country_name_by_code(rec['country_code'])
            if name:
                rec['country_name'] = name
        return rec

    def as_byip(self, addr):
        return self.find_data_byip(addr, self.colname_geoip_as)

    def locationid_byip(self, addr):
        return self.find_data_byip(addr, self.colname_geoip_city)

    def location_byid(self, locid):
        rec = self.db[self.colname_city_locations].find_one(
            {'location_id': locid})
        if rec:
            del rec['_id'], rec['location_id']
        return rec

    def location_byip(self, addr):
        locid = self.locationid_byip(addr)
        if locid:
            return self.location_byid(locid.get('location_id'))

    def infos_byip(self, addr):
        infos = {}
        for infos_byip in [self.country_byip,
                           self.as_byip,
                           self.location_byip]:
            newinfos = infos_byip(addr)
            if newinfos is not None:
                infos.update(newinfos)
        if infos:
            return infos

    def ipranges_bycountry(self, code):
        return [
            (x['start'], x['stop']) for x in
            self.db[self.colname_geoip_country].find(
                {'country_code': code},
                fields=['start', 'stop'])
        ]

    def ipranges_byas(self, asnum):
        if type(asnum) is str:
            if asnum.startswith('AS'):
                asnum = asnum[2:]
            asnum = int(asnum)
        return [
            (x['start'], x['stop']) for x in
            self.db[self.colname_geoip_as].find(
                {'as_num': asnum},
                fields=['start', 'stop'])
        ]
