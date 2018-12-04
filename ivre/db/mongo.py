#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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

"""This sub-module contains functions to interact with the MongoDB
databases.

"""


try:
    from collections import OrderedDict
except ImportError:
    # fallback to dict for Python 2.6
    OrderedDict = dict
from copy import deepcopy
import datetime
import json
import os
import re
import socket
import struct
import time
import uuid


from future.builtins import bytes, range
from future.utils import viewitems
from past.builtins import basestring
import bson
import pymongo


from ivre.db import DB, DBActive, DBNmap, DBPassive, DBAgent, DBView, LockError
from ivre import config, passive, utils, xmlnmap


class Nmap2Mongo(xmlnmap.Nmap2DB):
    @staticmethod
    def _to_binary(data):
        return bson.Binary(data)


def _old_array(*values, **kargs):
    """Returns a string construction using '$concat' to replace arrays for
MongoDB < 3.2.

    Uses kargs because Python 2.7 would not accept this:

    def _old_array(*values, sep="###", convert_to_string=False):

    """
    sep = kargs.get("sep", "###")
    convert_to_string = kargs.get("convert_to_string", False)
    result = []
    values = iter(values)
    try:
        elt = next(values)
    except StopIteration:
        return ""
    # $toLower is used as a hack to convert a value to a string and
    # prevent the exception "$concat only supports strings, not ..."
    result.append({'$toLower': elt} if convert_to_string else elt)
    for elt in values:
        result.extend([sep, {'$toLower': elt} if convert_to_string else elt])
    if len(result) == 1:
        return result
    return {'$concat': result}


class MongoDB(DB):

    schema_migrations = {}
    schema_migrations_indexes = {}
    schema_latest_versions = {}
    needunwind = []
    ipaddr_fields = []
    no_limit = 0

    def __init__(self, host, dbname,
                 username=None, password=None, mechanism=None,
                 maxscan=None, maxtime=None,
                 **_):
        self.host = host
        self.dbname = dbname
        self.username = username
        self.password = password
        self.mechanism = mechanism
        try:
            self.maxscan = int(maxscan)
        except TypeError:
            self.maxscan = None
        try:
            self.maxtime = int(maxtime)
        except TypeError:
            self.maxtime = None
        self.indexes = {}
        self.hint_indexes = {}

    def set_limits(self, cur):
        if self.maxscan is not None:
            cur.max_scan(self.maxscan)
        if self.maxtime is not None:
            cur.max_time_ms(self.maxtime)
        return cur

    def get_hint(self, spec):
        """Given a query spec, return an appropriate index in a form
        suitable to be passed to Cursor.hint().

        """
        for fieldname, hint in viewitems(self.hint_indexes):
            if fieldname in spec:
                return hint

    @property
    def db_client(self):
        """The DB connection."""
        try:
            return self._db_client
        except AttributeError:
            self._db_client = pymongo.MongoClient(
                host=self.host,
                read_preference=pymongo.ReadPreference.SECONDARY_PREFERRED
            )
            return self._db_client

    @property
    def db(self):
        """The DB."""
        try:
            return self._db
        except AttributeError:
            self._db = self.db_client[self.dbname]
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

    @property
    def server_info(self):
        """Server information."""
        try:
            return self._server_info
        except AttributeError:
            self._server_info = self.db_client.server_info()
            return self._server_info

    @property
    def mongodb_32_more(self):
        """True iff MongoDB server version is 3.2 or more."""
        try:
            return self._mongodb_32_more
        except AttributeError:
            self._mongodb_32_more = self.server_info['versionArray'] >= [3, 2]
            return self._mongodb_32_more

    @property
    def find(self):
        """Wrapper around column .find() method, depending on pymongo
        version.

        """
        try:
            return self._find
        except AttributeError:
            if pymongo.version_tuple[0] > 2:
                def _find(colname, *args, **kargs):
                    if 'spec' in kargs:
                        kargs['filter'] = kargs.pop('spec')
                    if 'fields' in kargs:
                        kargs['projection'] = kargs.pop('fields')
                    return self.db[colname].find(*args, **kargs)
            else:
                def _find(colname, *args, **kargs):
                    return self.db[colname].find(*args, **kargs)
            self._find = _find
            return self._find

    @property
    def find_one(self):
        """Wrapper around collection .find_one() method, depending on
        pymongo version.

        """
        try:
            return self._find_one
        except AttributeError:
            if pymongo.version_tuple[0] > 2:
                def _find_one(colname, *args, **kargs):
                    if 'spec_or_id' in kargs:
                        kargs['filter_or_id'] = kargs.pop('spec_or_id')
                    if 'fields' in kargs:
                        kargs['projection'] = kargs.pop('fields')
                    return self.db[colname].find_one(*args, **kargs)
                self._find_one = _find_one
            else:
                def _find_one(colname, *args, **kargs):
                    return self.db[colname].find_one(*args, **kargs)
                self._find_one = _find_one
            return self._find_one

    def _get_cursor(self, column, flt, **kargs):
        """Like .get(), but returns a MongoDB cursor (suitable for use with
e.g.  .explain()) based on the column and a filter.

        """
        if "fields" in kargs and any(fld in kargs["fields"]
                                     for fld in self.ipaddr_fields):
            fields = []
            for fld in kargs["fields"]:
                if fld in self.ipaddr_fields:
                    fields.extend(['%s_0' % fld, '%s_1' % fld])
                else:
                    fields.append(fld)
            kargs["fields"] = fields
        if "sort" in kargs and any(fld in (field for field, _ in kargs["sort"])
                                   for fld in self.ipaddr_fields):
            sort = []
            for fld, way in kargs["sort"]:
                if fld in self.ipaddr_fields:
                    sort.extend([('%s_0' % fld, way), ('%s_1' % fld, way)])
                else:
                    sort.append((fld, way))
            kargs["sort"] = sort
        return self.set_limits(self.find(column, flt, **kargs))

    def count(self, *args, **kargs):
        return self._get(*args, **kargs).count()

    @staticmethod
    def ip2internal(addr):
        if isinstance(addr, list):
            return addr
        return [val - 0x8000000000000000 for val in
                struct.unpack("!QQ", utils.ip2bin(addr))]

    @staticmethod
    def internal2ip(addr):
        return utils.bin2ip(
            struct.pack("!QQ", *(val + 0x8000000000000000 for val in addr))
        )

    @staticmethod
    def serialize(obj):
        if isinstance(obj, bson.ObjectId):
            return utils.encode_hex(obj.binary)
        return DB.serialize(obj)

    def explain(self, cursor, indent=None):
        return json.dumps(cursor.explain(), indent=indent,
                          default=self.serialize)

    def create_indexes(self):
        for colname, indexes in viewitems(self.indexes):
            for index in indexes:
                self.db[colname].create_index(index[0], **index[1])

    def ensure_indexes(self):
        for colname, indexes in viewitems(self.indexes):
            for index in indexes:
                self.db[colname].ensure_index(index[0], **index[1])

    def _migrate_update_record(self, colname, recid, update):
        """Define how an update is handled. Purpose-specific subclasses may
want to do something special here, e.g., mix with other records.

        """
        return self.db[colname].update({"_id": recid}, update)

    def migrate_schema(self, colname, version):
        """Process to schema migrations in column `colname` starting
        from `version`.

        """
        failed = 0
        while version in self.schema_migrations[colname]:
            new_version, migration_function = self.schema_migrations[
                colname][version]
            utils.LOGGER.info(
                "Migrating column %s from version %r to %r",
                colname, version, new_version,
            )
            # Ensuring new indexes
            new_indexes = self.schema_migrations_indexes[colname].get(
                new_version, {}
            ).get("ensure", [])
            if new_indexes:
                utils.LOGGER.info(
                    "Creating new indexes...",
                )
            if self.mongodb_32_more:
                try:
                    self.db[colname].create_indexes(
                        [
                            pymongo.IndexModel(idx[0], **idx[1])
                            for idx in new_indexes
                        ]
                    )
                except pymongo.errors.OperationFailure:
                    utils.LOGGER.debug("Cannot create indexes %r",
                                       new_indexes, exc_info=True)
            else:
                for idx in new_indexes:
                    try:
                        self.db[colname].create_index(idx[0], **idx[1])
                    except pymongo.errors.OperationFailure:
                        utils.LOGGER.debug("Cannot create index %s", idx,
                                           exc_info=True)
            if new_indexes:
                utils.LOGGER.info(
                    "  ... Done.",
                )
            utils.LOGGER.info(
                "Migrating records...",
            )
            updated = False
            # unlimited find()!
            for i, record in enumerate(self.find(colname,
                                                 self.searchversion(version),
                                                 no_cursor_timeout=True)):
                try:
                    update = migration_function(record)
                    if update is not None:
                        updated = True
                        self._migrate_update_record(colname, record["_id"],
                                                    update)
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate result %r", record, exc_info=True,
                    )
                    failed += 1
                if (i + 1) % 100000 == 0:
                    utils.LOGGER.info(
                        "  %d records migrated", i + 1
                    )
            utils.LOGGER.info(
                "  ... Done.",
            )
            # Checking for required actions on indexes
            utils.LOGGER.info(
                "  Performing other actions on indexes...",
            )
            for action, indexes in viewitems(
                    self.schema_migrations_indexes[colname].get(
                        new_version, {}
                    )
            ):
                if action == "ensure":
                    continue
                function = getattr(self.db[colname], "%s_index" % action)
                for idx in indexes:
                    try:
                        function(idx[0], **idx[1])
                    except pymongo.errors.OperationFailure:
                        (utils.LOGGER.warning if updated
                         else utils.LOGGER.debug)(
                            "Cannot %s index %s", action, idx,
                            exc_info=True
                        )
            utils.LOGGER.info(
                "  ... Done.",
            )
            utils.LOGGER.info(
                "Migration of column %s from version %r to %r DONE",
                colname, version, new_version,
            )
            version = new_version
        if failed:
            utils.LOGGER.info("Failed to migrate %d documents", failed)

    def cmp_schema_version(self, colname, document):
        """Returns 0 if the `document`'s schema version matches the
        code's current version for `colname`, -1 if it is higher (you
        need to update IVRE), and 1 if it is lower (you need to call
        .migrate_schema()).

        """
        val1 = self.schema_latest_versions.get(colname, 0)
        val2 = document.get("schema_version", 0)
        return (val1 > val2) - (val1 < val2)

    def _topvalues(self, field, flt=None, topnbr=10, sort=None,
                   limit=None, skip=None, least=False, aggrflt=None,
                   specialproj=None, specialflt=None, countfield=None):
        """This method makes use of the aggregation framework to
        produce top values for a given field.

        """
        if flt is None:
            flt = self.flt_empty
        if aggrflt is None:
            aggrflt = self.flt_empty
        if specialflt is None:
            specialflt = []
        pipeline = []
        if flt:
            pipeline += [{"$match": flt}]
        if sort is not None and ((limit is not None) or (skip is not None)):
            pipeline += [{"$sort": OrderedDict(sort)}]
        if skip is not None:
            pipeline += [{"$skip": skip}]
        if limit is not None:
            pipeline += [{"$limit": limit}]
        project = {"_id": 0, field: 1} if specialproj is None else specialproj
        if countfield is not None:
            project[countfield] = 1
        pipeline += [{"$project": project}]
        # hack to allow nested values as field
        # see <http://stackoverflow.com/questions/13708857/
        # mongodb-aggregation-framework-nested-arrays-subtract-expression>
        for i in range(field.count('.'), -1, -1):
            subfield = field.rsplit('.', i)[0]
            if subfield in self.needunwind:
                pipeline += [{"$unwind": "$" + subfield}]
        pipeline += specialflt
        # next step for previous hack
        project = {"field": "$%s" % field}
        if countfield is not None:
            project["count"] = "$%s" % countfield
        pipeline += [{"$project": project}]
        if aggrflt:
            pipeline += [{"$match": aggrflt}]
        else:
            # avoid null results
            pipeline += [{"$match": {"field": {"$exists": True}}}]
        pipeline += [{"$group": {"_id": "$field", "count": {
            "$sum": 1 if countfield is None else "$count"
        }}}]
        if least:
            pipeline += [{"$sort": {"count": 1}}]
        else:
            pipeline += [{"$sort": {"count": -1}}]
        if topnbr is not None:
            pipeline += [{"$limit": topnbr}]
        return pipeline

    def _distinct_pipeline(self, field, flt=None, sort=None, limit=None,
                           skip=None, is_ipfield=False):
        """This method makes use of the aggregation framework to
        produce distinct values for a given field.

        """
        pipeline = []
        if flt:
            pipeline.append({'$match': flt})
        if sort:
            pipeline.append({'$sort': OrderedDict(sort)})
        if skip is not None:
            pipeline += [{"$skip": skip}]
        if limit is not None:
            pipeline += [{"$limit": limit}]
        # hack to allow nested values as field
        # see <http://stackoverflow.com/questions/13708857/
        # mongodb-aggregation-framework-nested-arrays-subtract-expression>
        for i in range(field.count('.'), -1, -1):
            subfield = field.rsplit('.', i)[0]
            if subfield in self.needunwind:
                pipeline += [{"$unwind": "$" + subfield}]
        if is_ipfield:
            if self.mongodb_32_more:
                pipeline.append(
                    {'$project': {field: ['$%s_0' % field, '$%s_1' % field]}}
                )
            else:
                pipeline.append(
                    {'$project': {field: _old_array(
                        '$%s_0' % field, '$%s_1' % field,
                        convert_to_string=True,
                    )}}
                )
        pipeline.append({'$group': {'_id': '$%s' % field}})
        return pipeline

    def _distinct(self, column, field, flt=None, sort=None, limit=None,
                  skip=None):
        """This method makes use of the aggregation framework to
        produce distinct values for a given field in a given column.

        """
        is_ipfield = field in self.ipaddr_fields
        cursor = self.set_limits(
            self.db[column].aggregate(
                self._distinct_pipeline(field, flt=flt, sort=sort, limit=limit,
                                        skip=skip, is_ipfield=is_ipfield),
                cursor={}
            )
        )
        if is_ipfield:
            if self.mongodb_32_more:
                return (None if res['_id'][0] is None else res['_id']
                        for res in cursor)
            return ([int(val) for val in res] if res[0] else None
                    for res in (res['_id'].split('###') for res in cursor))
        return (res['_id'] for res in cursor)

    # filters
    flt_empty = {}

    @staticmethod
    def str2id(string):
        return bson.ObjectId(string)

    @staticmethod
    def str2flt(string):
        return json.loads(string)

    @staticmethod
    def to_binary(data):
        return bson.Binary(data)

    @classmethod
    def flt2str(cls, flt):
        return json.dumps(flt, default=cls.serialize)

    @staticmethod
    def _flt_and(cond1, cond2):
        """Returns a filter which will accept results if and only if
        they are accepted by both cond1 and cond2.

        """
        cond1k = set(cond1)
        cond2k = set(cond2)
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

    @staticmethod
    def flt_or(*args):
        return {'$or': args} if len(args) > 1 else args[0]

    @staticmethod
    def searchnonexistent():
        return {'_id': 0}

    @staticmethod
    def searchobjectid(oid, neg=False):
        """Filters records by their ObjectID.  `oid` can be a single or many
        (as a list or any iterable) object ID(s), specified as strings
        or an `ObjectID`s.

        """
        if isinstance(oid, (basestring, bson.objectid.ObjectId)):
            oid = [bson.objectid.ObjectId(oid)]
        else:
            oid = [bson.objectid.ObjectId(elt) for elt in oid]
        if len(oid) == 1:
            return {'_id': {'$ne': oid[0]} if neg else oid[0]}
        return {'_id': {'$nin' if neg else '$in': oid}}

    @staticmethod
    def searchversion(version):
        """Filters documents based on their schema's version."""
        return {"schema_version":
                {"$exists": False} if version is None else version}

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        addr = cls.ip2internal(addr)
        if neg:
            return {'$or': [{'addr_0': {'$ne': addr[0]}},
                            {'addr_1': {'$ne': addr[1]}}]}
        return {'addr_0': addr[0], 'addr_1': addr[1]}

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        return {'$and' if neg else '$or':
                [cls.searchhost(host, neg=neg) for host in hosts]}

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        """Filters (if `neg` == True, filters out) one particular IP
        address range.

        """
        start = cls.ip2internal(start)
        stop = cls.ip2internal(stop)
        if neg:
            return {'$or': [
                {'addr_0': start[0], 'addr_1': {'$lt': start[1]}},
                {'addr_0': {'$lt': start[0]}},
                {'addr_0': stop[0], 'addr_1': {'$gt': stop[1]}},
                {'addr_0': {'$gt': stop[0]}},
            ]}
        if start[0] == stop[0]:
            return {'addr_0': start[0], 'addr_1': {'$gte': start[1],
                                                   '$lte': stop[1]}}
        return {'$and': [
            {'$or': [{'addr_0': start[0], 'addr_1': {'$gte': start[1]}},
                     {'addr_0': {'$gt': start[0]}}]},
            {'$or': [{'addr_0': stop[0], 'addr_1': {'$lte': stop[1]}},
                     {'addr_0': {'$lt': stop[0]}}]},
        ]}

    @staticmethod
    def searchval(key, val):
        return {key: val}

    @staticmethod
    def searchcmp(key, val, cmpop):
        if cmpop == '<':
            return {key: {'$lt': val}}
        elif cmpop == '<=':
            return {key: {'$lte': val}}
        elif cmpop == '>':
            return {key: {'$gt': val}}
        elif cmpop == '>=':
            return {key: {'$gte': val}}


class MongoDBActive(MongoDB, DBActive):

    ipaddr_fields = ["addr", "traces.hops.ipaddr", "state_reason_ip"]
    needunwind = ["categories", "ports", "ports.scripts",
                  "ports.scripts.ssh-hostkey",
                  "ports.scripts.smb-enum-shares.shares",
                  "ports.scripts.ls.volumes",
                  "ports.scripts.ls.volumes.files",
                  "ports.scripts.mongodb-databases.databases",
                  "ports.scripts.mongodb-databases.databases.shards",
                  "ports.scripts.ike-info.transforms",
                  "ports.scripts.ike-info.vendor_ids",
                  "ports.scripts.vulns",
                  "ports.scripts.vulns.check_results",
                  "ports.scripts.vulns.description",
                  "ports.scripts.vulns.extra_info",
                  "ports.scripts.vulns.ids",
                  "ports.scripts.vulns.refs",
                  "ports.scripts.http-headers",
                  "ports.screenwords",
                  "traces", "traces.hops",
                  "os.osmatch", "os.osclass", "hostnames",
                  "hostnames.domains", "cpes"]

    def __init__(self, host, dbname, colname_hosts, **kargs):
        MongoDB.__init__(self, host, dbname, **kargs)
        DBActive.__init__(self)
        self.colname_hosts = colname_hosts
        self.indexes = {
            self.colname_hosts: [
                ([('scanid', pymongo.ASCENDING)], {}),
                ([('schema_version', pymongo.ASCENDING)], {}),
                ([
                    ('addr_0', pymongo.ASCENDING),
                    ('addr_1', pymongo.ASCENDING),
                ], {}),
                ([('starttime', pymongo.ASCENDING)], {}),
                ([('endtime', pymongo.ASCENDING)], {}),
                ([('source', pymongo.ASCENDING)], {}),
                ([('categories', pymongo.ASCENDING)], {}),
                ([('hostnames.domains', pymongo.ASCENDING)], {}),
                ([('traces.hops.domains', pymongo.ASCENDING)], {}),
                ([('openports.count', pymongo.ASCENDING)], {}),
                ([('openports.tcp.ports', pymongo.ASCENDING)], {}),
                ([('openports.tcp.count', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('openports.udp.ports', pymongo.ASCENDING)], {}),
                ([('openports.udp.count', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('ports.port', pymongo.ASCENDING)], {}),
                ([('ports.state_state', pymongo.ASCENDING)], {}),
                ([('ports.service_name', pymongo.ASCENDING)], {}),
                ([('ports.scripts.id', pymongo.ASCENDING)], {}),
                ([('ports.scripts.ls.volumes.volume', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('ports.scripts.ls.volumes.files.filename',
                   pymongo.ASCENDING)],
                 {"sparse": True}),
                ([
                    ('ports.scripts.vulns.id', pymongo.ASCENDING),
                    ('ports.scripts.vulns.state', pymongo.ASCENDING),
                ], {"sparse": True}),
                ([('ports.scripts.vulns.state', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([
                    ('ports.screenshot', pymongo.ASCENDING),
                    ('ports.screenwords', pymongo.ASCENDING),
                ], {"sparse": True}),
                ([('infos.as_num', pymongo.ASCENDING)], {}),
                ([
                    ('traces.hops.ipaddr_0', pymongo.ASCENDING),
                    ('traces.hops.ipaddr_1', pymongo.ASCENDING),
                    ('traces.hops.ttl', pymongo.ASCENDING),
                ], {}),
                ([
                    ('infos.country_code', pymongo.ASCENDING),
                    ('infos.city', pymongo.ASCENDING),
                ], {}),
                ([('infos.loc', pymongo.GEOSPHERE)], {}),
                ([
                    ('cpes.type', pymongo.ASCENDING),
                    ('cpes.vendor', pymongo.ASCENDING),
                    ('cpes.product', pymongo.ASCENDING),
                    ('cpes.version', pymongo.ASCENDING),
                ], {"sparse": True}),
            ],
        }
        self.schema_migrations = {
            self.colname_hosts: {
                None: (1, self.migrate_schema_hosts_0_1),
                1: (2, self.migrate_schema_hosts_1_2),
                2: (3, self.migrate_schema_hosts_2_3),
                3: (4, self.migrate_schema_hosts_3_4),
                4: (5, self.migrate_schema_hosts_4_5),
                5: (6, self.migrate_schema_hosts_5_6),
                6: (7, self.migrate_schema_hosts_6_7),
                7: (8, self.migrate_schema_hosts_7_8),
                8: (9, self.migrate_schema_hosts_8_9),
                9: (10, self.migrate_schema_hosts_9_10),
                10: (11, self.migrate_schema_hosts_10_11),
            },
        }
        self.schema_migrations_indexes[colname_hosts] = {
            1: {"ensure": [
                ([
                    ('ports.screenshot', pymongo.ASCENDING),
                    ('ports.screenwords', pymongo.ASCENDING),
                ], {"sparse": True}),
                ([('schema_version', pymongo.ASCENDING)], {}),
                ([('openports.count', pymongo.ASCENDING)], {}),
                ([('openports.tcp.ports', pymongo.ASCENDING)], {}),
                ([('openports.udp.ports', pymongo.ASCENDING)], {}),
                ([('openports.tcp.count', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('openports.udp.count', pymongo.ASCENDING)],
                 {"sparse": True}),
            ]},
            3: {"ensure": [
                ([('ports.scripts.ls.volumes.volume', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('ports.scripts.ls.volumes.files.filename',
                   pymongo.ASCENDING)],
                 {"sparse": True}),
                # Let's skip these ones since we are going to drop
                # them right after that.
                # ([('scripts.ls.volumes.volume', pymongo.ASCENDING)],
                #  {"sparse": True}),
                # ([('scripts.ls.volumes.files.filename', pymongo.ASCENDING)],
                #  {"sparse": True}),
            ]},
            4: {"drop": [
                ([('scripts.id', pymongo.ASCENDING)], {}),
                ([('scripts.ls.volumes.volume', pymongo.ASCENDING)], {}),
                ([('scripts.ls.volumes.files.filename', pymongo.ASCENDING)],
                 {}),
            ]},
            6: {"ensure": [
                ([('ports.scripts.vulns.state', pymongo.ASCENDING)],
                 {"sparse": True}),
            ]},
            11: {
                "drop": [
                    ([('addr', pymongo.ASCENDING)], {}),
                    ([
                        ('traces.hops.ipaddr', pymongo.ASCENDING),
                        ('traces.hops.ttl', pymongo.ASCENDING),
                    ], {}),
                ],
                "ensure": [
                    ([
                        ('addr_0', pymongo.ASCENDING),
                        ('addr_1', pymongo.ASCENDING),
                    ], {}),
                    ([
                        ('traces.hops.ipaddr_0', pymongo.ASCENDING),
                        ('traces.hops.ipaddr_1', pymongo.ASCENDING),
                        ('traces.hops.ttl', pymongo.ASCENDING),
                    ], {}),
                ],
            },
        }
        self.schema_latest_versions = {
            self.colname_hosts: xmlnmap.SCHEMA_VERSION,
        }

    def init(self):
        """Initializes the "active" columns, i.e., drops those columns and
creates the default indexes."""
        self.db[self.colname_hosts].drop()
        self.create_indexes()

    def cmp_schema_version_host(self, host):
        """Returns 0 if the `host`'s schema version matches the code's
        current version, -1 if it is higher (you need to update IVRE),
        and 1 if it is lower (you need to call .migrate_schema()).

        """
        return self.cmp_schema_version(self.colname_hosts, host)

    def migrate_schema(self, version):
        """Process to schema migrations in column `colname_hosts`
        starting from `version`.

        """
        MongoDB.migrate_schema(self, self.colname_hosts, version)

    @classmethod
    def migrate_schema_hosts_0_1(cls, doc):
        """Converts a record from version 0 (no "schema_version" key
        in the document) to version 1 (`doc["schema_version"] ==
        1`). Version 1 adds an "openports" nested document to ease
        open ports based researches.

        """
        assert "schema_version" not in doc
        assert "openports" not in doc
        update = {"$set": {"schema_version": 1}}
        updated_ports = False
        openports = {}
        for port in doc.get("ports", []):
            # populate openports
            if port.get('state_state') == 'open':
                openports.setdefault(port["protocol"], {}).setdefault(
                    "ports", []).append(port["port"])
            # create the screenwords attribute
            if 'screenshot' in port and 'screenwords' not in port:
                screenwords = utils.screenwords(cls.getscreenshot(port))
                if screenwords is not None:
                    port['screenwords'] = screenwords
                    updated_ports = True
        for proto in list(openports):
            count = len(openports[proto]["ports"])
            openports[proto]["count"] = count
            openports["count"] = openports.get("count", 0) + count
        if not openports:
            openports["count"] = 0
        if updated_ports:
            update["$set"]["ports"] = doc["ports"]
        update["$set"]["openports"] = openports
        return update

    @staticmethod
    def migrate_schema_hosts_1_2(doc):
        """Converts a record from version 1 to version 2. Version 2
        discards service names when they have been found from
        nmap-services file.

        """
        assert doc["schema_version"] == 1
        update = {"$set": {"schema_version": 2}}
        update_ports = False
        for port in doc.get("ports", []):
            if port.get("service_method") == "table":
                update_ports = True
                for key in list(port):
                    if key.startswith('service_'):
                        del port[key]
        if update_ports:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_2_3(doc):
        """Converts a record from version 2 to version 3. Version 3
        uses new Nmap structured data for scripts using the ls
        library.

        """
        assert doc["schema_version"] == 2
        update = {"$set": {"schema_version": 3}}
        updated_ports = False
        updated_scripts = False
        migrate_scripts = set([
            "afp-ls", "nfs-ls", "smb-ls", "ftp-anon", "http-ls"
        ])
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] in migrate_scripts:
                    if script['id'] in script:
                        script["ls"] = xmlnmap.change_ls(
                            script.pop(script['id']))
                        updated_ports = True
                    elif "ls" not in script:
                        data = xmlnmap.add_ls_data(script)
                        if data is not None:
                            script['ls'] = data
                            updated_ports = True
        for script in doc.get('scripts', []):
            if script['id'] in migrate_scripts:
                data = xmlnmap.add_ls_data(script)
                if data is not None:
                    script['ls'] = data
                    updated_scripts = True
        if updated_ports:
            update["$set"]["ports"] = doc['ports']
        if updated_scripts:
            update["$set"]["scripts"] = doc['scripts']
        return update

    @staticmethod
    def migrate_schema_hosts_3_4(doc):
        """Converts a record from version 3 to version 4. Version 4
        creates a "fake" port entry to store host scripts.

        """
        assert doc["schema_version"] == 3
        update = {"$set": {"schema_version": 4}}
        if 'scripts' in doc:
            doc.setdefault('ports', []).append({
                "port": "host",
                "scripts": doc.pop('scripts'),
            })
            update["$set"]["ports"] = doc["ports"]
            update["$unset"] = {"scripts": True}
        return update

    @staticmethod
    def migrate_schema_hosts_4_5(doc):
        """Converts a record from version 4 to version 5. Version 5
        uses the magic value -1 instead of "host" for "port" in the
        "fake" port entry used to store host scripts (see
        `migrate_schema_hosts_3_4()`). Moreover, it changes the
        structure of the values of "extraports" from [totalcount,
        {"state": count}] to {"total": totalcount, "state": count}.

        """
        assert doc["schema_version"] == 4
        update = {"$set": {"schema_version": 5}}
        updated_ports = False
        updated_extraports = False
        for port in doc.get('ports', []):
            if port['port'] == 'host':
                port['port'] = -1
                updated_ports = True
        if updated_ports:
            update["$set"]["ports"] = doc['ports']
        for state, (total, counts) in list(viewitems(doc.get('extraports',
                                                             {}))):
            doc['extraports'][state] = {"total": total, "reasons": counts}
            updated_extraports = True
        if updated_extraports:
            update["$set"]["extraports"] = doc['extraports']
        return update

    @staticmethod
    def migrate_schema_hosts_5_6(doc):
        """Converts a record from version 5 to version 6. Version 6 uses Nmap
        structured data for scripts using the vulns NSE library.

        """
        assert doc["schema_version"] == 5
        update = {"$set": {"schema_version": 6}}
        updated = False
        migrate_scripts = set(script for script, alias
                              in viewitems(xmlnmap.ALIASES_TABLE_ELEMS)
                              if alias == 'vulns')
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] in migrate_scripts:
                    table = None
                    if script['id'] in script:
                        table = script.pop(script['id'])
                        script["vulns"] = table
                        updated = True
                    elif "vulns" in script:
                        table = script["vulns"]
                    else:
                        continue
                    newtable = xmlnmap.change_vulns(table)
                    if newtable != table:
                        script["vulns"] = newtable
                        updated = True
        if updated:
            update["$set"]["ports"] = doc['ports']
        return update

    @staticmethod
    def migrate_schema_hosts_6_7(doc):
        """Converts a record from version 6 to version 7. Version 7 creates a
        structured output for mongodb-databases script.

        """
        assert doc["schema_version"] == 6
        update = {"$set": {"schema_version": 7}}
        updated = False
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] == "mongodb-databases":
                    if 'mongodb-databases' not in script:
                        data = xmlnmap.add_mongodb_databases_data(script)
                        if data is not None:
                            script['mongodb-databases'] = data
                            updated = True
        if updated:
            update["$set"]["ports"] = doc['ports']
        return update

    @staticmethod
    def migrate_schema_hosts_7_8(doc):
        """Converts a record from version 7 to version 8. Version 8 fixes the
        structured output for scripts using the vulns NSE library.

        """
        assert doc["schema_version"] == 7
        update = {"$set": {"schema_version": 8}}
        updated = False
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if 'vulns' in script:
                    if any(elt in script['vulns'] for elt in
                           ["ids", "refs", "description", "state", "title"]):
                        script['vulns'] = [script['vulns']]
                    else:
                        script['vulns'] = [dict(tab, id=vulnid)
                                           for vulnid, tab in
                                           viewitems(script['vulns'])]
                    updated = True
        if updated:
            update["$set"]["ports"] = doc['ports']
        return update

    @staticmethod
    def migrate_schema_hosts_8_9(doc):
        """Converts a record from version 8 to version 9. Version 9 creates a
        structured output for http-headers script.

        """
        assert doc["schema_version"] == 8
        update = {"$set": {"schema_version": 9}}
        updated = False
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] == "http-headers":
                    if 'http-headers' not in script:
                        data = xmlnmap.add_http_headers_data(script)
                        if data is not None:
                            script['http-headers'] = data
                            updated = True
        if updated:
            update["$set"]["ports"] = doc['ports']
        return update

    @staticmethod
    def migrate_schema_hosts_9_10(doc):
        """Converts a record from version 9 to version 10. Version 10 changes
the field names of the structured output for s7-info script.

        """
        assert doc["schema_version"] == 9
        update = {"$set": {"schema_version": 10}}
        updated = False
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] == "s7-info":
                    if 's7-info' in script:
                        xmlnmap.change_s7_info_keys(script['s7-info'])
                        updated = True
        if updated:
            update["$set"]["ports"] = doc['ports']
        return update

    @classmethod
    def migrate_schema_hosts_10_11(cls, doc):
        """Converts a record from version 10 to version 11. Version 11 changes
the way IP addresses are stored.

In version 10, they are stored as integers.

In version 11, they are stored as canonical string representations in
JSON format, and as two 64-bit unsigned integers (the `addr` field
becomes `addr_0` and `addr_1`, and the same applies to other fields
representing IP addresses).

The reasons for this choice are the impossibility to store (and hence,
index) unsigned 128-bit integers in MongoDB.

        """
        assert doc["schema_version"] == 10
        update = {"$set": {"schema_version": 11}}

        def convert(val):
            return cls.ip2internal(utils.force_int2ip(val))
        try:
            addr = convert(doc['addr'])
        except (KeyError, ValueError):
            pass
        else:
            update["$unset"] = {"addr": ""}
            update["$set"]["addr_0"], update["$set"]["addr_1"] = addr
        updated = False
        for port in doc.get('ports', []):
            if 'state_reason_ip' in port:
                try:
                    ipaddr = convert(port['state_reason_ip'])
                except ValueError:
                    pass
                else:
                    del port['state_reason_ip']
                    (port['state_reason_ip_0'],
                     port['state_reason_ip_1']) = ipaddr
                    updated = True
            for script in port.get('scripts', []):
                if script['id'] == 'ssl-cert':
                    if 'pem' in script['ssl-cert']:
                        data = ''.join(
                            script['ssl-cert']['pem'].splitlines()[1:-1]
                        ).encode()
                        try:
                            newout, newinfo = xmlnmap.create_ssl_cert(data)
                        except Exception:
                            utils.LOGGER.warning('Cannot parse certificate %r',
                                                 data,
                                                 exc_info=True)
                        else:
                            script['output'] = '\n'.join(newout)
                            script['ssl-cert'] = newinfo
                            updated = True
                            continue
                    try:
                        pubkeytype = {
                            'rsaEncryption': 'rsa',
                            'id-ecPublicKey': 'ec',
                            'id-dsa': 'dsa',
                            'dhpublicnumber': 'dh',
                        }[script['ssl-cert'].pop('pubkeyalgo')]
                    except KeyError:
                        pass
                    else:
                        script['pubkey'] = {'type': pubkeytype}
                        updated = True
        if updated:
            update["$set"]["ports"] = doc['ports']
        updated = False
        for trace in doc.get('traces', []):
            for hop in trace.get('hops', []):
                if 'ipaddr' in hop:
                    try:
                        ipaddr = convert(hop['ipaddr'])
                    except ValueError:
                        pass
                    else:
                        del hop['ipaddr']
                        hop['ipaddr_0'], hop['ipaddr_1'] = ipaddr
                        updated = True
        if updated:
            update["$set"]["traces"] = doc['traces']
        return update

    def _get(self, flt, **kargs):
        """Like .get(), but returns a MongoDB cursor (suitable for use with
e.g.  .explain()).

        """
        return self._get_cursor(self.colname_hosts, flt, **kargs)

    def get(self, spec, **kargs):
        """Queries the active column with the provided filter "spec",
and returns a MongoDB cursor.

This should be very fast, as no operation is done (the cursor is only
returned). Next operations (e.g., .count(), enumeration, etc.) might
take a long time, depending on both the operations and the filter.

Any keyword argument is passed to the .find() method of the Mongodb
column object, without any validation (and might have no effect if
it is not expected)."""
        # Convert IP addresses to internal DB format
        for host in self._get(spec, **kargs):
            try:
                host['addr'] = self.internal2ip([host.pop('addr_0'),
                                                 host.pop('addr_1')])
            except (KeyError, socket.error):
                pass
            for port in host.get('ports', []):
                try:
                    port['state_reason_ip'] = self.internal2ip([
                        port.pop('state_reason_ip_0'),
                        port.pop('state_reason_ip_1'),
                    ])
                except (KeyError, socket.error):
                    pass
            for trace in host.get('traces', []):
                for hop in trace.get('hops', []):
                    try:
                        hop['ipaddr'] = self.internal2ip([hop.pop('ipaddr_0'),
                                                          hop.pop('ipaddr_1')])
                    except (KeyError, socket.error):
                        pass
            if 'coordinates' in host.get('infos', {}).get('loc', {}):
                host['infos']['coordinates'] = host['infos'].pop('loc')[
                    'coordinates'
                ][::-1]
            yield host

    @staticmethod
    def getscanids(host):
        scanids = host.get('scanid')
        if scanids is None:
            return []
        if isinstance(scanids, list):
            return scanids
        return [scanids]

    def setscreenshot(self, host, port, data, protocol='tcp',
                      overwrite=False):
        """Sets the content of a port's screenshot."""
        try:
            port = [p for p in host.get('ports', [])
                    if p['port'] == port and p['protocol'] == protocol][0]
        except IndexError:
            raise KeyError("Port %s/%d does not exist" % (protocol, port))
        if 'screenshot' in port and not overwrite:
            return
        port['screenshot'] = "field"
        trim_result = utils.trim_image(data)
        if trim_result is False:
            # Image no longer exists after trim
            return
        elif trim_result is not True:
            # Image has been trimmed
            data = trim_result
        port['screendata'] = bson.Binary(data)
        screenwords = utils.screenwords(data)
        if screenwords is not None:
            port['screenwords'] = screenwords
        self.db[self.colname_hosts].update(
            {"_id": host['_id']}, {"$set": {'ports': host['ports']}}
        )

    def setscreenwords(self, host, port=None, protocol="tcp",
                       overwrite=False):
        """Sets the `screenwords` attribute based on the screenshot
        data.

        """
        if port is None:
            if overwrite:
                def flt_cond(p):
                    return 'screenshot' in p
            else:
                def flt_cond(p):
                    return 'screenshot' in p and 'screenwords' not in p
        else:
            if overwrite:
                def flt_cond(p):
                    return ('screenshot' in p and
                            p.get('port') == port and
                            p.get('protocol') == protocol)
            else:
                def flt_cond(p):
                    return ('screenshot' in p and
                            'screenwords' not in p and
                            p.get('port') == port and
                            p.get('protocol') == protocol)
        updated = False
        for port in host.get('ports', []):
            if not flt_cond(port):
                continue
            screenwords = utils.screenwords(self.getscreenshot(port))
            if screenwords is not None:
                port['screenwords'] = screenwords
                updated = True
        if updated:
            self.db[self.colname_hosts].update(
                {"_id": host['_id']}, {"$set": {'ports': host['ports']}}
            )

    def removescreenshot(self, host, port=None, protocol='tcp'):
        """Removes screenshots"""
        changed = False
        for p in host.get('ports', []):
            if port is None or (p['port'] == port and
                                p.get('protocol') == protocol):
                if 'screenshot' in p:
                    if p['screenshot'] == "field":
                        if 'screendata' in p:
                            del p['screendata']
                    if 'screenwords' in p:
                        del p['screenwords']
                    del p['screenshot']
                    changed = True
        if changed:
            self.db[self.colname_hosts].update(
                {"_id": host["_id"]}, {"$set": {'ports': host['ports']}}
            )

    def getlocations(self, flt):
        col = self.db[self.colname_hosts]
        pipeline = [
            {"$match": self.flt_and(flt, self.searchhaslocation())},
            {"$project": {"_id": 0, "coords": "$infos.loc.coordinates"}},
            {"$group": {"_id": "$coords", "count": {"$sum": 1}}},
        ]
        return ({'_id': tuple(rec['_id'][::-1]), 'count': rec['count']}
                for rec in col.aggregate(pipeline, cursor={}))

    def get_ips_ports(self, flt, limit=None, skip=None):
        cur = self._get(
            flt, fields=['addr_0', 'addr_1', 'ports.port',
                         'ports.state_state'],
            limit=limit or 0, skip=skip or 0,
        )
        count = sum(len(host.get('ports', [])) for host in cur)
        cur.rewind()
        return ((dict(res, addr=self.internal2ip([res['addr_0'],
                                                  res['addr_1']]))
                 for res in cur),
                count)

    def get_ips(self, flt, limit=None, skip=None):
        cur = self._get(flt, fields=['addr_0', 'addr_1'], limit=limit or 0,
                        skip=skip or 0)
        return ((dict(res, addr=self.internal2ip([res['addr_0'],
                                                  res['addr_1']]))
                 for res in cur),
                cur.count())

    def get_open_port_count(self, flt, limit=None, skip=None):
        cur = self._get(
            flt, fields=['addr_0', 'addr_1', 'starttime', 'openports.count'],
            limit=limit or 0, skip=skip or 0,
        )
        return ((dict(res, addr=self.internal2ip([res['addr_0'],
                                                  res['addr_1']]))
                 for res in cur),
                cur.count())

    def store_host(self, host):
        host = deepcopy(host)
        # Convert IP addresses to internal DB format
        try:
            host['addr_0'], host['addr_1'] = self.ip2internal(host.pop('addr'))
        except (KeyError, ValueError):
            pass
        for port in host.get('ports', []):
            if 'state_reason_ip' in port:
                try:
                    (
                        port['state_reason_ip_0'],
                        port['state_reason_ip_1'],
                    ) = self.ip2internal(
                        port.pop('state_reason_ip')
                    )
                except ValueError:
                    pass
        for trace in host.get('traces', []):
            for hop in trace.get('hops', []):
                if 'ipaddr' in hop:
                    try:
                        hop['ipaddr_0'], hop['ipaddr_1'] = self.ip2internal(
                            hop.pop('ipaddr')
                        )
                    except ValueError:
                        pass
        # keep location data in appropriate format for GEOSPHERE index
        if 'coordinates' in host.get('infos', {}):
            host['infos']['loc'] = {
                "type": "Point",
                "coordinates": host['infos'].pop('coordinates')[::-1],
            }
        ident = self.db[self.colname_hosts].insert(host)
        utils.LOGGER.debug("HOST STORED: %r in %r", ident, self.colname_hosts)
        return ident

    def merge_host_docs(self, rec1, rec2):
        """Merge two host records and return the result. Unmergeable /
        hard-to-merge fields are lost (e.g., extraports).

        """
        rec = super(MongoDBActive, self).merge_host_docs(rec1, rec2)
        scanid = set()
        for record in [rec1, rec2]:
            scanid.update(self.getscanids(record))
        if scanid:
            if len(scanid) == 1:
                rec["scanid"] = scanid.pop()
            else:
                rec["scanid"] = list(scanid)
        return rec

    def remove(self, host):
        """Removes the host "view" from the active column.
        "view" must be the record as returned by MongoDB.

        """
        self.db[self.colname_hosts].remove(spec_or_id=host['_id'])

    def store_or_merge_host(self, host):
        raise NotImplementedError

    def get_mean_open_ports(self, flt):
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
        return self.db[self.colname_hosts].aggregate(aggr, cursor={})

    def group_by_port(self, flt):
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
        return self.db[self.colname_hosts].aggregate(aggr, cursor={})

    @staticmethod
    def json2dbrec(host):
        for fname in ["starttime", "endtime"]:
            if fname in host:
                host[fname] = datetime.datetime.strptime(
                    host[fname], "%Y-%m-%d %H:%M:%S"
                )
        for port in host.get('ports', []):
            if 'screendata' in port:
                port['screendata'] = bson.Binary(
                    utils.decode_b64(port['screendata'].encode())
                )
            for script in port.get('scripts', []):
                if 'masscan' in script and 'raw' in script['masscan']:
                    script['masscan']['raw'] = bson.Binary(
                        utils.decode_b64(script['masscan']['raw'].encode())
                    )
        return host

    @staticmethod
    def searchdomain(name, neg=False):
        if neg:
            if isinstance(name, utils.REGEXP_T):
                return {"hostnames.domains": {"$not": name}}
            return {"hostnames.domains": {"$ne": name}}
        return {"hostnames.domains": name}

    def searchhostname(self, name, neg=False):
        if neg:
            if isinstance(name, utils.REGEXP_T):
                return {"hostnames.name": {"$not": name}}
            return {"hostnames.name": {"$ne": name}}
        return self.flt_and(
            # This is indexed
            self.searchdomain(name, neg=neg),
            # This is not
            {"hostnames.name": name},
        )

    @staticmethod
    def searchcategory(cat, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular category
        (records may have zero, one or more categories).
        """
        if neg:
            if isinstance(cat, utils.REGEXP_T):
                return {'categories': {'$not': cat}}
            if isinstance(cat, list):
                if len(cat) == 1:
                    cat = cat[0]
                else:
                    return {'categories': {'$nin': cat}}
            return {'categories': {'$ne': cat}}
        if isinstance(cat, list):
            if len(cat) == 1:
                cat = cat[0]
            else:
                return {'categories': {'$in': cat}}
        return {'categories': cat}

    @staticmethod
    def searchcountry(country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        country = utils.country_unalias(country)
        if isinstance(country, list):
            return {'infos.country_code':
                    {'$nin' if neg else '$in': country}}
        return {'infos.country_code':
                {'$ne': country} if neg else country}

    @staticmethod
    def searchhaslocation(neg=False):
        return {'infos.loc': {"$exists": not neg}}

    @staticmethod
    def searchcity(city, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular city.
        """
        if neg:
            if isinstance(city, utils.REGEXP_T):
                return {'infos.city': {'$not': city}}
            return {'infos.city': {'$ne': city}}
        return {'infos.city': city}

    @staticmethod
    def searchasnum(asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        if not isinstance(asnum, basestring) and hasattr(asnum, '__iter__'):
            return {'infos.as_num':
                    {'$nin' if neg else '$in': [int(val) for val in asnum]}}
        asnum = int(asnum)
        return {'infos.as_num': {'$ne': asnum} if neg else asnum}

    @staticmethod
    def searchasname(asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        if neg:
            if isinstance(asname, utils.REGEXP_T):
                return {'infos.as_name': {'$not': asname}}
            else:
                return {'infos.as_name': {'$ne': asname}}
        return {'infos.as_name': asname}

    @staticmethod
    def searchsource(src, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        source.

        """
        if neg:
            return {'source': {'$not': {'$in': [src]}}}
        return {'source': {'$in': [src]}}

    @staticmethod
    def searchport(port, protocol='tcp', state='open', neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        if port == "host":
            return {'ports.port': {"$gte": 0} if neg else -1}
        if state == "open":
            return {"openports.%s.ports" % protocol:
                    {'$ne': port} if neg else port}
        if neg:
            return {
                '$or': [
                    {'ports': {'$elemMatch': {
                        'port': port,
                        'protocol': protocol,
                        'state_state': {'$ne': state}
                    }}},
                    {'ports.port': {'$ne': port}},
                ]
            }
        return {'ports': {'$elemMatch': {
            'port': port,
            'protocol': protocol,
            'state_state': state
        }}}

    def searchportsother(self, ports, protocol='tcp', state='open'):
        """Filters records with at least one port other than those
        listed in `ports` with state `state`.

        """
        return self.searchport(
            {'$elemMatch': {'$nin': ports}} if state == 'open'
            else {'$nin': ports},
            protocol=protocol,
            state=state,
        )

    def searchports(self, ports, protocol='tcp', state='open', neg=False):
        if state == "open" and not neg:
            return self.searchport({'$all': ports}, state=state,
                                   protocol=protocol, neg=neg)
        if neg:
            return self.flt_and(*(self.searchport(p, protocol=protocol,
                                                  state=state, neg=neg)
                                  for p in ports))
        return {'ports': {'$all': [
            self.searchport(port, protocol=protocol,
                            state=state, neg=neg)['ports']
            for port in ports]}}

    @staticmethod
    def searchcountopenports(minn=None, maxn=None, neg=False):
        "Filters records with open port number between minn and maxn"
        assert minn is not None or maxn is not None
        flt = []
        if minn == maxn:
            return {'openports.count': {'$ne': minn} if neg else minn}
        if minn is not None:
            flt.append({'$lt' if neg else '$gte': minn})
        if maxn is not None:
            flt.append({'$gt' if neg else '$lte': maxn})
        if len(flt) == 1:
            return {'openports.count': flt[0]}
        if neg:
            return {'$or': [{'openports.count': cond} for cond in flt]}
        # return {'openports.count':
        #         dict(item for cond in flt for item in viewitems(cond))}
        return {'openports.count': {'$lte': maxn, '$gte': minn}}

    @staticmethod
    def searchopenport(neg=False):
        "Filters records with at least one open port."
        return {'ports.state_state': {'$nin': ['open']} if neg else 'open'}

    @staticmethod
    def searchservice(srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        flt = {'service_name': srv}
        if port is not None:
            flt['port'] = port
        if protocol is not None:
            flt['protocol'] = protocol
        if len(flt) == 1:
            return {'ports.service_name': srv}
        return {'ports': {'$elemMatch': flt}}

    @staticmethod
    def searchproduct(product, version=None, service=None, port=None,
                      protocol=None):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        flt = {'service_product': product}
        if version is not None:
            flt['service_version'] = version
        if service is not None:
            flt['service_name'] = service
        if port is not None:
            flt['port'] = port
        if protocol is not None:
            flt['protocol'] = protocol
        if len(flt) == 1:
            return {'ports.service_product': product}
        return {'ports': {'$elemMatch': flt}}

    @staticmethod
    def searchscript(name=None, output=None, values=None, neg=False):
        """Search a particular content in the scripts results.

        """
        req = {}
        if name:
            req['id'] = name
        if output is not None:
            req['output'] = output
        if values is not None:
            if name is None:
                raise TypeError(".searchscript() needs a `name` arg "
                                "when using a `values` arg")
            for field, value in viewitems(values):
                req["%s.%s" % (xmlnmap.ALIASES_TABLE_ELEMS.get(name, name),
                               field)] = value
        if not req:
            return {"ports.scripts": {"$exists": not neg}}
        if len(req) == 1:
            field, value = next(iter(viewitems(req)))
            if neg:
                return {"ports.scripts.%s" % field: {"$ne": value}}
            else:
                return {"ports.scripts.%s" % field: value}
        if neg:
            return {"ports.scripts": {"$not": {"$elemMatch": req}}}
        else:
            return {"ports.scripts": {"$elemMatch": req}}

    @classmethod
    def searchcert(cls, keytype=None):
        if keytype is None:
            return cls.searchscript(name="ssl-cert")
        return cls.searchscript(name="ssl-cert",
                                values={'pubkey.type': keytype})

    @classmethod
    def searchsshkey(cls, keytype=None):
        if keytype is None:
            return cls.searchscript(name="ssh-hostkey")
        return cls.searchscript(name="ssh-hostkey",
                                values={'type': 'ssh-%s' % keytype})

    @staticmethod
    def searchsvchostname(hostname):
        return {'ports.service_hostname': hostname}

    @staticmethod
    def searchwebmin():
        return {
            'ports': {
                '$elemMatch': {
                    'service_name': 'http',
                    'service_product': 'MiniServ',
                    'service_extrainfo': {'$ne': 'Webmin httpd'},
                }}}

    @staticmethod
    def searchx11():
        return {
            'ports': {'$elemMatch': {
                'service_name': 'X11',
                'service_extrainfo': {'$ne': 'access denied'}
            }}}

    def searchfile(self, fname=None, scripts=None):
        """Search shared files from a file name (either a string or a
        regexp), only from scripts using the "ls" NSE module.

        """
        if fname is None:
            fname = {"$exists": True}
        if scripts is None:
            return {"ports.scripts.ls.volumes.files.filename": fname}
        if isinstance(scripts, basestring):
            scripts = [scripts]
        return {"ports.scripts": {"$elemMatch": {
            "id": scripts.pop() if len(scripts) == 1 else {"$in": scripts},
            "ls.volumes.files.filename": fname
        }}}

    def searchsmbshares(self, access='', hidden=None):
        """Filter SMB shares with given `access` (default: either read
        or write, accepted values 'r', 'w', 'rw').

        If `hidden` is set to `True`, look for hidden shares, for
        non-hidden if set to `False` and for both if set to `None`
        (this is the default).

        """
        access = {
            '': re.compile('^(READ|WRITE)'),
            'r': re.compile('^READ(/|$)'),
            'w': re.compile('(^|/)WRITE$'),
            'rw': 'READ/WRITE',
            'wr': 'READ/WRITE',
        }[access.lower()]
        share_type = {
            # None: re.compile('^STYPE_DISKTREE(_HIDDEN)?$'),
            # None: accept share in unsure
            None: {'$nin': ['STYPE_IPC_HIDDEN', 'Not a file share',
                            'STYPE_IPC', 'STYPE_PRINTQ']},
            True: 'STYPE_DISKTREE_HIDDEN',
            False: 'STYPE_DISKTREE',
        }[hidden]
        return self.searchscript(
            name='smb-enum-shares',
            values={'shares': {'$elemMatch': {
                '$or': [
                    {'%s access' % user: access} for user in ['Anonymous',
                                                              'Current user']
                ],
                'Type': share_type,
                'Share': {'$ne': 'IPC$'},
            }}},
        )

    def searchhttptitle(self, title):
        return self.searchscript(
            name={'$in': ['http-title', 'html-title']},
            output=title,
        )

    @staticmethod
    def searchos(txt):
        return {
            '$or': [
                {'os.osclass.vendor': txt},
                {'os.osclass.osfamily': txt},
                {'os.osclass.osgen': txt}
            ]}

    @staticmethod
    def searchvsftpdbackdoor():
        return {
            'ports': {
                '$elemMatch': {
                    'protocol': 'tcp',
                    'state_state': 'open',
                    'service_product': 'vsftpd',
                    'service_version': '2.3.4',
                }}}

    @staticmethod
    def searchvulnintersil():
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

    @staticmethod
    def searchdevicetype(devtype):
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

    @staticmethod
    def searchldapanon():
        return {'ports.service_extrainfo': 'Anonymous bind OK'}

    @staticmethod
    def searchvuln(vulnid=None, status=None):
        if status is None:
            return {'ports.scripts.vulns.id':
                    {'$exists': True} if vulnid is None else vulnid}
        if vulnid is None:
            return {'ports.scripts.vulns.status': status}
        return {'ports.scripts.vulns': {
            '$elemMatch': {'id': vulnid, 'status': status}
        }}

    @staticmethod
    def searchtimeago(delta, neg=False):
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

    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        try:
            hop = cls.ip2internal(hop)
        except ValueError:
            pass
        if ttl is None:
            flt = {'traces.hops': {'$elemMatch': {'ipaddr_0': hop[0],
                                                  'ipaddr_1': hop[1]}}}
            return {'$not': flt} if neg else flt
        if neg:
            return {
                '$or': [
                    {'traces.hops': {'$elemMatch': {
                        'ttl': ttl,
                        '$or': [
                            {'ipaddr_0': {'$ne': hop[0]}},
                            {'ipaddr_1': {'$ne': hop[1]}},
                        ],
                    }}},
                    {'traces.hops.ttl': {'$ne': ttl}},
                ]
            }
        return {'traces.hops': {'$elemMatch': {'ipaddr_0': hop[0],
                                               'ipaddr_1': hop[1],
                                               'ttl': ttl}}}

    @staticmethod
    def searchhopdomain(hop, neg=False):
        if neg:
            if isinstance(hop, utils.REGEXP_T):
                return {'traces.hops.domains': {'$not': hop}}
            return {'traces.hops.domains': {'$ne': hop}}
        return {'traces.hops.domains': hop}

    def searchhopname(self, hop, neg=False):
        if neg:
            if isinstance(hop, utils.REGEXP_T):
                return {'traces.hops.host': {'$not': hop}}
            return {'traces.hops.host': {'$ne': hop}}
        return self.flt_and(
            # This is indexed
            self.searchhopdomain(hop, neg=neg),
            # This is not
            {'traces.hops.host': hop},
        )

    @staticmethod
    def searchscreenshot(port=None, protocol='tcp', service=None, words=None,
                         neg=False):
        """Filter results with (without, when `neg == True`) a
        screenshot (on a specific `port` if specified).

        `words` can be specified as a string, a regular expression, a
        boolean, or as a list and is/are matched against the OCR
        results. When `words` is specified and `neg == True`, the
        result will filter results **with** a screenshot **without**
        the word(s) in the OCR results.

        """
        result = {'ports': {'$elemMatch': {}}}
        if words is None:
            if port is None and service is None:
                return {'ports.screenshot': {'$exists': not neg}}
            result['ports']['$elemMatch']['screenshot'] = {'$exists': not neg}
        else:
            result['ports']['$elemMatch']['screenshot'] = {'$exists': True}
            if isinstance(words, list):
                words = {'$ne' if neg else '$all': words}
            elif isinstance(words, utils.REGEXP_T):
                words = {'$not': words} if neg else words
            elif isinstance(words, bool):
                words = {"$exists": words}
            else:
                words = {'$ne': words} if neg else words
            result['ports']['$elemMatch']['screenwords'] = words
        if port is not None:
            result['ports']['$elemMatch']['port'] = port
            result['ports']['$elemMatch']['protocol'] = protocol
        if service is not None:
            result['ports']['$elemMatch']['service_name'] = service
        return result

    @staticmethod
    def searchcpe(cpe_type=None, vendor=None, product=None, version=None):
        """Look for a CPE by type (a, o or h), vendor, product or version (the
        part after the column following the product). No argument will just
        check for cpe existence.

        """
        fields = [
            ("type", cpe_type),
            ("vendor", vendor),
            ("product", product),
            ("version", version),
        ]
        flt = dict((field, value)
                   for field, value in fields
                   if value is not None)
        nflt = len(flt)
        if nflt == 0:
            return {"cpes": {"$exists": True}}
        elif nflt == 1:
            field, value = flt.popitem()
            return {"cpes.%s" % field: value}
        else:
            return {"cpes": {"$elemMatch": flt}}

    def topvalues(self, field, flt=None, topnbr=10, sort=None,
                  limit=None, skip=None, least=False, aggrflt=None,
                  specialproj=None, specialflt=None):
        """
        This method makes use of the aggregation framework to produce
        top values for a given field or pseudo-field. Pseudo-fields are:
          - category / asnum / country / net[:mask]
          - port
          - port:open / :closed / :filtered / :<servicename>
          - portlist:open / :closed / :filtered
          - countports:open / :closed / :filtered
          - service / service:<portnbr>
          - product / product:<portnbr>
          - cpe / cpe.<part> / cpe:<cpe_spec> / cpe.<part>:<cpe_spec>
          - devicetype / devicetype:<portnbr>
          - script:<scriptid> / script:<port>:<scriptid>
            / script:host:<scriptid>
          - cert.* / smb.* / sshkey.* / ike.*
          - httphdr / httphdr.{name,value} / httphdr:<name>
          - modbus.* / s7.* / enip.*
          - mongo.dbs.*
          - vulns.*
          - screenwords
          - file.* / file.*:scriptid
          - hop
        """
        def null_if_empty(val):
            return val if val else None
        outputproc = None
        if flt is None:
            flt = self.flt_empty
        if aggrflt is None:
            aggrflt = self.flt_empty
        if specialflt is None:
            specialflt = []
        # pseudo-fields
        if field == "category":
            field = "categories"
        elif field == "country":
            flt = self.flt_and(flt, {"infos.country_code": {"$exists": True}})
            field = "country"
            if self.mongodb_32_more:
                specialproj = {"_id": 0,
                               "country": [
                                   "$infos.country_code",
                                   {"$ifNull": ["$infos.country_name", "?"]},
                               ]}

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'])}
            else:
                specialproj = {"_id": 0,
                               "country": _old_array(
                                   "$infos.country_code",
                                   {"$ifNull": ["$infos.country_name", "?"]},
                               )}

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'].split('###', 1))}
        elif field == "city":
            flt = self.flt_and(
                flt,
                {"infos.country_code": {"$exists": True}},
                {"infos.city": {"$exists": True}}
            )
            if self.mongodb_32_more:
                specialproj = {"_id": 0,
                               "city": [
                                   "$infos.country_code",
                                   "$infos.city",
                               ]}

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'])}
            else:
                specialproj = {"_id": 0,
                               "city": _old_array(
                                   "$infos.country_code",
                                   "$infos.city",
                               )}

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'].split('###', 1))}
        elif field == "asnum":
            flt = self.flt_and(flt, {"infos.as_num": {"$exists": True}})
            field = "infos.as_num"
        elif field == "as":
            flt = self.flt_and(flt, {"infos.as_num": {"$exists": True}})
            if self.mongodb_32_more:
                specialproj = {
                    "_id": 0,
                    "as": ["$infos.as_num", '$infos.as_name'],
                }

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(
                            int(y) if i == 0 else y
                            for i, y in enumerate(x['_id'])
                        ),
                    }
            else:
                specialproj = {
                    "_id": 0,
                    "as": _old_array(
                        {"$toLower": "$infos.as_num"},
                        {"$ifNull": ['$infos.as_name', '']},
                    )
                }

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(
                            int(y) if i == 0 else y for i, y in
                            enumerate(x['_id'].split('###'))
                        ),
                    }
        elif field == "addr":
            specialproj = {
                "_id": 0,
                '$addr_0': 1,
                '$addr_1': 1,
            }
            if self.mongodb_32_more:
                specialflt = [{"$project": {field: ['$addr_0', '$addr_1']}}]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': self.internal2ip(x['_id']),
                    }
            else:
                specialflt = [{"$project": {field: _old_array(
                    "$addr_0", "$addr_1",
                    convert_to_string=True,
                )}}]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': self.internal2ip([int(val) for val in
                                                 x['_id'].split('###')]),
                    }
        elif field == "net" or field.startswith("net:"):
            flt = self.flt_and(flt, self.searchipv4())
            mask = int(field.split(':', 1)[1]) if ':' in field else 24
            field = "addr"
            # This should not overflow thanks to .searchipv4() filter
            addr = {"$add": ["$addr_1", 0x7fff000100000000]}
            if self.mongodb_32_more:
                specialproj = {
                    "_id": 0,
                    "addr": {"$floor": {"$divide": [addr, 2 ** (32 - mask)]}},
                }
            else:
                specialproj = {
                    "_id": 0,
                    "addr": {"$subtract": [{"$divide": [addr,
                                                        2 ** (32 - mask)]},
                                           {"$mod": [{"$divide": [
                                               addr,
                                               2 ** (32 - mask),
                                           ]}, 1]}]},
                }
            flt = self.flt_and(flt, self.searchipv4())

            def outputproc(x):
                return {
                    'count': x['count'],
                    '_id': '%s/%d' % (
                        utils.int2ip(int(x['_id']) * 2 ** (32 - mask)),
                        mask,
                    ),
                }
        elif field == "port" or field.startswith("port:"):
            if field == "port":
                info = {"$exists": True}
                flt_field = "ports.state_state"
            else:
                info = field.split(':', 1)[1]
                flt_field = "ports.%s" % (
                    "state_state"
                    if info in ['open', 'filtered', 'closed'] else
                    "service_name"
                )
            field = "ports.port"
            flt = self.flt_and(flt, {flt_field: info})
            specialproj = {"_id": 0, flt_field: 1, field: 1,
                           "ports.protocol": 1}
            if self.mongodb_32_more:
                specialflt = [
                    {"$match": {flt_field: info}},
                    {"$project": {field: ["$ports.protocol", "$ports.port"]}},
                ]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(int(y) if i == 1 else y for i, y in
                                     enumerate(x['_id'])),
                    }
            else:
                specialflt = [
                    {"$match": {flt_field: info}},
                    {"$project": {field: _old_array(
                        "$ports.protocol",
                        {"$toLower": "$ports.port"},
                    )}},
                ]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(int(y) if i == 1 else y for i, y in
                                     enumerate(x['_id'].split('###'))),
                    }
        elif field.startswith("portlist:"):
            specialproj = {"ports.port": 1, "ports.protocol": 1,
                           "ports.state_state": 1}
            specialflt = [
                {"$project": {"ports.port": 1, "ports.protocol": 1,
                              "ports.state_state": 1}},
                # if the host has no ports attribute, we create an empty list
                {"$project": {"ports": {"$ifNull": ["$ports", []]}}},
                # We use $redact instead of $match to keep an empty
                # list when no port matches.
                #
                # The first "$cond" help us make the difference
                # between main document ($ports exists in that case)
                # and a nested document ($ports does not exist in that
                # case). The second only keeps ports we are interested in.
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
                {"$project": {"ports.port": 1, "ports.protocol": 1}},
                {"$project": {"portlist": "$ports"}},
            ]
            field = "portlist"

            def outputproc(x):
                return {
                    'count': x['count'],
                    '_id': [(y['protocol'], y['port']) for y in x['_id']],
                }

        elif field.startswith('countports:'):
            state = field.split(':', 1)[1]
            if state == 'open':
                field = "openports.count"
            else:
                specialproj = {"_id": 0,
                               "ports.state_state": 1}
                specialflt = [
                    {"$project": {"ports": {"$ifNull": ["$ports", []]}}},
                    # See "portlist:".
                    {"$redact": {"$cond": {"if": {"$eq": [{"$ifNull":
                                                           ["$ports", None]},
                                                          None]},
                                           "then": {
                                               "$cond": {
                                                   "if": {"$eq": [
                                                       "$state_state",
                                                       state]},
                                                   "then": "$$KEEP",
                                                   "else": "$$PRUNE"}},
                                           "else": "$$DESCEND"}}},
                    {"$project": {"countports": {"$size": "$ports"}}},
                ]
                field = "countports"
        elif field == "service":
            flt = self.flt_and(flt, self.searchopenport())
            specialproj = {
                "_id": 0,
                "ports.state_state": 1,
                "ports.service_name": 1,
            }
            specialflt = [
                {"$match": {"ports.state_state": "open"}},
                {"$project":
                 {"ports.service_name":
                  {"$ifNull": ["$ports.service_name", ""]}}},
            ]
            field = "ports.service_name"

            def outputproc(x):
                return {'count': x['count'],
                        '_id': x['_id'] if x['_id'] else None}
        elif field.startswith("service:"):
            port = int(field.split(':', 1)[1])
            flt = self.flt_and(flt, self.searchport(port))
            specialproj = {"_id": 0, "ports.port": 1, "ports.service_name": 1}
            specialflt = [
                {"$match": {"ports.port": port}},
                {"$project":
                 {"ports.service_name":
                  {"$ifNull": ["$ports.service_name", ""]}}},
            ]
            field = "ports.service_name"
        elif field == 'product':
            flt = self.flt_and(flt, self.searchopenport())
            specialproj = {
                "_id": 0,
                "ports.state_state": 1,
                "ports.service_name": 1,
                "ports.service_product": 1,
            }
            if self.mongodb_32_more:
                specialflt = [
                    {"$match": {"ports.state_state": "open"}},
                    {"$project":
                     {"ports.service_product":
                      ["$ports.service_name",
                       "$ports.service_product"]}},
                ]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(x['_id']),
                    }
            else:
                specialflt = [
                    {"$match": {"ports.state_state": "open"}},
                    {"$project":
                     {"ports.service_product": _old_array(
                         {"$ifNull": ["$ports.service_name", ""]},
                         {"$ifNull": ["$ports.service_product", ""]},
                     )}},
                ]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(elt if elt else None for elt in
                                     x['_id'].split('###')),
                    }
            field = "ports.service_product"
        elif field.startswith('product:'):
            service = field.split(':', 1)[1]
            if service.isdigit():
                port = int(service)
                flt = self.flt_and(flt, self.searchport(port))
                specialflt = [
                    {"$match": {"ports.port": port}},
                ]
            else:
                flt = self.flt_and(flt, self.searchservice(service))
                specialflt = [
                    {"$match": {"ports.service_name": service}},
                ]
            specialproj = {
                "_id": 0,
                "ports.port": 1,
                "ports.service_name": 1,
                "ports.service_product": 1,
            }
            if self.mongodb_32_more:
                specialflt.append(
                    {"$project":
                     {"ports.service_product":
                      ["$ports.service_name", "$ports.service_product"]}},
                )

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(x['_id']),
                    }
            else:
                specialflt.append(
                    {"$project":
                     {"ports.service_product": _old_array(
                         {"$ifNull": ["$ports.service_name", ""]},
                         {"$ifNull": ["$ports.service_product", ""]},
                     )}},
                )

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(elt if elt else None for elt in
                                     x['_id'].split('###')),
                    }
            field = "ports.service_product"
        elif field == 'version':
            flt = self.flt_and(flt, self.searchopenport())
            specialproj = {
                "_id": 0,
                "ports.state_state": 1,
                "ports.service_name": 1,
                "ports.service_product": 1,
                "ports.service_version": 1,
            }
            if self.mongodb_32_more:
                specialflt = [
                    {"$match": {"ports.state_state": "open"}},
                    {"$project":
                     {"ports.service_product": [
                         "$ports.service_name",
                         "$ports.service_product",
                         "$ports.service_version",
                     ]}},
                ]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(x['_id']),
                    }
            else:
                specialflt = [
                    {"$match": {"ports.state_state": "open"}},
                    {"$project":
                     {"ports.service_product": _old_array(
                         {"$ifNull": ["$ports.service_name", ""]},
                         {"$ifNull": ["$ports.service_product", ""]},
                         {"$ifNull": ["$ports.service_version", ""]},
                     )}},
                ]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(elt if elt else None for elt in
                                     x['_id'].split('###')),
                    }
            field = "ports.service_product"
        elif field.startswith('version:'):
            service = field.split(':', 1)[1]
            if service.isdigit():
                port = int(service)
                flt = self.flt_and(flt, self.searchport(port))
                specialflt = [
                    {"$match": {"ports.port": port}},
                ]
            elif ":" in service:
                service, product = service.split(':', 1)
                flt = self.flt_and(flt, self.searchproduct(
                    product,
                    service=service,
                ))
                specialflt = [
                    {"$match": {"ports.service_name": service,
                                "ports.service_product": product}},
                ]
            else:
                flt = self.flt_and(flt, self.searchservice(service))
                specialflt = [
                    {"$match": {"ports.service_name": service}},
                ]
            specialproj = {
                "_id": 0,
                "ports.port": 1,
                "ports.service_name": 1,
                "ports.service_product": 1,
                "ports.service_version": 1,
            }
            if self.mongodb_32_more:
                specialflt.append(
                    {"$project":
                     {"ports.service_product": [
                         "$ports.service_name",
                         "$ports.service_product",
                         "$ports.service_version",
                     ]}},
                )

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(x['_id']),
                    }
            else:
                specialflt.append(
                    {"$project":
                     {"ports.service_product": _old_array(
                         {"$ifNull": ["$ports.service_name", ""]},
                         {"$ifNull": ["$ports.service_product", ""]},
                         {"$ifNull": ["$ports.service_version", ""]},
                     )}},
                )

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': tuple(elt if elt else None for elt in
                                     x['_id'].split('###')),
                    }
            field = "ports.service_product"
        elif field.startswith("cpe"):
            try:
                field, cpeflt = field.split(":", 1)
                cpeflt = cpeflt.split(':', 3)
            except ValueError:
                cpeflt = []
            try:
                field = field.split(".", 1)[1]
            except IndexError:
                field = "version"
            fields = ["type", "vendor", "product", "version"]
            if field not in fields:
                try:
                    field = fields[int(field) - 1]
                except (IndexError, ValueError):
                    field = "version"
            cpeflt = zip(fields, (utils.str2regexp(value) for value in cpeflt))
            # We need two different filters because we need two
            # different $match in the pipeline. The first one occurs
            # before the $unwind operation, so we need an $elemMatch
            # when we filter against more than one value, while the
            # second one occurs after, so an $elemMatch would fail.
            cpeflt1 = self.searchcpe(**dict(
                ("cpe_type" if key == "type" else key, value)
                for key, value in cpeflt
            ))
            cpeflt2 = dict(("cpes.%s" % key, value) for key, value in cpeflt)
            # We need to keep enough cpes.* fields for the projection
            # *and* for our filter
            fields = fields[:max(fields.index(field), len(cpeflt)) + 1]
            flt = self.flt_and(flt, cpeflt1)
            specialproj = dict(("cpes.%s" % fname, 1) for fname in fields)
            specialproj["_id"] = 0
            concat = ["$cpes.%s" % fields[0]]
            # Now we only keep what the user wanted
            for fname in fields[1:fields.index(field) + 1]:
                concat.append(":")
                concat.append("$cpes.%s" % fname)
            specialflt = []
            if cpeflt2:
                specialflt.append({"$match": cpeflt2})
            specialflt.append(
                {"$project": {"cpes.%s" % field: {"$concat": concat}}})
            field = "cpes.%s" % field

            def outputproc(x):
                return {'count': x['count'],
                        '_id': tuple(x['_id'].split(':', 3))}
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
        elif field.startswith('smb.'):
            flt = self.flt_and(
                flt, self.searchscript(name='smb-os-discovery')
            )
            if field == 'smb.dnsdomain':
                field = 'ports.scripts.smb-os-discovery.domain_dns'
            elif field == 'smb.forest':
                field = 'ports.scripts.smb-os-discovery.forest_dns'
            else:
                field = 'ports.scripts.smb-os-discovery.' + field[4:]
        elif field == "script":
            flt = self.flt_and(
                flt, self.searchscript(name={"$exists": True})
            )
            field = "ports.scripts.id"
        elif field.startswith('script:'):
            scriptid = field.split(':', 1)[1]
            flt = self.flt_and(flt, self.searchscript(name={"$exists": True}))
            if ':' in scriptid:
                port, scriptid = scriptid.split(':', 1)
                if port.isdigit():
                    port = int(port)
                flt = self.flt_and(flt, self.searchport(port))
            else:
                port, scriptid = None, field.split(':', 1)[1]
            specialproj = {"_id": 0, "ports.scripts.id": 1,
                           "ports.scripts.output": 1}
            if port is not None:
                specialproj.update({'ports.port': 1})
            specialflt = [
                {"$match": ({"ports.scripts.id": scriptid}
                            if port is None else
                            {"ports.scripts.id": scriptid,
                             "ports.port": port})},
                {"$project": {"ports.scripts.output": 1}}
            ]
            field = "ports.scripts.output"
        elif field == 'domains':
            flt = self.flt_and(flt, self.searchdomain({'$exists': True}))
            field = 'hostnames.domains'
        elif field.startswith('domains:'):
            flt = self.flt_and(flt, self.searchdomain({'$exists': True}))
            level = int(field[8:]) - 1
            field = 'hostnames.domains'
            aggrflt = {
                "field": re.compile('^([^\\.]+\\.){%d}[^\\.]+$' % level)}
        elif field.startswith('cert.'):
            subfield = field[5:]
            field = 'ports.scripts.ssl-cert.' + subfield
        elif field == 'sshkey.bits':
            flt = self.flt_and(flt, self.searchsshkey())
            specialproj = {"ports.scripts.ssh-hostkey.type": 1,
                           "ports.scripts.ssh-hostkey.bits": 1}
            if self.mongodb_32_more:
                specialflt = [{"$project": {
                    "_id": 0,
                    "ports.scripts.ssh-hostkey.bits": [
                        "$ports.scripts.ssh-hostkey.type",
                        "$ports.scripts.ssh-hostkey.bits",
                    ],
                }}]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'])}
            else:
                specialflt = [{"$project": {
                    "_id": 0,
                    "ports.scripts.ssh-hostkey.bits": _old_array(
                        "$ports.scripts.ssh-hostkey.type",
                        "$ports.scripts.ssh-hostkey.bits",
                    ),
                }}]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'].split('###'))}
            field = "ports.scripts.ssh-hostkey.bits"
        elif field.startswith('sshkey.'):
            flt = self.flt_and(flt, self.searchsshkey())
            subfield = field[7:]
            field = 'ports.scripts.ssh-hostkey.' + subfield
        elif field == 'ike.vendor_ids':
            flt = self.flt_and(flt, self.searchscript(name="ike-info"))
            specialproj = {"ports.scripts.ike-info.vendor_ids.value": 1,
                           "ports.scripts.ike-info.vendor_ids.name": 1}
            if self.mongodb_32_more:
                specialflt = [{"$project": {
                    "_id": 0,
                    "ports.scripts.ike-info.vendor_ids": [
                        "$ports.scripts.ike-info.vendor_ids.value",
                        "$ports.scripts.ike-info.vendor_ids.name",
                    ],
                }}]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'])}
            else:
                specialflt = [{"$project": {
                    "_id": 0,
                    "ports.scripts.ike-info.vendor_ids": _old_array(
                        "$ports.scripts.ike-info.vendor_ids.value",
                        {"$ifNull": ["$ports.scripts.ike-info.vendor_ids.name",
                                     ""]},
                    ),
                }}]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(null_if_empty(val) for val
                                         in x['_id'].split('###'))}
            field = "ports.scripts.ike-info.vendor_ids"
        elif field == 'ike.transforms':
            flt = self.flt_and(flt, self.searchscript(
                name="ike-info",
                values={"transforms": {"$exists": True}},
            ))
            specialproj = {
                "ports.scripts.ike-info.transforms.Authentication": 1,
                "ports.scripts.ike-info.transforms.Encryption": 1,
                "ports.scripts.ike-info.transforms.GroupDesc": 1,
                "ports.scripts.ike-info.transforms.Hash": 1,
                "ports.scripts.ike-info.transforms.LifeDuration": 1,
                "ports.scripts.ike-info.transforms.LifeType": 1,
            }
            if self.mongodb_32_more:
                specialflt = [{"$project": {
                    "_id": 0,
                    "ports.scripts.ike-info.transforms": [
                        "$ports.scripts.ike-info.transforms.Authentication",
                        "$ports.scripts.ike-info.transforms.Encryption",
                        "$ports.scripts.ike-info.transforms.GroupDesc",
                        "$ports.scripts.ike-info.transforms.Hash",
                        "$ports.scripts.ike-info.transforms.LifeDuration",
                        "$ports.scripts.ike-info.transforms.LifeType",
                    ],
                }}]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'])}
            else:
                specialflt = [{"$project": {
                    "_id": 0,
                    "ports.scripts.ike-info.transforms": _old_array(
                        {"$ifNull": [
                            "$ports.scripts.ike-info.transforms."
                            "Authentication",
                            "",
                        ]},
                        {"$ifNull": [
                            "$ports.scripts.ike-info.transforms.Encryption",
                            "",
                        ]},
                        {"$ifNull":
                         ["$ports.scripts.ike-info.transforms.GroupDesc", ""]},
                        {"$ifNull":
                         ["$ports.scripts.ike-info.transforms.Hash", ""]},
                        {"$toLower":
                         "$ports.scripts.ike-info.transforms.LifeDuration"},
                        {"$ifNull":
                         ["$ports.scripts.ike-info.transforms.LifeType", ""]},
                    ),
                }}]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(null_if_empty(val) for val
                                         in x['_id'].split('###'))}
            field = "ports.scripts.ike-info.transforms"
        elif field == 'ike.notification':
            flt = self.flt_and(flt, self.searchscript(
                name="ike-info",
                values={"notification_type": {"$exists": True}},
            ))
            field = "ports.scripts.ike-info.notification_type"
        elif field.startswith('ike.'):
            flt = self.flt_and(flt, self.searchscript(name="ike-info"))
            field = "ports.scripts.ike-info." + field[4:]
        elif field == 'httphdr':
            flt = self.flt_and(flt, self.searchscript(name="http-headers"))
            specialproj = {"_id": 0, "ports.scripts.http-headers.name": 1,
                           "ports.scripts.http-headers.value": 1}
            if self.mongodb_32_more:
                specialflt = [{"$project": {
                    "_id": 0,
                    "ports.scripts.http-headers": [
                        "$ports.scripts.http-headers.name",
                        "$ports.scripts.http-headers.value",
                    ],
                }}]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(x['_id'])}
            else:
                specialflt = [{"$project": {
                    "_id": 0,
                    "ports.scripts.http-headers": _old_array(
                        "$ports.scripts.http-headers.name",
                        "$ports.scripts.http-headers.value",
                    ),
                }}]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': tuple(null_if_empty(val) for val
                                         in x['_id'].split('###'))}
            field = "ports.scripts.http-headers"
        elif field.startswith('httphdr.'):
            flt = self.flt_and(flt, self.searchscript(name="http-headers"))
            field = "ports.scripts.http-headers.%s" % field[8:]
        elif field.startswith('httphdr:'):
            flt = self.flt_and(flt, self.searchscript(name="http-headers"))
            specialproj = {"_id": 0, "ports.scripts.http-headers.name": 1,
                           "ports.scripts.http-headers.value": 1}
            specialflt = [
                {"$match": {"ports.scripts.http-headers.name":
                            field[8:].lower()}}
            ]
            field = "ports.scripts.http-headers.value"
        elif field.startswith('modbus.'):
            flt = self.flt_and(flt, self.searchscript(name="modbus-discover"))
            subfield = field[7:]
            field = 'ports.scripts.modbus-discover.' + subfield
        elif field.startswith('s7.'):
            flt = self.flt_and(flt, self.searchscript(name="s7-info"))
            subfield = field[3:]
            field = 'ports.scripts.s7-info.' + subfield
        elif field.startswith('enip.'):
            flt = self.flt_and(flt, self.searchscript(name="enip-info"))
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
        elif field.startswith('mongo.dbs.'):
            flt = self.flt_and(flt,
                               self.searchscript(name="mongodb-databases"))
            field = 'ports.scripts.mongodb-databases.' + field[10:]
        elif field.startswith('vulns.'):
            flt = self.flt_and(flt, self.searchvuln())
            subfield = field[6:]
            if subfield == "id":
                field = 'ports.scripts.vulns.id'
            else:
                field = "ports.scripts.vulns." + subfield
                specialproj = {
                    "_id": 0,
                    "ports.scripts.vulns.id": 1,
                    field: 1,
                }
                if self.mongodb_32_more:
                    specialflt = [{
                        "$project": {
                            "_id": 0,
                            field: [
                                "$ports.scripts.vulns.id",
                                "$" + field,
                            ],
                        },
                    }]

                    def outputproc(x):
                        return {'count': x['count'],
                                '_id': tuple(x['_id'])}
                else:
                    specialflt = [{
                        "$project": {
                            "_id": 0,
                            field: _old_array(
                                "$ports.scripts.vulns.id",
                                "$" + field,
                            ),
                        },
                    }]

                    def outputproc(x):
                        return {
                            'count': x['count'],
                            '_id': tuple(x['_id'].split('###', 1)),
                        }
        elif field == 'file' or (field.startswith('file') and
                                 field[4] in '.:'):
            if field.startswith('file:'):
                scripts = field[5:]
                if '.' in scripts:
                    scripts, field = scripts.split('.', 1)
                else:
                    field = 'filename'
                scripts = scripts.split(',')
            else:
                field = field[5:] or 'filename'
                scripts = None
            flt = self.flt_and(flt, self.searchfile(scripts=scripts))
            field = 'ports.scripts.ls.volumes.files.%s' % field
            if scripts is not None:
                specialproj = {"_id": 0, field: 1, 'ports.scripts.id': 1}
                # We need two different filters here (see `cpeflt`
                # above).
                specialflt = [
                    {"$match": {"ports.scripts.id":
                                flt['ports.scripts']['$elemMatch']['id']}},
                    {"$project": {field: {"$ifNull": ["$" + field, ""]}}},
                    # {"$project": {field: 1}},
                ]
            else:
                specialflt = [
                    {"$project": {field: {"$ifNull": ["$" + field, ""]}}},
                ]

            def outputproc(x):
                return {'count': x['count'],
                        '_id': x['_id'] if x['_id'] else None}
        elif field == 'screenwords':
            field = 'ports.screenwords'
            flt = self.flt_and(flt, self.searchscreenshot(words=True))
        elif field == 'hop':
            field = 'traces.hops.ipaddr'
            specialproj = {"_id": 0,
                           "traces.hops.ipaddr_0": 1,
                           "traces.hops.ipaddr_1": 1}
            if self.mongodb_32_more:
                specialflt = [
                    {"$project": {field: ['$traces.hops.ipaddr_0',
                                          '$traces.hops.ipaddr_1']}},
                ]

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': self.internal2ip(x['_id'])}
            else:
                specialflt = [
                    {"$project": {field: _old_array('$traces.hops.ipaddr_0',
                                                    '$traces.hops.ipaddr_1',
                                                    convert_to_string=True)}},
                ]

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': self.internal2ip([
                            int(val) for val in
                            x['_id'].split('###')
                        ]),
                    }
        elif field.startswith('hop') and field[3] in ':>':
            specialproj = {"_id": 0,
                           "traces.hops.ipaddr_0": 1,
                           "traces.hops.ipaddr_1": 1,
                           "traces.hops.ttl": 1}
            specialflt = [
                {"$match": {
                    "traces.hops.ttl": (
                        int(field[4:])
                        if field[3] == ':' else
                        {"$gt": int(field[4:])}
                    )}}]
            if self.mongodb_32_more:
                specialflt.append(
                    {"$project": {'traces.hops.ipaddr': [
                        '$traces.hops.ipaddr_0',
                        '$traces.hops.ipaddr_1',
                    ]}},
                )

                def outputproc(x):
                    return {'count': x['count'],
                            '_id': self.internal2ip(x['_id'])}
            else:
                specialflt.append(
                    {"$project": {'traces.hops.ipaddr': _old_array(
                        '$traces.hops.ipaddr_0',
                        '$traces.hops.ipaddr_1',
                        convert_to_string=True,
                    )}},
                )

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': self.internal2ip([
                            int(val) for val in
                            x['_id'].split('###')
                        ]),
                    }
            field = 'traces.hops.ipaddr'
        pipeline = self._topvalues(
            field, flt=flt, topnbr=topnbr, sort=sort, limit=limit,
            skip=skip, least=least, aggrflt=aggrflt,
            specialproj=specialproj, specialflt=specialflt,
        )
        cursor = self.set_limits(
            self.db[self.colname_hosts].aggregate(pipeline, cursor={})
        )
        if outputproc is not None:
            return (outputproc(res) for res in cursor)
        return cursor

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None):
        """This method makes use of the aggregation framework to
        produce distinct values for a given field.

        """
        return self._distinct(self.colname_hosts, field, flt=flt, sort=sort,
                              limit=limit, skip=skip)

    def diff_categories(self, category1, category2, flt=None,
                        include_both_open=True):
        """`category1` and `category2` must be categories (provided as str or
        unicode objects)

        Returns a generator of tuples:
        ({'addr': address, 'proto': protocol, 'port': port}, value)

        Where `address` is an integer (use `utils.int2ip` to get the
        corresponding string), and value is:

          - -1  if the port is open in category1 and not in category2,

          -  0  if the port is open in both category1 and category2,

          -  1  if the port is open in category2 and not in category1.

        This can be useful to compare open ports from two scan results
        against the same targets.

        """
        category_filter = self.searchcategory([category1, category2])
        if self.mongodb_32_more:
            addr = ['$addr_0', '$addr_1']
        else:
            addr = _old_array('$addr_0', '$addr_1', convert_to_string=True)
        pipeline = [
            {"$match": (category_filter if flt is None else
                        self.flt_and(flt, category_filter))},
            {"$unwind": "$categories"},
            {"$match": category_filter},
            {"$unwind": "$ports"},
            {"$match": {"ports.state_state": "open"}},
            {"$project": {"_id": 0, "addr": addr, "ports.protocol": 1,
                          "ports.port": 1,
                          "categories": 1}},
            {"$group": {"_id": {"addr": "$addr", "proto": "$ports.protocol",
                                "port": "$ports.port"},
                        "categories": {"$push": "$categories"}}},
        ]
        cursor = self.db[self.colname_hosts].aggregate(pipeline, cursor={})

        def categories_to_val(categories):
            state1, state2 = category1 in categories, category2 in categories
            # assert any(states)
            return (state2 > state1) - (state2 < state1)
        cursor = (dict(x['_id'], value=categories_to_val(x['categories']))
                  for x in cursor)
        if not self.mongodb_32_more:
            cursor = (
                dict(x, addr=[int(val) for val in x['addr'].split('###')])
                for x in cursor
            )
        if include_both_open:
            return cursor
        else:
            return (result for result in cursor if result["value"])


class MongoDBNmap(MongoDBActive, DBNmap):

    def __init__(self, host, dbname, colname_scans="scans",
                 colname_hosts="hosts", **kwargs):
        MongoDBActive.__init__(self, host, dbname, colname_hosts=colname_hosts,
                               **kwargs)
        DBNmap.__init__(self)
        self.colname_scans = colname_scans
        self.content_handler = Nmap2Mongo
        self.output_function = None

    def store_scan_doc(self, scan):
        ident = self.db[self.colname_scans].insert(scan)
        utils.LOGGER.debug("SCAN STORED: %r in %r", ident, self.colname_scans)
        return ident

    def store_or_merge_host(self, host):
        self.store_host(host)

    def init(self):
        self.db[self.colname_scans].drop()
        super(MongoDBNmap, self).init()

    def cmp_schema_version_scan(self, scan):
        """Returns 0 if the `scan`'s schema version matches the code's
        current version, -1 if it is higher (you need to update IVRE),
        and 1 if it is lower (you need to call .migrate_schema()).

        """
        return self.cmp_schema_version(self.colname_scans, scan)

    def getscan(self, scanid):
        return self.find_one(self.colname_scans, {'_id': scanid})

    def is_scan_present(self, scanid):
        if self.find_one(self.colname_scans, {"_id": scanid},
                         fields=[]) is not None:
            return True
        return False

    def remove(self, host):
        """Removes the host "host" from the active column.
        "host" must be the host record as returned by MongoDB.

        If "host" has a "scanid" attribute, and if it refers to a scan
        that have no more host record after the deletion of "host",
        then the scan record is also removed.

        """
        super(MongoDBNmap, self).remove(host)
        for scanid in self.getscanids(host):
            if self.find_one(self.colname_hosts, {'scanid': scanid}) is None:
                self.db[self.colname_scans].remove(spec_or_id=scanid)


class MongoDBView(MongoDBActive, DBView):

    def __init__(self, host, dbname, colname_hosts="views", **kwargs):
        MongoDBActive.__init__(self, host, dbname, colname_hosts=colname_hosts,
                               **kwargs)
        DBView.__init__(self)

    def store_or_merge_host(self, host):
        if not self.merge_host(host):
            self.store_host(host)


class MongoDBPassive(MongoDB, DBPassive):

    needunwind = ["infos.san"]
    ipaddr_fields = ["addr"]

    def __init__(self, host, dbname,
                 colname_passive="passive",
                 **kargs):
        MongoDB.__init__(self, host, dbname, **kargs)
        DBPassive.__init__(self)
        self.colname_passive = colname_passive
        self.indexes = {
            self.colname_passive: [
                ([('schema_version', pymongo.ASCENDING)], {}),
                ([('port', pymongo.ASCENDING)], {}),
                ([('value', pymongo.ASCENDING)], {}),
                ([('targetval', pymongo.ASCENDING)], {}),
                ([('recontype', pymongo.ASCENDING)], {}),
                ([('firstseen', pymongo.ASCENDING)], {}),
                ([('lastseen', pymongo.ASCENDING)], {}),
                ([('sensor', pymongo.ASCENDING)], {}),
                ([
                    ('addr_0', pymongo.ASCENDING),
                    ('addr_1', pymongo.ASCENDING),
                    ('recontype', pymongo.ASCENDING),
                    ('port', pymongo.ASCENDING),
                ], {}),
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
                ([('infos.md5', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.sha1', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.sha256', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.issuer_text', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.subject_text', pymongo.ASCENDING)],
                 {"sparse": True}),
                ([('infos.pubkeyalgo', pymongo.ASCENDING)],
                 {"sparse": True}),
            ],
        }
        self.schema_migrations = {
            self.colname_passive: {
                None: (1, self.migrate_schema_passive_0_1),
            },
        }
        self.schema_migrations_indexes[colname_passive] = {
            1: {
                "drop": [
                    ([
                        ('addr', pymongo.ASCENDING),
                        ('recontype', pymongo.ASCENDING),
                        ('port', pymongo.ASCENDING),
                    ], {}),
                    ([('infos.issuer', pymongo.ASCENDING)],
                     {"sparse": True}),
                    ([('infos.subject', pymongo.ASCENDING)],
                     {"sparse": True}),
                ],
                "ensure": [
                    ([
                        ('addr_0', pymongo.ASCENDING),
                        ('addr_1', pymongo.ASCENDING),
                        ('recontype', pymongo.ASCENDING),
                        ('port', pymongo.ASCENDING),
                    ], {}),
                    ([('schema_version', pymongo.ASCENDING)], {}),
                    ([('infos.issuer_text', pymongo.ASCENDING)],
                     {"sparse": True}),
                    ([('infos.subject_text', pymongo.ASCENDING)],
                     {"sparse": True}),
                    ([('infos.san', pymongo.ASCENDING)],
                     {"sparse": True}),
                ],
            },
        }
        self.hint_indexes = OrderedDict([
            ["addr_0", [("addr_0", 1), ("addr_1", 1), ("recontype", 1),
                        ("port", 1)]],
            ["targetval", [("targetval", 1)]],
        ])

    def init(self):
        """Initializes the "passive" columns, i.e., drops the columns, and
creates the default indexes."""
        self.db[self.colname_passive].drop()
        self.create_indexes()

    def cmp_schema_version_passive(self, rec):
        """Returns 0 if the `rec`'s schema version matches the code's
        current version, -1 if it is higher (you need to update IVRE),
        and 1 if it is lower (you need to call .migrate_schema()).

        """
        return self.cmp_schema_version(self.colname_passive, rec)

    def migrate_schema(self, version):
        """Process to schema migrations in column `colname_passive`
        starting from `version`.

        """
        MongoDB.migrate_schema(self, self.colname_passive, version)

    def _migrate_update_record(self, colname, recid, update):
        """Define how an update is handled. Purpose-specific subclasses may
want to do something special here, e.g., mix with other records.

        """
        if colname == self.colname_passive:  # just in case
            del update['_id']
            self.insert_or_update_mix(update, getinfos=passive.getinfos)
            self.remove(recid)
        else:
            return super(MongoDBPassive,
                         self)._migrate_update_record(colname, recid, update)

    @classmethod
    def migrate_schema_passive_0_1(cls, doc):
        """Converts a record from version 0 (no "schema_version" key in the
document) to version 1 (`doc["schema_version"] == 1`). Version 1
changes the way IP addresses and timestamps are stored.

In version 0, IP addresses are stored as integers and timestamps
(firstseen & lastseen) as floats.

In version 1, IP addresses are stored as two 64-bit unsigned integers
(the `addr` field becomes `addr_0` and `addr_1`) and timestamps are
stored as Timestamps (a BSON type, represented as datetime.datetime
objects by the Python driver; this format is already used in the
active databases)

Also, the structured data for SSL certificates has been updated.

        """
        assert "schema_version" not in doc
        doc["schema_version"] = 1
        for key in ["firstseen", "lastseen"]:
            doc[key] = datetime.datetime.fromtimestamp(doc[key])
        if "addr" in doc:
            doc['addr_0'], doc['addr_1'] = cls.ip2internal(utils.force_int2ip(
                doc.pop('addr')
            ))
        if (
                doc["recontype"] == "SSL_SERVER" and
                doc["source"] == "cert"
        ):
            doc.update(passive._getinfos_cert(doc, cls.to_binary))
        return doc

    def _get(self, flt, **kargs):
        """Like .get(), but returns a MongoDB cursor (suitable for use with
e.g.  .explain()).

        """
        return self._get_cursor(self.colname_passive, flt, **kargs)

    def get(self, spec, hint=None, **kargs):
        """Queries the passive column with the provided filter "spec", and
returns a MongoDB cursor.

This should be very fast, as no operation is done (the cursor is only
returned). Next operations (e.g., .count(), enumeration, etc.) might
take a long time, depending on both the operations and the filter.

Any keyword argument is passed to the .find() method of the Mongodb
column object, without any validation (and might have no effect if it
is not expected)."""
        cursor = self._get(spec, **kargs)
        if hint is not None:
            cursor.hint(hint)
        for rec in cursor:
            try:
                rec['addr'] = self.internal2ip([rec.pop('addr_0'),
                                                rec.pop('addr_1')])
            except (KeyError, socket.error):
                pass
            yield rec

    def get_one(self, spec, **kargs):
        """Same function as get, except .find_one() method is called
instead of .find(), so the first record matching "spec" (or None) is
returned.

Unlike get(), this function might take a long time, depending
on "spec" and the indexes set on colname_passive column."""
        # TODO: check limits
        rec = self.find_one(self.colname_passive, spec, **kargs)
        try:
            rec['addr'] = self.internal2ip([rec['addr_0'], rec['addr_1']])
        except (TypeError, KeyError, socket.error):
            pass
        else:
            del rec['addr_0'], rec['addr_1']
        return rec

    def update(self, spec, **kargs):
        """Updates the first record matching "spec" in the "passive" column,
setting values according to the keyword arguments.
"""
        self.db[self.colname_passive].update(spec, {'$set': kargs})

    def insert(self, spec, getinfos=None):
        """Inserts the record "spec" into the passive column."""
        if getinfos is not None:
            spec.update(getinfos(spec, self.to_binary))
        try:
            spec['addr_0'], spec['addr_1'] = self.ip2internal(spec.pop('addr'))
        except (KeyError, ValueError):
            pass
        self.db[self.colname_passive].insert(spec)

    def insert_or_update(self, timestamp, spec, getinfos=None, lastseen=None):
        if spec is None:
            return
        try:
            spec['addr_0'], spec['addr_1'] = self.ip2internal(spec.pop('addr'))
        except (KeyError, ValueError):
            pass
        hint = self.get_hint(spec)
        current = self.get(spec, hint=hint, fields=[])
        try:
            current = next(current)
        except StopIteration:
            current = None
        updatespec = {
            '$inc': {'count': spec.pop("count", 1)},
            '$min': {'firstseen': timestamp},
            '$max': {'lastseen': lastseen or timestamp},
        }
        if current is not None:
            self.db[self.colname_passive].update(
                {'_id': current['_id']},
                updatespec,
            )
        else:
            if getinfos is not None:
                infos = getinfos(spec, self.to_binary)
                if infos:
                    updatespec['$setOnInsert'] = infos
            self.db[self.colname_passive].update(
                spec,
                updatespec,
                upsert=True,
            )

    def insert_or_update_bulk(self, specs, getinfos=None,
                              separated_timestamps=True):
        """Like `.insert_or_update()`, but `specs` parameter has to be an
        iterable of (timestamp, spec) values. This will perform bulk
        MongoDB inserts with the major drawback that the `getinfos`
        parameter will be called (if it is not `None`) for each spec,
        even when the spec already exists in the database and the call
        was hence unnecessary.

        It's up to you to decide whether having bulk insert is worth
        it or if you want to go with the regular `.insert_or_update()`
        method.

        """
        bulk = self.db[self.colname_passive].initialize_unordered_bulk_op()
        count = 0

        if separated_timestamps:
            def generator(specs):
                for timestamp, spec in specs:
                    yield timestamp, timestamp, spec
        else:
            def generator(specs):
                for spec in specs:
                    firstseen = spec.pop("firstseen", None)
                    lastseen = spec.pop("lastseen", None)
                    yield firstseen or lastseen, lastseen or firstseen, spec
        try:
            for firstseen, lastseen, spec in generator(specs):
                if spec is None:
                    continue
                try:
                    spec['addr_0'], spec['addr_1'] = self.ip2internal(
                        spec.pop('addr')
                    )
                except (KeyError, ValueError):
                    pass
                updatespec = {
                    '$inc': {'count': 1},
                    '$min': {'firstseen': firstseen},
                    '$max': {'lastseen': lastseen},
                }
                if getinfos is not None:
                    infos = getinfos(spec, self.to_binary)
                    if infos:
                        updatespec['$setOnInsert'] = infos
                bulk.find(spec).upsert().update(updatespec)
                count += 1
                if count >= config.MONGODB_BATCH_SIZE:
                    utils.LOGGER.debug("DB:MongoDB bulk upsert: %d", count)
                    bulk.execute()
                    bulk = self.db[self.colname_passive]\
                               .initialize_unordered_bulk_op()
                    count = 0
        except IOError:
            pass
        if count > 0:
            utils.LOGGER.debug("DB:MongoDB bulk upsert: %d (final)", count)
            bulk.execute()

    def insert_or_update_mix(self, spec, getinfos=None):
        """Updates the first record matching "spec" (without
        "firstseen", "lastseen" and "count") by mixing "firstseen",
        "lastseen" and "count" from "spec" and from the database.

        This is usefull to mix records from different databases.

        """
        updatespec = {}
        try:
            spec['addr_0'], spec['addr_1'] = self.ip2internal(spec.pop('addr'))
        except (KeyError, ValueError):
            pass
        if 'firstseen' in spec:
            updatespec['$min'] = {'firstseen': spec.pop('firstseen')}
        if 'lastseen' in spec:
            updatespec['$max'] = {'lastseen': spec.pop('lastseen')}
        if 'count' in spec:
            updatespec['$inc'] = {'count': spec.pop('count')}
        else:
            updatespec['$inc'] = {'count': 1}
        if 'infos' in spec:
            updatespec['$setOnInsert'] = {'infos': spec.pop('infos')}
        if 'fullinfos' in spec:
            if '$setOnInsert' in updatespec:
                updatespec['$setOnInsert'].update(
                    {'fullinfos': spec.pop('fullinfos')}
                )
            else:
                updatespec['$setOnInsert'] = {
                    'fullinfos': spec.pop('fullinfos'),
                }
        current = self.get_one(spec, fields=[])
        if current:
            self.db[self.colname_passive].update(
                {'_id': current['_id']},
                updatespec,
            )
        else:
            if getinfos is not None and "$setOnInsert" not in updatespec:
                infos = getinfos(spec, self.to_binary)
                if infos:
                    updatespec['$setOnInsert'] = infos
            self.db[self.colname_passive].update(
                spec,
                updatespec,
                upsert=True,
            )

    def remove(self, spec_or_id):
        self.db[self.colname_passive].remove(spec_or_id=spec_or_id)

    def topvalues(self, field, flt=None, distinct=True, **kargs):
        """This method makes use of the aggregation framework to
        produce top values for a given field.

        If `distinct` is True (default), the top values are computed
        by distinct events. If it is False, they are computed based on
        the "count" field.

        """
        if flt is None:
            flt = self.flt_empty
        if not distinct:
            kargs['countfield'] = 'count'
        outputproc = None
        specialproj = None
        if field == "addr":
            if self.mongodb_32_more:
                specialproj = {
                    "_id": 0,
                    "addr": ['$addr_0', '$addr_1'],
                }

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': (None if x['_id'][0] is None else
                                self.internal2ip(x['_id'])),
                    }
            else:
                specialproj = {
                    "_id": 0,
                    "addr": _old_array(
                        '$addr_0', '$addr_1',
                        convert_to_string=True,
                    ),
                }

                def outputproc(x):
                    return {
                        'count': x['count'],
                        '_id': (None if x['_id'] == '###' else
                                self.internal2ip([int(val) for val in
                                                  x['_id'].split('###')])),
                    }
        elif field == "net" or field.startswith("net:"):
            flt = self.flt_and(flt, self.searchipv4())
            mask = int(field.split(':', 1)[1]) if ':' in field else 24
            field = "addr"
            # This should not overflow thanks to .searchipv4() filter
            addr = {"$add": ["$addr_1", 0x7fff000100000000]}
            if self.mongodb_32_more:
                specialproj = {
                    "_id": 0,
                    "addr": {"$floor": {"$divide": [addr, 2 ** (32 - mask)]}},
                }
            else:
                specialproj = {
                    "_id": 0,
                    "addr": {"$subtract": [{"$divide": [addr,
                                                        2 ** (32 - mask)]},
                                           {"$mod": [{"$divide": [
                                               addr,
                                               2 ** (32 - mask),
                                           ]}, 1]}]},
                }
            flt = self.flt_and(flt, self.searchipv4())

            def outputproc(x):
                return {
                    'count': x['count'],
                    '_id': '%s/%d' % (
                        utils.int2ip(int(x['_id']) * 2 ** (32 - mask)),
                        mask,
                    ),
                }
        pipeline = self._topvalues(field, flt=flt, specialproj=specialproj,
                                   **kargs)
        cursor = self.set_limits(
            self.db[self.colname_passive].aggregate(pipeline, cursor={})
        )
        if outputproc is not None:
            return (outputproc(res) for res in cursor)
        return cursor

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None):
        """This method makes use of the aggregation framework to
        produce distinct values for a given field.

        """
        return self._distinct(self.colname_passive, field, flt=flt, sort=sort,
                              limit=limit, skip=skip)

    @staticmethod
    def searchrecontype(rectype):
        return {'recontype': rectype}

    @staticmethod
    def searchsensor(sensor, neg=False):
        if neg:
            if isinstance(sensor, utils.REGEXP_T):
                return {'sensor': {'$not': sensor}}
            return {'sensor': {'$ne': sensor}}
        return {'sensor': sensor}

    @staticmethod
    def searchport(port, protocol='tcp', state='open', neg=False):
        """Filters (if `neg` == True, filters out) records on the specified
        protocol/port.

        """
        if protocol != 'tcp':
            raise ValueError("Protocols other than TCP are not supported "
                             "in passive")
        if state != 'open':
            raise ValueError("Only open ports can be found in passive")
        return {'port': {'$ne': port} if neg else port}

    @staticmethod
    def searchservice(srv, port=None, protocol=None):
        """Search a port with a particular service."""
        flt = {'infos.service_name': srv}
        if port is not None:
            flt['port'] = port
        if protocol is not None and protocol != 'tcp':
            raise ValueError("Protocols other than TCP are not supported "
                             "in passive")
        return flt

    @staticmethod
    def searchproduct(product, version=None, service=None, port=None,
                      protocol=None):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        flt = {'infos.service_product': product}
        if version is not None:
            flt['infos.service_version'] = version
        if service is not None:
            flt['infos.service_name'] = service
        if port is not None:
            flt['port'] = port
        if protocol is not None:
            if protocol != 'tcp':
                raise ValueError("Protocols other than TCP are not supported "
                                 "in passive")
        return flt

    @staticmethod
    def searchsvchostname(hostname):
        return {'infos.service_hostname': hostname}

    @staticmethod
    def searchuseragent(useragent):
        return {
            'recontype': 'HTTP_CLIENT_HEADER',
            'source': 'USER-AGENT',
            'value': useragent
        }

    @staticmethod
    def searchdns(name, reverse=False, subdomains=False):
        return {
            'recontype': 'DNS_ANSWER',
            (('infos.domaintarget' if reverse else 'infos.domain')
             if subdomains else ('targetval' if reverse else 'value')): name,
        }

    @staticmethod
    def searchcert(keytype=None):
        if keytype is None:
            return {'recontype': 'SSL_SERVER',
                    'source': 'cert'}
        return {'recontype': 'SSL_SERVER',
                'source': 'cert',
                'infos.pubkeyalgo': keytype + 'Encryption'}

    @staticmethod
    def searchsshkey(keytype=None):
        if keytype is None:
            return {'recontype': 'SSH_SERVER_HOSTKEY',
                    'source': 'SSHv2'}
        return {'recontype': 'SSH_SERVER_HOSTKEY',
                'source': 'SSHv2',
                'infos.algo': 'ssh-' + keytype}

    @staticmethod
    def searchcertsubject(expr):
        return {'recontype': 'SSL_SERVER',
                'source': 'cert',
                'infos.subject_text': expr}

    @staticmethod
    def searchcertissuer(expr):
        return {'recontype': 'SSL_SERVER',
                'source': 'cert',
                'infos.issuer_text': expr}

    @staticmethod
    def searchbasicauth():
        return {
            'recontype': {'$in': ['HTTP_CLIENT_HEADER',
                                  'HTTP_CLIENT_HEADER_SERVER']},
            'source': {'$in': ['AUTHORIZATION',
                               'PROXY-AUTHORIZATION']},
            'value': re.compile('^Basic', re.I),
        }

    @staticmethod
    def searchhttpauth():
        return {
            'recontype': {'$in': ['HTTP_CLIENT_HEADER',
                                  'HTTP_CLIENT_HEADER_SERVER']},
            'source': {'$in': ['AUTHORIZATION',
                               'PROXY-AUTHORIZATION']},
        }

    @staticmethod
    def searchftpauth():
        return {'recontype': {'$in': ['FTP_CLIENT', 'FTP_SERVER']}}

    @staticmethod
    def searchpopauth():
        return {'recontype': {'$in': ['POP_CLIENT', 'POP_SERVER']}}

    @staticmethod
    def searchtcpsrvbanner(banner):
        return {'recontype': 'TCP_SERVER_BANNER', 'value': banner}

    @staticmethod
    def searchtimeago(delta, neg=False, new=False):
        if isinstance(delta, datetime.timedelta):
            delta = delta.total_seconds()
        return {'lastseen' if new else 'firstseen':
                {'$lt' if neg else '$gte': time.time() - delta}}

    @staticmethod
    def searchnewer(timestamp, neg=False, new=False):
        return {'lastseen' if new else 'firstseen':
                {'$lte' if neg else '$gt': timestamp}}


class MongoDBAgent(MongoDB, DBAgent):
    """MongoDB-specific code to handle agents-in-DB"""

    def __init__(self, host, dbname,
                 colname_agents="agents",
                 colname_scans="runningscans",
                 colname_masters="masters",
                 **kargs):
        MongoDB.__init__(self, host, dbname, **kargs)
        DBAgent.__init__(self)
        self.colname_agents = colname_agents
        self.colname_scans = colname_scans
        self.colname_masters = colname_masters
        self.indexes = {
            self.colname_agents: [
                ([('host', pymongo.ASCENDING)], {}),
                ([('path.remote', pymongo.ASCENDING)], {}),
                ([('path.local', pymongo.ASCENDING)], {}),
                ([('master', pymongo.ASCENDING)], {}),
                ([('scan', pymongo.ASCENDING)], {}),
            ],
            self.colname_scans: [
                ([('agents', pymongo.ASCENDING)], {}),
            ],
            self.colname_masters: [
                ([('hostname', pymongo.ASCENDING),
                  ('path', pymongo.ASCENDING)], {}),
            ],
        }

    def init(self):
        """Initializes the "agent" columns, i.e., drops those columns
        and creates the default indexes.

        """
        self.db[self.colname_agents].drop()
        self.db[self.colname_scans].drop()
        self.db[self.colname_masters].drop()
        self.create_indexes()

    def stop_agent(self, agentid):
        agent = self.get_agent(agentid)
        if agent is None:
            raise IndexError("Agent not found [%r]" % agentid)
        if agent['scan'] is not None:
            self.unassign_agent(agent['_id'])

    def _add_agent(self, agent):
        return self.db[self.colname_agents].insert(agent)

    def get_agent(self, agentid):
        return self.find_one(self.colname_agents, {"_id": agentid})

    def get_free_agents(self):
        return (x['_id'] for x in
                self.set_limits(
                    self.find(self.colname_agents,
                              {"scan": None},
                              fields=["_id"])))

    def get_agents_by_master(self, masterid):
        return (x['_id'] for x in
                self.set_limits(
                    self.find(self.colname_agents,
                              {"master": masterid},
                              fields=["_id"])))

    def get_agents(self):
        return (x['_id'] for x in
                self.set_limits(
                    self.find(self.colname_agents,
                              fields=["_id"])))

    def assign_agent(self, agentid, scanid,
                     only_if_unassigned=False,
                     force=False):
        flt = {"_id": agentid}
        if only_if_unassigned:
            flt.update({"scan": None})
        elif not force:
            flt.update({"scan": {"$ne": False}})
        self.db[self.colname_agents].update(
            flt,
            {"$set": {"scan": scanid}}
        )
        agent = self.get_agent(agentid)
        if scanid is not None and scanid is not False \
           and scanid == agent["scan"]:
            self.db[self.colname_scans].update(
                {"_id": scanid, "agents": {"$ne": agentid}},
                {"$push": {"agents": agentid}}
            )

    def unassign_agent(self, agentid, dont_reuse=False):
        agent = self.get_agent(agentid)
        scanid = agent["scan"]
        if scanid is not None:
            self.db[self.colname_scans].update(
                {"_id": scanid, "agents": agentid},
                {"$pull": {"agents": agentid}}
            )
        if dont_reuse:
            self.assign_agent(agentid, False, force=True)
        else:
            self.assign_agent(agentid, None, force=True)

    def _del_agent(self, agentid):
        return self.db[self.colname_agents].remove(spec_or_id=agentid)

    def _add_scan(self, scan):
        return self.db[self.colname_scans].insert(scan)

    def get_scan(self, scanid):
        scan = self.find_one(self.colname_scans, {"_id": scanid},
                             fields={'target': 0})
        if scan.get('lock') is not None:
            scan['lock'] = uuid.UUID(bytes=scan['lock'])
        if "target_info" not in scan:
            target = self.get_scan_target(scanid)
            if target is not None:
                target_info = target.target.infos
                self.db[self.colname_scans].update(
                    {"_id": scanid},
                    {"$set": {"target_info": target_info}},
                )
                scan["target_info"] = target_info
        return scan

    def _get_scan_target(self, scanid):
        scan = self.find_one(self.colname_scans, {"_id": scanid},
                             fields={'target': 1, '_id': 0})
        return None if scan is None else scan['target']

    def _lock_scan(self, scanid, oldlockid, newlockid):
        """Change lock for scanid from oldlockid to newlockid. Returns the new
scan object on success, and raises a LockError on failure.

        """
        if oldlockid is not None:
            oldlockid = bson.Binary(oldlockid)
        if newlockid is not None:
            newlockid = bson.Binary(newlockid)
        scan = self.db[self.colname_scans].find_and_modify({
            "_id": scanid,
            "lock": oldlockid,
        }, {
            "$set": {"lock": newlockid, "pid": os.getpid()},
        }, full_response=True, fields={'target': False}, new=True)['value']
        if scan is None:
            if oldlockid is None:
                raise LockError('Cannot acquire lock for %r' % scanid)
            if newlockid is None:
                raise LockError('Cannot release lock for %r' % scanid)
            raise LockError('Cannot change lock for %r from '
                            '%r to %r' % (scanid, oldlockid, newlockid))
        if "target_info" not in scan:
            target = self.get_scan_target(scanid)
            if target is not None:
                target_info = target.target.infos
                self.db[self.colname_scans].update(
                    {"_id": scanid},
                    {"$set": {"target_info": target_info}},
                )
                scan["target_info"] = target_info
        if scan['lock'] is not None:
            scan['lock'] = bytes(scan['lock'])
        return scan

    def get_scans(self):
        return (x['_id'] for x in
                self.set_limits(
                    self.find(self.colname_scans,
                              fields=["_id"])))

    def _update_scan_target(self, scanid, target):
        return self.db[self.colname_scans].update(
            {"_id": scanid}, {"$set": {"target": target}})

    def incr_scan_results(self, scanid):
        return self.db[self.colname_scans].update(
            {"_id": scanid}, {"$inc": {"results": 1}})

    def _add_master(self, master):
        return self.db[self.colname_masters].insert(master)

    def get_master(self, masterid):
        return self.find_one(self.colname_masters, {"_id": masterid})

    def get_masters(self):
        return (x['_id'] for x in
                self.set_limits(
                    self.find(self.colname_masters,
                              fields=["_id"])))
