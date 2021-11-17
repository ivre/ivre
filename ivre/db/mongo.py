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

"""This sub-module contains functions to interact with the MongoDB
databases.

"""


from collections import OrderedDict
from copy import deepcopy
import datetime
import hashlib
import json
import os
import re
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Pattern, Tuple, Union
from urllib.parse import unquote
import uuid


import bson  # type: ignore
from pymongo.errors import BulkWriteError  # type: ignore
import pymongo  # type: ignore

try:
    import krbV  # type: ignore
except ImportError:
    HAS_KRBV = False
else:
    HAS_KRBV = True


from ivre.active.data import ALIASES_TABLE_ELEMS
from ivre.db import (
    DB,
    DBActive,
    DBNmap,
    DBPassive,
    DBAgent,
    DBView,
    DBFlow,
    DBFlowMeta,
    LockError,
)
from ivre import config, passive, utils, xmlnmap, flow
from ivre.types import Filter, SortKey


class Nmap2Mongo(xmlnmap.Nmap2DB):
    @staticmethod
    def _to_binary(data):
        return bson.Binary(data)


def log_pipeline(pipeline):
    """Simple function to log (when config.DEBUG_DB is set) a MongoDB
    pipeline for the aggregation framework.

    """
    utils.LOGGER.debug("DB: MongoDB aggregation pipeline: %r", pipeline)


class MongoDB(DB):

    schema_migrations_indexes: List[
        Dict[int, Dict[str, List[Tuple[List[SortKey], Dict[str, Any]]]]]
    ] = []
    schema_latest_versions: List[int] = []
    hint_indexes: List[Dict[str, List[SortKey]]] = []
    no_limit = 0

    def __init__(self, url):
        super().__init__()
        self.username = None
        self.password = None
        self.mechanism = None
        if "@" in url.netloc:
            username, self.host = url.netloc.split("@", 1)
            if ":" in username:
                self.username, self.password = (
                    unquote(val) for val in username.split(":", 1)
                )
            elif HAS_KRBV:
                username = unquote(username)
                if username == "GSSAPI":
                    self.username = (
                        krbV.default_context().default_ccache().principal().name
                    )
                    self.mechanism = "GSSAPI"
                else:
                    self.username = username
                    if "@" in username:
                        self.mechanism = "GSSAPI"
            else:
                self.username = username
        else:
            self.host = url.netloc
        if not self.host:
            self.host = None
        self.dbname = url.path.lstrip("/")
        if not self.dbname:
            self.dbname = "ivre"
        params = dict(
            x.split("=", 1) if "=" in x else (x, None)
            for x in url.query.split("&")
            if x
        )
        try:
            self.maxscan = int(params.pop("maxscan", None))
        except TypeError:
            self.maxscan = None
        try:
            self.maxtime = int(params.pop("maxtime", None))
        except TypeError:
            self.maxtime = None
        self.params = params
        self.schema_migrations = []

    def set_limits(self, cur):
        if self.maxscan is not None:
            cur.max_scan(self.maxscan)
        if self.maxtime is not None:
            cur.max_time_ms(self.maxtime)
        return cur

    @classmethod
    def get_hint(cls, spec):
        """Given a query spec, return an appropriate index in a form
        suitable to be passed to Cursor.hint().

        """
        for fieldname, hint in cls.hint_indexes[cls.column_passive].items():
            if fieldname in spec:
                return hint
        return None

    @property
    def db_client(self):
        """The DB connection."""
        try:
            return self._db_client
        except AttributeError:
            self._db_client = pymongo.MongoClient(
                host=self.host,
                read_preference=pymongo.ReadPreference.SECONDARY_PREFERRED,
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
                    self.db.authenticate(self.username, mechanism=self.mechanism)
                else:
                    raise TypeError(
                        "provide either 'password' or 'mechanism'" " with 'username'"
                    )
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
    def find(self):
        """Wrapper around column .find() method, depending on pymongo
        version.

        """
        try:
            return self._find
        except AttributeError:
            if pymongo.version_tuple[0] > 2:

                def _find(colname, *args, **kargs):
                    if "spec" in kargs:
                        kargs["filter"] = kargs.pop("spec")
                    if "fields" in kargs:
                        kargs["projection"] = kargs.pop("fields")
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
                    if "spec_or_id" in kargs:
                        kargs["filter_or_id"] = kargs.pop("spec_or_id")
                    if "fields" in kargs:
                        kargs["projection"] = kargs.pop("fields")
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
        if "fields" in kargs and any(
            fld in kargs["fields"] for fld in self.ipaddr_fields
        ):
            fields = []
            for fld in kargs["fields"]:
                if fld in self.ipaddr_fields:
                    fields.extend(["%s_0" % fld, "%s_1" % fld])
                else:
                    fields.append(fld)
            kargs["fields"] = fields
        if "sort" in kargs and any(
            fld in (field for field, _ in kargs["sort"]) for fld in self.ipaddr_fields
        ):
            sort = []
            for fld, way in kargs["sort"]:
                if fld in self.ipaddr_fields:
                    sort.extend([("%s_0" % fld, way), ("%s_1" % fld, way)])
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
        return [
            val - 0x8000000000000000 for val in struct.unpack("!QQ", utils.ip2bin(addr))
        ]

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
        return json.dumps(cursor.explain(), indent=indent, default=self.serialize)

    def init(self):
        """Initializes the column(s), i.e., drops the column(s) and creates
        the default indexes.

        """
        for colname in self.columns:
            self.db[colname].drop()
        self.create_indexes()

    def create_indexes(self):
        for colnum, indexes in enumerate(self.indexes):
            self.db[self.columns[colnum]].create_indexes(
                [pymongo.IndexModel(idx[0], **idx[1]) for idx in indexes]
            )

    def ensure_indexes(self):
        return self.create_indexes()

    def _migrate_update_record(self, colname, recid, update):
        """Define how an update is handled. Purpose-specific subclasses may
        want to do something special here, e.g., mix with other records.

        """
        return self.db[colname].update({"_id": recid}, update)

    def migrate_schema(self, colnum, version):
        """Process to schema migrations in column `colname` starting
        from `version`.

        """
        failed = 0
        while version in self.schema_migrations[colnum]:
            new_version, migration_function = self.schema_migrations[colnum][version]
            utils.LOGGER.info(
                "Migrating column %d from version %r to %r",
                colnum,
                version,
                new_version,
            )
            # Ensuring new indexes
            new_indexes = (
                self.schema_migrations_indexes[colnum]
                .get(new_version, {})
                .get("ensure", [])
            )
            if new_indexes:
                utils.LOGGER.info(
                    "Creating new indexes...",
                )
                try:
                    self.db[self.columns[colnum]].create_indexes(
                        [pymongo.IndexModel(idx[0], **idx[1]) for idx in new_indexes]
                    )
                except pymongo.errors.OperationFailure:
                    utils.LOGGER.debug(
                        "Cannot create indexes %r", new_indexes, exc_info=True
                    )
                utils.LOGGER.info(
                    "  ... Done.",
                )
            utils.LOGGER.info(
                "Migrating records...",
            )
            updated = False
            # unlimited find()!
            for i, record in enumerate(
                self.find(
                    self.columns[colnum],
                    self.searchversion(version),
                    no_cursor_timeout=True,
                ).batch_size(50000)
            ):
                try:
                    update = migration_function(record)
                    if update is not None:
                        updated = True
                        self._migrate_update_record(
                            self.columns[colnum], record["_id"], update
                        )
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate result %r",
                        record,
                        exc_info=True,
                    )
                    failed += 1
                if (i + 1) % 100000 == 0:
                    utils.LOGGER.info("  %d records migrated", i + 1)
            utils.LOGGER.info(
                "  ... Done.",
            )
            # Checking for required actions on indexes
            utils.LOGGER.info(
                "  Performing other actions on indexes...",
            )
            for action, indexes in (
                self.schema_migrations_indexes[colnum].get(new_version, {}).items()
            ):
                if action == "ensure":
                    continue
                function = getattr(self.db[self.columns[colnum]], "%s_index" % action)
                for idx in indexes:
                    try:
                        function(idx[0], **idx[1])
                    except pymongo.errors.OperationFailure:
                        (utils.LOGGER.warning if updated else utils.LOGGER.debug)(
                            "Cannot %s index %s", action, idx, exc_info=True
                        )
            utils.LOGGER.info(
                "  ... Done.",
            )
            utils.LOGGER.info(
                "Migration of column %d from version %r to %r DONE",
                colnum,
                version,
                new_version,
            )
            version = new_version
        if failed:
            utils.LOGGER.info("Failed to migrate %d documents", failed)

    def cmp_schema_version(self, colnum, document):
        """Returns 0 if the `document`'s schema version matches the code's
        current version for column `colnum`, -1 if it is higher (you
        need to update IVRE), and 1 if it is lower (you need to call
        .migrate_schema()).

        """
        val1 = self.schema_latest_versions[colnum]
        val2 = document.get("schema_version", 0)
        return (val1 > val2) - (val1 < val2)

    def _topvalues(
        self,
        field,
        flt=None,
        topnbr=10,
        sort=None,
        limit=None,
        skip=None,
        least=False,
        aggrflt=None,
        specialproj=None,
        specialflt=None,
        countfield=None,
    ):
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
        for i in range(field.count("."), -1, -1):
            subfield = field.rsplit(".", i)[0]
            if subfield in self.list_fields:
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
        pipeline += [
            {
                "$group": {
                    "_id": "$field",
                    "count": {"$sum": 1 if countfield is None else "$count"},
                }
            }
        ]
        if least:
            pipeline += [{"$sort": {"count": 1}}]
        else:
            pipeline += [{"$sort": {"count": -1}}]
        if topnbr is not None:
            pipeline += [{"$limit": topnbr}]
        return pipeline

    def _distinct_pipeline(
        self, field, flt=None, sort=None, limit=None, skip=None, is_ipfield=False
    ):
        """This method makes use of the aggregation framework to
        produce distinct values for a given field.

        """
        pipeline = []
        if flt:
            pipeline.append({"$match": flt})
        if sort:
            pipeline.append({"$sort": OrderedDict(sort)})
        if skip is not None:
            pipeline += [{"$skip": skip}]
        if limit:
            pipeline += [{"$limit": limit}]
        # hack to allow nested values as field
        # see <http://stackoverflow.com/questions/13708857/
        # mongodb-aggregation-framework-nested-arrays-subtract-expression>
        for i in range(field.count("."), -1, -1):
            subfield = field.rsplit(".", i)[0]
            if subfield in self.list_fields:
                pipeline += [{"$unwind": "$" + subfield}]
        if is_ipfield:
            pipeline.append({"$project": {field: ["$%s_0" % field, "$%s_1" % field]}})
        pipeline.append({"$group": {"_id": "$%s" % field}})
        return pipeline

    def _distinct(self, column, field, flt=None, sort=None, limit=None, skip=None):
        """This method makes use of the aggregation framework to
        produce distinct values for a given field in a given column.

        """
        is_ipfield = field in self.ipaddr_fields
        pipeline = self._distinct_pipeline(
            field, flt=flt, sort=sort, limit=limit, skip=skip, is_ipfield=is_ipfield
        )
        log_pipeline(pipeline)
        cursor = self.set_limits(self.db[column].aggregate(pipeline, cursor={}))
        if is_ipfield:
            return (
                None if res["_id"][0] is None else self.internal2ip(res["_id"])
                for res in cursor
            )
        return (res["_id"] for res in cursor)

    def _features_port_list(self, flt, yieldall, use_service, use_product, use_version):
        pipeline, port, service_base = self._features_port_list_pipeline(
            flt,
            use_service,
            use_product,
            use_version,
        )
        project = [port]
        if use_service:
            project.append("%s.service_name" % service_base)
            if use_product:
                project.append("%s.service_product" % service_base)
                if use_version:
                    project.append("%s.service_version" % service_base)
        project = {"field": project}
        pipeline.extend(
            [
                {"$project": project},
                {"$group": {"_id": "$field"}},
            ]
        )
        if not yieldall:
            # When not using yieldall, we can sort in
            # database.
            pipeline.append({"$sort": OrderedDict([("_id", 1)])})
        log_pipeline(pipeline)
        for rec in self.db[self.columns[self._features_column]].aggregate(
            pipeline, cursor={}
        ):
            yield rec["_id"]

    def _features_port_list_pipeline(self, flt, use_service, use_product, use_version):
        raise NotImplementedError()

    # filters
    flt_empty: Filter = {}

    @staticmethod
    def str2id(string):
        return bson.ObjectId(string)

    @staticmethod
    def str2flt(string):
        return json.loads(string)

    @staticmethod
    def to_binary(data):
        return bson.Binary(data)

    @staticmethod
    def from_binary(data):
        return bytes(data)

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
        if "$and" in cond1:
            cond1k.remove("$and")
            cond["$and"] = cond1["$and"]
        if "$and" in cond2:
            cond2k.remove("$and")
            cond.setdefault("$and", []).extend(cond2["$and"])
        for k in cond1k.difference(cond2k):
            cond[k] = cond1[k]
        for k in cond2k.difference(cond1k):
            cond[k] = cond2[k]
        for k in cond1k.intersection(cond2k):
            if cond1[k] == cond2[k]:
                cond[k] = cond1[k]
            else:
                cond.setdefault("$and", []).extend([{k: cond1[k]}, {k: cond2[k]}])
        return cond

    @staticmethod
    def flt_or(*args):
        return {"$or": list(args)} if len(args) > 1 else args[0]

    @staticmethod
    def _search_field_exists(field):
        return {field: {"$exists": True}}

    @staticmethod
    def searchnonexistent():
        return {"_id": 0}

    @staticmethod
    def searchobjectid(oid, neg=False):
        """Filters records by their ObjectID.  `oid` can be a single or many
        (as a list or any iterable) object ID(s), specified as strings
        or an `ObjectID`s.

        """
        if isinstance(oid, (str, bytes, bson.objectid.ObjectId)):
            oid = [bson.objectid.ObjectId(oid)]
        else:
            oid = [bson.objectid.ObjectId(elt) for elt in oid]
        if len(oid) == 1:
            return {"_id": {"$ne": oid[0]} if neg else oid[0]}
        return {"_id": {"$nin" if neg else "$in": oid}}

    @staticmethod
    def searchversion(version):
        """Filters documents based on their schema's version."""
        return {"schema_version": {"$exists": False} if version is None else version}

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        return cls._searchhost(addr, neg=neg)

    @classmethod
    def _searchhost(cls, addr, neg=False, fieldname="addr"):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).
        fieldname is the internal name of the addr field
        """
        addr = cls.ip2internal(addr)
        addr_0 = "%s_0" % fieldname
        addr_1 = "%s_1" % fieldname
        if neg:
            return {"$or": [{addr_0: {"$ne": addr[0]}}, {addr_1: {"$ne": addr[1]}}]}
        return {addr_0: addr[0], addr_1: addr[1]}

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        if not hosts:
            return cls.flt_empty if neg else cls.searchnonexistent()
        return {
            "$and" if neg else "$or": [cls.searchhost(host, neg=neg) for host in hosts]
        }

    @classmethod
    def searchnet(cls, net, neg=False):
        return cls._searchnet(net, neg=neg)

    @classmethod
    def _searchnet(cls, net, neg=False, fieldname="addr"):
        return cls._searchrange(*utils.net2range(net), neg=neg, fieldname=fieldname)

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        return cls._searchrange(start, stop, neg=neg)

    @classmethod
    def _searchrange(cls, start, stop, neg=False, fieldname="addr"):
        """Filters (if `neg` == True, filters out) one particular IP
        address range.

        """
        start = cls.ip2internal(start)
        stop = cls.ip2internal(stop)
        addr_0 = "%s_0" % fieldname
        addr_1 = "%s_1" % fieldname
        if neg:
            return {
                "$or": [
                    {addr_0: start[0], addr_1: {"$lt": start[1]}},
                    {addr_0: {"$lt": start[0]}},
                    {addr_0: stop[0], addr_1: {"$gt": stop[1]}},
                    {addr_0: {"$gt": stop[0]}},
                ]
            }
        if start[0] == stop[0]:
            return {addr_0: start[0], addr_1: {"$gte": start[1], "$lte": stop[1]}}
        return {
            "$and": [
                {
                    "$or": [
                        {addr_0: start[0], addr_1: {"$gte": start[1]}},
                        {addr_0: {"$gt": start[0]}},
                    ]
                },
                {
                    "$or": [
                        {addr_0: stop[0], addr_1: {"$lte": stop[1]}},
                        {addr_0: {"$lt": stop[0]}},
                    ]
                },
            ]
        }

    @staticmethod
    def searchval(key, val):
        return {key: val}

    @staticmethod
    def searchcmp(key, val, cmpop):
        if cmpop == "<":
            return {key: {"$lt": val}}
        if cmpop == "<=":
            return {key: {"$lte": val}}
        if cmpop == ">":
            return {key: {"$gt": val}}
        if cmpop == ">=":
            return {key: {"$gte": val}}
        if cmpop in {"=", "=="}:
            return {key: val}
        if cmpop == "!=":
            return {key: {"$ne": val}}
        raise Exception(
            "Unknown operator %r (for key %r and val %r)"
            % (
                cmpop,
                key,
                val,
            )
        )


class MongoDBActive(MongoDB, DBActive):

    column_hosts = 0
    _features_column = 0
    indexes = [
        # hosts
        [
            ([("scanid", pymongo.ASCENDING)], {}),
            ([("schema_version", pymongo.ASCENDING)], {}),
            (
                [
                    ("addr_0", pymongo.ASCENDING),
                    ("addr_1", pymongo.ASCENDING),
                ],
                {},
            ),
            ([("addresses.mac", pymongo.ASCENDING)], {"sparse": True}),
            ([("starttime", pymongo.ASCENDING)], {}),
            ([("endtime", pymongo.ASCENDING)], {}),
            ([("source", pymongo.ASCENDING)], {}),
            (
                [
                    ("categories", pymongo.ASCENDING),
                    ("addr_0", pymongo.ASCENDING),
                    ("addr_1", pymongo.ASCENDING),
                ],
                {},
            ),
            ([("synack_honeypot", pymongo.ASCENDING)], {"sparse": True}),
            ([("hostnames.domains", pymongo.ASCENDING)], {}),
            ([("traces.hops.domains", pymongo.ASCENDING)], {}),
            ([("openports.count", pymongo.ASCENDING)], {}),
            ([("openports.tcp.ports", pymongo.ASCENDING)], {}),
            ([("openports.tcp.count", pymongo.ASCENDING)], {"sparse": True}),
            ([("openports.udp.ports", pymongo.ASCENDING)], {}),
            ([("openports.udp.count", pymongo.ASCENDING)], {"sparse": True}),
            ([("ports.port", pymongo.ASCENDING)], {}),
            ([("ports.state_state", pymongo.ASCENDING)], {}),
            (
                [
                    ("ports.service_name", pymongo.ASCENDING),
                    ("ports.service_product", pymongo.ASCENDING),
                    ("ports.service_version", pymongo.ASCENDING),
                ],
                {},
            ),
            ([("ports.scripts.id", pymongo.ASCENDING)], {}),
            (
                [
                    ("ports.scripts.http-headers.name", pymongo.ASCENDING),
                    ("ports.scripts.http-headers.value", pymongo.ASCENDING),
                ],
                {"sparse": True},
            ),
            (
                [
                    ("ports.scripts.http-app.application", pymongo.ASCENDING),
                    ("ports.scripts.http-app.version", pymongo.ASCENDING),
                ],
                {"sparse": True},
            ),
            (
                [("ports.scripts.dns-domains.parents", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ls.volumes.volume", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ls.volumes.files.filename", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ssl-cert.self_signed", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            ([("ports.scripts.ssl-cert.san", pymongo.ASCENDING)], {"sparse": True}),
            (
                [("ports.scripts.ssl-cert.subject_text", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ssl-cert.issuer_text", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ssl-cert.issuer.commonName", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [
                    ("ports.scripts.ssl-cert.issuer.countryName", pymongo.ASCENDING),
                    (
                        "ports.scripts.ssl-cert.issuer.stateOrProvinceName",
                        pymongo.ASCENDING,
                    ),
                    ("ports.scripts.ssl-cert.issuer.localityName", pymongo.ASCENDING),
                    (
                        "ports.scripts.ssl-cert.issuer.organizationName",
                        pymongo.ASCENDING,
                    ),
                    (
                        "ports.scripts.ssl-cert.issuer.organizationalUnitName",
                        pymongo.ASCENDING,
                    ),
                ],
                {
                    "sparse": True,
                    "name": "ivre.hosts.$ports.scripts.ssl-cert.issuer.fields_1",
                },
            ),
            (
                [("ports.scripts.ssl-cert.subject.commonName", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [
                    ("ports.scripts.ssl-cert.subject.countryName", pymongo.ASCENDING),
                    (
                        "ports.scripts.ssl-cert.subject.stateOrProvinceName",
                        pymongo.ASCENDING,
                    ),
                    ("ports.scripts.ssl-cert.subject.localityName", pymongo.ASCENDING),
                    (
                        "ports.scripts.ssl-cert.subject.organizationName",
                        pymongo.ASCENDING,
                    ),
                    (
                        "ports.scripts.ssl-cert.subject.organizationalUnitName",
                        pymongo.ASCENDING,
                    ),
                ],
                {
                    "sparse": True,
                    "name": "ivre.hosts.$ports.scripts.ssl-cert.subject.fields_1",
                },
            ),
            ([("ports.scripts.ssl-cert.md5", pymongo.ASCENDING)], {"sparse": True}),
            ([("ports.scripts.ssl-cert.sha1", pymongo.ASCENDING)], {"sparse": True}),
            ([("ports.scripts.ssl-cert.sha256", pymongo.ASCENDING)], {"sparse": True}),
            (
                [("ports.scripts.ssl-cert.pubkey.md5", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ssl-cert.pubkey.sha1", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ssl-cert.pubkey.sha256", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [
                    ("ports.scripts.vulns.id", pymongo.ASCENDING),
                    ("ports.scripts.vulns.state", pymongo.ASCENDING),
                ],
                {"sparse": True},
            ),
            ([("ports.scripts.vulns.state", pymongo.ASCENDING)], {"sparse": True}),
            (
                [
                    ("ports.screenshot", pymongo.ASCENDING),
                    ("ports.screenwords", pymongo.ASCENDING),
                ],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ntlm-info.NetBIOS_Domain", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            (
                [("ports.scripts.ntlm-info.Product_Version", pymongo.ASCENDING)],
                {"sparse": True},
            ),
            ([("infos.as_num", pymongo.ASCENDING)], {}),
            (
                [
                    ("traces.hops.ipaddr_0", pymongo.ASCENDING),
                    ("traces.hops.ipaddr_1", pymongo.ASCENDING),
                    ("traces.hops.ttl", pymongo.ASCENDING),
                ],
                {},
            ),
            (
                [
                    ("infos.country_code", pymongo.ASCENDING),
                    ("infos.city", pymongo.ASCENDING),
                ],
                {},
            ),
            ([("infos.loc", pymongo.GEOSPHERE)], {}),
            (
                [
                    ("cpes.type", pymongo.ASCENDING),
                    ("cpes.vendor", pymongo.ASCENDING),
                    ("cpes.product", pymongo.ASCENDING),
                    ("cpes.version", pymongo.ASCENDING),
                ],
                {"sparse": True},
            ),
        ],
    ]
    schema_migrations_indexes = [
        # hosts
        {
            1: {
                "ensure": [
                    (
                        [
                            ("ports.screenshot", pymongo.ASCENDING),
                            ("ports.screenwords", pymongo.ASCENDING),
                        ],
                        {"sparse": True},
                    ),
                    ([("schema_version", pymongo.ASCENDING)], {}),
                    ([("openports.count", pymongo.ASCENDING)], {}),
                    ([("openports.tcp.ports", pymongo.ASCENDING)], {}),
                    ([("openports.udp.ports", pymongo.ASCENDING)], {}),
                    ([("openports.tcp.count", pymongo.ASCENDING)], {"sparse": True}),
                    ([("openports.udp.count", pymongo.ASCENDING)], {"sparse": True}),
                ]
            },
            3: {
                "ensure": [
                    (
                        [("ports.scripts.ls.volumes.volume", pymongo.ASCENDING)],
                        {"sparse": True},
                    ),
                    (
                        [
                            (
                                "ports.scripts.ls.volumes.files.filename",
                                pymongo.ASCENDING,
                            )
                        ],
                        {"sparse": True},
                    ),
                    # Let's skip these ones since we are going to drop
                    # them right after that.
                    # ([('scripts.ls.volumes.volume', pymongo.ASCENDING)],
                    #  {"sparse": True}),
                    # ([('scripts.ls.volumes.files.filename', pymongo.ASCENDING)],
                    #  {"sparse": True}),
                ]
            },
            4: {
                "drop": [
                    ([("scripts.id", pymongo.ASCENDING)], {}),
                    ([("scripts.ls.volumes.volume", pymongo.ASCENDING)], {}),
                    ([("scripts.ls.volumes.files.filename", pymongo.ASCENDING)], {}),
                ]
            },
            6: {
                "ensure": [
                    (
                        [("ports.scripts.vulns.state", pymongo.ASCENDING)],
                        {"sparse": True},
                    ),
                ]
            },
            11: {
                "drop": [
                    ([("addr", pymongo.ASCENDING)], {}),
                    (
                        [
                            ("traces.hops.ipaddr", pymongo.ASCENDING),
                            ("traces.hops.ttl", pymongo.ASCENDING),
                        ],
                        {},
                    ),
                ],
                "ensure": [
                    (
                        [
                            ("addr_0", pymongo.ASCENDING),
                            ("addr_1", pymongo.ASCENDING),
                        ],
                        {},
                    ),
                    (
                        [
                            ("traces.hops.ipaddr_0", pymongo.ASCENDING),
                            ("traces.hops.ipaddr_1", pymongo.ASCENDING),
                            ("traces.hops.ttl", pymongo.ASCENDING),
                        ],
                        {},
                    ),
                ],
            },
            17: {
                "drop": [
                    ([("categories", pymongo.ASCENDING)], {}),
                    ([("ports.service_name", pymongo.ASCENDING)], {}),
                ],
                "ensure": [
                    (
                        [
                            ("categories", pymongo.ASCENDING),
                            ("addr_0", pymongo.ASCENDING),
                            ("addr_1", pymongo.ASCENDING),
                        ],
                        {},
                    ),
                    (
                        [
                            ("ports.service_name", pymongo.ASCENDING),
                            ("ports.service_product", pymongo.ASCENDING),
                            ("ports.service_version", pymongo.ASCENDING),
                        ],
                        {},
                    ),
                    (
                        [("ports.scripts.ssl-cert.self_signed", pymongo.ASCENDING)],
                        {"sparse": True},
                    ),
                    (
                        [("ports.scripts.ssl-cert.san", pymongo.ASCENDING)],
                        {"sparse": True},
                    ),
                    (
                        [
                            (
                                "ports.scripts.ssl-cert.issuer.commonName",
                                pymongo.ASCENDING,
                            )
                        ],
                        {"sparse": True},
                    ),
                    (
                        [
                            (
                                "ports.scripts.ssl-cert.issuer.countryName",
                                pymongo.ASCENDING,
                            ),
                            (
                                "ports.scripts.ssl-cert.issuer.stateOrProvinceName",
                                pymongo.ASCENDING,
                            ),
                            (
                                "ports.scripts.ssl-cert.issuer.localityName",
                                pymongo.ASCENDING,
                            ),
                            (
                                "ports.scripts.ssl-cert.issuer.organizationName",
                                pymongo.ASCENDING,
                            ),
                            (
                                "ports.scripts.ssl-cert.issuer.organizationalUnitName",
                                pymongo.ASCENDING,
                            ),
                        ],
                        {
                            "sparse": True,
                            "name": "ivre.hosts.$ports.scripts.ssl-cert.issuer.fields_1",
                        },
                    ),
                    (
                        [
                            (
                                "ports.scripts.ssl-cert.subject.commonName",
                                pymongo.ASCENDING,
                            )
                        ],
                        {"sparse": True},
                    ),
                    (
                        [
                            (
                                "ports.scripts.ssl-cert.subject.countryName",
                                pymongo.ASCENDING,
                            ),
                            (
                                "ports.scripts.ssl-cert.subject.stateOrProvinceName",
                                pymongo.ASCENDING,
                            ),
                            (
                                "ports.scripts.ssl-cert.subject.localityName",
                                pymongo.ASCENDING,
                            ),
                            (
                                "ports.scripts.ssl-cert.subject.organizationName",
                                pymongo.ASCENDING,
                            ),
                            (
                                "ports.scripts.ssl-cert.subject.organizationalUnitName",
                                pymongo.ASCENDING,
                            ),
                        ],
                        {
                            "sparse": True,
                            "name": "ivre.hosts.$ports.scripts.ssl-cert.subject.fields_1",
                        },
                    ),
                    (
                        [("ports.scripts.ssl-cert.pubkey.md5", pymongo.ASCENDING)],
                        {"sparse": True},
                    ),
                    (
                        [("ports.scripts.ssl-cert.pubkey.sha1", pymongo.ASCENDING)],
                        {"sparse": True},
                    ),
                    (
                        [("ports.scripts.ssl-cert.pubkey.sha256", pymongo.ASCENDING)],
                        {"sparse": True},
                    ),
                ],
            },
            19: {
                "ensure": [
                    (
                        [("ports.scripts.ntlm-info.NetBIOS_Domain", pymongo.ASCENDING)],
                        {"sparse": True},
                    ),
                    (
                        [
                            (
                                "ports.scripts.ntlm-info.Product_Version",
                                pymongo.ASCENDING,
                            )
                        ],
                        {"sparse": True},
                    ),
                ]
            },
        },
    ]
    schema_latest_versions = [
        # hosts
        xmlnmap.SCHEMA_VERSION,
    ]

    def __init__(self, url):
        super().__init__(url)
        self.schema_migrations = [
            # hosts
            {
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
                11: (12, self.migrate_schema_hosts_11_12),
                12: (13, self.migrate_schema_hosts_12_13),
                13: (14, self.migrate_schema_hosts_13_14),
                14: (15, self.migrate_schema_hosts_14_15),
                15: (16, self.migrate_schema_hosts_15_16),
                16: (17, self.migrate_schema_hosts_16_17),
                17: (18, self.migrate_schema_hosts_17_18),
                18: (19, self.migrate_schema_hosts_18_19),
            },
        ]

    def cmp_schema_version_host(self, host):
        """Returns 0 if the `host`'s schema version matches the code's
        current version, -1 if it is higher (you need to update IVRE),
        and 1 if it is lower (you need to call .migrate_schema()).

        """
        return self.cmp_schema_version(self.column_hosts, host)

    def migrate_schema(self, version):
        """Process to schema migrations in column hosts starting from
        `version`.

        """
        MongoDB.migrate_schema(self, self.column_hosts, version)

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
            if port.get("state_state") == "open":
                openports.setdefault(port["protocol"], {}).setdefault(
                    "ports", []
                ).append(port["port"])
            # create the screenwords attribute
            if "screenshot" in port and "screenwords" not in port:
                screenwords = utils.screenwords(cls.getscreenshot(port))
                if screenwords is not None:
                    port["screenwords"] = screenwords
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
                    if key.startswith("service_"):
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
        migrate_scripts = set(["afp-ls", "nfs-ls", "smb-ls", "ftp-anon", "http-ls"])
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] in migrate_scripts:
                    if script["id"] in script:
                        script["ls"] = xmlnmap.change_ls(script.pop(script["id"]))
                        updated_ports = True
                    elif "ls" not in script:
                        data = xmlnmap.add_ls_data(script)
                        if data is not None:
                            script["ls"] = data
                            updated_ports = True
        for script in doc.get("scripts", []):
            if script["id"] in migrate_scripts:
                data = xmlnmap.add_ls_data(script)
                if data is not None:
                    script["ls"] = data
                    updated_scripts = True
        if updated_ports:
            update["$set"]["ports"] = doc["ports"]
        if updated_scripts:
            update["$set"]["scripts"] = doc["scripts"]
        return update

    @staticmethod
    def migrate_schema_hosts_3_4(doc):
        """Converts a record from version 3 to version 4. Version 4
        creates a "fake" port entry to store host scripts.

        """
        assert doc["schema_version"] == 3
        update = {"$set": {"schema_version": 4}}
        if "scripts" in doc:
            doc.setdefault("ports", []).append(
                {
                    "port": "host",
                    "scripts": doc.pop("scripts"),
                }
            )
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
        for port in doc.get("ports", []):
            if port["port"] == "host":
                port["port"] = -1
                updated_ports = True
        if updated_ports:
            update["$set"]["ports"] = doc["ports"]
        for state, (total, counts) in list(doc.get("extraports", {}).items()):
            doc["extraports"][state] = {"total": total, "reasons": counts}
            updated_extraports = True
        if updated_extraports:
            update["$set"]["extraports"] = doc["extraports"]
        return update

    @staticmethod
    def migrate_schema_hosts_5_6(doc):
        """Converts a record from version 5 to version 6. Version 6 uses Nmap
        structured data for scripts using the vulns NSE library.

        """
        assert doc["schema_version"] == 5
        update = {"$set": {"schema_version": 6}}
        updated = False
        migrate_scripts = set(
            script for script, alias in ALIASES_TABLE_ELEMS.items() if alias == "vulns"
        )
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] in migrate_scripts:
                    table = None
                    if script["id"] in script:
                        table = script.pop(script["id"])
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
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_6_7(doc):
        """Converts a record from version 6 to version 7. Version 7 creates a
        structured output for mongodb-databases script.

        """
        assert doc["schema_version"] == 6
        update = {"$set": {"schema_version": 7}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "mongodb-databases":
                    if "mongodb-databases" not in script:
                        data = xmlnmap.add_mongodb_databases_data(script)
                        if data is not None:
                            script["mongodb-databases"] = data
                            updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_7_8(doc):
        """Converts a record from version 7 to version 8. Version 8 fixes the
        structured output for scripts using the vulns NSE library.

        """
        assert doc["schema_version"] == 7
        update = {"$set": {"schema_version": 8}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if "vulns" in script:
                    if any(
                        elt in script["vulns"]
                        for elt in ["ids", "refs", "description", "state", "title"]
                    ):
                        script["vulns"] = [script["vulns"]]
                    else:
                        script["vulns"] = [
                            dict(tab, id=vulnid)
                            for vulnid, tab in script["vulns"].items()
                        ]
                    updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_8_9(doc):
        """Converts a record from version 8 to version 9. Version 9 creates a
        structured output for http-headers script.

        """
        assert doc["schema_version"] == 8
        update = {"$set": {"schema_version": 9}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "http-headers":
                    if "http-headers" not in script:
                        data = xmlnmap.add_http_headers_data(script)
                        if data is not None:
                            script["http-headers"] = data
                            updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_9_10(doc):
        """Converts a record from version 9 to version 10. Version 10 changes
        the field names of the structured output for s7-info script.

        """
        assert doc["schema_version"] == 9
        update = {"$set": {"schema_version": 10}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "s7-info":
                    if "s7-info" in script:
                        xmlnmap.change_s7_info_keys(script["s7-info"])
                        updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
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
            addr = convert(doc["addr"])
        except (KeyError, ValueError):
            pass
        else:
            update["$unset"] = {"addr": ""}
            update["$set"]["addr_0"], update["$set"]["addr_1"] = addr
        updated = False
        for port in doc.get("ports", []):
            if "state_reason_ip" in port:
                try:
                    ipaddr = convert(port["state_reason_ip"])
                except ValueError:
                    pass
                else:
                    del port["state_reason_ip"]
                    (port["state_reason_ip_0"], port["state_reason_ip_1"]) = ipaddr
                    updated = True
            for script in port.get("scripts", []):
                if script["id"] == "ssl-cert":
                    if "pem" in script["ssl-cert"]:
                        data = "".join(
                            script["ssl-cert"]["pem"].splitlines()[1:-1]
                        ).encode()
                        try:
                            (
                                script["output"],
                                script["ssl-cert"],
                            ) = xmlnmap.create_ssl_cert(data)
                        except Exception:
                            utils.LOGGER.warning(
                                "Cannot parse certificate %r", data, exc_info=True
                            )
                        else:
                            updated = True
                            continue
                    try:
                        algo = script["ssl-cert"].pop("pubkeyalgo")
                    except KeyError:
                        pass
                    else:
                        script["pubkey"] = {
                            "type": utils.PUBKEY_TYPES.get(algo, algo),
                        }
                        updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        updated = False
        for trace in doc.get("traces", []):
            for hop in trace.get("hops", []):
                if "ipaddr" in hop:
                    try:
                        ipaddr = convert(hop["ipaddr"])
                    except ValueError:
                        pass
                    else:
                        del hop["ipaddr"]
                        hop["ipaddr_0"], hop["ipaddr_1"] = ipaddr
                        updated = True
        if updated:
            update["$set"]["traces"] = doc["traces"]
        return update

    @staticmethod
    def migrate_schema_hosts_11_12(doc):
        """Converts a record from version 11 to version 12. Version 12 changes
        the structured output for fcrdns and rpcinfo script.

        """
        assert doc["schema_version"] == 11
        update = {"$set": {"schema_version": 12}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "fcrdns":
                    if "fcrdns" in script:
                        script["fcrdns"] = xmlnmap.change_fcrdns_migrate(
                            script["fcrdns"]
                        )
                        updated = True
                elif script["id"] == "rpcinfo":
                    if "rpcinfo" in script:
                        script["rpcinfo"] = xmlnmap.change_rpcinfo(script["rpcinfo"])
                        updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_12_13(doc):
        """Converts a record from version 12 to version 13. Version 13 changes
        the structured output for ms-sql-info and smb-enum-shares scripts.

        """
        assert doc["schema_version"] == 12
        update = {"$set": {"schema_version": 13}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ms-sql-info":
                    if "ms-sql-info" in script:
                        script["ms-sql-info"] = xmlnmap.change_ms_sql_info(
                            script["ms-sql-info"]
                        )
                        updated = True
                elif script["id"] == "smb-enum-shares":
                    if "smb-enum-shares" in script:
                        script["smb-enum-shares"] = xmlnmap.change_smb_enum_shares(
                            script["smb-enum-shares"]
                        )
                        updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_13_14(doc):
        """Converts a record from version 13 to version 14. Version 14 changes
        the structured output for ssh-hostkey and ls scripts to prevent a same
        field from having different data types.

        """
        assert doc["schema_version"] == 13
        update = {"$set": {"schema_version": 14}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ssh-hostkey" and "ssh-hostkey" in script:
                    script["ssh-hostkey"] = xmlnmap.change_ssh_hostkey(
                        script["ssh-hostkey"]
                    )
                    updated = True
                elif ALIASES_TABLE_ELEMS.get(script["id"]) == "ls" and "ls" in script:
                    script["ls"] = xmlnmap.change_ls_migrate(script["ls"])
                    updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_14_15(doc):
        """Converts a record from version 14 to version 15. Version 15 changes
        the structured output for http-git script to move data to values
        instead of keys.

        """
        assert doc["schema_version"] == 14
        update = {"$set": {"schema_version": 15}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "http-git" and "http-git" in script:
                    script["http-git"] = xmlnmap.change_ssh_hostkey(script["http-git"])
                    updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_15_16(doc):
        """Converts a record from version 15 to version 16. Version 16 uses a
        consistent structured output for Nmap http-server-header script (old
        versions reported `{"Server": "value"}`, while recent versions report
        `["value"]`).

        """
        assert doc["schema_version"] == 15
        update = {"$set": {"schema_version": 16}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "http-server-header":
                    if "http-server-header" in script:
                        data = script["http-server-header"]
                        if isinstance(data, dict):
                            if "Server" in data:
                                script["http-server-header"] = [data["Server"]]
                            else:
                                script["http-server-header"] = []
                            updated = True
                    else:
                        script["http-server-header"] = [
                            line.split(":", 1)[1].lstrip()
                            for line in (
                                line.strip() for line in script["output"].splitlines()
                            )
                            if line.startswith("Server:")
                        ]
                        updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_16_17(doc):
        """Converts a record from version 16 to version 17. Version 17 uses a
        list for ssl-cert output, since several certificates may exist on a
        single port.

        The parsing has been improved and more data gets stored, so while we
        do this, we use the opportunity to parse the certificate again.

        """
        assert doc["schema_version"] == 16
        update = {"$set": {"schema_version": 17}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ssl-cert" and "ssl-cert" in script:
                    table = script["ssl-cert"]
                    if "pem" in table:
                        data = "".join(table["pem"].splitlines()[1:-1]).encode()
                        try:
                            script["output"], table = xmlnmap.create_ssl_cert(data)
                        except Exception:
                            utils.LOGGER.warning(
                                "Cannot parse certificate %r", data, exc_info=True
                            )
                            table = [table]
                    script["ssl-cert"] = table
                    updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_17_18(doc):
        """Converts a record from version 17 to version 18. Version 18
        introduces HASSH (SSH fingerprint) in ssh2-enum-algos.

        """
        assert doc["schema_version"] == 17
        update = {"$set": {"schema_version": 18}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ssh2-enum-algos" and "ssh2-enum-algos" in script:
                    (
                        script["output"],
                        script["ssh2-enum-algos"],
                    ) = xmlnmap.change_ssh2_enum_algos(
                        script["output"], script["ssh2-enum-algos"]
                    )
                    updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    @staticmethod
    def migrate_schema_hosts_18_19(doc):
        """Converts a record from version 18 to version 19. Version 19
        splits smb-os-discovery scripts into two, a ntlm-info one that contains all
        the information the original smb-os-discovery script got from NTLM, and a
        smb-os-discovery script with only the information regarding SMB

        """
        assert doc["schema_version"] == 18
        update = {"$set": {"schema_version": 19}}
        updated = False
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "smb-os-discovery":
                    smb, ntlm = xmlnmap.split_smb_os_discovery(script)
                    script.update(smb)
                    if ntlm:
                        port["scripts"].append(ntlm)
                    updated = True
                if script["id"].endswith("-ntlm-info"):
                    xmlnmap.post_ntlm_info(script, port, doc)
                    updated = True
        if updated:
            update["$set"]["ports"] = doc["ports"]
        return update

    def _get(self, flt, **kargs):
        """Like .get(), but returns a MongoDB cursor (suitable for use with
        e.g.  .explain()).

        """
        return self._get_cursor(self.columns[self.column_hosts], flt, **kargs)

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
                host["addr"] = self.internal2ip(
                    [host.pop("addr_0"), host.pop("addr_1")]
                )
            except (KeyError, socket.error):
                pass
            for port in host.get("ports", []):
                try:
                    port["state_reason_ip"] = self.internal2ip(
                        [
                            port.pop("state_reason_ip_0"),
                            port.pop("state_reason_ip_1"),
                        ]
                    )
                except (KeyError, socket.error):
                    pass
            for trace in host.get("traces", []):
                for hop in trace.get("hops", []):
                    try:
                        hop["ipaddr"] = self.internal2ip(
                            [hop.pop("ipaddr_0"), hop.pop("ipaddr_1")]
                        )
                    except (KeyError, socket.error):
                        pass
            if "coordinates" in host.get("infos", {}).get("loc", {}):
                host["infos"]["coordinates"] = host["infos"].pop("loc")["coordinates"][
                    ::-1
                ]
            yield host

    @staticmethod
    def getscanids(host):
        scanids = host.get("scanid")
        if scanids is None:
            return []
        if isinstance(scanids, list):
            return scanids
        return [scanids]

    def setscreenshot(self, host, port, data, protocol="tcp", overwrite=False):
        """Sets the content of a port's screenshot."""
        try:
            port = [
                p
                for p in host.get("ports", [])
                if p["port"] == port and p["protocol"] == protocol
            ][0]
        except IndexError:
            raise KeyError("Port %s/%d does not exist" % (protocol, port))
        if "screenshot" in port and not overwrite:
            return
        trim_result = utils.trim_image(data)
        if trim_result is False:
            # Image no longer exists after trim
            port["screenshot"] = "empty"
            self.db[self.columns[self.column_hosts]].update(
                {"_id": host["_id"]}, {"$set": {"ports": host["ports"]}}
            )
            return
        port["screenshot"] = "field"
        if trim_result is not True:
            # Image has been trimmed
            data = trim_result
        port["screendata"] = bson.Binary(data)
        screenwords = utils.screenwords(data)
        if screenwords is not None:
            port["screenwords"] = screenwords
        self.db[self.columns[self.column_hosts]].update(
            {"_id": host["_id"]}, {"$set": {"ports": host["ports"]}}
        )

    def setscreenwords(self, host, port=None, protocol="tcp", overwrite=False):
        """Sets the `screenwords` attribute based on the screenshot
        data.

        """
        if port is None:
            if overwrite:

                def flt_cond(p):
                    return "screenshot" in p

            else:

                def flt_cond(p):
                    return "screenshot" in p and "screenwords" not in p

        else:
            if overwrite:

                def flt_cond(p):
                    return (
                        "screenshot" in p
                        and p.get("port") == port
                        and p.get("protocol") == protocol
                    )

            else:

                def flt_cond(p):
                    return (
                        "screenshot" in p
                        and "screenwords" not in p
                        and p.get("port") == port
                        and p.get("protocol") == protocol
                    )

        updated = False
        for portdoc in host.get("ports", []):
            if not flt_cond(portdoc):
                continue
            screenwords = utils.screenwords(self.getscreenshot(portdoc))
            if screenwords is not None:
                portdoc["screenwords"] = screenwords
                updated = True
        if updated:
            self.db[self.columns[self.column_hosts]].update(
                {"_id": host["_id"]}, {"$set": {"ports": host["ports"]}}
            )

    def removescreenshot(self, host, port=None, protocol="tcp"):
        """Removes screenshots"""
        changed = False
        for p in host.get("ports", []):
            if port is None or (p["port"] == port and p.get("protocol") == protocol):
                if "screenshot" in p:
                    if p["screenshot"] == "field":
                        if "screendata" in p:
                            del p["screendata"]
                    if "screenwords" in p:
                        del p["screenwords"]
                    del p["screenshot"]
                    changed = True
        if changed:
            self.db[self.columns[self.column_hosts]].update(
                {"_id": host["_id"]}, {"$set": {"ports": host["ports"]}}
            )

    def getlocations(self, flt):
        col = self.db[self.columns[self.column_hosts]]
        pipeline = [
            {"$match": self.flt_and(flt, self.searchhaslocation())},
            {"$project": {"_id": 0, "coords": "$infos.loc.coordinates"}},
            {"$group": {"_id": "$coords", "count": {"$sum": 1}}},
        ]
        log_pipeline(pipeline)
        return (
            {"_id": tuple(rec["_id"][::-1]), "count": rec["count"]}
            for rec in col.aggregate(pipeline, cursor={})
        )

    def get_ips_ports(self, flt, limit=None, skip=None):
        cur = self._get(
            flt,
            fields=["addr_0", "addr_1", "ports.port", "ports.state_state"],
            limit=limit or 0,
            skip=skip or 0,
        )
        count = sum(len(host.get("ports", [])) for host in cur)
        cur.rewind()
        return (
            (
                dict(res, addr=self.internal2ip([res["addr_0"], res["addr_1"]]))
                for res in cur
            ),
            count,
        )

    def get_ips(self, flt, limit=None, skip=None):
        cur = self._get(
            flt, fields=["addr_0", "addr_1"], limit=limit or 0, skip=skip or 0
        )
        return (
            (
                dict(res, addr=self.internal2ip([res["addr_0"], res["addr_1"]]))
                for res in cur
            ),
            cur.count(),
        )

    def get_open_port_count(self, flt, limit=None, skip=None):
        cur = self._get(
            flt,
            fields=["addr_0", "addr_1", "starttime", "openports.count"],
            limit=limit or 0,
            skip=skip or 0,
        )
        return (
            (
                dict(res, addr=self.internal2ip([res["addr_0"], res["addr_1"]]))
                for res in cur
            ),
            cur.count(),
        )

    def store_host(self, host):
        host = deepcopy(host)
        # Convert IP addresses to internal DB format
        try:
            host["addr_0"], host["addr_1"] = self.ip2internal(host.pop("addr"))
        except (KeyError, ValueError):
            pass
        for port in host.get("ports", []):
            if "state_reason_ip" in port:
                try:
                    (
                        port["state_reason_ip_0"],
                        port["state_reason_ip_1"],
                    ) = self.ip2internal(port.pop("state_reason_ip"))
                except ValueError:
                    pass
        for trace in host.get("traces", []):
            for hop in trace.get("hops", []):
                if "ipaddr" in hop:
                    try:
                        hop["ipaddr_0"], hop["ipaddr_1"] = self.ip2internal(
                            hop.pop("ipaddr")
                        )
                    except ValueError:
                        pass
        # keep location data in appropriate format for GEOSPHERE index
        if "coordinates" in host.get("infos", {}):
            host["infos"]["loc"] = {
                "type": "Point",
                "coordinates": host["infos"].pop("coordinates")[::-1],
            }
        try:
            ident = self.db[self.columns[self.column_hosts]].insert(host)
        except Exception:
            utils.LOGGER.warning("Cannot insert host %r", host, exc_info=True)
            return None
        utils.LOGGER.debug(
            "HOST STORED: %r in %r", ident, self.columns[self.column_hosts]
        )
        return ident

    def merge_host_docs(self, rec1, rec2):
        """Merge two host records and return the result. Unmergeable /
        hard-to-merge fields are lost (e.g., extraports).

        """
        rec = super().merge_host_docs(rec1, rec2)
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
        """Removes the host from the active column. `host` must be the record
        as returned by `.get()`.

        """
        self.db[self.columns[self.column_hosts]].delete_one({"_id": host["_id"]})

    def remove_many(self, flt):
        """Removes hosts from the active column, based on the filter `flt`."""
        self.db[self.columns[self.column_hosts]].delete_many(flt)

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
            {
                "$redact": {
                    "$cond": {
                        "if": {"$eq": [{"$ifNull": ["$ports", None]}, None]},
                        "then": {
                            "$cond": {
                                "if": {"$eq": ["$state_state", "open"]},
                                "then": "$$KEEP",
                                "else": "$$PRUNE",
                            }
                        },
                        "else": "$$DESCEND",
                    }
                }
            },
            {
                "$project": {
                    "ports": {"$cond": [{"$eq": ["$ports", []]}, [0], "$ports.port"]}
                }
            },
            {"$unwind": "$ports"},
            {
                "$group": {
                    "_id": "$_id",
                    "count": {"$sum": 1},
                    "ports": {"$sum": "$ports"},
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "id": "$_id",
                    "mean": {"$multiply": ["$count", "$ports"]},
                }
            },
        ]
        log_pipeline(aggr)
        return self.db[self.columns[self.column_hosts]].aggregate(aggr, cursor={})

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
            {
                "$redact": {
                    "$cond": {
                        "if": {"$eq": [{"$ifNull": ["$ports", None]}, None]},
                        "then": {
                            "$cond": {
                                "if": {"$eq": ["$state_state", "open"]},
                                "then": "$$KEEP",
                                "else": "$$PRUNE",
                            }
                        },
                        "else": "$$DESCEND",
                    }
                }
            },
            {
                "$project": {
                    "ports": {"$cond": [{"$eq": ["$ports", []]}, [0], "$ports.port"]}
                }
            },
            {"$group": {"_id": "$ports", "ids": {"$addToSet": "$_id"}}},
        ]
        log_pipeline(aggr)
        return self.db[self.columns[self.column_hosts]].aggregate(aggr, cursor={})

    @staticmethod
    def json2dbrec(host):
        for fname in ["starttime", "endtime"]:
            if fname in host:
                host[fname] = datetime.datetime.strptime(
                    host[fname], "%Y-%m-%d %H:%M:%S"
                )
        for port in host.get("ports", []):
            if "screendata" in port:
                port["screendata"] = bson.Binary(
                    utils.decode_b64(port["screendata"].encode())
                )
            for script in port.get("scripts", []):
                if "masscan" in script and "raw" in script["masscan"]:
                    script["masscan"]["raw"] = bson.Binary(
                        utils.decode_b64(script["masscan"]["raw"].encode())
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

    @classmethod
    def searchmac(cls, mac=None, neg=False):
        if mac is not None:
            if isinstance(mac, utils.REGEXP_T):
                mac = re.compile(mac.pattern, mac.flags | re.I)
                if neg:
                    return {"addresses.mac": {"$not": mac}}
                return {"addresses.mac": mac}
            if neg:
                return {"addresses.mac": {"$ne": mac.lower()}}
            return {"addresses.mac": mac.lower()}
        return {"addresses.mac": {"$exists": not neg}}

    @staticmethod
    def searchcategory(cat, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular category
        (records may have zero, one or more categories).
        """
        if neg:
            if isinstance(cat, utils.REGEXP_T):
                return {"categories": {"$not": cat}}
            if isinstance(cat, list):
                if len(cat) == 1:
                    cat = cat[0]
                else:
                    return {"categories": {"$nin": cat}}
            return {"categories": {"$ne": cat}}
        if isinstance(cat, list):
            if len(cat) == 1:
                cat = cat[0]
            else:
                return {"categories": {"$in": cat}}
        return {"categories": cat}

    @staticmethod
    def searchcountry(country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        country = utils.country_unalias(country)
        if isinstance(country, list):
            return {"infos.country_code": {"$nin" if neg else "$in": country}}
        return {"infos.country_code": {"$ne": country} if neg else country}

    @staticmethod
    def searchhaslocation(neg=False):
        return {"infos.loc": {"$exists": not neg}}

    @staticmethod
    def searchcity(city, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular city.
        """
        if neg:
            if isinstance(city, utils.REGEXP_T):
                return {"infos.city": {"$not": city}}
            return {"infos.city": {"$ne": city}}
        return {"infos.city": city}

    @staticmethod
    def searchasnum(asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        if not isinstance(asnum, str) and hasattr(asnum, "__iter__"):
            return {
                "infos.as_num": {"$nin" if neg else "$in": [int(val) for val in asnum]}
            }
        asnum = int(asnum)
        return {"infos.as_num": {"$ne": asnum} if neg else asnum}

    @staticmethod
    def searchasname(asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        if neg:
            if isinstance(asname, utils.REGEXP_T):
                return {"infos.as_name": {"$not": asname}}
            return {"infos.as_name": {"$ne": asname}}
        return {"infos.as_name": asname}

    @staticmethod
    def searchsource(src, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        source.

        """
        if neg:
            if isinstance(src, utils.REGEXP_T):
                return {"source": {"$not": src}}
            if isinstance(src, list):
                if len(src) == 1:
                    src = src[0]
                else:
                    return {"source": {"$nin": src}}
            return {"source": {"$ne": src}}
        if isinstance(src, list):
            if len(src) == 1:
                src = src[0]
            else:
                return {"source": {"$in": src}}
        return {"source": src}

    @staticmethod
    def searchport(port, protocol="tcp", state="open", neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        if port == "host":
            return {"ports.port": {"$gte": 0} if neg else -1}
        if state == "open":
            return {"openports.%s.ports" % protocol: {"$ne": port} if neg else port}
        if neg:
            return {
                "$or": [
                    {
                        "ports": {
                            "$elemMatch": {
                                "port": port,
                                "protocol": protocol,
                                "state_state": {"$ne": state},
                            }
                        }
                    },
                    {"ports.port": {"$ne": port}},
                ]
            }
        return {
            "ports": {
                "$elemMatch": {"port": port, "protocol": protocol, "state_state": state}
            }
        }

    def searchportsother(self, ports, protocol="tcp", state="open"):
        """Filters records with at least one port other than those
        listed in `ports` with state `state`.

        """
        return self.searchport(
            {"$elemMatch": {"$nin": ports}} if state == "open" else {"$nin": ports},
            protocol=protocol,
            state=state,
        )

    def searchports(self, ports, protocol="tcp", state="open", neg=False, any_=False):
        if state == "open" and not neg:
            return self.searchport(
                {"$in" if any_ else "$all": ports},
                state=state,
                protocol=protocol,
            )
        if neg:
            if any_:
                raise ValueError("searchports: cannot set both neg and any_")
            return self.flt_and(
                *(
                    self.searchport(p, protocol=protocol, state=state, neg=True)
                    for p in ports
                )
            )
        if any_:
            return self.searchport(
                {"$in": ports}, protocol=protocol, state=state, neg=neg
            )
        return {
            "ports": {
                "$all": [
                    self.searchport(port, protocol=protocol, state=state, neg=neg)[
                        "ports"
                    ]
                    for port in ports
                ]
            }
        }

    @staticmethod
    def searchcountopenports(minn=None, maxn=None, neg=False):
        "Filters records with open port number between minn and maxn"
        assert minn is not None or maxn is not None
        flt = []
        if minn == maxn:
            return {"openports.count": {"$ne": minn} if neg else minn}
        if minn is not None:
            flt.append({"$lt" if neg else "$gte": minn})
        if maxn is not None:
            flt.append({"$gt" if neg else "$lte": maxn})
        if len(flt) == 1:
            return {"openports.count": flt[0]}
        if neg:
            return {"$or": [{"openports.count": cond} for cond in flt]}
        # return {'openports.count':
        #         dict(item for cond in flt for item in cond.items())}
        return {"openports.count": {"$lte": maxn, "$gte": minn}}

    @staticmethod
    def searchopenport(neg=False):
        "Filters records with at least one open port."
        return {"ports.state_state": {"$nin": ["open"]} if neg else "open"}

    @staticmethod
    def searchservice(srv, port=None, protocol=None):
        """Search an open port with a particular service. False means the
        service is unknown.

        """
        if srv is False:
            srv = {"$exists": False}
        elif isinstance(srv, list):
            srv = {"$in": srv}
        flt = {"service_name": srv}
        if port is not None:
            flt["port"] = port
        if protocol is not None:
            flt["protocol"] = protocol
        if len(flt) == 1:
            return {"ports.service_name": srv}
        return {"ports": {"$elemMatch": flt}}

    @staticmethod
    def searchproduct(
        product=None, version=None, service=None, port=None, protocol=None
    ):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        For product, version and service parameters, False is a
        special value that means "unknown"

        """
        flt = {}
        if product is not None:
            if product is False:
                flt["service_product"] = {"$exists": False}
            elif isinstance(product, list):
                flt["service_product"] = {"$in": product}
            else:
                flt["service_product"] = product
        if version is not None:
            if product is False:
                flt["service_version"] = {"$exists": False}
            elif isinstance(version, list):
                flt["service_version"] = {"$in": version}
            else:
                flt["service_version"] = version
        if service is not None:
            if service is False:
                flt["service_name"] = {"$exists": False}
            elif isinstance(service, list):
                flt["service_name"] = {"$in": service}
            else:
                flt["service_name"] = service
        if port is not None:
            flt["port"] = port
        if protocol is not None:
            flt["protocol"] = protocol
        if len(flt) == 1:
            return {"ports.%s" % key: value for key, value in flt.items()}
        return {"ports": {"$elemMatch": flt}}

    @classmethod
    def searchscript(cls, name=None, output=None, values=None, neg=False):
        """Search a particular content in the scripts results."""
        req = {}
        if isinstance(name, list):
            req["id"] = {"$in": name}
        elif name is not None:
            req["id"] = name
        if output is not None:
            req["output"] = output
        if values:
            if isinstance(name, list):
                all_keys = set(ALIASES_TABLE_ELEMS.get(n, n) for n in name)
                if len(all_keys) != 1:
                    raise TypeError(
                        ".searchscript() needs similar `name` values when using a `values` arg"
                    )
                key = all_keys.pop()
            elif not isinstance(name, str):
                raise TypeError(
                    ".searchscript() needs a `name` arg when using a `values` arg"
                )
            else:
                key = ALIASES_TABLE_ELEMS.get(name, name)
            if isinstance(values, (str, utils.REGEXP_T)):
                req[key] = values
            else:
                if len(values) >= 2 and "ports.scripts.%s" % key in cls.list_fields:
                    req[key] = {"$elemMatch": values}
                else:
                    for field, value in values.items():
                        req["%s.%s" % (key, field)] = value
        if not req:
            return {"ports.scripts": {"$exists": not neg}}
        if len(req) == 1:
            field, value = next(iter(req.items()))
            if neg:
                return {"ports.scripts.%s" % field: {"$ne": value}}
            return {"ports.scripts.%s" % field: value}
        if neg:
            return {"ports.scripts": {"$not": {"$elemMatch": req}}}
        return {"ports.scripts": {"$elemMatch": req}}

    @staticmethod
    def searchsvchostname(hostname):
        return {"ports.service_hostname": hostname}

    @staticmethod
    def searchwebmin():
        return {
            "ports": {
                "$elemMatch": {
                    "service_name": "http",
                    "service_product": "MiniServ",
                    "service_extrainfo": {"$ne": "Webmin httpd"},
                }
            }
        }

    @staticmethod
    def searchx11():
        return {
            "ports": {
                "$elemMatch": {
                    "service_name": "X11",
                    "service_extrainfo": {"$ne": "access denied"},
                }
            }
        }

    def searchfile(self, fname=None, scripts=None):
        """Search shared files from a file name (either a string or a
        regexp), only from scripts using the "ls" NSE module.

        """
        if fname is None:
            fname = {"$exists": True}
        elif isinstance(fname, list):
            fname = {"$in": fname}
        if scripts is None:
            return {"ports.scripts.ls.volumes.files.filename": fname}
        if isinstance(scripts, str):
            scripts = [scripts]
        return {
            "ports.scripts": {
                "$elemMatch": {
                    "id": scripts.pop() if len(scripts) == 1 else {"$in": scripts},
                    "ls.volumes.files.filename": fname,
                }
            }
        }

    def searchsmbshares(self, access="", hidden=None):
        """Filter SMB shares with given `access` (default: either read
        or write, accepted values 'r', 'w', 'rw').

        If `hidden` is set to `True`, look for hidden shares, for
        non-hidden if set to `False` and for both if set to `None`
        (this is the default).

        """
        access = {
            "": re.compile("^(READ|WRITE)"),
            "r": re.compile("^READ(/|$)"),
            "w": re.compile("(^|/)WRITE$"),
            "rw": "READ/WRITE",
            "wr": "READ/WRITE",
        }[access.lower()]
        share_type = {
            # None: re.compile('^STYPE_DISKTREE(_HIDDEN)?$'),
            # None: accept share in unsure
            None: {
                "$nin": [
                    "STYPE_IPC_HIDDEN",
                    "Not a file share",
                    "STYPE_IPC",
                    "STYPE_PRINTQ",
                ]
            },
            True: "STYPE_DISKTREE_HIDDEN",
            False: "STYPE_DISKTREE",
        }[hidden]
        return self.searchscript(
            name="smb-enum-shares",
            values={
                "shares": {
                    "$elemMatch": {
                        "$or": [
                            {"%s access" % user: access}
                            for user in ["Anonymous", "Current user"]
                        ],
                        "Type": share_type,
                        "Share": {"$ne": "IPC$"},
                    }
                }
            },
        )

    def searchhttptitle(self, title):
        return self.searchscript(
            name=["http-title", "html-title"],
            output=title,
        )

    @staticmethod
    def searchos(txt):
        return {
            "$or": [
                {"os.osclass.vendor": txt},
                {"os.osclass.osfamily": txt},
                {"os.osclass.osgen": txt},
                {"os.osclass.type": txt},
            ]
        }

    @staticmethod
    def searchvsftpdbackdoor():
        return {
            "ports": {
                "$elemMatch": {
                    "protocol": "tcp",
                    "state_state": "open",
                    "service_product": "vsftpd",
                    "service_version": "2.3.4",
                }
            }
        }

    @staticmethod
    def searchvulnintersil():
        # See MSF modules/auxiliary/admin/http/intersil_pass_reset.rb
        return {
            "ports": {
                "$elemMatch": {
                    "protocol": "tcp",
                    "state_state": "open",
                    "service_product": "Boa HTTPd",
                    "service_version": re.compile(
                        "^0\\.9(3([^0-9]|$)|" "4\\.([0-9]|0[0-9]|" "1[0-1])([^0-9]|$))"
                    ),
                }
            }
        }

    @staticmethod
    def searchdevicetype(devtype):
        return {"ports.service_devicetype": devtype}

    def searchnetdev(self):
        return self.searchdevicetype(
            {
                "$in": [
                    "bridge",
                    "broadband router",
                    "firewall",
                    "hub",
                    "load balancer",
                    "proxy server",
                    "router",
                    "switch",
                    "WAP",
                ]
            }
        )

    def searchphonedev(self):
        return self.searchdevicetype(
            {
                "$in": [
                    "PBX",
                    "phone",
                    "telecom-misc",
                    "VoIP adapter",
                    "VoIP phone",
                ]
            }
        )

    @staticmethod
    def searchldapanon():
        return {"ports.service_extrainfo": "Anonymous bind OK"}

    @staticmethod
    def searchvuln(vulnid=None, state=None):
        if state is None:
            return {
                "ports.scripts.vulns.id": {"$exists": True}
                if vulnid is None
                else vulnid
            }
        if vulnid is None:
            return {"ports.scripts.vulns.state": state}
        return {"ports.scripts.vulns": {"$elemMatch": {"id": vulnid, "status": state}}}

    @staticmethod
    def searchtimeago(delta, neg=False):
        if not isinstance(delta, datetime.timedelta):
            delta = datetime.timedelta(seconds=delta)
        return {"endtime": {"$lt" if neg else "$gte": datetime.datetime.now() - delta}}

    def searchtimerange(self, start, stop, neg=False):
        if not isinstance(start, datetime.datetime):
            start = datetime.datetime.fromtimestamp(start)
        if not isinstance(stop, datetime.datetime):
            stop = datetime.datetime.fromtimestamp(stop)
        if neg:
            return self.flt_or(
                {"endtime": {"$lt": start}}, {"starttime": {"$gt": stop}}
            )
        return {"endtime": {"$gte": start}, "starttime": {"$lte": stop}}

    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        try:
            hop = cls.ip2internal(hop)
        except ValueError:
            pass
        if ttl is None:
            flt = {
                "traces.hops": {"$elemMatch": {"ipaddr_0": hop[0], "ipaddr_1": hop[1]}}
            }
            return {"$not": flt} if neg else flt
        if neg:
            return {
                "$or": [
                    {
                        "traces.hops": {
                            "$elemMatch": {
                                "ttl": ttl,
                                "$or": [
                                    {"ipaddr_0": {"$ne": hop[0]}},
                                    {"ipaddr_1": {"$ne": hop[1]}},
                                ],
                            }
                        }
                    },
                    {"traces.hops.ttl": {"$ne": ttl}},
                ]
            }
        return {
            "traces.hops": {
                "$elemMatch": {"ipaddr_0": hop[0], "ipaddr_1": hop[1], "ttl": ttl}
            }
        }

    @staticmethod
    def searchhopdomain(hop, neg=False):
        if neg:
            if isinstance(hop, utils.REGEXP_T):
                return {"traces.hops.domains": {"$not": hop}}
            return {"traces.hops.domains": {"$ne": hop}}
        return {"traces.hops.domains": hop}

    def searchhopname(self, hop, neg=False):
        if neg:
            if isinstance(hop, utils.REGEXP_T):
                return {"traces.hops.host": {"$not": hop}}
            return {"traces.hops.host": {"$ne": hop}}
        return self.flt_and(
            # This is indexed
            self.searchhopdomain(hop, neg=neg),
            # This is not
            {"traces.hops.host": hop},
        )

    @staticmethod
    def searchscreenshot(
        port: Optional[int] = None,
        protocol: str = "tcp",
        service: Optional[str] = None,
        words: Optional[Union[bool, str, Pattern[str], List[str]]] = None,
        neg: bool = False,
    ) -> Filter:
        """Filter results with (without, when `neg == True`) a
        screenshot (on a specific `port` if specified).

        `words` can be specified as a string, a regular expression, a
        boolean, or as a list and is/are matched against the OCR
        results. When `words` is specified and `neg == True`, the
        result will filter results **with** a screenshot **without**
        the word(s) in the OCR results.

        """
        result: Filter = {"ports": {"$elemMatch": {}}}
        if words is None:
            if port is None and service is None:
                return {"ports.screenshot": {"$exists": not neg}}
            result["ports"]["$elemMatch"]["screenshot"] = {"$exists": not neg}
        else:
            words_f: Filter
            result["ports"]["$elemMatch"]["screenshot"] = {"$exists": True}
            if isinstance(words, list):
                words_f = {"$ne" if neg else "$all": [w.lower() for w in words]}
            elif isinstance(words, Pattern):
                words = re.compile(words.pattern.lower(), flags=words.flags)
                words_f = {"$not": words} if neg else words
            elif isinstance(words, bool):
                words_f = {"$exists": words}
            else:
                words = words.lower()
                words_f = {"$ne": words} if neg else words
            result["ports"]["$elemMatch"]["screenwords"] = words_f
        if port is not None:
            result["ports"]["$elemMatch"]["port"] = port
            result["ports"]["$elemMatch"]["protocol"] = protocol
        if service is not None:
            result["ports"]["$elemMatch"]["service_name"] = service
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
        flt = dict((field, value) for field, value in fields if value is not None)
        nflt = len(flt)
        if nflt == 0:
            return {"cpes": {"$exists": True}}
        if nflt == 1:
            field, value = flt.popitem()
            return {"cpes.%s" % field: value}
        return {"cpes": {"$elemMatch": flt}}

    def topvalues(
        self,
        field,
        flt=None,
        topnbr=10,
        sort=None,
        limit=None,
        skip=None,
        least=False,
        aggrflt=None,
        specialproj=None,
        specialflt=None,
    ):
        """
        This method makes use of the aggregation framework to produce
        top values for a given field or pseudo-field. Pseudo-fields are:
          - category[:regexp] / asnum / country / net[:mask]
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
          - httpapp / httpapp:<name>
          - modbus.* / s7.* / enip.*
          - mongo.dbs.*
          - vulns.*
          - screenwords
          - file.* / file.*:scriptid
          - hop
          - scanner.name / scanner.port:tcp / scanner.port:udp
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
        elif field.startswith("category:") or field.startswith("categories:"):
            subflt = utils.str2regexp(field.split(":", 1)[1])
            catflt = self.searchcategory(subflt)
            flt = self.flt_and(flt, catflt)
            specialflt = [{"$match": catflt}]
            field = "categories"
        elif field == "country":
            flt = self.flt_and(flt, {"infos.country_code": {"$exists": True}})
            field = "country"
            specialproj = {
                "_id": 0,
                "country": [
                    "$infos.country_code",
                    {"$ifNull": ["$infos.country_name", "?"]},
                ],
            }

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"])}

        elif field == "city":
            flt = self.flt_and(
                flt,
                {"infos.country_code": {"$exists": True}},
                {"infos.city": {"$exists": True}},
            )
            specialproj = {
                "_id": 0,
                "city": [
                    "$infos.country_code",
                    "$infos.city",
                ],
            }

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"])}

        elif field == "asnum":
            flt = self.flt_and(flt, {"infos.as_num": {"$exists": True}})
            field = "infos.as_num"
        elif field == "as":
            flt = self.flt_and(flt, {"infos.as_num": {"$exists": True}})
            specialproj = {
                "_id": 0,
                "as": ["$infos.as_num", "$infos.as_name"],
            }

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": tuple(x["_id"]),
                }

        elif field == "addr":
            specialproj = {
                "_id": 0,
                "addr_0": 1,
                "addr_1": 1,
            }
            specialflt = [{"$project": {field: ["$addr_0", "$addr_1"]}}]

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": self.internal2ip(x["_id"]),
                }

        elif field == "net" or field.startswith("net:"):
            flt = self.flt_and(flt, self.searchipv4())
            mask = int(field.split(":", 1)[1]) if ":" in field else 24
            field = "addr"
            # This should not overflow thanks to .searchipv4() filter
            addr = {"$add": ["$addr_1", 0x7FFF000100000000]}
            specialproj = {
                "_id": 0,
                "addr": {"$floor": {"$divide": [addr, 2 ** (32 - mask)]}},
            }
            flt = self.flt_and(flt, self.searchipv4())

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": "%s/%d"
                    % (
                        utils.int2ip(int(x["_id"]) * 2 ** (32 - mask)),
                        mask,
                    ),
                }

        elif field == "port" or field.startswith("port:"):
            if field == "port":
                info = {"$exists": True}
                flt_field = "ports.state_state"
            else:
                info = field.split(":", 1)[1]
                flt_field = "ports.%s" % (
                    "state_state"
                    if info in ["open", "filtered", "closed"]
                    else "service_name"
                )
            field = "ports.port"
            flt = self.flt_and(flt, {flt_field: info})
            specialproj = {"_id": 0, flt_field: 1, field: 1, "ports.protocol": 1}
            specialflt = [
                {"$match": {flt_field: info}},
                {"$project": {field: ["$ports.protocol", "$ports.port"]}},
            ]

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": tuple(x["_id"]),
                }

        elif field.startswith("portlist:"):
            specialproj = {"ports.port": 1, "ports.protocol": 1, "ports.state_state": 1}
            specialflt = [
                {
                    "$project": {
                        "ports.port": 1,
                        "ports.protocol": 1,
                        "ports.state_state": 1,
                    }
                },
                # if the host has no ports attribute, we create an empty list
                {"$project": {"ports": {"$ifNull": ["$ports", []]}}},
                # We use $redact instead of $match to keep an empty
                # list when no port matches.
                #
                # The first "$cond" help us make the difference
                # between main document ($ports exists in that case)
                # and a nested document ($ports does not exist in that
                # case). The second only keeps ports we are interested in.
                {
                    "$redact": {
                        "$cond": {
                            "if": {"$eq": [{"$ifNull": ["$ports", None]}, None]},
                            "then": {
                                "$cond": {
                                    "if": {
                                        "$eq": ["$state_state", field.split(":", 1)[1]]
                                    },
                                    "then": "$$KEEP",
                                    "else": "$$PRUNE",
                                }
                            },
                            "else": "$$DESCEND",
                        }
                    }
                },
                {"$project": {"ports.port": 1, "ports.protocol": 1}},
                {"$project": {"portlist": "$ports"}},
            ]
            field = "portlist"

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": [(y["protocol"], y["port"]) for y in x["_id"]],
                }

        elif field.startswith("countports:"):
            state = field.split(":", 1)[1]
            if state == "open":
                field = "openports.count"
            else:
                specialproj = {"_id": 0, "ports.state_state": 1}
                specialflt = [
                    {"$project": {"ports": {"$ifNull": ["$ports", []]}}},
                    # See "portlist:".
                    {
                        "$redact": {
                            "$cond": {
                                "if": {"$eq": [{"$ifNull": ["$ports", None]}, None]},
                                "then": {
                                    "$cond": {
                                        "if": {"$eq": ["$state_state", state]},
                                        "then": "$$KEEP",
                                        "else": "$$PRUNE",
                                    }
                                },
                                "else": "$$DESCEND",
                            }
                        }
                    },
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
                {
                    "$project": {
                        "ports.service_name": {"$ifNull": ["$ports.service_name", ""]}
                    }
                },
            ]
            field = "ports.service_name"

            def outputproc(x):
                return {"count": x["count"], "_id": null_if_empty(x["_id"])}

        elif field.startswith("service:"):
            port = int(field[8:])
            flt = self.flt_and(flt, self.searchport(port))
            specialproj = {"_id": 0, "ports.port": 1, "ports.service_name": 1}
            specialflt = [
                {"$match": {"ports.port": port}},
                {
                    "$project": {
                        "ports.service_name": {"$ifNull": ["$ports.service_name", ""]}
                    }
                },
            ]
            field = "ports.service_name"
        elif field == "product":
            flt = self.flt_and(flt, self.searchopenport())
            specialproj = {
                "_id": 0,
                "ports.state_state": 1,
                "ports.service_name": 1,
                "ports.service_product": 1,
            }
            specialflt = [
                {"$match": {"ports.state_state": "open"}},
                {
                    "$project": {
                        "ports.service_product": [
                            "$ports.service_name",
                            "$ports.service_product",
                        ]
                    }
                },
            ]

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": tuple(x["_id"]),
                }

            field = "ports.service_product"
        elif field.startswith("product:"):
            service = field[8:]
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
            specialflt.append(
                {
                    "$project": {
                        "ports.service_product": [
                            "$ports.service_name",
                            "$ports.service_product",
                        ]
                    }
                },
            )

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": tuple(x["_id"]),
                }

            field = "ports.service_product"
        elif field == "version":
            flt = self.flt_and(flt, self.searchopenport())
            specialproj = {
                "_id": 0,
                "ports.state_state": 1,
                "ports.service_name": 1,
                "ports.service_product": 1,
                "ports.service_version": 1,
            }
            specialflt = [
                {"$match": {"ports.state_state": "open"}},
                {
                    "$project": {
                        "ports.service_product": [
                            "$ports.service_name",
                            "$ports.service_product",
                            "$ports.service_version",
                        ]
                    }
                },
            ]

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": tuple(x["_id"]),
                }

            field = "ports.service_product"
        elif field.startswith("version:"):
            service = field[8:]
            if service.isdigit():
                port = int(service)
                flt = self.flt_and(flt, self.searchport(port))
                specialflt = [
                    {"$match": {"ports.port": port}},
                ]
            elif ":" in service:
                service, product = service.split(":", 1)
                flt = self.flt_and(
                    flt,
                    self.searchproduct(
                        product=product,
                        service=service,
                    ),
                )
                specialflt = [
                    {
                        "$match": {
                            "ports.service_name": service,
                            "ports.service_product": product,
                        }
                    },
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
            specialflt.append(
                {
                    "$project": {
                        "ports.service_product": [
                            "$ports.service_name",
                            "$ports.service_product",
                            "$ports.service_version",
                        ]
                    }
                },
            )

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": tuple(x["_id"]),
                }

            field = "ports.service_product"
        elif field.startswith("cpe"):
            try:
                field, cpeflt = field.split(":", 1)
                cpeflt = cpeflt.split(":", 3)
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
            cpeflt1 = self.searchcpe(
                **dict(
                    ("cpe_type" if key == "type" else key, value)
                    for key, value in cpeflt
                )
            )
            cpeflt2 = dict(("cpes.%s" % key, value) for key, value in cpeflt)
            # We need to keep enough cpes.* fields for the projection
            # *and* for our filter
            fields = fields[: max(fields.index(field), len(cpeflt2)) + 1]
            flt = self.flt_and(flt, cpeflt1)
            specialproj = dict((("cpes.%s" % fname, 1) for fname in fields), _id=0)
            concat = ["$cpes.%s" % fields[0]]
            # Now we only keep what the user wanted
            for fname in fields[1 : fields.index(field) + 1]:
                concat.append(":")
                concat.append("$cpes.%s" % fname)
            specialflt = []
            if cpeflt2:
                specialflt.append({"$match": cpeflt2})
            specialflt.append({"$project": {"cpes.%s" % field: {"$concat": concat}}})
            field = "cpes.%s" % field

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"].split(":", 3))}

        elif field == "devicetype":
            field = "ports.service_devicetype"
        elif field.startswith("devicetype:"):
            port = int(field.split(":", 1)[1])
            flt = self.flt_and(flt, self.searchport(port))
            specialproj = {"_id": 0, "ports.port": 1, "ports.service_devicetype": 1}
            specialflt = [
                {"$match": {"ports.port": port}},
                {"$project": {"ports.service_devicetype": 1}},
            ]
            field = "ports.service_devicetype"
        elif field.startswith("smb."):
            flt = self.flt_and(flt, self.searchsmb())
            field = "ports.scripts.smb-os-discovery." + field[4:]
        elif field == "ntlm":
            flt = self.flt_and(flt, self.searchntlm())
            field = "ports.scripts.ntlm-info"
        elif field.startswith("ntlm."):
            arg = field[5:]
            arg = {
                "name": "Target_Name",
                "server": "NetBIOS_Computer_Name",
                "domain": "NetBIOS_Domain_Name",
                "workgroup": "Workgroup",
                "domain_dns": "DNS_Domain_Name",
                "forest": "DNS_Tree_Name",
                "fqdn": "DNS_Computer_Name",
                "os": "Product_Version",
                "version": "NTLM_Version",
            }.get(arg, arg)
            flt = self.flt_and(flt, self.searchntlm())
            field = "ports.scripts.ntlm-info." + arg
        elif field == "script":
            flt = self.flt_and(flt, self.searchscript())
            field = "ports.scripts.id"
        elif field.startswith("script:"):
            scriptid = field.split(":", 1)[1]
            flt = self.flt_and(flt, self.searchscript())
            if ":" in scriptid:
                port, scriptid = scriptid.split(":", 1)
                if port.isdigit():
                    port = int(port)
                flt = self.flt_and(flt, self.searchport(port))
            else:
                port, scriptid = None, field.split(":", 1)[1]
            specialproj = {"_id": 0, "ports.scripts.id": 1, "ports.scripts.output": 1}
            if port is not None:
                specialproj.update({"ports.port": 1})
            specialflt = [
                {
                    "$match": (
                        {"ports.scripts.id": scriptid}
                        if port is None
                        else {"ports.scripts.id": scriptid, "ports.port": port}
                    )
                },
                {"$project": {"ports.scripts.output": 1}},
            ]
            field = "ports.scripts.output"
        elif field == "domains":
            flt = self.flt_and(flt, self.searchdomain({"$exists": True}))
            field = "hostnames.domains"
        elif field.startswith("domains:"):
            flt = self.flt_and(flt, self.searchdomain({"$exists": True}))
            level = int(field[8:]) - 1
            field = "hostnames.domains"
            aggrflt = {"field": re.compile("^([^\\.]+\\.){%d}[^\\.]+$" % level)}
        elif field.startswith("cert."):
            field = "ports.scripts.ssl-cert." + field[5:]
        elif field == "useragent" or field.startswith("useragent:"):
            if field == "useragent":
                flt = self.flt_and(flt, self.searchuseragent())
            else:
                subfield = utils.str2regexp(field[10:])
                flt = self.flt_and(flt, self.searchuseragent(useragent=subfield))
                specialflt = [
                    {"$match": {"ports.scripts.http-user-agent": subfield}},
                ]
            field = "ports.scripts.http-user-agent"
        elif field == "ja3-client" or (
            field.startswith("ja3-client") and field[10] in ":."
        ):
            if ":" in field:
                field, value = field.split(":", 1)
                subkey, value = self._ja3keyvalue(utils.str2regexp(value))
                specialflt = [
                    {
                        "$match": {
                            "ports.scripts.ssl-ja3-client.%s" % subkey: value,
                        }
                    },
                ]
            else:
                value = None
                subkey = None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            if subkey is not None and subkey != subfield:
                specialproj = {
                    "_id": 0,
                    "ports.scripts.ssl-ja3-client.%s" % subkey: 1,
                    "ports.scripts.ssl-ja3-client.%s" % subfield: 1,
                }
            flt = self.flt_and(flt, self.searchja3client(value_or_hash=value))
            field = "ports.scripts.ssl-ja3-client.%s" % subfield
        elif field == "ja3-server" or (
            field.startswith("ja3-server") and field[10] in ":."
        ):
            if ":" in field:
                field, values = field.split(":", 1)
                if ":" in values:
                    value1, value2 = values.split(":", 1)
                    if value1:
                        subkey1, value1 = self._ja3keyvalue(utils.str2regexp(value1))
                    else:
                        subkey1, value1 = None, None
                    if value2:
                        subkey2, value2 = self._ja3keyvalue(utils.str2regexp(value2))
                    else:
                        subkey2, value2 = None, None
                else:
                    subkey1, value1 = self._ja3keyvalue(utils.str2regexp(values))
                    subkey2, value2 = None, None
            else:
                subkey1, value1 = None, None
                subkey2, value2 = None, None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            flt = self.flt_and(
                flt,
                self.searchja3server(
                    value_or_hash=value1,
                    client_value_or_hash=value2,
                ),
            )
            specialproj = {
                "_id": 0,
                "ports.scripts.ssl-ja3-server.%s" % subfield: 1,
                "ports.scripts.ssl-ja3-server.client.%s" % subfield: 1,
            }
            if subkey1 is not None and subkey1 != subfield:
                specialproj["ports.scripts.ssl-ja3-server.%s" % subkey1] = 1
            if subkey2 is not None and subkey2 != subfield:
                specialproj["ports.scripts.ssl-ja3-server.client.%s" % subkey2] = 1
            field = "ports.scripts.ssl-ja3-server"
            specialflt.append(
                {
                    "$project": {
                        "_id": 0,
                        field: [
                            "$ports.scripts.ssl-ja3-server.%s" % subfield,
                            "$ports.scripts.ssl-ja3-server.client.%s" % subfield,
                        ],
                    }
                }
            )

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"])}

        elif field == "sshkey.bits":
            flt = self.flt_and(flt, self.searchsshkey())
            specialproj = {
                "ports.scripts.ssh-hostkey.type": 1,
                "ports.scripts.ssh-hostkey.bits": 1,
            }
            specialflt = [
                {
                    "$project": {
                        "_id": 0,
                        "ports.scripts.ssh-hostkey.bits": [
                            "$ports.scripts.ssh-hostkey.type",
                            "$ports.scripts.ssh-hostkey.bits",
                        ],
                    }
                }
            ]

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"])}

            field = "ports.scripts.ssh-hostkey.bits"
        elif field.startswith("sshkey."):
            flt = self.flt_and(flt, self.searchsshkey())
            field = "ports.scripts.ssh-hostkey." + field[7:]
        elif field == "ike.vendor_ids":
            flt = self.flt_and(flt, self.searchscript(name="ike-info"))
            specialproj = {
                "ports.scripts.ike-info.vendor_ids.value": 1,
                "ports.scripts.ike-info.vendor_ids.name": 1,
            }
            specialflt = [
                {
                    "$project": {
                        "_id": 0,
                        "ports.scripts.ike-info.vendor_ids": [
                            "$ports.scripts.ike-info.vendor_ids.value",
                            "$ports.scripts.ike-info.vendor_ids.name",
                        ],
                    }
                }
            ]

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"])}

            field = "ports.scripts.ike-info.vendor_ids"
        elif field == "ike.transforms":
            flt = self.flt_and(
                flt,
                self.searchscript(
                    name="ike-info",
                    values={"transforms": {"$exists": True}},
                ),
            )
            specialproj = {
                "ports.scripts.ike-info.transforms.Authentication": 1,
                "ports.scripts.ike-info.transforms.Encryption": 1,
                "ports.scripts.ike-info.transforms.GroupDesc": 1,
                "ports.scripts.ike-info.transforms.Hash": 1,
                "ports.scripts.ike-info.transforms.LifeDuration": 1,
                "ports.scripts.ike-info.transforms.LifeType": 1,
            }
            specialflt = [
                {
                    "$project": {
                        "_id": 0,
                        "ports.scripts.ike-info.transforms": [
                            "$ports.scripts.ike-info.transforms.Authentication",
                            "$ports.scripts.ike-info.transforms.Encryption",
                            "$ports.scripts.ike-info.transforms.GroupDesc",
                            "$ports.scripts.ike-info.transforms.Hash",
                            "$ports.scripts.ike-info.transforms.LifeDuration",
                            "$ports.scripts.ike-info.transforms.LifeType",
                        ],
                    }
                }
            ]

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"])}

            field = "ports.scripts.ike-info.transforms"
        elif field == "ike.notification":
            flt = self.flt_and(
                flt,
                self.searchscript(
                    name="ike-info",
                    values={"notification_type": {"$exists": True}},
                ),
            )
            field = "ports.scripts.ike-info.notification_type"
        elif field.startswith("ike."):
            flt = self.flt_and(flt, self.searchscript(name="ike-info"))
            field = "ports.scripts.ike-info." + field[4:]
        elif field == "httphdr":
            flt = self.flt_and(flt, self.searchhttphdr())
            specialproj = {
                "_id": 0,
                "ports.scripts.http-headers.name": 1,
                "ports.scripts.http-headers.value": 1,
            }
            specialflt = [
                {
                    "$project": {
                        "_id": 0,
                        "ports.scripts.http-headers": [
                            "$ports.scripts.http-headers.name",
                            "$ports.scripts.http-headers.value",
                        ],
                    }
                }
            ]

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"])}

            field = "ports.scripts.http-headers"
        elif field.startswith("httphdr."):
            flt = self.flt_and(flt, self.searchhttphdr())
            field = "ports.scripts.http-headers.%s" % field[8:]
        elif field.startswith("httphdr:"):
            subfield = field[8:].lower()
            flt = self.flt_and(flt, self.searchhttphdr(name=subfield))
            specialproj = {
                "_id": 0,
                "ports.scripts.http-headers.name": 1,
                "ports.scripts.http-headers.value": 1,
            }
            specialflt = [{"$match": {"ports.scripts.http-headers.name": subfield}}]
            field = "ports.scripts.http-headers.value"
        elif field == "httpapp":
            flt = self.flt_and(flt, self.searchhttpapp())
            specialproj = {
                "_id": 0,
                "ports.scripts.http-app.application": 1,
                "ports.scripts.http-app.version": 1,
            }
            specialflt = [
                {
                    "$project": {
                        "_id": 0,
                        "ports.scripts.http-app": [
                            "$ports.scripts.http-app.application",
                            "$ports.scripts.http-app.version",
                        ],
                    }
                }
            ]

            def outputproc(x):
                return {"count": x["count"], "_id": tuple(x["_id"])}

            field = "ports.scripts.http-app"
        elif field.startswith("httpapp:"):
            subfield = field[8:]
            flt = self.flt_and(flt, self.searchhttpapp(name=subfield))
            specialproj = {
                "_id": 0,
                "ports.scripts.http-app.application": 1,
                "ports.scripts.http-app.version": 1,
            }
            specialflt = [{"$match": {"ports.scripts.http-app.application": subfield}}]
            field = "ports.scripts.http-app.version"
        elif field.startswith("modbus."):
            flt = self.flt_and(flt, self.searchscript(name="modbus-discover"))
            field = "ports.scripts.modbus-discover." + field[7:]
        elif field.startswith("s7."):
            flt = self.flt_and(flt, self.searchscript(name="s7-info"))
            field = "ports.scripts.s7-info." + field[3:]
        elif field.startswith("enip."):
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
            field = "ports.scripts.enip-info." + subfield
        elif field.startswith("mongo.dbs."):
            flt = self.flt_and(flt, self.searchscript(name="mongodb-databases"))
            field = "ports.scripts.mongodb-databases." + field[10:]
        elif field.startswith("vulns."):
            flt = self.flt_and(flt, self.searchvuln())
            subfield = field[6:]
            if subfield == "id":
                field = "ports.scripts.vulns.id"
            else:
                field = "ports.scripts.vulns." + subfield
                specialproj = {
                    "_id": 0,
                    "ports.scripts.vulns.id": 1,
                    field: 1,
                }
                specialflt = [
                    {
                        "$project": {
                            "_id": 0,
                            field: [
                                "$ports.scripts.vulns.id",
                                "$" + field,
                            ],
                        },
                    }
                ]

                def outputproc(x):
                    return {"count": x["count"], "_id": tuple(x["_id"])}

        elif field == "file" or (field.startswith("file") and field[4] in ".:"):
            if field.startswith("file:"):
                scripts = field[5:]
                if "." in scripts:
                    scripts, field = scripts.split(".", 1)
                else:
                    field = "filename"
                scripts = scripts.split(",")
            else:
                field = field[5:] or "filename"
                scripts = None
            flt = self.flt_and(flt, self.searchfile(scripts=scripts))
            field = "ports.scripts.ls.volumes.files.%s" % field
            if scripts is not None:
                specialproj = {"_id": 0, field: 1, "ports.scripts.id": 1}
                # We need two different filters here (see `cpeflt`
                # above).
                specialflt = [
                    {
                        "$match": {
                            "ports.scripts.id": flt["ports.scripts"]["$elemMatch"]["id"]
                        }
                    },
                    {"$project": {field: {"$ifNull": ["$" + field, ""]}}},
                    # {"$project": {field: 1}},
                ]
            else:
                specialflt = [
                    {"$project": {field: {"$ifNull": ["$" + field, ""]}}},
                ]

            def outputproc(x):
                return {"count": x["count"], "_id": null_if_empty(x["_id"])}

        elif field == "screenwords":
            field = "ports.screenwords"
            flt = self.flt_and(flt, self.searchscreenshot(words=True))
        elif field == "hop":
            field = "traces.hops.ipaddr"
            specialproj = {
                "_id": 0,
                "traces.hops.ipaddr_0": 1,
                "traces.hops.ipaddr_1": 1,
            }
            specialflt = [
                {
                    "$project": {
                        field: ["$traces.hops.ipaddr_0", "$traces.hops.ipaddr_1"]
                    }
                },
            ]

            def outputproc(x):
                return {"count": x["count"], "_id": self.internal2ip(x["_id"])}

        elif field.startswith("hop") and field[3] in ":>":
            specialproj = {
                "_id": 0,
                "traces.hops.ipaddr_0": 1,
                "traces.hops.ipaddr_1": 1,
                "traces.hops.ttl": 1,
            }
            specialflt = [
                {
                    "$match": {
                        "traces.hops.ttl": (
                            int(field[4:])
                            if field[3] == ":"
                            else {"$gt": int(field[4:])}
                        )
                    }
                }
            ]
            specialflt.append(
                {
                    "$project": {
                        "traces.hops.ipaddr": [
                            "$traces.hops.ipaddr_0",
                            "$traces.hops.ipaddr_1",
                        ]
                    }
                },
            )

            def outputproc(x):
                return {"count": x["count"], "_id": self.internal2ip(x["_id"])}

            field = "traces.hops.ipaddr"
        elif field.startswith("scanner.port:"):
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = "ports.scripts.scanner.ports.%s.ports" % field[13:]
        elif field == "scanner.name":
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = "ports.scripts.scanner.scanners.name"
        pipeline = self._topvalues(
            field,
            flt=flt,
            topnbr=topnbr,
            sort=sort,
            limit=limit,
            skip=skip,
            least=least,
            aggrflt=aggrflt,
            specialproj=specialproj,
            specialflt=specialflt,
        )
        log_pipeline(pipeline)
        cursor = self.set_limits(
            self.db[self.columns[self.column_hosts]].aggregate(pipeline, cursor={})
        )
        if outputproc is not None:
            return (outputproc(res) for res in cursor)
        return cursor

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None):
        """This method makes use of the aggregation framework to
        produce distinct values for a given field.

        """
        return self._distinct(
            self.columns[self.column_hosts],
            field,
            flt=flt,
            sort=sort,
            limit=limit,
            skip=skip,
        )

    def _features_port_list_pipeline(self, flt, use_service, use_product, use_version):
        return (
            [
                {"$match": self.flt_and(flt, {"ports.port": {"$exists": True}})},
                {"$project": {"_id": 0, "ports": 1}},
                {"$unwind": "$ports"},
                {"$match": {"ports.port": {"$ne": -1}}},
            ],
            "$ports.port",
            "$ports",
        )

    def diff_categories(self, category1, category2, flt=None, include_both_open=True):
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
        addr = ["$addr_0", "$addr_1"]
        pipeline = [
            {
                "$match": (
                    category_filter
                    if flt is None
                    else self.flt_and(flt, category_filter)
                )
            },
            {"$unwind": "$categories"},
            {"$match": category_filter},
            {"$unwind": "$ports"},
            {"$match": {"ports.state_state": "open"}},
            {
                "$project": {
                    "_id": 0,
                    "addr": addr,
                    "ports.protocol": 1,
                    "ports.port": 1,
                    "categories": 1,
                }
            },
            {
                "$group": {
                    "_id": {
                        "addr": "$addr",
                        "proto": "$ports.protocol",
                        "port": "$ports.port",
                    },
                    "categories": {"$push": "$categories"},
                }
            },
        ]
        log_pipeline(pipeline)

        cursor = self.db[self.columns[self.column_hosts]].aggregate(pipeline, cursor={})

        def categories_to_val(categories):
            state1, state2 = category1 in categories, category2 in categories
            # assert any(states)
            return (state2 > state1) - (state2 < state1)

        cursor = (
            dict(x["_id"], value=categories_to_val(x["categories"])) for x in cursor
        )
        if include_both_open:
            return cursor
        return (result for result in cursor if result["value"])


class MongoDBNmap(MongoDBActive, DBNmap):

    column_scans = 1
    content_handler = Nmap2Mongo

    def __init__(self, url):
        super().__init__(url)
        self.columns = [
            self.params.pop("colname_hosts", "hosts"),
            self.params.pop("colname_scans", "scans"),
        ]
        self.schema_migrations.append({})  # scans
        self.output_function = None

    def store_scan_doc(self, scan):
        ident = self.db[self.columns[self.column_scans]].insert(scan)
        utils.LOGGER.debug(
            "SCAN STORED: %r in %r", ident, self.columns[self.column_scans]
        )
        return ident

    def update_scan_doc(self, scan_id, data):
        self.db[self.columns[self.column_scans]].update(
            {"_id": scan_id},
            {"set": data},
            multi=False,
        )

    def store_or_merge_host(self, host):
        self.store_host(host)

    def cmp_schema_version_scan(self, scan):
        """Returns 0 if the `scan`'s schema version matches the code's
        current version, -1 if it is higher (you need to update IVRE),
        and 1 if it is lower (you need to call .migrate_schema()).

        """
        return self.cmp_schema_version(self.column_scans, scan)

    def getscan(self, scanid):
        return self.find_one(self.columns[self.column_scans], {"_id": scanid})

    def is_scan_present(self, scanid):
        if (
            self.find_one(self.columns[self.column_scans], {"_id": scanid}, fields=[])
            is not None
        ):
            return True
        return False

    def remove(self, host):
        """Removes the host from the active column. `host` must be the host
        record as returned by `.get()`.

        If `host` has a `scanid` attribute, and if it refers to a scan that
        have no more host record after the deletion of `host`, then the scan
        record is also removed.

        """
        super().remove(host)
        for scanid in self.getscanids(host):
            if (
                self.find_one(self.columns[self.column_hosts], {"scanid": scanid})
                is None
            ):
                self.db[self.columns[self.column_scans]].delete_one({"_id": scanid})

    def remove_many(self, flt):
        """Removes hosts from the active column, based on the filter `flt`.

        If the hosts removed had `scanid` attributes, and if some of them
        refer to scans that have no more host record after the deletion of the
        hosts, then the scan records are also removed.

        """
        scanids = list(self.distinct("scanid", flt=flt))
        super().remove_many(flt)
        for scanid in scanids:
            if (
                self.find_one(self.columns[self.column_hosts], {"scanid": scanid})
                is None
            ):
                self.db[self.columns[self.column_scans]].delete_one({"_id": scanid})


class MongoDBView(MongoDBActive, DBView):
    def __init__(self, url):
        super().__init__(url)
        self.columns = [self.params.pop("colname_hosts", "views")]

    def store_or_merge_host(self, host):
        if not self.merge_host(host):
            self.store_host(host)


class MongoDBPassive(MongoDB, DBPassive):

    column_passive = 0
    _features_column = 0
    indexes = [
        # passive
        [
            ([("schema_version", pymongo.ASCENDING)], {}),
            ([("port", pymongo.ASCENDING)], {}),
            ([("value", pymongo.ASCENDING)], {}),
            ([("targetval", pymongo.ASCENDING)], {}),
            ([("recontype", pymongo.ASCENDING), ("source", pymongo.ASCENDING)], {}),
            ([("firstseen", pymongo.ASCENDING)], {}),
            (
                [
                    ("lastseen", pymongo.ASCENDING),
                    ("addr_0", pymongo.ASCENDING),
                    ("addr_1", pymongo.ASCENDING),
                ],
                {},
            ),
            ([("sensor", pymongo.ASCENDING)], {}),
            (
                [
                    ("addr_0", pymongo.ASCENDING),
                    ("addr_1", pymongo.ASCENDING),
                    ("recontype", pymongo.ASCENDING),
                    ("port", pymongo.ASCENDING),
                ],
                {},
            ),
            # HTTP Auth basic
            ([("infos.username", pymongo.ASCENDING)], {"sparse": True}),
            ([("infos.password", pymongo.ASCENDING)], {"sparse": True}),
            # DNS
            ([("infos.domain", pymongo.ASCENDING)], {"sparse": True}),
            ([("infos.domaintarget", pymongo.ASCENDING)], {"sparse": True}),
            # SSL
            ([("infos.md5", pymongo.ASCENDING)], {"sparse": True}),
            ([("infos.sha1", pymongo.ASCENDING)], {"sparse": True}),
            ([("infos.sha256", pymongo.ASCENDING)], {"sparse": True}),
            ([("infos.issuer_text", pymongo.ASCENDING)], {"sparse": True}),
            ([("infos.subject_text", pymongo.ASCENDING)], {"sparse": True}),
            ([("infos.pubkey.type", pymongo.ASCENDING)], {"sparse": True}),
        ],
    ]
    schema_migrations_indexes = [
        # passive
        {
            1: {
                "drop": [
                    ([("recontype", pymongo.ASCENDING)], {}),
                    (
                        [
                            ("addr", pymongo.ASCENDING),
                            ("recontype", pymongo.ASCENDING),
                            ("port", pymongo.ASCENDING),
                        ],
                        {},
                    ),
                    ([("infos.issuer", pymongo.ASCENDING)], {"sparse": True}),
                    ([("infos.subject", pymongo.ASCENDING)], {"sparse": True}),
                ],
                "ensure": [
                    (
                        [
                            ("recontype", pymongo.ASCENDING),
                            ("source", pymongo.ASCENDING),
                        ],
                        {},
                    ),
                    (
                        [
                            ("addr_0", pymongo.ASCENDING),
                            ("addr_1", pymongo.ASCENDING),
                            ("recontype", pymongo.ASCENDING),
                            ("port", pymongo.ASCENDING),
                        ],
                        {},
                    ),
                    ([("schema_version", pymongo.ASCENDING)], {}),
                    ([("infos.issuer_text", pymongo.ASCENDING)], {"sparse": True}),
                    ([("infos.subject_text", pymongo.ASCENDING)], {"sparse": True}),
                    ([("infos.san", pymongo.ASCENDING)], {"sparse": True}),
                ],
            },
            2: {
                "drop": [
                    ([("infos.pubkeyalgo", pymongo.ASCENDING)], {"sparse": True}),
                ],
                "ensure": [
                    ([("infos.pubkey.type", pymongo.ASCENDING)], {"sparse": True}),
                ],
            },
        }
    ]
    schema_latest_versions = [
        # hosts
        xmlnmap.SCHEMA_VERSION,
    ]
    hint_indexes = [
        # passive
        OrderedDict(
            [
                (
                    "addr_0",
                    [("addr_0", 1), ("addr_1", 1), ("recontype", 1), ("port", 1)],
                ),
                ("targetval", [("targetval", 1)]),
            ]
        ),
    ]

    def __init__(self, url):
        super().__init__(url)
        self.columns = [self.params.pop("colname_passive", "passive")]
        self.schema_migrations = [
            # passive
            {
                None: (1, self.migrate_schema_passive_0_1),
                1: (2, self.migrate_schema_passive_1_2),
            },
        ]

    def cmp_schema_version_passive(self, rec):
        """Returns 0 if the `rec`'s schema version matches the code's
        current version, -1 if it is higher (you need to update IVRE),
        and 1 if it is lower (you need to call .migrate_schema()).

        """
        return self.cmp_schema_version(self.column_passive, rec)

    def migrate_schema(self, version):
        """Process to schema migrations in column passive starting from
        `version`.

        """
        MongoDB.migrate_schema(self, self.column_passive, version)

    def _migrate_update_record(self, colname, recid, update):
        """Define how an update is handled. Purpose-specific subclasses may
        want to do something special here, e.g., mix with other records.

        """
        if colname == self.columns[self.column_passive]:  # just in case
            del update["_id"]
            self.insert_or_update_mix(update, getinfos=passive.getinfos)
            self.remove(recid)
            return None
        return super()._migrate_update_record(colname, recid, update)

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
        doc = cls.internal2rec(doc)
        doc["schema_version"] = 1
        for key in ["firstseen", "lastseen"]:
            doc[key] = datetime.datetime.fromtimestamp(doc[key])
        if "addr" in doc:
            doc["addr_0"], doc["addr_1"] = cls.ip2internal(
                utils.force_int2ip(doc.pop("addr"))
            )
        if doc["recontype"] == "SSL_SERVER" and doc["source"] == "cert":
            doc.update(passive._getinfos_cert(doc))
        return doc

    @classmethod
    def migrate_schema_passive_1_2(cls, doc):
        """Converts a record from version 1 to version 2. In version 2 the
        structured data for SSL certificates has been updated.

        """
        assert doc["schema_version"] == 1
        doc = cls.internal2rec(doc)
        doc["schema_version"] = 2
        if doc["recontype"] == "SSL_SERVER" and doc["source"] == "cert":
            info = utils.get_cert_info(doc["value"])
            if info:
                doc["infos"] = info
            doc["value"] = utils.encode_b64(doc["value"]).decode()
        return doc

    def _get(self, flt, **kargs):
        """Like .get(), but returns a MongoDB cursor (suitable for use with
        e.g.  .explain()).

        """
        return self._get_cursor(self.columns[self.column_passive], flt, **kargs)

    @classmethod
    def rec2internal(cls, rec):
        """Given a record as presented to the user, fixes it before it can be
        inserted in the database.

        """
        try:
            rec["addr_0"], rec["addr_1"] = cls.ip2internal(rec.pop("addr"))
        except (KeyError, ValueError):
            pass
        if rec.get("recontype") in {"SSL_SERVER", "SSL_CLIENT"} and rec.get(
            "source"
        ) in {
            "cert",
            "cacert",
        }:
            rec["value"] = cls.to_binary(utils.decode_b64(rec["value"].encode()))
        cls._fix_sizes(rec)
        return rec

    @classmethod
    def internal2rec(cls, rec):
        """Given a record as stored in the database, fixes it before it can be
        returned to backend-agnostic functions.

        """
        try:
            rec["addr"] = cls.internal2ip([rec.pop("addr_0"), rec.pop("addr_1")])
        except (KeyError, socket.error):
            pass
        for key in ["value", "targetval"]:
            if "full" + key in rec:
                rec[key] = rec.pop("full" + key)
        if "fullinfos" in rec:
            rec.setdefault("infos", {}).update(rec.pop("fullinfos"))
        return rec

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
            yield self.internal2rec(rec)

    def get_one(self, spec, **kargs):
        """Same function as get, except .find_one() method is called
        instead of .find(), so the first record matching "spec" (or None) is
        returned.

        Unlike get(), this function might take a long time, depending
        on "spec" and the indexes set on passive column."""
        # TODO: check limits
        rec = self.find_one(self.columns[self.column_passive], spec, **kargs)
        if rec is None:
            return None
        return self.internal2rec(rec)

    def update(self, spec, **kargs):
        """Updates the first record matching "spec" in the "passive" column,
        setting values according to the keyword arguments."""
        self.db[self.columns[self.column_passive]].update(spec, {"$set": kargs})

    @classmethod
    def _fix_sizes(cls, spec):
        # Finally we prepare the record to be stored. For that, we make
        # sure that no indexed value has a size greater than MAXVALLEN. If
        # so, we replace the value with its SHA1 hash and store the
        # original value in full[original column name].
        for key in ["value", "targetval"]:
            if len(spec.get(key) or "") > utils.MAXVALLEN:
                spec["full" + key] = spec[key]
                value = spec[key]
                if not isinstance(value, bytes):
                    value = value.encode()
                spec[key] = hashlib.sha1(value).hexdigest()
        # We enforce a utils.MAXVALLEN // 10 size limits for subkey values in
        # infos; this is because MongoDB cannot index values longer than 1024
        # bytes.
        for field in list(spec.get("infos", {})):
            # Do not limit size of non-indexed values
            if field not in (
                idx[6:]
                for idxes, _ in cls.indexes[cls.column_passive]
                for idx, _ in idxes
                if idx.startswith("infos")
            ):
                continue
            value = spec["infos"][field]
            if isinstance(value, str) and len(value) > utils.MAXVALLEN // 10:
                spec.setdefault("fullinfos", {})[field] = value
                spec["infos"][field] = value[: utils.MAXVALLEN // 10]

    def insert(self, spec, getinfos=None):
        """Inserts the record "spec" into the passive column."""
        if getinfos is not None:
            spec.update(getinfos(spec))
        spec = self.rec2internal(spec)
        self.db[self.columns[self.column_passive]].insert(spec)

    def insert_or_update(
        self, timestamp, spec, getinfos=None, lastseen=None, replacecount=False
    ):
        if spec is None:
            return
        orig = deepcopy(spec)
        spec = self.rec2internal(spec)
        try:
            del spec["infos"]
        except KeyError:
            pass
        hint = self.get_hint(spec)
        current = self.get(spec, hint=hint, fields=[])
        try:
            current = next(current)
        except StopIteration:
            current = None
        updatespec = {
            "$min": {"firstseen": timestamp},
            "$max": {"lastseen": lastseen or timestamp},
        }
        if replacecount:
            updatespec["$set"] = {"count": spec.pop("count", 1)}
        else:
            updatespec["$inc"] = {"count": spec.pop("count", 1)}
        if current is not None:
            self.db[self.columns[self.column_passive]].update(
                {"_id": current["_id"]},
                updatespec,
            )
        else:
            if getinfos is not None:
                orig.update(getinfos(orig))
                try:
                    infos = {"infos": orig["infos"]}
                except KeyError:
                    pass
                else:
                    self._fix_sizes(infos)
                    updatespec["$setOnInsert"] = infos
            self.db[self.columns[self.column_passive]].update(
                spec,
                updatespec,
                upsert=True,
            )

    def insert_or_update_bulk(
        self, specs, getinfos=None, separated_timestamps=True, replacecount=False
    ):
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
        bulk = self.db[self.columns[self.column_passive]].initialize_unordered_bulk_op()
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
                updatespec = {
                    "$min": {"firstseen": firstseen},
                    "$max": {"lastseen": lastseen},
                }
                if replacecount:
                    updatespec["$set"] = {"count": spec.pop("count", 1)}
                else:
                    updatespec["$inc"] = {"count": spec.pop("count", 1)}
                if getinfos is not None:
                    spec.update(getinfos(spec))
                    try:
                        infos = {"infos": spec["infos"]}
                    except KeyError:
                        pass
                    else:
                        self._fix_sizes(infos)
                        updatespec["$setOnInsert"] = infos
                spec = self.rec2internal(spec)
                findspec = deepcopy(spec)
                for key in ["infos", "fullinfos"]:
                    try:
                        del findspec[key]
                    except KeyError:
                        pass
                bulk.find(findspec).upsert().update(updatespec)
                count += 1
                if count >= config.MONGODB_BATCH_SIZE:
                    utils.LOGGER.debug("DB:MongoDB bulk upsert: %d", count)
                    bulk.execute()
                    bulk = self.db[
                        self.columns[self.column_passive]
                    ].initialize_unordered_bulk_op()
                    count = 0
        except IOError:
            pass
        if count > 0:
            utils.LOGGER.debug("DB:MongoDB bulk upsert: %d (final)", count)
            bulk.execute()

    def insert_or_update_mix(self, spec, getinfos=None, replacecount=False):
        """Updates the first record matching "spec" (without
        "firstseen", "lastseen" and "count") by mixing "firstseen",
        "lastseen" and "count" from "spec" and from the database.

        This is useful to mix records from different databases.

        """
        updatespec = {}
        spec = self.rec2internal(spec)
        if "firstseen" in spec:
            updatespec["$min"] = {"firstseen": spec.pop("firstseen")}
        if "lastseen" in spec:
            updatespec["$max"] = {"lastseen": spec.pop("lastseen")}
        if replacecount:
            updatespec["$set"] = {"count": spec.pop("count", 1)}
        else:
            updatespec["$inc"] = {"count": spec.pop("count", 1)}
        if "infos" in spec:
            updatespec["$setOnInsert"] = {"infos": spec.pop("infos")}
        if "fullinfos" in spec:
            if "$setOnInsert" in updatespec:
                updatespec["$setOnInsert"].update({"fullinfos": spec.pop("fullinfos")})
            else:
                updatespec["$setOnInsert"] = {
                    "fullinfos": spec.pop("fullinfos"),
                }
        current = self.get_one(spec, fields=[])
        if current:
            self.db[self.columns[self.column_passive]].update(
                {"_id": current["_id"]},
                updatespec,
            )
        else:
            if getinfos is not None and "$setOnInsert" not in updatespec:
                infos = getinfos(spec)
                if infos:
                    updatespec["$setOnInsert"] = infos
            self.db[self.columns[self.column_passive]].update(
                spec,
                updatespec,
                upsert=True,
            )

    def remove(self, spec_or_id):
        self.db[self.columns[self.column_passive]].remove(spec_or_id=spec_or_id)

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
            kargs["countfield"] = "count"
        outputproc = None
        aggrflt = None
        specialproj = None
        if field == "addr":
            specialproj = {
                "_id": 0,
                "addr": ["$addr_0", "$addr_1"],
            }

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": (
                        None if x["_id"][0] is None else self.internal2ip(x["_id"])
                    ),
                }

        elif field == "net" or field.startswith("net:"):
            flt = self.flt_and(flt, self.searchipv4())
            mask = int(field.split(":", 1)[1]) if ":" in field else 24
            field = "addr"
            # This should not overflow thanks to .searchipv4() filter
            addr = {"$add": ["$addr_1", 0x7FFF000100000000]}
            specialproj = {
                "_id": 0,
                "addr": {"$floor": {"$divide": [addr, 2 ** (32 - mask)]}},
            }
            flt = self.flt_and(flt, self.searchipv4())

            def outputproc(x):
                return {
                    "count": x["count"],
                    "_id": "%s/%d"
                    % (
                        utils.int2ip(int(x["_id"]) * 2 ** (32 - mask)),
                        mask,
                    ),
                }

        elif field == "domains":
            flt = self.flt_and(flt, self.searchdns())
            field = "infos.domain"
        elif field.startswith("domains:"):
            flt = self.flt_and(flt, self.searchdns())
            level = int(field[8:]) - 1
            field = "infos.domain"
            aggrflt = {"field": re.compile("^([^\\.]+\\.){%d}[^\\.]+$" % level)}
        pipeline = self._topvalues(
            field, flt=flt, aggrflt=aggrflt, specialproj=specialproj, **kargs
        )
        log_pipeline(pipeline)
        cursor = self.set_limits(
            self.db[self.columns[self.column_passive]].aggregate(
                pipeline,
                cursor={},
            )
        )
        if outputproc is not None:
            return (outputproc(res) for res in cursor)
        return cursor

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None):
        """This method makes use of the aggregation framework to
        produce distinct values for a given field.

        """
        return self._distinct(
            self.columns[self.column_passive],
            field,
            flt=flt,
            sort=sort,
            limit=limit,
            skip=skip,
        )

    def _features_port_list_pipeline(self, flt, use_service, use_product, use_version):
        return (
            [{"$match": self.flt_and(flt, {"port": {"$exists": True}})}],
            "$port",
            "$infos",
        )

    @staticmethod
    def searchrecontype(rectype, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular recontype.
        """
        if neg:
            if isinstance(rectype, utils.REGEXP_T):
                return {"recontype": {"$not": rectype}}
            if isinstance(rectype, list):
                if len(rectype) == 1:
                    rectype = rectype[0]
                else:
                    return {"recontype": {"$nin": rectype}}
            return {"recontype": {"$ne": rectype}}
        if isinstance(rectype, list):
            if len(rectype) == 1:
                rectype = rectype[0]
            else:
                return {"recontype": {"$in": rectype}}
        return {"recontype": rectype}

    @staticmethod
    def searchsensor(sensor, neg=False):
        if neg:
            if isinstance(sensor, utils.REGEXP_T):
                return {"sensor": {"$not": sensor}}
            if isinstance(sensor, list):
                if len(sensor) == 1:
                    sensor = sensor[0]
                else:
                    return {"sensor": {"$nin": sensor}}
            return {"sensor": {"$ne": sensor}}
        if isinstance(sensor, list):
            if len(sensor) == 1:
                sensor = sensor[0]
            else:
                return {"sensor": {"$in": sensor}}
        return {"sensor": sensor}

    @staticmethod
    def searchport(port, protocol="tcp", state="open", neg=False):
        """Filters (if `neg` == True, filters out) records on the specified
        protocol/port.

        """
        if protocol != "tcp":
            raise ValueError("Protocols other than TCP are not supported " "in passive")
        if state != "open":
            raise ValueError("Only open ports can be found in passive")
        return {"port": {"$ne": port} if neg else port}

    @staticmethod
    def searchservice(srv, port=None, protocol=None):
        """Search an open port with a particular service. False means the
        service is unknown.

        """
        if srv is False:
            srv = {"$exists": False}
        elif isinstance(srv, list):
            srv = {"$in": srv}
        flt = {"infos.service_name": srv}
        if port is not None:
            flt["port"] = port
        if protocol is not None and protocol != "tcp":
            raise ValueError("Protocols other than TCP are not supported " "in passive")
        return flt

    @staticmethod
    def searchproduct(
        product=None, version=None, service=None, port=None, protocol=None
    ):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        For product, version and service parameters, False is a
        special value that means "unknown"

        """
        flt = {}
        if product is not None:
            if product is False:
                flt["infos.service_product"] = {"$exists": False}
            elif isinstance(product, list):
                flt["infos.service_product"] = {"$in": product}
            else:
                flt["infos.service_product"] = product
        if version is not None:
            if product is False:
                flt["infos.service_version"] = {"$exists": False}
            elif isinstance(version, list):
                flt["infos.service_version"] = {"$in": version}
            else:
                flt["infos.service_version"] = version
        if service is not None:
            if service is False:
                flt["infos.service_name"] = {"$exists": False}
            elif isinstance(service, list):
                flt["infos.service_name"] = {"$in": service}
            else:
                flt["infos.service_name"] = service
        if port is not None:
            flt["port"] = port
        if protocol is not None:
            if protocol != "tcp":
                raise ValueError(
                    "Protocols other than TCP are not supported " "in passive"
                )
        return flt

    @staticmethod
    def searchsvchostname(hostname):
        return {"infos.service_hostname": hostname}

    @classmethod
    def searchmac(cls, mac=None, neg=False):
        res = {"recontype": "MAC_ADDRESS"}
        if mac is not None:
            if isinstance(mac, utils.REGEXP_T):
                mac = re.compile(mac.pattern, mac.flags | re.I)
                if neg:
                    res["value"] = {"$not": mac}
                else:
                    res["value"] = mac
            elif neg:
                res["value"] = {"$ne": mac.lower()}
            else:
                res["value"] = mac.lower()
        elif neg:
            return {"recontype": {"$not": "MAC_ADDRESS"}}
        return res

    @staticmethod
    def searchuseragent(useragent=None, neg=False):
        if neg:
            raise ValueError(
                "searchuseragent([...], neg=True) is not " "supported in passive DB."
            )
        if useragent is None:
            return {
                "recontype": "HTTP_CLIENT_HEADER",
                "source": "USER-AGENT",
            }
        return {
            "recontype": "HTTP_CLIENT_HEADER",
            "source": "USER-AGENT",
            "value": useragent,
        }

    @staticmethod
    def searchdns(name=None, reverse=False, dnstype=None, subdomains=False):
        if isinstance(name, list):
            if len(name) == 1:
                name = name[0]
            else:
                name = {"$in": name}
        res = {
            "recontype": "DNS_ANSWER",
        }
        if name is not None:
            res[
                (
                    ("infos.domaintarget" if reverse else "infos.domain")
                    if subdomains
                    else ("targetval" if reverse else "value")
                )
            ] = name
        if dnstype is not None:
            res["source"] = re.compile("^%s-" % dnstype.upper())
        return res

    @staticmethod
    def searchcert(
        keytype=None,
        md5=None,
        sha1=None,
        sha256=None,
        subject=None,
        issuer=None,
        self_signed=None,
        pkmd5=None,
        pksha1=None,
        pksha256=None,
        cacert=False,
    ):
        res = {"recontype": "SSL_SERVER", "source": "cacert" if cacert else "cert"}
        if keytype is not None:
            res["infos.pubkey.type"] = keytype
        if md5 is not None:
            res["infos.md5"] = md5.lower()
        if sha1 is not None:
            res["infos.sha1"] = sha1.lower()
        if sha256 is not None:
            res["infos.sha256"] = sha256.lower()
        if subject is not None:
            res["infos.subject_text"] = subject
        if issuer is not None:
            res["infos.issuer_text"] = issuer
        if self_signed is not None:
            res["infos.self_signed"] = self_signed
        if pkmd5 is not None:
            res["infos.pubkey.md5"] = pkmd5.lower()
        if pksha1 is not None:
            res["infos.pubkey.sha1"] = pksha1.lower()
        if pksha256 is not None:
            res["infos.pubkey.sha256"] = pksha256.lower()
        return res

    @classmethod
    def _searchja3(cls, value_or_hash):
        if not value_or_hash:
            return {}
        key, value = cls._ja3keyvalue(value_or_hash)
        return {"value" if key == "md5" else "infos.%s" % key: value}

    @classmethod
    def searchja3client(cls, value_or_hash=None):
        return dict(cls._searchja3(value_or_hash), recontype="SSL_CLIENT", source="ja3")

    @classmethod
    def searchja3server(cls, value_or_hash=None, client_value_or_hash=None):
        base = dict(cls._searchja3(value_or_hash), recontype="SSL_SERVER")
        if not client_value_or_hash:
            return dict(base, source=re.compile("^ja3-"))
        key, value = cls._ja3keyvalue(client_value_or_hash)
        if key == "md5":
            return dict(base, source="ja3-%s" % value)
        return dict(
            base,
            source=re.compile("^ja3-"),
            **{"infos.client.%s" % key: client_value_or_hash},
        )

    @staticmethod
    def searchsshkey(keytype=None):
        if keytype is None:
            return {"recontype": "SSH_SERVER_HOSTKEY", "source": "SSHv2"}
        return {
            "recontype": "SSH_SERVER_HOSTKEY",
            "source": "SSHv2",
            "infos.algo": "ssh-" + keytype,
        }

    @staticmethod
    def searchbasicauth():
        return {
            "recontype": {"$in": ["HTTP_CLIENT_HEADER", "HTTP_CLIENT_HEADER_SERVER"]},
            "source": {"$in": ["AUTHORIZATION", "PROXY-AUTHORIZATION"]},
            "value": re.compile("^Basic", re.I),
        }

    @staticmethod
    def searchhttpauth():
        return {
            "recontype": {"$in": ["HTTP_CLIENT_HEADER", "HTTP_CLIENT_HEADER_SERVER"]},
            "source": {"$in": ["AUTHORIZATION", "PROXY-AUTHORIZATION"]},
        }

    @staticmethod
    def searchftpauth():
        return {"recontype": {"$in": ["FTP_CLIENT", "FTP_SERVER"]}}

    @staticmethod
    def searchpopauth():
        return {"recontype": {"$in": ["POP_CLIENT", "POP_SERVER"]}}

    @staticmethod
    def searchtcpsrvbanner(banner):
        return {"recontype": "TCP_SERVER_BANNER", "value": banner}

    @staticmethod
    def searchtimeago(delta, neg=False, new=True):
        if not isinstance(delta, datetime.timedelta):
            delta = datetime.timedelta(seconds=delta)
        return {
            "firstseen"
            if new
            else "lastseen": {"$lt" if neg else "$gte": datetime.datetime.now() - delta}
        }

    @staticmethod
    def searchnewer(timestamp, neg=False, new=True):
        if not isinstance(timestamp, datetime.datetime):
            timestamp = datetime.datetime.fromtimestamp(timestamp)
        return {
            "firstseen" if new else "lastseen": {"$lte" if neg else "$gt": timestamp}
        }


class MongoDBAgent(MongoDB, DBAgent):
    """MongoDB-specific code to handle agents-in-DB"""

    column_agents = 0
    column_scans = 1
    column_masters = 2
    indexes: List[List[Tuple[List[SortKey], Dict[str, Any]]]] = [
        # agents
        [
            ([("host", pymongo.ASCENDING)], {}),
            ([("path.remote", pymongo.ASCENDING)], {}),
            ([("path.local", pymongo.ASCENDING)], {}),
            ([("master", pymongo.ASCENDING)], {}),
            ([("scan", pymongo.ASCENDING)], {}),
        ],
        # scans
        [
            ([("agents", pymongo.ASCENDING)], {}),
        ],
        # masters
        [
            ([("hostname", pymongo.ASCENDING), ("path", pymongo.ASCENDING)], {}),
        ],
    ]

    def __init__(self, url):
        super().__init__(url)
        self.columns = [
            self.params.pop("colname_agents", "agents"),
            self.params.pop("colname_scans", "runningscans"),
            self.params.pop("colname_masters", "masters"),
        ]

    def _add_agent(self, agent):
        return self.db[self.columns[self.column_agents]].insert(agent)

    def get_agent(self, agentid):
        return self.find_one(self.columns[self.column_agents], {"_id": agentid})

    def get_free_agents(self):
        return (
            x["_id"]
            for x in self.set_limits(
                self.find(
                    self.columns[self.column_agents], {"scan": None}, fields=["_id"]
                )
            )
        )

    def get_agents_by_master(self, masterid):
        return (
            x["_id"]
            for x in self.set_limits(
                self.find(
                    self.columns[self.column_agents],
                    {"master": masterid},
                    fields=["_id"],
                )
            )
        )

    def get_agents(self):
        return (
            x["_id"]
            for x in self.set_limits(
                self.find(self.columns[self.column_agents], fields=["_id"])
            )
        )

    def assign_agent(self, agentid, scanid, only_if_unassigned=False, force=False):
        flt = {"_id": agentid}
        if only_if_unassigned:
            flt["scan"] = None
        elif not force:
            flt["scan"] = {"$ne": False}
        self.db[self.columns[self.column_agents]].update(
            flt, {"$set": {"scan": scanid}}
        )
        agent = self.get_agent(agentid)
        if scanid is not None and scanid is not False and scanid == agent["scan"]:
            self.db[self.columns[self.column_scans]].update(
                {"_id": scanid, "agents": {"$ne": agentid}},
                {"$push": {"agents": agentid}},
            )

    def unassign_agent(self, agentid, dont_reuse=False):
        agent = self.get_agent(agentid)
        scanid = agent["scan"]
        if scanid is not None:
            self.db[self.columns[self.column_scans]].update(
                {"_id": scanid, "agents": agentid}, {"$pull": {"agents": agentid}}
            )
        if dont_reuse:
            self.assign_agent(agentid, False, force=True)
        else:
            self.assign_agent(agentid, None, force=True)

    def _del_agent(self, agentid):
        return self.db[self.columns[self.column_agents]].remove(spec_or_id=agentid)

    def _add_scan(self, scan):
        return self.db[self.columns[self.column_scans]].insert(scan)

    def get_scan(self, scanid):
        scan = self.find_one(
            self.columns[self.column_scans], {"_id": scanid}, fields={"target": 0}
        )
        if scan.get("lock") is not None:
            scan["lock"] = uuid.UUID(bytes=scan["lock"])
        if "target_info" not in scan:
            target = self.get_scan_target(scanid)
            if target is not None:
                target_info = target.target.infos
                self.db[self.columns[self.column_scans]].update(
                    {"_id": scanid},
                    {"$set": {"target_info": target_info}},
                )
                scan["target_info"] = target_info
        return scan

    def _get_scan_target(self, scanid):
        scan = self.find_one(
            self.columns[self.column_scans],
            {"_id": scanid},
            fields={"target": 1, "_id": 0},
        )
        return None if scan is None else scan["target"]

    def _lock_scan(self, scanid, oldlockid, newlockid):
        """Change lock for scanid from oldlockid to newlockid. Returns the new
        scan object on success, and raises a LockError on failure.

        """
        if oldlockid is not None:
            oldlockid = bson.Binary(oldlockid)
        if newlockid is not None:
            newlockid = bson.Binary(newlockid)
        scan = self.db[self.columns[self.column_scans]].find_and_modify(
            {
                "_id": scanid,
                "lock": oldlockid,
            },
            {
                "$set": {"lock": newlockid, "pid": os.getpid()},
            },
            full_response=True,
            fields={"target": False},
            new=True,
        )["value"]
        if scan is None:
            if oldlockid is None:
                raise LockError("Cannot acquire lock for %r" % scanid)
            if newlockid is None:
                raise LockError("Cannot release lock for %r" % scanid)
            raise LockError(
                "Cannot change lock for %r from "
                "%r to %r" % (scanid, oldlockid, newlockid)
            )
        if "target_info" not in scan:
            target = self.get_scan_target(scanid)
            if target is not None:
                target_info = target.target.infos
                self.db[self.columns[self.column_scans]].update(
                    {"_id": scanid},
                    {"$set": {"target_info": target_info}},
                )
                scan["target_info"] = target_info
        if scan["lock"] is not None:
            scan["lock"] = bytes(scan["lock"])
        return scan

    def get_scans(self):
        return (
            x["_id"]
            for x in self.set_limits(
                self.find(self.columns[self.column_scans], fields=["_id"])
            )
        )

    def _update_scan_target(self, scanid, target):
        return self.db[self.columns[self.column_scans]].update(
            {"_id": scanid}, {"$set": {"target": target}}
        )

    def incr_scan_results(self, scanid):
        return self.db[self.columns[self.column_scans]].update(
            {"_id": scanid}, {"$inc": {"results": 1}}
        )

    def _add_master(self, master):
        return self.db[self.columns[self.column_masters]].insert(master)

    def get_master(self, masterid):
        return self.find_one(self.columns[self.column_masters], {"_id": masterid})

    def get_masters(self):
        return (
            x["_id"]
            for x in self.set_limits(
                self.find(self.columns[self.column_masters], fields=["_id"])
            )
        )


class MongoDBFlow(MongoDB, DBFlow, metaclass=DBFlowMeta):
    column_flow = 0

    datefields = [
        "firstseen",
        "lastseen",
        "times.start",
    ]

    # This represents the kinds of metadata that are defined in flow.META_DESC
    # Each kind is associated with an aggregation operator used for
    # insertion in db.
    meta_kinds = {"keys": "$addToSet", "counters": "$inc"}

    indexes: List[List[Tuple[List[SortKey], Dict[str, Any]]]] = [
        # flows
        [
            (
                [
                    ("src_addr_0", pymongo.ASCENDING),
                    ("src_addr_1", pymongo.ASCENDING),
                    ("dst_addr_0", pymongo.ASCENDING),
                    ("dst_addr_1", pymongo.ASCENDING),
                    ("dport", pymongo.ASCENDING),
                    ("proto", pymongo.ASCENDING),
                ],
                {},
            ),
            ([("schema_version", pymongo.ASCENDING)], {}),
            ([("firstseen", pymongo.ASCENDING)], {}),
            ([("lastseen", pymongo.ASCENDING)], {}),
            ([("times", pymongo.ASCENDING)], {}),
            ([("count", pymongo.ASCENDING)], {}),
            ([("cspkts", pymongo.ASCENDING)], {}),
            ([("scpkts", pymongo.ASCENDING)], {}),
            ([("csbytes", pymongo.ASCENDING)], {}),
            ([("scbytes", pymongo.ASCENDING)], {}),
        ],
    ]

    def __init__(self, url):
        super().__init__(url)
        self.columns = ["flows"]

    def start_bulk_insert(self):
        """
        Initialize bulks for inserting data in MongoDB.
        Returns flow_bulk
        """
        utils.LOGGER.debug("start_bulk_insert called")
        return self.db[self.columns[self.column_flow]].initialize_unordered_bulk_op()

    @staticmethod
    def _get_flow_key(rec):
        """
        Returns a dict which represents the given flow in Flows.
        """
        key = {
            "src_addr_0": rec["src_addr_0"],
            "src_addr_1": rec["src_addr_1"],
            "dst_addr_0": rec["dst_addr_0"],
            "dst_addr_1": rec["dst_addr_1"],
            "proto": rec["proto"],
            "schema_version": flow.SCHEMA_VERSION,
        }
        if rec["proto"] in ["udp", "tcp"]:
            key["dport"] = rec["dport"]
        elif rec["proto"] == "icmp":
            key["type"] = rec["type"]

        return key

    @classmethod
    def _update_timeslots(cls, updatespec, rec):
        """
        If configured, adds timeslots in `updatespec`.
        config.FLOW_TIME enables timeslots.
        if config.FLOW_TIME_FULL_RANGE is set, a flow is linked to every
        timeslots between its start_time and end_time.
        Otherwise, it is only linked to the timeslot corresponding to its
        start_time.
        """
        if config.FLOW_TIME:
            if config.FLOW_TIME_FULL_RANGE:
                updatespec.setdefault("$addToSet", {})["times"] = {
                    "$each": cls._get_timeslots(rec["start_time"], rec["end_time"])
                }
            else:
                updatespec.setdefault("$addToSet", {})["times"] = cls._get_timeslot(
                    rec["start_time"], config.FLOW_TIME_PRECISION, config.FLOW_TIME_BASE
                )

    @classmethod
    def any2flow(cls, bulk, name, rec):
        """
        Takes a parsed *.log line entry and adds it to insert bulk.
        It is responsible for metadata processing (all but conn.log files).
        """
        # Convert addr
        rec["src_addr_0"], rec["src_addr_1"] = cls.ip2internal(rec["src"])
        rec["dst_addr_0"], rec["dst_addr_1"] = cls.ip2internal(rec["dst"])
        # Insert in flows
        findspec = cls._get_flow_key(rec)
        updatespec = {
            "$min": {"firstseen": rec["start_time"]},
            "$max": {"lastseen": rec["end_time"]},
            "$inc": {"meta.%s.count" % name: 1},
        }

        # metadata storage can be disabled.
        if config.FLOW_STORE_METADATA:
            for kind, op in cls.meta_kinds.items():
                for key, value in cls.meta_desc[name].get(kind, {}).items():
                    if not rec.get(value):
                        continue
                    if "%s.%s.%s" % (name, kind, key) in flow.META_DESC_ARRAYS:
                        rec[value] = {"$each": rec[value]}
                    updatespec.setdefault(op, {})["meta.%s.%s" % (name, key)] = rec[
                        value
                    ]

        cls._update_timeslots(updatespec, rec)

        bulk.find(findspec).upsert().update(updatespec)

    @classmethod
    def conn2flow(cls, bulk, rec):
        """
        Takes a parsed conn.log line entry and adds it to flow bulk.
        """
        rec["src_addr_0"], rec["src_addr_1"] = cls.ip2internal(rec["src"])
        rec["dst_addr_0"], rec["dst_addr_1"] = cls.ip2internal(rec["dst"])
        findspec = cls._get_flow_key(rec)

        updatespec = {
            "$min": {"firstseen": rec["start_time"]},
            "$max": {"lastseen": rec["end_time"]},
            "$inc": {
                "cspkts": rec["orig_pkts"],
                "scpkts": rec["resp_pkts"],
                "csbytes": rec["orig_ip_bytes"],
                "scbytes": rec["resp_ip_bytes"],
                "count": 1,
            },
        }

        cls._update_timeslots(updatespec, rec)

        if rec["proto"] in ["udp", "tcp"]:
            updatespec.setdefault("$addToSet", {})["sports"] = rec["sport"]
        elif rec["proto"] == "icmp":
            updatespec.setdefault("$addToSet", {})["codes"] = rec["code"]

        bulk.find(findspec).upsert().update(updatespec)

    @classmethod
    def flow2flow(cls, bulk, rec):
        """
        Takes an entry coming from Netflow or Argus and adds it to bulk.
        """
        rec["src_addr_0"], rec["src_addr_1"] = cls.ip2internal(rec["src"])
        rec["dst_addr_0"], rec["dst_addr_1"] = cls.ip2internal(rec["dst"])
        findspec = cls._get_flow_key(rec)

        updatespec = {
            "$min": {"firstseen": rec["start_time"]},
            "$max": {"lastseen": rec["end_time"]},
            "$inc": {
                "cspkts": rec["cspkts"],
                "scpkts": rec["scpkts"],
                "csbytes": rec["csbytes"],
                "scbytes": rec["scbytes"],
                "count": 1,
            },
        }

        cls._update_timeslots(updatespec, rec)

        if rec["proto"] in ["udp", "tcp"]:
            updatespec.setdefault("$addToSet", {})["sports"] = rec["sport"]
        elif rec["proto"] == "icmp":
            updatespec.setdefault("$addToSet", {})["codes"] = rec["code"]

        bulk.find(findspec).upsert().update(updatespec)

    @staticmethod
    def bulk_commit(bulk):
        try:
            start_time = time.time()
            result = bulk.execute()
            newtime = time.time()
            insert_rate = result.get("nInserted") / float(newtime - start_time)
            upsert_rate = result.get("nUpserted") / float(newtime - start_time)
            utils.LOGGER.debug(
                "%d inserts, %f/sec", result.get("nInserted"), insert_rate
            )
            utils.LOGGER.debug(
                "%d upserts, %f/sec", result.get("nUpserted"), upsert_rate
            )

        except BulkWriteError:
            utils.LOGGER.error("Bulk Write Error", exc_info=True)
        except pymongo.errors.InvalidOperation:
            # Raised when executing an empty bulk
            pass

    def get(self, flt, skip=None, limit=None, orderby=None, fields=None):
        """
        Returns an iterator over flows honoring the given filter
        with the given options.
        """
        sort = None
        if orderby == "dst":
            sort = [
                ("dst_addr_0", pymongo.ASCENDING),
                ("dst_addr_1", pymongo.ASCENDING),
            ]
        elif orderby == "src":
            sort = [
                ("src_addr_0", pymongo.ASCENDING),
                ("src_addr_1", pymongo.ASCENDING),
            ]
        elif orderby == "flow":
            sort = [("dport", pymongo.ASCENDING), ("proto", pymongo.ASCENDING)]
        elif orderby:
            raise ValueError("Unsupported orderby (should be 'src', 'dst' or 'flow')")
        for f in self._get_cursor(
            self.columns[self.column_flow],
            flt,
            limit=(limit or 0),
            skip=(skip or 0),
            sort=sort,
            fields=fields,
        ):
            try:
                f["src_addr"] = self.internal2ip(
                    [f.pop("src_addr_0"), f.pop("src_addr_1")]
                )
                f["dst_addr"] = self.internal2ip(
                    [f.pop("dst_addr_0"), f.pop("dst_addr_1")]
                )
            except KeyError:
                pass
            yield f

    def count(self, flt):
        """
        Returns a dict {'client': nb_clients, 'servers': nb_servers',
        'flows': nb_flows} according to the given filter.
        """
        sources = 0
        destinations = 0
        flows = self.db[self.columns[self.column_flow]].count(flt)
        if flows > 0:
            pipeline = [
                {"$match": flt},
                {
                    "$group": {
                        "_id": {
                            "src_addr_0": "$src_addr_0",
                            "src_addr_1": "$src_addr_1",
                        },
                    }
                },
                # This has the same behavior as '$count', which is only
                # available in Mongo >= 3.4. See
                # https://docs.mongodb.com/manual/reference/operator/aggregation/count/#behavior
                {"$group": {"_id": None, "count": {"$sum": 1}}},
            ]
            log_pipeline(pipeline)
            sources = next(self.db[self.columns[self.column_flow]].aggregate(pipeline))[
                "count"
            ]

            pipeline = [
                {"$match": flt},
                {
                    "$group": {
                        "_id": {
                            "dst_addr_0": "$dst_addr_0",
                            "dst_addr_1": "$dst_addr_1",
                        },
                    }
                },
                {"$group": {"_id": None, "count": {"$sum": 1}}},
            ]
            log_pipeline(pipeline)
            destinations = next(
                self.db[self.columns[self.column_flow]].aggregate(pipeline)
            )["count"]
        return {"clients": sources, "servers": destinations, "flows": flows}

    def topvalues(
        self,
        flt,
        fields,
        collect_fields=None,
        sum_fields=None,
        limit=None,
        skip=None,
        least=False,
        topnbr=10,
    ):
        """
        Returns the top values honoring the given `query` for the given
        fields list `fields`, counting and sorting the aggregated records
        by `sum_fields` sum and storing the `collect_fields` fields of
        each original entry in aggregated records as a list.
        By default, the aggregated records are sorted by their number of
        occurrences.
        Return format:
            {
                fields: (field_1_value, field_2_value, ...),
                count: count,
                collected: (
                    (collect_1_value, collect_2_value, ...),
                    ...
                )
            }
        Collected fields are unique.
        """
        collect_fields = collect_fields or []
        sum_fields = sum_fields or []

        pipeline = []

        # Translation dictionary for special fields
        special_fields = {
            "src.addr": ["src_addr_0", "src_addr_1"],
            "dst.addr": ["dst_addr_0", "dst_addr_1"],
            "sport": ["sports"],
        }

        # Validate fields
        for fields_list in (fields, collect_fields, sum_fields):
            for f in fields_list:
                # special fields can be shortcuts (ex: sport) and are not
                # necessary valid fields
                if f not in special_fields:
                    flow.validate_field(f)

        # special fields that are not addresses will be translated again at
        # the end
        reverse_special_fields = {"sports": "sport"}
        # special fields that have been translated
        # necessary to accept both already transformed and non transformed
        # field
        reversed_special_fields = set()

        # Compute the internal fields
        # internal_fields = [aggr fields, collect_fields, sum_fields]
        internal_fields = [[], [], []]
        external_fields = [fields, collect_fields, sum_fields]
        for i, ext_flds in enumerate(external_fields):
            for field in ext_flds:
                if field in special_fields:
                    internal_fields[i].extend(special_fields[field])
                    for t_field in special_fields[field]:
                        reversed_special_fields.add(t_field)
                else:
                    internal_fields[i].append(field)

        internal_fields_set = set(internal_fields[0])
        must_exist_fields_set = set(internal_fields[0] + internal_fields[1])

        # Reduce the amount of processed data
        if limit:
            pipeline.append({"$limit": limit})

        # Match the given query
        if flt:
            pipeline.append({"$match": flt})

        # Remove entries with non existing aggr or collected field
        match = {}
        for field in must_exist_fields_set:
            match[field] = {"$exists": True}
        pipeline.append({"$match": match})

        # Unwind aggregate array fields
        for field in internal_fields_set:
            for i in range(field.count("."), -1, -1):
                subfield = field.rsplit(".", i)[0]
                if subfield in self.list_fields:
                    pipeline += [{"$unwind": "$" + subfield}]

        # It is important to match the query after the unwind stages
        # because the query could target one of the aggregated fields
        # FIXME We should remove all 'non-aggregated' fields from the
        # filter
        if flt:
            pipeline.append({"$match": flt})

        # Create a projection for every fields retrieved
        # In the same time, prepare a group objects for the group stage
        project_fields = {}  # represents the projection {new_field: old_field}
        reverse_project_fields = {}
        group_fields = [{}, {}]
        index = 0  # each new field will be indexed
        for i, elt in enumerate(group_fields):
            for field in internal_fields[i]:
                cur_field = "$%s" % field
                field_name = None
                if cur_field in reverse_project_fields:
                    field_name = reverse_project_fields[cur_field]
                else:
                    field_name = "field%s" % index
                    project_fields[field_name] = cur_field
                    reverse_project_fields[cur_field] = field_name
                new_field_name = "$%s" % field_name
                # _id group
                if i == 0:
                    elt[field_name] = new_field_name
                # collect group
                else:
                    elt[field_name] = {"$push": new_field_name}
                index += 1
        # Add sum projection if sum_fields are provided
        if sum_fields:
            project_fields["_sum"] = {
                "$add": ["$%s" % field for field in internal_fields[2]]
            }

        pipeline.append({"$project": project_fields})

        # Group stage
        group = group_fields[1]
        group["_id"] = group_fields[0]
        group["_count"] = {"$sum": "$_sum" if sum_fields else 1}
        pipeline.append({"$group": group})

        pipeline.append({"$sort": {"_count": 1 if least else -1}})

        if skip is not None:
            pipeline.append({"$skip": skip})
        if topnbr is not None:
            pipeline.append({"$limit": topnbr})

        log_pipeline(pipeline)
        res = self.db[self.columns[self.column_flow]].aggregate(pipeline, cursor={})
        for entry in res:
            # Translate again the collected fields
            ext_entry = {}
            for key, value in entry.items():
                if key in project_fields:
                    ext_entry[project_fields[key][1:]] = value
                else:
                    ext_entry[key] = value
            # Translate again the aggr fields
            ext_entry["_id"] = {}
            for key, value in entry["_id"].items():
                if key in project_fields:
                    ext_entry["_id"][project_fields[key][1:]] = value
                else:
                    ext_entry["_id"][key] = value
            # apply internal2ip to addr results
            for addr_field in ["src_addr", "dst_addr"]:
                addr0, addr1 = (addr_field + "_0", addr_field + "_1")
                addr = addr_field[:3] + ".addr"
                # Apply in aggregate fields
                if addr0 in ext_entry["_id"] and addr1 in ext_entry["_id"]:
                    ext_entry["_id"][addr] = self.internal2ip(
                        (ext_entry["_id"].pop(addr0), ext_entry["_id"].pop(addr1))
                    )
                # Apply in collected fields
                if addr0 in ext_entry and addr1 in ext_entry:
                    ext_entry[addr] = [
                        self.internal2ip((a, b))
                        for a, b in zip(ext_entry[addr0], ext_entry[addr1])
                    ]
                    del ext_entry[addr0]
                    del ext_entry[addr1]
            # reverse special fields which have been reversed
            for key in list(ext_entry):
                if key in reversed_special_fields:
                    ext_entry[reverse_special_fields[key]] = ext_entry.pop(key)
            for key in list(ext_entry["_id"]):
                if key in reversed_special_fields:
                    ext_entry["_id"][reverse_special_fields[key]] = ext_entry[
                        "_id"
                    ].pop(key)
            # Format fields in a tuple ordered accordingly to fields argument
            res_fields_dict = ext_entry.pop("_id")
            res_fields = tuple(res_fields_dict.get(key) for key in fields)

            res_count = ext_entry.pop("_count")
            # Format collected results in a set of tuples to avoid duplicates
            if ext_entry:
                # Transforms collected list fields in tuples
                for key in ext_entry:
                    ext_entry[key] = [
                        elt if not isinstance(elt, list) else tuple(elt)
                        for elt in ext_entry[key]
                    ]
                # This keeps the order of collected fields
                res_collected = set(zip(*(ext_entry[key] for key in collect_fields)))
            else:
                res_collected = set()

            yield {"fields": res_fields, "collected": res_collected, "count": res_count}

    @classmethod
    def search_flow_net(cls, net, neg=False, fieldname=""):
        """
        Returns a MongoDB filter matching the given CIDR notation.
        If prefix is {src,dst}, it matches only the {src,dst} addr.
        """
        if fieldname not in ["src", "dst"]:
            res = [
                cls._searchnet(net, neg=neg, fieldname="src_addr"),
                cls._searchnet(net, neg=neg, fieldname="dst_addr"),
            ]
            op = "$and" if neg else "$or"
            return {op: res}
        return cls._searchnet(net, neg=neg, fieldname=fieldname + "_addr")

    @classmethod
    def search_flow_host(cls, addr, neg=False, prefix=""):
        """
        Returns a MongoDB filter matching the given IP address.
        If prefix is {src,dst}, it matches only the {src,dst} address.
        """
        addr = cls.ip2internal(addr)  # compute internal addr once and for all
        if prefix not in ["src", "dst"]:
            res = [
                cls._searchhost(addr, neg=neg, fieldname="src_addr"),
                cls._searchhost(addr, neg=neg, fieldname="dst_addr"),
            ]
            op = "$and" if neg else "$or"
            return {op: res}
        return cls._searchhost(addr, neg=neg, fieldname=prefix + "_addr")

    @classmethod
    def _flt_from_clause_addr(cls, clause):
        """
        Returns a filter direct from the given clause which deals
        with addresses. clause['attr'] should be addr, src.addr or dst.addr.
        """
        flt = None
        if clause["operator"] == "$ne":
            clause["operator"] = "$eq"
            clause["neg"] = not clause["neg"]
        if clause["operator"] == "$eq":
            flt = cls.search_flow_host(
                clause["value"], clause["neg"], cls.get_clause_attr_type(clause["attr"])
            )
        elif clause["operator"] == "$regex":
            flt = cls.search_flow_net(
                clause["value"],
                neg=clause["neg"],
                fieldname=cls.get_clause_attr_type(clause["attr"]),
            )
        return flt

    @classmethod
    def _get_longest_array_attr(cls, attr):
        """Returns (longest array attribute, remaining attributes) where the
        longest array attribute is the longest attribute stored in
        cls.list_fields which matches the given attr. Two attributes
        match each other if they share the same root. If no array
        attribute can be found, returns (None, attr) Example: a.b.c
        matches with a.b.c, a.b and a If cls.list_fields = ['a',
        'a.b'], then _get_longest_array_attr('a.b.c') returns ('a.b',
        'c').

        """
        for i in range(attr.count(".") + 1):
            subfield = attr.rsplit(".", i)
            if subfield[0] in cls.list_fields:
                return (subfield[0], ".".join(subfield[1:]))
        return (None, attr)

    @staticmethod
    def _flt_neg_op(op):
        """
        Returns the opposite of the given operator if it exists,
        None otherwise.
        """
        return {
            "$eq": "$ne",
            "$ne": "$eq",
            "$lt": "$gte",
            "$gte": "$lt",
            "$lte": "$gt",
            "$gt": "$lte",
        }.get(op, None)

    @classmethod
    def _flt_from_clause_any(cls, clause):
        """
        Returns a filter dict from the given clause that does not deal
        with addresses (see _flt_from_clause_addr).
        """
        add_operator = True
        # If the value is a regex, we need to compile it
        # This is compulsory to enable regex negation
        if clause["operator"] == "$regex":
            clause["value"] = re.compile(clause["value"])
            add_operator = False
        add_not = False
        # When neg is True, use the opposite operator
        # if it exists, add a $not prefix otherwise
        if clause["neg"]:
            neg_op = cls._flt_neg_op(clause["operator"])
            if neg_op is not None:
                clause["operator"] = neg_op
            else:
                add_not = True
        res = clause["value"]
        if clause["attr"] in cls.datefields:
            res = datetime.datetime.strptime(res, "%Y-%m-%d %H:%M:%S.%f")
        if add_operator:
            res = {clause["operator"]: res}
        if add_not:
            res = {"$not": res}
        return {clause["attr"]: res} if clause["attr"] is not None else res

    @staticmethod
    def get_clause_attr_type(attr):
        """
        Returns the first prefix of the given attr or None if there is only
        one branch.
        Examples:
        src.addr -> src
        dst.addr.port.babar -> dst
        addr -> None
        """
        splt = attr.split(".", 1)
        if len(splt) <= 1:
            return None
        return splt[0]

    @classmethod
    def flt_from_clause(cls, clause):
        """
        Returns a MongoDB filter from a clause.
        """
        operators = {
            ":": "$eq",
            "=": "$eq",
            "==": "$eq",
            "!=": "$ne",
            "<": "$lt",
            "<=": "$lte",
            ">": "$gt",
            ">=": "$gte",
            "=~": "$regex",
        }

        if clause["array_mode"] is None and clause["len_mode"] is False:
            if clause["operator"] is None:
                return {clause["attr"]: {"$exists": not clause["neg"]}}
            clause["operator"] = operators[clause["operator"]]
            if clause["attr"] in ["addr", "src.addr", "dst.addr"]:
                res = cls._flt_from_clause_addr(clause)
            else:
                res = cls._flt_from_clause_any(clause)
            return res

        if clause["array_mode"] is not None:
            if clause["operator"] is None:
                raise ValueError("Queries must have an operator in array mode")
            if clause["array_mode"] == "ANY":
                # Mongo performs the "ANY" operation by default
                clause["array_mode"] = None
                return cls.flt_from_clause(clause)
            if clause["array_mode"] == "ALL":
                # Getting entries where every elements of array A match the
                # predicate P is equivalent to get entries where there are NO
                # element of array A which do NOT match the predicate P
                # Remarks:
                # 1. We need make sure that the attribute exists in every
                # entries that we get.
                # 2. In case the criteria is not directly linked to the array
                # values (in other words when array values are dictionaries),
                # we must use $elemMatch on the array attribute.
                attr = clause["attr"]
                array_attr, value_attr = cls._get_longest_array_attr(clause["attr"])
                if array_attr is None:
                    raise ValueError(
                        "%s is not a valid array attribute" % clause["attr"]
                    )
                clause["operator"] = operators[clause["operator"]]
                clause["neg"] = not clause["neg"]
                clause["attr"] = value_attr if value_attr != "" else array_attr
                res = cls._flt_from_clause_any(clause)
                if value_attr != "":
                    # Array values are dictionaries
                    return {
                        "$nor": [
                            {array_attr: {"$elemMatch": res}},
                            {attr: {"$exists": False}},
                        ]
                    }
                return {"$nor": [res, {attr: {"$exists": False}}]}
            if clause["array_mode"] == "NONE":
                # it is equivalent to NOT(ANY)
                clause["neg"] = not clause["neg"]
                clause["array_mode"] = "ANY"
                return cls.flt_from_clause(clause)
            raise NotImplementedError

        # len_mode = True
        if clause["operator"] is None:
            raise ValueError("Queries must have an operator in len mode")

        clause["operator"] = operators[clause["operator"]]
        clause["value"] = int(clause["value"])
        if clause["operator"] == "$regex":
            raise ValueError("Regex are not supported in length mode")

        op = (
            clause["operator"]
            if not clause["neg"]
            else cls._flt_neg_op(clause["operator"])
        )
        if op in ["$eq", "$ne"]:
            res = {"$size": clause["value"]}
            if op == "$ne":
                res = {"$not": res}
            return {clause["attr"]: res}

        # MongoDB does not allow to add a comparison operator with $size
        # We can use the $exists operator on the n-th element of an array
        # to determine if it has at least n elements.
        # In case of '<' or '<=' comparison, we need to enforce the
        # existence of the attribute.

        # Assign to each operator a couple (value offset, existence)
        op_values = {
            "$lt": (-1, False),
            "$lte": (0, False),
            "$gt": (0, True),
            "$gte": (-1, True),
        }
        return {
            "%s.%d"
            % (clause["attr"], clause["value"] + op_values[op][0]): {
                "$exists": op_values[op][1]
            },
            clause["attr"]: {"$exists": True},
        }

    @classmethod
    def flt_from_query(cls, query):
        """
        Returns a MongoDB filter from the given query object.
        """
        clauses = query.clauses
        flt = {}
        and_clauses = []
        for and_clause in clauses:
            or_clauses = []
            for or_clause in and_clause:
                or_clauses.append(cls.flt_from_clause(or_clause))
            if len(or_clauses) > 1:
                and_clauses.append({"$or": or_clauses})
            elif len(or_clauses) == 1:
                and_clauses.append(or_clauses[0])
        if len(and_clauses) > 1:
            flt = {"$and": and_clauses}
        elif len(and_clauses) == 1:
            flt = and_clauses[0]
        return flt

    @classmethod
    def from_filters(
        cls,
        filters,
        limit=None,
        skip=0,
        orderby="",
        mode=None,
        timeline=False,
        after=None,
        before=None,
        precision=None,
    ):
        """
        Overloads from_filters method from MongoDB.
        It transforms flow.Query object returned by super().from_filters
        in MongoDB filter and returns it.
        Note: limit, skip, orderby, mode, timeline are IGNORED. They are
        present only for compatibility reasons.
        """
        query = super().from_filters(
            filters,
            limit=limit,
            skip=skip,
            orderby=orderby,
            mode=mode,
            timeline=timeline,
        )
        flt = cls.flt_from_query(query)
        times_filter = {}
        if after:
            times_filter.setdefault("start", {})["$gte"] = after
        if before:
            times_filter.setdefault("start", {})["$lt"] = before
        if precision:
            times_filter["duration"] = precision
        if times_filter:
            flt = cls.flt_and(flt, {"times": {"$elemMatch": times_filter}})
        return flt

    def host_details(self, node_id):
        """
        Returns details about an host with the given address.
        Details means a dict : {
            in_flows: set() => incoming flows (proto, dport),
            out_flows: set() => outcoming flows (proto, dport),
            elt: {} => data about the host
            clients: set() => hosts which talked to this host
            servers: set() => hosts which this host talked to
        }
        It is currently done in memory. It should be done using the
        aggregation framework.
        """
        g = {
            "in_flows": set(),
            "elt": {},
            "out_flows": set(),
            "clients": set(),
            "servers": set(),
        }
        g["elt"]["addr"] = node_id
        flt = self.search_flow_host(node_id)
        res = self.db[self.columns[self.column_flow]].find(flt)
        for row in res:
            internal_addr = self.ip2internal(node_id)
            if g["elt"].get("firstseen", None) is None or g["elt"].get(
                "firstseen"
            ) > row.get("firstseen"):
                g["elt"]["firstseen"] = row.get("firstseen")
            if g["elt"].get("lastseen", None) is None or g["elt"].get(
                "lastseen"
            ) < row.get("lastseen"):
                g["elt"]["lastseen"] = row.get("lastseen")
            # if it is an outcoming flow
            if (
                row.get("src_addr_0") == internal_addr[0]
                and row.get("src_addr_1") == internal_addr[1]
            ):
                g["out_flows"].add((row.get("proto"), row.get("dport", None)))
                g["servers"].add(
                    self.internal2ip([row.get("dst_addr_0"), row.get("dst_addr_1")])
                )
            else:
                # if it is an incoming flow
                g["in_flows"].add((row.get("proto"), row.get("dport", None)))
                g["clients"].add(
                    self.internal2ip([row.get("src_addr_0"), row.get("src_addr_1")])
                )
        g["clients"] = list(g["clients"])
        g["servers"] = list(g["servers"])
        g["in_flows"] = list(g["in_flows"])
        g["out_flows"] = list(g["out_flows"])
        return g

    def flow_details(self, flow_id):
        """
        Returns details about a flow with the given ObjectId.
        Details mean : {
            elt: {} => basic data about the flow,
            meta: [] => meta entries corresponding to the flow
        }
        """
        g = {"elt": {}}
        res = self.db[self.columns[self.column_flow]].find(
            {"_id": bson.ObjectId(flow_id)}
        )
        if res.count() != 1:
            return None
        row = res[0]
        g["elt"] = self._edge2json_default(row)["data"]
        g["elt"]["firstseen"] = row.get("firstseen")
        g["elt"]["lastseen"] = row.get("lastseen")
        if row.get("meta", None):
            g["meta"] = row.get("meta")
        return g

    def flow_daily(self, precision, flt, after=None, before=None):
        """
        Returns a generator within each element is a dict
        {
            flows: [("proto/dport", count), ...]
            time_in_day: time
        }.
        """
        pipeline = []

        if flt:
            pipeline.append({"$match": flt})

        # Unwind timeslots
        pipeline.append({"$unwind": "$times"})

        match = {}
        # Keep only timeslots with the given precision
        match["times.duration"] = precision
        # We need to ensure after and before filters after $unwind
        if after:
            match.setdefault("times.start", {})["$gte"] = after
        if before:
            match.setdefault("times.start", {})["$lt"] = before

        pipeline.append({"$match": match})

        # Project time in hours, minutes, seconds
        pipeline.append(
            {
                "$project": {
                    "hour": {"$hour": "$times.start"},
                    "minute": {"$minute": "$times.start"},
                    "second": {"$second": "$times.start"},
                    "proto": 1,
                    "dport": 1,
                    "count": 1,
                    "type": 1,
                }
            }
        )

        # Group by (hour, minutes, seconds), push proto/dport
        pipeline.append(
            {
                "$group": {
                    "_id": {
                        "hour": "$hour",
                        "minute": "$minute",
                        "second": "$second",
                    },
                    "fields": {
                        "$push": {
                            "proto": "$proto",
                            "dport": "$dport",
                            "type": "$type",
                        }
                    },
                }
            }
        )

        # Sort by time ascending
        pipeline.append({"$sort": {"_id.hour": 1, "_id.minute": 1, "_id.second": 1}})

        log_pipeline(pipeline)
        res = self.db[self.columns[self.column_flow]].aggregate(pipeline, cursor={})

        for entry in res:
            flows = {}
            for fields in entry["fields"]:
                if fields.get("proto") in ["tcp", "udp"]:
                    entry_name = "%(proto)s/%(dport)d" % fields
                elif fields.get("type") is not None:
                    entry_name = "%(proto)s/%(type)d" % fields
                else:
                    entry_name = fields["proto"]
                flows.setdefault(entry_name, 0)
                flows[entry_name] += 1
            res = {
                "flows": list(flows.items()),
                "time_in_day": datetime.time(
                    hour=entry["_id"]["hour"],
                    minute=entry["_id"]["minute"],
                    second=entry["_id"]["second"],
                ),
            }
            yield res

    def reduce_precision(
        self, new_precision, flt=None, before=None, after=None, current_precision=None
    ):
        base = config.FLOW_TIME_BASE

        new_duration = new_precision
        current_duration = current_precision
        if current_duration is not None:
            if base % current_duration != 0:
                raise ValueError(
                    "Base %d must be a multiple of current "
                    "precision." % config.FLOW_TIME_BASE
                )
            base %= new_duration
            # validate new duration
            if new_duration <= current_duration:
                raise ValueError(
                    "New precision value must be greater than " "current one."
                )
            if new_duration % current_duration != 0:
                raise ValueError(
                    "New precision must be a multiple of current " "precision."
                )

        # Create the update bulk
        bulk = self.db[self.columns[self.column_flow]].initialize_unordered_bulk_op()

        if flt is None:
            flt = self.flt_empty

        for flw in self._get_cursor(self.columns[self.column_flow], flt):
            # We must ensure the unicity of timeslots in a flow
            new_times = set()
            for timeslot in flw["times"]:
                # This timeslot may not need to be changed
                if (
                    (
                        current_duration is not None
                        and timeslot["duration"] != current_duration
                    )
                    or (
                        current_duration is None
                        and (
                            new_duration <= timeslot["duration"]
                            or new_duration % timeslot["duration"] != 0
                            or base % timeslot["duration"] != 0
                        )
                    )
                    or (before is not None and timeslot["start"] >= before)
                    or (after is not None and timeslot["start"] < after)
                ):
                    new_times.add((timeslot["start"], timeslot["duration"]))
                    continue
                # Compute new timeslot
                new_tslt = self._get_timeslot(timeslot["start"], new_duration, base)
                new_times.add((new_tslt["start"], new_tslt["duration"]))
            # Build a list of timeslot dicts from new timeslots set
            timeslots = [
                {"start": timeslot[0], "duration": timeslot[1]}
                for timeslot in new_times
            ]
            bulk.find({"_id": flw["_id"]}).update({"$set": {"times": timeslots}})
        # Execute bulk
        try:
            start_time = time.time()
            result = bulk.execute()
            newtime = time.time()
            update_rate = result.get("nModified") / float(newtime - start_time)
            utils.LOGGER.debug(
                "%d updates, %f/sec", result.get("nModified"), update_rate
            )
        except pymongo.errors.InvalidOperation:
            utils.LOGGER.debug("No operation to execute.")

    def list_precisions(self):
        pipeline = [
            {"$unwind": "$times"},
            {"$group": {"_id": "$times.duration"}},
            {"$sort": {"_id": 1}},
        ]

        res = self.db[self.columns[self.column_flow]].aggregate(pipeline, cursor={})
        for entry in res:
            yield entry["_id"]

    @staticmethod
    def should_switch_hosts(flw):
        """
        Returns True if flow hosts should be switched, False otherwise.
        """
        if len(flw["dports"]) <= 5:
            return False

        # Try to avoid reversing scans
        if flw["_id"]["proto"] == "tcp":
            ratio = 0
            divisor = 0
            if flw["cspkts"] > 0:
                ratio += flw["csbytes"] / float(flw["cspkts"])
                divisor += 1
            if flw["scpkts"] > 0:
                ratio += flw["scbytes"] / float(flw["scpkts"])
                divisor += 1

            avg = ratio / float(divisor)
            if avg < 50:
                # TCP segments were almost empty, which most of the time
                # corresponds to an active scan.
                return False

        return True

    def cleanup_flows(self):
        """
        Cleanup flows which source and destination seem to have been switched.
        """
        # Get flows which have a unique source port
        pipeline = [
            {
                "$match": {
                    "sports": {"$size": 1},
                    "dport": {"$gt": 128},
                }
            },
            {"$unwind": "$sports"},
            {"$unwind": "$times"},
            {
                "$group": {
                    "_id": {
                        "src_addr_0": "$src_addr_0",
                        "src_addr_1": "$src_addr_1",
                        "dst_addr_0": "$dst_addr_0",
                        "dst_addr_1": "$dst_addr_1",
                        "proto": "$proto",
                        "sport": "$sports",
                    },
                    "dports": {"$addToSet": "$dport"},
                    "_ids": {"$addToSet": "$_id"},
                    "cspkts": {"$sum": "$cspkts"},
                    "scpkts": {"$sum": "$scpkts"},
                    "csbytes": {"$sum": "$csbytes"},
                    "scbytes": {"$sum": "$scbytes"},
                    "firstseen": {"$min": "$firstseen"},
                    "lastseen": {"$max": "$lastseen"},
                    "count": {"$sum": "$count"},
                    "times": {"$addToSet": "$times"},
                }
            },
        ]
        res = self.db[self.columns[self.column_flow]].aggregate(pipeline)
        bulk = self.start_bulk_insert()
        counter = 0
        for rec in res:
            rec["_id"]["src_addr"] = self.internal2ip(
                [rec["_id"]["src_addr_0"], rec["_id"]["src_addr_1"]]
            )
            rec["_id"]["dst_addr"] = self.internal2ip(
                [rec["_id"]["dst_addr_0"], rec["_id"]["dst_addr_1"]]
            )
            if self.should_switch_hosts(rec):
                # new_rec is the new reversed flow
                new_rec = {}
                new_rec["src_addr_0"] = rec["_id"]["dst_addr_0"]
                new_rec["src_addr_1"] = rec["_id"]["dst_addr_1"]
                new_rec["dst_addr_0"] = rec["_id"]["src_addr_0"]
                new_rec["dst_addr_1"] = rec["_id"]["src_addr_1"]
                new_rec["dport"] = rec["_id"]["sport"]
                new_rec["proto"] = rec["_id"]["proto"]
                findspec = self._get_flow_key(new_rec)

                # Note that sizes and packet numbers have been switched
                # between src and dst
                updatespec = {
                    "$min": {"firstseen": rec["firstseen"]},
                    "$max": {"lastseen": rec["lastseen"]},
                    "$inc": {
                        "cspkts": rec["scpkts"],
                        "scpkts": rec["cspkts"],
                        "csbytes": rec["scbytes"],
                        "scbytes": rec["csbytes"],
                        "count": rec["count"],
                    },
                    "$addToSet": {"sports": {"$each": rec["dports"]}},
                }

                # Remove old flows
                removespec = {"_id": {"$in": rec["_ids"]}}

                if config.FLOW_TIME:
                    updatespec["$addToSet"]["times"] = {"$each": rec["times"]}

                if config.DEBUG:
                    f_str = "%s (%d) -- %s --> %s (%s)" % (
                        rec["_id"]["src_addr"],
                        rec["_id"]["sport"],
                        rec["_id"]["proto"],
                        rec["_id"]["dst_addr"],
                        ",".join([str(elt) for elt in rec["dports"]]),
                    )
                    utils.LOGGER.debug("Switch flow hosts: %s", f_str)

                bulk.find(findspec).upsert().update(updatespec)
                bulk.find(removespec).remove()
                counter += len(rec["_ids"])

        self.bulk_commit(bulk)
        utils.LOGGER.debug("%d flows switched.", counter)
