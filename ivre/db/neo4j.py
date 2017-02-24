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

"""This sub-module contains functions to interact with the Neo4j
databases.

"""

from ivre.db import DB, DBFlow
from ivre import config
from ivre import utils

import datetime
import operator
import random
import re
import sys
import time
import warnings
from py2neo import Graph, Node, Relationship, GraphError
from py2neo import http
from py2neo.database import cypher_escape
from py2neo.database.status import TransientError
from py2neo.types import remote

http.socket_timeout = 3600
# We are aware of that, let's just ignore it for now
warnings.filterwarnings("ignore",
        "Map literals returned over the Neo4j REST interface are ambiguous.*",
        module="py2neo.database")

class Neo4jDB(DB):
    values = re.compile('{([^}]+)}')

    DATE_FIELDS = ['firstseen', 'lastseen']
    TIMEFMT = '%Y-%m-%d %H:%M:%S.%f'

    def __init__(self, url):
        self.dburl = url

    @property
    def db(self):
        """The DB connection."""
        try:
            return self._db
        except AttributeError:
            self._db = Graph(self.dburl)
            return self._db

    @property
    def db_version(self):
        """The tuple representing the database version"""
        try:
            return self._db_version
        except:
            self._db_version = self.db.neo4j_version
        return self._db_version

    def drop(self):
        for query in ["MATCH (n:%s) DETACH DELETE n" % label
                      for label in self.node_labels]:
            self.db.run(query)

        for query in ["DROP INDEX ON :%s(%s)" % (nodelabel, pprty)
                      for nodelabel, properties in self.indexes.iteritems()
                      for pprty in properties]:
            try:
                self.db.run(query)
            except GraphError:
                pass

    def init(self):
        self.drop()
        self.create_indexes()

    def create_indexes(self):
        for label, attrs in self.indexes.iteritems():
            for attr in attrs:
                self.db.schema.create_index(label, attr)

    def ensure_indexes(self):
        for label, attrs in self.indexes.iteritems():
            cur_indexes = self.db.schema.get_indexes(label)
            for attr in attrs:
                if attr not in cur_indexes:
                    self.db.schema.create_index(label, attr)

    def start_bulk_insert(self, size=None, retries=0):
        return BulkInsert(self.db, size=size, retries=retries)

    @staticmethod
    def query(*args, **kargs):
        return Query(*args, **kargs)

    def run(self, query):
        if config.DEBUG_DB:
            utils.LOGGER.debug("DB:Executing query:\n%s\nWith params: %s",
                               query.query, query.params)
            t1 = time.time()
        res = self.db.run(query.query, **query.params)
        if config.DEBUG_DB:
            utils.LOGGER.debug("DB:Result in %s", time.time() - t1)
        return res

    @classmethod
    def from_dbdict(cls, d):
        d.pop("__key__", None)
        for k in d:
            d[k] = cls.from_dbprop(k, d[k])

    @classmethod
    def from_dbprop(cls, prop, val):
        if prop in cls.DATE_FIELDS:
            if isinstance(val, float):
                val = datetime.datetime.fromtimestamp(val)
            if isinstance(val, basestring):
                val = datetime.datetime.strptime(val, cls.TIMEFMT)
            elif isinstance(val, datetime.datetime):
                pass
            else:
                raise ValueError(
                        "Expected float or str for date field %s" % prop)
        return val

    @classmethod
    def to_dbdict(cls, d):
        d.pop("__key__", None)
        for k in d:
            d[k] = cls.to_dbprop(k, d[k])
        seen_time = d.get("start_time", d.get("end_time", None))
        if seen_time and "seen_time" not in d:
            d["seen_time"] = cls._date_round(seen_time)

    @classmethod
    def to_dbprop(cls, prop, val):
        if prop in cls.DATE_FIELDS and isinstance(val, basestring):
            val = datetime.datetime.strptime(val, cls.TIMEFMT)
        # Intentional double if: str -> datetime -> float
        if isinstance(val, datetime.datetime):
            val = utils.datetime2timestamp(val)
        return val

    @classmethod
    def _date_round(cls, date):
        if isinstance(date, datetime.datetime):
            ts = utils.datetime2timestamp(date)
        else:
            ts = date
        ts = ts - (ts % config.FLOW_TIME_PRECISION)
        if isinstance(date, datetime.datetime):
            return datetime.datetime.fromtimestamp(ts)
        else:
            return ts


class Query(object):
    operators = {
        ":": "=",
        "=": "=",
        "==": "=",
        "!=": "<>",
        "<": "<",
        "<=": "<=",
        ">": ">",
        ">=": ">=",
        "=~": "=~",
    }
    operators_re = re.compile('|'.join(re.escape(x) for x in operators))
    identifier = re.compile('^[a-zA-Z][a-zA-Z0-9_]*$')
    or_re = re.compile('^OR|\\|\\|$')

    def __init__(self, src=None, link=None, dst=None, ret=None,
                 limit=None, skip=None, **params):
        self.labels = {}
        if src is not None:
            self.labels["src"] = src
        if link is not None:
            self.labels["link"] = link
        if dst is not None:
            self.labels["dst"] = dst
        self.clauses = []
        self._params = params
        self.ret = "RETURN *" if ret is None else ret
        self.orderby = ""
        self.idcounter = -1
        self.meta_link = False
        self.meta_src = False
        self.meta_dst = False
        self.limit = limit
        self.skip = skip

    def nextid(self):
        self.idcounter += 1
        return "internal_id_%04x" % self.idcounter

    @property
    def mline(self):
        line = ["MATCH (src%s)-[:SEND]->(link%s)-[:TO]->(dst%s)" % tuple(
            ":%s" % self.labels[key] if key in self.labels else ""
            for key in ["src", "link", "dst"]
        )]
        src_dst_meta = self.meta_src and self.meta_dst
        opt = "OPTIONAL " if src_dst_meta else ""
        if self.meta_link:
            line.append("MATCH (link)-->(linkmeta:Intel)")
        if self.meta_src:
            line.append("%sMATCH (src)-->(srcmeta:Intel)" % opt)
        if self.meta_dst:
            line.append("%sMATCH (dst)-->(dstmeta:Intel)" % opt)
        if src_dst_meta:
            # in this case, there will be an OPTIONAL MATCH, adding the "WITH"
            # trick allows to append a WHERE that is _always_ evaluated.
            # Otherwise, the WHERE is only evaluated on match. Sad.
            # FIXME: this workaround is a bit dirty, a better system should be
            # found.
            line.append("WITH *")
        return "\n".join(line)

    @property
    def params(self):
        Neo4jDB.to_dbdict(self._params)
        return self._params

    def add_clause(self, clause=None, **params):
        if config.DEBUG and any(key in self._params for key in params):
            keys = [key for key in set(params).intersection(self._params)
                    if params[key] != self._params[key]]
            if keys:
                utils.LOGGER.warning(
                    'Parameter%s overwritten:%s',
                    "s" if len(keys) > 1 else "",
                    ("\n%" % "\n".join(
                        '  - %r [%r -> %r]' % (key, self._params[key], params[key])
                        for key in keys
                    )) if keys else "",
                )
        self._params.update(params)
        if isinstance(clause, basestring):
            self.clauses.append(clause)
        elif clause is None:
            pass
        else:
            self.clauses.extend(clause)
        return self

    def _add_clause_from_filter(self, flt, mode="node"):
        """Returns a WHERE clause (tuple (query, parameters)) from a single
        filter (no OR).

        Devs: `flt` **can** be set from an untrusted source.

        """
        if not flt:
            return None

        if flt[0] in "-!~":
            neg = True
            flt = flt[1:]
        else:
            neg = False

        array_mode = None
        len_mode = None
        if flt.startswith("ANY "):
            array_mode = "ANY"
            flt = flt[4:]
        elif flt.startswith("ALL "):
            array_mode = "ALL"
            flt = flt[4:]
        elif flt.startswith("ONE "):
            array_mode = "SINGLE"
            flt = flt[4:]
        elif flt.startswith("NONE "):
            array_mode = "NONE"
            flt = flt[5:]
        elif flt.startswith("LEN "):
            len_mode = "LENGTH"
            flt = flt[4:]

        try:
            operator = self.operators_re.search(flt).group()
        except AttributeError:
            operator = None
            attr = flt
        else:
            attr, value = [elt.strip() for elt in flt.split(operator, 1)]
            value = utils.str2pyval(value)
        if attr[0] in "@#":
            qtype = attr[0]
            attr = attr[1:]
        else:
            qtype = "@"
        try:
            # Sorry for the horrendous code -- jalet
            elements, attr = attr.rsplit('.', 1)
            if elements == "meta":
                if mode == "edge":
                    elements = ["linkmeta"]
                    self.meta_link = True
                elif mode == "node":
                    elements = ["srcmeta", "dstmeta"]
                    self.meta_src = True
                    self.meta_dst = True
            elif elements == "src.meta":
                elements = ["srcmeta"]
                self.meta_src = True
            elif elements == "dst.meta":
                elements = ["dstmeta"]
                self.meta_dst = True
            else:
                elements = [elements]
        except ValueError:
            if mode == "node":
                elements = ["src", "dst"]
            elif mode == "edge":
                elements = ["link"]
            else:
                raise ValueError()
        else:
            assert all(self.identifier.search(elt) for elt in elements)
        assert self.identifier.search(attr)
        if operator is None:
            if qtype == "@":
                return (
                    "%s(%s)" % (
                        "NOT " if neg else "",
                        " OR ".join(
                            "EXISTS(`%s`.`%s`)" % (elt, attr)
                            for elt in elements
                        ),
                    ),
                    {},
                )
            if qtype == "#":
                identifier = self.nextid()
                return (
                    "%s(%s)" % (
                        "NOT " if neg else "",
                        " OR ".join(
                            "{%s} IN labels(`%s`)" % (identifier, elt)
                            for elt in elements
                        ),
                    ),
                    {identifier: attr},
                )
        if qtype == "@":
            identifier = self.nextid()
            operator = self.operators[operator]

            clauses = []
            for elt in elements:
                attr_expr = "%s.%s" % tuple(cypher_escape(s) for s in (elt, attr))
                if array_mode is not None:
                    lval = "x"
                elif len_mode is not None:
                    lval = "%s(%s)" % (len_mode, attr_expr)
                else:
                    lval = attr_expr
                clause_part = "%s %s {%s}" % (lval, operator, identifier)
                if array_mode is not None:
                    if array_mode in ["ALL", "ANY", "SINGLE"]:
                        prereq = "LENGTH(%s) <> 0 AND" % attr_expr
                    elif array_mode in ["NONE"]:
                        prereq = "LENGTH(%s) = 0 OR"
                    clause_part = "%s %s(x IN %s WHERE %s)" % (
                                  prereq, array_mode, attr_expr, clause_part)
                clauses.append(clause_part)

            clause = " OR ".join(clauses)

            if neg:
                clause = "%s OR NOT (%s)" % (
                    " OR ".join("NOT EXISTS(`%s`.`%s`)" % (elt, attr)
                                for elt in elements),
                    clause,
                )
            value = Neo4jDB.to_dbprop(attr, value)
            return (
                "%s" % clause,
                {identifier: value},
            )
        raise ValueError()

    splitter_re = re.compile('(?:[^\\s"]|"(?:\\\\.|[^"])*")+')

    @classmethod
    def _split_filter_or(cls, flt):
        current = []
        for subflt in cls.splitter_re.finditer(flt):
            subflt = subflt.group()
            if cls.or_re.search(subflt):
                yield " ".join(current)
                current = []
            else:
                current.append(subflt)
        yield " ".join(current)

    def add_clause_from_filter(self, flt, mode="node"):
        """ADD a WHERE clause from a node filter.

        Devs: `flt` **can** be set from an untrusted source.

        """
        clauses, params = [], {}
        for subflt in self._split_filter_or(flt):
            if subflt:
                subclause, subparams = self._add_clause_from_filter(subflt, mode=mode)
                clauses.append(subclause)
                params.update(subparams)
        return self.add_clause(
            "WHERE %s" % " OR ".join("(%s)" % clause for clause in clauses),
            **params
        )

    @property
    def all_clauses(self):
        cur_where = []
        for clause in self.clauses:
            if clause.upper().startswith('WHERE '):
                cur_where.append(clause[6:].lstrip())
            else:
                if cur_where:
                    yield "WHERE %s" % " AND ".join("(%s)" % whc for whc in cur_where)
                    cur_where = []
                yield clause
        if cur_where:
            yield "WHERE %s" % " AND ".join("(%s)" % whc for whc in cur_where)

    @property
    def query(self):
        return "%s\n%s\n%s\n%s\n%s%s" % (
            self.mline,
            "\n".join(self.all_clauses),
            self.ret,
            self.orderby,
            # FIXME: param?
            "SKIP %d" % self.skip if self.skip else "",
            " LIMIT %d" % self.limit if self.limit else "",
        )


class BulkInsert(object):
    """A Neo4J transaction, with automatic commits"""

    def __init__(self, db, size=None, retries=0):
        """`size` is the number of inserts per commit and `retries` is the
        number of times to retry a failed transaction (when inserting
        concurrently for example). 0 is forever, 1 does not retry, 2 retries
        once, etc.
        """
        self.db = db
        self.queries = []
        self.start_time = time.time()
        self.count = 0
        self.commited_count = 0
        self.size = config.NEO4J_BATCH_SIZE if size is None else size
        self.retries = retries

    def append(self, *args, **kargs):
        self.queries.append((args, kargs))
        self.count += 1
        if self.count >= self.size:
            self.commit()

    def _commit_transaction(self):
        try_count = self.retries
        # Concurrent insertion handling
        while True:
            try:
                transaction = self.db.begin()
                for args, kargs in self.queries:
                    if len(args) > 1:
                        Neo4jDB.to_dbdict(args[1])
                    transaction.run(*args, **kargs)
                transaction.commit()
                break
            # FIXME: there might be more exceptions to catch
            except TransientError as e:
                try_count -= 1
                if self.retries == 0 or try_count > 0:
                    utils.LOGGER.debug(
                        "DB:Concurrent access error (%r), retrying.", e,
                    )
                    # Reduce contention with a little sleep
                    time.sleep(random.random()/10)
                else:
                    raise

    def commit(self, renew=True):
        self._commit_transaction()
        newtime = time.time()
        rate = self.size / (newtime - self.start_time)
        utils.LOGGER.debug("%d inserts, %f/sec (total %d)\n",
                           self.count, rate, self.commited_count + self.count)
        if renew:
            self.start_time = newtime
            self.queries = []
            self.commited_count += self.count
            self.count = 0

    def close(self):
        self.commit(renew=False)


class Neo4jDBFlow(Neo4jDB, DBFlow):
    indexes = {
        "Host": ["addr"],
        "Mac": ["addr"],
        "Wlan": ["addr"],
        "DNS": ["__key__", "name"],
        "Flow": ["__key__", "proto", "dport", "type"],
        "HTTP": ["__key__"],
        "SSL": ["__key__"],
        "SSH": ["__key__"],
        "SIP": ["__key__"],
        "Modbus": ["__key__"],
        "SNMP": ["__key__"],
        "Time": ["__key__", "time"],
        "Name": ["__key__", "name"],
        "Software": ["__key__", "name", "version_major", "version_minor"],
    }
    node_labels = ["Host", "Mac", "Wlan", "DNS", "Flow", "HTTP", "SSL", "SSH",
                   "SIP", "Modbus", "SNMP", "Time", "Name", "Software"]

    LABEL2NAME = {}

    def __init__(self, url):
        Neo4jDB.__init__(self, url)
        DBFlow.__init__(self)

    @staticmethod
    def query(*args, **kargs):
        return Query(*args, src="Host", dst="Host", **kargs)

    def query_flow(self, flt=None, project=None, action=None):
        query = self.query(
            ret="RETURN %s" % "src, flow, dst" if action is None else action,
        )
        if flt is not None:
            query.add_clause("WHERE %s" % flt)
        if project is not None:
            query.add_clause("WITH %s" % ", ".join(
                fld if alias is None else "%s AS %s" % (fld, alias)
                for fld, alias in project))
        utils.LOGGER.debug("DB:%s", query.query)
        return self.run(query)

    @classmethod
    def _update_times(cls, elt, on_create_set, on_match_set,
                      start=None, end=None):
        if start is None:
            start = "{start_time}"
        if end is None:
            end = "{end_time}"
        on_create_set.append("%s.firstseen = %s" % (elt, start))
        on_match_set.append("%(elt)s.firstseen = CASE WHEN %(elt)s.firstseen > "
                            "%(start)s THEN %(start)s ELSE "
                            "%(elt)s.firstseen END" %
                            {"elt":elt, "start": start})
        on_create_set.append("%s.lastseen = %s" % (elt, end))
        on_match_set.append("%(elt)s.lastseen = CASE WHEN %(elt)s.lastseen < "
                            "%(end)s THEN %(end)s ELSE "
                            "%(elt)s.lastseen END" %
                            {"elt":elt, "end": end})

    @classmethod
    def _update_time_seen(cls, elt):
        if config.FLOW_TIME:
            # Experimental and possibly useless
            if config.FLOW_TIME_FULL_RANGE:
                return (
                    "FOREACH (stime IN RANGE(\n"
                    "           {start_time} - ({start_time} %% %(prec)d),\n"
                    "           {end_time} - ({end_time} %% %(prec)d),\n"
                    "           %(prec)d) | \n"
                    "    MERGE (t:Time {time: stime})\n"
                    "    MERGE (%(elt)s)-[:SEEN]->(t))"
                ) % { "elt": elt, "prec": config.FLOW_TIME_PRECISION }
            else:
                return (
                    "MERGE (t:Time {time: {seen_time}})\n"
                    "MERGE (%s)-[:SEEN]->(t)" % elt
                )
        else:
            return ""

    @classmethod
    def _set_props(cls, elt, props, set_list):
        props = utils.normalize_props(props)
        set_list.extend(["%s.%s = %s" % (elt, attr, cnt)
                              for attr, cnt in props.iteritems()])

    @classmethod
    def _update_counters(cls, elt, counters, on_create_set, on_match_set):
        counters = utils.normalize_props(counters)
        counters["count"] = 1
        cls._set_props(elt, counters, on_create_set)
        on_match_set.extend(
            ["%(elt)s.%(key)s = COALESCE(%(elt)s.%(key)s, 0) + %(value)s" % (
             {"elt": elt,
              "key": key,
              "value": value}
        ) for key, value in counters.iteritems()])

    @classmethod
    def _update_accumulators(cls, elt, accumulators,
                             on_create_set, on_match_set):
        on_create_set.extend(["%s.%s = [%s]" % (elt, field, srcfield)
                              for field, (srcfield, _) in
                              accumulators.iteritems()])
        on_match_set.extend([
            ("%(elt)s.%(field)s = CASE WHEN " +
             ("" if maxvalue is None else
              "SIZE(%(elt)s.%(field)s) > %(maxvalue)d OR ") +
             "%(srcfield)s IN %(elt)s.%(field)s THEN %(elt)s.%(field)s ELSE " +
             "COALESCE(%(elt)s.%(field)s, []) + %(srcfield)s END") % {
                 "elt": elt, "field": field, "srcfield": srcfield,
                 "maxvalue": maxvalue
             } for field, (srcfield, maxvalue) in accumulators.iteritems()
        ])

    @classmethod
    def _gen_merge_elt(cls, elt, labels, attrs):
        attrs = utils.normalize_props(attrs)
        return "%s:%s {%s}" % (
            elt,
            ":".join(labels),
            ", ".join("%s: %s" % (key, value)
                      for key, value in attrs.iteritems())
        )

    def _key_from_attrs(self, attrs, src="src", dst="dst", link=None):
        # Sort by key to canonize the expression
        skeys = sorted(attrs.iteritems(), key=operator.itemgetter(0))
        # Include all keys in the aggregated key
        str_func = "str" if self.db_version[0] < 3 else "toString"
        key = (('ID(%s)+' % src if src else "") +
               '"|"+' +
               ('ID(%s)+' % dst if dst else "") +
               '"-"+' +
               ('ID(%s)+' % link if link else "") +
                '+"|"+'.join(['"-"'] + ["%s(%s)" %
                (str_func, v) for _, v in skeys]))
        return key

    @classmethod
    def _prop_update(cls, elt, props=None, counters=None, accumulators=None,
                         create_clauses=None, match_clauses=None,
                         start_time=None, end_time=None, time=True):
        on_create_set = (create_clauses or [])[:]
        on_match_set = (match_clauses or [])[:]
        # Basic props
        if props:
            cls._set_props(elt, props, on_create_set)
        # handling counters (empty counter still updates the "count" field
        if counters is not None:
            cls._update_counters(elt, counters, on_create_set, on_match_set)
        # handling firstseen & lastseen
        if time:
            cls._update_times(elt, on_create_set, on_match_set,
                              start=start_time, end=end_time)
        # handling accumulators
        if accumulators:
            cls._update_accumulators(elt, accumulators,
                                     on_create_set, on_match_set)

        clauses = []
        if on_create_set:
            clauses.append(
                "ON CREATE SET\n    %s" % ",\n    ".join(on_create_set))
        if on_match_set:
            clauses.append(
                "ON MATCH SET\n    %s" % ",\n    ".join(on_match_set))

        return '\n'.join(clauses)

    def _add_flow(self, labels, keys, elt="link", counters=None,
                  accumulators=None, srcnode=None, dstnode=None, time=True):
        keys = utils.normalize_props(keys)
        if srcnode is None:
            srcnode = (["Host"], {"addr": "{src}"})
        if dstnode is None:
            dstnode = (["Host"], {"addr": "{dst}"})

        key = self._key_from_attrs(keys)

        query = [
            self.add_host("src", srcnode[0], srcnode[1], time=time),
            self.add_host("dst", dstnode[0], dstnode[1], time=time),
            "MERGE (%s)" % (
                self._gen_merge_elt(elt, labels, {"__key__": key})),
            "MERGE (%s)<-[:SEND]-(src)" % elt,
            "MERGE (%s)-[:TO]->(dst)" % elt,
        ]

        query.append(self._prop_update(elt, props=keys, counters=counters,
                                       accumulators=accumulators, time=time))
        query.append(self._update_time_seen(elt))
        return "\n".join(query)

    def add_flow(self, *args, **kargs):
        kargs.setdefault("counters", [])
        query = self._add_flow(*args, **kargs)
        #utils.LOGGER.debug("DB:%s", query)
        return query

    @classmethod
    def add_host(cls, elt="h", labels=None, keys=None, time=True):
        if keys is None:
            keys = {"addr": "{src}"}
        if labels is None:
            labels = ["Host"]

        query = ["MERGE (%s)" % cls._gen_merge_elt(elt, labels, keys)]
        # handling firstseen & lastseen
        query.append(cls._prop_update(elt, time=time))
        return "\n".join(query)

    def add_flow_metadata(self, labels, linktype, keys, flow_keys, counters=None,
                          accumulators=None, time=True, flow_labels=["Flow"]):
        counters = {} if counters is None else counters
        query = [self._add_flow(flow_labels, flow_keys)]
        keys = utils.normalize_props(keys)
        key = self._key_from_attrs(keys, src=None, dst=None)

        query.extend([
            "MERGE (%s)" % (
                self._gen_merge_elt("meta", labels, {"__key__": key})),
            "MERGE (link)-[:%s]->(meta)" % (linktype,),
        ])
        query.append(self._prop_update("meta", props=keys, counters=counters,
                                       create_clauses=["meta:Intel"],
                                       accumulators=accumulators, time=time))
        return "\n".join(query)

    def add_host_metadata(self, labels, linktype, keys, host_keys=None,
                          counters=None, accumulators=None, time=True):
        counters = {} if counters is None else counters
        query = [self.add_host("h", keys=host_keys)]
        keys = utils.normalize_props(keys)
        key = self._key_from_attrs(keys, src=None, dst=None)

        query.extend([
            "MERGE (%s)" % (
                self._gen_merge_elt("meta", labels, {"__key__": key})),
            "MERGE (h)-[:%s]->(meta)" % (linktype,),
        ])
        query.append(self._prop_update("meta", props=keys, counters=counters,
                                       create_clauses=["meta:Intel"],
                                       accumulators=accumulators, time=time))
        return "\n".join(query)

    @classmethod
    def _cleanup_record(cls, elt):
        for k, v in elt.iteritems():
            if isinstance(v, list) and len(v) == 1 and \
                    isinstance(v[0], dict) and \
                    all(x == None for x in v[0].itervalues()):
                elt[k] = []

        cls.from_dbdict(cls._get_props(elt["elt"]))
        new_meta = {}
        if isinstance(elt["meta"], list):
            for rec in elt["meta"]:
                if rec["info"] is None and rec["link"] is None:
                    continue
                info = rec["info"] or {}
                info_props = cls._get_props(info)
                link = rec["link"] or {}
                link_tag = link.get("type", link.get("labels", [""])[0]).lower()
                link_props = cls._get_props(link)
                key = "%s%s" % (
                        "_".join(label
                                 for label in cls._get_labels(info, info_props)
                                 if label != "Intel"),
                                "_%s" % link_tag if link_tag else ""
                )
                new_data = dict(("%s_%s" % (link_tag, k), v)
                                for k, v in link_props.iteritems())
                new_data.update(info_props)
                new_meta.setdefault(key, []).append(new_data)
            if new_meta:
                elt["meta"] = new_meta
                for reclist in new_meta.itervalues():
                    for rec in reclist:
                        cls.from_dbdict(rec)

        if ("times" in elt["meta"] and elt["meta"]["times"] and
                isinstance(elt["meta"]["times"], list) and
                isinstance(elt["meta"]["times"][0], float)):
            elt["meta"]["times"] = map(datetime.datetime.fromtimestamp,
                                       elt["meta"]["times"])

        if not elt["meta"]:
            del(elt["meta"])

    @staticmethod
    def _time_quad2date(time_quad):
        """Transforms (year, month, date, hour) into datetime."""
        return datetime.datetime(*time_quad)

    def host_details(self, node_id):
        q = """
        MATCH (n)
        WHERE ID(n) = {nid}
        OPTIONAL MATCH (n)-[sr]->(infos:Intel)
        WITH n, collect(distinct {info: infos, link: sr}) as infos
        OPTIONAL MATCH (n)<-[:TO]-(in:Flow)<-[:SEND]-()
        WITH n, infos,
             COLLECT(DISTINCT [in.proto, COALESCE(in.dport, in.type)]) as in_flows
        OPTIONAL MATCH (n)-[:SEND]->(out:Flow)-[:TO]->()
        WITH n, infos, in_flows,
             COLLECT(DISTINCT [out.proto, COALESCE(out.dport, out.type)]) as out_flows
        OPTIONAL MATCH (n)-[:SEND]->(:Flow)-[:TO]->(dst:Host)
        WITH n, infos, in_flows, out_flows,
             COLLECT(DISTINCT dst.addr) as servers
        OPTIONAL MATCH (n)<-[:TO]-(:Flow)<-[:SEND]-(src:Host)
        WITH n, infos, in_flows, out_flows, servers,
             COLLECT(DISTINCT src.addr) as clients
        RETURN {elt: n, meta: infos,
                in_flows: in_flows, out_flows: out_flows,
                servers: servers, clients: clients}
        """
        node = dict(self.db.run(q, nid=node_id).evaluate())
        self._cleanup_record(node)
        return node

    def flow_details(self, node_id):
        q = """
        MATCH (n)
        WHERE ID(n) = {nid}
        OPTIONAL MATCH (n)-[sr]->(infos:Intel)
        WITH n, collect(distinct {info: infos, link: sr}) as infos
        RETURN {elt: n, meta: infos}
        """
        node = dict(self.db.run(q, nid=node_id).evaluate())
        self._cleanup_record(node)
        return node

    @classmethod
    def _filters2cypher(cls, queries, limit=None, skip=0, orderby="", mode=None,
                        timeline=False):
        limit = config.WEB_GRAPH_LIMIT if limit is None else limit
        query = cls.query(
            skip=skip, limit=limit,
        )
        for flt_type in ["node", "edge"]:
            for flt in queries.get("%ss" % flt_type, []):
                query.add_clause_from_filter(flt, mode=flt_type)

        if mode == "talk_map":
            query.add_clause('WITH src, dst, COUNT(link) AS t, '
                             'COLLECT(DISTINCT LABELS(link)) AS labels, '
                             'HEAD(COLLECT(ID(link))) AS ref')
            query.add_clause(
                "WITH {elt: src, meta: []} as src,\n"
                "     {meta: [],\n"
                "      elt: {\n"
                "          data: { count: t, labels: labels },\n"
                "          metadata: {labels: ['TALK'], id: ref}\n"
                "      }} as link,\n"
                "     {elt: dst, meta: []} as dst\n"
            )

        elif mode == "flow_map":
            query.add_clause('WITH src, dst, '
                             'COLLECT(DISTINCT [link.proto, link.dport]) AS flows, '
                             'HEAD(COLLECT(ID(link))) AS ref')
            query.add_clause('WITH src, dst, flows, ref, SIZE(flows) AS t')
            query.add_clause(
                "WITH {elt: src, meta: []} as src,\n"
                "     {meta: [],\n"
                "      elt: {\n"
                "          data: { count: t, flows: flows },\n"
                "          metadata: {labels: ['MERGED_FLOWS'], id: ref}\n"
                "      }} as link,\n"
                "     {elt: dst, meta: []} as dst\n"
            )
        else:
            if timeline:
                query.add_clause(
                    "MATCH (link)-[:SEEN]->(t:Time)\n"
                    "WITH src, link, dst,\n"
                    "     COLLECT(t.time) AS times\n"
                    "WITH {elt: src, meta: [] } as src,\n"
                    "     {elt: link, meta: {times: times} } as link,\n"
                    "     {elt: dst, meta: [] } as dst\n"
                )
            else:
                query.add_clause(
                    "WITH {elt: src, meta: [] } as src,\n"
                    "       {elt: link, meta: [] } as link,\n"
                    "       {elt: dst, meta: [] } as dst\n"
                )
        query.ret = "RETURN src, link, dst"

        if orderby == "src":
            query.orderby = "ORDER BY src.elt.addr"
        elif orderby == "dst":
            query.orderby = "ORDER BY dst.elt.addr"
        elif orderby == "flow":
            # FIXME: link.elt.code?
            query.orderby = "ORDER BY link.elt.dport, link.elt.proto"
        elif orderby:
            raise ValueError(
                    "Unsupported orderby (should be 'src', 'dst' or 'flow')")
        return query

    @staticmethod
    def _flow2name(ref, labels, properties):
        proto = properties.get("proto", "Flow")
        attr = properties.get("dport", properties.get("type", None))
        return "%s%s" % (proto, "/%s" % attr if attr is not None else "")

    @classmethod
    def _elt2name(cls, ref, labels, properties):
        name = None
        for label in labels:
            for attr in cls.LABEL2NAME.get(label, []):
                if isinstance(attr, str) or isinstance(attr, unicode):
                    if attr in properties:
                        name = properties[attr]
                        break
                else:
                    # It's a function
                    name = attr(ref, labels, properties)
                    break
            if name is not None:
                break
        if name is None:
            name = ", ".join(labels)
        return name

    @classmethod
    def _node2json(cls, ref, labels, properties):
        name = cls._elt2name(ref, labels, properties)
        return {
            "id": ref,
            "label": name,
            "labels": labels,
            "data": properties,
            "x": random.random(),
            "y": random.random(),
        }

    @classmethod
    def _edge2json(cls, ref, from_ref, to_ref, labels, properties):
        name = cls._elt2name(ref, labels, properties)
        return {
            "id": ref,
            "label": name,
            "labels": labels,
            "data": properties,
            "source": from_ref,
            "target": to_ref,
        }

    @staticmethod
    def _get_props(elt, meta=None):
        if isinstance(elt, Node) or isinstance(elt, Relationship):
            props = elt.properties
        else:
            props = elt.get("data", {})
        if meta:
            props["meta"] = meta
        return props

    @staticmethod
    def _get_ref(elt, props):
        if isinstance(elt, Node):
            return int(remote(elt).ref.split('/', 1)[-1])
        else:
            return elt["metadata"]["id"]

    @staticmethod
    def _get_labels(elt, props):
        if isinstance(elt, Node):
            return list(elt.labels())
        elif isinstance(elt, Relationship):
            return [elt.type()]
        else:
            meta = elt["metadata"]
            return meta["labels"] if "labels" in meta else [meta["type"]]

    @classmethod
    def cursor2json_iter(cls, cursor):
        """Transforms a neo4j returned by executing a query into an iterator of
        {src: <dict>, flow: <dict>, dst: <dict>}.
        """
        for src, flow, dst in cursor:
            map(cls._cleanup_record, (src, flow, dst))
            src_props = cls._get_props(src["elt"], src.get("meta"))
            src_ref = cls._get_ref(src["elt"], src_props)
            src_labels = cls._get_labels(src["elt"], src_props)
            src_node = cls._node2json(src_ref, src_labels, src_props)

            dst_props = cls._get_props(dst["elt"], dst.get("meta"))
            dst_ref = cls._get_ref(dst["elt"], dst_props)
            dst_labels = cls._get_labels(dst["elt"], dst_props)
            dst_node = cls._node2json(dst_ref, dst_labels, dst_props)

            flow_props = cls._get_props(flow["elt"], flow.get("meta"))
            flow_ref = cls._get_ref(flow["elt"], flow_props)
            flow_labels = cls._get_labels(flow["elt"], flow_props)
            flow_node = cls._edge2json(flow_ref, src_ref, dst_ref, flow_labels,
                                       flow_props)
            yield {"src": src_node, "dst": dst_node, "flow": flow_node}


    @classmethod
    def cursor2json_graph(cls, cursor):
        """Transforms a cursor of triplets of (node, edge, node) to a graph of
        hosts and flows. All the elements are of the form
        {elt: <neo4j element-like>, meta: [<list of metadata>]}
        This is an internal API that is very likely to change.
        """
        # Allows for a static layout
        random.seed(0)
        g = {"nodes": [], "edges": []}
        done = set()

        for row in cls.cursor2json_iter(cursor):
            for node, typ in ((row["src"], "nodes"),
                              (row["flow"], "edges"),
                              (row["dst"], "nodes")):
                if node["id"] not in done:
                    g[typ].append(node)
                    done.add(node["id"])
        return g

    @classmethod
    def cursor2count(cls, cursor):
        res = cursor.next
        # Compat py2neo < 3
        try:
            res = res()
        except TypeError:
            pass
        return {"clients": res['clients'],
                "flows": res['flows'],
                "servers": res['servers']}

    @classmethod
    def _cursor2flow_daily(cls, cursor):
        for row in cursor:
            yield {"flow": "%s/%s" % tuple(row["flow"]),
                   "time_in_day":
                        datetime.datetime.fromtimestamp(row["time_in_day"]),
                   "count": row["count"]}

    @classmethod
    def _cursor2top(cls, cursor):
        for row in cursor:
            yield {
                "fields": row["fields"],
                "count": row["count"],
                "collected": row["collected"],
            }

    def from_filters(self, filters, limit=None, skip=0, orderby="", mode=None,
                     timeline=False):
        cypher_query = self._filters2cypher(filters, limit=limit, skip=skip,
                                            orderby=orderby, mode=mode,
                                            timeline=timeline)
        return cypher_query

    def to_graph(self, query):
        res = self.cursor2json_graph(self.run(query))
        return res

    def to_iter(self, query):
        return self.cursor2json_iter(self.run(query))

    def count(self, query):
        old_limit = query.limit
        old_skip = query.skip
        old_ret = query.ret
        old_orderby = query.orderby
        query.limit = None
        query.skip = None
        query.ret = (
            "RETURN COUNT(DISTINCT src) as clients,\n"
            "       COUNT(DISTINCT link) as flows,\n"
            "       COUNT(DISTINCT dst) as servers\n"
        )
        query.orderby = ""
        counts = self.cursor2count(self.run(query))
        query.limit = old_limit
        query.skip = old_skip
        query.ret = old_ret
        query.orderby = old_orderby
        return counts

    def flow_daily(self, query):
        """Returns a dict of {flow: {time_in_day: count}}

        WARNING/FIXME: this mutates the query
        """
        query.add_clause(
            "WITH src.elt as src, link.elt as link, dst.elt as dst\n"
            "MATCH (link)-[:SEEN]->(t:Time)\n"
            "WITH src, link, dst, t, (t.time % 86400) as time_in_day\n"
            "WITH [link.proto, COALESCE(link.dport, link.type)] AS flow,\n"
            "     time_in_day, COUNT(*) AS count\n"
        )
        query.ret = "RETURN flow, time_in_day, count"
        query.orderby = "ORDER BY flow[0], flow[1], time_in_day"
        counts = self._cursor2flow_daily(self.run(query))
        return counts

    def top(self, query, fields, collect=None, sumfields=None):
        """Returns an iterator of:
        {fields: <fields>, count: <number of occurrence or sum of sumfields>,
         collected: <collected fields>}.

        WARNING/FIXME: this mutates the query
        """
        collect = collect or []
        sumfields = sumfields or []
        for flist in fields, collect, sumfields:
            for i in range(len(flist)):
                if flist[i].startswith("link."):
                    flist[i] = flist[i].replace("flow.", "link.")
                if "." not in flist[i]:
                    flist[i] = "link.%s" % flist[i]
                flist[i] = '.'.join(map(cypher_escape, flist[i].split(".")))

        cy_fields = "[%s]" % ', '.join(fields)
        cy_collect = "[%s]" % ', '.join(collect)
        cy_sumfields = "SUM(%s)" % ' + '.join(sumfields)
        query.add_clause(
            "WITH src.elt as src, link.elt as link, dst.elt as dst\n"
            "WITH %s as fields, %s as count, %s as collected" %
            (cy_fields,
             "COUNT(*)" if not sumfields else cy_sumfields,
             "NULL" if not collect else "COLLECT(DISTINCT %s)" % cy_collect)
        )
        query.ret = "RETURN fields, count, collected"
        query.orderby = "ORDER BY count DESC"
        top = self._cursor2top(self.run(query))
        return top

    def cleanup_flows(self):
        """Cleanup mistakes when predicting client/server ports"""
        self._cleanup_phase1()
        self._cleanup_phase2()
        self._sanity_check()

    def _sanity_check(self):
        keys = {"dport": "f.dport", "proto": "f.proto"}
        key = self._key_from_attrs(keys)
        q = (
            "MATCH (src:Host)-[:SEND]->(f:Flow)-[:TO]->(dst:Host)\n"
            "WHERE f.proto IN ['udp', 'tcp'] AND\n"
            "     f.__key__ <> %s\n"
            "RETURN COUNT(f)\n" % key
        )
        cur = self.db.run(q)
        res = cur.evaluate()
        # TODO: fix it
        if res != 0:
            raise ValueError("Invalid db state: incoherent keys")

    def _cleanup_phase1(self):
        keys = {"dport": "sport", "proto": "proto"}
        counters = {
            "cspkts": "cspkts",
            "scpkts": "scpkts",
            "csbytes": "csbytes",
            "scbytes": "scbytes",
            "sports": "dports",
        }

        new_key = self._key_from_attrs(keys, src="dst", dst="src")
        set_clause = self._prop_update(
                "new_f", props=keys, counters=counters, start_time="firstseen",
                end_time="lastseen", time=time,
        )

        q = """
MATCH (f:Flow)
WHERE f.dport > 128 and SIZE(f.sports) = 1
MATCH (f)<-[:SEND]-(src:Host)
MATCH (f)-[:TO]->(dst:Host)
WITH src, dst, f.proto as proto,
    MIN(f.firstseen) as firstseen, MAX(f.lastseen) as lastseen,
    HEAD(f.sports) as sport, COLLECT(DISTINCT f.dport) as dports,
    SUM(f.scpkts) as scpkts, SUM(f.scbytes) as scbytes,
    SUM(f.cspkts) as cspkts, SUM(f.csbytes) as csbytes
WHERE size(dports) > 5
MERGE (%s)
MERGE (new_f)-[:TO]->(src)
MERGE (new_f)<-[:SEND]-(dst)
%s
WITH *
MATCH (src)-[:SEND]->(df:Flow {sports: [sport]})-[:TO]->(dst)
%s
DETACH DELETE df
        """ % (
            self._gen_merge_elt("new_f", ["Flow"], {"__key__": new_key}),
            set_clause,
            "MATCH (df)-[:SEEN]->(t:Time)\n"
            "MERGE (new_f)-[:SEEN]->(t)" if config.FLOW_TIME else "",
        )
        if config.DEBUG_DB:
            utils.LOGGER.debug("DB:Fixing client/server ports...")
            tstamp = time.time()
        self.db.run(q)
        if config.DEBUG_DB:
            utils.LOGGER.debug("DB:Took %f secs", (time.time() - tstamp))
            tstamp = time.time()

    def _cleanup_phase2(self):
        keys = {"dport": "sport", "proto": "proto"}
        counters = {
                "cspkts": "old_f.cspkts",
                "scpkts": "old_f.scpkts",
                "csbytes": "old_f.csbytes",
                "scbytes": "old_f.scbytes",
        }
        accumulators = {"sports": ("old_f.dport", 5)}

        new_key = self._key_from_attrs(keys, src="src", dst="d2")
        set_clause = self._prop_update(
                "new_f", props=keys, counters=counters,
                accumulators=accumulators,
                start_time="firstseen", end_time="lastseen", time=time,
        )

        q = """
MATCH (f:Flow)
WHERE (f.proto = 'tcp' or f.proto = 'udp') and f.dport > 128
    and SIZE(f.sports) = 1
MATCH (f)<-[:SEND]-(dst:Host)
MATCH (f)-[:TO]->(src:Host)
WITH src, f.proto as proto,
    MIN(f.firstseen) as firstseen, MAX(f.lastseen) as lastseen,
    HEAD(f.sports) as sport, COLLECT(DISTINCT f.dport) as dports,
    COUNT(DISTINCT dst) as n_dst
WHERE size(dports) > 5 OR n_dst > 1 OR (src)<-[:TO]-(:Flow {dport: sport})
MATCH (src)<-[:TO]-(old_f:Flow {sports: [sport], proto: proto})
WITH src, proto, sport, firstseen, lastseen,
    COUNT(DISTINCT old_f.dport) as n_dports
WHERE n_dports > 2
MATCH (src)<-[:TO]-(old_f:Flow {sports: [sport], proto: proto})<-[:SEND]-(d2)
MERGE (%s)
MERGE (new_f)-[:TO]->(d2)
MERGE (new_f)<-[:SEND]-(src)
%s
WITH *
%s
DETACH DELETE old_f
        """ % (
            self._gen_merge_elt("new_f", ["Flow"], {"__key__": new_key}),
            set_clause,
            "MATCH (old_f)-[:SEEN]->(t:Time)\n"
            "MERGE (new_f)-[:SEEN]->(t)" if config.FLOW_TIME else "",
        )

        if config.DEBUG_DB:
            utils.LOGGER.debug("DB:Second (slower) pass...")
            tstamp = time.time()
        self.db.run(q)
        if config.DEBUG:
            utils.LOGGER.debug("DB:Took %f secs", time.time() - tstamp)

Neo4jDBFlow.LABEL2NAME.update({
    "Host": ["addr"],
    "Flow": [Neo4jDBFlow._flow2name],
})
