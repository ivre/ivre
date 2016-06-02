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
from py2neo import Graph, GraphError
from py2neo import http
from py2neo.database.status import TransientError

http.socket_timeout = 3600

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
        return self.db.run(query.query, properties=query.params)

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

    @classmethod
    def to_dbprop(cls, prop, val):
        if prop in cls.DATE_FIELDS and isinstance(val, basestring):
            val = datetime.datetime.strptime(val, cls.TIMEFMT)
        # Intentional double if: str -> datetime -> float
        if isinstance(val, datetime.datetime):
            val = utils.datetime2timestamp(val)
        return val

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

    def __init__(self, src=None, link=None, dst=None, ret=None, **params):
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
        self.idcounter = -1
        self.meta_link = False
        self.meta_src = False
        self.meta_dst = False

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
                sys.stderr.write('WARNING: parameter%s overwritten:'
                                 '\n' % ("s" if len(keys) > 1 else ""))
                for key in keys:
                    sys.stderr.write('  - %r [%r -> %r]'
                                     '\n' % (key, self._params[key],
                                             params[key]))
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
        try:
            operator = self.operators_re.search(flt).group()
        except AttributeError:
            operator = None
            attr = flt
        else:
            attr, value = [elt.strip() for elt in flt.split(operator, 1)]
            value = utils.str2pyval(value)
        if attr[0] in "-!~":
            neg = True
            attr = attr[1:]
        else:
            neg = False
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
            clause = " OR ".join(
                "`%s`.`%s` %s {%s}"
                "" % (elt, attr, operator, identifier)
                for elt in elements
            )
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

    splitter_re = re.compile('(?:[^\\s,"]|"(?:\\\\.|[^"])*")+')

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
        return "%s\n%s\n%s" % (self.mline,
                               "\n".join(self.all_clauses),
                               self.ret)


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
                    if config.DEBUG:
                        sys.stderr.write(
                            "DB concurrent access error (%r), retrying.\n" % e)
                    # Reduce contention with a little sleep
                    time.sleep(random.random()/10)
                else:
                    raise

    def commit(self, renew=True):
        self._commit_transaction()
        newtime = time.time()
        rate = self.size / (newtime - self.start_time)
        if config.DEBUG:
            sys.stderr.write(
                "%d inserts, %f/sec (total %d)\n" % (
                    self.count, rate, self.commited_count + self.count)
            )
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
    }
    node_labels = ["Host", "Mac", "Wlan", "DNS", "Flow", "HTTP", "SSL", "SSH",
                   "SIP", "Modbus", "SNMP"]

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
        if config.DEBUG:
            sys.stderr.write(query.query + "\n")
        return self.run(query)

    def count_flow(self, flt=None):
        return self.query_flow(action="COUNT(flow)").next['COUNT(flow)']

    def distinct_flow(self, fields, flt=None):
        if isinstance(fields, basestring):
            return (x[fields] for x in
                    self.query_flow(action="DISTINCT %s" % fields))
        return self.query_flow(action="DISTINCT %s" % ", ".join(fields))

    def top_flow(self, field, sumfield=None, flt=None, limit=10):
        return self.query_flow(
            flt=flt,
            project=[
                ("DISTINCT %s" % field, "field"),
                ("SUM(%s)" % "1" if sumfield is None else sumfield, "count"),
            ],
            action="* ORDER BY count DESC%s" % ("" if limit is None else " LIMIT %d" % limit),
        )

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
        return "\n".join(query)

    def add_flow(self, *args, **kargs):
        kargs.setdefault("counters", [])
        query = self._add_flow(*args, **kargs)
        #if config.DEBUG:
        #    sys.stderr.write(query + "\n")
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

    def cleanup_flows(self):
        """Cleanup mistakes when predicting client/server ports"""
        self._cleanup_phase1()
        self._cleanup_phase2()
        self._sanity_check()

    def _sanity_check(self):
        keys = {"dport": "f.dport", "proto": "f.proto"}
        key = self._key_from_attrs(keys)
        q = """
        MATCH (src:Host)-[:SEND]->(f:Flow)-[:TO]->(dst:Host)
        WHERE f.proto IN ["udp", "tcp"] AND
             f.__key__ <> %s
        RETURN COUNT(f)
        """ % key
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
DETACH DELETE df
        """ % (
            self._gen_merge_elt("new_f", ["Flow"], {"__key__": new_key}),
            set_clause,
        )
        if config.DEBUG:
            sys.stderr.write("Fixing client/server ports...\n")
            tstamp = time.time()
        self.db.run(q)
        if config.DEBUG:
            sys.stderr.write("Took %f secs\n" % (time.time() - tstamp))
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
DETACH DELETE old_f
        """ % (
            self._gen_merge_elt("new_f", ["Flow"], {"__key__": new_key}),
            set_clause,
        )

        if config.DEBUG:
            sys.stderr.write("Second (slower) pass...\n")
            tstamp = time.time()
        self.db.run(q)
        if config.DEBUG:
            sys.stderr.write("Took %f secs\n" % (time.time() - tstamp))
