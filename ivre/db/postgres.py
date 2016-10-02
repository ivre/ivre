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

"""This sub-module contains functions to interact with PostgreSQL
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

from sqlalchemy import Column, DateTime, Integer, ForeignKey, String,\
                       create_engine, Index, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Host(Base):
    __tablename__ = "host"
    id = Column(Integer, primary_key=True)
    source = Column(String(32), index=True, default="")
    addr = Column(postgresql.INET)
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    __table_args__ = (
        Index('category_addr', 'source', 'addr', unique=True),
    )

class Flow(Base):
    __tablename__ = "flow"
    id = Column(Integer, primary_key=True)
    proto = Column(String(32), index=True)
    dport = Column(Integer, index=True)
    src = Column(Integer, ForeignKey('host.id'))
    dst = Column(Integer, ForeignKey('host.id'))
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    scpkts = Column(Integer)
    scbytes = Column(Integer)
    cspkts = Column(Integer)
    csbytes = Column(Integer)
    sports = Column(postgresql.ARRAY(Integer))
    __table_args__ = (
        #Index('host_idx_tag_addr', 'tag', 'addr', unique=True),
    )

class PostgresDB(DB):
    def __init__(self, url):
        self.dburl = url

    @property
    def db(self):
        """The DB connection."""
        try:
            return self._db
        except AttributeError:
            self._db = create_engine(self.dburl)
            return self._db

    def drop(self):
        Base.metadata.drop_all(self.db)

    def init(self):
        self.drop()
        Base.metadata.create_all(self.db)
        #self.create_indexes()

    def create_indexes(self):
        raise NotImplementedError()

    def ensure_indexes(self):
        raise NotImplementedError()

    def start_bulk_insert(self, size=None, retries=0):
        return BulkInsert(self.db)

    @staticmethod
    def query(*args, **kargs):
        raise NotImplementedError()

    def run(self, query):
        raise NotImplementedError()

    @classmethod
    def from_dbdict(cls, d):
        raise NotImplementedError()

    @classmethod
    def from_dbprop(cls, prop, val):
        raise NotImplementedError()

    @classmethod
    def to_dbdict(cls, d):
        raise NotImplementedError()

    @classmethod
    def to_dbprop(cls, prop, val):
        raise NotImplementedError()

    # FIXME: move this method
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


class BulkInsert(object):
    """A PostgreSQL transaction, with automatic commits"""

    def __init__(self, db, size=None, retries=0):
        """`size` is the number of inserts per commit and `retries` is the
        number of times to retry a failed transaction (when inserting
        concurrently for example). 0 is forever, 1 does not retry, 2 retries
        once, etc.
        """
        self.db = db
        self.start_time = time.time()
        self.count = 0
        self.commited_count = 0
        self.size = config.POSTGRES_BATCH_SIZE if size is None else size
        self.retries = retries
        self.conn = db.connect()
        self.trans = self.conn.begin()

    def append(self, query):
        s_query = str(query)
        params = query.parameters
        query.parameters = None
        self.queries.setdefault(s_query,
                                (query, []))[1].append(params)
        if len(self.queries[s_query][1]) >= self.size:
            self.commit(query=s_query)

    def commit_transaction(self, query=None, renew=True):
        if query is None:
            last = len(self.queries) - 1
            for i, query in enumerate(self.queries.keys()):
                self.commit(query=query, renew=True if i < last else renew)
            return
        q_query, params = self.queries.pop(query)
        self.conn.execute(q_query, *params)
        self.trans.commit()

    def commit(self, renew=True):
        self.commit_transaction()
        newtime = time.time()
        rate = self.size / (newtime - self.start_time)
        if config.DEBUG:
            sys.stderr.write(
                "%d inserts, %f/sec (total %d)\n" % (
                    self.count, rate, self.commited_count + self.count)
            )
        if renew:
            self.start_time = newtime
            self.commited_count += self.count
            self.count = 0
            self.trans = self.conn.begin()

    def close(self):
        self.commit(renew=False)
        self.conn.close()


class PostgresDBFlow(PostgresDB, DBFlow):
    indexes = {}

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBFlow.__init__(self)

    @staticmethod
    def query(*args, **kargs):
        raise NotImplementedError()

    def add_flow(self, labels, keys, counters=None, accumulators=None,
                 srcnode=None, dstnode=None, time=True):
        raise NotImplementedError()

    @classmethod
    def add_host(cls, labels=None, keys=None, time=True):
        q = postgresql.insert(Host)
        raise NotImplementedError()

    def add_flow_metadata(self, labels, linktype, keys, flow_keys, counters=None,
                          accumulators=None, time=True, flow_labels=["Flow"]):
        raise NotImplementedError()

    def add_host_metadata(self, labels, linktype, keys, host_keys=None,
                          counters=None, accumulators=None, time=True):
        raise NotImplementedError()

    def host_details(self, node_id):
        raise NotImplementedError()

    def flow_details(self, node_id):
        raise NotImplementedError()

    def from_filters(self, filters, limit=None, skip=0, orderby="", mode=None,
                     timeline=False):
        raise NotImplementedError()

    def to_graph(self, query):
        raise NotImplementedError()

    def to_iter(self, query):
        raise NotImplementedError()

    def count(self, query):
        raise NotImplementedError()

    def flow_daily(self, query):
        raise NotImplementedError()

    def top(self, query, fields, collect=None, sumfields=None):
        """Returns an iterator of:
        {fields: <fields>, count: <number of occurrence or sum of sumfields>,
         collected: <collected fields>}.
        """
        raise NotImplementedError()

    def cleanup_flows(self):
        raise NotImplementedError()

#Neo4jDBFlow.LABEL2NAME.update({
#    "Host": ["addr"],
#    "Flow": [Neo4jDBFlow._flow2name],
#})
