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

from ivre.db import DB, DBFlow, DBData
from ivre import config
from ivre import utils

import datetime
import operator
import random
import re
import sys
import time
import warnings

from sqlalchemy import create_engine, func, join, select, Column, \
    DateTime, Integer, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import UserDefinedType
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Context(Base):
    __tablename__ = "context"
    id = Column(Integer, primary_key=True)
    name = Column(String(32), index=True)

class Host(Base):
    __tablename__ = "host"
    id = Column(Integer, primary_key=True)
    context = Column(Integer, ForeignKey('context.id'))
    addr = Column(postgresql.INET)
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    __table_args__ = (
        Index('addr_context', 'addr', 'context', unique=True),
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

# Data

class Country(Base):
    __tablename__ = "country"
    code = Column(String(2), primary_key=True)
    name = Column(String(64), index=True)


class AS(Base):
    __tablename__ = "aut_sys"
    num = Column(Integer, primary_key=True)
    name = Column(String(128), index=True)


class Point(UserDefinedType):

    def get_col_spec(self):
        return "POINT"

    def bind_expression(self, bindvalue):
        return func.Point_In(bindvalue, type_=self)

    def bind_processor(self, dialect):
        def process(value):
            if value is None:
                return None
            return "%f,%f" % value
        return process

    def result_processor(self, dialect, coltype):
        def process(value):
            if value is None:
                return None
            return tuple(float(val) for val in value[6:-1].split(','))
        return process


class Location(Base):
    __tablename__ = "location"
    id = Column(Integer, primary_key=True)
    country_code = Column(String(2), ForeignKey('country.code'))
    city = Column(String(64))
    coordinates = Column(Point) #, index=True
    area_code = Column(Integer)
    metro_code = Column(Integer)
    postal_code = Column(String(16))
    region_code = Column(String(2), index=True)
    __table_args__ = (
        Index('country_city', 'country_code', 'city'),
    )


class AS_Range(Base):
    __tablename__ = "as_range"
    id = Column(Integer, primary_key=True)
    aut_sys = Column(Integer, ForeignKey('aut_sys.num'))
    start = Column(postgresql.INET, index=True)
    stop = Column(postgresql.INET)


class Location_Range(Base):
    __tablename__ = "location_range"
    id = Column(Integer, primary_key=True)
    location_id = Column(Integer, ForeignKey('location.id'))
    start = Column(postgresql.INET, index=True)
    stop = Column(postgresql.INET)


class PostgresDB(DB):
    def __init__(self, url):
        self.dburl = url

    @property
    def db(self):
        """The DB connection."""
        try:
            return self._db
        except AttributeError:
            self._db = create_engine(self.dburl, echo=config.DEBUG)
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

    @staticmethod
    def fmt_results(fields, result):
        return dict((fld, value) for fld, value in zip(fields, result)
                    if value is not None)


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

class PostgresDBData(PostgresDB, DBData):
    indexes = {}

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBData.__init__(self)

    def feed_geoip_city(self, fname, feedipdata=None,
                        createipdata=False):
        with open(fname) as fdesc:
            bulk = self.start_bulk_insert()
            # Skip the two first lines
            fdesc.readline()
            fdesc.readline()
            for line in fdesc:
                values = self.parse_line_city(line, feedipdata=feedipdata,
                                              createipdata=createipdata)
                values['start'] = utils.int2ip(values['start'])
                values['stop'] = utils.int2ip(values['stop'])
                bulk.append(Location_Range.__table__.insert().values(
                    values
                ))
            bulk.close()

    def feed_country_codes(self, fname):
        with open(fname) as fdesc:
            bulk = self.start_bulk_insert()
            for line in fdesc:
                bulk.append(Country.__table__.insert().values(
                    **self.parse_line_country_codes(line)
                ))
            # missing from GeoIP file
            bulk.append(Country.__table__.insert().values(
                code="AN", name="Netherlands Antilles",
            ))
            bulk.close()

    def feed_city_location(self, fname):
        with open(fname) as fdesc:
            bulk = self.start_bulk_insert()
            # Skip the two first lines
            fdesc.readline()
            fdesc.readline()
            for line in fdesc:
                values = self.parse_line_city_location(line)
                values['id'] = values.pop('location_id')
                if 'loc' in values:
                    values['coordinates'] = tuple(
                        values.pop('loc')['coordinates']
                    )
                bulk.append(Location.__table__.insert().values(**values))
            bulk.close()

    def feed_geoip_asnum(self, fname, feedipdata=None,
                         createipdata=False):
        with open(fname) as fdesc:
            bulk = self.start_bulk_insert()
            asnums = set()
            for line in fdesc:
                values = self.parse_line_asnum(line)
                if values['as_num'] not in asnums:
                    bulk.append(AS.__table__.insert().values(
                        num=values['as_num'], name=values.get('as_name'),
                    ))
                    asnums.add(values['as_num'])
                bulk.append(AS_Range.__table__.insert().values(
                    aut_sys=values['as_num'],
                    start=utils.int2ip(values['start']),
                    stop=utils.int2ip(values['stop']),
                ))
            bulk.close()

    def country_byip(self, addr):
        data_range = select([Location_Range.stop, Location_Range.location_id])\
                     .where(Location_Range.start <= addr)\
                     .order_by(Location_Range.start.desc())\
                     .limit(1)\
                     .cte("data_range")
        location = select([Location.country_code])\
                   .where(Location.id == select([data_range.c.location_id]))\
                   .limit(1)\
                   .cte("location")
        data = self.db.execute(
            select([data_range.c.stop, location.c.country_code, Country.name])\
            .where(location.c.country_code == Country.code)
        ).fetchone()
        if utils.ip2int(addr) <= utils.ip2int(data[0]):
            return self.fmt_results(
                ['country_code', 'country_name'],
                data[1:],
            )

    def location_byip(self, addr):
        data_range = select([Location_Range.stop, Location_Range.location_id])\
                     .where(Location_Range.start <= addr)\
                     .order_by(Location_Range.start.desc())\
                     .limit(1)\
                     .cte("data_range")
        location = select([Location])\
                   .where(Location.id == select([data_range.c.location_id]))\
                   .limit(1)\
                   .cte("location")
        data = self.db.execute(
            select([data_range.c.stop, location.c.coordinates,
                    location.c.country_code, Country.name, location.c.city,
                    location.c.area_code, location.c.metro_code,
                    location.c.postal_code, location.c.region_code])\
            .where(location.c.country_code == Country.code)
        ).fetchone()
        if utils.ip2int(addr) <= utils.ip2int(data[0]):
            return self.fmt_results(
                ['coordinates', 'country_code', 'country_name', 'city',
                 'area_code', 'metro_code', 'postal_code', 'region_code'],
                data[1:],
            )

    def as_byip(self, addr):
        data_range = select([AS_Range.stop, AS_Range.aut_sys])\
                  .where(AS_Range.start <= addr)\
                  .order_by(AS_Range.start.desc())\
                  .limit(1)\
                  .cte("data_range")
        data = self.db.execute(
            select([data_range.c.stop, data_range.c.aut_sys, AS.name])\
            .where(AS.num == select([data_range.c.aut_sys]))
        ).fetchone()
        if utils.ip2int(addr) <= utils.ip2int(data[0]):
            return self.fmt_results(
                ['as_num', 'as_name'],
                data[1:],
            )

    def ipranges_bycountry(self, code):
        """Returns a generator of every (start, stop) IP ranges for a country
given its ISO-3166-1 "alpha-2" code or its name."""
        if len(code) != 2:
            return self.db.execute(
                select([Location_Range.start, Location_Range.stop])\
                .select_from(join(join(Location, Location_Range), Country))\
                .where(Country.name == code)
            )
        return self.db.execute(
            select([Location_Range.start, Location_Range.stop])\
            .select_from(join(Location, Location_Range))\
            .where(Location.country_code == code)
        )

    def ipranges_byas(self, asnum):
        """Returns a generator of every (start, stop) IP ranges for an
Autonomous System given its number or its name.

        """
        if isinstance(asnum, basestring):
            try:
                if asnum.startswith('AS'):
                    asnum = int(asnum[2:])
                else:
                    asnum = int(asnum)
            except ValueError:
                # lookup by name
                return self.db.execute(
                    select([AS_Range.start, AS_Range.stop])\
                    .select_from(join(AS, AS_Range))\
                    .where(AS.name == asnum)
                )
        return self.db.execute(
            select([AS_Range.start, AS_Range.stop])\
            .where(AS_Range.aut_sys == asnum)
        )
