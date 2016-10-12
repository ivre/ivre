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

from bisect import bisect_left
import codecs
import csv
import datetime
import sys
import struct
import time

from sqlalchemy import create_engine, desc, func, text, column, delete, \
    exists, insert, join, select, update, and_, not_, or_, Column, ForeignKey, \
    Index, Table, ARRAY, Boolean, DateTime, Integer, LargeBinary, String, Text, \
    tuple_
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.types import UserDefinedType
from sqlalchemy.ext.declarative import declarative_base

from ivre.db import DB, DBFlow, DBData, DBNmap
from ivre import config, utils, xmlnmap

Base = declarative_base()

class Context(Base):
    __tablename__ = "context"
    id = Column(Integer, primary_key=True)
    name = Column(String(32))
    __table_args__ = (
        Index('ix_context_name', 'name', unique=True),
    )

class Host(Base):
    __tablename__ = "host"
    id = Column(Integer, primary_key=True)
    context = Column(Integer, ForeignKey('context.id'))
    addr = Column(postgresql.INET)
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    __table_args__ = (
        Index('ix_host_addr_context', 'addr', 'context', unique=True),
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
class GeoIPCSVFile(object):
    def __init__(self, fname, skip=0):
        self.fdesc = codecs.open(fname, encoding='latin-1')
        for _ in xrange(skip):
            self.fdesc.readline()
        self.inp = csv.reader(self.fdesc)
    @staticmethod
    def fixline(line):
        return line
    def read(self, size=None):
        try:
            return '%s\n' % '\t'.join(self.fixline(self.inp.next()))
        except StopIteration:
            return ''
    def readline(self):
        return self.read()
    def __exit__(self, *args):
        self.fdesc.__exit__(*args)
    def __enter__(self):
        return self

class GeoIPCSVLocationFile(GeoIPCSVFile):
    @staticmethod
    def fixline(line):
        return line[:5] + ["%s,%s" % tuple(line[5:7])] + line[7:]

class GeoIPCSVLocationRangeFile(GeoIPCSVFile):
    @staticmethod
    def fixline(line):
        for i in xrange(2):
            line[i] = utils.int2ip(int(line[i]))
        return line

class GeoIPCSVASFile(GeoIPCSVFile):
    @staticmethod
    def fixline(line):
        line = line[2].split(' ', 1)
        return [line[0][2:], '' if len(line) == 1 else line[1]]

class GeoIPCSVASRangeFile(GeoIPCSVFile):
    @staticmethod
    def fixline(line):
        for i in xrange(2):
            line[i] = utils.int2ip(int(line[i]))
        line[2] = line[2].split(' ', 1)[0][2:]
        return line

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
            return tuple(float(val) for val in value[1:-1].split(','))
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
        Index('ix_location_country_city', 'country_code', 'city'),
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


# Nmap

class Association_Scan_ScanFile(Base):
    __tablename__ = 'association_scan_scanfile'
    scan = Column(Integer, ForeignKey('scan.id'), primary_key=True)
    scan_file = Column(LargeBinary(32), ForeignKey('scan_file.sha256'), primary_key=True)

class ScanFile(Base):
    __tablename__ = "scan_file"
    sha256 = Column(LargeBinary(32), primary_key=True)
    args = Column(Text)
    scaninfos = Column(postgresql.JSONB)
    scanner = Column(String(16))
    start = Column(DateTime)
    version = Column(String(16))
    xmloutputversion = Column(String(16))

class Association_Scan_Category(Base):
    __tablename__ = 'association_scan_category'
    scan = Column(Integer, ForeignKey('scan.id'), primary_key=True)
    category = Column(Integer, ForeignKey('category.id'), primary_key=True)

class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(32))
    __table_args__ = (
        Index('ix_category_name', 'name', unique=True),
    )


class Association_Scan_Source(Base):
    __tablename__ = 'association_scan_source'
    scan = Column(Integer, ForeignKey('scan.id'), primary_key=True)
    source = Column(Integer, ForeignKey('source.id'), primary_key=True)

class Source(Base):
    __tablename__ = 'source'
    id = Column(Integer, primary_key=True)
    name = Column(String(32))
    __table_args__ = (
        Index('ix_source_name', 'name', unique=True),
    )

class Script(Base):
    __tablename__ = 'script'
    port = Column(Integer, ForeignKey('port.id'), primary_key=True)
    name = Column(String(64), primary_key=True)
    output = Column(Text)
    data = Column(postgresql.JSONB)

class Port(Base):
    __tablename__ = 'port'
    id = Column(Integer, primary_key=True)
    scan = Column(Integer, ForeignKey('scan.id'))
    port = Column(Integer)
    protocol = Column(String(16))
    state = Column(String(32))
    state_reason = Column(String(32))
    state_reason_ip = Column(postgresql.INET)
    state_reason_ttl = Column(Integer)
    # Service-related fields, _name & _tunnel are part of the unique
    # index
    service_name = Column(String(64))
    service_tunnel = Column(String(16))
    service_product = Column(String(256))
    service_version = Column(String(256))
    service_conf = Column(Integer)
    service_devicetype = Column(String(64))
    service_extrainfo = Column(Text)
    service_hostname = Column(String(256))
    service_ostype = Column(String(64))
    service_fp = Column(Text)
    __table_args__ = (
        Index('ix_port_scan_port', 'scan', 'port', 'protocol', unique=True),
    )

class Hostname(Base):
    __tablename__ = "hostname"
    id = Column(Integer, primary_key=True)
    scan = Column(Integer, ForeignKey('scan.id'))
    domains = Column(ARRAY(String(255)), index=True)
    name = Column(String(255), index=True)
    type = Column(String(16), index=True)
    __table_args__ = (
        Index('ix_hostname_scan_name_type', 'scan', 'name', 'type',
              unique=True),
    )

class Scan(Base):
    __tablename__ = "scan"
    id = Column(Integer, primary_key=True)
    host = Column(Integer, ForeignKey('host.id'))
    info = Column(postgresql.JSONB)
    time_start = Column(DateTime)
    time_stop = Column(DateTime)
    state = Column(String(32))
    state_reason = Column(String(32))
    state_reason_ttl = Column(Integer)
    archive = Column(Integer, nullable=False)
    merge = Column(Boolean, nullable=False)
    __table_args__ = (
        Index('ix_scan_info', 'info', postgresql_using='gin'),
        Index('ix_scan_host_archive', 'host', 'archive', unique=True),
    )


class PostgresDB(DB):
    tables = []
    required_tables = []
    shared_tables = {}
    context_names = [
        "Current-Net",
        "Public",
        "Private",
        "Public",
        "CGN",
        "Public",
        "Loopback",
        "Public",
        "Link-Local",
        "Public",
        "Private",
        "Public",
        "IPv6-to-IPv4",
        "Public",
        "Private",
        "Public",
        "Multicast",
        "Reserved",
        "Broadcast",
    ]
    context_last_ips = [
        utils.ip2int("0.255.255.255"),
        utils.ip2int("9.255.255.255"),
        utils.ip2int("10.255.255.255"),
        utils.ip2int("100.63.255.255"),
        utils.ip2int("100.127.255.255"),
        utils.ip2int("126.255.255.255"),
        utils.ip2int("127.255.255.255"),
        utils.ip2int("169.253.255.255"),
        utils.ip2int("169.254.255.255"),
        utils.ip2int("172.15.255.255"),
        utils.ip2int("172.31.255.255"),
        utils.ip2int("192.88.98.255"),
        utils.ip2int("192.88.99.255"),
        utils.ip2int("192.167.255.255"),
        utils.ip2int("192.168.255.255"),
        utils.ip2int("223.255.255.255"),
        utils.ip2int("239.255.255.255"),
        utils.ip2int("255.255.255.254"),
        utils.ip2int("255.255.255.255"),
    ]

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
        for table in reversed(self.tables):
            table.__table__.drop(bind=self.db, checkfirst=True)
        for table, tabfld, fields in self.shared_tables:
            try:
                self.db.execute(delete(table)\
                                .where(not_(exists(select([1])\
                                                   .where(not_(or_(*(
                                                       tabfld == field
                                                       for field in fields
                                                   ))))
                                )))
                )
            except ProgrammingError:
                pass

    def init(self):
        self.drop()
        for table in self.required_tables:
            table.__table__.create(bind=self.db, checkfirst=True)
        # hack to handle dependencies in self.shared_tables
        need_cont = True
        max_loop = len(self.shared_tables)
        while need_cont and max_loop:
            need_cont = False
            max_loop -= 1
            for table, _, _ in self.shared_tables:
                try:
                    table.__table__.create(bind=self.db, checkfirst=True)
                except ProgrammingError:
                    need_cont = True
        for table in self.tables:
            table.__table__.create(bind=self.db)

    def copy_from(self, *args, **kargs):
        cursor = self.db.raw_connection().cursor()
        conn = self.db.connect()
        trans = conn.begin()
        cursor.copy_from(*args, **kargs)
        trans.commit()
        conn.close()

    def create_tmp_table(self, table):
        cols = [c.copy() for c in table.__table__.columns]
        for c in cols:
            c.index = False
            if c.primary_key:
                c.primary_key = False
                c.index = True
        t = Table("tmp_%s" % table.__tablename__,
                  table.__table__.metadata, *cols,
                  prefixes=['TEMPORARY'])
        t.create(bind=self.db)
        return t

    @staticmethod
    def convert_ip(addr):
        try:
            return utils.int2ip(addr)
        except (TypeError, struct.error):
            return addr

    def flt_and(*args):
        return and_(*args)

    def flt_or(*args):
        return or_(*args)

    def store_host_context(self, addr, context, firstseen, lastseen):
        insrt = postgresql.insert(Context)
        ctxt = self.db.execute(insrt.values(name=context)\
                               .on_conflict_do_update(
                                   index_elements=['name'],
                                   set_={'name': insrt.excluded.name}
                               )\
                               .returning(Context.id)).fetchone()[0]
        insrt = postgresql.insert(Host)
        return self.db.execute(insrt.values(context=ctxt,
                                            addr=addr,
                                            firstseen=firstseen,
                                            lastseen=lastseen)\
                               .on_conflict_do_update(
                                   index_elements=['addr', 'context'],
                                   set_={
                                       'firstseen': func.least(
                                           Host.firstseen,
                                           insrt.excluded.firstseen,
                                         ),
                                       'lastseen': func.greatest(
                                           Host.lastseen,
                                           insrt.excluded.lastseen,
                                       )},
                               )\
                               .returning(Host.id)).fetchone()[0]

    def create_indexes(self):
        raise NotImplementedError()

    def ensure_indexes(self):
        raise NotImplementedError()

    def start_bulk_insert(self, size=None, retries=0):
        return BulkInsert(self.db, size=size, retries=retries)

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

    @classmethod
    def default_context(cls, addr):
        # default case:
        try:
            addr = utils.ip2int(addr)
        except TypeError:
            pass
        return cls.context_names[bisect_left(cls.context_last_ips, addr)]

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """

        if neg:
            return Host.addr != cls.convert_ip(addr)
        return Host.addr == cls.convert_ip(addr)

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        hosts = [cls.convert_ip(host) for host in hosts]
        if neg:
            return Host.addr.notin_(hosts)
        return Host.addr.in_(hosts)

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        start, stop = cls.convert_ip(start), cls.convert_ip(stop)
        if neg:
            return or_(Host.addr < start, Host.addr > stop)
        return and_(Host.addr >= start, Host.addr <= stop)


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
        self.commited_counts = {}
        self.size = config.POSTGRES_BATCH_SIZE if size is None else size
        self.retries = retries
        self.conn = db.connect()
        self.trans = self.conn.begin()
        self.queries = {}

    def append(self, query):
        s_query = str(query)
        params = query.parameters
        query.parameters = None
        self.queries.setdefault(s_query,
                                (query, []))[1].append(params)
        if len(self.queries[s_query][1]) >= self.size:
            self.commit(query=s_query)

    def commit(self, query=None, renew=True):
        if query is None:
            last = len(self.queries) - 1
            for i, query in enumerate(self.queries.keys()):
                self.commit(query=query, renew=True if i < last else renew)
            return
        q_query, params = self.queries.pop(query)
        self.conn.execute(q_query, *params)
        self.trans.commit()
        newtime = time.time()
        l_params = len(params)
        try:
            self.commited_counts[query] += l_params
        except KeyError:
            self.commited_counts[query] = l_params
        rate = l_params / (newtime - self.start_time)
        if config.DEBUG:
            sys.stderr.write(
                "%s\n" % query
            )
            sys.stderr.write(
                "%d inserts, %f/sec (total %d)\n" % (
                    l_params, rate, self.commited_counts[query])
            )
        if renew:
            self.start_time = newtime
            self.trans = self.conn.begin()

    def close(self):
        self.commit(renew=False)
        self.conn.close()


class PostgresDBFlow(PostgresDB, DBFlow):
    tables = [Flow]
    shared_tables = [(Host, Host.id, [Scan.host]),
                     (Context, Context.name, [Host.context])]

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
    tables = [Country, Location, Location_Range, AS, AS_Range]

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBData.__init__(self)

    def feed_geoip_country(self, *_, **__):
        "Country database has been dropped in favor of Location/City"
        pass

    def feed_geoip_city(self, fname, feedipdata=None,
                        createipdata=False):
        with GeoIPCSVLocationRangeFile(fname, skip=2) as fdesc:
            self.copy_from(
                fdesc, Location_Range.__tablename__, null='',
                columns=['start', 'stop', 'location_id'],
            )

    def feed_country_codes(self, fname):
        with GeoIPCSVFile(fname) as fdesc:
            self.copy_from(fdesc, Country.__tablename__, null='')
        # Missing from iso3166.csv file but used in GeoIPCity-Location.csv
        self.db.execute(insert(Country).values(
            code="AN",
            name="Netherlands Antilles",
        ))

    def feed_city_location(self, fname):
        with GeoIPCSVLocationFile(fname, skip=2) as fdesc:
            self.copy_from(
                fdesc, Location.__tablename__, null='',
                columns=['id', 'country_code', 'region_code', 'city',
                         'postal_code', 'coordinates', 'metro_code',
                         'area_code'],
            )

    def feed_geoip_asnum(self, fname, feedipdata=None,
                         createipdata=False):
        with GeoIPCSVASFile(fname) as fdesc:
            tmp = self.create_tmp_table(AS)
            self.copy_from(fdesc, tmp.name, null='')
        self.db.execute(insert(AS).from_select(['num', 'name'],
                                               select([tmp]).distinct("num")))
        with GeoIPCSVASRangeFile(fname) as fdesc:
            self.copy_from(
                fdesc, AS_Range.__tablename__, null='',
                columns=['start', 'stop', 'aut_sys'],
            )

    def country_byip(self, addr):
        try:
            addr = utils.int2ip(addr)
        except (TypeError, struct.error):
            pass
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
        if data and utils.ip2int(addr) <= utils.ip2int(data[0]):
            return self.fmt_results(
                ['country_code', 'country_name'],
                data[1:],
            )

    def location_byip(self, addr):
        try:
            addr = utils.int2ip(addr)
        except (TypeError, struct.error):
            pass
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
        if data and utils.ip2int(addr) <= utils.ip2int(data[0]):
            return self.fmt_results(
                ['coordinates', 'country_code', 'country_name', 'city',
                 'area_code', 'metro_code', 'postal_code', 'region_code'],
                data[1:],
            )

    def as_byip(self, addr):
        try:
            addr = utils.int2ip(addr)
        except (TypeError, struct.error):
            pass
        data_range = select([AS_Range.stop, AS_Range.aut_sys])\
                  .where(AS_Range.start <= addr)\
                  .order_by(AS_Range.start.desc())\
                  .limit(1)\
                  .cte("data_range")
        data = self.db.execute(
            select([data_range.c.stop, data_range.c.aut_sys, AS.name])\
            .where(AS.num == select([data_range.c.aut_sys]))
        ).fetchone()
        if data and utils.ip2int(addr) <= utils.ip2int(data[0]):
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


class NmapFilter(object):
    def __init__(self, main=None, category=None, source=None, port=None,
                 script=None):
        self.main = main
        self.category = [] if category is None else category
        self.source = [] if source is None else source
        self.port = [] if port is None else port
        self.script = [] if script is None else script
    @staticmethod
    def fltand(flt1, flt2):
        return flt1 if flt2 is None else flt2 if flt1 is None else and_(flt1, flt2)
    def __and__(self, other):
        return self.__class__(
            main=self.fltand(self.main, other.main),
            category=self.category + other.category,
            source=self.source + other.source,
            port=self.port + other.port,
            script=self.script + other.script,
        )


class PostgresDBNmap(PostgresDB, DBNmap):
    tables = [ScanFile, Category, Source, Scan, Port, Script,
              Association_Scan_Source, Association_Scan_Category,
              Association_Scan_ScanFile]
    required_tables = [AS, Country, Location]
    shared_tables = [(Host, Host.id, [Flow.src, Flow.dst]),
                     (Context, Context.name, [Host.context])]

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBNmap.__init__(self)
        self.content_handler = xmlnmap.Nmap2Posgres
        self.output_function = None
        self.flt_empty = NmapFilter()

    def get_context(self, addr, source=None):
        ctxt = self.default_context(addr)
        if source is None:
            return ctxt
        return 'Public' if ctxt == 'Public' else '%s-%s' % (ctxt, source)

    def is_scan_present(self, scanid):
        return bool(self.db.execute(select([True])\
                                    .where(
                                        ScanFile.sha256 == scanid.decode('hex')
                                    )\
                                    .limit(1)).fetchone())

    def store_scan_doc(self, scan):
        scan = scan.copy()
        if 'start' in scan:
            scan['start'] = datetime.datetime.utcfromtimestamp(
                int(scan['start'])
            )
        scan["sha256"] = scan.pop('_id').decode('hex')
        self.db.execute(insert(ScanFile).values(
            **dict(
                (key, scan[key])
                for key in ['sha256', 'args', 'scaninfos', 'scanner', 'start',
                            'version', 'xmloutputversion']
                if key in scan
            )
        ))

    def store_host(self, host, merge=False):
        addr = host['addr']
        context = self.get_context(addr, source=host.get('source'))
        try:
            addr = utils.int2ip(addr)
        except (TypeError, struct.error):
            pass
        hostid = self.store_host_context(addr, context, host['starttime'], host['endtime'])
        if merge:
            insrt = postgresql.insert(Scan)
            scanid, scan_tstop, merge = self.db.execute(
                insrt.values(
                    host=hostid,
                    info=host.get('infos'),
                    time_start=host['starttime'],
                    time_stop=host['endtime'],
                    archive=0,
                    merge=False,
                    **dict(
                        (key, host[key]) for key in ['state', 'state_reason',
                                                     'state_reason_ttl']
                        if key in host
                    )
                )\
                .on_conflict_do_update(
                    index_elements=['host', 'archive'],
                    set_={
                        'time_start': func.least(
                            Scan.time_start,
                            insrt.excluded.time_start,
                        ),
                        'time_stop': func.greatest(
                            Scan.time_stop,
                            insrt.excluded.time_stop,
                        ),
                        'merge': True,
                    },
                )\
                .returning(Scan.id, Scan.time_stop,
                           Scan.merge)).fetchone()
            if merge:
                # Test should be ==, using <= in case of rounding
                # issues.
                newest = scan_tstop <= host['endtime']
        else:
            curarchive = self.db.execute(select([func.max(Scan.archive)])\
                                         .where(Scan.host == hostid))\
                                .fetchone()[0]
            if curarchive is not None:
                self.db.execute(update(Scan).where(and_(
                    Scan.host == hostid,
                    Scan.archive == 0,
                )).values(archive=curarchive + 1))
            scanid = self.db.execute(insert(Scan)\
                                     .values(
                                         host=hostid,
                                         info=host.get('infos'),
                                         time_start=host['starttime'],
                                         time_stop=host['endtime'],
                                         state=host['state'],
                                         state_reason=host['state_reason'],
                                         state_reason_ttl=host['state_reason_ttl'],
                                         archive=0,
                                         merge=False,
                                     )\
                                     .returning(Scan.id)).fetchone()[0]
        insrt = postgresql.insert(Association_Scan_ScanFile)
        self.db.execute(insrt\
                        .values(scan=scanid,
                                scan_file=host['scanid'].decode('hex'))\
                        .on_conflict_do_nothing())
        if host.get('source'):
            insrt = postgresql.insert(Source)
            sourceid = self.db.execute(insrt.values(name=host['source'])\
                                       .on_conflict_do_update(
                                           index_elements=['name'],
                                           set_={'name': insrt.excluded.name}
                                       )\
                                       .returning(Source.id)).fetchone()[0]
            self.db.execute(postgresql.insert(Association_Scan_Source)\
                            .values(scan=scanid, source=sourceid)\
                            .on_conflict_do_nothing())
        for category in host.get("categories", []):
            insrt = postgresql.insert(Category)
            catid = self.db.execute(insrt.values(name=category)\
                                    .on_conflict_do_update(
                                        index_elements=['name'],
                                        set_={'name': insrt.excluded.name}
                                    )\
                                    .returning(Category.id)).fetchone()[0]
            self.db.execute(postgresql.insert(Association_Scan_Category)\
                            .values(scan=scanid, category=catid)\
                            .on_conflict_do_nothing())
        for port in host.get('ports', []):
            scripts = port.pop('scripts', [])
            # FIXME: handle screenshots
            for fld in ['screendata', 'screenshot', 'screenwords', 'service_method']:
                try:
                    del port[fld]
                except KeyError:
                    pass
            if 'service_servicefp' in port:
                port['service_fp'] = port.pop('service_servicefp')
            if 'state_state' in port:
                port['state'] = port.pop('state_state')
            if merge:
                insrt = postgresql.insert(Port)
                portid = self.db.execute(insrt.values(scan=scanid, **port)\
                                         .on_conflict_do_update(
                                             index_elements=['scan', 'port',
                                                             'protocol'],
                                             set_=dict(
                                                 scan=scanid,
                                                 **(port if newest else {})
                                             )
                                         )\
                                         .returning(Port.id)).fetchone()[0]
            else:
                portid = self.db.execute(insert(Port).values(scan=scanid,
                                                             **port)\
                                         .returning(Port.id)).fetchone()[0]
            for script in scripts:
                name, output = script.pop('id'), script.pop('output')
                if merge:
                    if newest:
                        insrt = postgresql.insert(Script)
                        self.db.execute(insrt\
                                        .values(
                                            port=portid,
                                            name=name,
                                            output=output,
                                            data=script
                                        )\
                                        .on_conflict_do_update(
                                            index_elements=['port', 'name'],
                                            set_={
                                                "output": insrt.excluded.output,
                                                "data": insrt.excluded.data,
                                            },
                                        ))
                    else:
                        insrt = postgresql.insert(Script)
                        self.db.execute(insrt\
                                        .values(
                                            port=portid,
                                            name=name,
                                            output=output,
                                            data=script
                                        )\
                                        .on_conflict_do_nothing())
                else:
                    self.db.execute(insert(Script).values(
                        port=portid,
                        name=name,
                        output=output,
                        data=script
                    ))

    def store_or_merge_host(self, host, gettoarchive, merge=False):
        self.store_host(host, merge=merge)

    @staticmethod
    def query_from_filter(flt, archive, req):
        if flt.main is not None:
            req = req.where(flt.main)
        if not archive:
            req = req.where(Scan.archive == 0)
        for idx, catflt in enumerate(flt.category):
            cte = select([Association_Scan_Category.scan])\
                  .select_from(join(Category, Association_Scan_Category))\
                  .where(catflt).cte("category_%d" % idx)
            req = req.where(Scan.id.in_(select([cte.c.scan])))
        for idx, srcflt in enumerate(flt.source):
            cte = select([Association_Scan_Source.scan])\
                  .select_from(join(Source, Association_Scan_Source))\
                  .where(srcflt).cte("source_%d" % idx)
            req = req.where(Scan.id.in_(select([cte.c.scan])))
        for idx, prtflt in enumerate(flt.port):
            cte = select([Port.scan]).where(prtflt).cte("port_%d" % idx)
            req = req.where(Scan.id.in_(select([cte.c.scan])))
        for idx, scrflt in enumerate(flt.script):
            cte = select([Port.scan]).select_from(join(Script, Port))\
                                     .where(scrflt).cte("script_%d" % idx)
            req = req.where(Scan.id.in_(select([cte.c.scan])))
        return req

    def count(self, flt, archive, **kargs):
        return self.db.execute(
            self.query_from_filter(
                flt, archive,
                select([func.count()])\
                .select_from(join(Scan, join(Host, Context)))
            )
        ).fetchone()[0]

    def get_open_port_count(self, flt, archive=False, limit=None, skip=None):
        req = self.query_from_filter(
            flt, archive,
            select([Scan.id]).select_from(join(Scan, join(Host, Context)))
        )
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        base = req.cte("base")
        return (
            {"addr": rec[2], "starttime": rec[1],
             "openports": {"count": rec[0]}}
            for rec in
            self.db.execute(
                select([func.count(Port.id), Scan.time_start, Host.addr])\
                .select_from(join(Port, join(Scan, Host)))\
                .where(Port.state == "open")\
                .group_by(Host.addr, Scan.time_start)\
                .where(Scan.id.in_(base))
            )
        )

    def get_ips_ports(self, flt, archive=False, limit=None, skip=None):
        req = self.query_from_filter(
            flt, archive,
            select([Scan.id]).select_from(join(Scan, join(Host, Context)))
        )
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        base = req.cte("base")
        return (
            {"addr": rec[2], "starttime": rec[1],
             "ports": [
                 {"proto": proto, "port": int(port), "state_state": state}
                 for proto, port, state in (
                         elt.split(',') for elt in rec[0][3:-3].split(')","(')
                 )
             ]}
            for rec in
            self.db.execute(
                select([
                    func.array_agg(postgresql.aggregate_order_by(
                                    tuple_(Port.protocol, Port.port,
                                           Port.state).label('a'),
                                    tuple_(Port.protocol, Port.port).label('a')
                                )).label('ports'),
                    Scan.time_start, Host.addr,
                ])\
                .select_from(join(Port, join(Scan, Host)))\
                .group_by(Host.addr, Scan.time_start)\
                .where(Scan.id.in_(base))
            )
        )

    def getlocations(self, flt, archive=False, limit=None, skip=None):
        req = self.query_from_filter(
            flt, archive,
            select([func.count(Scan.id), Scan.info['coordinates'].astext])\
            .select_from(join(Scan, join(Host, Context)))\
            .where(Scan.info.has_key('coordinates'))
        )
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return ({'_id': Point().result_processor(None, None)(rec[1])[::-1],
                 'count': rec[0]}
                for rec in
                self.db.execute(req.group_by(Scan.info['coordinates'].astext)))

    def get(self, flt, archive=False, limit=None, skip=None, **kargs):
        req = self.query_from_filter(
            flt, archive, select([join(Scan, join(Host, Context))])
        )
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        for scanrec in self.db.execute(req):
            rec = {}
            (scanid, _, rec["infos"], rec["starttime"], rec["endtime"],
             rec["state"], rec["state_reason"], rec["state_reason_ttl"],
             rec["archive"], rec["merge"], hostid, _, rec["addr"], _, _, _,
             rec["host_context"]) = scanrec
            if not rec["infos"]:
                del rec["infos"]
            sources = select([Association_Scan_Source.source])\
                      .where(Association_Scan_Source.scan == scanid)\
                      .cte("sources")
            sources = [src[0] for src in
                       self.db.execute(select([Source.name])\
                                       .where(Source.id == sources.c.source))]
            if sources:
                rec['source'] = ', '.join(sources)
            categories = select([Association_Scan_Category.category])\
                         .where(Association_Scan_Category.scan == scanid)\
                         .cte("categories")
            rec["categories"] = [src[0] for src in
                                 self.db.execute(
                                     select([Category.name])\
                                     .where(Category.id == categories.c.category)
                                 )]
            for port in self.db.execute(select([Port]).where(Port.scan == scanid)):
                recp = {}
                (portid, _, recp["port"], recp["protocol"], recp["state_state"],
                 recp["state_reason"], recp["state_reason_ip"],
                 recp["state_reason_ttl"], recp["service_name"],
                 recp["service_tunnel"], recp["service_product"],
                 recp["service_version"], recp["service_conf"],
                 recp["service_devicetype"], recp["service_extrainfo"],
                 recp["service_hostname"], recp["service_ostype"],
                 recp["service_servicefp"]) = port
                for fld, value in recp.items():
                    if value is None:
                        del recp[fld]
                for script in self.db.execute(select([Script.name, Script.output])\
                                              .where(Script.port == portid)):
                    recp.setdefault('scripts', []).append(
                        {'id': script.name,
                         'output': script.output}
                    )
                rec.setdefault('ports', []).append(recp)
            yield rec

    def topvalues(self, field, flt=None, topnbr=10, sortby=None,
                  limit=None, skip=None, least=False, archive=False,
                  aggrflt=None, specialproj=None, specialflt=None):
        """
        This method makes use of the aggregation framework to produce
        top values for a given field or pseudo-field. Pseudo-fields are:
          - category / label / asnum / country / net[:mask]
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
          - cert.* / smb.* / sshkey.*
          - modbus.* / s7.* / enip.*
          - mongo.dbs.*
          - vulns.*
          - screenwords
          - file.* / file.*:scriptid
          - hop
        """
        if flt is None:
            flt = NmapFilter()
        base = self.query_from_filter(
            flt, archive,
            select([Scan.id]).select_from(join(Scan, join(Host, Context))),
        ).cte("base")
        order = "count" if least else desc("count")
        if field == "port":
            field = (Port, [Port.protocol, Port.port], Port.state == "open")
        elif field.startswith('port:'):
            info = field[5:]
            field = (Port, [Port.protocol, Port.port],
                     (Port.state == info)
                     if info in {'open', 'filtered', 'closed', 'open|filtered'}
                     else (Port.service_name == info))
        elif field.startswith('countports:'):
            info = field[11:]
            return ({"count": result[0], "_id": result[1]}
                    for result in self.db.execute(
                            select([func.count().label("count"),
                                    column('cnt')])\
                            .select_from(select([func.count().label('cnt')])\
                                         .select_from(Port)\
                                         .where(and_(Port.state == info,
                                                     Port.scan.in_(base)))\
                                         .group_by(Port.scan)\
                                         .alias('cnt'))\
                            .group_by('cnt').order_by(order).limit(topnbr)
                    ))
        elif field.startswith('portlist:'):
            info = field[9:]
            return ({"count": result[0], "_id": [
                (proto, int(port)) for proto, port in (
                    elt.split(',') for elt in result[1][3:-3].split(')","(')
                )
            ]}
                    for result in self.db.execute(
                            select([func.count().label("count"),
                                    column('ports')])\
                            .select_from(select([
                                func.array_agg(postgresql.aggregate_order_by(
                                    tuple_(Port.protocol, Port.port).label('a'),
                                    tuple_(Port.protocol, Port.port).label('a')
                                )).label('ports'),
                            ])\
                                         .where(and_(
                                             Port.state == info,
                                             Port.scan.in_(base),
                                         ))\
                                         .group_by(Port.scan)\
                                         .alias('ports'))\
                            .group_by('ports').order_by(order).limit(topnbr)
                    ))
        elif field == "service":
            field = (Port, [Port.service_name], Port.state == "open")
        elif field.startswith("service:"):
            info = field[8:]
            if '/' in info:
                info = info.split('/', 1)
                field = (Port, [Port.service_name],
                         and_(Port.protocol == info[0],
                              Port.port == int(info[1])))
            else:
                field = (Port, [Port.service_name], Port.port == int(info))
        elif field == "product":
            field = (Port, [Port.service_name, Port.service_product],
                     Port.state == "open")
        elif field == "version":
            field = (Port, [Port.service_name, Port.service_product,
                            Port.service_version],
                     Port.state == "open")
        elif field == "asnum":
            field = (Scan, [Scan.info["as_num"]], None)
        elif field == "as":
            field = (Scan, [Scan.info["as_num"], Scan.info["as_name"]], None)
        elif field == "country":
            field = (Scan, [Scan.info["country_code"],
                            Scan.info["country_name"]], None)
        elif field == "city":
            field = (Scan, [Scan.info["country_code"], Scan.info["city"]], None)
        elif field == "net" or field.startswith("net:"):
            info = field[4:]
            info = int(info) if info else 24
            field = (Host, [func.set_masklen(text("host.addr::cidr"), info)], None)
        else:
            raise NotImplementedError()
        s_from = {
            Scan: Scan,
            Port: join(Port, Scan),
            Host: join(Scan, Host),
        }
        req = select([func.count().label("count")] + field[1])\
              .select_from(s_from[field[0]])\
              .group_by(*field[1])\
              .where(Scan.id.in_(base))
        if field[2] is not None:
            req = req.where(field[2])
        return ({"count": result[0], "_id": result[1:] if len(result) > 2 else result[1]}
                for result in self.db.execute(req.order_by(order).limit(topnbr)))


    @staticmethod
    def _flt_and(flt1, flt2):
        return flt1 & flt2

    @staticmethod
    def _flt_or(flt1, flt2):
        return flt1 | flt2

    @classmethod
    def flt_and(cls, *args):
        """Returns a condition that is true iff all of the given
        conditions is true.

        """
        return reduce(cls._flt_and, args)

    @classmethod
    def flt_or(cls, *args):
        """Returns a condition that is true iff any of the given
        conditions is true.

        """
        return reduce(self._flt_or, args)

    @staticmethod
    def _searchstring_re(field, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            flt = field.op('~')(value.pattern)
            if neg:
                return not_(flt)
            return flt
        if neg:
            return field != value
        return field == value

    @staticmethod
    def _searchstring_list(field, value, neg=False, map_=None):
        if not isinstance(value, basestring) and hasattr(value, '__iter__'):
            if map_ is not None:
                value = map(map_, value)
            if neg:
                return field.notin_(value)
            return field.in_(value)
        if map_ is not None:
            value = map_(value)
        if neg:
            return field != value
        return field == value

    @staticmethod
    def searchhost(addr, neg=False):
        return NmapFilter(main=PostgresDB.searchhost(addr, neg=neg))

    @staticmethod
    def searchhosts(hosts, neg=False):
        return NmapFilter(main=PostgresDB.searchhosts(hosts, neg=neg))

    @staticmethod
    def searchrange(start, stop, neg=False):
        return NmapFilter(main=PostgresDB.searchrange(start, stop, neg=neg))

    @classmethod
    def searchdomain(cls, name, neg=False):
        return NmapFilter(main=cls._searchstring_re(Scan.domainname, name,
                                                    neg=neg))

    @classmethod
    def searchhostname(cls, name, neg=False):
        return NmapFilter(main=cls._searchstring_re(Scan.hostname, name,
                                                    neg=neg))

    @classmethod
    def searchcategory(cls, cat, neg=False):
        return NmapFilter(category=[cls._searchstring_re(Category.name, cat,
                                                         neg=neg)])

    @classmethod
    def searchsource(cls, src, neg=False):
        return NmapFilter(source=[cls._searchstring_re(Source.name, src,
                                                       neg=neg)])

    @classmethod
    def searchcountry(cls, country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        country = utils.country_unalias(country)
        return NmapFilter(
            main=cls._searchstring_list(Scan.info['country_code'].astext,
                                        country, neg=neg)
        )

    @classmethod
    def searchcity(cls, city, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        city

        """
        return NmapFilter(
            main=cls._searchstring_re(Scan.info['city'].astext,
                                      city, neg=neg)
        )

    @classmethod
    def searchasnum(cls, asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        return NmapFilter(
            main=cls._searchstring_list(Scan.info['as_num'], asnum,
                                        neg=neg, map_=str)
        )

    @classmethod
    def searchasname(cls, asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        return NmapFilter(
            main=cls._searchstring_re(Scan.info['as_name'].astext, asname,
                                      neg=neg)
        )

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
            return NmapFilter(port=[(Port.port >= 0) if neg
                                    else (Port.port == -1)])
        if neg:
            return NmapFilter(
                port=[or_(and_(Port.port == port, Port.protocol == protocol,
                               Port.state != state),
                          not_(exists(and_(Port.port == port,
                                           Port.protocol == protocol))))]
            )
        return NmapFilter(port=[and_(Port.port == port,
                                     Port.protocol == protocol,
                                     Port.state == state)])

    @staticmethod
    def searchportsother(ports, protocol='tcp', state='open'):
        """Filters records with at least one port other than those
        listed in `ports` with state `state`.

        """
        return NmapFilter(port=[and_(or_(Port.port.notin_(ports),
                                         Port.protocol != protocol),
                                     Port.state == state)])

    @classmethod
    def searchports(cls, ports, protocol='tcp', state='open', neg=False):
        return cls.flt_and(*(cls.searchport(port, protocol=protocol,
                                            state=state, neg=neg)
                      for port in ports))

    @staticmethod
    def searchcountopenports(minn=None, maxn=None, neg=False):
        "Filters records with open port number between minn and maxn"
        assert minn is not None or maxn is not None
        req = select([column("scan")])\
              .select_from(select([Port.scan.label("scan"),
                                   func.count().label("count")])\
                           .where(Port.state == "open")\
                           .group_by(Port.scan).alias("pcnt"))
        if minn == maxn:
            if neg:
                req = req.where(column("count") != minn)
            else:
                req = req.where(column("count") == minn)
        else:
            if minn is not None:
                if neg:
                    req = req.where(column("count") < minn)
                else:
                    req = req.where(column("count") >= minn)
            if maxn is not None:
                if neg:
                    req = req.where(column("count") > maxn)
                else:
                    req = req.where(column("count") <= maxn)
        return NmapFilter(main=Scan.id.in_(req))

    @staticmethod
    def searchopenport(neg=False):
        "Filters records with at least one open port."
        if neg:
            req = select([column("scan")])\
                  .select_from(select([Port.scan.label("scan")])\
                               .where(Port.state == "open")\
                               .group_by(Port.scan).alias("pcnt"))
            return NmapFilter(main=Scan.id.notin_(req))
            raise ValueError()
        return NmapFilter(port=[Port.state == "open"])

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        req = cls._searchstring_re(Port.service_name, srv)
        if port is not None:
            req = and_(req, Port.port == port)
        if protocol is not None:
            req = and_(req, Port.protocol == protocol)
        return NmapFilter(port=[req])

    @classmethod
    def searchproduct(cls, product, version=None, service=None, port=None,
                      protocol=None):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        req = cls._searchstring_re(Port.service_product, product)
        if version is not None:
            req = and_(req, cls._searchstring_re(Port.service_version, version))
        if service is not None:
            req = and_(req, cls._searchstring_re(Port.service_name, service))
        if port is not None:
            req = and_(req, Port.port == port)
        if protocol is not None:
            req = and_(req, Port.protocol == protocol)
        return NmapFilter(port=[req])

    @classmethod
    def searchscript(cls, name=None, output=None, values=None):
        """Search a particular content in the scripts results.

        """
        req = True
        if name is not None:
            req = and_(req, cls._searchstring_re(Script.name, name, neg=False))
        if output is not None:
            req = and_(req, cls._searchstring_re(Script.output, output, neg=False))
        if values:
            if name is None:
                raise TypeError(".searchscript() needs a `name` arg "
                                "when using a `values` arg")
            req = and_(req, Script.data.contains(
                {xmlnmap.ALIASES_TABLE_ELEMS.get(name, name): values}
            ))
        return NmapFilter(script=[req])

    @staticmethod
    def searchsvchostname(srv):
        return NmapFilter(port=[Port.service_hostname == srv])

    @staticmethod
    def searchwebmin():
        return NmapFilter(
            port=[and_(Port.service_name == 'http',
                       Port.service_product == 'MiniServ',
                       Port.service_extrainfo == 'Webmin httpd')]
        )

    @staticmethod
    def searchx11():
        return NmapFilter(
            port=[and_(Port.service_name == 'X11',
                       Port.service_extrainfo != 'access denied')]
        )

    @classmethod
    def searchfile(cls, fname=None, scripts=None):
        """Search shared files from a file name (either a string or a
        regexp), only from scripts using the "ls" NSE module.

        """
        if fname is None:
            req = Script.values.has_key('ls.volumes.files.filename')
        else:
            req = cls._searchstring_re(
                Script.values['ls.volumes.files.filename'], fname
            )
        if scripts is None:
            return NmapFilter(script=[req])
        if isinstance(scripts, basestring):
            scripts = [scripts]
        if len(scripts) == 1:
            return NmapFilter(script=[and_(Script.name == scripts.pop(), req)])
        return NmapFilter(script=[and_(Script.name.in_(scripts), req)])

    @classmethod
    def searchhttptitle(cls, title):
        return NmapFilter(script=[
            Script.name.in_(['http-title', 'html-title']),
            cls._searchstring_re(Script.output, title),
        ])
