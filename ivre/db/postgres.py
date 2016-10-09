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

from sqlalchemy import create_engine, delete, exists, func, insert, join, \
    select, update, and_, not_, or_, Column, ForeignKey, Index, Table, \
    Boolean, DateTime, Integer, LargeBinary, String, Text
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

class PostgresDBNmap(PostgresDB, DBNmap):
    tables = [ScanFile, Category, Source, Scan, Port, Script,
              Association_Scan_Source, Association_Scan_Category,
              Association_Scan_ScanFile]
    required_tables = [AS, Country, Location]
    shared_tables = [(Host, Host.id, [Flow.src, Flow.dst]),
                     (Context, Context.name, [Host.context])]
    flt_empty = None

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBNmap.__init__(self)
        self.content_handler = xmlnmap.Nmap2Posgres
        self.output_function = None

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

    def get(self, flt, archive=False, **kargs):
        req = select([Scan])
        if not archive:
            req = req.where(Scan.archive == 0)
        for scanrec in self.db.execute(req):
            rec = {}
            (scanid, hostid, rec["infos"], rec["starttime"], rec["endtime"],
             rec["state"], rec["state_reason"],
             rec["state_reason_ttl"], rec["archive"], rec["merge"]) = scanrec
            rec["addr"] = self.db.execute(
                select([Host.addr]).where(Host.id == hostid)
            ).fetchone()[0]
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
