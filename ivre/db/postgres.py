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

"""This sub-module contains functions to interact with PostgreSQL
databases.

"""


from bisect import bisect_left
import codecs
import csv
import datetime
from functools import reduce
import json
import re
import socket
import struct
import time


from builtins import int, range
from future.utils import viewitems, viewvalues
from past.builtins import basestring
from sqlalchemy import event, create_engine, desc, func, text, column, delete, \
    exists, insert, join, select, union, update, null, and_, not_, or_, \
    Column, ForeignKey, Index, Table, ARRAY, Boolean, DateTime, Float, \
    Integer, LargeBinary, String, Text, tuple_, ForeignKeyConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import UserDefinedType
from sqlalchemy.ext.declarative import declarative_base
from collections import namedtuple


from ivre.db import DB, DBFlow, DBData, DBNmap, DBPassive, DBView
from ivre import config, utils, xmlnmap


Base = declarative_base()

class Context(Base):
    __tablename__ = "context"
    id = Column(Integer, primary_key=True)
    name = Column(String(32))
    __table_args__ = (
        Index('ix_context_name', 'name', unique=True),
    )

def _after_context_create(target, connection, **_):
    connection.execute(insert(Context).values(id=0))

event.listen(Context.__table__, "after_create", _after_context_create)


class Host(Base):
    __tablename__ = "host"
    id = Column(Integer, primary_key=True)
    context = Column(Integer, ForeignKey('context.id', ondelete='RESTRICT'))
    addr = Column(postgresql.INET)
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    __table_args__ = (
        Index('ix_host_addr_context', 'addr', 'context', unique=True),
    )

def _after_host_create(target, connection, **_):
    connection.execute(insert(Host).values(id=0, context=0))

event.listen(Host.__table__, "after_create", _after_host_create)


class Flow(Base):
    __tablename__ = "flow"
    id = Column(Integer, primary_key=True)
    proto = Column(String(32), index=True)
    dport = Column(Integer, index=True)
    src = Column(Integer, ForeignKey('host.id', ondelete='RESTRICT'))
    dst = Column(Integer, ForeignKey('host.id', ondelete='RESTRICT'))
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

class CSVFile(object):
    """A file like object generating CSV lines suitable for use with
PostgresDB.copy_from(). Reads (at most `limit`, when it's not None)
lines from `fname`, skipping `skip` first lines.

When .read() returns the empty string, the attribute `.more_to_read`
is set to True when the `limit` has been reached, and to False when
there is no more data to read from the input.

    """
    def __init__(self, fname, skip=0, limit=None):
        self.fdesc = codecs.open(fname, encoding='latin-1')
        for _ in range(skip):
            self.fdesc.readline()
        self.limit = limit
        if limit is not None:
            self.count = 0
        self.more_to_read = None
        self.inp = csv.reader(self.fdesc)

    @staticmethod
    def fixline(line):
        """Subclasses can override this method to generate the CSV line from
the original line.

        """
        return line
    def read(self, size=None):
        if self.limit is not None:
            if self.count >= self.limit:
                self.more_to_read = True
                return ''
        try:
            line = None
            while line is None:
                line = self.fixline(next(self.inp))
            if self.limit is not None:
                self.count += 1
            return '%s\n' % '\t'.join(line)
        except StopIteration:
            self.more_to_read = False
            return ''
    def readline(self):
        return self.read()
    def __exit__(self, *args):
        if self.fdesc is not None:
            self.fdesc.__exit__(*args)
    def __enter__(self):
        return self

class GeoIPCSVLocationFile(CSVFile):
    @staticmethod
    def fixline(line):
        return line[:5] + ["%s,%s" % tuple(line[5:7])] + line[7:]

class GeoIPCSVLocationRangeFile(CSVFile):
    @staticmethod
    def fixline(line):
        for i in range(2):
            line[i] = utils.int2ip(int(line[i]))
        return line

class GeoIPCSVASFile(CSVFile):
    @staticmethod
    def fixline(line):
        line = line[2].split(' ', 1)
        return [line[0][2:], '' if len(line) == 1 else line[1]]

class GeoIPCSVASRangeFile(CSVFile):
    @staticmethod
    def fixline(line):
        for i in range(2):
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
    country_code = Column(String(2), ForeignKey('country.code',
                                                ondelete='CASCADE'))
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
    aut_sys = Column(Integer, ForeignKey('aut_sys.num', ondelete='CASCADE'))
    start = Column(postgresql.INET, index=True)
    stop = Column(postgresql.INET)


class Location_Range(Base):
    __tablename__ = "location_range"
    id = Column(Integer, primary_key=True)
    location_id = Column(Integer, ForeignKey('location.id', ondelete='CASCADE'))
    start = Column(postgresql.INET, index=True)
    stop = Column(postgresql.INET)


# Nmap

class ScanCSVFile(CSVFile):
    def __init__(self, hostgen, get_context, table):
        self.get_context = get_context
        self.table = table
        self.inp = hostgen
        self.fdesc = None
    def fixline(self, line):
        for field in ["cpes", "extraports", "openports", "os", "traces"]:
            line.pop(field, None)
        line["context"] = self.get_context(line['addr'],
                                           source=line.get('source'))
        line["addr"] = PostgresDB.convert_ip(line['addr'])
        scanfileid = line.pop('scanid')
        if isinstance(scanfileid, basestring):
            scanfileid = [scanfileid]
        line["scanfileid"] = '{%s}' % ','.join('"\\x%s"' % fid
                                               for fid in scanfileid)
        line["time_start"] = line.pop('starttime')
        line["time_stop"] = line.pop('endtime')
        line["info"] = line.pop('infos', None)
        for field in ["categories"]:
            if field in line:
                line[field] = "{%s}" % json.dumps(line[field])[1:-1]
        for port in line.get('ports', []):
            for script in port.get('scripts', []):
                if 'masscan' in script and 'raw' in script['masscan']:
                    script['masscan']['raw'] = utils.encode_b64(
                        script['masscan']['raw']
                    )
            if 'screendata' in port:
                port['screendata'] = utils.encode_b64(port['screendata'])
        for field in ["hostnames", "ports", "info"]:
            if field in line:
                line[field] = json.dumps(line[field]).replace('\\', '\\\\')
        return ["\\N" if line.get(col.name) is None else str(line.get(col.name))
                for col in self.table.columns]


class Association_Scan_ScanFile_Columns(object):
    scan = Column(Integer, primary_key=True)
    scan_file = Column(LargeBinary(32), primary_key=True)

class Association_Scan_ScanFile(Base, Association_Scan_ScanFile_Columns):
    __tablename__ = 'association_scan_scanfile'
    __table_args__ = (
        ForeignKeyConstraint(['scan_file'],
                             ['scan_file.sha256'],
                             ondelete='CASCADE'),
        ForeignKeyConstraint(['scan'], ['scan.id'], ondelete='CASCADE'),
    )

class ScanFile_Columns(object):
    sha256 = Column(LargeBinary(32), primary_key=True)
    args = Column(Text)
    scaninfo = Column(postgresql.JSONB)
    scanner = Column(String(16))
    start = Column(DateTime)
    version = Column(String(16))
    xmloutputversion = Column(String(16))

class ScanFile(Base, ScanFile_Columns):
    __tablename__ = "scan_file"

class Association_Scan_N_Category_Columns(object):
    scan = Column(Integer, primary_key=True)
    category = Column(Integer, primary_key=True)

class Association_Scan_N_Category(Base, Association_Scan_N_Category_Columns):
    __tablename__ = 'association_scan_n_category'
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['scan.id'], ondelete="CASCADE"),
        ForeignKeyConstraint(['category'], ['n_category.id'],
                             ondelete="CASCADE"),
    )

class Category_Columns(object):
    id = Column(Integer, primary_key=True)
    name = Column(String(32))

class N_Category(Base, Category_Columns):
    __tablename__ = 'n_category'
    __table_args__ = (
        Index('ix_n_category_name', 'name', unique=True),
    )

class Script_Columns(object):
    name = Column(String(64), primary_key=True)
    port = Column(Integer, primary_key=True)
    output = Column(Text)
    data = Column(postgresql.JSONB)

class N_Script(Base, Script_Columns):
    __tablename__ = 'n_script'
    __table_args__ = (
        ForeignKeyConstraint(['port'], ['n_port.id'], ondelete="CASCADE"),
        Index('ix_n_script_data', 'data', postgresql_using='gin'),
        Index('ix_n_script_name', 'name'),
    )

class Port_Columns(object):
    id = Column(Integer, primary_key=True)
    scan = Column(Integer)
    port = Column(Integer)
    protocol = Column(String(16))
    state = Column(String(32))
    state_reason = Column(String(32))
    state_reason_ip = Column(postgresql.INET)
    state_reason_ttl = Column(Integer)
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

class N_Port(Base, Port_Columns):
    __tablename__ = 'n_port'
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['scan.id'], ondelete="CASCADE"),
        Index('ix_port_scan_port', 'scan', 'port', 'protocol', unique=True),
    )

class Hostname_Columns(object):
    id = Column(Integer, primary_key=True)
    scan = Column(Integer)
    domains = Column(ARRAY(String(255)), index=True)
    name = Column(String(255), index=True)
    type = Column(String(16), index=True)

class N_Hostname(Base, Hostname_Columns):
    __tablename__ = "n_hostname"
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['scan.id'], ondelete="CASCADE"),
        Index('ix_hostname_scan_name_type', 'scan', 'name', 'type',
              unique=True),
    )

class Association_Scan_N_Hostname_Columns(object):
    scan = Column(Integer, primary_key=True)
    hostname = Column(Integer,  primary_key=True)

class Association_Scan_N_Hostname(Base, Association_Scan_N_Hostname_Columns):
    __tablename__ = 'association_scan_n_hostname'
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['scan.id'], ondelete="CASCADE"),
        ForeignKeyConstraint(['hostname'],
                             ['n_hostname.id'],
                             ondelete="CASCADE"),
    )

class Trace_Columns(object):
    id = Column(Integer, primary_key=True)
    scan = Column(Integer, nullable=False)
    port = Column(Integer)
    protocol = Column(String(16))

class N_Trace(Base, Trace_Columns):
    __tablename__ = "n_trace"
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['scan.id'], ondelete="CASCADE"),
    )

class Hop_Columns(object):
    id = Column(Integer, primary_key=True)
    ipaddr = Column(postgresql.INET)
    ttl = Column(Integer)
    rtt = Column(Float)
    trace = Column(Integer, nullable=False)
    host = Column(String(255), index=True)
    domains = Column(ARRAY(String(255)), index=True)

class N_Hop(Base, Hop_Columns):
    __tablename__ = "n_hop"
    __table_args__ = (
        ForeignKeyConstraint(['trace'], ['n_trace.id'], ondelete="CASCADE"),
        Index('ix_n_hop_ipaddr_ttl', 'ipaddr', 'ttl'),
    )

class Scan_Columns(object):
    id = Column(Integer, primary_key=True)
    addr = Column(postgresql.INET, nullable=False)
    source = Column(String(32), nullable=False)
    info = Column(postgresql.JSONB)
    time_start = Column(DateTime)
    time_stop = Column(DateTime)
    state = Column(String(32))
    state_reason = Column(String(32))
    state_reason_ttl = Column(Integer)
    schema_version = Column(Integer, default=xmlnmap.SCHEMA_VERSION)

class Scan(Base, Scan_Columns):
    __tablename__ = "scan"
    __table_args__ = (
        Index('ix_scan_info', 'info', postgresql_using='gin'),
        Index('ix_scan_host', 'addr', 'source'),
        Index('ix_scan_time', 'time_start', 'time_stop'),
    )


# Passive

class PassiveCSVFile(CSVFile):
    info_fields = set(["distance", "signature", "version"])
    def __init__(self, siggen, get_context, table, limit=None, getinfos=None,
                 separated_timestamps=True):
        self.get_context = get_context
        self.table = table
        self.inp = siggen
        self.fdesc = None
        self.limit = limit
        if limit is not None:
            self.count = 0
        self.getinfos = getinfos
        self.timestamps = separated_timestamps
    def fixline(self, line):
        if self.timestamps:
            timestamp, line = line
            if isinstance(timestamp, datetime.datetime):
                line["firstseen"] = line["lastseen"] = timestamp
            else:
                line["firstseen"] = line["lastseen"] = datetime\
                                                       .datetime\
                                                       .fromtimestamp(timestamp)
        else:
            if not isinstance(line["firstseen"], datetime.datetime):
                line["firstseen"] = datetime.datetime\
                    .fromtimestamp(line["firstseen"])
            if not isinstance(line["lastseen"], datetime.datetime):
                line["lastseen"] = datetime.datetime\
                    .fromtimestamp(line["lastseen"])
        if self.getinfos is not None:
            additional_info = self.getinfos(line)
            try:
                line.update(additional_info['infos'])
            except KeyError:
                pass
            try:
                line.update(additional_info['fullinfos'])
            except KeyError:
                pass
        if "addr" in line:
            addr = line["addr"]
            line["context"] = self.get_context(addr, sensor=line.get('sensor'))
            line["addr"] = PostgresDB.convert_ip(addr)
        else:
            line["addr"] = None
            line["context"] = None
        line.setdefault("count", 1)
        line.setdefault("port", 0)
        for key in ["sensor", "value", "source", "targetval"]:
            line.setdefault(key, "")
        for key, value in viewitems(line):
            if key not in ["info", "moreinfo"] and \
               isinstance(value, basestring):
                try:
                    value = value.encode('latin-1')
                except:
                    pass
                line[key] = "".join(
                    c.decode() if b' ' <= c <= b'~' else
                    ('\\x%02x' % ord(c))
                    for c in (value[i:i + 1] for i in range(len(value)))
                ).replace('\\', '\\\\')
        line["info"] = "%s" % json.dumps(
            dict((key, line.pop(key)) for key in list(line)
                 if key in self.info_fields),
        ).replace('\\', '\\\\')
        line["moreinfo"] = "%s" % json.dumps(
            dict((key, line.pop(key)) for key in list(line)
                 if key not in self.table.columns),
        ).replace('\\', '\\\\')
        return ["\\N" if line.get(col.name) is None else str(line.get(col.name))
                for col in self.table.columns]


class Passive(Base):
    __tablename__ = "passive"
    id = Column(Integer, primary_key=True)
    host = Column(Integer, ForeignKey('host.id', ondelete='RESTRICT'))
    sensor = Column(String(64))
    count = Column(Integer)
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    port = Column(Integer)
    recontype = Column(String(64))
    source = Column(String(64))
    targetval = Column(Text)
    value = Column(Text)
    fullvalue = Column(Text)
    info = Column(postgresql.JSONB)
    moreinfo = Column(postgresql.JSONB)
    # moreinfo and fullvalue contain data that are not tested for
    # unicity on insertion (the unicity is guaranteed by the value)
    # for performance reasons
    __table_args__ = (
        Index('ix_passive_record', 'host', 'sensor', 'recontype', 'port',
              'source', 'value', 'targetval', 'info', unique=True),
    )


class PostgresDB(DB):
    tables = []
    required_tables = []
    shared_tables = []
    fields = {}
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
            # echo on debug disabled for tests
            self._db = create_engine(self.dburl, echo=config.DEBUG_DB)
            return self._db

    def drop(self):
        for table in reversed(self.tables):
            table.__table__.drop(bind=self.db, checkfirst=True)
        for table, othercols in self.shared_tables:
            if table.__table__.exists(bind=self.db):
                basevals = [select([col.distinct()]) for col in othercols
                            if col.table.exists(bind=self.db)]
                if basevals:
                    base = union(*(basevals)).cte("base")
                    self.db.execute(delete(table).where(table.id.notin_(base)))
                else:
                    table.__table__.drop(bind=self.db, checkfirst=True)

    def create(self):
        for table in self.required_tables:
            table.__table__.create(bind=self.db, checkfirst=True)
        for table, _ in self.shared_tables[::-1]:
            table.__table__.create(bind=self.db, checkfirst=True)
        for table in self.tables:
            table.__table__.create(bind=self.db, checkfirst=True)
        # Make sur we always have the 0 record
        try:
            _after_context_create(None, self.db)
        except:
            pass
        try:
            _after_host_create(None, self.db)
        except:
            pass

    def init(self):
        self.drop()
        self.create()

    @staticmethod
    def to_binary(data):
        return utils.encode_b64(data).decode()

    @staticmethod
    def from_binary(data):
        return utils.decode_b64(data.encode())

    def copy_from(self, *args, **kargs):
        cursor = self.db.raw_connection().cursor()
        conn = self.db.connect()
        trans = conn.begin()
        cursor.copy_from(*args, **kargs)
        trans.commit()
        conn.close()

    def create_tmp_table(self, table, extracols=None):
        cols = [c.copy() for c in table.__table__.columns]
        for c in cols:
            c.index = False
            c.nullable = True
            c.foreign_keys = None
            if c.primary_key:
                c.primary_key = False
                c.index = True
        if extracols is not None:
            cols.extend(extracols)
        t = Table("tmp_%s" % table.__tablename__,
                  table.__table__.metadata, *cols,
                  prefixes=['TEMPORARY'])
        t.create(bind=self.db, checkfirst=True)
        return t

    @staticmethod
    def flt_and(*args):
        return and_(*args)

    @staticmethod
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
        except (TypeError, socket.error):
            # FIXME no IPv6 support
            return "Public"
        return cls.context_names[bisect_left(cls.context_last_ips, addr)]

    @classmethod
    def searchobjectid(cls, oid, neg=False):
        """Filters records by their ObjectID.  `oid` can be a single or many
        (as a list or any iterable) object ID(s), specified as strings
        or an `ObjectID`s.

        """
        if isinstance(oid, (int, basestring)):
            oid = [int(oid)]
        else:
            oid = [int(oid) for oid in oid]
        return cls._searchobjectid(oid, neg=neg)

    @classmethod
    def _searchobjectid(cls, oid, neg=False):
        raise NotImplementedError

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """

        if neg:
            return Host.addr != cls.convert_ip(addr)
        return Host.addr == cls.convert_ip(addr)

    @staticmethod
    def _distinct_req(field, flt):
        return flt.query(
            select([field.distinct()]).select_from(flt.select_from)
        )

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None,
                 **kargs):
        """This method produces a generator of distinct values for a given
field.

        """
        if isinstance(field, basestring):
            field = self.fields[field]
        if flt is None:
            flt = self.flt_empty
        sort = [
            (self.fields[key] if isinstance(key, basestring) else key, way)
            for key, way in sort or []
        ]
        req = self._distinct_req(field, flt, **kargs)
        for key, way in sort:
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return (next(iter(viewvalues(res))) for res in self.db.execute(req))

    def get(self, *args, **kargs):
        cur = self._get(*args, **kargs)
        # mimic MongoDB cursor.count()
        cur.count = lambda: cur.rowcount
        return cur

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
        return reduce(cls._flt_or, args)

    @staticmethod
    def _searchstring_re_inarray(idfield, field, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            if neg:
                # FIXME
                raise ValueError("Not implemented")
            operator = '~*' if (value.flags & re.IGNORECASE) else '~'
            value = value.pattern
            base1 = select([idfield.label('id'),
                            func.unnest(field).label('field')]).cte('base1')
            base2 = select([column('id')])\
                .select_from(base1)\
                .where(column('field').op(operator)(value))\
                .cte('base2')
            return idfield.in_(base2)
        return not_(field.any(value)) if neg else field.any(value)

    @staticmethod
    def _searchstring_re(field, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            flt = field.op(
                '~*' if (value.flags & re.IGNORECASE) else '~'
            )(value.pattern)
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
                value = [map_(elt) for elt in value]
            if neg:
                return field.notin_(value)
            return field.in_(value)
        if map_ is not None:
            value = map_(value)
        if neg:
            return field != value
        return field == value


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
        query._set_bind(self.db)
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
            for i, query in enumerate(list(self.queries)):
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
        utils.LOGGER.debug("DB:%s", query)
        utils.LOGGER.debug("DB:%d inserts, %f/sec (total %d)",
                           l_params, rate, self.commited_counts[query])
        if renew:
            self.start_time = newtime
            self.trans = self.conn.begin()

    def close(self):
        self.commit(renew=False)
        self.conn.close()



class PostgresDBFlow(PostgresDB, DBFlow):

    FlowLayout = namedtuple('FlowLayout', ['flow'])
    tables = FlowLayout(Flow)
    shared_tables = [(Host, [Passive.host]),
                     (Context, [Host.context])]

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

    def add_flow_metadata(self, labels, linktype, keys, flow_keys,
                          counters=None, accumulators=None, time=True,
                          flow_labels=["Flow"]):
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

# Note Error -> Type names and field names cannot be a keyword: 'as'

class PostgresDBData(PostgresDB, DBData):

    DataLayout = namedtuple('DataLayout', ['country', 'location',
                            'location_range', 'as_num', 'as_range'])
    tables = DataLayout(Country, Location, Location_Range, AS, AS_Range)

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBData.__init__(self)

    def feed_geoip_country(self, *_, **__):
        "Country database has been dropped in favor of Location/City"
        pass

    def feed_geoip_city(self, fname, feedipdata=None,
                        createipdata=False):
        utils.LOGGER.debug("START IMPORT: %s", fname)
        with GeoIPCSVLocationRangeFile(fname, skip=2) as fdesc:
            self.copy_from(
                fdesc, self.tables.location_range.__tablename__, null='',
                columns=['start', 'stop', 'location_id'],
            )
        utils.LOGGER.debug("IMPORT DONE (%s)", fname)

    def feed_country_codes(self, fname):
        utils.LOGGER.debug("START IMPORT: %s", fname)
        with CSVFile(fname) as fdesc:
            self.copy_from(fdesc, self.tables.country.__tablename__, null='')
        # Missing from iso3166.csv file but used in GeoIPCity-Location.csv
        self.db.execute(insert(self.tables.country).values(
            code="AN",
            name="Netherlands Antilles",
        ))
        utils.LOGGER.debug("IMPORT DONE (%s)", fname)

    def feed_city_location(self, fname):
        utils.LOGGER.debug("START IMPORT: %s", fname)
        with GeoIPCSVLocationFile(fname, skip=2) as fdesc:
            self.copy_from(
                fdesc, self.tables.location.__tablename__, null='',
                columns=['id', 'country_code', 'region_code', 'city',
                         'postal_code', 'coordinates', 'metro_code',
                         'area_code'],
            )
        utils.LOGGER.debug("IMPORT DONE (%s)", fname)

    def feed_geoip_asnum(self, fname, feedipdata=None,
                         createipdata=False):
        utils.LOGGER.debug("START IMPORT: %s", fname)
        with GeoIPCSVASFile(fname) as fdesc:
            tmp = self.create_tmp_table(self.tables.as_num)
            self.copy_from(fdesc, tmp.name, null='')
        self.db.execute(insert(self.tables.as_num).from_select(['num', 'name'],
                                               select([tmp]).distinct("num")))
        with GeoIPCSVASRangeFile(fname) as fdesc:
            self.copy_from(
                fdesc, self.tables.as_range.__tablename__, null='',
                columns=['start', 'stop', 'aut_sys'],
            )
        utils.LOGGER.debug("IMPORT DONE (%s)", fname)

    def country_byip(self, addr):
        try:
            addr = utils.int2ip(addr)
        except (TypeError, struct.error):
            pass
        data_range = select([self.tables.location_range.stop,
                             self.tables.location_range.location_id])\
                     .where(self.tables.location_range.start <= addr)\
                     .order_by(self.tables.location_range.start.desc())\
                     .limit(1)\
                     .cte("data_range")
        location = select([self.tables.location.country_code])\
                   .where(self.tables.location.id == select([
                        data_range.c.location_id
                   ]))\
                   .limit(1)\
                   .cte("location")
        data = self.db.execute(
            select([data_range.c.stop,
                    location.c.country_code,
                    self.tables.country.name])\
            .where(location.c.country_code == self.tables.country.code)
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
        data_range = select([self.tables.location_range.stop,
                             self.tables.location_range.location_id])\
                     .where(self.tables.location_range.start <= addr)\
                     .order_by(self.tables.location_range.start.desc())\
                     .limit(1)\
                     .cte("data_range")
        location = select([self.tables.location])\
                   .where(self.tables.location.id == select([
                        data_range.c.location_id]))\
                   .limit(1)\
                   .cte("location")
        data = self.db.execute(
            select([data_range.c.stop, location.c.coordinates,
                    location.c.country_code, self.tables.country.name,
                    location.c.city, location.c.area_code,
                    location.c.metro_code, location.c.postal_code,
                    location.c.region_code])\
            .where(location.c.country_code == self.tables.country.code)
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
        data_range = select([self.tables.as_range.stop,
                             self.tables.as_range.aut_sys])\
                  .where(self.tables.as_range.start <= addr)\
                  .order_by(self.tables.as_range.start.desc())\
                  .limit(1)\
                  .cte("data_range")
        data = self.db.execute(
            select([data_range.c.stop,
                    data_range.c.aut_sys,
                    self.tables.as_num.name])\
            .where(self.tables.as_num.num == select([data_range.c.aut_sys]))
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
                select([self.tables.location_range.start,
                        self.tables.location_range.stop])\
                .select_from(join(join(self.tables.location,
                                       self.tables.location_range),
                                  self.tables.country))\
                .where(self.tables.country.name == code)
            )
        return self.db.execute(
            select([self.tables.location_range.start,
                    self.tables.location_range.stop])\
            .select_from(join(self.tables.location,
                              self.tables.location_range))\
            .where(self.tables.location.country_code == code)
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
                    select([self.tables.as_range.start,
                            self.tables.as_range.stop])\
                    .select_from(join(self.tables.as_num,
                                      self.tables.as_range))\
                    .where(self.tables.as_num.name == asnum)
                )
        return self.db.execute(
            select([self.tables.as_range.start, self.tables.as_range.stop])\
            .where(self.tables.as_range.aut_sys == asnum)
        )


class Filter(object):
    @staticmethod
    def fltand(flt1, flt2):
        return flt1 if flt2 is None else \
            flt2 if flt1 is None else and_(flt1, flt2)
    @staticmethod
    def fltor(flt1, flt2):
        return flt1 if flt2 is None else \
            flt2 if flt1 is None else or_(flt1, flt2)


class ActiveFilter(Filter):
    def __init__(self, main=None, hostname=None, category=None, source=None,
                 port=None, script=None, trace=None, tables=None):
        self.tables = tables
        self.main = main
        self.hostname = [] if hostname is None else hostname
        self.category = [] if category is None else category
        self.source = [] if source is None else source
        self.port = [] if port is None else port
        self.script = [] if script is None else script
        self.trace = [] if trace is None else trace
    def copy(self):
        return self.__class__(
            tables=self.tables,
            main=self.main,
            hostname=self.hostname[:],
            category=self.category[:],
            source=self.source[:],
            port=self.port[:],
            script=self.script[:],
            trace=self.trace[:],
        )
    def __and__(self, other):
        return self.__class__(
            tables=self.tables,
            main=self.fltand(self.main, other.main),
            hostname=self.hostname + other.hostname,
            category=self.category + other.category,
            source=self.source + other.source,
            port=self.port + other.port,
            script=self.script + other.script,
            trace=self.trace + other.trace,
        )
    def __or__(self, other):
        # FIXME: this has to be implemented
        if self.hostname and other.hostname:
            raise ValueError("Cannot 'OR' two filters on hostname")
        if self.category and other.category:
            raise ValueError("Cannot 'OR' two filters on category")
        if self.source and other.source:
            raise ValueError("Cannot 'OR' two filters on source")
        if self.port and other.port:
            raise ValueError("Cannot 'OR' two filters on port")
        if self.script and other.script:
            raise ValueError("Cannot 'OR' two filters on script")
        if self.trace and other.trace:
            raise ValueError("Cannot 'OR' two filters on trace")
        return self.__class__(
            tables=self.tables,
            main=self.fltor(self.main, other.main),
            hostname=self.hostname + other.hostname,
            category=self.category + other.category,
            source=self.source + other.source,
            port=self.port + other.port,
            script=self.script + other.script,
            trace=self.trace + other.trace,
        )
    def select_from_base(self, base=None):
        if not base:
            base = self.tables.scan
        if base in [self.tables.scan, self.tables.scan.__mapper__]:
            base = self.tables.scan
        else:
            base = join(self.tables.scan, base)
        return base

    @property
    def select_from(self):
        return self.select_from_base()

    def query(self, req):
        # TODO: improve performances
        #   - use a materialized view for `Scan` ?
        if self.main is not None:
            req = req.where(self.main)
        for incl, subflt in self.hostname:
            base = select([self.tables.hostname.scan])\
                    .where(subflt).cte("base")
            if incl:
                req = req.where(self.tables.scan.id.in_(base))
            else:
                req = req.where(self.tables.scan.id.notin_(base))
        # See <http://stackoverflow.com/q/17112345/3223422> - "Using
        # INTERSECT with tables from a WITH clause"
        for subflt in self.category:
            req = req.where(exists(
                select([1])\
                .select_from(join(self.tables.category,
                             self.tables.association_scan_category))\
                .where(subflt)\
                .where(self.tables.association_scan_category\
                    .scan == self.tables.scan.id)
            ))
        for incl, subflt in self.port:
            if incl:
                req = req.where(exists(
                    select([1])\
                    .select_from(self.tables.port)\
                    .where(subflt)\
                    .where(self.tables.port.scan == self.tables.scan.id)
                ))
            else:
                base = select([self.tables.port.scan]).where(subflt).cte("base")
                req = req.where(self.tables.scan.id.notin_(base))
        for subflt in self.script:
            req = req.where(exists(
                select([1])\
                .select_from(join(self.tables.script, self.tables.port))\
                .where(subflt)\
                .where(self.tables.port.scan == self.tables.scan.id)
            ))
        for subflt in self.trace:
            req = req.where(exists(
                select([1])\
                .select_from(join(self.tables.trace, self.tables.hop))\
                .where(subflt)\
                .where(self.tables.trace.scan == self.tables.scan.id)
            ))
        return req

class ViewFilter(ActiveFilter):
    """Change filter name for View."""

class NmapFilter(ActiveFilter):
    """Change filter name for Nmap."""


class PostgresDBActive(PostgresDB):

    ActiveLayout = namedtuple('activelayout', ['category', 'scan', 'hostname',
                                               'port', 'script', 'trace', 'hop',
                                               'association_scan_hostname',
                                               'association_scan_category'])

    def get_context(self, addr, source=None):
        ctxt = self.default_context(addr)
        if source is None:
            return ctxt
        return 'Public' if ctxt == 'Public' else '%s-%s' % (ctxt, source)

    def is_scan_present(self, scanid):
        return bool(self.db.execute(select([True]).where(
                        self.tables.scanfile.sha256 == utils.decode_hex(
                                    scanid
                        )
                   ).limit(1)).fetchone())

    def store_scan_doc(self, scan):
        scan = scan.copy()
        if 'start' in scan:
            scan['start'] = datetime.datetime.utcfromtimestamp(
                int(scan['start'])
            )
        if 'scaninfos' in scan:
            scan["scaninfo"] = scan.pop('scaninfos')
        scan["sha256"] = utils.decode_hex(scan.pop('_id'))
        insrt = insert(self.tables.scanfile).values(
            **dict(
                (key, scan[key])
                for key in ['sha256', 'args', 'scaninfo', 'scanner', 'start',
                            'version', 'xmloutputversion']
                if key in scan
            )
        )
        if config.DEBUG:
            scanfileid = self.db.execute(
                insrt.returning(self.tables.scanfile.sha256)
            ).fetchone()[0]
            utils.LOGGER.debug("SCAN STORED: %r", utils.encode_hex(scanfileid))
        else:
            self.db.execute(insrt)

    def store_hosts(self, hosts):
        tmp = self.create_tmp_table(self.tables.scan, extracols=[
            Column("context", String(32)),
            Column("scanfileid", ARRAY(LargeBinary(32))),
            Column("categories", ARRAY(String(32))),
            Column("source", String(32)),
            #Column("cpe", postgresql.JSONB),
            #Column("extraports", postgresql.JSONB),
            Column("hostnames", postgresql.JSONB),
            # openports
            #Column("os", postgresql.JSONB),
            Column("ports", postgresql.JSONB),
            #Column("traceroutes", postgresql.JSONB),
        ])
        with ScanCSVFile(hosts, self.get_context, tmp) as fdesc:
            self.copy_from(fdesc, tmp.name)

    def start_store_hosts(self):
        """Backend-specific subclasses may use this method to create some bulk
insert structures.

        """
        self.bulk = self.start_bulk_insert()

    def stop_store_hosts(self):
        """Backend-specific subclasses may use this method to commit bulk
insert structures.

        """
        self.bulk.close()
        self.bulk = None

    def store_host(self, host, merge=False):
        addr = host['addr']
        addr = self.convert_ip(addr)
        info = host.get('infos')
        if 'coordinates' in (info or {}).get('loc', {}):
            info['coordinates'] = info.pop('loc')['coordinates'][::-1]
        source = host.get('source', '')
        if merge:
            insrt = postgresql.insert(self.tables.scan, bind=self.db)
            scanid, scan_tstop = self.db.execute(
                insrt.values(
                    addr=addr,
                    source=source,
                    info=info,
                    time_start=host['starttime'],
                    time_stop=host['endtime'],
                    **dict(
                        (key, host.get(key)) for key in ['state', 'state_reason',
                                                         'state_reason_ttl']
                        if key in host
                    )
                )\
                .on_conflict_do_update(
                    index_elements=['addr', 'source'],
                    set_={
                        'time_start': func.least(
                            self.tables.scan.time_start,
                            insrt.excluded.time_start,
                        ),
                        'time_stop': func.greatest(
                            self.tables.scan.time_stop,
                            insrt.excluded.time_stop,
                        ),
                    },
                )\
                .returning(self.tables.scan.id,
                           self.tables.scan.time_stop)).fetchone()
            if merge:
                # Test should be ==, using <= in case of rounding
                # issues.
                newest = scan_tstop <= host['endtime']
            else:
                newest = None
        else:
            scanid = self.db.execute(insert(self.tables.scan)\
                        .values(
                            addr=addr,
                            source=source,
                            info=info,
                            time_start=host['starttime'],
                            time_stop=host['endtime'],
                            state=host.get('state'),
                            state_reason=host.get('state_reason'),
                            state_reason_ttl=host.get('state_reason_ttl'),
                        )\
                        .returning(self.tables.scan.id)).fetchone()[0]
        for category in host.get("categories", []):
            insrt = postgresql.insert(self.tables.category, bind=self.db)
            catid = self.db.execute(insrt.values(name=category)\
                        .on_conflict_do_update(
                            index_elements=['name'],
                            set_={'name': insrt.excluded.name}
                        )\
                        .returning(self.tables.category.id)).fetchone()[0]
            self.db.execute(postgresql\
                            .insert(self.tables.association_scan_category)\
                            .values(scan=scanid, category=catid)\
                            .on_conflict_do_nothing())
        for port in host.get('ports', []):
            scripts = port.pop('scripts', [])
            # FIXME: handle screenshots
            for fld in ['screendata', 'screenshot',
                        'screenwords', 'service_method']:
                try:
                    del port[fld]
                except KeyError:
                    pass
            if 'service_servicefp' in port:
                port['service_fp'] = port.pop('service_servicefp')
            if 'state_state' in port:
                port['state'] = port.pop('state_state')
            if 'state_reason_ip' in port:
                port['state_reason_ip'] = self.convert_ip(
                    port['state_reason_ip'])
            if merge:
                insrt = postgresql.insert(self.tables.port, bind=self.db)
                portid = self.db.execute(insrt.values(scan=scanid, **port)\
                            .on_conflict_do_update(
                                index_elements=['scan', 'port', 'protocol'],
                                set_=dict(
                                scan=scanid,
                                **(port if newest else {})
                            )
                         )\
                         .returning(self.tables.port.id)).fetchone()[0]
            else:
                portid = self.db.execute(insert(self.tables.port)\
                                         .values(scan=scanid, **port)\
                                         .returning(self.tables.port.id)
                                        ).fetchone()[0]
            for script in scripts:
                name, output = script.pop('id'), script.pop('output')
                if merge:
                    if newest:
                        insrt = postgresql.insert(self.tables.script, bind=self.db)
                        self.bulk.append(insrt\
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
                        insrt = postgresql.insert(self.tables.script, bind=self.db)
                        self.bulk.append(insrt\
                                         .values(
                                             port=portid,
                                             name=name,
                                             output=output,
                                             data=script
                                         )\
                                         .on_conflict_do_nothing())
                else:
                    self.bulk.append(insert(self.tables.script).values(
                        port=portid,
                        name=name,
                        output=output,
                        data=script
                    ))
        if not merge:
            # FIXME: handle traceroutes on merge
            for trace in host.get('traces', []):
                traceid = self.db.execute(insert(self.tables.trace).values(
                    scan=scanid,
                    port=trace.get('port'),
                    protocol=trace['protocol']
                ).returning(self.tables.trace.id)).fetchone()[0]
                for hop in trace.get('hops'):
                    hop['ipaddr'] = self.convert_ip(hop['ipaddr'])
                    self.bulk.append(insert(self.tables.hop).values(
                        trace=traceid,
                        ipaddr=self.convert_ip(hop['ipaddr']),
                        ttl=hop["ttl"],
                        rtt=None if hop["rtt"] == '--' else hop["rtt"],
                        host=hop.get("host"),
                        domains=hop.get("domains"),
                    ))
            # FIXME: handle hostnames on merge
            for hostname in host.get('hostnames', []):
                self.bulk.append(insert(self.tables.hostname).values(
                    scan=scanid,
                    domains=hostname.get('domains'),
                    name=hostname.get('name'),
                    type=hostname.get('type'),
                ))
        utils.LOGGER.debug("HOST STORED: %r", scanid)
        return scanid

    def store_or_merge_host(self, host):
        raise NotImplementedError

    def count(self, flt, **_):
        return self.db.execute(
            flt.query(select([func.count()]))\
            .select_from(flt.select_from)
        ).fetchone()[0]

    @staticmethod
    def _distinct_req(field, flt):
        flt = flt.copy()
        return flt.query(
            select([field.distinct()]).select_from(
                flt.select_from_base(field.parent)
            ),
        )

    def get_open_port_count(self, flt, limit=None, skip=None):
        req = flt.query(select([self.tables.scan.id]))
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
                select([func.count(self.tables.port.id),
                        self.tables.scan.time_start,
                        self.tables.scan.addr])\
                .select_from(join(self.tables.port, self.tables.scan))\
                .where(self.tables.port.state == "open")\
                .group_by(self.tables.scan.addr,
                          self.tables.scan.time_start)\
                .where(self.tables.scan.id.in_(base))
            )
        )

    def get_ips_ports(self, flt, limit=None, skip=None):
        req = flt.query(select([self.tables.scan.id]))
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
                        tuple_(self.tables.port.protocol,
                               self.tables.port.port,
                               self.tables.port.state).label('a'),
                        tuple_(self.tables.port.protocol,
                               self.tables.port.port).label('a')
                    )).label('ports'),
                    self.tables.scan.time_start, self.tables.scan.addr,
                ])\
                .select_from(join(self.tables.port, self.tables.scan))\
                .group_by(self.tables.scan.addr,
                          self.tables.scan.time_start)\
                .where(self.tables.scan.id.in_(base))
            )
        )

    def getlocations(self, flt, limit=None, skip=None):
        req = flt.query(
            select([func.count(self.tables.scan.id),
                    self.tables.scan.info['coordinates'].astext])\
            .where(self.tables.scan.info.has_key('coordinates')),
        )
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return ({'_id': Point().result_processor(None, None)(rec[1])[::-1],
                 'count': rec[0]}
                for rec in
                self.db.execute(
                    req.group_by(self.tables.scan.info['coordinates'].astext)
                ))

    def get(self, flt, limit=None, skip=None, sort=None,
            **kargs):
        req = flt.query(select([self.tables.scan])\
                        .select_from(flt.select_from))
        for key, way in sort or []:
            if isinstance(key, basestring) and key in self.fields:
                key = self.fields[key]
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        for scanrec in self.db.execute(req):
            rec = {}
            correspondance = {
                'id': '_id',
                'addr': 'addr',
                'source': 'source',
                'info': 'infos',
                'time_start': 'starttime',
                'time_stop': 'endtime',
                'state': 'state',
                'state_reason': 'state_reason',
                'state_reason_ttl': 'state_reason_ttl',
                'schema_version': 'schema_version',
            }
            for oldkey, newkey in viewitems(correspondance):
                rec[newkey] = scanrec[oldkey]
            if rec["infos"]:
                if 'coordinates' in rec['infos']:
                    rec['infos']['loc'] = {
                        'type': 'Point',
                        'coordinates': rec['infos'].pop('coordinates')[::-1],
                    }
            else:
                del rec["infos"]
            categories = select(
                    [self.tables.association_scan_category.category]
                ).where(
                    self.tables.association_scan_category.scan == rec["_id"]
                ).cte("categories")
            rec["categories"] = [cat[0] for cat in
                                 self.db.execute(
                                     select([self.tables.category.name])\
                                     .where(self.tables.category.id == categories.c.category)
                                 )]
            
            for port in self.db.execute(select([self.tables.port])\
                            .where(self.tables.port.scan == rec["_id"])):
                recp = {}
                portid = port['id']
                correspondance = {
                    'port': 'port',
                    'protocol': 'protocol',
                    'state': 'state_state',
                    'state_reason': 'state_reason',
                    'state_reason_ip': 'state_reason_ip',
                    'state_reason_ttl': 'state_reason_ttl',
                    'service_name': 'service_name',
                    'service_tunnel': 'service_tunnel',
                    'service_product': 'service_product',
                    'service_version': 'service_version',
                    'service_conf': 'service_conf',
                    'service_devicetype': 'service_devicetype',
                    'service_extrainfo': 'service_extrainfo',
                    'service_hostname': 'service_hostname',
                    'service_ostype': 'service_ostype',
                    'service_fp': 'service_servicefp',
                }
                for oldkey, newkey in viewitems(correspondance):
                    recp[newkey] = port[oldkey] if oldkey in port else None
                for fld, value in list(viewitems(recp)):
                    if value is None:
                        del recp[fld]
                for script in self.db.execute(
                                select([self.tables.script.name,
                                        self.tables.script.output,
                                        self.tables.script.data])\
                                .where(self.tables.script.port == portid)):
                    recp.setdefault('scripts', []).append(
                        dict(id=script.name,
                             output=script.output,
                             **(script.data if script.data else {}))
                    )
                rec.setdefault('ports', []).append(recp)
            for trace in self.db.execute(
                            select([self.tables.trace])\
                            .where(self.tables.trace.scan == rec["_id"])):
                curtrace = {}
                rec.setdefault('traces', []).append(curtrace)
                curtrace['port'] = trace['port']
                curtrace['protocol'] = trace['protocol']
                curtrace['hops'] = []
                for hop in self.db.execute(
                                select([self.tables.hop])\
                                .where(self.tables.hop.trace == trace['id'])\
                                .order_by(self.tables.hop.ttl)):
                    curtrace['hops'].append(dict(
                        (key, hop[key]) for key in ['ipaddr', 'ttl', 'rtt',
                                                    'host', 'domains']
                    ))
            for hostname in self.db.execute(
                    select([self.tables.hostname])\
                    .where(self.tables.hostname.scan == rec["_id"])
            ):
                rec.setdefault('hostnames', []).append(dict(
                    (key, hostname[key]) for key in ['name', 'type', 'domains']
                ))
            yield rec

    def topvalues(self, field, flt=None, topnbr=10, sort=None,
                  limit=None, skip=None, least=False):
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
            flt = ActiveFilter(tables=self.tables)
        base = flt.query(
            select([self.tables.scan.id]).select_from(flt.select_from),
        ).cte("base")
        order = "count" if least else desc("count")
        outputproc = None
        if field == "port":
            field = (self.tables.port,
                     [self.tables.port.protocol, self.tables.port.port],
                     self.tables.port.state == "open")
        elif field == "ttl":
            field = (self.tables.port,
                     [self.tables.port.state_reason_ttl],
                     self.tables.port.state_reason_ttl != None)
        elif field == "ttlinit":
            field = (
                self.tables.port,
                [func.least(255, func.power(2, func.ceil(
                    func.log(2, self.tables.port.state_reason_ttl)
                )))],
                self.tables.port.state_reason_ttl != None,
            )
            outputproc = int
        elif field.startswith('port:'):
            info = field[5:]
            field = (self.tables.port,
                     [self.tables.port.protocol, self.tables.port.port],
                     (self.tables.port.state == info)
                     if info in set(['open', 'filtered', 'closed',
                                     'open|filtered'])
                     else (self.tables.port.service_name == info))
        elif field.startswith('countports:'):
            info = field[11:]
            return ({"count": result[0], "_id": result[1]}
                    for result in self.db.execute(
                        select([func.count().label("count"),
                                column('cnt')])\
                        .select_from(select([func.count().label('cnt')])\
                                     .select_from(self.tables.port)\
                                     .where(and_(
                                         self.tables.port.state == info,
                                         # self.tables.port.scan.in_(base),
                                         exists(select([1])\
                                                .select_from(base)\
                                                .where(
                                                    self.tables.port.scan == base.c.id
                                                )),
                                     ))\
                                     .group_by(self.tables.port.scan)\
                                     .alias('cnt'))\
                        .group_by('cnt').order_by(order).limit(topnbr)
                    ))
        elif field.startswith('portlist:'):
            ### Deux options pour filtrer:
            ###   -1- Port.scan.in_(base),
            ###   -2- exists(select([1])\
            ###       .select_from(base)\
            ###       .where(
            ###         Port.scan == base.c.id
            ###       )),
            ###
            ### D'après quelques tests, l'option -1- est plus beaucoup
            ### rapide quand (base) est pas ou peu sélectif, l'option
            ### -2- un peu plus rapide quand (base) est très sélectif
            ###
            ### TODO: vérifier si c'est pareil pour:
            ###  - countports:open
            ###  - tous les autres
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
                                tuple_(self.tables.port.protocol,
                                       self.tables.port.port).label('a'),
                                tuple_(self.tables.port.protocol,
                                       self.tables.port.port).label('a')
                            )).label('ports'),
                        ])\
                                     .where(and_(
                                         self.tables.port.state == info,
                                         self.tables.port.scan.in_(base),
                                         # exists(select([1])\
                                         #        .select_from(base)\
                                         #        .where(
                                         #            Port.scan == base.c.id
                                         #        )),
                                     ))\
                                     .group_by(self.tables.port.scan)\
                                     .alias('ports'))\
                        .group_by('ports').order_by(order).limit(topnbr)
                    ))
        elif field == "service":
            field = (self.tables.port,
                     [self.tables.port.service_name],
                     self.tables.port.state == "open")
        elif field.startswith("service:"):
            info = field[8:]
            if '/' in info:
                info = info.split('/', 1)
                field = (self.tables.port,
                         [self.tables.port.service_name],
                         and_(self.tables.port.protocol == info[0],
                              self.tables.port.port == int(info[1])))
            else:
                field = (self.tables.port,
                         [self.tables.port.service_name],
                         self.tables.port.port == int(info))
        elif field == "product":
            field = (self.tables.port,
                     [self.tables.port.service_name,
                      self.tables.port.service_product],
                     self.tables.port.state == "open")
        elif field.startswith("product:"):
            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = (self.tables.port,
                         [self.tables.port.service_name,
                          self.tables.port.service_product],
                         and_(self.tables.port.state == "open",
                              self.tables.port.port == info))
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = (self.tables.port,
                         [self.tables.port.service_name,
                          self.tables.port.service_product],
                         and_(self.tables.port.state == "open",
                              self.tables.port.port == info[1],
                              self.tables.port.protocol == info[0]))
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = (self.tables.port,
                         [self.tables.port.service_name,
                          self.tables.port.service_product],
                         and_(self.tables.port.state == "open",
                              self.tables.port.service_name == info))
        elif field == "devicetype":
            field = (self.tables.port,
                     [self.tables.port.service_devicetype],
                     self.tables.port.state == "open")
        elif field.startswith("devicetype:"):
            info = field[11:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = (self.tables.port,
                         [self.tables.port.service_devicetype],
                         and_(self.tables.port.state == "open",
                              self.tables.port.port == info))
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = (self.tables.port,
                         [self.tables.port.service_devicetype],
                         and_(self.tables.port.state == "open",
                              self.tables.port.port == info[1],
                              self.tables.port.protocol == info[0]))
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = (self.tables.port,
                         [self.tables.port.service_devicetype],
                         and_(self.tables.port.state == "open",
                              self.tables.port.service_name == info))
        elif field == "version":
            field = (self.tables.port,
                     [self.tables.port.service_name,
                      self.tables.port.service_product,
                      self.tables.port.service_version],
                     self.tables.port.state == "open")
        elif field.startswith("version:"):
            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = (self.tables.port,
                         [self.tables.port.service_name,
                          self.tables.port.service_product,
                          self.tables.port.service_version],
                         and_(self.tables.port.state == "open",
                              self.tables.port.port == info))
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = (self.tables.port,
                         [self.tables.port.service_name,
                          self.tables.port.service_product,
                          self.tables.port.service_version],
                         and_(self.tables.port.state == "open",
                              self.tables.port.port == info[1],
                              self.tables.port.protocol == info[0]))
            elif ':' in info:
                info = info.split(':', 1)
                flt = self.flt_and(flt, self.searchproduct(info[1], service=info[0]))
                field = (self.tables.port,
                         [self.tables.port.service_name,
                          self.tables.port.service_product,
                          self.tables.port.service_version],
                         and_(self.tables.port.state == "open",
                              self.tables.port.service_name == info[0],
                              self.tables.port.service_product == info[1]))
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = (self.tables.port,
                         [self.tables.port.service_name,
                          self.tables.port.service_product,
                          self.tables.port.service_version],
                         and_(self.tables.port.state == "open",
                              self.tables.port.service_name == info))


        elif field == "asnum":
            field = (self.tables.scan,
                     [self.tables.scan.info["as_num"]], None)
        elif field == "as":
            field = (self.tables.scan,
                     [self.tables.scan.info["as_num"],
                      self.tables.scan.info["as_name"]],
                     None)
        elif field == "country":
            field = (self.tables.scan,
                     [self.tables.scan.info["country_code"],
                      self.tables.scan.info["country_name"]],
                     None)
        elif field == "city":
            field = (self.tables.scan,
                     [self.tables.scan.info["country_code"],
                      self.tables.scan.info["city"]],
                     None)
        elif field == "net" or field.startswith("net:"):
            info = field[4:]
            info = int(info) if info else 24
            field = (self.tables.scan,
                     [func.set_masklen(text("scan.addr::cidr"), info)],
                     None)
        elif field == "script" or field.startswith("script:"):
            info = field[7:]
            if info:
                field = (self.tables.script,
                         [self.tables.script.output],
                         self.tables.script.name == info)
            else:
                field = (self.tables.script, [self.tables.script.name],
                         None)
        elif field in ["category", "categories"]:
            field = (self.tables.category, [self.tables.category.name],
                     None)
        elif field == "source":
            field = (self.tables.scan, [self.tables.scan.source], None)
        elif field == "domains":
            field = (self.tables.hostname,
                     [func.unnest(self.tables.hostname.domains)],
                     None)
        elif field.startswith("domains:"):
            level = int(field[8:]) - 1
            base1 = select([func.unnest(self.tables.hostname.domains)\
                            .label("domains")])\
                   .where(exists(select([1])\
                                 .select_from(base)\
                                 .where(self.tables.hostname.scan == base.c.id)))\
                   .cte("base1")
            return ({"count": result[1], "_id": result[0]}
                    for result in self.db.execute(
                        select([base1.c.domains, func.count().label("count")])\
                        .where(base1.c.domains.op('~')(
                            '^([^\\.]+\\.){%d}[^\\.]+$' % level
                        ))\
                        .group_by(base1.c.domains)\
                        .order_by(order)\
                        .limit(topnbr)
                    ))
        elif field == "hop":
            field = (self.tables.hop, [self.tables.hop.ipaddr], None)
        elif field.startswith('hop') and field[3] in ':>':
            ttl = int(field[4:])
            field = (self.tables.hop, [self.tables.hop.ipaddr],
                     (self.tables.hop.ttl > ttl) if field[3] == '>' else 
                     (self.tables.hop.ttl == ttl))
        elif field == 'file' or (field.startswith('file') and field[4] in '.:'):
            if field.startswith('file:'):
                scripts = field[5:]
                if '.' in scripts:
                    scripts, field = scripts.split('.', 1)
                else:
                    field = 'filename'
                scripts = scripts.split(',')
                flt = (self.tables.script.name == scripts[0] \
                        if len(scripts) == 1 else
                       self.tables.script.name.in_(scripts))
            else:
                field = field[5:] or 'filename'
                flt = True
            field = (
                self.tables.script,
                [func.jsonb_array_elements(
                    func.jsonb_array_elements(
                        self.tables.script.data['ls']['volumes']
                    ).op('->')('files')
                ).op('->>')(field).label(field)],
                and_(
                    flt,
                    self.tables.script.data.op('@>')(
                        '{"ls": {"volumes": [{"files": []}]}}'
                    ),
                ),
            )
        elif field.startswith('modbus.'):
            subfield = field[7:]
            field = (self.tables.script,
                     [self.tables.script.data['modbus-discover'][subfield]],
                     and_(self.tables.script.name == 'modbus-discover',
                          self.tables.script.data['modbus-discover'].has_key(subfield)))
        else:
            raise NotImplementedError()
        s_from = {
            self.tables.script: join(self.tables.script, self.tables.port),
            self.tables.port: self.tables.port,
            self.tables.category: join(self.tables.association_scan_category, self.tables.category),
            self.tables.hostname: self.tables.hostname,
            self.tables.hop: join(self.tables.trace, self.tables.hop),
        }
        where_clause = {
            self.tables.script: self.tables.port.scan == base.c.id,
            self.tables.port: self.tables.port.scan == base.c.id,
            self.tables.category: self.tables.association_scan_category.scan == base.c.id,
            self.tables.hostname: self.tables.hostname.scan == base.c.id,
            self.tables.hop: self.tables.trace.scan == base.c.id
        }
        if field[0] == self.tables.scan:
            req = flt.query(
                select([func.count().label("count")] + field[1])\
                .select_from(self.tables.scan)\
                .group_by(*field[1]),
            )
        else:
            req = select([func.count().label("count")] + field[1])\
                  .select_from(s_from[field[0]])\
                  .group_by(*field[1])\
                  .where(exists(select([1]).select_from(base)\
                                .where(where_clause[field[0]])))
        if field[2] is not None:
            req = req.where(field[2])
        if outputproc is None:
            return ({"count": result[0],
                     "_id": result[1:] if len(result) > 2 else result[1]}
                    for result in self.db.execute(req.order_by(order).limit(topnbr)))
        else:
            return ({"count": result[0],
                     "_id": outputproc(result[1:] if len(result) > 2
                                       else result[1])}
                    for result in self.db.execute(req.order_by(order).limit(topnbr)))

    @staticmethod
    def getscanids(host):
        return host['scanid']

    def getscan(self, scanid):
        if isinstance(scanid, basestring) and len(scanid) == 64:
            scanid = utils.decode_hex(scanid)
        return self.db.execute(
                select([self.tables.scanfile])\
                .where(self.tables.scanfile.sha256 == scanid)).fetchone()

    @classmethod
    def searchnonexistent(cls):
        return ActiveFilter(main=False, tables=cls.tables)

    @classmethod
    def _searchobjectid(cls, oid, neg=False):
        if len(oid) == 1:
            return ActiveFilter(main=(cls.tables.scan.id != oid[0]) if neg else
                              (cls.tables.scan.id == oid[0]), tables=cls.tables)
        return ActiveFilter(main=(cls.tables.scan.id.notin_(oid[0])) if neg else
                          (cls.tables.scan.id.in_(oid[0])), tables=cls.tables)

    @classmethod
    def searchcmp(cls, key, val, cmpop):
        if isinstance(key, basestring):
            key = cls.fields[key]
        return ActiveFilter(main=key.op(cmpop)(val), tables=cls.tables)

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        if neg:
            return ActiveFilter(main=cls.tables.scan.addr != cls.convert_ip(addr),
                tables=cls.tables)
        return ActiveFilter(main=cls.tables.scan.addr == cls.convert_ip(addr),
            tables=cls.tables)

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        hosts = [cls.convert_ip(host) for host in hosts]
        if neg:
            return ActiveFilter(main=cls.tables.scan.addr.notin_(hosts), tables=cls.tables)
        return ActiveFilter(main=cls.tables.scan.addr.in_(hosts), tables=cls.tables)

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        start, stop = cls.convert_ip(start), cls.convert_ip(stop)
        if neg:
            return ActiveFilter(main=or_(cls.tables.scan.addr < start, cls.tables.scan.addr > stop), tables=cls.tables)
        return ActiveFilter(main=and_(cls.tables.scan.addr >= start, cls.tables.scan.addr <= stop), tables=cls.tables)

    @classmethod
    def searchdomain(cls, name, neg=False):
        return ActiveFilter(hostname=[
            (not neg, cls._searchstring_re_inarray(
                        cls.tables.hostname.id,
                        cls.tables.hostname.domains, name,
                        neg=False)),
        ], tables=cls.tables)

    @classmethod
    def searchhostname(cls, name, neg=False):
        return ActiveFilter(hostname=[
            (not neg, cls._searchstring_re(
                        cls.tables.hostname.name,
                        name,
                        neg=False)),
        ], tables=cls.tables)

    @classmethod
    def searchcategory(cls, cat, neg=False):
        return ActiveFilter(category=[cls._searchstring_re(
                                    cls.tables.category.name,
                                    cat,
                                    neg=neg)], tables=cls.tables)

    @classmethod
    def searchsource(cls, src, neg=False):
        return ActiveFilter(main=cls._searchstring_re(
                                cls.tables.scan.source,
                                src,
                                neg=neg), tables=cls.tables)

    @classmethod
    def searchcountry(cls, country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        country = utils.country_unalias(country)
        return ActiveFilter(
            main=cls._searchstring_list(
                    cls.tables.scan.info['country_code'].astext,
                    country, neg=neg
                ),
            tables=cls.tables
        )

    @classmethod
    def searchcity(cls, city, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        city

        """
        return ActiveFilter(
            main=cls._searchstring_re(cls.tables.scan.info['city'].astext,
                                      city, neg=neg),
            tables=cls.tables
        )

    @classmethod
    def searchasnum(cls, asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        return ActiveFilter(
            main=cls._searchstring_list(cls.tables.scan.info['as_num'], 
                                        asnum, neg=neg, map_=str),
            tables=cls.tables
        )

    @classmethod
    def searchasname(cls, asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        return ActiveFilter(
            main=cls._searchstring_re(cls.tables.scan.info['as_name'].astext,
                                      asname, neg=neg),
            tables=cls.tables
        )

    @classmethod
    def searchport(cls, port, protocol='tcp', state='open', neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        if port == "host":
            return ActiveFilter(port=[
                (True, (cls.tables.port.port >= 0) if neg else
                       (cls.tables.port.port == -1)),
            ], tables=cls.tables)
        return ActiveFilter(port=[
            (not neg,
             and_(cls.tables.port.port == port,
                  cls.tables.port.protocol == protocol,
                  cls.tables.port.state == state)),
        ], tables=cls.tables)

    @classmethod
    def searchportsother(cls, ports, protocol='tcp', state='open'):
        """Filters records with at least one port other than those
        listed in `ports` with state `state`.

        """
        return ActiveFilter(port=[(True,
                                 and_(or_(cls.tables.port.port.notin_(ports),
                                          cls.tables.port.protocol != protocol),
                                      cls.tables.port.state == state))],
                            tables=cls.tables)

    @classmethod
    def searchports(cls, ports, protocol='tcp', state='open', neg=False):
        return cls.flt_and(*(cls.searchport(port, protocol=protocol,
                                            state=state, neg=neg)
                             for port in ports))

    @classmethod
    def searchcountopenports(cls, minn=None, maxn=None, neg=False):
        "Filters records with open port number between minn and maxn"
        assert minn is not None or maxn is not None
        req = select([column("scan")])\
              .select_from(select([cls.tables.port.scan.label("scan"),
                                   func.count().label("count")])\
                           .where(cls.tables.port.state == "open")\
                           .group_by(cls.tables.port.scan).alias("pcnt"))
        if minn == maxn:
            req = req.where(column("count") == minn)
        else:
            if minn is not None:
                req = req.where(column("count") >= minn)
            if maxn is not None:
                req = req.where(column("count") <= maxn)
        return ActiveFilter(main=cls.tables.scan.id.notin_(req) if neg else cls.tables.scan.id.in_(req),
                            tables=cls.tables)

    @classmethod
    def searchopenport(cls, neg=False):
        "Filters records with at least one open port."
        return ActiveFilter(port=[(not neg, cls.tables.port.state == "open")],
                            tables=cls.tables)

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        req = cls._searchstring_re(cls.tables.port.service_name, srv)
        if port is not None:
            req = and_(req, cls.tables.port.port == port)
        if protocol is not None:
            req = and_(req, cls.tables.port.protocol == protocol)
        return ActiveFilter(port=[(True, req)], tables=cls.tables)

    @classmethod
    def searchproduct(cls, product, version=None, service=None, port=None,
                      protocol=None):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        req = cls._searchstring_re(cls.tables.port.service_product, product)
        if version is not None:
            req = and_(req, cls._searchstring_re(
                                cls.tables.port.service_version, version))
        if service is not None:
            req = and_(req, cls._searchstring_re(
                                cls.tables.port.service_name, service))
        if port is not None:
            req = and_(req, cls.tables.port.port == port)
        if protocol is not None:
            req = and_(req, cls.tables.port.protocol == protocol)
        return ActiveFilter(port=[(True, req)], tables=cls.tables)

    @classmethod
    def searchscript(cls, name=None, output=None, values=None):
        """Search a particular content in the scripts results.

        """
        req = True
        if name is not None:
            req = and_(req, cls._searchstring_re(cls.tables.script.name,
                       name, neg=False))
        if output is not None:
            req = and_(req, cls._searchstring_re(cls.tables.script.output,
                       output, neg=False))
        if values:
            if name is None:
                raise TypeError(".searchscript() needs a `name` arg "
                                "when using a `values` arg")
            req = and_(req, cls.tables.script.data.contains(
                {xmlnmap.ALIASES_TABLE_ELEMS.get(name, name): values}
            ))
        return ActiveFilter(script=[req], tables=cls.tables)

    @classmethod
    def searchsvchostname(cls, srv):
        return ActiveFilter(port=[(True,
                                 cls.tables.port.service_hostname == srv)],
                            tables=cls.tables)

    @classmethod
    def searchwebmin(cls):
        return ActiveFilter(
            port=[(True, and_(cls.tables.port.service_name == 'http',
                              cls.tables.port.service_product == 'MiniServ',
                              cls.tables.port.service_extrainfo\
                                    != 'Webmin httpd'))],
            tables=cls.tables
        )

    @classmethod
    def searchx11(cls):
        return ActiveFilter(
            port=[(True, and_(cls.tables.port.service_name == 'X11',
                              cls.tables.port.service_extrainfo\
                                    != 'access denied'))],
            tables=cls.tables
        )

    def searchtimerange(self, start, stop, neg=False):
        if not isinstance(start, datetime.datetime):
            start = datetime.datetime.fromtimestamp(start)
        if not isinstance(stop, datetime.datetime):
            stop = datetime.datetime.fromtimestamp(stop)
        if neg:
            return ActiveFilter(
                main=(self.tables.scan.time_start < start) | 
                     (self.tables.scan.time_stop > stop),
                tables=self.tables
            )
        return ActiveFilter(
            main=(self.tables.scan.time_start >= start) &
                 (self.tables.scan.time_stop <= stop),
            tables=self.tables
        )

    @classmethod
    def searchfile(cls, fname=None, scripts=None):
        """Search shared files from a file name (either a string or a
        regexp), only from scripts using the "ls" NSE module.

        """
        if fname is None:
            req = cls.tables.script.data\
                  .op('@>')('{"ls": {"volumes": [{"files": []}]}}')
        else:
            if isinstance(fname, utils.REGEXP_T):
                base1 = select([
                    cls.tables.script.port,
                    func.jsonb_array_elements(
                        func.jsonb_array_elements(
                            cls.tables.script.data['ls']['volumes']
                        ).op('->')('files')
                    ).op('->>')('filename').label('filename')])\
                    .where(cls.tables.script.data.op('@>')(
                        '{"ls": {"volumes": [{"files": []}]}}'
                    ))\
                    .cte('base1')
                base2 = select([column('port')])\
                        .select_from(base1)\
                        .where(column('filename').op(
                            '~*' if (fname.flags & re.IGNORECASE) else '~'
                        )(fname.pattern))\
                        .cte('base2')
                return ActiveFilter(port=[(True, cls.tables.port.id.in_(base2))],
                                    tables=cls.tables)
            else:
                req = cls.tables.script.data.op('@>')(json.dumps(
                    {"ls": {"volumes": [{"files": [{"filename": fname}]}]}}
                ))
        if scripts is None:
            return ActiveFilter(script=[req], tables=cls.tables)
        if isinstance(scripts, basestring):
            scripts = [scripts]
        if len(scripts) == 1:
            return ActiveFilter(
                    script=[and_(cls.tables.script.name == scripts.pop(),
                            req)], tables=cls.tables)
        return ActiveFilter(
                    script=[and_(cls.tables.script.name.in_(scripts),
                            req)], tables=cls.tables)

    @classmethod
    def searchhttptitle(cls, title):
        return ActiveFilter(script=[
            cls.tables.script.name.in_(['http-title', 'html-title']),
            cls._searchstring_re(cls.tables.script.output, title),
        ], tables=cls.tables)

    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        res = cls.tables.hop.ipaddr == cls.convert_ip(hop)
        if ttl is not None:
            res &= cls.tables.hop.ttl == ttl
        return ActiveFilter(trace=[not_(res) if neg else res],
                            tables=cls.tables)

    @classmethod
    def searchhopdomain(cls, hop, neg=False):
        return ActiveFilter(trace=[cls._searchstring_re_inarray(
            cls.tables.hop.id, cls.tables.hop.domains, hop, neg=neg)],
                            tables = cls.tables
        )

    @classmethod
    def searchhopname(cls, hop, neg=False):
        return ActiveFilter(trace=[cls._searchstring_re(cls.tables.hop.host,
                                                      hop, neg=neg)],
                            tables=cls.tables)

    @classmethod
    def searchdevicetype(cls, devtype):
        return ActiveFilter(port=[
            (True, cls._searchstring_re(cls.tables.port.service_devicetype,
                                        devtype))
        ], tables=cls.tables)

    @classmethod
    def searchnetdev(cls):
        return ActiveFilter(port=[(
            True,
            cls.tables.port.service_devicetype.in_([
                'bridge',
                'broadband router',
                'firewall',
                'hub',
                'load balancer',
                'proxy server',
                'router',
                'switch',
                'WAP',
            ])
        )], tables=cls.tables)

    @classmethod
    def searchphonedev(cls):
        return ActiveFilter(port=[(
            True,
            cls.tables.port.service_devicetype.in_([
                'PBX',
                'phone',
                'telecom-misc',
                'VoIP adapter',
                'VoIP phone',
            ])
        )], tables=cls.tables)

    @classmethod
    def searchldapanon(cls):
        return ActiveFilter(port=[(
            True, cls.tables.port.service_extrainfo == 'Anonymous bind OK',
        )], tables=cls.tables)

    @classmethod
    def searchvsftpdbackdoor(cls):
        return ActiveFilter(port=[(
            True,
            and_(cls.tables.port.protocol == 'tcp',
                 cls.tables.port.state == 'open',
                 cls.tables.port.service_product == 'vsftpd',
                 cls.tables.port.service_version == '2.3.4')
        )], tables=cls.tables)


class PassiveFilter(Filter):
    def __init__(self, main=None, location=None, aut_sys=None,
                 uses_country=False, tables=None):
        self.tables = tables
        self.main = main
        self.location = location
        self.aut_sys = aut_sys
        self.uses_country = uses_country
    def __nonzero__(self):
        return self.main is not None or self.location is not None \
            or self.aut_sys is not None or self.uses_country
    def copy(self):
        return self.__class__(
            tables=self.tables,
            main=self.main,
            location=self.location,
            aut_sys=self.aut_sys,
            uses_country=self.uses_country,
        )
    def __and__(self, other):
        return self.__class__(
            tables=self.tables,
            main=self.fltand(self.main, other.main),
            location=self.fltand(self.location, other.location),
            aut_sys=self.fltand(self.aut_sys, other.aut_sys),
            uses_country=self.uses_country or other.uses_country,
        )
    def __or__(self, other):
        return self.__class__(
            tables=self.tables,
            main=self.fltor(self.main, other.main),
            location=self.fltor(self.location, other.location),
            aut_sys=self.fltor(self.aut_sys, other.aut_sys),
            uses_country=self.uses_country or other.uses_country,
        )
    @property
    def select_from(self):
        if self.location is not None:
            return [
                join(Host, self.tables.Passive),
                join(join(Location, Country), Location_Range)
                if self.uses_country else
                join(Location, Location_Range),
            ]
        if self.aut_sys is not None:
            return [join(Host, self.tables.passive), join(AS, AS_Range)]
        return join(Host, self.tables.passive)
    def query(self, req):
        if self.main is not None:
            req = req.where(self.main)
        if self.location is not None:
            req = req.where(self.location)
        if self.aut_sys is not None:
            req = req.where(self.aut_sys)
        return req



class PostgresDBPassive(PostgresDB, DBPassive):

    PassiveLayout = namedtuple('PassiveLayout', ['passive'])
    tables = PassiveLayout(Passive)
    shared_tables = [(Host, [Flow.src, Flow.dst]),
                     (Context, [Host.context])]
    fields = {
        "_id": Passive.id,
        "addr": Host.addr,
        "sensor": Passive.sensor,
        "count": Passive.count,
        "firstseen": Passive.firstseen,
        "lastseen": Passive.lastseen,
        "distance": Passive.info.op('->>')('distance'),
        "signature": Passive.info.op('->>')('signature'),
        "version": Passive.info.op('->>')('version'),
        "infos": Passive.moreinfo,
        "infos.domain": Passive.moreinfo.op('->>')('domain'),
        "infos.issuer": Passive.moreinfo.op('->>')('issuer'),
        "infos.md5hash": Passive.moreinfo.op('->>')('md5hash'),
        "infos.pubkeyalgo": Passive.moreinfo.op('->>')('pubkeyalgo'),
        "infos.sha1hash": Passive.moreinfo.op('->>')('sha1hash'),
        "infos.subject": Passive.moreinfo.op('->>')('subject'),
        "infos.domaintarget": Passive.moreinfo.op('->>')('domaintarget'),
        "infos.username": Passive.moreinfo.op('->>')('username'),
        "infos.password": Passive.moreinfo.op('->>')('password'),
        "port": Passive.port,
        "recontype": Passive.recontype,
        "source": Passive.source,
        "targetval": Passive.targetval,
        "value": Passive.value,
    }

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBPassive.__init__(self)
        self.flt_empty = PassiveFilter(tables=self.tables)

    def get_context(self, addr, sensor=None):
        ctxt = self.default_context(addr)
        if sensor is None:
            return ctxt
        return 'Public' if ctxt == 'Public' else '%s-%s' % (ctxt, sensor)

    def count(self, flt):
        return self.db.execute(
            flt.query(
                select([func.count()]).select_from(flt.select_from)
            )
        ).fetchone()[0]

    def remove(self, flt):
        base = flt.query(
            select([self.tables.passive.id]).select_from(flt.select_from)
        ).cte("base")
        self.db.execute(delete(self.tables.passive)\
                        .where(self.tables.passive.id.in_(base)))

    def _get(self, flt, limit=None, skip=None, sort=None):
        """Queries the passive database with the provided filter "flt", and
returns a generator.

        """
        req = flt.query(
            select([Host.addr, self.tables.passive.sensor,
                    self.tables.passive.count,
                    self.tables.passive.firstseen,
                    self.tables.passive.lastseen,
                    self.tables.passive.info,
                    self.tables.passive.port,
                    self.tables.passive.recontype,
                    self.tables.passive.source,
                    self.tables.passive.targetval,
                    self.tables.passive.value,
                    self.tables.passive.moreinfo])\
                    .select_from(flt.select_from)
        )
        for key, way in sort or []:
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return self.db.execute(req)

    def get_one(self, flt, skip=None):
        """Queries the passive database with the provided filter "flt", and
returns the first result, or None if no result exists."""
        return self._get(flt, limit=1, skip=skip).fetchone()

    def insert_or_update(self, timestamp, spec, getinfos=None):
        if spec is None:
            return
        if getinfos is not None:
            additional_info = getinfos(spec)
            try:
                spec.update(additional_info['infos'])
            except KeyError:
                pass
            try:
                spec.update(additional_info['fullinfos'])
            except KeyError:
                pass
        addr = spec.pop("addr", None)
        timestamp = datetime.datetime.fromtimestamp(timestamp)
        if addr:
            addr = self.convert_ip(addr)
            context = self.get_context(addr, sensor=spec.get('sensor'))
            hostid = self.store_host_context(addr, context, timestamp, timestamp)
        else:
            hostid = 0
        insrt = postgresql.insert(self.tables.passive)
        otherfields = dict(
            (key, spec.pop(key, "")) for key in ["sensor", "source",
                                                 "targetval", "value"]
        )
        info = dict(
            (key, spec.pop(key)) for key in ["distance", "signature", "version"]
            if key in spec
        )
        upsert = {
            'firstseen': func.least(
                self.tables.passive.firstseen,
                timestamp,
            ),
            'lastseen': func.greatest(
                self.tables.passive.lastseen,
                timestamp,
            ),
            'count': self.tables.passive.count + insrt.excluded.count,
        }
        self.db.execute(
            insrt.values(
                host=hostid,
                # sensor: otherfields
                count=spec.pop("count", 1),
                firstseen=timestamp,
                lastseen=timestamp,
                port=spec.pop("port", 0),
                recontype=spec.pop("recontype"),
                # source, targetval, value: otherfields
                fullvalue=spec.pop("fullvalue", None),
                info=info,
                moreinfo=spec,
                **otherfields
            )\
            .on_conflict_do_update(
                index_elements=['host', 'sensor', 'recontype', 'port', 'source',
                                'value', 'targetval', 'info'],
                set_=upsert,
            )
        )

    def insert_or_update_bulk(self, specs, getinfos=None,
                              separated_timestamps=True):
        """Like `.insert_or_update()`, but `specs` parameter has to be an
        iterable of `(timestamp, spec)` (if `separated_timestamps` is
        True) or `spec` (if it is False) values. This will perform
        PostgreSQL COPY FROM inserts with the major drawback that the
        `getinfos` parameter will be called (if it is not `None`) for
        each spec, even when the spec already exists in the database
        and the call was hence unnecessary.

        It's up to you to decide whether having bulk insert is worth
        it or if you want to go with the regular `.insert_or_update()`
        method.

        """
        more_to_read = True
        tmp = self.create_tmp_table(self.tables.passive, extracols=[
            Column("addr", postgresql.INET),
            Column("context", String(32)),
        ])
        if config.DEBUG_DB:
            total_upserted = 0
            total_start_time = time.time()
        while more_to_read:
            if config.DEBUG_DB:
                start_time = time.time()
            with PassiveCSVFile(specs, self.get_context, tmp, getinfos=getinfos,
                                separated_timestamps=separated_timestamps,
                                limit=config.POSTGRES_BATCH_SIZE) as fdesc:
                self.copy_from(fdesc, tmp.name)
                more_to_read = fdesc.more_to_read
                if config.DEBUG_DB:
                    count_upserted = fdesc.count
            self.db.execute(postgresql.insert(Context).from_select(
                ['name'],
                select([column("context")]).select_from(tmp)\
                .where(tmp.columns["context"].isnot(null()))\
                .distinct(column("context")),
            ).on_conflict_do_nothing())
            insrt = postgresql.insert(Host)
            self.db.execute(
                insrt\
                .from_select(
                    [column(col) for col in ['context', 'addr', 'firstseen',
                                             'lastseen']],
                    select([Context.id, column("addr"),
                            func.min_(column("firstseen")),
                            func.max_(column("lastseen"))])\
                    .select_from(join(Context, tmp,
                                      Context.name == column("context")))\
                    .where(tmp.columns["addr"].isnot(null()))\
                    .group_by(Context.id, column("addr"))
                )\
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
                )
            )
            insrt = postgresql.insert(self.tables.passive)
            self.db.execute(
                insrt\
                .from_select(
                    [column(col) for col in [
                        # Host.id
                        'host',
                        # sum / min / max
                        'count', 'firstseen', 'lastseen',
                        # grouped
                        'sensor', 'port', 'recontype', 'source', 'targetval',
                        'value', 'fullvalue', 'info', 'moreinfo'
                    ]],
                    select([Host.id, func.sum_(tmp.columns['count']),
                            func.min_(tmp.columns['firstseen']),
                            func.max_(tmp.columns['lastseen'])] + [
                                tmp.columns[col] for col in [
                                    'sensor', 'port', 'recontype', 'source',
                                    'targetval', 'value', 'fullvalue', 'info',
                                    'moreinfo']])\
                    .select_from(join(tmp, join(Context, Host),
                                      ((Context.name == tmp.columns["context"]) |
                                       (Context.name.is_(null()) &
                                        tmp.columns["context"].is_(null()))) &
                                      ((Host.addr == tmp.columns["addr"]) |
                                       (Host.addr.is_(null()) &
                                        tmp.columns["addr"].is_(null())))))\
                    .group_by(Host.id, *(tmp.columns[col] for col in [
                        'sensor', 'port', 'recontype', 'source', 'targetval',
                        'value', 'fullvalue', 'info', 'moreinfo']))
                )\
                .on_conflict_do_update(
                    index_elements=['host', 'sensor', 'recontype', 'port',
                                    'source', 'value', 'targetval', 'info'],
                    set_={
                        'firstseen': func.least(
                            self.tables.passive.firstseen,
                            insrt.excluded.firstseen,
                        ),
                        'lastseen': func.greatest(
                            self.tables.passive.lastseen,
                            insrt.excluded.lastseen,
                        ),
                        'count': self.tables.passive.count +
                                 insrt.excluded.count,
                    },
                )
            )
            self.db.execute(delete(tmp))
            if config.DEBUG_DB:
                stop_time = time.time()
                time_spent = stop_time - start_time
                total_upserted += count_upserted
                total_time_spent = stop_time - total_start_time
                utils.LOGGER.debug(
                    "DB:PERFORMANCE STATS %s upserts, %f s, %s/s\n"
                    "\ttotal: %s upserts, %f s, %s/s",
                    utils.num2readable(count_upserted), time_spent,
                    utils.num2readable(count_upserted / time_spent),
                    utils.num2readable(total_upserted), total_time_spent,
                    utils.num2readable(total_upserted / total_time_spent),
                )

    def migrate_from_db(self, db, flt=None, limit=None, skip=None, sort=None):
        if flt is None:
            flt = db.flt_empty
        self.insert_or_update_bulk(db.get(flt, limit=limit, skip=skip,
                                          sort=sort),
                                   separated_timestamps=False, getinfos=None)

    def migrate_from_mongodb_backup(self, backupfdesc):
        """This function uses a MongoDB backup file as a source to feed the
passive table."""
        def _backupgen(fdesc):
            for line in fdesc:
                try:
                    line = line.decode()
                except AttributeError:
                    pass
                try:
                    line = json.loads(line)
                except ValueError:
                    utils.LOGGER.warning("ignoring line [%r]", line)
                    continue
                try:
                    del line['_id']
                except KeyError:
                    pass
                line.update(line.pop('infos', {}))
                line.update(line.pop('fullinfos', {}))
                for key, value in viewitems(line):
                    if isinstance(value, dict) and len(value) == 1 \
                       and "$numberLong" in value:
                        line[key] = int(value['$numberLong'])
                yield line
        self.insert_or_update_bulk(_backupgen(backupfdesc), getinfos=None,
                                   separated_timestamps=False)

    def topvalues(self, field, flt=None, topnbr=10, sort=None,
                  limit=None, skip=None, least=False, distinct=True):
        """This method makes use of the aggregation framework to
        produce top values for a given field.

        If `distinct` is True (default), the top values are computed
        by distinct events. If it is False, they are computed based on
        the "count" field.

        """
        if isinstance(field, basestring):
            field = self.fields[field]
        outputproc = None
        if flt is None:
            flt = PassiveFilter(tables=self.tables)
        base = flt.query(
            select([self.tables.passive.id]).select_from(flt.select_from),
        ).cte("base")
        order = "count" if least else desc("count")
        req = flt.query(
            select([(func.count() if distinct else func.sum(self.tables.passive.count))\
                    .label("count"), field])\
            .select_from(flt.select_from)\
            .group_by(field)
        )
        if outputproc is None:
            outputproc = lambda val: val
        return (
            {"count": result[0],
             "_id": outputproc(result[1:] if len(result) > 2 else result[1])}
            for result in self.db.execute(req.order_by(order).limit(topnbr))
        )

    @classmethod
    def _searchobjectid(cls, oid, neg=False):
        if len(oid) == 1:
            return PassiveFilter(main=(cls.tables.passive.id != oid[0]) if neg else
                                 (cls.tables.passive.id == oid[0]),
                                 tables=cls.tables)
        return PassiveFilter(main=(cls.tables.passive.id.notin_(oid[0])) if neg else
                             (cls.tables.passive.id.in_(oid[0])),
                             tables=cls.tables)

    @classmethod
    def searchcmp(cls, key, val, cmpop):
        if isinstance(key, basestring):
            key = cls.fields[key]
        return PassiveFilter(main=key.op(cmpop)(val), tables=cls.tables)

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        return PassiveFilter(main=PostgresDB.searchhost(addr, neg=neg),
                             tables=cls.tables)

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        return PassiveFilter(main=PostgresDB.searchhosts(hosts, neg=neg),
                             tables=cls.tables)

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        return PassiveFilter(main=PostgresDB.searchrange(start, stop, neg=neg),
                             tables=cls.tables)

    @classmethod
    def searchrecontype(cls, rectype):
        return PassiveFilter(main=(cls.tables.passive.recontype == rectype),
                             tables=cls.tables)

    @classmethod
    def searchdns(cls, name, reverse=False, subdomains=False):
        return PassiveFilter(main=(
            (cls.tables.passive.recontype == 'DNS_ANSWER') &
            (
                (cls.tables.passive.moreinfo['domaintarget'
                                  if reverse else
                                  'domain'].has_key(name))
                if subdomains else
                cls._searchstring_re(cls.tables.passive.targetval
                                     if reverse else cls.tables.passive.value,
                                     name)
            )),
                             tables=cls.tables)

    @classmethod
    def searchuseragent(cls, useragent):
        return PassiveFilter(main=(
            (cls.tables.passive.recontype == 'HTTP_CLIENT_HEADER') &
            (cls.tables.passive.source == 'USER-AGENT') &
            (cls._searchstring_re(cls.tables.passive.value, useragent))),
                             tables=cls.tables)

    @classmethod
    def searchftpauth(cls):
        return PassiveFilter(main=(
            (cls.tables.passive.recontype == 'FTP_CLIENT') |
            (cls.tables.passive.recontype == 'FTP_SERVER')),
                             tables=cls.tables)

    @classmethod
    def searchpopauth(cls):
        return PassiveFilter(main=(
            (cls.tables.passive.recontype == 'POP_CLIENT') |
            (cls.tables.passive.recontype == 'POP_SERVER')),
                             tables=cls.tables)

    @classmethod
    def searchbasicauth(cls):
        return PassiveFilter(main=(
            ((cls.tables.passive.recontype == 'HTTP_CLIENT_HEADER') |
             (cls.tables.passive.recontype == 'HTTP_CLIENT_HEADER_SERVER')) &
            ((cls.tables.passive.source == 'AUTHORIZATION') |
             (cls.tables.passive.source == 'PROXY-AUTHORIZATION')) &
            cls.tables.passive.value.op('~*')('^Basic')),
                             tables=cls.tables)

    @classmethod
    def searchhttpauth(cls):
        return PassiveFilter(main=(
            ((cls.tables.passive.recontype == 'HTTP_CLIENT_HEADER') |
             (cls.tables.passive.recontype == 'HTTP_CLIENT_HEADER_SERVER')) &
            ((cls.tables.passive.source == 'AUTHORIZATION') |
             (cls.tables.passive.source == 'PROXY-AUTHORIZATION'))),
                             tables=cls.tables)

    @classmethod
    def searchcert(cls):
        return PassiveFilter(main=(
            (cls.tables.passive.recontype == 'SSL_SERVER') &
            (cls.tables.passive.source == 'cert')),
                             tables=cls.tables)

    @classmethod
    def searchcertsubject(cls, expr):
        return PassiveFilter(main=(
            (cls.tables.passive.recontype == 'SSL_SERVER') &
            (cls.tables.passive.source == 'cert') &
            (cls._searchstring_re(cls.tables.passive.moreinfo.op('->>')('subject'), expr))),
                             tables=cls.tables)

    @classmethod
    def searchcertissuer(cls, expr):
        return PassiveFilter(main=(
            (cls.tables.passive.recontype == 'SSL_SERVER') &
            (cls.tables.passive.source == 'cert') &
            (cls._searchstring_re(cls.tables.passive.moreinfo.op('->>')('issuer'), expr))),
                             tables=cls.tables)

    @classmethod
    def searchsensor(cls, sensor, neg=False):
        return PassiveFilter(
            main=(cls._searchstring_re(cls.tables.passive.sensor, sensor, neg=neg)),
            tables=cls.tables
        )

    @staticmethod
    def searchtimeago(delta, neg=False, new=False):
        field = Passive.lastseen if new else Passive.firstseen
        if not isinstance(delta, datetime.timedelta):
            delta = datetime.timedelta(seconds=delta)
        now = datetime.datetime.now()
        timestamp = now - delta
        return PassiveFilter(main=(field < timestamp if neg else
                                   field >= timestamp))

    @staticmethod
    def searchnewer(timestamp, neg=False, new=False):
        field = Passive.lastseen if new else Passive.firstseen
        if not isinstance(timestamp, datetime.datetime):
            timestamp = datetime.datetime.fromtimestamp(timestamp)
        return PassiveFilter(main=(field <= timestamp if neg else
                                   field > timestamp))

class PostgresDBNmap(PostgresDBActive, DBNmap):

    ScanFileLayout = namedtuple('ScanFileLayout',
                                ['scanfile', 'association_scan_scanfile'])

    NmapLayout = namedtuple('NmapLayout',
                            PostgresDBActive.ActiveLayout._fields + 
                            ScanFileLayout._fields)

    tables = NmapLayout(N_Category, Scan, N_Hostname, N_Port, N_Script, N_Trace,
                        N_Hop, Association_Scan_N_Hostname,
                        Association_Scan_N_Category, ScanFile,
                        Association_Scan_ScanFile)

    fields = {
        "_id": Scan.id,
        "addr": Scan.addr,
        "source": Scan.source,
        "scanid": Association_Scan_ScanFile.scan_file,
        "starttime": Scan.time_start,
        "endtime": Scan.time_stop,
        "infos": Scan.info,
        "state": Scan.state_reason_ttl,
        "state_reason": Scan.state_reason_ttl,
        "state_reason_ttl": Scan.state_reason_ttl,
        "categories": N_Category.name,
        "hostnames.name": N_Hostname.name,
        "hostnames.domains": N_Hostname.domains,
    }

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBNmap.__init__(self)
        self.content_handler = xmlnmap.Nmap2DB
        self.output_function = None
        self.flt_empty = NmapFilter(tables = self.tables)
        self.bulk = None

    def store_host(self, host):
        scanid = super(PostgresDBNmap, self).store_host(host, merge=False)
        insrt = postgresql.insert(self.tables.association_scan_scanfile)
        self.db.execute(insrt\
                        .values(scan=scanid,
                                scan_file=utils.decode_hex(host['scanid']))\
                        .on_conflict_do_nothing())

    def store_or_merge_host(self, host):
        self.store_host(host)

    def get(self, flt, limit=None, skip=None, sort=None,
            **kargs):
        records = super(PostgresDBNmap, self).get(flt, limit, skip,
                        sort, **kargs)
        for rec in records:
            rec["scanid"] = [
                scanfile[0] for scanfile in self.db.execute(
                    select([self.tables.association_scan_scanfile.scan_file])\
                    .where(self.tables.association_scan_scanfile.scan == rec["_id"]))
            ]
            yield rec

    def remove(self, host):
        """Removes the host scan result. "host" must be a record as yielded by
        .get() or a valid ActiveFilter() instance.

        The scan files that are no longer linked to a scan are removed
        at the end of the call.

        """
        if isinstance(host, dict):
            base = [host['_id']]
        else:
            base = host.query(select([self.tables.scan.id])).cte("base")
        self.db.execute(delete(self.tables.scan)\
                        .where(self.tables.scan.id.in_(base)))
        # remove unused scan files
        base = select([self.tables.association_scan_scanfile.scan_file])\
               .cte('base')
        self.db.execute(delete(self.tables.scanfile)\
                        .where(self.tables.scanfile.sha256.notin_(base)))


# View

class Association_View_V_Category_Columns(object):
    scan = Column(Integer, primary_key=True)
    category = Column(Integer, primary_key=True)

class Association_View_V_Category(Base, Association_View_V_Category_Columns):
    __tablename__ = 'association_view_v_category'
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['view.id'], ondelete="CASCADE"),
        ForeignKeyConstraint(['category'], ['v_category.id'], ondelete="CASCADE"),
    )

class V_Category(Base, Category_Columns):
    __tablename__ = 'v_category'
    __table_args__ = (
        Index('ix_v_category_name', 'name', unique=True),
    )

class V_Script(Base, Script_Columns):
    __tablename__ = 'v_script'
    __table_args__ = (
        ForeignKeyConstraint(['port'], ['v_port.id'], ondelete="CASCADE"),
        Index('ix_v_script_data', 'data', postgresql_using='gin'),
        Index('ix_v_script_name', 'name'),
    )

class V_Port(Base, Port_Columns):
    __tablename__ = 'v_port'
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['view.id'], ondelete="CASCADE"),
        Index('ix_v_port_scan_port', 'scan', 'port', 'protocol', unique=True),
    )

class V_Hostname(Base, Hostname_Columns):
    __tablename__ = "v_hostname"
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['view.id'], ondelete="CASCADE"),
        Index('ix_v_hostname_scan_name_type', 'scan', 'name', 'type',
              unique=True),
    )

class Association_View_V_Hostname_Columns(object):
    scan = Column(Integer, primary_key=True)
    hostname = Column(Integer,  primary_key=True)

class Association_View_V_Hostname(Base, Association_View_V_Hostname_Columns):
    __tablename__ = 'association_view_v_hostname'
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['view.id'], ondelete="CASCADE"),
        ForeignKeyConstraint(['hostname'], ['v_hostname.id'], ondelete="CASCADE"),
    )

class V_Trace(Base, Trace_Columns):
    __tablename__ = "v_trace"
    __table_args__ = (
        ForeignKeyConstraint(['scan'], ['view.id'], ondelete="CASCADE"),
    )

class V_Hop(Base, Hop_Columns):
    __tablename__ = "v_hop"
    __table_args__ = (
        ForeignKeyConstraint(['trace'], ['v_trace.id'], ondelete="CASCADE"),
        Index('ix_v_hop_ipaddr_ttl', 'ipaddr', 'ttl'),
    )

class View(Base, Scan_Columns):
    __tablename__ = "view"
    __table_args__ = (
        Index('ix_view_info', 'info', postgresql_using='gin'),
        Index('ix_view_host', 'addr', 'source', unique=True),
        Index('ix_view_time', 'time_start', 'time_stop'),
    )


class PostgresDBView(PostgresDBActive, DBView):

    ViewLayout = PostgresDBActive.ActiveLayout

    tables = ViewLayout(V_Category, View, V_Hostname, V_Port,
                             V_Script, V_Trace, V_Hop,
                             Association_View_V_Hostname,
                             Association_View_V_Category)

    fields = {
        "_id": View.id,
        "addr": View.addr,
        "source": View.source,
        "starttime": View.time_start,
        "endtime": View.time_stop,
        "infos": View.info,
        "state": View.state_reason_ttl,
        "state_reason": View.state_reason_ttl,
        "state_reason_ttl": View.state_reason_ttl,
        "categories": V_Category.name,
        "hostnames.name": V_Hostname.name,
        "hostnames.domains": V_Hostname.domains,
    }

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBView.__init__(self)
        self.output_function = None
        self.flt_empty = ViewFilter(tables = self.tables)
        self.bulk = None

    def store_host(self, host):
        self.start_store_hosts()
        super(PostgresDBView, self).store_host(host, merge=True)
        self.stop_store_hosts()

    def store_or_merge_host(self, host):
        self.store_host(host)

    def remove(self, host):
        """Removes the host view. "host" must be a record as yielded by
        .get() or a valid ActiveFilter() instance.

        """
        if isinstance(host, dict):
            base = [host['_id']]
        else:
            base = host.query(select([self.tables.scan.id])).cte("base")
        self.db.execute(delete(self.tables.scan)\
                        .where(self.tables.scan.id.in_(base)))

