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
import json
import re
import sys
import socket
import struct
import time

from sqlalchemy import event, create_engine, desc, func, text, column, \
    literal_column, delete, exists, insert, join, select, union, update, null, \
    and_, not_, or_, Column, ForeignKey, Index, Table, ARRAY, Boolean, \
    DateTime, Float, Integer, LargeBinary, String, Text, tuple_
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import UserDefinedType
from sqlalchemy.ext.declarative import declarative_base

from ivre.db import DB, DBFlow, DBData, DBNmap, DBPassive
from ivre import config, utils, xmlnmap

Base = declarative_base()

class Context(Base):
    __tablename__ = "context"
    id = Column(Integer, primary_key=True)
    name = Column(String(32))
    __table_args__ = (
        Index('ix_context_name', 'name', unique=True),
    )

def _after_context_create(target, connection, **kwargs):
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

def _after_host_create(target, connection, **kwargs):
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
        for _ in xrange(skip):
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
                line = self.fixline(self.inp.next())
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
        for i in xrange(2):
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
    country_code = Column(String(2), ForeignKey('country.code', ondelete='CASCADE'))
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
    def __init__(self, hostgen, get_context, table, merge):
        self.get_context = get_context
        self.table = table
        self.inp = hostgen
        self.merge = merge
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
        if line["info"].get("city") == "Norwood" and (
                '\xad' in repr(line['info']) or 'xad' in repr(line['info'])
        ):
            print line["info"]
        line["archive"] = 0
        line["merge"] = False
        for field in ["categories"]:
            if field in line:
                line[field] = "{%s}" % json.dumps(line[field])[1:-1]
        for port in line.get('ports', []):
            for script in port.get('scripts', []):
                if 'masscan' in script and 'raw' in script['masscan']:
                    script['masscan']['raw'] = script['masscan']['raw'].encode(
                        'base64'
                    ).replace('\n', '')
            if 'screendata' in port:
                port['screendata'] = port['screendata'].encode('base64')\
                                                       .replace('\n', '')
        for field in ["hostnames", "ports", "info"]:
            if field in line:
                line[field] = json.dumps(line[field]).replace('\\', '\\\\')
        return ["\\N" if line.get(col.name) is None else str(line.get(col.name))
                for col in self.table.columns]


class Association_Scan_ScanFile(Base):
    __tablename__ = 'association_scan_scanfile'
    scan = Column(Integer, ForeignKey('scan.id', ondelete='CASCADE'),
                  primary_key=True)
    scan_file = Column(LargeBinary(32), ForeignKey('scan_file.sha256',
                                                   ondelete='CASCADE'),
                       primary_key=True)

class ScanFile(Base):
    __tablename__ = "scan_file"
    sha256 = Column(LargeBinary(32), primary_key=True)
    args = Column(Text)
    scaninfo = Column(postgresql.JSONB)
    scanner = Column(String(16))
    start = Column(DateTime)
    version = Column(String(16))
    xmloutputversion = Column(String(16))

class Association_Scan_Category(Base):
    __tablename__ = 'association_scan_category'
    scan = Column(Integer, ForeignKey('scan.id', ondelete='CASCADE'),
                  primary_key=True)
    category = Column(Integer, ForeignKey('category.id', ondelete='CASCADE'),
                      primary_key=True)

class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(32))
    __table_args__ = (
        Index('ix_category_name', 'name', unique=True),
    )

class Script(Base):
    __tablename__ = 'script'
    port = Column(Integer, ForeignKey('port.id', ondelete='CASCADE'),
                  primary_key=True)
    name = Column(String(64), primary_key=True)
    output = Column(Text)
    data = Column(postgresql.JSONB)
    __table_args__ = (
        Index('ix_script_data', 'data', postgresql_using='gin'),
        Index('ix_script_name', 'name'),
    )

class Port(Base):
    __tablename__ = 'port'
    id = Column(Integer, primary_key=True)
    scan = Column(Integer, ForeignKey('scan.id', ondelete='CASCADE'))
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
    __table_args__ = (
        Index('ix_port_scan_port', 'scan', 'port', 'protocol', unique=True),
    )

class Hostname(Base):
    __tablename__ = "hostname"
    id = Column(Integer, primary_key=True)
    scan = Column(Integer, ForeignKey('scan.id', ondelete='CASCADE'))
    domains = Column(ARRAY(String(255)), index=True)
    name = Column(String(255), index=True)
    type = Column(String(16), index=True)
    __table_args__ = (
        Index('ix_hostname_scan_name_type', 'scan', 'name', 'type',
              unique=True),
    )

class Association_Scan_Hostname(Base):
    __tablename__ = 'association_scan_hostname'
    scan = Column(Integer, ForeignKey('scan.id', ondelete='CASCADE'),
                  primary_key=True)
    hostname = Column(Integer, ForeignKey('hostname.id', ondelete='CASCADE'),
                      primary_key=True)

class Trace(Base):
    # FIXME: unicity (scan, port, protocol) to handle merge. Special
    # value for port when not present?
    __tablename__ = "trace"
    id = Column(Integer, primary_key=True)
    scan = Column(Integer, ForeignKey('scan.id', ondelete='CASCADE'),
                  nullable=False)
    port = Column(Integer)
    protocol = Column(String(16))

class Hop(Base):
    __tablename__ = "hop"
    id = Column(Integer, primary_key=True)
    trace = Column(Integer, ForeignKey('trace.id', ondelete='CASCADE'),
                   nullable=False)
    ipaddr = Column(postgresql.INET)
    ttl = Column(Integer)
    rtt = Column(Float)
    host = Column(String(255), index=True)
    domains = Column(ARRAY(String(255)), index=True)
    __table_args__ = (
        Index('ix_hop_ipaddr_ttl', 'ipaddr', 'ttl'),
    )

class Scan(Base):
    __tablename__ = "scan"
    id = Column(Integer, primary_key=True)
    addr = Column(postgresql.INET, nullable=False)
    source = Column(String(32), nullable=False)
    info = Column(postgresql.JSONB)
    time_start = Column(DateTime)
    time_stop = Column(DateTime)
    state = Column(String(32))
    state_reason = Column(String(32))
    state_reason_ttl = Column(Integer)
    archive = Column(Integer, nullable=False, index=True)
    merge = Column(Boolean, nullable=False)
    schema_version = Column(Integer, default=xmlnmap.SCHEMA_VERSION)
    __table_args__ = (
        Index('ix_scan_info', 'info', postgresql_using='gin'),
        Index('ix_scan_host_archive', 'addr', 'source', 'archive', unique=True),
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
                line["firstseen"] = datetime.datetime.fromtimestamp(line["firstseen"])
            if not isinstance(line["lastseen"], datetime.datetime):
                line["lastseen"] = datetime.datetime.fromtimestamp(line["lastseen"])
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
        for key, value in line.iteritems():
            if key not in ["info", "moreinfo"] and \
               isinstance(value, basestring):
                if isinstance(value, unicode):
                    try:
                        value = value.encode('latin-1')
                    except:
                        pass
                line[key] = "".join(c if ' ' <= c <= '~' else
                                    ('\\x%s' % c.encode('hex'))
                                    for c in value).replace('\\', '\\\\')
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
    def convert_ip(addr):
        try:
            return utils.int2ip(addr)
        except (TypeError, struct.error):
            return addr

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
        if isinstance(oid, (basestring, int, long)):
            oid = [int(oid)]
        else:
            oid = [int(oid) for oid in oid]
        return cls._searchobjectid(oid, neg=neg)

    @staticmethod
    def _searchobjectid(oid, neg=False):
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
        return (res.itervalues().next() for res in self.db.execute(req))

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
                value = map(map_, value)
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
    tables = [Flow]
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
        with CSVFile(fname) as fdesc:
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


class Filter(object):
    @staticmethod
    def fltand(flt1, flt2):
        return flt1 if flt2 is None else flt2 if flt1 is None else and_(flt1, flt2)
    @staticmethod
    def fltor(flt1, flt2):
        return flt1 if flt2 is None else flt2 if flt1 is None else or_(flt1, flt2)


class NmapFilter(Filter):
    def __init__(self, main=None, hostname=None, category=None, source=None,
                 port=None, script=None, trace=None):
        self.main = main
        self.hostname = [] if hostname is None else hostname
        self.category = [] if category is None else category
        self.source = [] if source is None else source
        self.port = [] if port is None else port
        self.script = [] if script is None else script
        self.trace = [] if trace is None else trace
    def copy(self):
        return self.__class__(
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
            main=self.fltor(self.main, other.main),
            hostname=self.hostname + other.hostname,
            category=self.category + other.category,
            source=self.source + other.source,
            port=self.port + other.port,
            script=self.script + other.script,
            trace=self.trace + other.trace,
        )
    def select_from_base(self, base=Scan):
        if base in [Scan, Scan.__mapper__]:
            base = Scan
        else:
            base = join(Scan, base)
        return base
    @property
    def select_from(self):
        return self.select_from_base()
    def query(self, req, archive=False):
        # TODO: improve performances
        #   - use a materialized view for `Scan` with `archive == 0`?
        if self.main is not None:
            req = req.where(self.main)
        if archive:
            req = req.where(Scan.archive > 0)
        else:
            req = req.where(Scan.archive == 0)
        for incl, subflt in self.hostname:
            base = select([Hostname.scan]).where(subflt).cte("base")
            if incl:
                req = req.where(Scan.id.in_(base))
            else:
                req = req.where(Scan.id.notin_(base))
        # See <http://stackoverflow.com/q/17112345/3223422> - "Using
        # INTERSECT with tables from a WITH clause"
        for subflt in self.category:
            req = req.where(exists(
                select([1])\
                .select_from(join(Category, Association_Scan_Category))\
                .where(subflt)\
                .where(Association_Scan_Category.scan == Scan.id)
            ))
        for incl, subflt in self.port:
            if incl:
                req = req.where(exists(
                    select([1])\
                    .select_from(Port)\
                    .where(subflt)\
                    .where(Port.scan == Scan.id)
                ))
            else:
                base = select([Port.scan]).where(subflt).cte("base")
                req = req.where(Scan.id.notin_(base))
        for subflt in self.script:
            req = req.where(exists(
                select([1])\
                .select_from(join(Script, Port))\
                .where(subflt)\
                .where(Port.scan == Scan.id)
            ))
        for subflt in self.trace:
            req = req.where(exists(
                select([1])\
                .select_from(join(Trace, Hop))\
                .where(subflt)\
                .where(Trace.scan == Scan.id)
            ))
        return req


class PostgresDBNmap(PostgresDB, DBNmap):
    tables = [ScanFile, Category, Scan, Hostname, Port, Script, Trace, Hop,
              Association_Scan_Hostname, Association_Scan_Category,
              Association_Scan_ScanFile]
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
        "categories": Category.name,
        "hostnames.name": Hostname.name,
        "hostnames.domains": Hostname.domains,
    }

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        DBNmap.__init__(self)
        self.content_handler = xmlnmap.Nmap2Posgres
        self.output_function = None
        self.flt_empty = NmapFilter()
        self.bulk = None

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
        if 'scaninfos' in scan:
            scan["scaninfo"] = scan.pop('scaninfos')
        scan["sha256"] = scan.pop('_id').decode('hex')
        insrt = insert(ScanFile).values(
            **dict(
                (key, scan[key])
                for key in ['sha256', 'args', 'scaninfo', 'scanner', 'start',
                            'version', 'xmloutputversion']
                if key in scan
            )
        )
        if config.DEBUG:
            scanfileid = self.db.execute(
                insrt.returning(ScanFile.sha256)
            ).fetchone()[0]
            utils.LOGGER.debug("SCAN STORED: %r", scanfileid.encode('hex'))
        else:
            self.db.execute(insrt)

    def store_hosts(self, hosts, merge=False):
        tmp = self.create_tmp_table(Scan, extracols=[
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
        with ScanCSVFile(hosts, self.get_context, tmp, merge) as fdesc:
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
        source = host.get('source', '')
        if merge:
            insrt = postgresql.insert(Scan)
            scanid, scan_tstop, merge = self.db.execute(
                insrt.values(
                    addr=addr,
                    source=source,
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
                    index_elements=['addr', 'source', 'archive'],
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
                newest = None
        else:
            curarchive = self.db.execute(select([func.max(Scan.archive)])\
                                         .where(and_(Scan.addr == addr,
                                                     Scan.source == source)))\
                                .fetchone()[0]
            if curarchive is not None:
                self.db.execute(update(Scan).where(and_(
                    Scan.addr == addr,
                    Scan.source == source,
                    Scan.archive == 0,
                )).values(archive=curarchive + 1))
            scanid = self.db.execute(insert(Scan)\
                                     .values(
                                         addr=addr,
                                         source=source,
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
            if 'state_reason_ip' in port:
                port['state_reason_ip'] = self.convert_ip(port['state_reason_ip'])
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
                        insrt = postgresql.insert(Script)
                        self.bulk.append(insrt\
                                         .values(
                                             port=portid,
                                             name=name,
                                             output=output,
                                             data=script
                                         )\
                                         .on_conflict_do_nothing())
                else:
                    self.bulk.append(insert(Script).values(
                        port=portid,
                        name=name,
                        output=output,
                        data=script
                    ))
        if not merge:
            # FIXME: handle traceroutes on merge
            for trace in host.get('traces', []):
                traceid = self.db.execute(insert(Trace).values(
                    scan=scanid,
                    port=trace.get('port'),
                    protocol=trace['protocol']
                ).returning(Trace.id)).fetchone()[0]
                for hop in trace.get('hops'):
                    hop['ipaddr'] = self.convert_ip(hop['ipaddr'])
                    self.bulk.append(insert(Hop).values(
                        trace=traceid,
                        ipaddr=self.convert_ip(hop['ipaddr']),
                        ttl=hop["ttl"],
                        rtt=None if hop["rtt"] == '--' else hop["rtt"],
                        host=hop.get("host"),
                        domains=hop.get("domains"),
                    ))
            # FIXME: handle hostnames on merge
            for hostname in host.get('hostnames', []):
                self.bulk.append(insert(Hostname).values(
                    scan=scanid,
                    domains=hostname.get('domains'),
                    name=hostname.get('name'),
                    type=hostname.get('type'),
                ))
        utils.LOGGER.debug("HOST STORED: %r", scanid)

    def store_or_merge_host(self, host, gettoarchive, merge=False):
        self.store_host(host, merge=merge)

    def count(self, flt, archive=False, **_):
        return self.db.execute(
            flt.query(select([func.count()]), archive=archive)\
            .select_from(flt.select_from)
        ).fetchone()[0]

    @staticmethod
    def _distinct_req(field, flt, archive=False):
        flt = flt.copy()
        return flt.query(
            select([field.distinct()]).select_from(
                flt.select_from_base(field.parent)
            ),
            archive=archive
        )

    def get_open_port_count(self, flt, archive=False, limit=None, skip=None):
        req = flt.query(select([Scan.id]), archive=archive)
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
                select([func.count(Port.id), Scan.time_start, Scan.addr])\
                .select_from(join(Port, Scan))\
                .where(Port.state == "open")\
                .group_by(Scan.addr, Scan.time_start)\
                .where(Scan.id.in_(base))
            )
        )

    def get_ips_ports(self, flt, archive=False, limit=None, skip=None):
        req = flt.query(select([Scan.id]), archive=archive)
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
                    Scan.time_start, Scan.addr,
                ])\
                .select_from(join(Port, Scan))\
                .group_by(Scan.addr, Scan.time_start)\
                .where(Scan.id.in_(base))
            )
        )

    def getlocations(self, flt, archive=False, limit=None, skip=None):
        req = flt.query(
            select([func.count(Scan.id), Scan.info['coordinates'].astext])\
            .where(Scan.info.has_key('coordinates')),
            archive=archive,
        )
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return ({'_id': Point().result_processor(None, None)(rec[1])[::-1],
                 'count': rec[0]}
                for rec in
                self.db.execute(req.group_by(Scan.info['coordinates'].astext)))

    def get(self, flt, archive=False, limit=None, skip=None, sort=None,
            **kargs):
        req = flt.query(select([Scan]).select_from(flt.select_from),
                        archive=archive)
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
            (rec["_id"], rec["addr"], rec["source"], rec["infos"],
             rec["starttime"], rec["endtime"], rec["state"], rec["state_reason"],
             rec["state_reason_ttl"], rec["archive"], rec["merge"],
             rec["schema_version"]) = scanrec
            if not rec["infos"]:
                del rec["infos"]
            categories = select([Association_Scan_Category.category])\
                         .where(Association_Scan_Category.scan == rec["_id"])\
                         .cte("categories")
            rec["categories"] = [cat[0] for cat in
                                 self.db.execute(
                                     select([Category.name])\
                                     .where(Category.id == categories.c.category)
                                 )]
            rec["scanid"] = [
                scanfile[0] for scanfile in self.db.execute(
                    select([Association_Scan_ScanFile.scan_file])\
                    .where(Association_Scan_ScanFile.scan == rec["_id"]))
            ]
            for port in self.db.execute(select([Port])\
                                        .where(Port.scan == rec["_id"])):
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
                for script in self.db.execute(select([Script.name,
                                                      Script.output,
                                                      Script.data])\
                                              .where(Script.port == portid)):
                    recp.setdefault('scripts', []).append(
                        dict(id=script.name,
                             output=script.output,
                             **(script.data if script.data else {}))
                    )
                rec.setdefault('ports', []).append(recp)
            for trace in self.db.execute(select([Trace])\
                                         .where(Trace.scan == rec["_id"])):
                curtrace = {}
                rec.setdefault('traces', []).append(curtrace)
                curtrace['port'] = trace['port']
                curtrace['protocol'] = trace['protocol']
                curtrace['hops'] = []
                for hop in self.db.execute(select([Hop])\
                                           .where(Hop.trace == trace['id'])\
                                           .order_by(Hop.ttl)):
                    curtrace['hops'].append(dict(
                        (key, hop[key]) for key in ['ipaddr', 'ttl', 'rtt',
                                                    'host', 'domains']
                    ))
            for hostname in self.db.execute(
                    select([Hostname])\
                    .where(Hostname.scan == rec["_id"])
            ):
                rec.setdefault('hostnames', []).append(dict(
                    (key, hostname[key]) for key in ['name', 'type', 'domains']
                ))
            yield rec

    def remove(self, host, archive=False):
        """Removes the host scan result. "host" must be a record as yielded by
        .get() or a valid NmapFilter() instance.

        The scan files that are no longer linked to a scan are removed
        at the end of the call.

        """
        if isinstance(host, dict):
            base = [host['_id']]
        else:
            base = host.query(select([Scan.id]), archive=archive).cte("base")
        self.db.execute(delete(Scan).where(Scan.id.in_(base)))
        # remove unused scan files
        base = select([Association_Scan_ScanFile.scan_file]).cte('base')
        self.db.execute(delete(ScanFile).where(ScanFile.sha256.notin_(base)))

    def topvalues(self, field, flt=None, topnbr=10, sort=None,
                  limit=None, skip=None, least=False, archive=False):
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
        base = flt.query(
            select([Scan.id]).select_from(flt.select_from),
            archive=archive,
        ).cte("base")
        order = "count" if least else desc("count")
        outputproc = None
        if field == "port":
            field = (Port, [Port.protocol, Port.port], Port.state == "open")
        elif field == "ttl":
            field = (Port, [Port.state_reason_ttl],
                     Port.state_reason_ttl != None)
        elif field == "ttlinit":
            field = (
                Port,
                [func.least(255, func.power(2, func.ceil(
                    func.log(2, Port.state_reason_ttl)
                )))],
                Port.state_reason_ttl != None,
            )
            outputproc = int
        elif field.startswith('port:'):
            info = field[5:]
            field = (Port, [Port.protocol, Port.port],
                     (Port.state == info)
                     if info in set(['open', 'filtered', 'closed', 'open|filtered'])
                     else (Port.service_name == info))
        elif field.startswith('countports:'):
            info = field[11:]
            return ({"count": result[0], "_id": result[1]}
                    for result in self.db.execute(
                        select([func.count().label("count"),
                                column('cnt')])\
                        .select_from(select([func.count().label('cnt')])\
                                     .select_from(Port)\
                                     .where(and_(
                                         Port.state == info,
                                         # Port.scan.in_(base),
                                         exists(select([1])\
                                                .select_from(base)\
                                                .where(
                                                    Port.scan == base.c.id
                                                )),
                                     ))\
                                     .group_by(Port.scan)\
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
                                tuple_(Port.protocol, Port.port).label('a'),
                                tuple_(Port.protocol, Port.port).label('a')
                            )).label('ports'),
                        ])\
                                     .where(and_(
                                         Port.state == info,
                                         Port.scan.in_(base),
                                         # exists(select([1])\
                                         #        .select_from(base)\
                                         #        .where(
                                         #            Port.scan == base.c.id
                                         #        )),
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
        elif field.startswith("product:"):
            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = (Port, [Port.service_name, Port.service_product],
                         and_(Port.state == "open", Port.port == info))
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = (Port, [Port.service_name, Port.service_product],
                         and_(Port.state == "open", Port.port == info[1],
                              Port.protocol == info[0]))
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = (Port, [Port.service_name, Port.service_product],
                         and_(Port.state == "open", Port.service_name == info))
        elif field == "devicetype":
            field = (Port, [Port.service_devicetype], Port.state == "open")
        elif field.startswith("devicetype:"):
            info = field[11:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = (Port, [Port.service_devicetype],
                         and_(Port.state == "open", Port.port == info))
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = (Port, [Port.service_devicetype],
                         and_(Port.state == "open", Port.port == info[1],
                              Port.protocol == info[0]))
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = (Port, [Port.service_devicetype],
                         and_(Port.state == "open", Port.service_name == info))
        elif field == "version":
            field = (Port, [Port.service_name, Port.service_product,
                            Port.service_version],
                     Port.state == "open")
        elif field.startswith("version:"):
            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = (Port, [Port.service_name, Port.service_product,
                                Port.service_version],
                         and_(Port.state == "open", Port.port == info))
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = (Port, [Port.service_name, Port.service_product,
                                Port.service_version],
                         and_(Port.state == "open", Port.port == info[1],
                              Port.protocol == info[0]))
            elif ':' in info:
                info = info.split(':', 1)
                flt = self.flt_and(flt, self.searchproduct(info[1], service=info[0]))
                field = (Port, [Port.service_name, Port.service_product,
                                Port.service_version],
                         and_(Port.state == "open", Port.service_name == info[0],
                              Port.service_product == info[1]))
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = (Port, [Port.service_name, Port.service_product,
                                Port.service_version],
                         and_(Port.state == "open", Port.service_name == info))


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
            field = (Scan, [func.set_masklen(text("scan.addr::cidr"), info)], None)
        elif field == "script" or field.startswith("script:"):
            info = field[7:]
            if info:
                field = (Script, [Script.output], Script.name == info)
            else:
                field = (Script, [Script.name], None)
        elif field in ["category", "categories"]:
            field = (Category, [Category.name], None)
        elif field == "source":
            field = (Scan, [Scan.source], None)
        elif field == "domains":
            field = (Hostname, [func.unnest(Hostname.domains)], None)
        elif field.startswith("domains:"):
            level = int(field[8:]) - 1
            base1 = select([func.unnest(Hostname.domains).label("domains")])\
                   .where(exists(select([1])\
                                 .select_from(base)\
                                 .where(Hostname.scan == base.c.id)))\
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
            field = (Hop, [Hop.ipaddr], None)
        elif field.startswith('hop') and field[3] in ':>':
            ttl = int(field[4:])
            field = (Hop, [Hop.ipaddr],
                     (Hop.ttl > ttl) if field[3] == '>' else (Hop.ttl == ttl))
        elif field == 'file' or (field.startswith('file') and field[4] in '.:'):
            if field.startswith('file:'):
                scripts = field[5:]
                if '.' in scripts:
                    scripts, field = scripts.split('.', 1)
                else:
                    field = 'filename'
                scripts = scripts.split(',')
                flt = (Script.name == scripts[0] if len(scripts) == 1 else
                       Script.name.in_(scripts))
            else:
                field = field[5:] or 'filename'
                flt = True
            field = (
                Script,
                [func.jsonb_array_elements(
                    func.jsonb_array_elements(
                        Script.data['ls']['volumes']
                    ).op('->')('files')
                ).op('->>')(field).label(field)],
                and_(flt,
                     Script.data.op('@>')(
                         '{"ls": {"volumes": [{"files": []}]}}'
                     ),
                ),
            )
        elif field.startswith('modbus.'):
            subfield = field[7:]
            field = (Script,
                     [Script.data['modbus-discover'][subfield]],
                     and_(Script.name == 'modbus-discover',
                          Script.data['modbus-discover'].has_key(subfield)))
        else:
            raise NotImplementedError()
        s_from = {
            Script: join(Script, Port),
            Port: Port,
            Category: join(Association_Scan_Category, Category),
            Hostname: Hostname,
            Hop: join(Trace, Hop),
        }
        where_clause = {
            Script: Port.scan == base.c.id,
            Port: Port.scan == base.c.id,
            Category: Association_Scan_Category.scan == base.c.id,
            Hostname: Hostname.scan == base.c.id,
            Hop: Trace.scan == base.c.id
        }
        if field[0] == Scan:
            req = flt.query(
                select([func.count().label("count")] + field[1])\
                .select_from(Scan)\
                .group_by(*field[1]),
                archive=archive,
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

    def getscan(self, scanid, archive=False):
        if isinstance(scanid, basestring) and len(scanid) == 64:
            scanid = scanid.decode('hex')
        return self.db.execute(select([ScanFile])\
                               .where(ScanFile.sha256 == scanid)).fetchone()

    @staticmethod
    def searchnonexistent():
        return NmapFilter(main=False)

    @staticmethod
    def _searchobjectid(oid, neg=False):
        if len(oid) == 1:
            return NmapFilter(main=(Scan.id != oid[0]) if neg else
                              (Scan.id == oid[0]))
        return NmapFilter(main=(Scan.id.notin_(oid[0])) if neg else
                          (Scan.id.in_(oid[0])))

    @classmethod
    def searchcmp(cls, key, val, cmpop):
        if isinstance(key, basestring):
            key = cls.fields[key]
        return NmapFilter(main=key.op(cmpop)(val))

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        if neg:
            return NmapFilter(main=Scan.addr != cls.convert_ip(addr))
        return NmapFilter(main=Scan.addr == cls.convert_ip(addr))

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        hosts = [cls.convert_ip(host) for host in hosts]
        if neg:
            return NmapFilter(main=Scan.addr.notin_(hosts))
        return NmapFilter(main=Scan.addr.in_(hosts))

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        start, stop = cls.convert_ip(start), cls.convert_ip(stop)
        if neg:
            return NmapFilter(main=or_(Scan.addr < start, Scan.addr > stop))
        return NmapFilter(main=and_(Scan.addr >= start, Scan.addr <= stop))

    @classmethod
    def searchdomain(cls, name, neg=False):
        return NmapFilter(hostname=[
            (not neg, cls._searchstring_re_inarray(Hostname.id,
                                                   Hostname.domains, name,
                                                   neg=False)),
        ])

    @classmethod
    def searchhostname(cls, name, neg=False):
        return NmapFilter(hostname=[
            (not neg, cls._searchstring_re(Hostname.name, name, neg=False)),
        ])

    @classmethod
    def searchcategory(cls, cat, neg=False):
        return NmapFilter(category=[cls._searchstring_re(Category.name, cat,
                                                         neg=neg)])

    @classmethod
    def searchsource(cls, src, neg=False):
        return NmapFilter(main=cls._searchstring_re(Scan.source, src,
                                                    neg=neg))

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
            return NmapFilter(port=[
                (True, (Port.port >= 0) if neg else (Port.port == -1)),
            ])
        return NmapFilter(port=[
            (not neg,
             and_(Port.port == port,
                  Port.protocol == protocol,
                  Port.state == state)),
        ])

    @staticmethod
    def searchportsother(ports, protocol='tcp', state='open'):
        """Filters records with at least one port other than those
        listed in `ports` with state `state`.

        """
        return NmapFilter(port=[(True,
                                 and_(or_(Port.port.notin_(ports),
                                          Port.protocol != protocol),
                                      Port.state == state))])

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
            req = req.where(column("count") == minn)
        else:
            if minn is not None:
                req = req.where(column("count") >= minn)
            if maxn is not None:
                req = req.where(column("count") <= maxn)
        return NmapFilter(main=Scan.id.notin_(req) if neg else Scan.id.in_(req))

    @staticmethod
    def searchopenport(neg=False):
        "Filters records with at least one open port."
        return NmapFilter(port=[(not neg, Port.state == "open")])

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        req = cls._searchstring_re(Port.service_name, srv)
        if port is not None:
            req = and_(req, Port.port == port)
        if protocol is not None:
            req = and_(req, Port.protocol == protocol)
        return NmapFilter(port=[(True, req)])

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
        return NmapFilter(port=[(True, req)])

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
        return NmapFilter(port=[(True, Port.service_hostname == srv)])

    @staticmethod
    def searchwebmin():
        return NmapFilter(
            port=[(True, and_(Port.service_name == 'http',
                              Port.service_product == 'MiniServ',
                              Port.service_extrainfo != 'Webmin httpd'))]
        )

    @staticmethod
    def searchx11():
        return NmapFilter(
            port=[(True, and_(Port.service_name == 'X11',
                              Port.service_extrainfo != 'access denied'))]
        )

    def searchtimerange(self, start, stop, neg=False):
        if not isinstance(start, datetime.datetime):
            start = datetime.datetime.fromtimestamp(start)
        if not isinstance(stop, datetime.datetime):
            stop = datetime.datetime.fromtimestamp(stop)
        if neg:
            return NmapFilter(
                main=(Scan.time_start < start) | (Scan.time_stop > stop)
            )
        return NmapFilter(
            main=(Scan.time_start >= start) & (Scan.time_stop <= stop)
        )

    @classmethod
    def searchfile(cls, fname=None, scripts=None):
        """Search shared files from a file name (either a string or a
        regexp), only from scripts using the "ls" NSE module.

        """
        if fname is None:
            req = Script.data.op('@>')('{"ls": {"volumes": [{"files": []}]}}')
        else:
            if isinstance(fname, utils.REGEXP_T):
                base1 = select([
                    Script.port,
                    func.jsonb_array_elements(
                        func.jsonb_array_elements(
                            Script.data['ls']['volumes']
                        ).op('->')('files')
                    ).op('->>')('filename').label('filename')])\
                    .where(Script.data.op('@>')(
                        '{"ls": {"volumes": [{"files": []}]}}'
                    ))\
                    .cte('base1')
                base2 = select([column('port')])\
                        .select_from(base1)\
                        .where(column('filename').op(
                            '~*' if (fname.flags & re.IGNORECASE) else '~'
                        )(fname.pattern))\
                        .cte('base2')
                return NmapFilter(port=[(True, Port.id.in_(base2))])
            else:
                req = Script.data.op('@>')(json.dumps(
                    {"ls": {"volumes": [{"files": [{"filename": fname}]}]}}
                ))
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

    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        res = Hop.ipaddr == cls.convert_ip(hop)
        if ttl is not None:
            res &= Hop.ttl == ttl
        return NmapFilter(trace=[not_(res) if neg else res])

    @classmethod
    def searchhopdomain(cls, hop, neg=False):
        return NmapFilter(trace=[cls._searchstring_re_inarray(
            Hop.id, Hop.domains, hop, neg=neg
        )])

    @classmethod
    def searchhopname(cls, hop, neg=False):
        return NmapFilter(trace=[cls._searchstring_re(Hop.host,
                                                      hop, neg=neg)])

    @classmethod
    def searchdevicetype(cls, devtype):
        return NmapFilter(port=[
            (True, cls._searchstring_re(Port.service_devicetype, devtype))
        ])

    @staticmethod
    def searchnetdev():
        return NmapFilter(port=[(
            True,
            Port.service_devicetype.in_([
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
        )])

    @staticmethod
    def searchphonedev():
        return NmapFilter(port=[(
            True,
            Port.service_devicetype.in_([
                'PBX',
                'phone',
                'telecom-misc',
                'VoIP adapter',
                'VoIP phone',
            ])
        )])

    @staticmethod
    def searchldapanon():
        return NmapFilter(port=[(
            True, Port.service_extrainfo == 'Anonymous bind OK',
        )])

    @staticmethod
    def searchvsftpdbackdoor():
        return NmapFilter(port=[(
            True,
            and_(Port.protocol == 'tcp',
                 Port.state == 'open',
                 Port.service_product == 'vsftpd',
                 Port.service_version == '2.3.4')
        )])


class PassiveFilter(Filter):
    def __init__(self, main=None, location=None, aut_sys=None,
                 uses_country=False):
        self.main = main
        self.location = location
        self.aut_sys = aut_sys
        self.uses_country = uses_country
    def __nonzero__(self):
        return self.main is not None or self.location is not None \
            or self.aut_sys is not None or self.uses_country is not None
    def copy(self):
        return self.__class__(
            main=self.main,
            location=self.location,
            aut_sys=self.aut_sys,
            uses_country=self.uses_country,
        )
    def __and__(self, other):
        return self.__class__(
            main=self.fltand(self.main, other.main),
            location=self.fltand(self.location, other.location),
            aut_sys=self.fltand(self.aut_sys, other.aut_sys),
            uses_country=self.uses_country or other.uses_country,
        )
    def __or__(self, other):
        return self.__class__(
            main=self.fltor(self.main, other.main),
            location=self.fltor(self.location, other.location),
            aut_sys=self.fltor(self.aut_sys, other.aut_sys),
            uses_country=self.uses_country or other.uses_country,
        )
    @property
    def select_from(self):
        if self.location is not None:
            return [
                join(Passive, Host),
                join(join(Location, Country), Location_Range)
                if self.uses_country else
                join(Location, Location_Range),
            ]
        if self.aut_sys is not None:
            return [join(Passive, Host), join(AS, AS_Range)]
        return join(Passive, Host)
    def query(self, req):
        if self.main is not None:
            req = req.where(self.main)
        if self.location is not None:
            req = req.where(self.location)
        if self.aut_sys is not None:
            req = req.where(self.aut_sys)
        return req


class PostgresDBPassive(PostgresDB, DBPassive):
    tables = [Passive]
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
        self.flt_empty = PassiveFilter()

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
            select([Passive.id]).select_from(flt.select_from)
        ).cte("base")
        self.db.execute(delete(Passive).where(Passive.id.in_(base)))

    def _get(self, flt, limit=None, skip=None, sort=None):
        """Queries the passive database with the provided filter "flt", and
returns a generator.

        """
        req = flt.query(
            select([Host.addr, Passive.sensor, Passive.count, Passive.firstseen,
                    Passive.lastseen, Passive.info, Passive.port,
                    Passive.recontype, Passive.source, Passive.targetval,
                    Passive.value, Passive.moreinfo]).select_from(flt.select_from)
        )
        for key, way in sort or []:
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return self.db.execute(req)

    def get_one(self, flt, limit=None, skip=None):
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
        insrt = postgresql.insert(Passive)
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
                Passive.firstseen,
                timestamp,
            ),
            'lastseen': func.greatest(
                Passive.lastseen,
                timestamp,
            ),
            'count': Passive.count + insrt.excluded.count,
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
        tmp = self.create_tmp_table(Passive, extracols=[
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
            insrt = postgresql.insert(Passive)
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
                            Passive.firstseen,
                            insrt.excluded.firstseen,
                        ),
                        'lastseen': func.greatest(
                            Passive.lastseen,
                            insrt.excluded.lastseen,
                        ),
                        'count': Passive.count + insrt.excluded.count,
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
                for key, value in line.iteritems():
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
            flt = PassiveFilter()
        base = flt.query(
            select([Passive.id]).select_from(flt.select_from),
        ).cte("base")
        order = "count" if least else desc("count")
        req = flt.query(
            select([(func.count() if distinct else func.sum(Passive.count))\
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

    @staticmethod
    def _searchobjectid(oid, neg=False):
        if len(oid) == 1:
            return PassiveFilter(main=(Passive.id != oid[0]) if neg else
                                 (Passive.id == oid[0]))
        return PassiveFilter(main=(Passive.id.notin_(oid[0])) if neg else
                             (Passive.id.in_(oid[0])))

    @classmethod
    def searchcmp(cls, key, val, cmpop):
        if isinstance(key, basestring):
            key = cls.fields[key]
        return PassiveFilter(main=key.op(cmpop)(val))

    @staticmethod
    def searchhost(addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        return PassiveFilter(main=PostgresDB.searchhost(addr, neg=neg))

    @staticmethod
    def searchhosts(hosts, neg=False):
        return PassiveFilter(main=PostgresDB.searchhosts(hosts, neg=neg))

    @staticmethod
    def searchrange(start, stop, neg=False):
        return PassiveFilter(main=PostgresDB.searchrange(start, stop, neg=neg))

    @staticmethod
    def searchrecontype(rectype):
        return PassiveFilter(main=(Passive.recontype == rectype))

    @classmethod
    def searchdns(cls, name, reverse=False, subdomains=False):
        return PassiveFilter(main=(
            (Passive.recontype == 'DNS_ANSWER') &
            (
                (Passive.moreinfo['domaintarget'
                                  if reverse else
                                  'domain'].has_key(name))
                if subdomains else
                (cls._searchstring_re(Passive.targetval
                                      if reverse else Passive.value), name)
            )
        ))

    @classmethod
    def searchuseragent(cls, useragent):
        return PassiveFilter(main=(
            (Passive.recontype == 'HTTP_CLIENT_HEADER') &
            (Passive.source == 'USER-AGENT') &
            (cls._searchstring_re(Passive.value, useragent))
        ))

    @staticmethod
    def searchftpauth():
        return PassiveFilter(main=(
            (Passive.recontype == 'FTP_CLIENT') |
            (Passive.recontype == 'FTP_SERVER')
        ))

    @staticmethod
    def searchpopauth():
        return PassiveFilter(main=(
            (Passive.recontype == 'POP_CLIENT') |
            (Passive.recontype == 'POP_SERVER')
        ))

    @staticmethod
    def searchbasicauth():
        return PassiveFilter(main=(
            ((Passive.recontype == 'HTTP_CLIENT_HEADER') |
             (Passive.recontype == 'HTTP_CLIENT_HEADER_SERVER')) &
            ((Passive.source == 'AUTHORIZATION') |
             (Passive.source == 'PROXY-AUTHORIZATION')) &
            Passive.value.op('~*')('^Basic')
        ))

    @staticmethod
    def searchhttpauth():
        return PassiveFilter(main=(
            ((Passive.recontype == 'HTTP_CLIENT_HEADER') |
             (Passive.recontype == 'HTTP_CLIENT_HEADER_SERVER')) &
            ((Passive.source == 'AUTHORIZATION') |
             (Passive.source == 'PROXY-AUTHORIZATION'))
        ))

    @staticmethod
    def searchcert():
        return PassiveFilter(main=(
            (Passive.recontype == 'SSL_SERVER') &
            (Passive.source == 'cert')
        ))

    @classmethod
    def searchcertsubject(cls, expr):
        return PassiveFilter(main=(
            (Passive.recontype == 'SSL_SERVER') &
            (Passive.source == 'cert') &
            (cls._searchstring_re(Passive.moreinfo.op('->>')('subject'), expr))
        ))

    @classmethod
    def searchcertissuer(cls, expr):
        return PassiveFilter(main=(
            (Passive.recontype == 'SSL_SERVER') &
            (Passive.source == 'cert') &
            (cls._searchstring_re(Passive.moreinfo.op('->>')('issuer'), expr))
        ))

    @classmethod
    def searchsensor(cls, sensor, neg=False):
        return PassiveFilter(
            main=(cls._searchstring_re(Passive.sensor, sensor, neg=neg)),
        )
