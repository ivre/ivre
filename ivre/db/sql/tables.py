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

"""This sub-module contains SQL tables and columns definition.

"""


import json
import re
import sqlite3


from sqlalchemy import event, func, Column, ForeignKey, Index, Boolean, \
    DateTime, Float, Integer, LargeBinary, String, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import UserDefinedType, TypeDecorator
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.operators import custom_op, json_getitem_op
from sqlalchemy.sql.expression import BinaryExpression
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.engine import Engine


from ivre import xmlnmap, utils


# sqlite

@event.listens_for(Engine, 'connect')
def sqlite_engine_connect(dbapi_connection, connection_record):
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return

    def least(a, b):
        return min(a, b)

    dbapi_connection.create_function('least', 2, least)

    def greatest(a, b):
        return max(a, b)

    dbapi_connection.create_function('greatest', 2, greatest)

    def regexp(s, p):
        return re.search(p, s) is not None

    dbapi_connection.create_function('REGEXP', 2, regexp)

    def iregexp(s, p):
        return re.search(p, s, re.IGNORECASE) is not None

    dbapi_connection.create_function('IREGEXP', 2, iregexp)

    def access(d, k):
        return json.dumps(json.loads(d).get(k), sort_keys=True)

    dbapi_connection.create_function('ACCESS', 2, access)

    def access_astext(d, k):
        return str(json.loads(d).get(k))

    dbapi_connection.create_function('ACCESS_TXT', 2, access_astext)

    def has_key(d, k):
        return k in json.loads(d) if json.loads(d) else False

    dbapi_connection.create_function('HAS_KEY', 2, has_key)


@compiles(BinaryExpression, 'sqlite')
def extend_binary_expression(element, compiler, **kwargs):
    if isinstance(element.operator, custom_op):
        opstring = element.operator.opstring
        if opstring == '~':
            return compiler.process(func.REGEXP(element.left, element.right))
        if opstring == '~*':
            return compiler.process(func.IREGEXP(element.left, element.right))
        if opstring == '->':
            return compiler.process(func.ACCESS(element.left, element.right))
        if opstring == '->>':
            return compiler.process(func.ACCESS_TXT(element.left,
                                                    element.right))
        if opstring == '?':
            return compiler.process(func.HAS_KEY(element.left, element.right))
    # FIXME: Variant base type Comparator seems to be used here.
    if element.operator == json_getitem_op:
        return compiler.process(func.ACCESS(element.left, element.right))
    return compiler.visit_binary(element)


# Types

class DefaultJSONB(UserDefinedType):

    def __init__(self):
        self.__visit_name__ = "DefaultJSONB"

    @property
    def python_type(self):
        return dict

    def get_col_spec(self):
        return self.__visit_name__

    def bind_processor(self, dialect):
        def process(value):
            if value is not None:
                value = json.dumps(value, sort_keys=True)
            return value
        return process

    def result_processor(self, dialect, coltype):
        def process(value):
            if value is not None:
                value = json.loads(value)
            return value
        return process


SQLJSONB = postgresql.JSONB().with_variant(DefaultJSONB(), "sqlite")


class DefaultARRAY(TypeDecorator):

    impl = Text

    def __init__(self, item_type, *args, **kwargs):
        TypeDecorator.__init__(self, *args, **kwargs)
        self.item_type = item_type

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value, sort_keys=True)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


def SQLARRAY(item_type):
    return postgresql.ARRAY(item_type)\
        .with_variant(DefaultARRAY(item_type), "sqlite")


class DefaultINET(UserDefinedType):

    def __init__(self):
        self.__visit_name__ = "DefaultINET"

    @property
    def python_type(self):
        return int

    def get_col_spec(self):
        return self.__visit_name__

    def bind_processor(self, dialect):
        def process(value):
            if value is None:
                return -1
            if value is not None:
                value = utils.ip2int(value)
            return value
        return process

    def result_processor(self, dialect, coltype):
        def process(value):
            if value == -1:
                return None
            if value is not None:
                value = utils.int2ip(value)
            return value
        return process


SQLINET = postgresql.INET()\
    .with_variant(DefaultINET(), "sqlite")


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


# Tables
Base = declarative_base()


# Flow
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
    sports = Column(SQLARRAY(Integer))
    __table_args__ = (
        # Index('host_idx_tag_addr', 'tag', 'addr', unique=True),
    )


# Nmap
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
    scaninfo = Column(SQLJSONB)
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
    data = Column(SQLJSONB)
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
    state_reason_ip = Column(SQLINET)
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
    domains = Column(SQLARRAY(String(255)), index=True)
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
    ipaddr = Column(SQLINET)
    ttl = Column(Integer)
    rtt = Column(Float)
    host = Column(String(255), index=True)
    domains = Column(SQLARRAY(String(255)), index=True)
    __table_args__ = (
        Index('ix_hop_ipaddr_ttl', 'ipaddr', 'ttl'),
    )


class Scan(Base):
    __tablename__ = "scan"
    id = Column(Integer, primary_key=True)
    addr = Column(SQLINET, nullable=False)
    source = Column(String(32), nullable=False)
    info = Column(SQLJSONB)
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
        Index('ix_scan_host_archive', 'addr', 'source', 'archive',
              unique=True),
        Index('ix_scan_time', 'time_start', 'time_stop'),
    )


# Passive

class Passive(Base):
    __tablename__ = "passive"
    id = Column(Integer, primary_key=True)
    addr = Column(SQLINET)
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
    info = Column(SQLJSONB)
    moreinfo = Column(SQLJSONB)
    # moreinfo and fullvalue contain data that are not tested for
    # unicity on insertion (the unicity is guaranteed by the value)
    # for performance reasons
    __table_args__ = (
        Index('ix_passive_record', 'addr', 'sensor', 'recontype', 'port',
              'source', 'value', 'targetval', 'info', unique=True),
    )
