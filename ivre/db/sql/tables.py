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

"""This sub-module contains SQL tables and columns definition.

"""


import json
import re
import sqlite3


from sqlalchemy import (
    event,
    func,
    Column,
    ForeignKey,
    Index,
    DateTime,
    Float,
    Integer,
    LargeBinary,
    String,
    Text,
    ForeignKeyConstraint,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import UserDefinedType, TypeDecorator
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql.operators import custom_op, json_getitem_op
from sqlalchemy.sql.expression import BinaryExpression
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.engine import Engine


from ivre import passive, utils, xmlnmap


# sqlite


@event.listens_for(Engine, "connect")
def sqlite_engine_connect(dbapi_connection, connection_record):
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return

    def least(a, b):
        return min(a, b)

    dbapi_connection.create_function("least", 2, least)

    def greatest(a, b):
        return max(a, b)

    dbapi_connection.create_function("greatest", 2, greatest)

    def regexp(s, p):
        return re.search(p, s) is not None

    dbapi_connection.create_function("_REGEXP", 2, regexp)

    def iregexp(s, p):
        return re.search(p, s, re.IGNORECASE) is not None

    dbapi_connection.create_function("_IREGEXP", 2, iregexp)

    def access(d, k):
        if k.startswith("$."):
            # With sqlalchemy >= 1.3.0, this seems to be
            # necessary. Please help me if you can.
            k = json.loads(k[2:])
        return json.dumps(json.loads(d).get(k), sort_keys=True)

    dbapi_connection.create_function("_ACCESS", 2, access)

    def access_astext(d, k):
        return str(json.loads(d).get(k))

    dbapi_connection.create_function("_ACCESS_TXT", 2, access_astext)

    def has_key(d, k):
        return k in json.loads(d) if json.loads(d) else False

    dbapi_connection.create_function("_HAS_KEY", 2, has_key)


@compiles(BinaryExpression, "sqlite")
def extend_binary_expression(element, compiler, **kwargs):
    if isinstance(element.operator, custom_op):
        opstring = element.operator.opstring
        if opstring == "~":
            return compiler.process(func._REGEXP(element.left, element.right))
        if opstring == "~*":
            return compiler.process(func._IREGEXP(element.left, element.right))
        if opstring == "->":
            return compiler.process(func._ACCESS(element.left, element.right))
        if opstring == "->>":
            return compiler.process(func._ACCESS_TXT(element.left, element.right))
        if opstring == "?":
            return compiler.process(func._HAS_KEY(element.left, element.right))
    # FIXME: Variant base type Comparator seems to be used here.
    if element.operator is json_getitem_op:
        return compiler.process(func._ACCESS(element.left, element.right))
    return compiler.visit_binary(element)


# Types


class DefaultJSONB(UserDefinedType):

    python_type = dict

    def __init__(self):
        self.__visit_name__ = "DefaultJSONB"

    def get_col_spec(self):
        return self.__visit_name__

    @staticmethod
    def bind_processor(dialect):
        def process(value):
            if value is not None:
                value = json.dumps(value, sort_keys=True)
            return value

        return process

    @staticmethod
    def result_processor(dialect, coltype):
        def process(value):
            if value is not None:
                value = json.loads(value)
            return value

        return process


SQLJSONB = postgresql.JSONB().with_variant(DefaultJSONB(), "sqlite")


class DefaultARRAY(TypeDecorator):

    impl = Text
    cache_ok = False

    def __init__(self, item_type, *args, **kwargs):
        TypeDecorator.__init__(self, *args, **kwargs)
        self.item_type = item_type

    @staticmethod
    def process_bind_param(value, dialect):
        if value is not None:
            value = json.dumps(value, sort_keys=True)
        return value

    @staticmethod
    def process_result_value(value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


def SQLARRAY(item_type):
    return postgresql.ARRAY(item_type).with_variant(DefaultARRAY(item_type), "sqlite")


class DefaultINET(UserDefinedType):

    python_type = bytes

    def __init__(self):
        self.__visit_name__ = "VARCHAR(32)"

    def get_col_spec(self):
        return self.__visit_name__

    def bind_processor(self, dialect):
        def process(value):
            return self.python_type(b"" if not value else utils.ip2bin(value))

        return process

    @staticmethod
    def result_processor(dialect, coltype):
        def process(value):
            return None if not value else utils.bin2ip(value)

        return process


SQLINET = postgresql.INET().with_variant(DefaultINET(), "sqlite")


class Point(UserDefinedType):

    # pylint: disable=no-self-use
    def get_col_spec(self):
        return "POINT"

    def bind_expression(self, bindvalue):
        return func.Point_In(bindvalue, type_=self)

    @staticmethod
    def bind_processor(dialect):
        def process(value):
            if value is None:
                return None
            return "%f,%f" % value

        return process

    @staticmethod
    def result_processor(dialect, coltype):
        def process(value):
            if value is None:
                return None
            return tuple(float(val) for val in value[1:-1].split(","))

        return process


# Tables
Base = declarative_base()


# Flow
class Flow(Base):
    __tablename__ = "flow"
    id = Column(Integer, primary_key=True)
    proto = Column(String(32), index=True)
    dport = Column(Integer, index=True)
    src = Column(Integer, ForeignKey("host.id", ondelete="RESTRICT"))
    dst = Column(Integer, ForeignKey("host.id", ondelete="RESTRICT"))
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


# Active
class _Association_Scan_ScanFile:
    scan = Column(Integer, primary_key=True)
    scan_file = Column(LargeBinary(32), primary_key=True)


class _ScanFile:
    sha256 = Column(LargeBinary(32), primary_key=True)
    args = Column(Text)
    scaninfo = Column(SQLJSONB)
    scanner = Column(String(16))
    start = Column(DateTime)
    end = Column(DateTime)
    elapsed = Column(Float)
    version = Column(String(16))
    xmloutputversion = Column(String(16))


class _Association_Scan_Category:
    scan = Column(Integer, primary_key=True)
    category = Column(Integer, primary_key=True)


class _Category:
    id = Column(Integer, primary_key=True)
    name = Column(String(32))


class _Script:
    port = Column(Integer, primary_key=True)
    name = Column(String(64), primary_key=True)
    output = Column(Text)
    data = Column(SQLJSONB)


class _Port:
    id = Column(Integer, primary_key=True)
    scan = Column(Integer)
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


class _Hostname:
    id = Column(Integer, primary_key=True)
    scan = Column(Integer)
    domains = Column(SQLARRAY(String(255)), index=True)
    name = Column(String(255), index=True)
    type = Column(String(16), index=True)


class _Association_Scan_Hostname:
    __tablename__ = "association_scan_hostname"
    scan = Column(Integer, primary_key=True)
    hostname = Column(Integer, primary_key=True)


class _Trace:
    id = Column(Integer, primary_key=True)
    scan = Column(Integer, nullable=False)
    port = Column(Integer)
    protocol = Column(String(16))


class _Hop:
    id = Column(Integer, primary_key=True)
    trace = Column(Integer, nullable=False)
    ipaddr = Column(SQLINET)
    ttl = Column(Integer)
    rtt = Column(Float)
    host = Column(String(255), index=True)
    domains = Column(SQLARRAY(String(255)), index=True)


class _Scan:
    id = Column(Integer, primary_key=True)
    addr = Column(SQLINET, nullable=False)
    # source = Column()
    info = Column(SQLJSONB)
    time_start = Column(DateTime)
    time_stop = Column(DateTime)
    state = Column(String(32))
    state_reason = Column(String(32))
    state_reason_ttl = Column(Integer)
    schema_version = Column(Integer, default=xmlnmap.SCHEMA_VERSION)


# Nmap
class N_Association_Scan_ScanFile(Base, _Association_Scan_ScanFile):
    __tablename__ = "n_association_scan_scanfile"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["scan_file"], ["n_scan_file.sha256"], ondelete="CASCADE"),
    )


class N_ScanFile(Base, _ScanFile):
    __tablename__ = "n_scan_file"


class N_Association_Scan_Category(Base, _Association_Scan_Category):
    __tablename__ = "n_association_scan_category"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["category"], ["n_category.id"], ondelete="CASCADE"),
    )


class N_Category(Base, _Category):
    __tablename__ = "n_category"
    __table_args__ = (Index("ix_n_category_name", "name", unique=True),)


class N_Script(Base, _Script):
    __tablename__ = "n_script"
    __table_args__ = (
        ForeignKeyConstraint(["port"], ["n_port.id"], ondelete="CASCADE"),
        Index("ix_n_script_data", "data", postgresql_using="gin"),
        Index("ix_n_script_name", "name"),
        Index("ix_n_script_port_name", "port", "name", unique=True),
    )


class N_Port(Base, _Port):
    __tablename__ = "n_port"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        Index("ix_n_port_scan_port", "scan", "port", "protocol", unique=True),
    )


class N_Hostname(Base, _Hostname):
    __tablename__ = "n_hostname"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        Index("ix_n_hostname_scan_name_type", "scan", "name", "type", unique=True),
    )


class N_Association_Scan_Hostname(Base, _Association_Scan_Hostname):
    __tablename__ = "n_association_scan_hostname"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["hostname"], ["n_hostname.id"], ondelete="CASCADE"),
    )


class N_Trace(Base, _Trace):
    __tablename__ = "n_trace"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
    )


class N_Hop(Base, _Hop):
    __tablename__ = "n_hop"
    __table_args__ = (
        Index("ix_n_hop_ipaddr_ttl", "ipaddr", "ttl"),
        ForeignKeyConstraint(["trace"], ["n_trace.id"], ondelete="CASCADE"),
    )


class N_Scan(Base, _Scan):
    __tablename__ = "n_scan"
    source = Column(String(32), nullable=False)
    __table_args__ = (
        Index("ix_n_scan_info", "info", postgresql_using="gin"),
        Index("ix_n_scan_time", "time_start", "time_stop"),
        Index("ix_n_scan_host", "addr"),
    )


# View
class V_Association_Scan_Category(Base, _Association_Scan_Category):
    __tablename__ = "v_association_scan_category"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["category"], ["v_category.id"], ondelete="CASCADE"),
    )


class V_Category(Base, _Category):
    __tablename__ = "v_category"
    __table_args__ = (Index("ix_v_category_name", "name", unique=True),)


class V_Script(Base, _Script):
    __tablename__ = "v_script"
    __table_args__ = (
        ForeignKeyConstraint(["port"], ["v_port.id"], ondelete="CASCADE"),
        Index("ix_v_script_data", "data", postgresql_using="gin"),
        Index("ix_v_script_name", "name"),
        Index("ix_v_script_port_name", "port", "name", unique=True),
    )


class V_Port(Base, _Port):
    __tablename__ = "v_port"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        Index("ix_v_port_scan_port", "scan", "port", "protocol", unique=True),
    )


class V_Hostname(Base, _Hostname):
    __tablename__ = "v_hostname"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        Index("ix_v_hostname_scan_name_type", "scan", "name", "type", unique=True),
    )


class V_Association_Scan_Hostname(Base, _Association_Scan_Hostname):
    __tablename__ = "v_association_scan_hostname"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["hostname"], ["v_hostname.id"], ondelete="CASCADE"),
    )


class V_Trace(Base, _Trace):
    # FIXME: unicity (scan, port, protocol) to handle merge. Special
    # value for port when not present?
    __tablename__ = "v_trace"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        Index("ix_v_trace_scan_port_proto", "scan", "port", "protocol", unique=True),
    )


class V_Hop(Base, _Hop):
    __tablename__ = "v_hop"
    __table_args__ = (
        Index("ix_v_hop_ipaddr_ttl", "ipaddr", "ttl"),
        ForeignKeyConstraint(["trace"], ["v_trace.id"], ondelete="CASCADE"),
    )


class V_Scan(Base, _Scan):
    __tablename__ = "v_scan"
    source = Column(SQLARRAY(String(32)))
    __table_args__ = (
        Index("ix_v_scan_info", "info", postgresql_using="gin"),
        Index("ix_v_scan_host", "addr", unique=True),
        Index("ix_v_scan_time", "time_start", "time_stop"),
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
    port = Column(Integer, default=-1)
    recontype = Column(String(64))
    source = Column(String(64))
    targetval = Column(Text)
    value = Column(Text)
    info = Column(SQLJSONB)
    moreinfo = Column(SQLJSONB)
    # moreinfo contain data that are not tested for
    # unicity on insertion (the unicity is guaranteed by the value)
    # for performance reasons
    schema_version = Column(Integer, default=passive.SCHEMA_VERSION)
