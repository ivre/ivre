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


from sqlalchemy import event, func, insert, Column, ForeignKey, Index, \
    ARRAY, Boolean, DateTime, Float, Integer, LargeBinary, String, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import UserDefinedType
from sqlalchemy.ext.declarative import declarative_base


from ivre import xmlnmap


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
        # Index('host_idx_tag_addr', 'tag', 'addr', unique=True),
    )


# Data

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
        Index('ix_scan_host_archive', 'addr', 'source', 'archive',
              unique=True),
        Index('ix_scan_time', 'time_start', 'time_stop'),
    )


# Passive

class Passive(Base):
    __tablename__ = "passive"
    id = Column(Integer, primary_key=True)
    addr = Column(postgresql.INET)
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
        Index('ix_passive_record', 'addr', 'sensor', 'recontype', 'port',
              'source', 'value', 'targetval', 'info', unique=True),
    )
