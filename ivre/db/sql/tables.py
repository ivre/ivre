#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
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

"""This sub-module contains SQL tables and columns definition."""

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import declarative_base
from sqlalchemy.types import UserDefinedType

from ivre import passive, xmlnmap

# Types
#
# The shared SQL types below are dialect-aware so the same
# column declarations work across every SQLAlchemy backend IVRE
# supports (currently PostgreSQL; DuckDB is the next first-class
# target). Per-dialect specialisations are layered via
# :meth:`TypeEngine.with_variant`.
#
# DuckDB native types differ from PostgreSQL's:
#   - PG ``JSONB`` -> DuckDB ``JSON`` (DuckDB has no ``JSONB``
#     keyword; ``JSONB`` raises ``Catalog Error: Type with name
#     JSONB does not exist!``). Both store JSON documents and
#     support the same ``->`` / ``->>`` accessors.
#   - PG ``INET`` works as-is on DuckDB (DuckDB has a native
#     ``INET`` type that accepts the same string literals,
#     including the ``'<ip>'::inet`` cast our ``INETLiteral``
#     emits).
#   - PG ``ARRAY(t)`` works as-is on DuckDB (duckdb-engine
#     compiles to the ``LIST``/``t[]`` form natively).

SQLJSONB = postgresql.JSONB().with_variant(JSON(), "duckdb")


def SQLARRAY(item_type):
    return postgresql.ARRAY(item_type)


class INETLiteral(postgresql.INET):
    """``postgresql.INET`` with a ``literal_processor`` so that
    queries inlined via ``.compile(literal_binds=True)`` (notably
    ``PostgresDB.explain``) render IP values as
    ``'192.0.2.1'::inet`` instead of raising
    ``sqlalchemy.exc.CompileError: No literal value renderer
    is available for literal value '...' with datatype INET``.

    SQLAlchemy 1.x shipped a default literal processor that
    rendered ``INET`` values as plain strings; SQLAlchemy 2.x
    removed it (see release notes / sqlalchemy/sqlalchemy#9521).
    Pinned by ``PostgresExplainTests.test_inet_literal_renders_with_cast``.

    Reused on DuckDB unchanged: the ``'<ip>'::inet`` cast form
    is accepted natively (DuckDB ships an ``INET`` type with
    the same string-coerce rules as PostgreSQL).
    """

    cache_ok = True

    def literal_processor(self, dialect):  # type: ignore[override]
        def process(value):
            if value is None:
                return "NULL"
            # The column rejects non-IP values at write time, but
            # belt-and-suspenders quote-escape the textual form
            # before inlining (a malformed value would fail the
            # ``::inet`` cast at SQL execution time anyway, with
            # no privilege escalation).
            escaped = str(value).replace("'", "''")
            return f"'{escaped}'::inet"

        return process


SQLINET = INETLiteral()


class Point(UserDefinedType):
    cache_ok = True

    def get_col_spec(self):
        return "POINT"

    def bind_expression(self, bindvalue):
        return func.Point_In(bindvalue, type_=self)

    @staticmethod
    def bind_processor(dialect):
        def process(value):
            if value is None:
                return None
            return f"{value[0]:f},{value[1]:f}"

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


class _Tag:
    id = Column(Integer, primary_key=True)
    scan = Column(Integer)
    value = Column(String(256))
    type = Column(String(16))
    info = Column(String(256))


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


class N_Tag(Base, _Tag):
    __tablename__ = "n_tag"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        Index("ix_n_tag_scan_value_info", "scan", "value", "info", unique=True),
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


class V_Tag(Base, _Tag):
    __tablename__ = "v_tag"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        Index("ix_v_tag_scan_value_info", "scan", "value", "info", unique=True),
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
