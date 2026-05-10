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
    BigInteger,
    Column,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    Sequence,
    String,
    Text,
    UniqueConstraint,
    cast,
    column,
    func,
    literal_column,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import declarative_base, declared_attr, mapped_column
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
#
# Auto-incrementing primary keys: PostgreSQL accepts the bare
# ``Column(Integer, primary_key=True)`` form and SQLAlchemy emits
# ``SERIAL``. DuckDB's catalog rejects ``SERIAL`` as well as
# ``GENERATED ... AS IDENTITY``, so every surrogate ``id`` column
# in IVRE's schema is bound to an explicit ``Sequence``: SA emits
# ``CREATE SEQUENCE`` once at ``create_all`` time and the column's
# ``server_default = seq.next_value()`` resolves to ``nextval(...)``
# under both dialects. Mixin classes use ``declared_attr`` so each
# concrete subclass (``n_*`` and ``v_*``) gets its own
# per-tablename sequence rather than sharing one and interleaving
# IDs between active scans and the merged view.

SQLJSONB = postgresql.JSONB().with_variant(JSON(), "duckdb")


def _id_column():
    """Return a fresh ``id`` ``Column`` bound to a per-table
    ``Sequence``.

    Used as a ``declared_attr`` on the abstract mixins below so
    each concrete subclass gets its own ``seq_<tablename>_id``.
    Top-level (non-mixin) tables inline the same pattern with a
    module-level ``Sequence`` for clarity at the call site.

    The mapping is built via :func:`sqlalchemy.orm.mapped_column`
    with ``sort_order=-100`` so the column is positioned *first*
    in the resulting :class:`~sqlalchemy.schema.Table`'s
    ``columns`` collection: ``declared_attr`` is processed after
    the regular class attributes, so without an explicit sort
    override the ``id`` column would land at the end of the
    column list.  Several call sites in
    :mod:`ivre.db.sql` (e.g.
    :meth:`SQLDBView.get` / :meth:`SQLDBNmap.get`) unpack
    ``select(self.tables.port)`` rows positionally and depend on
    the historical ``id`` -> ``scan`` -> ``port`` -> ... order;
    pinning it via ``sort_order`` avoids touching every such
    site while still keeping the per-table Sequence default that
    DuckDB requires.
    """

    @declared_attr
    def id(cls):  # pylint: disable=redefined-builtin
        seq = Sequence(f"seq_{cls.__tablename__}_id")
        return mapped_column(
            Integer,
            seq,
            server_default=seq.next_value(),
            primary_key=True,
            sort_order=-100,
        )

    return id


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

    A ``bind_expression`` wraps every parameter bind in
    ``CAST(? AS INET)`` so DuckDB accepts the value when the
    target table was created on a *different* connection
    (cross-process / cross-engine setup).  In that scenario
    DuckDB's parameter binder refuses to coerce ``VARCHAR`` to
    ``INET`` implicitly::

        Conversion Error: Type VARCHAR with value '<ip>' can't
        be cast to the destination type INET

    The explicit cast forces the coercion.  PostgreSQL accepts
    the same cast unchanged -- it's a no-op for an
    already-typed column bind.
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

    def bind_expression(self, bindvalue):  # type: ignore[override]
        # ``CAST(? AS INET)`` -- see class docstring for the
        # cross-connection rationale.
        return cast(bindvalue, self)


SQLINET = INETLiteral()

# DuckDB accepts ``INET`` as a column type but rejects it as an
# index key with ``Invalid type for index key``.  IVRE's existing
# DuckDB tables work around this by stripping any ``Index`` whose
# columns include INET (via :func:`_is_unsupported_on_duckdb`),
# accepting the missing index as a known degradation.  A
# ``UniqueConstraint`` cannot be stripped the same way: DuckDB
# materialises the constraint as a backing index at ``CREATE
# TABLE`` time and rejects the whole DDL with the same error
# before the ``init()`` filter has a chance to run.
#
# :class:`~ivre.db.sql.tables.Host` keys on ``addr`` via a
# ``UniqueConstraint`` (the natural key for the per-flow upsert
# path) and therefore must use the variant below: PostgreSQL keeps
# the native ``INET`` column (with the ``::inet`` cast on every
# bind so cross-process tests round-trip cleanly), while DuckDB
# falls back to a ``VARCHAR(64)`` column that accepts the same
# printable IP literals (``'10.0.0.1'`` / ``'2001:db8::1'``) as
# string equality keys -- enough for the constraint and the
# upsert lookup.  The 64-byte cap covers IPv6 with embedded
# IPv4 plus an optional ``/<prefix>`` suffix.
SQLINET_KEY = SQLINET.with_variant(String(64), "duckdb")


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


def _fts_concat(table_name, column_names):
    """Build the SQL expression
    ``to_tsvector('english',
    coalesce(<table>.<col1>, '') || ' ' || coalesce(<table>.<col2>, '') || ...)``
    used by both the ``searchtext()`` query path and the GIN
    indexes declared via :func:`_fts_index`.

    The two sites build the *exact same* expression so the
    PostgreSQL planner can match the index against the WHERE
    clause; any drift between the index expression and the
    query expression makes the index unusable.

    Returns a :func:`~sqlalchemy.literal_column` so the result
    supports SA operator overloading (``.op("@@")`` etc.) and
    therefore composes naturally into ``WHERE ... @@
    plainto_tsquery(...)`` clauses.  Lives in
    :mod:`ivre.db.sql.tables` rather than next to the runtime
    predicate in :mod:`ivre.db.sql` because table-level
    ``Index(...)`` declarations need module-import-time
    expressions, not closures over class attributes.
    """
    coalesced = " || ' ' || ".join(
        f"coalesce({table_name}.{col}, '')" for col in column_names
    )
    return literal_column(f"to_tsvector('english', {coalesced})")


def _fts_index(name, table_name, column_names):
    """Wrap ``_fts_concat`` in a GIN ``Index`` declaration that
    accelerates ``searchtext()`` queries against
    ``<table>.<col1>``, ``<table>.<col2>``, …  Skipped at
    create-time on DuckDB by
    :func:`ivre.db.sql.duckdb._is_unsupported_on_duckdb`
    (DuckDB has no GIN indexes; full-text matches degrade to
    sequential scans).
    """
    return Index(
        name,
        _fts_concat(table_name, column_names),
        postgresql_using="gin",
    )


# Tables
Base = declarative_base()


# Flow
#
# Schema mirrors :class:`MongoDBFlow` (``ivre/db/mongo.py:6176``);
# every flow record has the same logical columns on both
# backends, with two structural differences:
#
# * Mongo stores the source / destination addresses inline on the
#   flow record as ``src_addr_0`` / ``src_addr_1`` (int128 split).
#   The SQL backend uses a separate :class:`Host` table with a
#   native ``INET`` ``addr`` column and references it via
#   ``flow.src`` / ``flow.dst`` foreign keys.  This lets the
#   ``host_details`` / ``flow_details`` paths resolve a node to
#   its set of incident flows with a single indexed lookup
#   instead of scanning the flow table.
#
# * Mongo's ``times`` array (per-flow timeslot history, gated by
#   ``config.FLOW_TIME``) is documented as MongoDB-only in
#   ``ivre/flow.py:45-48`` (``FIELDS["times"] = "... (MongoDB
#   backend only)"``).  The SQL schema does not carry it;
#   ``flow_daily`` queries derive their per-bucket counts from
#   ``firstseen`` / ``lastseen`` instead.
#
# All other Mongo flow fields (``count``, ``cspkts`` / ``scpkts`` /
# ``csbytes`` / ``scbytes``, ``sports``, ``codes``, ``meta``,
# ``schema_version``, ``type``) have direct counterparts here.
# Per-flow byte / packet counters use ``BigInteger`` rather than
# the historical ``Integer`` so long-lived flows from busy hosts
# do not overflow at 2^31 -- the column was never populated
# (``SQLDBFlow`` raised ``NotImplementedError`` on every write
# path), so widening it has no migration cost.

_seq_host_id = Sequence("seq_host_id")
_seq_flow_id = Sequence("seq_flow_id")


class Host(Base):
    """Per-address record holding the endpoints of every
    :class:`Flow` row.  Populated lazily by the flow ingestion
    paths (:meth:`SQLDBFlow.any2flow` / ``conn2flow`` /
    ``flow2flow``), which upsert one row per source / destination
    address."""

    __tablename__ = "host"
    id = Column(
        Integer,
        _seq_host_id,
        server_default=_seq_host_id.next_value(),
        primary_key=True,
    )
    # ``SQLINET_KEY`` collapses to ``VARCHAR(64)`` on DuckDB so
    # the ``UniqueConstraint`` below can build its backing index
    # (DuckDB rejects ``INET`` as an index key); on PostgreSQL it
    # stays the native ``INET`` type.
    addr = Column(SQLINET_KEY, nullable=False)
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    __table_args__ = (
        # ``addr`` is the natural key: every ingested flow looks
        # up the host row by IP, so the unique index doubles as
        # the upsert lookup index.
        UniqueConstraint("addr", name="host_idx_addr"),
        Index("host_idx_firstseen", "firstseen"),
        Index("host_idx_lastseen", "lastseen"),
    )


class Flow(Base):
    __tablename__ = "flow"
    id = Column(
        Integer,
        _seq_flow_id,
        server_default=_seq_flow_id.next_value(),
        primary_key=True,
    )
    proto = Column(String(32))
    # Destination port for ``tcp`` / ``udp``; ICMP records leave
    # this ``NULL`` and use :attr:`type` instead.  Mirrors Mongo's
    # ``MongoDBFlow._get_flow_key`` dispatch
    # (``ivre/db/mongo.py:6242``).
    dport = Column(Integer)
    type = Column(Integer)
    src = Column(Integer, ForeignKey("host.id", ondelete="RESTRICT"))
    dst = Column(Integer, ForeignKey("host.id", ondelete="RESTRICT"))
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    # Cumulative packet / byte counters incremented on every
    # repeated ingestion of the same flow tuple (see Mongo's
    # ``conn2flow`` / ``flow2flow`` ``$inc`` blocks at
    # ``ivre/db/mongo.py:6311`` and ``:6340``).  ``BigInteger``
    # avoids 2^31 overflow on long-lived flows.
    scpkts = Column(BigInteger)
    scbytes = Column(BigInteger)
    cspkts = Column(BigInteger)
    csbytes = Column(BigInteger)
    # Number of discrete observations aggregated into this row
    # (incremented by ``conn2flow`` / ``flow2flow``, by
    # ``meta.<name>.count`` for ``any2flow``).
    count = Column(BigInteger)
    # Set-valued source ports (tcp/udp) and ICMP codes; mirror
    # Mongo's ``$addToSet`` semantics on the same column names.
    sports = Column(SQLARRAY(Integer))
    codes = Column(SQLARRAY(Integer))
    # Per-protocol metadata bag -- one sub-key per Zeek log type
    # (``http``, ``ssh``, ``dns``, ...) following
    # :data:`ivre.flow.META_DESC`.  JSONB so the per-protocol
    # ``keys`` / ``counters`` shape matches Mongo's ``meta.<name>``
    # sub-document one-for-one without a migration when new Zeek
    # log types are added.
    meta = Column(SQLJSONB)
    # Bound to :data:`ivre.flow.SCHEMA_VERSION`; written by every
    # ingestion path so future ``_migrate_schema_NN_MM`` helpers
    # can scope updates to specific generations.
    schema_version = Column(Integer)
    __table_args__ = (
        # Composite *unique* index covering the upsert lookup
        # key Mongo uses in ``MongoDBFlow._get_flow_key``:
        # TCP/UDP rows match on (src, dst, proto, dport,
        # schema_version), ICMP rows on (src, dst, proto,
        # type, schema_version), other protocols on (src,
        # dst, proto, schema_version) only.  A single B-tree
        # index over the union covers every shape because
        # ``dport`` / ``type`` are mutually exclusive (one is
        # always ``NULL``).  ``COALESCE(<col>, -1)`` collapses
        # the otherwise-distinct ``NULL`` values so the
        # uniqueness constraint matches Mongo's
        # ``$elemMatch``-style upsert key (port numbers are
        # always >= 0, so ``-1`` is a safe sentinel for "this
        # column does not apply to this protocol").  The
        # index doubles as the read-side lookup index and as
        # the ``ON CONFLICT`` target for the per-record
        # upsert path in :meth:`SQLDBFlow.bulk_commit`.
        Index(
            "flow_unique_lookup",
            "src",
            "dst",
            "proto",
            func.coalesce(column("dport"), -1),
            func.coalesce(column("type"), -1),
            "schema_version",
            unique=True,
        ),
        Index("flow_idx_proto", "proto"),
        Index("flow_idx_dport", "dport"),
        Index("flow_idx_schema_version", "schema_version"),
        Index("flow_idx_firstseen", "firstseen"),
        Index("flow_idx_lastseen", "lastseen"),
        Index("flow_idx_count", "count"),
        Index("flow_idx_cspkts", "cspkts"),
        Index("flow_idx_scpkts", "scpkts"),
        Index("flow_idx_csbytes", "csbytes"),
        Index("flow_idx_scbytes", "scbytes"),
    )


# Active
class _Association_Scan_Category:
    scan = Column(Integer, primary_key=True)
    category = Column(Integer, primary_key=True)


class _Category:
    id = _id_column()
    name = Column(String(32))


class _Script:
    port = Column(Integer, primary_key=True)
    name = Column(String(64), primary_key=True)
    output = Column(Text)
    data = Column(SQLJSONB)


class _Port:
    id = _id_column()
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
    # Screenshot fields. ``screenshot`` is a short text indicator
    # (``"field"`` when the bytes are stored in ``screendata``,
    # ``"empty"`` when the capture failed, or a filename for the
    # nmap NSE script-on-disk variant). ``screendata`` keeps the
    # raw bytes -- bytea on PostgreSQL, BLOB on DuckDB -- to match
    # the Mongo backend's ``bson.Binary`` round-trip semantics.
    # ``screenwords`` is the OCR word list extracted from the
    # screenshot via :func:`ivre.utils.screenwords`.
    screenshot = Column(String(256))
    screendata = Column(LargeBinary)
    screenwords = Column(SQLARRAY(Text))


class _Tag:
    id = _id_column()
    scan = Column(Integer)
    value = Column(String(256))
    type = Column(String(16))
    info = Column(String(256))


class _Hostname:
    id = _id_column()
    scan = Column(Integer)
    domains = Column(SQLARRAY(String(255)), index=True)
    name = Column(String(255), index=True)
    type = Column(String(16), index=True)


class _Association_Scan_Hostname:
    __tablename__ = "association_scan_hostname"
    scan = Column(Integer, primary_key=True)
    hostname = Column(Integer, primary_key=True)


class _Trace:
    id = _id_column()
    scan = Column(Integer, nullable=False)
    port = Column(Integer)
    protocol = Column(String(16))


class _Hop:
    id = _id_column()
    trace = Column(Integer, nullable=False)
    ipaddr = Column(SQLINET)
    ttl = Column(Integer)
    rtt = Column(Float)
    host = Column(String(255), index=True)
    domains = Column(SQLARRAY(String(255)), index=True)


class _Scan:
    id = _id_column()
    addr = Column(SQLINET, nullable=False)
    # source = Column()
    info = Column(SQLJSONB)
    time_start = Column(DateTime)
    time_stop = Column(DateTime)
    state = Column(String(32))
    state_reason = Column(String(32))
    state_reason_ttl = Column(Integer)
    schema_version = Column(Integer, default=xmlnmap.SCHEMA_VERSION)
    cpes = Column(SQLJSONB)
    os = Column(SQLJSONB)
    # ``addresses`` is a Mongo-shape ``{type: [addr, ...]}`` dict
    # holding non-IP host addresses (currently only ``mac``).
    # Stored verbatim from the host record so :meth:`searchmac`
    # can unwind ``addresses->'mac'`` and match any element.
    addresses = Column(SQLJSONB)


# Nmap
class N_Association_Scan_Category(Base, _Association_Scan_Category):
    __tablename__ = "n_association_scan_category"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["category"], ["n_category.id"], ondelete="CASCADE"),
    )


class N_Category(Base, _Category):
    __tablename__ = "n_category"
    __table_args__ = (
        Index("ix_n_category_name", "name", unique=True),
        _fts_index("ix_n_category_fts", "n_category", ("name",)),
    )


class N_Script(Base, _Script):
    __tablename__ = "n_script"
    __table_args__ = (
        ForeignKeyConstraint(["port"], ["n_port.id"], ondelete="CASCADE"),
        Index("ix_n_script_data", "data", postgresql_using="gin"),
        Index("ix_n_script_name", "name"),
        Index("ix_n_script_port_name", "port", "name", unique=True),
        _fts_index("ix_n_script_fts", "n_script", ("output",)),
    )


class N_Port(Base, _Port):
    __tablename__ = "n_port"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        Index("ix_n_port_scan_port", "scan", "port", "protocol", unique=True),
        _fts_index(
            "ix_n_port_fts",
            "n_port",
            (
                "service_name",
                "service_product",
                "service_version",
                "service_extrainfo",
                "service_devicetype",
                "service_hostname",
                "service_ostype",
            ),
        ),
    )


class N_Tag(Base, _Tag):
    __tablename__ = "n_tag"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        Index("ix_n_tag_scan_value_info", "scan", "value", "info", unique=True),
        _fts_index("ix_n_tag_fts", "n_tag", ("value", "info")),
    )


class N_Hostname(Base, _Hostname):
    __tablename__ = "n_hostname"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["n_scan.id"], ondelete="CASCADE"),
        Index("ix_n_hostname_scan_name_type", "scan", "name", "type", unique=True),
        _fts_index("ix_n_hostname_fts", "n_hostname", ("name",)),
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
        _fts_index("ix_n_hop_fts", "n_hop", ("host",)),
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
    __table_args__ = (
        Index("ix_v_category_name", "name", unique=True),
        _fts_index("ix_v_category_fts", "v_category", ("name",)),
    )


class V_Script(Base, _Script):
    __tablename__ = "v_script"
    __table_args__ = (
        ForeignKeyConstraint(["port"], ["v_port.id"], ondelete="CASCADE"),
        Index("ix_v_script_data", "data", postgresql_using="gin"),
        Index("ix_v_script_name", "name"),
        Index("ix_v_script_port_name", "port", "name", unique=True),
        _fts_index("ix_v_script_fts", "v_script", ("output",)),
    )


class V_Port(Base, _Port):
    __tablename__ = "v_port"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        Index("ix_v_port_scan_port", "scan", "port", "protocol", unique=True),
        _fts_index(
            "ix_v_port_fts",
            "v_port",
            (
                "service_name",
                "service_product",
                "service_version",
                "service_extrainfo",
                "service_devicetype",
                "service_hostname",
                "service_ostype",
            ),
        ),
    )


class V_Tag(Base, _Tag):
    __tablename__ = "v_tag"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        Index("ix_v_tag_scan_value_info", "scan", "value", "info", unique=True),
        _fts_index("ix_v_tag_fts", "v_tag", ("value", "info")),
    )


class V_Hostname(Base, _Hostname):
    __tablename__ = "v_hostname"
    __table_args__ = (
        ForeignKeyConstraint(["scan"], ["v_scan.id"], ondelete="CASCADE"),
        Index("ix_v_hostname_scan_name_type", "scan", "name", "type", unique=True),
        _fts_index("ix_v_hostname_fts", "v_hostname", ("name",)),
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
        _fts_index("ix_v_hop_fts", "v_hop", ("host",)),
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
_seq_passive_id = Sequence("seq_passive_id")


class Passive(Base):
    __tablename__ = "passive"
    id = Column(
        Integer,
        _seq_passive_id,
        server_default=_seq_passive_id.next_value(),
        primary_key=True,
    )
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


# RIR (Regional Internet Registry whois data)
#
# Schema mirrors :class:`MongoDBRir` (``ivre/db/mongo.py:5796``);
# every record is one ``inetnum`` / ``inet6num`` / ``aut-num``
# block from a downloaded RIR database file (RIPE / ARIN / APNIC
# / AFRINIC / LACNIC).  Mongo decomposes the IP range into a
# ``(start_0, start_1)`` / ``(stop_0, stop_1)`` pair of int128
# halves; the SQL backend uses native ``INET`` columns instead so
# range queries can use the dialect-native ``<=`` / ``>=`` /
# ``<<=`` operators rather than dual-key compares.  ``aut-num``
# records leave ``start`` / ``stop`` ``NULL`` and populate
# ``aut_num`` instead (mutually exclusive on the wire, so the
# ``aut_num`` partial index keeps the lookup tight).
#
# Text columns (``netname`` / ``descr`` / ``remarks`` / ``notify``
# / ``org``) are projected from :data:`DBRir.text_fields` and
# accelerate ``searchtext`` via the GIN index declared below.  All
# other RIR fields land in the ``extra`` :data:`SQLJSONB` bag for
# forward compatibility (RIR formats grow keys over time; we
# don't want a schema migration on every new attribute).
_seq_rir_id = Sequence("seq_rir_id")


class Rir(Base):
    """One ``inetnum`` / ``inet6num`` / ``aut-num`` whois record.

    Populated by :meth:`SQLDBRir.import_files` (the shared
    ingestion path inherited from :class:`DBRir`); read by the
    ``ivre rirlookup`` CLI and the ``/rir`` web route.
    """

    __tablename__ = "rir"
    id = Column(
        Integer,
        _seq_rir_id,
        server_default=_seq_rir_id.next_value(),
        primary_key=True,
    )
    # IP-range columns -- NULL on ``aut-num`` records, populated
    # on ``inetnum`` / ``inet6num``.  Native ``INET`` keeps range
    # comparisons simple and lets PostgreSQL pick a B-tree index.
    start = Column(SQLINET)
    stop = Column(SQLINET)
    # Pre-computed inclusive address-count of the range, mirrors
    # Mongo's ``size`` field (``mongo.py:6160``).  Pinned at
    # insert time so the web ``/rir`` route can sort
    # narrowest-first without a runtime expression.  ``Numeric``
    # rather than ``BigInteger`` because IPv6 ranges can reach
    # ``2 ** 128`` (overflows ``BigInt``); 40 digits cover that
    # on PostgreSQL.  DuckDB caps ``DECIMAL`` precision at 38,
    # so the variant collapses to ``NUMERIC(38, 0)`` there.  In
    # practice the narrowest real-world RIR allocation is a /3
    # (2 ** 125 addresses, 38 digits) so DuckDB still covers
    # every observed range; only a hypothetical /0-/2 IPv6
    # allocation would overflow, which we don't currently
    # ingest.
    size = Column(Numeric(40, 0).with_variant(Numeric(38, 0), "duckdb"))
    # ``aut-num`` records carry an integer AS number instead of a
    # range.  Mutually exclusive with ``start`` / ``stop`` on the
    # wire; the partial index below targets the populated form.
    aut_num = Column(Integer)
    as_name = Column(Text)
    # Text columns surfaced as filterable attributes (mirrors
    # :data:`DBRir.text_fields`).  Multi-line values are joined
    # with ``\n`` by the shared :meth:`DBRir.gen_records` parser.
    netname = Column(Text)
    descr = Column(Text)
    remarks = Column(Text)
    notify = Column(Text)
    org = Column(Text)
    # Two-letter country code on inet[6]num records.
    country = Column(String(8))
    # ``language`` was renamed to ``lang`` by
    # :meth:`DBRir.gen_records` (``ivre/db/__init__.py:5199``)
    # to work around a historical Mongo bulk-insert bug.  Keep
    # the same name on the SQL side for wire-format parity.
    lang = Column(String(64))
    # Source RIR (``afrinic`` / ``apnic`` / ``arin`` /
    # ``lacnic`` / ``ripe``).  Set from the imported file's
    # name when the parser doesn't yield it.
    source = Column(String(64))
    # ``source_file`` is the basename of the imported RIR
    # database file; ``source_hash`` is its SHA-256 hex digest.
    # Together they support the ``ivre rirlookup --remove`` /
    # idempotent re-import paths (see
    # :meth:`DBRir.import_files`).
    source_file = Column(String(256))
    source_hash = Column(String(128))
    # Forward-compatible bag for any RIR attribute we don't
    # call out as a typed column above (``mnt-by``, ``admin-c``,
    # ``tech-c``, ...).  Kept as JSONB so future ``searchXX``
    # helpers can index into the bag without a schema migration.
    extra = Column(SQLJSONB)
    # Bound to ``MongoDBRir.schema_latest_versions[0]`` so a
    # mixed PG / Mongo deployment shares the same migration
    # generation marker.
    schema_version = Column(Integer)
    __table_args__ = (
        # Range lookup index covering the
        # ``searchhost`` / ``searchnet`` / ``searchrange`` paths
        # (PostgreSQL B-tree over ``INET`` accepts ``<=`` /
        # ``>=`` / range-overlap predicates; the planner picks
        # this index for the ``WHERE start <= addr AND stop >=
        # addr`` shape :meth:`SQLDBRir.searchhost` builds).
        Index("rir_idx_range", "start", "stop"),
        # Partial index targeting the populated half of the
        # mutually-exclusive ``aut_num`` / range columns; keeps
        # the lookup tight for ``aut-num`` records.
        Index(
            "rir_idx_aut_num",
            "aut_num",
            postgresql_where=column("aut_num").isnot(None),
        ),
        Index("rir_idx_country", "country"),
        Index("rir_idx_source", "source"),
        Index("rir_idx_source_file", "source_file"),
        Index("rir_idx_source_hash", "source_hash"),
        Index("rir_idx_schema_version", "schema_version"),
        # Pre-computed range-size index; the web ``/rir`` route
        # sorts by ``size`` ascending to surface the most
        # specific allocation first (mirrors the Mongo path's
        # ``sort=[("size", 1)]`` default).
        Index("rir_idx_size", "size"),
        # GIN FTS index over the concatenation of every text
        # column.  Same expression on both sides of the
        # query / index split so the planner picks the index
        # for ``to_tsvector('english', ...) @@ plainto_tsquery
        # ('english', :term)`` clauses (see
        # :func:`_fts_index` for the byte-for-byte match
        # rationale).  Stripped on DuckDB by
        # :func:`ivre.db.sql.duckdb._is_unsupported_on_duckdb`
        # (no GIN support); the FTS extension's
        # ``match_bm25`` path is wired in a follow-up sub-PR.
        _fts_index(
            "rir_idx_fts",
            "rir",
            ("netname", "descr", "remarks", "notify", "org", "as_name"),
        ),
    )
