#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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

"""DuckDB backend for IVRE's SQL data layer.

DuckDB's SQLAlchemy dialect (``duckdb-engine``) inherits from
:class:`sqlalchemy.dialects.postgresql.psycopg2.PGDialect_psycopg2`,
so most PostgreSQL DDL and DML compiles unchanged.  This module
adapts the small set of behaviours that genuinely differ between
the two engines:

* ``INET`` round-trips as a Python ``dict``
  (``{'ip_type', 'address', 'mask'}``) rather than a string.
* ``CREATE INDEX ... USING gin`` is rejected (DuckDB only ships
  B-tree indexes).
* ``COPY ... FROM STDIN`` and ``CREATE TEMP TABLE`` based bulk
  paths are PG-specific implementation details; bulk-insert
  parity with PostgreSQL is deferred to a follow-up milestone.
* ``to_tsvector`` / ``plainto_tsquery`` / ``@@`` are not
  available on DuckDB; full-text search uses the ``fts``
  extension's ``PRAGMA create_fts_index`` +
  ``fts_main_<table>.match_bm25(...)`` API instead -- see
  :class:`DuckDBNmapFilter` / :class:`DuckDBViewFilter`.

The class hierarchy mirrors :mod:`ivre.db.sql.postgres`: a
:class:`DuckDBMixin` carries the dialect-specific overrides and is
placed *first* in the bases tuple of every concrete class so its
methods win the MRO lookup against ``PostgresDB*``'s defaults.
"""

from typing import Any, override

from sqlalchemy import event, exists, or_, select
from sqlalchemy import text as sa_text
from sqlalchemy.dialects import postgresql

from ivre import utils
from ivre.db.sql import NmapFilter, ViewFilter
from ivre.db.sql.postgres import (
    PostgresDBNmap,
    PostgresDBPassive,
    PostgresDBView,
)
from ivre.db.sql.tables import Base

# Column lists for the DuckDB FTS index, mirroring
# :attr:`SQLDBActive._TEXT_SEARCH_*_COLUMNS`.  Indexed by
# ``self.tables.<attr>`` so the same spec works for both
# ``n_*`` (DuckDBNmap) and ``v_*`` (DuckDBView) schemas.
_FTS_TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "hostname": ("name",),
    "tag": ("value", "info"),
    "port": (
        "service_name",
        "service_product",
        "service_version",
        "service_extrainfo",
        "service_devicetype",
        "service_hostname",
        "service_ostype",
    ),
    "script": ("output",),
    "hop": ("host",),
    "category": ("name",),
}


def _install_fts_on_connect(dbapi_connection: Any, _connection_record: Any) -> None:
    """SQLAlchemy ``connect`` event listener that loads
    DuckDB's ``fts`` extension on every new connection.

    The extension is required for any
    ``fts_main_<table>.match_bm25(...)`` call ``searchtext()``
    emits; without ``LOAD fts`` the function is unresolved and
    DuckDB raises ``Catalog Error: Scalar Function with name
    match_bm25 does not exist``.  Each ``ivre <tool>``
    subprocess opens its own engine, so the load has to happen
    per-connection, not once at process startup.  ``INSTALL
    fts`` is idempotent on DuckDB (it's a no-op once the
    extension is downloaded into the per-user cache).
    """
    cur = dbapi_connection.cursor()
    try:
        cur.execute("INSTALL fts")
        cur.execute("LOAD fts")
    finally:
        cur.close()


def _is_unsupported_on_duckdb(index: Any) -> bool:
    """Return ``True`` for indexes DuckDB rejects at create-time.

    DuckDB only ships B-tree (ART) indexes and only over a
    subset of column types; the following declarations are
    filtered out at ``init()`` time:

    * **GIN indexes** (``postgresql_using='gin'``) -- emitted
      against JSONB columns to accelerate containment queries
      on PostgreSQL. DuckDB raises ``Binder Error: Unknown
      index type: GIN``; JSONB lookups degrade to sequential
      scans.

    * **Partial indexes** (``postgresql_where=<expr>``) --
      DuckDB raises ``NotImplementedException: Creating partial
      indexes is not supported currently``. The relevant
      declarations on
      :class:`~ivre.db.sql.tables.Passive` collapse to a single
      multi-column unique constraint on DuckDB at the cost of
      treating ``NULL`` ``addr`` rows the same as any other.

    * **Indexes that key on an ``INET`` or ``ARRAY`` column** --
      DuckDB's catalog rejects them with
      ``Invalid type for index key``. The underlying ART index
      cannot order INET / list values, so IP-prefix and
      domain-array lookups fall back to sequential scans
      (matching the JSONB / partial-index degradation above).
    """
    if index.kwargs.get("postgresql_using") == "gin":
        return True
    if index.kwargs.get("postgresql_where") is not None:
        return True
    return any(
        isinstance(col.type, (postgresql.INET, postgresql.ARRAY))
        for col in index.columns
    )


# DuckDB's parser accepts only ``RESTRICT`` / ``NO ACTION``
# referential actions (the implicit defaults); ``CASCADE``,
# ``SET NULL`` and ``SET DEFAULT`` raise
# ``Parser Error: FOREIGN KEY constraints cannot use CASCADE,
# SET NULL or SET DEFAULT``.  Every cross-table FK in
# :mod:`ivre.db.sql.tables` declares ``ondelete='CASCADE'`` so
# that ``DELETE FROM scan WHERE id = ?`` auto-cleans child
# rows in the ``port`` / ``hostname`` / ``trace`` / ``hop`` /
# ``tag`` / ``association_scan_*`` / ``script`` tables.
#
# Stripping CASCADE down to the implicit RESTRICT keeps the FK
# *check*, which then fails IVRE's existing remove paths
# (:meth:`SQLDBNmap.remove` / :meth:`remove_many` issue a
# single ``DELETE FROM scan ...`` and rely on the cascade to
# clean up children).  DuckDB also has no per-statement
# ``CASCADE`` on ``DELETE``, so emulating the cascade in
# application code would mean overriding every remove method.
# The pragmatic compromise on this embedded-DB backend: drop
# the FK constraints themselves at ``init()`` time and rely on
# the application's existing scan-rooted delete paths.  Orphans
# in child tables are not visible to the read paths (which
# always project from ``scan`` joined to children); a periodic
# vacuum can be wired in later if needed.


class DuckDBMixin:
    """Dialect-specific overrides on top of :class:`PostgresDB`.

    Place *first* in the bases tuple of every concrete DuckDB
    backend class so the MRO resolves these overrides ahead of
    PostgreSQL's defaults (see :pep:`3119` C3 linearisation).
    """

    @property
    def db(self) -> Any:
        """Lazily build the SQLAlchemy engine and attach the
        ``fts`` extension loader to every new connection.

        :meth:`SQLDB.db` caches the engine on ``self._db``; we
        delegate to it to materialise the engine, then register
        the :func:`_install_fts_on_connect` listener once.
        Subsequent ``self.db`` accesses short-circuit through
        the cached attribute.
        """
        try:
            return self._db  # type: ignore[attr-defined]
        except AttributeError:
            # Defer to ``SQLDB.db`` (the parent's lazy-init
            # property) to actually build and cache the engine,
            # then attach the FTS loader.  ``event.listen``
            # only fires on *future* connections; the engine
            # itself doesn't open a connection on creation, so
            # the first ``Connection`` IVRE checks out (e.g.
            # via ``self.drop()``) sees the ``LOAD fts``.  The
            # local import is required to break the
            # ``ivre.db.sql`` <-> ``ivre.db.sql.duckdb`` import
            # cycle at module-load time.
            # pylint: disable=import-outside-toplevel
            from ivre.db.sql import SQLDB

            # pylint: disable-next=assignment-from-no-return
            engine = SQLDB.db.fget(self)  # type: ignore[union-attr]
            event.listen(engine, "connect", _install_fts_on_connect)
            return engine

    def _create_fts_indexes(self) -> None:
        """Build (or rebuild) the per-table FTS indexes
        DuckDB's ``fts`` extension uses for full-text search.

        DuckDB's FTS index is *static*: it doesn't track row
        inserts / updates after creation.  Re-running
        ``PRAGMA create_fts_index(... overwrite=1)`` rebuilds
        the index from the current table contents, which is
        why :meth:`searchtext` calls into this method on every
        full-text query.

        Each index is keyed by ``rowid``, the DuckDB
        pseudo-column that uniquely identifies a row regardless
        of declared primary key.  ``rowid`` works equally for
        tables with a single-column ``id`` and for tables with
        composite primary keys (``n_script`` / ``v_script``,
        which have ``(port, name)`` PKs and no surrogate
        column); the FTS extension's
        ``match_bm25(<id>, '<term>')`` accepts whatever column
        the index was built on.

        No-op on backends without text-bearing tables (e.g.
        :class:`DuckDBPassive`); checked via ``getattr`` on
        :attr:`self.tables`.
        """
        if not hasattr(self, "tables"):
            return
        statements = []
        for tname, cols in _FTS_TABLE_COLUMNS.items():
            tbl = getattr(self.tables, tname, None)
            if tbl is None:
                continue
            cols_sql = ", ".join(f"'{c}'" for c in cols)
            # The FTS PRAGMA cannot be parameterised; the
            # column names are class-level constants (not
            # user input), so the f-string is safe.
            statements.append(
                f"PRAGMA create_fts_index('{tbl.__tablename__}', "
                f"'rowid', {cols_sql}, overwrite=1)"
            )
        if not statements:
            return
        with self.db.begin() as conn:
            for stmt in statements:
                conn.execute(sa_text(stmt))

    @staticmethod
    def ip2internal(addr: str | int | None) -> str | None:
        """Convert an IP value into the form accepted by an INET
        bind on DuckDB.

        DuckDB's INET column accepts the same string literals as
        PostgreSQL (``'192.0.2.1'``, ``'2001:db8::1'``,
        ``'10.0.0.0/8'``, plus the ``'<ip>'::inet`` cast emitted
        by :class:`~ivre.db.sql.tables.INETLiteral` for inlined
        literals), so the bind side reduces to "give me the
        canonical string form" and matches PG byte-for-byte.

        ``utils.force_int2ip`` accepts either an existing string
        (returned unchanged) or an integer (rendered through
        :func:`socket.inet_ntoa` / :func:`socket.inet_ntop`).
        """
        if addr is None:
            return None
        return utils.force_int2ip(addr)

    @staticmethod
    def internal2ip(addr: dict[str, int] | str | None) -> str | None:
        """Convert a DuckDB ``INET`` round-trip value to an IP
        string.

        ``duckdb-engine`` returns ``INET`` columns as a struct
        ``{'ip_type': 1|2, 'address': int, 'mask': int}`` rather
        than the bare string PostgreSQL's ``psycopg2`` returns
        (which the parent :meth:`PostgresDB.internal2ip` simply
        passes through).  The unsigned address that
        :func:`ivre.utils.int2ip` / :func:`ivre.utils.int2ip6`
        expect is recovered as follows:

        * ``ip_type == 1`` (IPv4): ``address`` is already an
          unsigned 32-bit value; pass it straight to
          :func:`utils.int2ip`.
        * ``ip_type == 2`` (IPv6): ``address`` is a *biased*
          signed 128-bit integer and the true unsigned value is
          ``address + (1 << 127)``.  DuckDB's ``INET`` stores
          addresses as a signed ``HUGEINT`` with that bias so the
          natural ordering of the underlying integer matches the
          natural ordering of IP addresses across the IPv4/IPv6
          boundary.  :func:`utils.int2ip6` is used (instead of
          the v4/v6-autodetecting :func:`utils.int2ip`) to avoid
          mis-formatting low-valued v6 addresses such as ``::``
          or ``::1`` as IPv4.

        A bare string is returned unchanged so callers that have
        already normalised their input (or that hit code paths
        which do not go through DuckDB) keep working.
        """
        if addr is None:
            return None
        if isinstance(addr, dict):
            address = addr["address"]
            if addr["ip_type"] == 2:
                return utils.int2ip6(address + (1 << 127))
            return utils.int2ip(address)
        # Defensive: a future duckdb-engine release might switch
        # to returning strings (matching psycopg2). Pass them
        # through utils.force_int2ip so a stray int still
        # round-trips correctly.
        return utils.force_int2ip(addr)

    def copy_from(self, *args: Any, conn: Any = None, **kwargs: Any) -> None:
        """Not implemented on DuckDB.

        :meth:`PostgresDB.copy_from` wraps psycopg2's
        ``cursor.copy_from`` (``COPY ... FROM STDIN``); DuckDB
        exposes a different bulk-load API
        (``duckdb.DuckDBPyConnection.from_csv_auto`` /
        ``read_csv``) and the calling code in
        :meth:`PostgresDBPassive.insert_or_update_bulk` is built
        around the psycopg2 cursor protocol.  Wiring an
        equivalent fast path is tracked as a follow-up
        milestone; in the meantime, callers should use the
        per-row :meth:`insert_or_update` path on DuckDB.
        """
        raise NotImplementedError(
            "DuckDB has no psycopg2-style COPY FROM bulk path; "
            "use insert_or_update (per-row) on this backend."
        )

    def create_tmp_table(
        self, table: Any, extracols: Any = None, conn: Any = None
    ) -> Any:
        """Not implemented on DuckDB.

        Currently only used by
        :meth:`PostgresDBPassive.insert_or_update_bulk`, which
        depends on the psycopg2 ``COPY`` path
        (:meth:`copy_from`).  See :meth:`copy_from` for the
        rationale and the deferral plan.
        """
        raise NotImplementedError(
            "create_tmp_table is currently only consumed by the "
            "psycopg2 COPY-based bulk path, which is not wired "
            "for DuckDB."
        )

    def explain(self, req: Any, **_: Any) -> str:
        """Not implemented on DuckDB.

        DuckDB ships an ``EXPLAIN`` statement with a different
        output shape than PostgreSQL's; pretty-printing it
        through the same code path as
        :meth:`PostgresDB.explain` would mis-render results.
        Wired separately if and when ``ivre`` grows a
        DuckDB-specific debug helper.
        """
        raise NotImplementedError(
            "DuckDB EXPLAIN output formatting is not wired through this backend yet."
        )

    @override
    def init(self) -> None:  # type: ignore[misc]
        """Drop and recreate the schema, transparently rewriting
        the small set of declarations DuckDB does not accept:

        * Indexes flagged as unsupported by
          :func:`_is_unsupported_on_duckdb` (GIN; INET-keyed
          B-tree) are evicted from each table's ``indexes`` set.
        * Foreign-key constraints (table-level
          ``ForeignKeyConstraint`` and column-level
          ``ForeignKey``) are dropped entirely -- see the
          comment block at the top of this module for the
          rationale.

        Both edits are applied to the in-process
        :data:`~ivre.db.sql.tables.Base.metadata` for the
        duration of the drop / create cycle and reverted in a
        ``finally`` block so other engines sharing the same
        metadata in the same Python process (e.g. a parallel
        test run against PostgreSQL) see their original
        schema declarations.

        Unlike :meth:`SQLDB.init`, the drop and create steps run
        against *different* SQLAlchemy engines.  A single
        engine's connection pool reuses one DuckDB session
        across the two phases, and DuckDB's catalog refuses to
        commit a ``CREATE TABLE`` that re-introduces a name
        whose previous incarnation was dropped within the same
        session::

            TransactionException: Failed to commit: Could not
            commit creation of dependency, subject "<table>" has
            been deleted

        The bug surfaces the second time ``ivre <tool> --init``
        runs against a pre-existing DuckDB file (e.g. between
        two CI test runs, or any time tests pre-populate then
        re-init the schema).  Calling :meth:`Engine.dispose` on
        the cached engine and clearing :attr:`SQLDB._db` after
        :meth:`drop` forces the next ``self.db`` access to
        materialise a fresh engine -- and therefore a fresh
        DuckDB session -- which the subsequent :meth:`create`
        runs against without the catalog conflict.
        """
        saved_indexes: dict[Any, list[Any]] = {}
        saved_table_fkcs: dict[Any, set[Any]] = {}
        saved_column_fks: dict[Any, set[Any]] = {}
        try:
            for table in Base.metadata.tables.values():
                skipped = [ix for ix in table.indexes if _is_unsupported_on_duckdb(ix)]
                if skipped:
                    saved_indexes[table] = skipped
                    for ix in skipped:
                        table.indexes.discard(ix)
                # Snapshot then strip table-level FK constraints
                # (``ForeignKeyConstraint(...)``) -- DuckDB
                # cannot enforce ``ON DELETE CASCADE`` and the
                # implicit ``RESTRICT`` would break IVRE's
                # scan-rooted delete paths (see top-of-module
                # comment).
                if table.foreign_key_constraints:
                    saved_table_fkcs[table] = set(table.foreign_key_constraints)
                    for fkc in list(table.foreign_key_constraints):
                        table.constraints.discard(fkc)
                # Same treatment for column-level ``ForeignKey``
                # objects (e.g. ``Flow.src`` / ``Flow.dst``).
                for col in table.columns:
                    if col.foreign_keys:
                        saved_column_fks[col] = set(col.foreign_keys)
                        for fk in list(col.foreign_keys):
                            col.foreign_keys.discard(fk)
                            table.foreign_keys.discard(fk)
            self.drop()
            # Recycle the engine before ``create()``: see the
            # docstring above for the catalog-conflict
            # rationale.  ``self.db`` is a cached property on
            # :class:`SQLDB`; deleting ``self._db`` makes the
            # next access build a fresh engine on top of a
            # fresh DuckDB session.
            self.db.dispose()
            try:
                del self._db  # type: ignore[attr-defined]
            except AttributeError:
                pass
            self.create()
            # Initial empty FTS indexes -- the schema's
            # text-bearing tables are still empty here, so
            # ``PRAGMA create_fts_index`` builds zero-row
            # indexes that subsequent ``searchtext()`` calls
            # rebuild via ``overwrite=1`` once data is in.
            self._create_fts_indexes()
        finally:
            for table, indexes in saved_indexes.items():
                for ix in indexes:
                    table.indexes.add(ix)
            for table, fkcs in saved_table_fkcs.items():
                for fkc in fkcs:
                    table.append_constraint(fkc)
            for col, fks in saved_column_fks.items():
                for fk in fks:
                    col.foreign_keys.add(fk)
                    col.table.foreign_keys.add(fk)


class _DuckDBActiveFilterMixin:
    """Mixin overriding :meth:`ActiveFilter._text_predicate` for
    DuckDB.

    DuckDB lacks PostgreSQL's text-search primitives
    (``to_tsvector``, ``plainto_tsquery``, ``@@``).  Full-text
    search is delegated to the ``fts`` extension's
    ``fts_main_<table>.match_bm25(<id>, '<term>')`` function:
    the BM25 score is non-NULL when the row matches and NULL
    otherwise, so ``WHERE ... IS NOT NULL`` is the equivalent
    of PG's ``@@`` predicate.

    Each per-table predicate keeps the same ``EXISTS``-on-the-
    child shape :meth:`ActiveFilter._text_predicate` uses on
    PostgreSQL, so the filter composes cleanly with the rest
    of :class:`ActiveFilter`'s slots.
    """

    @staticmethod
    def _bm25_predicate(table_name: str, term: str) -> Any:  # type: ignore[no-untyped-def]
        """``fts_main_<table>.match_bm25(<table>.rowid, :term)
        IS NOT NULL`` -- the DuckDB FTS-extension predicate used
        in place of PostgreSQL's
        ``to_tsvector(...) @@ plainto_tsquery(...)``.
        """
        return sa_text(
            f"fts_main_{table_name}.match_bm25({table_name}.rowid, :fts_term) "
            "IS NOT NULL"
        ).bindparams(fts_term=term)

    def _text_predicate(self, term: str) -> Any:  # type: ignore[no-untyped-def]
        clauses = []
        # Direct children of ``scan``: hostname, tag, port.
        for tname in ("hostname", "tag", "port"):
            tbl = getattr(self.tables, tname)
            clauses.append(
                exists(
                    select(1)
                    .select_from(tbl)
                    .where(tbl.scan == self.tables.scan.id)
                    .where(self._bm25_predicate(tbl.__tablename__, term))
                )
            )
        # Two-hop child of ``scan``: ``script`` -> ``port`` ->
        # ``scan``.
        script_tbl = self.tables.script
        port_tbl = self.tables.port
        clauses.append(
            exists(
                select(1)
                .select_from(script_tbl.__table__.join(port_tbl.__table__))
                .where(port_tbl.scan == self.tables.scan.id)
                .where(self._bm25_predicate(script_tbl.__tablename__, term))
            )
        )
        # Two-hop child of ``scan``: ``hop`` -> ``trace`` ->
        # ``scan``.
        hop_tbl = self.tables.hop
        trace_tbl = self.tables.trace
        clauses.append(
            exists(
                select(1)
                .select_from(trace_tbl.__table__.join(hop_tbl.__table__))
                .where(trace_tbl.scan == self.tables.scan.id)
                .where(self._bm25_predicate(hop_tbl.__tablename__, term))
            )
        )
        # Two-hop child of ``scan``: ``category`` ->
        # ``association_scan_category`` -> ``scan``.
        cat_tbl = self.tables.category
        assoc_tbl = self.tables.association_scan_category
        clauses.append(
            exists(
                select(1)
                .select_from(cat_tbl.__table__.join(assoc_tbl.__table__))
                .where(assoc_tbl.scan == self.tables.scan.id)
                .where(self._bm25_predicate(cat_tbl.__tablename__, term))
            )
        )
        return or_(*clauses)


class DuckDBNmapFilter(_DuckDBActiveFilterMixin, NmapFilter):
    """``NmapFilter`` with DuckDB-flavoured full-text-search
    predicates (FTS extension's ``match_bm25`` instead of
    PostgreSQL's ``to_tsvector @@ plainto_tsquery``)."""


class DuckDBViewFilter(_DuckDBActiveFilterMixin, ViewFilter):
    """``ViewFilter`` with DuckDB-flavoured full-text-search
    predicates."""


class DuckDBNmap(DuckDBMixin, PostgresDBNmap):
    """DuckDB backend for the ``nmap`` (active-scan) data category."""

    base_filter = DuckDBNmapFilter

    # The override is an instance method (``self``) where the
    # parent :meth:`SQLDBActive.searchtext` is a ``@classmethod``
    # (``cls``); pylint compares positionally and reports the
    # ``cls`` -> ``self`` rename as a renamed parameter.  The
    # mismatch is by design: this override needs engine access
    # (``self.db``) to rebuild the FTS index, which a
    # classmethod cannot do.
    @override
    def searchtext(  # pylint: disable=arguments-renamed
        self, text: str, neg: bool = False
    ) -> Any:  # type: ignore[no-untyped-def, override]
        # DuckDB's FTS index is static -- it doesn't track row
        # inserts after creation.  Rebuild it before every
        # ``searchtext()`` query so the result is always fresh.
        # The cost is a full text-column scan per text-bearing
        # table, which is acceptable for the embedded /
        # single-host workloads DuckDB targets.
        self._create_fts_indexes()
        return self.base_filter(text=[(not neg, text)])


class DuckDBView(DuckDBMixin, PostgresDBView):
    """DuckDB backend for the ``view`` (merged-host) data category."""

    base_filter = DuckDBViewFilter

    # See :meth:`DuckDBNmap.searchtext` for the
    # classmethod-to-instance-method override rationale.
    @override
    def searchtext(  # pylint: disable=arguments-renamed
        self, text: str, neg: bool = False
    ) -> Any:  # type: ignore[no-untyped-def, override]
        # See :meth:`DuckDBNmap.searchtext` for the
        # rebuild-on-every-search rationale.
        self._create_fts_indexes()
        return self.base_filter(text=[(not neg, text)])


class DuckDBPassive(DuckDBMixin, PostgresDBPassive):
    """DuckDB backend for the ``passive`` data category.

    Bulk-insert (:meth:`insert_or_update_bulk`) inherits the
    PostgreSQL implementation, which is gated behind
    :meth:`copy_from` and :meth:`create_tmp_table` -- both raise
    :exc:`NotImplementedError` on DuckDB until parity work
    lands.  Per-row :meth:`insert_or_update` works today.
    """


# Flow ingestion on SQL backends is currently a stub:
# ``ivre.db.sql.tables.Flow`` references a ``host`` table that
# is not declared anywhere in :data:`Base.metadata`, so
# ``PostgresDBFlow().init()`` raises
# ``NoReferencedTableError`` on PostgreSQL too. A working flow
# backend is tracked separately and will land alongside the
# corresponding registration in :class:`~ivre.db.DBFlow`.
