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

The class hierarchy mirrors :mod:`ivre.db.sql.postgres`: a
:class:`DuckDBMixin` carries the dialect-specific overrides and is
placed *first* in the bases tuple of every concrete class so its
methods win the MRO lookup against ``PostgresDB*``'s defaults.
"""

from typing import Any, override

from sqlalchemy.dialects import postgresql

from ivre import utils
from ivre.db.sql.postgres import (
    PostgresDBNmap,
    PostgresDBPassive,
    PostgresDBView,
)
from ivre.db.sql.tables import Base


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
# SET NULL or SET DEFAULT``. Every cross-table FK in
# :mod:`ivre.db.sql.tables` declares ``ondelete='CASCADE'`` to
# auto-clean child rows on host deletion, which DuckDB rejects
# wholesale.
_DUCKDB_REJECTED_FK_ACTIONS = frozenset({"CASCADE", "SET NULL", "SET DEFAULT"})


def _normalise_fk_action(action: str | None) -> str | None:
    """Return ``None`` (i.e. emit no ``ON DELETE`` / ``ON UPDATE``
    clause -- DuckDB defaults to ``RESTRICT``) when ``action`` is
    one of the cascade-flavoured forms DuckDB cannot parse, or
    pass it through untouched when DuckDB accepts it
    (``RESTRICT`` / ``NO ACTION`` / ``None``).

    Stripping CASCADE down to the implicit RESTRICT preserves
    the FK constraint's referential-integrity check (an attempt
    to delete a parent row with extant children still raises an
    ``IntegrityError``); only the auto-cleanup behaviour is
    lost.  IVRE's PostgreSQL backend already issues child-first
    deletions in its remove paths, so the lost cascade does not
    affect the supported call sites in :class:`PostgresDB*`.
    """
    if action is None:
        return None
    if action.upper() in _DUCKDB_REJECTED_FK_ACTIONS:
        return None
    return action


class DuckDBMixin:
    """Dialect-specific overrides on top of :class:`PostgresDB`.

    Place *first* in the bases tuple of every concrete DuckDB
    backend class so the MRO resolves these overrides ahead of
    PostgreSQL's defaults (see :pep:`3119` C3 linearisation).
    """

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
        * Foreign-key referential actions that DuckDB's parser
          rejects (``CASCADE`` / ``SET NULL`` / ``SET DEFAULT``)
          are flattened to the implicit ``RESTRICT`` -- see
          :func:`_normalise_fk_action`.

        Both edits are applied to the in-process
        :data:`~ivre.db.sql.tables.Base.metadata` for the
        duration of ``super().init()`` and reverted in a
        ``finally`` block so other engines sharing the same
        metadata in the same Python process (e.g. a parallel
        test run against PostgreSQL) see their original
        schema declarations.
        """
        saved_indexes: dict[Any, list[Any]] = {}
        saved_fk_actions: list[tuple[Any, str | None, str | None]] = []
        try:
            for table in Base.metadata.tables.values():
                skipped = [ix for ix in table.indexes if _is_unsupported_on_duckdb(ix)]
                if skipped:
                    saved_indexes[table] = skipped
                    for ix in skipped:
                        table.indexes.discard(ix)
                # Table-level constraints: ForeignKeyConstraint(...)
                for fkc in table.foreign_key_constraints:
                    new_ondelete = _normalise_fk_action(fkc.ondelete)
                    new_onupdate = _normalise_fk_action(fkc.onupdate)
                    if (new_ondelete, new_onupdate) != (fkc.ondelete, fkc.onupdate):
                        saved_fk_actions.append((fkc, fkc.ondelete, fkc.onupdate))
                        fkc.ondelete = new_ondelete
                        fkc.onupdate = new_onupdate
                # Column-level ForeignKey(...) (e.g. Flow.src/dst).
                for fk in table.foreign_keys:
                    new_ondelete = _normalise_fk_action(fk.ondelete)
                    new_onupdate = _normalise_fk_action(fk.onupdate)
                    if (new_ondelete, new_onupdate) != (fk.ondelete, fk.onupdate):
                        saved_fk_actions.append((fk, fk.ondelete, fk.onupdate))
                        fk.ondelete = new_ondelete
                        fk.onupdate = new_onupdate
            super().init()  # type: ignore[misc]
        finally:
            for table, indexes in saved_indexes.items():
                for ix in indexes:
                    table.indexes.add(ix)
            for fk_or_fkc, ondelete, onupdate in saved_fk_actions:
                fk_or_fkc.ondelete = ondelete
                fk_or_fkc.onupdate = onupdate


class DuckDBNmap(DuckDBMixin, PostgresDBNmap):
    """DuckDB backend for the ``nmap`` (active-scan) data category."""


class DuckDBView(DuckDBMixin, PostgresDBView):
    """DuckDB backend for the ``view`` (merged-host) data category."""


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
