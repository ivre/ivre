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

"""This sub-module contains functions to interact with PostgreSQL
databases.

"""

# Tests like "expr == None" should be used for BinaryExpression instances
# pylint: disable=singleton-comparison


import datetime
import re
import time
from typing import Any

from sqlalchemy import (
    ARRAY,
    Column,
    Index,
    String,
    Table,
    and_,
    cast,
    column,
    delete,
    desc,
    exists,
    func,
    insert,
    join,
    lateral,
    not_,
    null,
    nulls_first,
    select,
    text,
    true,
    tuple_,
    update,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.sqltypes import TupleType

from ivre import config, utils, xmlnmap
from ivre.db.sql import (
    SQLDB,
    PassiveCSVFile,
    ScanCSVFile,
    SQLDBActive,
    SQLDBFlow,
    SQLDBNmap,
    SQLDBPassive,
    SQLDBView,
)

# Workaround an SQLAlchemy 1.4 regression where ``TupleType``
# carries a result_processor that mangles tuple result rows.
# The class-level attribute is absent on 2.x (the regression
# is gone); guard the ``del`` so the import succeeds on both
# major versions.
try:
    del TupleType.result_processor
except AttributeError:
    pass


def _decode_portlist(value: Any) -> list[tuple[str, int]]:
    """Decode the ``ports`` column of the ``portlist:*``
    ``topvalues`` query into ``[(proto, port), ...]``.

    SQLAlchemy compiles
    ``func.array_agg(tuple_(protocol, port))`` to
    ``array_agg(ROW(protocol, port))`` on every dialect, but
    the round-trip shape differs between backends:

    * **PostgreSQL** (``psycopg2``) returns the column as a
      ``record[]`` literal serialised as a string, e.g.
      ``'{"(tcp,80)","(tcp,443)"}'``.
    * **DuckDB** (``duckdb-engine``) maps
      ``LIST(STRUCT(VARCHAR, INTEGER))`` to a Python
      ``list[tuple[str, int]]`` directly, e.g.
      ``[('tcp', 80), ('tcp', 443)]``.

    Decoding both shapes here lets the rest of
    :meth:`PostgresDB.topvalues` stay backend-agnostic.
    """
    if isinstance(value, list):
        return [(proto, int(port)) for proto, port in value]
    # PostgreSQL ``record[]`` string form.  Empty arrays come
    # through as the literal ``"{}"``; the historical slice
    # below assumes at least one element wrapped in
    # ``"(...)"`` and would split a stray empty entry into a
    # 1-tuple.  Short-circuit the empty case explicitly.
    if value in ("{}", "{NULL}"):
        return []
    return [
        (proto, int(port))
        for proto, port in (elt.split(",") for elt in value[3:-3].split(')","('))
    ]


class PostgresDB(SQLDB):
    @staticmethod
    def ip2internal(addr):
        return utils.force_int2ip(addr)

    @staticmethod
    def internal2ip(addr):
        return addr

    def copy_from(self, *args, conn=None, **kargs):
        """Wrap ``psycopg2``'s ``cursor.copy_from`` with optional
        connection pinning.

        When ``conn`` is provided (a SQLAlchemy ``Connection``),
        the COPY runs on its underlying DBAPI connection so a
        ``CREATE TEMPORARY TABLE`` issued earlier on the same
        ``conn`` is visible. This is mandatory for
        ``insert_or_update_bulk`` -- TEMP tables are
        session-scoped in PostgreSQL and the pool would
        otherwise hand out a different connection per
        operation.

        When ``conn`` is ``None`` (legacy path, kept for any
        external caller), the method does its own connect /
        commit / close cycle on a fresh connection.
        """
        if conn is not None:
            cursor = conn.connection.cursor()
            cursor.copy_from(*args, **kargs)
            return
        cursor = self.db.raw_connection().cursor()
        own_conn = self.db.connect()
        trans = own_conn.begin()
        cursor.copy_from(*args, **kargs)
        trans.commit()
        own_conn.close()

    def create_tmp_table(self, table, extracols=None, conn=None):
        """Create (idempotently) a ``TEMPORARY`` mirror of ``table``.

        Reuses the in-memory ``Table`` definition when this
        method is called more than once per process for the
        same source table: SQLAlchemy's ``MetaData`` keeps a
        registry keyed by table name, and a second
        ``Table(...)`` call with the same name raises
        ``InvalidRequestError: Table 'tmp_<...>' is already
        defined for this MetaData instance``. The first caller
        that hits ``insert_or_update_bulk`` registers the
        ``tmp_<table>`` template; subsequent callers retrieve
        it from ``metadata.tables`` and only re-issue the
        ``CREATE TEMPORARY TABLE`` (``checkfirst=True`` makes
        that idempotent at the SQL layer too).

        ``conn`` (optional SQLAlchemy ``Connection``) pins the
        ``CREATE TEMPORARY TABLE`` to a specific session so the
        table is visible to subsequent operations on the same
        ``conn`` -- required by ``insert_or_update_bulk``.
        """
        tmp_name = f"tmp_{table.__tablename__}"
        metadata = table.__table__.metadata
        t = metadata.tables.get(tmp_name)
        if t is None:
            cols = [c.copy() for c in table.__table__.columns]
            for c in cols:
                c.index = False
                c.nullable = True
                c.foreign_keys = None
                if c.primary_key:
                    c.primary_key = False
                    c.index = True
                    # Strip the ``Sequence``-driven default that
                    # the source table's ``id`` column carries
                    # (see ``ivre.db.sql.tables._id_column``).
                    # ``Column.copy()`` propagates the
                    # ``server_default = nextval('seq_<table>_id')``
                    # clause to the temp-table mirror, which then
                    # holds a hard catalog dependency on the
                    # source sequence.  PostgreSQL refuses to
                    # ``DROP SEQUENCE seq_<table>_id`` while a
                    # pooled connection still owns the
                    # session-scoped ``tmp_<table>`` (error
                    # ``cannot drop sequence ... because other
                    # objects depend on it``), which propagates
                    # into the next test's ``init()`` and rolls
                    # back the schema reset, leaking data across
                    # tests.  The temp table never reads the
                    # ``id`` column -- callers project only the
                    # named columns through their
                    # ``INSERT ... FROM SELECT`` -- so the
                    # default is unnecessary; dropping it removes
                    # the cross-session dependency.
                    c.default = None
                    c.server_default = None
            if extracols is not None:
                cols.extend(extracols)
            t = Table(
                tmp_name,
                metadata,
                *cols,
                prefixes=["TEMPORARY"],
            )
        t.create(bind=conn if conn is not None else self.db, checkfirst=True)
        return t

    def start_bulk_insert(self, size=None, retries=0):
        return BulkInsert(self.db, size=size, retries=retries)

    def explain(self, req, **_):
        """Return the PostgreSQL ``EXPLAIN`` output for a SQLAlchemy
        query expression.

        Parameter values are inlined into the SQL statement using
        SQLAlchemy's per-type literal binding (``literal_binds``)
        so each value goes through the column type's
        ``literal_processor`` — strings get backslash-aware
        single-quote escaping, bytes are emitted as ``E'\\x...'``,
        datetimes are formatted with their proper PostgreSQL
        cast, ``None`` is emitted as ``NULL``, booleans as ``TRUE``
        / ``FALSE``, etc. This replaces an earlier approach that
        used ``repr(value)`` to produce SQL literals, which only
        coincidentally worked for plain strings and integers and
        was brittle at best (e.g. ``repr(b"x")`` is ``b'x'``,
        which is not valid PostgreSQL).

        The compiled SQL is dispatched via ``exec_driver_sql`` so
        that ``text()``'s bind-parameter parsing does not
        reinterpret ``:`` characters that may appear inside string
        literals or PostgreSQL ``::`` casts in the compiled
        statement.
        """
        compiled = req.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
        sql = f"EXPLAIN {compiled}"
        with self.db.connect() as conn:
            rows = conn.exec_driver_sql(sql).fetchall()
        return "\n".join(map(" ".join, rows))


class BulkInsert:
    """A PostgreSQL transaction, with automatic commits"""

    def __init__(self, db, size=None, retries=0):
        """`size` is the number of inserts per commit and `retries` is the
        number of times to retry a failed transaction (when inserting
        concurrently for example). 0 is forever, 1 does not retry, 2 retries
        once, etc.
        """
        self.db = db
        self.start_time = time.time()
        self.commited_counts: dict[str, int] = {}
        self.size = config.POSTGRES_BATCH_SIZE if size is None else size
        self.retries = retries
        self.conn = db.connect()
        self.trans = self.conn.begin()
        # Per-template queue: ``key -> (parameterless Insert,
        # list[params_dict])``. Identical SQL templates accumulate
        # their params for a single executemany on commit.
        self.queries: dict[str, tuple[Any, list[dict[str, Any]]]] = {}

    def append(self, stmt, params):
        """Queue a single row for executemany insertion.

        ``stmt`` is a *parameterless* :class:`~sqlalchemy.sql.dml.Insert`
        (or ``postgresql.insert``) over the target table. ``params``
        is a ``dict[str, Any]`` of column-to-value bindings for one
        row. Identical SQL strings (same target table, same bind-name
        set) batch into a single ``Connection.execute(stmt, [params,
        ...])`` call on commit.

        Replaces the legacy 1.x signature ``append(query)`` where
        ``query`` was a values-bound ``insert(...).values(**params)``;
        the values are now passed alongside the template so we don't
        depend on the private ``Insert._values`` / ``Insert.parameters``
        attributes that were renamed / removed in SQLAlchemy 2.x.
        """
        key = str(stmt)
        self.queries.setdefault(key, (stmt, []))[1].append(params)
        if len(self.queries[key][1]) >= self.size:
            self.commit(key=key)

    def commit(self, key=None, renew=True):
        if key is None:
            last = len(self.queries) - 1
            for i, q_key in enumerate(list(self.queries)):
                self.commit(key=q_key, renew=True if i < last else renew)
            return
        stmt, params = self.queries.pop(key)
        # ``Connection.execute(stmt, list_of_param_dicts)`` is
        # SQLAlchemy's executemany form on both 1.4 and 2.x and the
        # supported public replacement for the 1.x positional unpack
        # ``conn.execute(stmt, *params_list)``.
        self.conn.execute(stmt, params)
        self.trans.commit()
        newtime = time.time()
        l_params = len(params)
        try:
            self.commited_counts[key] += l_params
        except KeyError:
            self.commited_counts[key] = l_params
        rate = float(l_params) / (newtime - self.start_time)
        utils.LOGGER.debug("DB:%s", key)
        utils.LOGGER.debug(
            "DB:%d inserts, %f/sec (total %d)",
            l_params,
            rate,
            self.commited_counts[key],
        )
        if renew:
            self.start_time = newtime
            self.trans = self.conn.begin()

    def close(self):
        self.commit(renew=False)
        self.conn.close()


class PostgresDBFlow(PostgresDB, SQLDBFlow):
    pass


class PostgresDBActive(PostgresDB, SQLDBActive):
    def _migrate_schema_10_11(self):
        """Converts a record from version 10 to version 11.

        The PostgreSQL backend is only conerned by a limited subset of
        changes.

        """
        cond = self.tables.scan.schema_version == 10
        req = (
            select(
                self.tables.scan.id,
                self.tables.script.port,
                self.tables.script.output,
                self.tables.script.data,
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name == "ssl-cert"))
        )
        for rec in self._read_iter(req):
            if "ssl-cert" in rec.data:
                if "pem" in rec.data["ssl-cert"]:
                    data = "".join(
                        rec.data["ssl-cert"]["pem"].splitlines()[1:-1]
                    ).encode()
                    try:
                        newout, newinfo = xmlnmap.create_ssl_cert(data)
                    except Exception:
                        utils.LOGGER.warning(
                            "Cannot parse certificate %r", data, exc_info=True
                        )
                    else:
                        self._write(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == "ssl-cert",
                                )
                            )
                            .values(data={"ssl-cert": newinfo}, output=newout)
                        )
                        continue
                    try:
                        algo = rec.data["ssl-cert"].pop("pubkeyalgo")
                    except KeyError:
                        pass
                    else:
                        self._write(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == "ssl-cert",
                                )
                            )
                            .values(
                                data={
                                    "ssl-cert": dict(
                                        rec.data["ssl-cert"],
                                        type=utils.PUBKEY_TYPES.get(algo, algo),
                                    )
                                }
                            )
                        )
        self._write(update(self.tables.scan).where(cond).values(schema_version=11))
        return 0

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

    def _get_ips_ports(self, flt, limit=None, skip=None):
        req = flt.query(select(self.tables.scan.id))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return (
            {
                "addr": rec[2],
                "starttime": rec[1],
                "ports": [
                    {"proto": proto, "port": int(port), "state_state": state}
                    for proto, port, state in (
                        elt.split(",") for elt in "".join(rec[0])[3:-3].split(')","(')
                    )
                ],
            }
            for rec in self._read_iter(
                select(
                    func.array_agg(
                        postgresql.aggregate_order_by(
                            tuple_(
                                self.tables.port.protocol,
                                self.tables.port.port,
                                self.tables.port.state,
                            ).label("a"),
                            tuple_(
                                self.tables.port.protocol, self.tables.port.port
                            ).label("a"),
                        )
                    ).label("ports"),
                    self.tables.scan.time_start,
                    self.tables.scan.addr,
                )
                .select_from(join(self.tables.port, self.tables.scan))
                .group_by(self.tables.scan.addr, self.tables.scan.time_start)
                .where(and_(self.tables.port.port >= 0, self.tables.scan.id.in_(req)))
            )
        )

    def get_ips_ports(self, flt, limit=None, skip=None):
        result = list(self._get_ips_ports(flt, limit=limit, skip=skip))
        return result, sum(len(host.get("ports", [])) for host in result)

    def topvalues(
        self, field, flt=None, topnbr=10, sort=None, limit=None, skip=None, least=False
    ):
        """
        This method makes use of the aggregation framework to produce
        top values for a given field or pseudo-field. Pseudo-fields are:
          - category[:regexp] / label / asnum / country / net[:mask]
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
          - httphdr / httphdr.{name,value} / httphdr:<name>
          - httpapp / httpapp:<name>
          - modbus.* / s7.* / enip.*
          - mongo.dbs.*
          - vulns.*
          - screenwords
          - file.* / file.*:scriptid
          - hop
          - scanner.name / scanner.port:tcp / scanner.port:udp
          - domains / domains[:level] / domains[:domain] / domains[:domain[:level]]
          - ja3-client[:filter][.type], ja3-server[:filter][:client][.type], jarm
          - hassh.type, hassh-client.type, hassh-server.type
          - tag.{value,type,info} / tag[:value]
        """
        if flt is None:
            flt = self.flt_empty
        base = flt.query(select(self.tables.scan.id).select_from(flt.select_from))
        order = "count" if least else desc("count")
        outputproc = None
        if field == "port":
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.protocol, self.tables.port.port],
                self.tables.port.state == "open",
            )
        elif field == "ttl":
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.state_reason_ttl],
                self.tables.port.state_reason_ttl != None,  # noqa: E711
            )
        elif field == "ttlinit":
            field = self._topstructure(
                self.tables.port,
                [
                    func.least(
                        255,
                        func.power(
                            2, func.ceil(func.log(2, self.tables.port.state_reason_ttl))
                        ),
                    )
                ],
                self.tables.port.state_reason_ttl != None,  # noqa: E711
            )
            outputproc = int
        elif field.startswith("port:"):
            info = field[5:]
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.protocol, self.tables.port.port],
                (
                    (self.tables.port.state == info)
                    if info in ["open", "filtered", "closed", "open|filtered"]
                    else (self.tables.port.service_name == info)
                ),
            )
        elif field.startswith("countports:"):
            info = field[11:]
            return (
                {"count": result[0], "_id": result[1]}
                for result in self._read_iter(
                    select(func.count().label("count"), column("cnt"))
                    .select_from(
                        select(func.count().label("cnt"))
                        .select_from(self.tables.port)
                        .where(
                            and_(
                                self.tables.port.state == info,
                                # self.tables.port.scan.in_(base),
                                exists(
                                    select(1)
                                    .select_from(base)
                                    .where(self.tables.port.scan == base.c.id)
                                ),
                            )
                        )
                        .group_by(self.tables.port.scan)
                        .alias("cnt")
                    )
                    .group_by("cnt")
                    .order_by(order)
                    .limit(topnbr)
                )
            )
        elif field.startswith("portlist:"):
            # Deux options pour filtrer:
            #   -1- self.tables.port.scan.in_(base),
            #   -2- exists(select(1)\
            #       .select_from(base)\
            #       .where(
            #         self.tables.port.scan == base.c.id
            #       )),
            #
            # D'après quelques tests, l'option -1- est plus beaucoup
            # rapide quand (base) est pas ou peu sélectif, l'option
            # -2- un peu plus rapide quand (base) est très sélectif
            #
            # TODO: vérifier si c'est pareil pour:
            #  - countports:open
            #  - tous les autres
            info = field[9:]
            # ``array_agg(tuple_(...))`` returns a PostgreSQL
            # ``record[]`` literal serialised as a string on
            # PostgreSQL (e.g. ``{"(tcp,80)","(tcp,443)"}``)
            # and an actual ``list[tuple[str, int]]`` on DuckDB
            # (``duckdb-engine`` maps ``LIST(STRUCT(...))`` to
            # a Python list).  Decode both shapes uniformly
            # into ``[(proto, port), ...]``.
            return (
                {
                    "count": result[0],
                    "_id": _decode_portlist(result[1]),
                }
                for result in self._read_iter(
                    select(func.count().label("count"), column("ports"))
                    .select_from(
                        select(
                            func.array_agg(
                                postgresql.aggregate_order_by(
                                    tuple_(
                                        self.tables.port.protocol,
                                        self.tables.port.port,
                                    ).label("a"),
                                    tuple_(
                                        self.tables.port.protocol,
                                        self.tables.port.port,
                                    ).label("a"),
                                )
                            ).label("ports"),
                        )
                        .where(
                            and_(
                                self.tables.port.state == info,
                                self.tables.port.scan.in_(base),
                                # exists(select(1)\
                                #        .select_from(base)\
                                #        .where(
                                #            self.tables.port.scan == base.c.id
                                #        )),
                            )
                        )
                        .group_by(self.tables.port.scan)
                        .alias("ports")
                    )
                    .group_by("ports")
                    .order_by(order)
                    .limit(topnbr)
                )
            )
        elif field == "service":
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.service_name],
                self.tables.port.state == "open",
            )
        elif field.startswith("service:"):
            info = field[8:]
            if "/" in info:
                info = info.split("/", 1)
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name],
                    and_(
                        self.tables.port.protocol == info[0],
                        self.tables.port.port == int(info[1]),
                    ),
                )
            else:
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name],
                    self.tables.port.port == int(info),
                )
        elif field == "product":
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.service_name, self.tables.port.service_product],
                self.tables.port.state == "open",
            )
        elif field.startswith("product:"):
            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name, self.tables.port.service_product],
                    and_(
                        self.tables.port.state == "open", self.tables.port.port == info
                    ),
                )
            elif info.startswith("tcp/") or info.startswith("udp/"):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1], protocol=info[0]))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name, self.tables.port.service_product],
                    and_(
                        self.tables.port.state == "open",
                        self.tables.port.port == info[1],
                        self.tables.port.protocol == info[0],
                    ),
                )
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name, self.tables.port.service_product],
                    and_(
                        self.tables.port.state == "open",
                        self.tables.port.service_name == info,
                    ),
                )
        elif field.startswith("cpe"):
            # Mirrors :meth:`MongoDB.topvalues` ``cpe`` /
            # ``cpe.<part>`` / ``cpe:<spec>`` /
            # ``cpe.<part>:<spec>`` family (with ``<part>`` one
            # of ``type`` / ``vendor`` / ``product`` /
            # ``version`` -- or 1..4 -- and ``<spec>`` an
            # optional ``:``-separated list of regex filters
            # narrowing the unwound CPEs).  Mongo concats the
            # selected fields into a single ``:``-separated
            # string and the outputproc splits back into a
            # tuple; SQL lets us group by the columns
            # directly so we just project them as a tuple
            # (``_topstructure`` returns ``result[1:]`` when
            # there is more than one projection column).
            try:
                cpe_field, cpe_spec = field.split(":", 1)
                cpe_spec_parts = cpe_spec.split(":", 3)
            except ValueError:
                cpe_field = field
                cpe_spec_parts = []
            try:
                cpe_field = cpe_field.split(".", 1)[1]
            except IndexError:
                cpe_field = "version"
            cpe_keys = ["type", "vendor", "product", "version"]
            if cpe_field not in cpe_keys:
                try:
                    cpe_field = cpe_keys[int(cpe_field) - 1]
                except (IndexError, ValueError):
                    cpe_field = "version"
            cpe_filters = list(
                zip(
                    cpe_keys,
                    (utils.str2regexp(value) for value in cpe_spec_parts),
                )
            )
            # ``searchcpe`` takes the same dict shape Mongo
            # passes to its ``$elemMatch`` -- with ``type``
            # renamed to ``cpe_type`` per the helper's API.
            flt = self.flt_and(
                flt,
                self.searchcpe(
                    **{
                        ("cpe_type" if key == "type" else key): value
                        for key, value in cpe_filters
                    }
                ),
            )
            # Project up to and including ``cpe_field``;
            # filter on the spec keys that were supplied.
            keep_count = max(cpe_keys.index(cpe_field) + 1, len(cpe_filters))
            kept_keys = cpe_keys[:keep_count]
            # ``lateral(...)`` is required so PostgreSQL
            # correlates the JSON unwind with the outer
            # ``v_scan`` row -- without the explicit lateral
            # marker, SA emits a comma-join and PG flags it
            # as a cartesian product
            # (``SAWarning: SELECT statement has a cartesian
            # product between FROM element(s) "cpe" and FROM
            # element "v_scan"``).  Implicit-lateral on SRFs
            # produces correct results today, but the warning
            # leaks to stderr on every CLI ``--top`` call.
            cpe_alias = lateral(func.jsonb_array_elements(self.tables.scan.cpes)).alias(
                "cpe"
            )
            cpe_conds = [
                self._searchstring_re(column("cpe").op("->>")(key), value)
                for key, value in cpe_filters
            ]
            field = self._topstructure(
                self.tables.scan,
                [column("cpe").op("->>")(key) for key in kept_keys],
                (
                    and_(*cpe_conds)
                    if cpe_conds
                    else self.tables.scan.cpes != None  # noqa: E711
                ),
                None,
                cpe_alias,
            )
        elif field == "devicetype":
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.service_devicetype],
                self.tables.port.state == "open",
            )
        elif field.startswith("devicetype:"):
            info = field[11:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_devicetype],
                    and_(
                        self.tables.port.state == "open", self.tables.port.port == info
                    ),
                )
            elif info.startswith("tcp/") or info.startswith("udp/"):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1], protocol=info[0]))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_devicetype],
                    and_(
                        self.tables.port.state == "open",
                        self.tables.port.port == info[1],
                        self.tables.port.protocol == info[0],
                    ),
                )
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_devicetype],
                    and_(
                        self.tables.port.state == "open",
                        self.tables.port.service_name == info,
                    ),
                )
        elif field == "version":
            field = self._topstructure(
                self.tables.port,
                [
                    self.tables.port.service_name,
                    self.tables.port.service_product,
                    self.tables.port.service_version,
                ],
                self.tables.port.state == "open",
            )
        elif field.startswith("version:"):
            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = self._topstructure(
                    self.tables.port,
                    [
                        self.tables.port.service_name,
                        self.tables.port.service_product,
                        self.tables.port.service_version,
                    ],
                    and_(
                        self.tables.port.state == "open", self.tables.port.port == info
                    ),
                )
            elif info.startswith("tcp/") or info.startswith("udp/"):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1], protocol=info[0]))
                field = self._topstructure(
                    self.tables.port,
                    [
                        self.tables.port.service_name,
                        self.tables.port.service_product,
                        self.tables.port.service_version,
                    ],
                    and_(
                        self.tables.port.state == "open",
                        self.tables.port.port == info[1],
                        self.tables.port.protocol == info[0],
                    ),
                )
            elif ":" in info:
                info = info.split(":", 1)
                flt = self.flt_and(
                    flt, self.searchproduct(product=info[1], service=info[0])
                )
                field = self._topstructure(
                    self.tables.port,
                    [
                        self.tables.port.service_name,
                        self.tables.port.service_product,
                        self.tables.port.service_version,
                    ],
                    and_(
                        self.tables.port.state == "open",
                        self.tables.port.service_name == info[0],
                        self.tables.port.service_product == info[1],
                    ),
                )
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = self._topstructure(
                    self.tables.port,
                    [
                        self.tables.port.service_name,
                        self.tables.port.service_product,
                        self.tables.port.service_version,
                    ],
                    and_(
                        self.tables.port.state == "open",
                        self.tables.port.service_name == info,
                    ),
                )
        elif field == "addr":
            # Mirrors :meth:`MongoDB.topvalues` ``addr``
            # branch: top values of the host address column,
            # decoded back to a printable IP via
            # :meth:`SQLDB.internal2ip` (which handles both
            # the ``str`` and ``dict`` round-trip shapes
            # PostgreSQL / DuckDB use for ``INET``).
            field = self._topstructure(self.tables.scan, [self.tables.scan.addr])

            def outputproc(addr):
                try:
                    return self.internal2ip(addr)
                except (TypeError, ValueError):
                    return addr

        elif field == "asnum":
            field = self._topstructure(
                self.tables.scan, [self.tables.scan.info["as_num"]]
            )
        elif field == "as":
            field = self._topstructure(
                self.tables.scan,
                [self.tables.scan.info["as_num"], self.tables.scan.info["as_name"]],
            )
        elif field == "country":
            field = self._topstructure(
                self.tables.scan,
                [
                    self.tables.scan.info["country_code"],
                    self.tables.scan.info["country_name"],
                ],
            )
        elif field == "city":
            field = self._topstructure(
                self.tables.scan,
                [self.tables.scan.info["country_code"], self.tables.scan.info["city"]],
            )
        elif field == "net" or field.startswith("net:"):
            info = field[4:]
            info = int(info) if info else 24
            field = self._topstructure(
                self.tables.scan,
                [func.set_masklen(text("scan.addr::cidr"), info)],
            )
        elif field == "script" or field.startswith("script:"):
            info = field[7:]
            if info:
                field = self._topstructure(
                    self.tables.script,
                    [self.tables.script.output],
                    self.tables.script.name == info,
                )
            else:
                field = self._topstructure(
                    self.tables.script, [self.tables.script.name]
                )
        elif field in {"category", "categories"}:
            field = self._topstructure(
                self.tables.category, [self.tables.category.name]
            )
        elif field.startswith("category:") or field.startswith("categories:"):
            expr = utils.str2regexp(field.split(":", 1)[1])
            flt = self.flt_and(flt, self.searchcategory(expr))
            field = self._topstructure(
                self.tables.category,
                [self.tables.category.name],
                self._searchstring_re(
                    self.tables.category.name,
                    expr,
                ),
            )
        elif field.startswith("cert."):
            subfield = field[5:]
            topfld = func.jsonb_array_elements(self.tables.script.data["ssl-cert"])
            if "." in subfield:
                first_fields = subfield.split(".")
                last_field = first_fields.pop()
                for subfld in first_fields:
                    topfld = topfld.op("->")(subfld)
                topfld = topfld.op("->>")(last_field)
            else:
                topfld = topfld.op(
                    "->" if subfield in ["subject", "issuer", "pubkey"] else "->>"
                )(subfield)
            field = self._topstructure(
                self.tables.script, [topfld], self.tables.script.name == "ssl-cert"
            )
        elif field.startswith("cacert."):
            subfield = field[5:]
            field = self._topstructure(
                self.tables.script,
                [
                    func.jsonb_array_elements(
                        self.tables.script.data["ssl-cert"],
                    ).op(
                        "->" if subfield in ["subject", "issuer", "pubkey"] else "->>"
                    )(subfield)
                ],
                self.tables.script.name == "ssl-cacert",
            )
        elif field == "useragent" or field.startswith("useragent:"):
            if field == "useragent":
                flt = self.flt_and(flt, self.searchuseragent())
                field = self._topstructure(
                    self.tables.script,
                    [column("http_user_agent")],
                    self.tables.script.name == "http-user-agent",
                    None,
                    lateral(
                        func.jsonb_array_elements(
                            self.tables.script.data["http-user-agent"],
                        )
                    ).alias("http_user_agent"),
                )
            else:
                subfield = utils.str2regexp(field[10:])
                flt = self.flt_and(flt, self.searchuseragent(useragent=subfield))
                field = self._topstructure(
                    self.tables.script,
                    [column("http_user_agent")],
                    and_(
                        self.tables.script.name == "http-user-agent",
                        self._searchstring_re(
                            column("http_user_agent").op("->>")(0),
                            subfield,
                        ),
                    ),
                    None,
                    lateral(
                        func.jsonb_array_elements(
                            self.tables.script.data["http-user-agent"],
                        )
                    ).alias("http_user_agent"),
                )
        elif field == "ja3-client" or (
            field.startswith("ja3-client") and field[10] in ":."
        ):
            if ":" in field:
                field, value = field.split(":", 1)
                subkey, value = self._ja3keyvalue(utils.str2regexp(value))
            else:
                value = None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            flt = self.flt_and(flt, self.searchja3client(value_or_hash=value))
            if value is None:
                field = self._topstructure(
                    self.tables.script,
                    [column("ssl_ja3_client").op("->>")(subfield)],
                    self.tables.script.name == "ssl-ja3-client",
                    None,
                    lateral(
                        func.jsonb_array_elements(
                            self.tables.script.data["ssl-ja3-client"],
                        )
                    ).alias("ssl_ja3_client"),
                )
            else:
                field = self._topstructure(
                    self.tables.script,
                    [column("ssl_ja3_client").op("->>")(subfield)],
                    and_(
                        self.tables.script.name == "ssl-ja3-client",
                        # when value is not None, subkey is defined
                        # pylint: disable=possibly-used-before-assignment
                        self._searchstring_re(
                            column("ssl_ja3_client").op("->>")(subkey),
                            value,
                        ),
                    ),
                    None,
                    lateral(
                        func.jsonb_array_elements(
                            self.tables.script.data["ssl-ja3-client"],
                        )
                    ).alias("ssl_ja3_client"),
                )
        elif field == "ja3-server" or (
            field.startswith("ja3-server") and field[10] in ":."
        ):
            if ":" in field:
                field, values = field.split(":", 1)
                if ":" in values:
                    value1, value2 = values.split(":", 1)
                    if value1:
                        subkey1, value1 = self._ja3keyvalue(utils.str2regexp(value1))
                    else:
                        subkey1, value1 = None, None
                    if value2:
                        subkey2, value2 = self._ja3keyvalue(utils.str2regexp(value2))
                    else:
                        subkey2, value2 = None, None
                else:
                    subkey1, value1 = self._ja3keyvalue(utils.str2regexp(values))
                    subkey2, value2 = None, None
            else:
                subkey1, value1 = None, None
                subkey2, value2 = None, None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            condition = self.tables.script.name == "ssl-ja3-server"
            if value1 is not None:
                condition = and_(
                    condition,
                    self._searchstring_re(
                        column("ssl_ja3_server").op("->>")(subkey1),
                        value1,
                    ),
                )
            if value2 is not None:
                condition = and_(
                    condition,
                    self._searchstring_re(
                        column("ssl_ja3_server").op("->")("client").op("->>")(subkey2),
                        value2,
                    ),
                )
            field = self._topstructure(
                self.tables.script,
                [
                    column("ssl_ja3_server").op("->>")(subfield),
                    column("ssl_ja3_server").op("->")("client").op("->>")(subfield),
                ],
                condition,
                None,
                lateral(
                    func.jsonb_array_elements(
                        self.tables.script.data["ssl-ja3-server"],
                    )
                ).alias("ssl_ja3_server"),
            )
        elif field == "jarm":
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["ssl-jarm"]],
                self.tables.script.name == "ssl-jarm",
            )
        elif field.startswith("jarm:"):
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["ssl-jarm"]],
                (
                    (self.tables.script.name == "ssl-jarm")
                    & (self.tables.port.port == int(field[5:]))
                    & (self.tables.port.protocol == "tcp")
                ),
            )
        elif field == "sshkey.bits":
            # Mirrors :meth:`MongoDB.topvalues` ``sshkey.bits``
            # branch: tuple of ``(type, bits)`` unwound from
            # ``data.ssh-hostkey`` so the caller can correlate
            # the bit count to the key algorithm.  The Mongo
            # helper goes through ``searchsshkey()`` to scope
            # the filter; we do the same on the SQL side.
            flt = self.flt_and(flt, self.searchsshkey())
            field = self._topstructure(
                self.tables.script,
                [
                    column("sshkey").op("->>")("type"),
                    column("sshkey").op("->>")("bits"),
                ],
                self.tables.script.name == "ssh-hostkey",
                None,
                lateral(
                    func.jsonb_array_elements(
                        self.tables.script.data["ssh-hostkey"],
                    )
                ).alias("sshkey"),
            )
        elif field.startswith("sshkey."):
            # Mirrors :meth:`MongoDB.topvalues` ``sshkey.<other>``
            # branch: scalar value of a single key on each
            # unwound ``ssh-hostkey`` element.
            subfield = field[7:]
            flt = self.flt_and(flt, self.searchsshkey())
            field = self._topstructure(
                self.tables.script,
                [column("sshkey").op("->>")(subfield)],
                self.tables.script.name == "ssh-hostkey",
                None,
                lateral(
                    func.jsonb_array_elements(
                        self.tables.script.data["ssh-hostkey"],
                    )
                ).alias("sshkey"),
            )
        elif field == "ja4-client" or (
            field.startswith("ja4-client") and field[10] in ":."
        ):
            # Mirrors :meth:`MongoDB.topvalues` ``ja4-client``
            # branch: top values of a field on the unwound
            # ``ssl-ja4-client`` array.  The Mongo helper
            # supports the ``ja4-client[.<sub>][:<value>]``
            # form -- ``<sub>`` defaults to ``ja4`` (the
            # canonical fingerprint), ``<value>`` narrows the
            # filter to a specific fingerprint string.
            value = None
            if ":" in field:
                field, value = field.split(":", 1)
            if "." in field:
                _, subfield = field.split(".", 1)
            else:
                subfield = "ja4"
            flt = self.flt_and(flt, self.searchja4client(value=value))
            condition = self.tables.script.name == "ssl-ja4-client"
            if value is not None:
                condition = and_(
                    condition,
                    column("ssl_ja4_client").op("->>")("ja4") == value,
                )
            field = self._topstructure(
                self.tables.script,
                [column("ssl_ja4_client").op("->>")(subfield)],
                condition,
                None,
                lateral(
                    func.jsonb_array_elements(
                        self.tables.script.data["ssl-ja4-client"],
                    )
                ).alias("ssl_ja4_client"),
            )
        elif field == "hassh" or (field.startswith("hassh") and field[5] in "-."):
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            scriptflt = self.tables.script.name == "ssh2-enum-algos"
            if field == "hassh-server":
                flt = self.flt_and(flt, self.searchhassh(server=True))
                scriptflt = and_(scriptflt, self.tables.port.port != -1)
            elif field == "hassh-client":
                flt = self.flt_and(flt, self.searchhassh(server=False))
                scriptflt = and_(scriptflt, self.tables.port.port == -1)
            elif field == "hassh":
                flt = self.flt_and(flt, self.searchhassh())
            else:
                raise ValueError(f"Unknown field {field}")
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["ssh2-enum-algos"]["hassh"][subfield]],
                scriptflt,
            )
        elif field == "source":
            field = self._topstructure(self.tables.scan, [self.tables.scan.source])
        elif field == "domains":
            field = self._topstructure(
                self.tables.hostname, [func.unnest(self.tables.hostname.domains)]
            )
        elif field.startswith("domains:"):
            subfield = field[8:]
            field = "hostnames.domains"
            base1 = (
                select(func.unnest(self.tables.hostname.domains).label("domains"))
                .where(
                    exists(
                        select(1)
                        .select_from(base)
                        .where(self.tables.hostname.scan == base.c.id)
                    )
                )
                .cte("base1")
            )
            if subfield.isdigit():
                return (
                    {"count": result[1], "_id": result[0]}
                    for result in self._read_iter(
                        select(base1.c.domains, func.count().label("count"))
                        .where(
                            base1.c.domains.op("~")(
                                "^([^\\.]+\\.){%d}[^\\.]+$" % (int(subfield) - 1)
                            )
                        )
                        .group_by(base1.c.domains)
                        .order_by(order)
                        .limit(topnbr)
                    )
                )
            if ":" in subfield:
                subfield, level = subfield.split(":", 1)
                flt = self.flt_and(flt, self.searchdomain(subfield))
                return (
                    {"count": result[1], "_id": result[0]}
                    for result in self._read_iter(
                        select(base1.c.domains, func.count().label("count"))
                        .where(
                            base1.c.domains.op("~")(
                                "^([^\\.]+\\.){%d}%s$"
                                % (
                                    int(level) - subfield.count(".") - 1,
                                    re.escape(subfield),
                                )
                            )
                        )
                        .group_by(base1.c.domains)
                        .order_by(order)
                        .limit(topnbr)
                    )
                )
            flt = self.flt_and(flt, self.searchdomain(subfield))
            return (
                {"count": result[1], "_id": result[0]}
                for result in self._read_iter(
                    select(base1.c.domains, func.count().label("count"))
                    .where(base1.c.domains.op("~")(f"\\.{re.escape(subfield)}$"))
                    .group_by(base1.c.domains)
                    .order_by(order)
                    .limit(topnbr)
                )
            )
        elif field == "hop":
            field = self._topstructure(self.tables.hop, [self.tables.hop.ipaddr])
        elif field.startswith("hop") and field[3] in ":>":
            ttl = int(field[4:])
            field = self._topstructure(
                self.tables.hop,
                [self.tables.hop.ipaddr],
                (
                    (self.tables.hop.ttl > ttl)
                    if field[3] == ">"
                    else (self.tables.hop.ttl == ttl)
                ),
            )
        elif field == "file" or (field.startswith("file") and field[4] in ".:"):
            if field.startswith("file:"):
                scripts = field[5:]
                if "." in scripts:
                    scripts, field = scripts.split(".", 1)
                else:
                    field = "filename"
                scripts = scripts.split(",")
                flt = (
                    self.tables.script.name == scripts[0]
                    if len(scripts) == 1
                    else self.tables.script.name.in_(scripts)
                )
            else:
                field = field[5:] or "filename"
                flt = True
            field = self._topstructure(
                self.tables.script,
                [
                    func.jsonb_array_elements(
                        func.jsonb_array_elements(
                            self.tables.script.data["ls"]["volumes"]
                        ).op("->")("files")
                    )
                    .op("->>")(field)
                    .label(field)
                ],
                and_(
                    flt,
                    self.tables.script.data.op("@>")(
                        '{"ls": {"volumes": [{"files": []}]}}'
                    ),
                ),
            )
        elif field.startswith("modbus."):
            subfield = field[7:]
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["modbus-discover"][subfield]],
                and_(
                    self.tables.script.name == "modbus-discover",
                    self.tables.script.data["modbus-discover"].has_key(  # noqa: W601
                        subfield
                    ),
                ),
            )
        elif field.startswith("s7."):
            subfield = field[3:]
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["s7-info"][subfield]],
                and_(
                    self.tables.script.name == "s7-info",
                    self.tables.script.data["s7-info"].has_key(subfield),  # noqa: W601
                ),
            )
        elif field.startswith("smb."):
            # Mirrors :meth:`MongoDB.topvalues` ``smb.<key>``
            # branch: top values of a key on the
            # ``smb-os-discovery`` script's data document.  No
            # friendly-name aliases (the Mongo helper passes
            # the subkey through unchanged); :meth:`searchsmb`
            # narrows the active filter to scans carrying the
            # script.
            subfield = field[4:]
            flt = self.flt_and(flt, self.searchsmb())
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["smb-os-discovery"][subfield]],
                and_(
                    self.tables.script.name == "smb-os-discovery",
                    self.tables.script.data["smb-os-discovery"].has_key(  # noqa: W601
                        subfield
                    ),
                ),
            )
        elif field.startswith("mongo.dbs."):
            # Mirrors :meth:`MongoDB.topvalues` ``mongo.dbs.<key>``
            # branch: top values of a per-database field on the
            # ``mongodb-databases`` script's data document.
            subfield = field[10:]
            flt = self.flt_and(flt, self.searchscript(name="mongodb-databases"))
            field = self._topstructure(
                self.tables.script,
                [
                    self.tables.script.data["mongodb-databases"][subfield],
                ],
                and_(
                    self.tables.script.name == "mongodb-databases",
                    self.tables.script.data["mongodb-databases"].has_key(  # noqa: W601
                        subfield
                    ),
                ),
            )
        elif field.startswith("enip."):
            # Mirrors :meth:`MongoDB.topvalues` ``enip.<key>``
            # branch: friendly-name aliases for the most common
            # fields, pass-through for everything else.  Both
            # Mongo and the SQL backends index the same
            # ``ports.scripts.enip-info.<key>`` JSONB path.
            subfield = field[5:]
            subfield = {
                "vendor": "Vendor",
                "product": "Product Name",
                "serial": "Serial Number",
                "devtype": "Device Type",
                "prodcode": "Product Code",
                "rev": "Revision",
                "ip": "Device IP",
            }.get(subfield, subfield)
            flt = self.flt_and(flt, self.searchscript(name="enip-info"))
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["enip-info"][subfield]],
                and_(
                    self.tables.script.name == "enip-info",
                    self.tables.script.data["enip-info"].has_key(  # noqa: W601
                        subfield
                    ),
                ),
            )
        elif field == "ike.vendor_ids":
            # Mirrors :meth:`MongoDB.topvalues` ``ike.vendor_ids``
            # branch: tuple of ``(value, name)`` pairs unwound
            # from ``data.ike-info.vendor_ids``.  Both elements
            # land in the result tuple so a caller can render
            # the canonical ``Vendor IDs`` table verbatim.
            flt = self.flt_and(flt, self.searchscript(name="ike-info"))
            field = self._topstructure(
                self.tables.script,
                [
                    column("vendor_id").op("->>")("value"),
                    column("vendor_id").op("->>")("name"),
                ],
                self.tables.script.name == "ike-info",
                None,
                lateral(
                    func.jsonb_array_elements(
                        self.tables.script.data["ike-info"]["vendor_ids"],
                    )
                ).alias("vendor_id"),
            )
        elif field == "ike.transforms":
            # Mirrors :meth:`MongoDB.topvalues` ``ike.transforms``
            # branch: 6-tuple ``(Authentication, Encryption,
            # GroupDesc, Hash, LifeDuration, LifeType)`` unwound
            # from ``data.ike-info.transforms``.
            flt = self.flt_and(
                flt,
                self.searchscript(
                    name="ike-info",
                    values={"transforms": {"$exists": True}},
                ),
            )
            field = self._topstructure(
                self.tables.script,
                [
                    column("transform").op("->>")("Authentication"),
                    column("transform").op("->>")("Encryption"),
                    column("transform").op("->>")("GroupDesc"),
                    column("transform").op("->>")("Hash"),
                    column("transform").op("->>")("LifeDuration"),
                    column("transform").op("->>")("LifeType"),
                ],
                and_(
                    self.tables.script.name == "ike-info",
                    self.tables.script.data["ike-info"].has_key(  # noqa: W601
                        "transforms"
                    ),
                ),
                None,
                lateral(
                    func.jsonb_array_elements(
                        self.tables.script.data["ike-info"]["transforms"],
                    )
                ).alias("transform"),
            )
        elif field == "ike.notification":
            # Mirrors :meth:`MongoDB.topvalues` ``ike.notification``
            # branch: scalar ``notification_type`` value.
            flt = self.flt_and(
                flt,
                self.searchscript(
                    name="ike-info",
                    values={"notification_type": {"$exists": True}},
                ),
            )
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["ike-info"]["notification_type"]],
                and_(
                    self.tables.script.name == "ike-info",
                    self.tables.script.data["ike-info"].has_key(  # noqa: W601
                        "notification_type"
                    ),
                ),
            )
        elif field.startswith("ike."):
            # Pass-through for ``ike.<key>`` paths the specific
            # branches above do not cover -- mirrors the Mongo
            # helper's catch-all.
            subfield = field[4:]
            flt = self.flt_and(flt, self.searchscript(name="ike-info"))
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["ike-info"][subfield]],
                and_(
                    self.tables.script.name == "ike-info",
                    self.tables.script.data["ike-info"].has_key(subfield),  # noqa: W601
                ),
            )
        elif field == "vulns.id":
            # Mirrors :meth:`MongoDB.topvalues` ``vulns.id``
            # branch: top values of the vulnerability id field
            # across the unwound ``data.vulns`` array.  The
            # array lives on every script that emits the
            # ``vulns`` NSE-table (afp-path-vuln, *vsftpd*,
            # ssl-heartbleed, smb-vuln-*, http-vuln-*, ...) --
            # the JSONB-typeof guard is enough to scope the
            # aggregation without enumerating script names.
            flt = self.flt_and(flt, self.searchvuln())
            field = self._topstructure(
                self.tables.script,
                [column("vuln").op("->>")("id")],
                func.jsonb_typeof(self.tables.script.data.op("->")("vulns")) == "array",
                None,
                lateral(
                    func.jsonb_array_elements(
                        self.tables.script.data.op("->")("vulns"),
                    )
                ).alias("vuln"),
            )
        elif field.startswith("vulns."):
            # Mirrors :meth:`MongoDB.topvalues` ``vulns.<other>``
            # branch: tuple of ``(id, <other>)`` so the caller
            # can correlate the field back to the specific
            # vulnerability.  Same array-unwind shape as
            # ``vulns.id``.
            subfield = field[6:]
            flt = self.flt_and(flt, self.searchvuln())
            field = self._topstructure(
                self.tables.script,
                [
                    column("vuln").op("->>")("id"),
                    column("vuln").op("->>")(subfield),
                ],
                func.jsonb_typeof(self.tables.script.data.op("->")("vulns")) == "array",
                None,
                lateral(
                    func.jsonb_array_elements(
                        self.tables.script.data.op("->")("vulns"),
                    )
                ).alias("vuln"),
            )
        elif field == "screenwords":
            # Mirrors :meth:`MongoDB.topvalues` ``screenwords``
            # branch: top values of the OCR-derived word list
            # stored on the ``port.screenwords`` array column
            # (added in M4.3.2 alongside ``screenshot`` /
            # ``screendata``).  ``unnest()`` rolls each list
            # element out as its own row before grouping.
            flt = self.flt_and(flt, self.searchscreenshot(words=True))
            field = self._topstructure(
                self.tables.port,
                [func.unnest(self.tables.port.screenwords)],
                self.tables.port.screenwords != None,  # noqa: E711
            )
        elif field == "ntlm" or field.startswith("ntlm."):
            # Mirrors :meth:`MongoDB.topvalues` for the
            # ``ntlm`` branches (Mongo paths
            # ``ports.scripts.ntlm-info`` / ``...ntlm-info.<key>``).
            # The same friendly-name aliases the Mongo helper
            # exposes (``os`` -> ``Product_Version``,
            # ``domain`` -> ``NetBIOS_Domain_Name``, etc.) are
            # applied here so callers get identical results
            # across backends.
            flt = self.flt_and(flt, self.searchntlm())
            if field == "ntlm":
                # ``ntlm`` (no subkey) groups by the entire
                # ``ntlm-info`` JSONB document.
                field = self._topstructure(
                    self.tables.script,
                    [self.tables.script.data["ntlm-info"]],
                    self.tables.script.name == "ntlm-info",
                )
            else:
                subfield = field[5:]
                # Friendly-name aliases per
                # :meth:`MongoDB.topvalues` "ntlm." branch.
                subfield = {
                    "name": "Target_Name",
                    "server": "NetBIOS_Computer_Name",
                    "domain": "NetBIOS_Domain_Name",
                    "workgroup": "Workgroup",
                    "domain_dns": "DNS_Domain_Name",
                    "forest": "DNS_Tree_Name",
                    "fqdn": "DNS_Computer_Name",
                    "os": "Product_Version",
                    "version": "NTLM_Version",
                }.get(subfield, subfield)
                field = self._topstructure(
                    self.tables.script,
                    [self.tables.script.data["ntlm-info"][subfield]],
                    and_(
                        self.tables.script.name == "ntlm-info",
                        self.tables.script.data["ntlm-info"].has_key(  # noqa: W601
                            subfield
                        ),
                    ),
                )
        elif field == "httphdr":
            flt = self.flt_and(flt, self.searchhttphdr())
            field = self._topstructure(
                self.tables.script,
                [
                    column("hdr").op("->>")("name").label("name"),
                    column("hdr").op("->>")("value").label("value"),
                ],
                self.tables.script.name == "http-headers",
                [column("name"), column("value")],
                lateral(
                    func.jsonb_array_elements(self.tables.script.data["http-headers"])
                ).alias("hdr"),
            )
        elif field.startswith("httphdr."):
            flt = self.flt_and(flt, self.searchhttphdr())
            field = self._topstructure(
                self.tables.script,
                [column("hdr").op("->>")(field[8:]).label("topvalue")],
                self.tables.script.name == "http-headers",
                [column("topvalue")],
                lateral(
                    func.jsonb_array_elements(self.tables.script.data["http-headers"])
                ).alias("hdr"),
            )
        elif field.startswith("httphdr:"):
            subfield = field[8:].lower()
            flt = self.flt_and(flt, self.searchhttphdr(name=subfield))
            field = self._topstructure(
                self.tables.script,
                [column("hdr").op("->>")("value").label("value")],
                and_(
                    self.tables.script.name == "http-headers",
                    column("hdr").op("->>")("name") == subfield,
                ),
                [column("value")],
                lateral(
                    func.jsonb_array_elements(self.tables.script.data["http-headers"])
                ).alias("hdr"),
            )
        elif field == "httpapp":
            flt = self.flt_and(flt, self.searchhttpapp())
            field = self._topstructure(
                self.tables.script,
                [
                    column("app").op("->>")("application").label("application"),
                    column("app").op("->>")("version").label("version"),
                ],
                self.tables.script.name == "http-app",
                [column("application"), column("version")],
                lateral(
                    func.jsonb_array_elements(self.tables.script.data["http-app"])
                ).alias("app"),
            )
        elif field.startswith("httpapp:"):
            subfield = field[8:]
            flt = self.flt_and(flt, self.searchhttpapp(name=subfield))
            field = self._topstructure(
                self.tables.script,
                [column("app").op("->>")("version").label("version")],
                and_(
                    self.tables.script.name == "http-app",
                    column("app").op("->>")("application") == subfield,
                ),
                [column("version")],
                lateral(
                    func.jsonb_array_elements(self.tables.script.data["http-app"])
                ).alias("app"),
            )
        elif field == "schema_version":
            field = self._topstructure(
                self.tables.scan, [self.tables.scan.schema_version]
            )
        elif field.startswith("scanner.port:"):
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["scanner"]["ports"][field[13:]]["ports"]],
                and_(
                    self.tables.script.name == "scanner",
                    self.tables.script.data["scanner"].has_key("ports"),  # noqa: W601
                    self.tables.script.data["scanner"]["ports"].has_key(
                        field[13:]
                    ),  # noqa: W601
                ),
            )
        elif field == "scanner.name":
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data["scanner"]["scanners"]["name"]],
                and_(
                    self.tables.script.name == "scanner",
                    self.tables.script.data["scanner"].has_key(  # noqa: W601
                        "scanners"
                    ),
                ),
            )
        elif field == "tag" and hasattr(self, "searchtag"):
            flt = self.flt_and(flt, self.searchtag())
            field = self._topstructure(
                self.tables.tag, [self.tables.tag.value, self.tables.tag.info]
            )
        elif field == "tag.value" and hasattr(self, "searchtag"):
            flt = self.flt_and(flt, self.searchtag())
            field = self._topstructure(self.tables.tag, [self.tables.tag.value])
        elif field == "tag.info" and hasattr(self, "searchtag"):
            flt = self.flt_and(flt, self.searchtag())
            field = self._topstructure(self.tables.tag, [self.tables.tag.info])
        elif field == "tag.type" and hasattr(self, "searchtag"):
            flt = self.flt_and(flt, self.searchtag())
            field = self._topstructure(self.tables.tag, [self.tables.tag.type])
        elif field.startswith("tag:") and hasattr(self, "searchtag"):
            subfield = field[4:]
            flt = self.flt_and(flt, self.searchtag(tag={"value": subfield}))
            field = self._topstructure(
                self.tables.tag,
                [self.tables.tag.info],
                self.tables.tag.value == subfield,
            )
        else:
            raise ValueError(f"Unknown field {field}")
        s_from = {
            self.tables.script: join(self.tables.script, self.tables.port),
            self.tables.port: self.tables.port,
            self.tables.category: join(
                self.tables.association_scan_category, self.tables.category
            ),
            self.tables.hostname: self.tables.hostname,
            self.tables.hop: join(self.tables.trace, self.tables.hop),
            self.tables.tag: self.tables.tag,
        }
        where_clause = {
            self.tables.script: self.tables.port.scan == base.c.id,
            self.tables.port: self.tables.port.scan == base.c.id,
            self.tables.category: self.tables.association_scan_category.scan
            == base.c.id,
            self.tables.hostname: self.tables.hostname.scan == base.c.id,
            self.tables.hop: self.tables.trace.scan == base.c.id,
            self.tables.tag: self.tables.tag.scan == base.c.id,
        }
        if field.base == self.tables.scan:
            # ``extraselectfrom`` is supported on the
            # scan-base path too (cpe.* unwinds the
            # ``scan.cpes`` JSONB array via
            # :func:`jsonb_array_elements`); it is added to
            # the FROM list before the filter is applied so
            # the predicates and projection see the unwound
            # rows.  ``.join(extraselectfrom, true())``
            # produces explicit ``JOIN LATERAL ... ON true``
            # syntax SQLAlchemy recognises as a join,
            # silencing the
            # ``SAWarning: SELECT statement has a cartesian
            # product`` it would otherwise emit on
            # ``select_from(extraselectfrom)`` (a separate
            # FROM element with no join condition); the
            # behaviour at the database level is identical.
            scan_from = self.tables.scan
            if field.extraselectfrom is not None:
                scan_from = join(scan_from, field.extraselectfrom, true())
            req = (
                select(func.count().label("count"), *field.fields)
                .select_from(scan_from)
                .group_by(*(field.fields if field.group_by is None else field.group_by))
            )
            req = flt.query(req)
        else:
            base_from = s_from[field.base]
            # See :meth:`PostgresDBActive.topvalues`'s
            # scan-base branch above for the explicit
            # ``JOIN LATERAL ... ON true`` rationale -- same
            # SQLAlchemy-warning workaround applies here.
            if field.extraselectfrom is not None:
                base_from = join(base_from, field.extraselectfrom, true())
            req = select(func.count().label("count"), *field.fields).select_from(
                base_from
            )
            req = req.group_by(
                *(field.fields if field.group_by is None else field.group_by)
            ).where(exists(select(1).select_from(base).where(where_clause[field.base])))
        if field.where is not None:
            req = req.where(field.where)
        if outputproc is None:
            return (
                {
                    "count": result[0],
                    "_id": result[1:] if len(result) > 2 else result[1],
                }
                for result in self._read_iter(req.order_by(order).limit(topnbr))
            )
        return (
            {
                "count": result[0],
                "_id": outputproc(result[1:] if len(result) > 2 else result[1]),
            }
            for result in self._read_iter(req.order_by(order).limit(topnbr))
        )

    def _features_port_list(self, flt, yieldall, use_service, use_product, use_version):
        base = flt.query(select(self.tables.scan.id).select_from(flt.select_from)).cte(
            "base"
        )
        if use_version:
            fields = [
                self.tables.port.port,
                self.tables.port.service_name,
                self.tables.port.service_product,
                self.tables.port.service_version,
            ]
        elif use_product:
            fields = [
                self.tables.port.port,
                self.tables.port.service_name,
                self.tables.port.service_product,
            ]
        elif use_service:
            fields = [self.tables.port.port, self.tables.port.service_name]
        else:
            fields = [self.tables.port.port]
        req = (
            select(*fields)
            .group_by(*fields)
            .where(
                and_(
                    exists(
                        select(1)
                        .select_from(base)
                        .where(self.tables.port.scan == base.c.id)
                    ),
                    self.tables.port.state == "open",
                    self.tables.port.port != -1,
                )
            )
        )
        if not yieldall:
            req = req.order_by(*(nulls_first(fld) for fld in fields))
            return self._read_iter(req)
        # results will be modified, we cannot keep a RowProxy
        # instance, so we convert the results to lists
        return (list(rec) for rec in self._read_iter(req))

    def _features_port_get(
        self, features, flt, yieldall, use_service, use_product, use_version
    ):
        base = flt.query(select(self.tables.scan.id).select_from(flt.select_from)).cte(
            "base"
        )
        if use_version:
            fields = [
                cast(self.tables.port.port, String),
                self.tables.port.service_name,
                self.tables.port.service_product,
                self.tables.port.service_version,
            ]
        elif use_product:
            fields = [
                cast(self.tables.port.port, String),
                self.tables.port.service_name,
                self.tables.port.service_product,
            ]
        elif use_service:
            fields = [
                cast(self.tables.port.port, String),
                self.tables.port.service_name,
            ]
        else:
            fields = [self.tables.port.port]
        n_features = len(features)
        for addr, cur_features in self._read_iter(
            select(
                self.tables.scan.id,
                func.array_agg(func.distinct(postgresql.array(fields))),
            )
            .select_from(join(self.tables.scan, self.tables.port))
            .group_by(self.tables.scan.id)
            .where(
                and_(
                    exists(
                        select(1)
                        .select_from(base)
                        .where(self.tables.port.scan == base.c.id)
                    ),
                    self.tables.port.state == "open",
                    self.tables.port.port != -1,
                )
            )
        ):
            currec = [0] * n_features
            for feat in cur_features:
                if use_service:
                    # convert port number back to an integer
                    feat[0] = int(feat[0])
                try:
                    currec[features[tuple(feat)]] = 1
                except KeyError:
                    pass
            yield (addr, currec)
        # add features for addresses without open ports
        base2 = flt.query(
            select(func.distinct(self.tables.port.scan).label("scan"))
            .select_from(flt.select_from)
            .where(
                and_(
                    exists(
                        select(1)
                        .select_from(base)
                        .where(self.tables.port.scan == base.c.id)
                    ),
                    self.tables.port.state == "open",
                    self.tables.port.port != -1,
                )
            )
        ).cte("base2")
        for (addr,) in self._read_iter(
            flt.query(
                select(func.distinct(self.tables.scan.addr))
                .select_from(flt.select_from)
                .where(
                    not_(
                        exists(
                            select(1)
                            .select_from(base2)
                            .where(self.tables.scan.id == base2.c.scan)
                        )
                    )
                )
            )
        ):
            print(f"ADDING RECORD FOR {addr!r}")
            yield (addr, [0] * n_features)


class PostgresDBNmap(PostgresDBActive, SQLDBNmap):
    def _store_host(self, host):
        addr = self.ip2internal(host["addr"])
        info = host.get("infos")
        source = host.get("source", "")
        host_tstart = utils.all2datetime(host["starttime"])
        host_tstop = utils.all2datetime(host["endtime"])
        scanid = self._write(
            postgresql.insert(self.tables.scan)
            .values(
                addr=addr,
                source=source,
                info=info,
                time_start=host_tstart,
                time_stop=host_tstop,
                # FIXME: masscan results may lack 'state' and 'state_reason'
                state=host.get("state"),
                state_reason=host.get("state_reason"),
                state_reason_ttl=host.get("state_reason_ttl"),
                # SQLAlchemy's JSON / JSONB ``bind_processor`` calls
                # :func:`json.dumps` on whatever Python value it
                # receives, so passing ``None`` would store the
                # JSON literal ``'null'`` (and ``cpes IS NOT NULL``
                # would still match the row).  Pass an explicit
                # SQL ``NULL`` for absent / empty payloads so
                # :meth:`searchcpe` / :meth:`searchos` match only
                # records with real data, mirroring Mongo's
                # ``{"$exists": true}`` semantics on the array
                # field.
                cpes=host["cpes"] if host.get("cpes") else null(),
                os=host["os"] if host.get("os") else null(),
                addresses=(host["addresses"] if host.get("addresses") else null()),
            )
            .on_conflict_do_nothing()
            .returning(self.tables.scan.id)
        ).fetchone()[0]
        for category in host.get("categories", []):
            insrt = postgresql.insert(self.tables.category)
            catid = self._write(
                insrt.values(name=category)
                .on_conflict_do_update(
                    index_elements=["name"], set_={"name": insrt.excluded.name}
                )
                .returning(self.tables.category.id)
            ).fetchone()[0]
            self._write(
                postgresql.insert(self.tables.association_scan_category)
                .values(scan=scanid, category=catid)
                .on_conflict_do_nothing()
            )
        for tag in host.get("tags", []):
            if "info" not in tag:
                self.bulk.append(
                    postgresql.insert(self.tables.tag),
                    {"scan": scanid, **tag},
                )
            else:
                for info in tag["info"]:
                    self.bulk.append(
                        postgresql.insert(self.tables.tag),
                        {"scan": scanid, **dict(tag, info=info)},
                    )
        for port in host.get("ports", []):
            scripts = port.pop("scripts", [])
            # ``service_method`` has no dedicated column on the
            # ``_Port`` mixin -- it's an ephemeral nmap-detection
            # tag (``probed`` / ``table``) that doesn't add value
            # to a stored record.  ``screendata`` is normalised
            # below: bytes are kept as-is for the ``LargeBinary``
            # column, base64-encoded strings (some ingestion
            # paths produce those) are decoded back to bytes.
            port.pop("service_method", None)
            if "screendata" in port and isinstance(port["screendata"], str):
                port["screendata"] = utils.decode_b64(port["screendata"].encode())
            if "service_servicefp" in port:
                port["service_fp"] = port.pop("service_servicefp")
            if "state_state" in port:
                port["state"] = port.pop("state_state")
            if "state_reason_ip" in port:
                port["state_reason_ip"] = self.ip2internal(port["state_reason_ip"])
            portid = self._write(
                insert(self.tables.port)
                .values(scan=scanid, **port)
                .returning(self.tables.port.id)
            ).fetchone()[0]
            for script in scripts:
                name, output = script.pop("id"), script.pop("output")
                if "ssl-cert" in script:
                    for cert in script["ssl-cert"]:
                        for fld in ["not_before", "not_after"]:
                            if fld not in cert:
                                continue
                            if isinstance(cert[fld], datetime.datetime):
                                cert[fld] = cert[fld].timestamp()
                            elif isinstance(cert[fld], str):
                                cert[fld] = utils.all2datetime(cert[fld]).timestamp()
                self.bulk.append(
                    insert(self.tables.script),
                    {
                        "port": portid,
                        "name": name,
                        "output": output,
                        "data": script,
                    },
                )
        for trace in host.get("traces", []):
            traceid = self._write(
                insert(self.tables.trace)
                .values(scan=scanid, port=trace.get("port"), protocol=trace["protocol"])
                .returning(self.tables.trace.id)
            ).fetchone()[0]
            for hop in trace.get("hops"):
                hop["ipaddr"] = self.ip2internal(hop["ipaddr"])
                self.bulk.append(
                    insert(self.tables.hop),
                    {
                        "trace": traceid,
                        "ipaddr": self.ip2internal(hop["ipaddr"]),
                        "ttl": hop["ttl"],
                        "rtt": None if hop["rtt"] == "--" else hop["rtt"],
                        "host": hop.get("host"),
                        "domains": hop.get("domains"),
                    },
                )
        for hostname in host.get("hostnames", []):
            self.bulk.append(
                insert(self.tables.hostname),
                {
                    "scan": scanid,
                    "domains": hostname.get("domains"),
                    "name": hostname.get("name"),
                    "type": hostname.get("type"),
                },
            )
        utils.LOGGER.debug("HOST STORED: %r", scanid)
        return scanid

    def store_host(self, host):
        self._store_host(host)

    def store_hosts(self, hosts):
        tmp = self.create_tmp_table(
            self.tables.scan,
            extracols=[
                Column("categories", ARRAY(String(32))),
                Column("source", String(32)),
                # Column("extraports", postgresql.JSONB),
                Column("hostnames", postgresql.JSONB),
                # openports
                Column("ports", postgresql.JSONB),
                # Column("traceroutes", postgresql.JSONB),
            ],
        )
        with ScanCSVFile(hosts, self.ip2internal, tmp) as fdesc:
            self.copy_from(fdesc, tmp.name)


class PostgresDBView(PostgresDBActive, SQLDBView):
    def _store_host(self, host):
        addr = self.ip2internal(host["addr"])
        info = host.get("infos")
        source = host.get("source", [])
        host_tstart = utils.all2datetime(host["starttime"])
        host_tstop = utils.all2datetime(host["endtime"])
        insrt = postgresql.insert(self.tables.scan)
        scanid, scan_tstop = self._write(
            insrt.values(
                addr=addr,
                source=source,
                info=info,
                time_start=host_tstart,
                time_stop=host_tstop,
                # See :meth:`PostgresDBNmap._store_host` for the
                # ``null()`` rationale (a Python ``None`` would
                # serialise to JSON ``'null'`` rather than SQL
                # ``NULL`` on a JSONB column, defeating
                # ``IS NOT NULL`` filters in :meth:`searchcpe` /
                # :meth:`searchos`).
                cpes=host["cpes"] if host.get("cpes") else null(),
                os=host["os"] if host.get("os") else null(),
                addresses=(host["addresses"] if host.get("addresses") else null()),
                **{
                    key: host.get(key)
                    for key in ["state", "state_reason", "state_reason_ttl"]
                    if key in host
                },
            )
            .on_conflict_do_update(
                index_elements=["addr"],
                set_={
                    "source": self.tables.scan.source + insrt.excluded.source,
                    "time_start": func.least(
                        self.tables.scan.time_start,
                        insrt.excluded.time_start,
                    ),
                    "time_stop": func.greatest(
                        self.tables.scan.time_stop,
                        insrt.excluded.time_stop,
                    ),
                    "cpes": func.coalesce(insrt.excluded.cpes, self.tables.scan.cpes),
                    "os": func.coalesce(insrt.excluded.os, self.tables.scan.os),
                    "addresses": func.coalesce(
                        insrt.excluded.addresses, self.tables.scan.addresses
                    ),
                },
            )
            .returning(self.tables.scan.id, self.tables.scan.time_stop)
        ).fetchone()
        newest = scan_tstop <= host_tstop
        for category in host.get("categories", []):
            insrt = postgresql.insert(self.tables.category)
            catid = self._write(
                insrt.values(name=category)
                .on_conflict_do_update(
                    index_elements=["name"], set_={"name": insrt.excluded.name}
                )
                .returning(self.tables.category.id)
            ).fetchone()[0]
            self._write(
                postgresql.insert(self.tables.association_scan_category)
                .values(scan=scanid, category=catid)
                .on_conflict_do_nothing()
            )
        for port in host.get("ports", []):
            scripts = port.pop("scripts", [])
            # See :meth:`PostgresDBNmap._store_host` for the
            # ``service_method`` and ``screendata`` rationale.
            port.pop("service_method", None)
            if "screendata" in port and isinstance(port["screendata"], str):
                port["screendata"] = utils.decode_b64(port["screendata"].encode())
            if "service_servicefp" in port:
                port["service_fp"] = port.pop("service_servicefp")
            if "state_state" in port:
                port["state"] = port.pop("state_state")
            if "state_reason_ip" in port:
                port["state_reason_ip"] = self.ip2internal(port["state_reason_ip"])
            insrt = postgresql.insert(self.tables.port)
            portid = self._write(
                insrt.values(scan=scanid, **port)
                .on_conflict_do_update(
                    index_elements=["scan", "port", "protocol"],
                    set_={"scan": scanid, **(port if newest else {})},
                )
                .returning(self.tables.port.id)
            ).fetchone()[0]
            for script in scripts:
                name, output = script.pop("id"), script.pop("output")
                if "ssl-cert" in script:
                    for cert in script["ssl-cert"]:
                        for fld in ["not_before", "not_after"]:
                            if fld not in cert:
                                continue
                            if isinstance(cert[fld], datetime.datetime):
                                cert[fld] = cert[fld].timestamp()
                            elif isinstance(cert[fld], str):
                                cert[fld] = utils.all2datetime(cert[fld]).timestamp()
                if newest:
                    insrt = postgresql.insert(self.tables.script)
                    self.bulk.append(
                        insrt.on_conflict_do_update(
                            index_elements=["port", "name"],
                            set_={
                                "output": insrt.excluded.output,
                                "data": insrt.excluded.data,
                            },
                        ),
                        {
                            "port": portid,
                            "name": name,
                            "output": output,
                            "data": script,
                        },
                    )
                else:
                    insrt = postgresql.insert(self.tables.script)
                    self.bulk.append(
                        insrt.on_conflict_do_nothing(),
                        {
                            "port": portid,
                            "name": name,
                            "output": output,
                            "data": script,
                        },
                    )
        for tag in host.get("tags", []):
            if "info" not in tag:
                self.bulk.append(
                    postgresql.insert(self.tables.tag).on_conflict_do_nothing(),
                    {"scan": scanid, **tag},
                )
            else:
                for info in tag["info"]:
                    self.bulk.append(
                        postgresql.insert(self.tables.tag).on_conflict_do_nothing(),
                        {"scan": scanid, **dict(tag, info=info)},
                    )
        for trace in host.get("traces", []):
            traceid = self._write(
                postgresql.insert(self.tables.trace)
                .values(scan=scanid, port=trace.get("port"), protocol=trace["protocol"])
                .on_conflict_do_nothing()
                .returning(self.tables.trace.id)
            ).fetchone()[0]
            for hop in trace.get("hops"):
                hop["ipaddr"] = self.ip2internal(hop["ipaddr"])
                self.bulk.append(
                    postgresql.insert(self.tables.hop),
                    {
                        "trace": traceid,
                        "ipaddr": self.ip2internal(hop["ipaddr"]),
                        "ttl": hop["ttl"],
                        "rtt": None if hop["rtt"] == "--" else hop["rtt"],
                        "host": hop.get("host"),
                        "domains": hop.get("domains"),
                    },
                )
        for hostname in host.get("hostnames", []):
            self.bulk.append(
                postgresql.insert(self.tables.hostname).on_conflict_do_nothing(),
                {
                    "scan": scanid,
                    "domains": hostname.get("domains"),
                    "name": hostname.get("name"),
                    "type": hostname.get("type"),
                },
            )
        utils.LOGGER.debug("VIEW STORED: %r", scanid)
        return scanid

    def store_host(self, host):
        self._store_host(host)


class PostgresDBPassive(PostgresDB, SQLDBPassive):
    def __init__(self, url):
        super().__init__(url)
        Index(
            "ix_passive_record",
            self.tables.passive.addr,
            self.tables.passive.sensor,
            self.tables.passive.recontype,
            self.tables.passive.port,
            self.tables.passive.source,
            self.tables.passive.value,
            self.tables.passive.targetval,
            self.tables.passive.info,
            unique=True,
            postgresql_where=self.tables.passive.addr != None,  # noqa: E711
        )
        Index(
            "ix_passive_record_noaddr",
            self.tables.passive.sensor,
            self.tables.passive.recontype,
            self.tables.passive.port,
            self.tables.passive.source,
            self.tables.passive.value,
            self.tables.passive.targetval,
            self.tables.passive.info,
            unique=True,
            postgresql_where=self.tables.passive.addr == None,  # noqa: E711
        )

    def _insert_or_update(self, timestamp, values, lastseen=None, replacecount=False):
        stmt = postgresql.insert(self.tables.passive).values(values)
        upsert = {
            "firstseen": func.least(
                self.tables.passive.firstseen,
                timestamp,
            ),
            "lastseen": func.greatest(
                self.tables.passive.lastseen,
                lastseen or timestamp,
            ),
            "count": (
                stmt.excluded.count
                if replacecount
                else self.tables.passive.count + stmt.excluded.count
            ),
        }
        if values.get("addr"):
            stmt = stmt.on_conflict_do_update(
                index_elements=[
                    "addr",
                    "sensor",
                    "recontype",
                    "port",
                    "source",
                    "value",
                    "targetval",
                    "info",
                ],
                index_where=self.tables.passive.addr != None,  # noqa: E711
                set_=upsert,
            )
        else:
            stmt = stmt.on_conflict_do_update(
                index_elements=[
                    "sensor",
                    "recontype",
                    "port",
                    "source",
                    "value",
                    "targetval",
                    "info",
                ],
                index_where=self.tables.passive.addr == None,  # noqa: E711
                set_=upsert,
            )
        self._write(stmt)

    def insert_or_update_bulk(
        self, specs, getinfos=None, separated_timestamps=True, replacecount=False
    ):
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
        if config.DEBUG_DB:
            total_upserted = 0
            total_start_time = time.time()
        # Hold ONE connection for the entire bulk-insert sequence.
        # PostgreSQL TEMP tables are session-scoped, so the
        # ``CREATE TEMPORARY TABLE`` issued by
        # ``create_tmp_table``, the ``COPY FROM`` issued by
        # ``copy_from``, and the two ``INSERT ... FROM SELECT
        # ... ON CONFLICT`` statements + the final
        # ``DELETE FROM tmp`` MUST all run on the same session.
        # The default per-method ``self.db.connect()`` path would
        # hand out a different pooled connection each time, with
        # the ``COPY`` then failing
        # ``psycopg2.errors.UndefinedTable: relation
        # "tmp_passive" does not exist`` (the TEMP table only
        # exists on the session that issued the CREATE).
        # ``Engine.begin()`` opens a transaction-scoped
        # connection; on success it commits (also dropping the
        # TEMP table at end-of-session), on exception it rolls
        # back.
        with self.db.begin() as conn:
            tmp = self.create_tmp_table(self.tables.passive, conn=conn)
            while more_to_read:
                if config.DEBUG_DB:
                    start_time = time.time()
                with PassiveCSVFile(
                    specs,
                    self.ip2internal,
                    tmp,
                    getinfos=getinfos,
                    separated_timestamps=separated_timestamps,
                    limit=config.POSTGRES_BATCH_SIZE,
                ) as fdesc:
                    self.copy_from(fdesc, tmp.name, conn=conn)
                    more_to_read = fdesc.more_to_read
                    if config.DEBUG_DB:
                        count_upserted = fdesc.count
                insrt = postgresql.insert(self.tables.passive)
                conn.execute(
                    insrt.from_select(
                        [
                            column(col)
                            for col in [
                                "addr",
                                # sum / min / max
                                "count",
                                "firstseen",
                                "lastseen",
                                # grouped
                                "sensor",
                                "port",
                                "recontype",
                                "source",
                                "targetval",
                                "value",
                                "info",
                                "moreinfo",
                            ]
                        ],
                        select(
                            tmp.columns["addr"],
                            func.sum_(tmp.columns["count"]),
                            func.min_(tmp.columns["firstseen"]),
                            func.max_(tmp.columns["lastseen"]),
                            *(
                                tmp.columns[col]
                                for col in [
                                    "sensor",
                                    "port",
                                    "recontype",
                                    "source",
                                    "targetval",
                                    "value",
                                    "info",
                                    "moreinfo",
                                ]
                            ),
                        )
                        .where(tmp.columns["addr"] != None)  # noqa: E711
                        .group_by(
                            *(
                                tmp.columns[col]
                                for col in [
                                    "addr",
                                    "sensor",
                                    "port",
                                    "recontype",
                                    "source",
                                    "targetval",
                                    "value",
                                    "info",
                                    "moreinfo",
                                ]
                            )
                        ),
                    ).on_conflict_do_update(
                        index_elements=[
                            "addr",
                            "sensor",
                            "recontype",
                            "port",
                            "source",
                            "value",
                            "targetval",
                            "info",
                        ],
                        index_where=self.tables.passive.addr != None,  # noqa: E711
                        set_={
                            "firstseen": func.least(
                                self.tables.passive.firstseen,
                                insrt.excluded.firstseen,
                            ),
                            "lastseen": func.greatest(
                                self.tables.passive.lastseen,
                                insrt.excluded.lastseen,
                            ),
                            "count": (
                                insrt.excluded.count
                                if replacecount
                                else self.tables.passive.count + insrt.excluded.count
                            ),
                        },
                    )
                )
                conn.execute(
                    insrt.from_select(
                        [
                            column(col)
                            for col in [
                                "addr",
                                # sum / min / max
                                "count",
                                "firstseen",
                                "lastseen",
                                # grouped
                                "sensor",
                                "port",
                                "recontype",
                                "source",
                                "targetval",
                                "value",
                                "info",
                                "moreinfo",
                            ]
                        ],
                        select(
                            tmp.columns["addr"],
                            func.sum_(tmp.columns["count"]),
                            func.min_(tmp.columns["firstseen"]),
                            func.max_(tmp.columns["lastseen"]),
                            *(
                                tmp.columns[col]
                                for col in [
                                    "sensor",
                                    "port",
                                    "recontype",
                                    "source",
                                    "targetval",
                                    "value",
                                    "info",
                                    "moreinfo",
                                ]
                            ),
                        )
                        .where(tmp.columns["addr"] == None)  # noqa: E711
                        .group_by(
                            *(
                                tmp.columns[col]
                                for col in [
                                    "addr",
                                    "sensor",
                                    "port",
                                    "recontype",
                                    "source",
                                    "targetval",
                                    "value",
                                    "info",
                                    "moreinfo",
                                ]
                            )
                        ),
                    ).on_conflict_do_update(
                        index_elements=[
                            "sensor",
                            "recontype",
                            "port",
                            "source",
                            "value",
                            "targetval",
                            "info",
                        ],
                        index_where=self.tables.passive.addr == None,  # noqa: E711
                        # (BinaryExpression)
                        set_={
                            "firstseen": func.least(
                                self.tables.passive.firstseen,
                                insrt.excluded.firstseen,
                            ),
                            "lastseen": func.greatest(
                                self.tables.passive.lastseen,
                                insrt.excluded.lastseen,
                            ),
                            "count": (
                                insrt.excluded.count
                                if replacecount
                                else self.tables.passive.count + insrt.excluded.count
                            ),
                        },
                    )
                )
                conn.execute(delete(tmp))
                if config.DEBUG_DB:
                    stop_time = time.time()
                    time_spent = stop_time - start_time
                    total_upserted += count_upserted
                    total_time_spent = stop_time - total_start_time
                    utils.LOGGER.debug(
                        "DB:PERFORMANCE STATS %s upserts, %f s, %s/s\n"
                        "\ttotal: %s upserts, %f s, %s/s",
                        utils.num2readable(count_upserted),
                        time_spent,
                        utils.num2readable(float(count_upserted) / time_spent),
                        utils.num2readable(total_upserted),
                        total_time_spent,
                        utils.num2readable(float(total_upserted) / total_time_spent),
                    )

    def _features_port_get(
        self, features, flt, yieldall, use_service, use_product, use_version
    ):
        flt = self.flt_and(flt, self.searchport(-1, neg=True))
        if use_version:
            fields = [
                cast(self.tables.passive.port, String),
                self.tables.passive.moreinfo.op("->>")("service_name"),
                self.tables.passive.moreinfo.op("->>")("service_product"),
                self.tables.passive.moreinfo.op("->>")("service_version"),
            ]
        elif use_product:
            fields = [
                cast(self.tables.passive.port, String),
                self.tables.passive.moreinfo.op("->>")("service_name"),
                self.tables.passive.moreinfo.op("->>")("service_product"),
            ]
        elif use_service:
            fields = [
                cast(self.tables.passive.port, String),
                self.tables.passive.moreinfo.op("->>")("service_name"),
            ]
        else:
            fields = [self.tables.passive.port]
        n_features = len(features)
        for addr, cur_features in self._read_iter(
            flt.query(
                select(
                    self.tables.passive.addr,
                    func.array_agg(func.distinct(postgresql.array(fields))),
                ).group_by(self.tables.passive.addr)
            )
        ):
            currec = [0] * n_features
            for feat in cur_features:
                if use_service:
                    # convert port number back to an integer
                    feat[0] = int(feat[0])
                try:
                    currec[features[tuple(feat)]] = 1
                except KeyError:
                    pass
            yield (addr, currec)
