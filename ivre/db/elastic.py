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

"""This sub-module contains functions to interact with the ElasticSearch
databases.

"""

import json
import re
from urllib.parse import unquote

from elasticsearch import Elasticsearch, helpers
from elasticsearch_dsl import Q
from elasticsearch_dsl.query import Query

from ivre import utils
from ivre.active.nmap import ALIASES_TABLE_ELEMS
from ivre.db import DB, DBActive, DBView
from ivre.plugins import load_plugins

PAGESIZE = 250


class ElasticDB(DB):
    nested_fields = []

    # filters
    flt_empty = Q()

    def __init__(self, url):
        super().__init__()
        self.username = ""
        self.password = ""
        self.hosts = None
        self.tls = url.scheme == "elastics"
        if "@" in url.netloc:
            username, hostname = url.netloc.split("@", 1)
            if ":" in username:
                self.username, self.password = (
                    unquote(val) for val in username.split(":", 1)
                )
            else:
                self.username = unquote(username)
            if hostname:
                self.hosts = [f"http{'s' if self.tls else ''}://{hostname}"]
        elif url.netloc:
            self.hosts = [f"http{'s' if self.tls else ''}://{url.netloc}"]
        index_prefix = url.path.lstrip("/")
        if index_prefix:
            self.index_prefix = f"{index_prefix}-"
        else:
            self.index_prefix = "ivre-"
        self.params = dict(
            x.split("=", 1) if "=" in x else (x, None)
            for x in url.query.split("&")
            if x
        )

    def init(self):
        """Initializes the mappings."""
        for idxnum, mapping in enumerate(self.mappings):
            idxname = self.indexes[idxnum]
            self.db_client.indices.delete(
                index=idxname,
                ignore=[400, 404],
            )
            self.db_client.indices.create(
                index=idxname,
                body={
                    "mappings": {
                        "properties": mapping,
                        # Since we do not need full text searches, use
                        # type "keyword" for strings (unless otherwise
                        # specified in mapping) instead of default
                        # (text + keyword)
                        "dynamic_templates": [
                            {
                                "strings": {
                                    "match_mapping_type": "string",
                                    # prevent RequestError exceptions when
                                    # one term's UTF-8 encoding is bigger
                                    # than the max length 32766
                                    "mapping": {
                                        "type": "keyword",
                                        "ignore_above": 32000,
                                    },
                                }
                            },
                        ],
                    }
                },
            )

    @property
    def db_client(self):
        """The DB connection."""
        try:
            return self._db_client
        except AttributeError:
            self._db_client = Elasticsearch(
                hosts=self.hosts, http_auth=(self.username, self.password)
            )
            return self._db_client

    @property
    def server_info(self):
        """Server information."""
        try:
            return self._server_info
        except AttributeError:
            self._server_info = self.db_client.info()
            return self._server_info

    @staticmethod
    def to_binary(data):
        return utils.encode_b64(data).decode()

    @staticmethod
    def from_binary(data):
        return utils.decode_b64(data.encode())

    def flush(self):
        """Force-refresh every Elasticsearch index this backend
        owns so that just-written documents become searchable.

        Elasticsearch buffers writes for the cluster's
        ``refresh_interval`` (default 1s) before they are visible
        to ``_search``. Tests that read-back-after-write rely on
        this synchronous refresh to avoid race conditions; in
        production, the default refresh cadence is fine and the
        method is rarely used outside the test suite.
        """
        for idxname in self.indexes:
            self.db_client.indices.refresh(index=idxname)

    @staticmethod
    def ip2internal(addr):
        return addr

    @staticmethod
    def internal2ip(addr):
        return addr

    @staticmethod
    def searchnonexistent():
        return Q("match", _id=0)

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).
        """
        return Q("match", addr=addr)

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        pass

    @staticmethod
    def searchversion(version):
        """Filter records by their stored ``schema_version``.

        Mirrors :meth:`MongoDB.searchversion`: ``version=None``
        matches records without a ``schema_version`` field,
        ``version=N`` matches records whose ``schema_version``
        equals ``N``.  ``ivre view --init`` always writes the
        current :data:`ivre.xmlnmap.SCHEMA_VERSION` on every
        document, so the ``version=None`` branch only matches
        legacy data ingested by an older release.
        """
        if version is None:
            return ~Q("exists", field="schema_version")
        return Q("match", schema_version=version)

    @staticmethod
    def searchrange(start, stop, neg=False):
        """Filter records by an inclusive IP-address range.

        Mirrors :meth:`MongoDB.searchrange`.  ``addr`` is mapped
        as Elasticsearch's native ``ip`` type, so the comparison
        runs directly on the printable IP string -- no
        ``ip2internal`` int128 split is needed (the Mongo helper
        applies one because it stores addresses as a pair of
        ``addr_0`` / ``addr_1`` 64-bit ints).

        The base-class chain also routes
        :meth:`DB.searchnet` / :meth:`DB.searchipv4` /
        :meth:`DB.searchipv6` through this method, so adding it
        here unlocks every CIDR / IP-family filter on the
        Elastic backend in one step.
        """
        res = Q("range", addr={"gte": start, "lte": stop})
        if neg:
            return ~res
        return res

    @staticmethod
    def _get_pattern(regexp):
        # The equivalent to a MongoDB or PostgreSQL search for regexp
        # /Test/ would be /.*Test.*/ in Elasticsearch, while /Test/ in
        # Elasticsearch is equivalent to /^Test$/ in MongoDB or
        # PostgreSQL.
        #
        # Returns the pattern as a plain string.  Python regex
        # flags have no direct Elasticsearch equivalent at this
        # layer; a warning is issued for any flag other than
        # ``re.UNICODE``.  Callers that build
        # ``Q("regexp", **{field: ...})`` clauses on textual
        # fields and want the ``re.IGNORECASE`` flag honored
        # should use :meth:`_regexp_clause` instead, which
        # routes through Elasticsearch's
        # ``regexp.<field>.case_insensitive`` parameter (ES
        # 7.10+).  This helper stays stable for ``terms.include``
        # aggregation contexts and the certificate-hash
        # call sites that ``.lower()`` the returned string.
        pattern, flags = utils.regexp2pattern(regexp)
        if flags & ~re.UNICODE:
            utils.LOGGER.warning(
                "Elasticsearch does not support flags in regular "
                "expressions [%r with flags=%r]",
                pattern,
                flags,
            )
        return pattern

    @classmethod
    def _regexp_clause(cls, field, value):
        """Build a ``Q("regexp", ...)`` clause that honors
        ``re.IGNORECASE`` on the source regex.

        Elasticsearch's ``regexp`` query accepts a
        ``case_insensitive`` parameter since 7.10; with the
        flag set, the pattern is wrapped in
        ``{"value": pattern, "case_insensitive": True}``.
        Without ``re.IGNORECASE`` the legacy plain-string
        shape is preserved for byte-for-byte compatibility
        with the existing pin tests.

        Used by helpers that translate user-supplied regex
        filters where ``re.IGNORECASE`` is part of the IVRE
        shorthand syntax (``/pattern/i``) and the underlying
        textual content (e.g. ``http-user-agent`` script
        values, host script outputs) needs case-insensitive
        matching to mirror the Mongo backend.
        """
        if isinstance(value, utils.REGEXP_T):
            pattern, flags = utils.regexp2pattern(value)
            unsupported = flags & ~(re.UNICODE | re.IGNORECASE)
            if unsupported:
                utils.LOGGER.warning(
                    "Elasticsearch does not support flags in regular "
                    "expressions [%r with flags=%r]",
                    pattern,
                    flags,
                )
            if flags & re.IGNORECASE:
                return Q(
                    "regexp",
                    **{field: {"value": pattern, "case_insensitive": True}},
                )
            return Q("regexp", **{field: pattern})
        return Q("regexp", **{field: cls._get_pattern(value)})

    @classmethod
    def _search_field(cls, field, value, neg=False):
        """Build the canonical Elasticsearch query for ``field``
        against ``value`` with optional negation. Mirrors the
        ``MongoDB._search_field`` helper on the Mongo side: a
        single dispatch over the four input shapes the IVRE web
        filter language can produce.

        - ``value`` is a regex (``utils.REGEXP_T``) → ``regexp``
          query (the pattern is rewritten via :meth:`_get_pattern`
          to match Elasticsearch's anchored-by-default semantics).
        - ``value`` is a list of length one → ``match`` query on
          the single element (collapses to the scalar shape so
          the wire output stays comparable to the legacy
          ``terms``-with-one-element form would).
        - ``value`` is a list of more elements → ``terms`` query.
        - ``value`` is a scalar → ``match`` query.

        ``neg=True`` wraps the result in ``~`` (a ``bool``
        ``must_not`` clause).
        """
        if isinstance(value, utils.REGEXP_T):
            res = Q("regexp", **{field: cls._get_pattern(value)})
        elif isinstance(value, list):
            if len(value) == 1:
                res = Q("match", **{field: value[0]})
            else:
                res = Q("terms", **{field: value})
        else:
            res = Q("match", **{field: value})
        if neg:
            return ~res
        return res

    @staticmethod
    def _flt_and(cond1, cond2):
        return cond1 & cond2

    @staticmethod
    def _flt_or(cond1, cond2):
        return cond1 | cond2

    @staticmethod
    def flt2str(flt):
        return json.dumps(flt.to_dict())


def _create_mappings(nested, all_mappings):
    res = {}
    for fld in nested:
        cur = res
        curkey = None
        for subkey in fld.split(".")[:-1]:
            if curkey is not None:
                subkey = f"{curkey}.{subkey}"
            if cur.get(subkey, {}).get("type") == "nested":
                cur = cur[subkey].setdefault("properties", {})
                curkey = None
            else:
                curkey = subkey
        subkey = fld.rsplit(".", 1)[-1]
        if curkey is not None:
            subkey = f"{curkey}.{subkey}"
        cur[subkey] = {
            "type": "nested",
            # This is needed to use the nested fields in
            # Kibana:
            "include_in_parent": True,
        }
    for fldtype, fldnames in all_mappings:
        for fld in fldnames:
            cur = res
            curkey = None
            for subkey in fld.split(".")[:-1]:
                if curkey is not None:
                    subkey = f"{curkey}.{subkey}"
                if cur.get(subkey, {}).get("type") == "nested":
                    cur = cur[subkey].setdefault("properties", {})
                    curkey = None
                else:
                    curkey = subkey
            subkey = fld.rsplit(".", 1)[-1]
            if curkey is not None:
                subkey = f"{curkey}.{subkey}"
            cur.setdefault(subkey, {})["type"] = fldtype
    return res


class ElasticDBActive(ElasticDB, DBActive):
    nested_fields = [
        "ports",
        "ports.scripts",
        "ports.scripts.http-app",
        "ports.scripts.http-headers",
        "ports.scripts.ssl-cert",
        "ports.scripts.ssl-ja3-client",
        "ports.scripts.ssl-ja3-server",
        "ports.scripts.ssl-ja4-client",
        # ``traces.hops`` is an array of objects; declaring it
        # nested preserves cross-field correlation inside a
        # single hop record (e.g. a ``searchhop(ip, ttl=N)``
        # query must match a hop where *both* ``ipaddr`` and
        # ``ttl`` come from the same array element, not any
        # combination across elements).  ``include_in_parent``
        # is implicit via :func:`_create_mappings` so flat
        # single-field queries on ``traces.hops.<key>`` keep
        # working unchanged.
        "traces.hops",
        "tags",
    ]
    mappings = [
        _create_mappings(
            nested_fields,
            [
                ("nested", nested_fields),
                ("ip", DBActive.ipaddr_fields),
                ("date", DBActive.datetime_fields),
                ("geo_point", ["infos.coordinates"]),
            ],
        ),
    ]
    index_hosts = 0

    def store_or_merge_host(self, host):
        raise NotImplementedError

    def store_host(self, host):
        if "coordinates" in host.get("infos", {}):
            host["infos"]["coordinates"] = host["infos"]["coordinates"][::-1]
        self.db_client.index(index=self.indexes[0], body=host)

    def count(self, flt):
        return self.db_client.count(
            body={"query": flt.to_dict()},
            index=self.indexes[0],
            ignore_unavailable=True,
        )["count"]

    # Elasticsearch's ``index.max_result_window`` setting
    # (default 10 000) caps ``from + size`` on any non-scroll
    # ``_search`` request -- exceed it and the request fails
    # with ``Result window is too large``.  IVRE's web
    # paginators drive ``get()`` with successive ``skip:N``
    # values (``RESULTS_COUNT = 200`` per page over the HTTP
    # backend, ``WEB_LIMIT`` over the cgi/JSON one), so any
    # ``size`` we pick has to leave room for ``skip`` no
    # matter how deep the pagination goes.
    _MAX_RESULT_WINDOW = 10000

    # ``no_limit`` is the sentinel value that translates to
    # "return every match" for the per-backend ``limit`` /
    # ``size`` argument.  ``MongoDBActive`` uses ``0`` (Mongo
    # cursor convention); the SQL and HTTP backends use
    # ``None``; for Elasticsearch, ``None`` lets :meth:`get` /
    # :meth:`distinct` apply their own scroll- or
    # composite-pagination defaults instead of forcing a
    # specific window.  Consumed by ``web/app.py:452`` (the
    # ``/cgi/.../distinct`` route) and
    # ``ivre/tools/ipinfo.py:377-379``.
    no_limit = None

    def get(self, spec, fields=None, sort=None, limit=None, skip=None, **kargs):
        """Queries the active index.

        ``sort`` / ``limit`` / ``skip`` are honored via the
        ``search`` API (``from`` + ``size`` + ``sort``); when
        none of them are set, the more efficient
        ``helpers.scan`` scroll path streams every match.
        ``sort`` follows IVRE's ``[(field, direction), ...]``
        convention -- ``direction`` is ``1`` for ascending or
        ``-1`` for descending.

        Honoring ``skip`` is what unblocks the
        :func:`tests.tests.IvreTests.find_record_cgi` paginated
        web-API loop, which was previously infinite on the
        Elastic backend: every page returned the same first
        ``WEB_LIMIT`` records because the pagination kwargs
        were silently swallowed by ``**kargs`` and the scroll
        helper has no offset support.

        ``size`` is always capped so ``from + size`` stays
        within :attr:`_MAX_RESULT_WINDOW`; deep pagination
        beyond that ceiling would need ``search_after`` /
        ``scroll``, which the cgi paginators do not currently
        exercise.  When ``limit`` is unspecified we still want
        a sensible default (callers iterate the cursor and
        break at their own consumer-level cap), so the size
        falls back to 1000 -- larger than any in-tree
        per-page consumer needs, and well clear of the
        ``from + size`` cap for typical CI fixtures.
        """
        query = {"query": spec.to_dict()}
        if fields is not None:
            query["_source"] = fields
        # ``sort=[]`` (the default ``flt_params.sortby`` value
        # the cgi handler hands us) is "not None" but means
        # "no sort"; treat it as scan-friendly so the empty
        # sort body does not push us into the search-API
        # branch unnecessarily.
        sort_active = bool(sort)
        use_search = sort_active or limit is not None or skip is not None
        if use_search:
            if sort_active:
                query["sort"] = [
                    {field: ("desc" if direction == -1 else "asc")}
                    for field, direction in sort
                ]
            search_kw = {
                "index": self.indexes[0],
                "ignore_unavailable": True,
                "body": query,
            }
            from_ = skip or 0
            if from_:
                # ``from_`` (trailing underscore) avoids a
                # collision with the Python keyword.
                search_kw["from_"] = from_
            requested = limit if limit is not None else 1000
            cap = self._MAX_RESULT_WINDOW - from_
            if cap <= 0:
                # Past the ``index.max_result_window`` cap; no
                # ``search_after`` cursor here, so yield
                # nothing and let the caller stop paginating.
                return
            search_kw["size"] = min(requested, cap)
            result = self.db_client.search(**search_kw)
            records = result["hits"]["hits"]
        else:
            records = helpers.scan(
                self.db_client,
                query=query,
                index=self.indexes[0],
                ignore_unavailable=True,
            )
        for rec in records:
            host = dict(rec["_source"], _id=rec["_id"])
            if "coordinates" in host.get("infos", {}):
                host["infos"]["coordinates"] = host["infos"]["coordinates"][::-1]
            for field in self.datetime_fields:
                self._set_datetime_field(host, field)
            yield host

    @staticmethod
    def _features_port_list_fields(use_service, use_product, use_version):
        """Return the minimal ``_source`` projection the
        ``features_port_list`` / ``features_port_get`` paths
        need to read.  Pulled out as a tiny helper because both
        :meth:`_features_port_list` and
        :meth:`_features_port_get` need the same set; without
        the projection the inherited ``_features_port_get``
        would scan every host's full ``_source`` (including
        every script output, every cert, every header) on
        every ``features()`` call -- ~10 of which run in the
        view test method, a few of those once per ``subflts``
        entry.  On a fixture of even moderate size this turns
        into many gigabytes of wire traffic and makes the test
        appear to hang.  Restricting to ``addr`` plus the
        few ``ports.*`` columns the feature extractor reads
        keeps each scroll page small and bounds the wall-clock
        cost.
        """
        fields = ["addr", "ports.port"]
        if use_service:
            fields.append("ports.service_name")
            if use_product:
                fields.append("ports.service_product")
                if use_version:
                    fields.append("ports.service_version")
        return fields

    def _features_port_list(self, flt, yieldall, use_service, use_product, use_version):
        """Yield distinct ``(port, service_name?, service_product?,
        service_version?)`` tuples for every matching host's
        ports.  Mirrors :meth:`MongoDBActive._features_port_list`
        which uses a ``$unwind ports`` / ``$group`` aggregation
        pipeline; Elasticsearch has no native equivalent that
        preserves nested-field cross-correlation here, so we
        materialize the distinct set client-side via a Python
        ``set``.

        The base-class ``features_port_list`` wrapper (in
        :class:`DB`) handles ``yieldall`` expansion and
        canonical sorting on top of the raw tuples this
        method yields.
        """
        fields = self._features_port_list_fields(use_service, use_product, use_version)
        seen: set[tuple] = set()
        for rec in self.get(flt, fields=fields):
            for port in rec.get("ports", []):
                if port["port"] == -1:
                    continue
                tup: list = [port["port"]]
                if use_service:
                    tup.append(port.get("service_name"))
                    if use_product:
                        tup.append(port.get("service_product"))
                        if use_version:
                            tup.append(port.get("service_version"))
                seen.add(tuple(tup))
        yield from seen

    def _features_port_get(
        self, features, flt, yieldall, use_service, use_product, use_version
    ):
        """Override :meth:`DBActive._features_port_get` to scope
        the ``_source`` projection to the columns the feature
        extractor actually reads.

        The inherited helper iterates ``self.get(flt)`` with
        no field filter, which on Elasticsearch routes through
        ``helpers.scan`` with ``_source: True`` -- every host
        document is shipped over the wire in full, including
        every script output, every certificate, every HTTP
        header.  The view test method runs ``features()`` ten
        times (some of those once per ``subflts`` entry), so
        the cumulative wire traffic on a fixture of even
        moderate size made the test appear to hang.  Filtering
        to ``addr`` plus the per-port columns the extractor
        actually inspects collapses each scroll page to a
        bounded size.
        """
        fields = self._features_port_list_fields(use_service, use_product, use_version)

        if use_version:

            def _extract(rec):
                for port in rec.get("ports", []):
                    if port["port"] == -1:
                        continue
                    yield (
                        port["port"],
                        port.get("service_name"),
                        port.get("service_product"),
                        port.get("service_version"),
                    )
                    if not yieldall:
                        continue
                    if port.get("service_version") is not None:
                        yield (
                            port["port"],
                            port.get("service_name"),
                            port.get("service_product"),
                            None,
                        )
                    else:
                        continue
                    if port.get("service_product") is not None:
                        yield (port["port"], port.get("service_name"), None, None)
                    else:
                        continue
                    if port.get("service_name") is not None:
                        yield (port["port"], None, None, None)

        elif use_product:

            def _extract(rec):
                for port in rec.get("ports", []):
                    if port["port"] == -1:
                        continue
                    yield (
                        port["port"],
                        port.get("service_name"),
                        port.get("service_product"),
                    )
                    if not yieldall:
                        continue
                    if port.get("service_product") is not None:
                        yield (port["port"], port.get("service_name"), None)
                    else:
                        continue
                    if port.get("service_name") is not None:
                        yield (port["port"], None, None)

        elif use_service:

            def _extract(rec):
                for port in rec.get("ports", []):
                    if port["port"] == -1:
                        continue
                    yield (port["port"], port.get("service_name"))
                    if not yieldall:
                        continue
                    if port.get("service_name") is not None:
                        yield (port["port"], None)

        else:

            def _extract(rec):
                for port in rec.get("ports", []):
                    if port["port"] == -1:
                        continue
                    yield (port["port"],)

        n_features = len(features)
        for rec in self.get(flt, fields=fields):
            currec = [0] * n_features
            for feat in _extract(rec):
                try:
                    currec[features[feat]] = 1
                except KeyError:
                    pass
            yield (rec["addr"], currec)

    def get_ips(self, flt, limit=None, skip=None):
        """Return ``(records, count)`` where ``records`` yields
        only the ``addr`` field of every matching host.  Used by
        the ``/cgi/<view|scans>/onlyips`` web endpoint.

        Mirrors :meth:`MongoDB.get_ips` but skips the int128
        ``addr_0`` / ``addr_1`` reassembly because the Elastic
        backend stores ``addr`` as a native ``ip`` field
        already in printable form.
        """
        return (
            self.get(flt, fields=["addr"], limit=limit, skip=skip),
            self.count(flt),
        )

    def get_ips_ports(self, flt, limit=None, skip=None):
        """Return ``(records, total_port_count)`` where
        ``records`` yields each matching host with its ``addr``
        and the ``port`` / ``state_state`` of every recorded
        port.  Powers the ``/cgi/<view|scans>/ipsports`` web
        endpoint.

        Mirrors :meth:`MongoDB.get_ips_ports`; the ``count``
        component is the total number of ``ports`` entries
        across the result set, not the number of hosts (used
        client-side for pagination of port-count UIs).
        """
        records = list(
            self.get(
                flt,
                fields=["addr", "ports.port", "ports.state_state"],
                limit=limit,
                skip=skip,
            )
        )
        count = sum(len(host.get("ports", [])) for host in records)
        return iter(records), count

    def get_open_port_count(self, flt, limit=None, skip=None):
        """Return ``(records, host_count)`` where ``records``
        yields ``addr`` / ``starttime`` / ``openports.count``
        for every matching host.  Powers the
        ``/cgi/<view|scans>/timeline`` and ``/countopenports``
        endpoints.

        Mirrors :meth:`MongoDB.get_open_port_count`.
        """
        return (
            self.get(
                flt,
                fields=["addr", "starttime", "openports.count"],
                limit=limit,
                skip=skip,
            ),
            self.count(flt),
        )

    def remove(self, host):
        """Removes the host from the active column. `host` must be the record as
        returned by .get().

        """
        self.db_client.delete(
            index=self.indexes[0],
            id=host["_id"],
        )

    def remove_many(self, flt):
        """Removes the host from the active column. `host` must be the record as
        returned by .get().

        """
        self.db_client.delete_by_query(
            index=self.indexes[0],
            body={"query": flt.to_dict()},
        )

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None):
        if flt is None:
            flt = self.flt_empty
        if field == "infos.coordinates" and hasattr(self, "searchhaslocation"):

            def fix_result(value):
                return tuple(float(v) for v in value.split(","))

            # Read ``infos.coordinates`` from ``_source``
            # rather than from the indexed ``geo_point``
            # (``doc[...].value``) -- the geo_point storage
            # round-trips floats through a 32-bit-precision
            # internal representation, so e.g. ``48.86``
            # comes back as ``48.85999997612089``.  Direct
            # ``_source`` access keeps the original JSON
            # values intact, which the ``/cgi/view/coordinates``
            # endpoint (and other consumers comparing against
            # the ``_source``-based ``get()`` path) relies on.
            # ``_source`` is the post-:meth:`store_host` form
            # ``[lng, lat]``; the script swaps back to IVRE's
            # ``[lat, lng]`` convention so the parsed tuple
            # matches Mongo's ``infos.coordinates`` group key.
            base_query = {
                "script": {
                    "lang": "painless",
                    "source": (
                        "def c = params._source.infos.coordinates;"
                        " return c[1] + ',' + c[0];"
                    ),
                }
            }
            flt = self.flt_and(flt, self.searchhaslocation())
        else:
            base_query = {"field": field}
            if field in self.datetime_fields:

                def fix_result(value):
                    return utils.all2datetime(value / 1000.0)

            else:

                def fix_result(value):
                    return value

        # https://techoverflow.net/2019/03/17/how-to-query-distinct-field-values-in-elasticsearch/
        query = {"size": PAGESIZE, "sources": [{field: {"terms": base_query}}]}
        while True:
            result = self.db_client.search(
                body={"query": flt.to_dict(), "aggs": {"values": {"composite": query}}},
                index=self.indexes[0],
                ignore_unavailable=True,
                size=0,
            )
            for value in result["aggregations"]["values"]["buckets"]:
                yield fix_result(value["key"][field])
            if "after_key" not in result["aggregations"]["values"]:
                break
            query["after"] = result["aggregations"]["values"]["after_key"]

    @staticmethod
    def _dn_painless_source(scriptid, subkey):
        """Build a painless ``terms.script.source`` that walks
        every ``ports[*].scripts[*][<scriptid>][*].<subkey>``
        object on the host's ``_source`` and emits one
        ``\\u0001``-separated ``key\\u0001value\\u0001...``
        string per matching DN -- one bucket entry per cert
        observation, not per host.

        Walking ``_source`` directly (no nested aggregation
        wrapper) lets the script enumerate whatever DN
        attributes the certificate actually carries, mirroring
        Mongo's ``$unwind ports.scripts -> $group by subject``
        shape exactly.  No whitelist of attribute names is
        kept: a cert with an OID-named or future-X.509-extension
        attribute reaches the bucket key with the same
        fidelity Mongo's ``$group`` would produce.

        ``\\u0001`` (Start of Heading) is never present in
        X.509 DN values, so the resulting string is
        unambiguously parseable client-side: split on
        ``\\u0001`` and zip the resulting ``[k, v, k, v, ...]``
        array into a Python dict.
        """
        # ``params._source`` access in aggregation contexts
        # has the same per-document overhead :meth:`getlocations`
        # already pays; the cert.subject / cert.issuer paths
        # are infrequent enough (one ``terms`` request per UI
        # interaction) that the trade-off is acceptable in
        # exchange for whitelist-free correctness.
        return (
            "def out = [];"
            " def ports = params._source.ports;"
            " if (ports == null) return out;"
            " for (def port : ports) {"
            " def scripts = port.scripts;"
            " if (scripts == null) continue;"
            " for (def script : scripts) {"
            f" if (script.id != '{scriptid}') continue;"
            f" def certs = script['{scriptid}'];"
            " if (certs == null) continue;"
            " for (def cert : certs) {"
            f" def dn = cert.{subkey};"
            " if (dn == null) continue;"
            " def parts = [];"
            " for (def entry : dn.entrySet()) {"
            " parts.add(entry.getKey());"
            " parts.add(entry.getValue());"
            " }"
            " out.add(String.join('\u0001', parts));"
            " }"
            " }"
            " }"
            " return out;"
        )

    @staticmethod
    def _build_script_nested_agg(scriptid, subfield, baseterms, terms_extra=None):
        """Build a two-level nested aggregation
        (``ports`` -> ``ports.scripts``) with a script-id
        filter and a ``terms`` aggregation on
        ``ports.scripts.<scriptid>.<subfield>``.

        Mirrors the per-script counting semantics
        :meth:`MongoDB.topvalues` produces by
        ``$unwind``-ing ``ports`` then ``ports.scripts``: each
        script subdocument contributes one observation to the
        bucket, so a host that publishes the same NTLM /
        SMB / modbus value on several ports counts once per
        port (not once per host as a flat aggregation would).

        ``terms_extra`` is merged into the inner ``terms``
        clause, used by callers that need ``missing`` /
        ``include`` / ``script`` / ... overrides.
        """
        terms = dict(baseterms, field=f"ports.scripts.{scriptid}.{subfield}")
        if terms_extra is not None:
            terms.update(terms_extra)
        return {
            "nested": {"path": "ports"},
            "aggs": {
                "patterns": {
                    "nested": {"path": "ports.scripts"},
                    "aggs": {
                        "patterns": {
                            "filter": {"match": {"ports.scripts.id": scriptid}},
                            "aggs": {"patterns": {"terms": terms}},
                        },
                    },
                },
            },
        }

    def topvalues(self, field, flt=None, topnbr=10, sort=None, least=False):
        """This method uses an aggregation to produce top values for a given
        field or pseudo-field. Pseudo-fields are:
          - category[:regexp] / asnum / country / net[:mask]
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
          - cert.* / smb.* / sshkey.* / ike.*
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
          - ja3-client[:filter][.type], ja3-server[:filter][:client][.type]
          - ja4-client[:filter][.type], jarm
          - hassh.type, hassh-client.type, hassh-server.type
          - tag.{value,type,info} / tag[:value]

        """
        baseterms = {"size": topnbr}
        if least:
            baseterms["order"] = {"_count": "asc"}
        outputproc = None
        nested = None
        if flt is None:
            flt = self.flt_empty
        if field == "category":
            field = {"field": "categories"}
        elif field.startswith("category:") or field.startswith("categories:"):
            subfield = utils.str2regexp(field.split(":", 1)[1])
            flt = self.flt_and(flt, self.searchcategory(subfield))
            if isinstance(subfield, utils.REGEXP_T):
                subfield = self._get_pattern(subfield)
            else:
                subfield = re.escape(subfield)
            field = {"field": "categories", "include": subfield}
        elif field == "asnum":
            flt = self.flt_and(flt, Q("exists", field="infos.as_num"))
            field = {"field": "infos.as_num"}
        elif field == "country":
            # Mirrors :meth:`MongoDB.topvalues` ``country``
            # branch: tuple of ``(country_code, country_name)``
            # with the country-name fall-back to ``"?"`` when
            # the GeoIP enrichment landed only the code.
            flt = self.flt_and(flt, Q("exists", field="infos.country_code"))

            def outputproc(value):  # noqa: F811
                code, name = value.split(",", 1)
                return (code, name)

            field = {
                "script": {
                    "lang": "painless",
                    "source": (
                        "doc['infos.country_code'].value + ',' + "
                        "(doc['infos.country_name'].size() == 0 "
                        "? '?' : doc['infos.country_name'].value)"
                    ),
                }
            }
        elif field == "city":
            # Mirrors :meth:`MongoDB.topvalues` ``city``
            # branch: tuple of ``(country_code, city)``.
            flt = self.flt_and(
                flt,
                Q("exists", field="infos.country_code"),
                Q("exists", field="infos.city"),
            )

            def outputproc(value):  # noqa: F811
                code, city = value.split(",", 1)
                return (code, city)

            field = {
                "script": {
                    "lang": "painless",
                    "source": (
                        "doc['infos.country_code'].value + ',' + "
                        "doc['infos.city'].value"
                    ),
                }
            }
        elif field == "addr":
            # Mirrors :meth:`MongoDB.topvalues` ``addr``
            # branch: top values of the host address.  The
            # Mongo helper splits the int128 into ``addr_0`` /
            # ``addr_1`` and rebuilds the printable IP via
            # :meth:`internal2ip`; the Elastic schema stores
            # ``addr`` as a native ``ip`` type, so the
            # aggregation runs on the field directly.
            field = {"field": "addr"}
        elif field == "as":

            def outputproc(value):  # noqa: F811
                return tuple(
                    val if i else int(val) for i, val in enumerate(value.split(",", 1))
                )

            flt = self.flt_and(flt, Q("exists", field="infos.as_num"))
            field = {
                "script": {
                    "lang": "painless",
                    "source": "doc['infos.as_num'].value + ',' + "
                    "doc['infos.as_name'].value",
                }
            }
        elif field == "port" or field.startswith("port:"):

            def outputproc(value):
                return tuple(
                    int(val) if i else val for i, val in enumerate(value.rsplit("/", 1))
                )

            if field == "port":
                flt = self.flt_and(
                    flt,
                    Q("nested", path="ports", query=Q("exists", field="ports.port")),
                )
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "filter": {
                                "bool": {
                                    "must_not": [
                                        {"match": {"ports.port": -1}},
                                    ]
                                }
                            },
                            "aggs": {
                                "patterns": {
                                    "terms": dict(
                                        baseterms,
                                        script={
                                            "lang": "painless",
                                            "source": 'doc["ports.protocol"].value + "/" + '
                                            'doc["ports.port"].value',
                                        },
                                    ),
                                }
                            },
                        }
                    },
                }
            else:
                info = field[5:]
                if info in ["open", "filtered", "closed"]:
                    flt = self.flt_and(
                        flt,
                        Q(
                            "nested",
                            path="ports",
                            query=Q("match", ports__state_state=info),
                        ),
                    )
                    matchfield = "state_state"
                else:
                    flt = self.flt_and(
                        flt,
                        Q(
                            "nested",
                            path="ports",
                            query=Q("match", ports__service_name=info),
                        ),
                    )
                    matchfield = "service_name"
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "filter": {
                                "bool": {
                                    "must": [{"match": {f"ports.{matchfield}": info}}],
                                    "must_not": [{"match": {"ports.port": -1}}],
                                }
                            },
                            "aggs": {
                                "patterns": {
                                    "terms": dict(
                                        baseterms,
                                        script={
                                            "lang": "painless",
                                            "source": 'doc["ports.protocol"].value + "/" + '
                                            'doc["ports.port"].value',
                                        },
                                    ),
                                }
                            },
                        }
                    },
                }
        elif field == "service":

            def outputproc(value):
                return value or None

            flt = self.flt_and(flt, self.searchopenport())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"ports.state_state": "open"}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    field="ports.service_name",
                                    missing="",
                                ),
                            }
                        },
                    }
                },
            }
        elif field.startswith("service:"):
            port = int(field[8:])
            flt = self.flt_and(flt, self.searchport(port))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {"match": {"ports.state_state": "open"}},
                                    {"match": {"ports.port": port}},
                                ]
                            }
                        },
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    field="ports.service_name",
                                    missing="",
                                ),
                            }
                        },
                    }
                },
            }
        elif field == "product":

            def outputproc(value):
                return tuple(v or None for v in value.split("###", 1))

            flt = self.flt_and(flt, self.searchopenport())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"ports.state_state": "open"}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    script="""
String result = "";
if(doc['ports.service_name'].size() > 0) {
    result += doc['ports.service_name'].value;
}
result += "###";
if(doc['ports.service_product'].size() > 0) {
    result += doc['ports.service_product'].value;
}
return result;
""",
                                    missing="",
                                ),
                            }
                        },
                    }
                },
            }
        elif field.startswith("product:"):

            def outputproc(value):
                return tuple(v or None for v in value.split("###", 1))

            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                matchfield = "port"
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                matchfield = "service_name"
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {"match": {"ports.state_state": "open"}},
                                    {"match": {f"ports.{matchfield}": info}},
                                ]
                            }
                        },
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    script="""
String result = "";
if(doc['ports.service_name'].size() > 0) {
    result += doc['ports.service_name'].value;
}
result += "###";
if(doc['ports.service_product'].size() > 0) {
    result += doc['ports.service_product'].value;
}
return result;
""",
                                ),
                            }
                        },
                    }
                },
            }
        elif field == "version":

            def outputproc(value):
                return tuple(v or None for v in value.split("###", 2))

            flt = self.flt_and(flt, self.searchopenport())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"ports.state_state": "open"}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    script="""
String result = "";
if(doc['ports.service_name'].size() > 0) {
    result += doc['ports.service_name'].value;
}
result += "###";
if(doc['ports.service_product'].size() > 0) {
    result += doc['ports.service_product'].value;
}
result += "###";
if(doc['ports.service_version'].size() > 0) {
    result += doc['ports.service_version'].value;
}
return result;
""",
                                    missing="",
                                ),
                            }
                        },
                    }
                },
            }
        elif field.startswith("version:"):

            def outputproc(value):
                return tuple(v or None for v in value.split("###", 2))

            info = field[8:]
            if info.isdigit():
                port = int(info)
                flt = self.flt_and(flt, self.searchport(port))
                matchflt = Q("match", ports__port=port)
            elif ":" in info:
                service, product = info.split(":", 1)
                flt = self.flt_and(
                    flt,
                    self.searchproduct(
                        product=product,
                        service=service,
                    ),
                )
                matchflt = Q("match", ports__service_name=service) & Q(
                    "match", ports__service_product=product
                )
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                matchflt = Q("match", ports__service_name=info)
            matchflt &= Q("match", ports__state_state="open")
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": matchflt.to_dict(),
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    script="""
String result = "";
if(doc['ports.service_name'].size() > 0) {
    result += doc['ports.service_name'].value;
}
result += "###";
if(doc['ports.service_product'].size() > 0) {
    result += doc['ports.service_product'].value;
}
result += "###";
if(doc['ports.service_version'].size() > 0) {
    result += doc['ports.service_version'].value;
}
return result;
""",
                                ),
                            }
                        },
                    }
                },
            }
        elif field == "httphdr":

            def outputproc(value):
                return tuple(value.split(":", 1))

            flt = self.flt_and(flt, self.searchhttphdr())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-headers"},
                                "aggs": {
                                    "patterns": {
                                        "terms": dict(
                                            baseterms,
                                            script={
                                                "lang": "painless",
                                                "source": "doc['ports.scripts.http-headers.name']."
                                                "value + ':' + doc['ports.scripts.http-"
                                                "headers.value'].value",
                                            },
                                        )
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field.startswith("httphdr."):
            flt = self.flt_and(flt, self.searchhttphdr())
            field = f"ports.scripts.http-headers.{field[8:]}"
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-headers"},
                                "aggs": {
                                    "patterns": {
                                        "terms": dict(baseterms, field=field),
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field.startswith("httphdr:"):
            subfield = field[8:].lower()
            flt = self.flt_and(flt, self.searchhttphdr(name=subfield))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-headers"},
                                "aggs": {
                                    "patterns": {
                                        "filter": {
                                            "match": {
                                                "ports.scripts.http-headers.name": subfield,
                                            }
                                        },
                                        "aggs": {
                                            "patterns": {
                                                "terms": dict(
                                                    baseterms,
                                                    field="ports.scripts.http-headers.value",
                                                ),
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field == "httpapp":

            def outputproc(value):
                return tuple(value.split(":", 1))

            flt = self.flt_and(flt, self.searchhttpapp())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-app"},
                                "aggs": {
                                    "patterns": {
                                        "terms": dict(
                                            baseterms,
                                            script={
                                                "lang": "painless",
                                                "source": "doc['ports.scripts.http-app.application']"
                                                ".value + ':' + doc['ports.scripts.http-"
                                                "app.version'].value",
                                            },
                                        )
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field.startswith("httpapp:"):
            subfield = field[8:]
            flt = self.flt_and(flt, self.searchhttpapp(name=subfield))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-app"},
                                "aggs": {
                                    "patterns": {
                                        "filter": {
                                            "match": {
                                                "ports.scripts.http-app.application": subfield,
                                            }
                                        },
                                        "aggs": {
                                            "patterns": {
                                                "terms": dict(
                                                    baseterms,
                                                    field="ports.scripts.http-app.version",
                                                ),
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field == "useragent" or field.startswith("useragent:"):
            if field == "useragent":
                flt = self.flt_and(flt, self.searchuseragent())
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "nested": {"path": "ports.scripts"},
                            "aggs": {
                                "patterns": {
                                    "terms": dict(
                                        baseterms,
                                        field="ports.scripts.http-user-agent",
                                    ),
                                }
                            },
                        }
                    },
                }
            else:
                subfield = utils.str2regexp(field[10:])
                flt = self.flt_and(flt, self.searchuseragent(useragent=subfield))
                if isinstance(subfield, utils.REGEXP_T):
                    subfield = self._get_pattern(subfield)
                else:
                    subfield = re.escape(subfield)
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "nested": {"path": "ports.scripts"},
                            "aggs": {
                                "patterns": {
                                    "terms": dict(
                                        baseterms,
                                        field="ports.scripts.http-user-agent",
                                        include=subfield,
                                    ),
                                }
                            },
                        }
                    },
                }
        elif field == "ja3-client" or (
            field.startswith("ja3-client") and field[10] in ":."
        ):
            if ":" in field:
                field, value = field.split(":", 1)
                subkey, value = self._ja3keyvalue(utils.str2regexp(value))
                if isinstance(value, utils.REGEXP_T):
                    include_value = self._get_pattern(value)
                    filter_value = {
                        "regexp": {
                            f"ports.scripts.ssl-ja3-client.{subkey}": include_value,
                        }
                    }
                else:
                    include_value = re.escape(value)
                    filter_value = {
                        "match": {
                            f"ports.scripts.ssl-ja3-client.{subkey}": value,
                        }
                    }
            else:
                value = None
                subkey = None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            base = {
                "terms": dict(
                    baseterms,
                    field=f"ports.scripts.ssl-ja3-client.{subfield}",
                ),
            }
            if subkey is not None:
                if subkey != subfield:
                    base = {
                        # filter_value exists when subkey is not None
                        "filter": filter_value,  # pylint: disable=possibly-used-before-assignment
                        "aggs": {"patterns": base},
                    }
                else:
                    base["terms"]["include"] = include_value
            flt = self.flt_and(flt, self.searchja3client(value_or_hash=value))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.ssl-ja3-client"},
                                "aggs": {"patterns": base},
                            }
                        },
                    }
                },
            }
        elif field == "ja3-server" or (
            field.startswith("ja3-server") and field[10] in ":."
        ):

            def outputproc(value):
                return tuple(value.split("/"))

            if ":" in field:
                field, values = field.split(":", 1)
                if ":" in values:
                    value1, value2 = values.split(":", 1)
                    if value1:
                        subkey1, value1 = self._ja3keyvalue(utils.str2regexp(value1))
                        if isinstance(value1, utils.REGEXP_T):
                            filter_value1 = {
                                "regexp": {
                                    f"ports.scripts.ssl-ja3-server.{subkey1}": self._get_pattern(
                                        value1
                                    ),
                                }
                            }
                        else:
                            filter_value1 = {
                                "match": {
                                    f"ports.scripts.ssl-ja3-server.{subkey1}": value1,
                                }
                            }
                    else:
                        subkey1, value1 = None, None
                    if value2:
                        subkey2, value2 = self._ja3keyvalue(utils.str2regexp(value2))
                        if isinstance(value2, utils.REGEXP_T):
                            filter_value2 = {
                                "regexp": {
                                    f"ports.scripts.ssl-ja3-server.client.{subkey2}": self._get_pattern(
                                        value2
                                    ),
                                }
                            }
                        else:
                            filter_value2 = {
                                "match": {
                                    f"ports.scripts.ssl-ja3-server.client.{subkey2}": value2,
                                }
                            }
                    else:
                        subkey2, value2 = None, None
                else:
                    subkey1, value1 = self._ja3keyvalue(utils.str2regexp(values))
                    if isinstance(value1, utils.REGEXP_T):
                        filter_value1 = {
                            "regexp": {
                                f"ports.scripts.ssl-ja3-server.{subkey1}": self._get_pattern(
                                    value1
                                ),
                            }
                        }
                    else:
                        filter_value1 = {
                            "match": {
                                f"ports.scripts.ssl-ja3-server.{subkey1}": value1,
                            }
                        }
                    subkey2, value2 = None, None
            else:
                subkey1, value1 = None, None
                subkey2, value2 = None, None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            flt = self.flt_and(
                flt,
                self.searchja3server(
                    value_or_hash=value1,
                    client_value_or_hash=value2,
                ),
            )
            base = {
                "terms": dict(
                    baseterms,
                    script={
                        "lang": "painless",
                        "source": f"doc['ports.scripts.ssl-ja3-server.{subfield}'].value + '/' + doc['ports.scripts.ssl-ja3-server.client.{subfield}'].value",
                    },
                ),
            }
            if value1 is not None:
                base = {
                    # filter_value1 exists when value1 is not None
                    "filter": filter_value1,  # pylint: disable=used-before-assignment
                    "aggs": {"patterns": base},
                }
            if value2 is not None:
                base = {
                    # filter_value2 exists when value2 is not None
                    "filter": filter_value2,  # pylint: disable=used-before-assignment
                    "aggs": {"patterns": base},
                }
            flt = self.flt_and(
                flt,
                self.searchja3server(
                    value_or_hash=value1,
                    client_value_or_hash=value2,
                ),
            )
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.ssl-ja3-server"},
                                "aggs": {"patterns": base},
                            }
                        },
                    }
                },
            }
        elif field == "ja4-client" or (
            field.startswith("ja4-client") and field[10] in ":."
        ):
            if ":" in field:
                field, value = field.split(":", 1)
                if isinstance(value, utils.REGEXP_T):
                    include_value = self._get_pattern(value)
                else:
                    include_value = re.escape(value)
            else:
                value = None
                include_value = None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "ja4"
            base = {
                "terms": dict(
                    baseterms,
                    field=f"ports.scripts.ssl-ja4-client.{subfield}",
                ),
            }
            if include_value is not None:
                base["terms"]["include"] = include_value
            flt = self.flt_and(flt, self.searchja4client(value=value))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.ssl-ja4-client"},
                                "aggs": {"patterns": base},
                            }
                        },
                    }
                },
            }
        elif field == "hassh" or (field.startswith("hassh") and field[5] in "-."):
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            aggs = {
                "patterns": {
                    "nested": {"path": "ports.scripts"},
                    "aggs": {
                        "patterns": {
                            "terms": dict(
                                baseterms,
                                field=f"ports.scripts.ssh2-enum-algos.hassh.{subfield}",
                            )
                        }
                    },
                }
            }
            if field == "hassh-server":
                flt = self.flt_and(flt, self.searchhassh(server=True))
                aggs = {
                    "patterns": {
                        "filter": {
                            "bool": {"must_not": [{"match": {"ports.port": -1}}]}
                        },
                        "aggs": aggs,
                    }
                }
            elif field == "hassh-client":
                flt = self.flt_and(flt, self.searchhassh(server=False))
                aggs = {
                    "patterns": {
                        "filter": {"match": {"ports.port": -1}},
                        "aggs": aggs,
                    }
                }
            elif field == "hassh":
                flt = self.flt_and(flt, self.searchhassh())
            else:
                raise ValueError(f"Unknown field {field}")
            nested = {"nested": {"path": "ports"}, "aggs": aggs}
        elif field.startswith("s7."):
            flt = self.flt_and(flt, self.searchscript(name="s7-info"))
            subfield = field[3:]
            field = {"field": f"ports.scripts.s7-info.{subfield}"}
        elif field.startswith("ntlm."):
            # Mirrors :meth:`MongoDB.topvalues` ``ntlm.<key>``
            # branch.  The same friendly-name alias map the
            # Mongo helper exposes (``os`` -> ``Product_Version``,
            # ``domain`` -> ``NetBIOS_Domain_Name``, ...) is
            # applied here so callers get identical results
            # across backends.
            #
            # The aggregation runs inside a two-level nested
            # context (``ports`` -> ``ports.scripts``) with a
            # script-id filter so the per-key counts mirror
            # Mongo's ``$unwind ports`` / ``$unwind ports.scripts``
            # / ``$match {scripts.id: "ntlm-info"}`` pipeline.
            # A flat aggregation would dedupe per parent
            # document and undercount hosts that publish the
            # same NTLM value on several ports.
            flt = self.flt_and(flt, self.searchntlm())
            subfield = field[5:]
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
            nested = self._build_script_nested_agg("ntlm-info", subfield, baseterms)
        elif field.startswith("smb."):
            # Mirrors :meth:`MongoDB.topvalues` ``smb.<key>``
            # branch: per-port aggregation on
            # ``ports.scripts.smb-os-discovery.<key>`` with the
            # same nested wrapping as the ``ntlm.<key>`` arm.
            flt = self.flt_and(flt, self.searchsmb())
            subfield = field[4:]
            nested = self._build_script_nested_agg(
                "smb-os-discovery", subfield, baseterms
            )
        elif field.startswith("modbus."):
            # Mirrors :meth:`MongoDB.topvalues` ``modbus.<key>``
            # branch.  Per-port aggregation on
            # ``ports.scripts.modbus-discover.<key>``;
            # ``view_top_modbus_deviceids`` exercises the
            # ``modbus.deviceid`` shape end-to-end.
            flt = self.flt_and(flt, self.searchscript(name="modbus-discover"))
            subfield = field[7:]
            nested = self._build_script_nested_agg(
                "modbus-discover", subfield, baseterms
            )
        elif field == "devicetype":
            # Mirrors :meth:`MongoDB.topvalues` ``devicetype``
            # branch: per-port top values of
            # ``ports.service_devicetype``.  Wrapped in a
            # ``nested(ports)`` aggregation so each port
            # contributes its own count -- a host with three
            # ports announcing the same ``service_devicetype``
            # contributes three to the bucket, matching Mongo's
            # ``$unwind ports`` count semantics.
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "terms": dict(baseterms, field="ports.service_devicetype"),
                    },
                },
            }
        elif field.startswith("devicetype:"):
            # ``devicetype:<port>`` -- same per-port aggregation
            # as the bare form but restricted to a specific
            # port number.  The host-level :meth:`searchport`
            # filter keeps the candidate document set small;
            # the inner ``filter`` clause then narrows the
            # nested aggregation to the matching port subdoc
            # so other ports on the same host do not leak
            # into the bucket count.
            port = int(field.split(":", 1)[1])
            flt = self.flt_and(flt, self.searchport(port))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"ports.port": port}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    field="ports.service_devicetype",
                                ),
                            },
                        },
                    },
                },
            }
        elif field == "cpe" or (field.startswith("cpe") and field[3] in ":."):
            # Mirrors :meth:`MongoDB.topvalues` ``cpe`` /
            # ``cpe.<part>`` / ``cpe:<spec>`` /
            # ``cpe.<part>:<spec>`` family.  Mongo concats
            # the kept fields with ``:`` separators inside a
            # ``$concat`` pipeline stage and the outputproc
            # splits back into a tuple; Elastic uses a
            # painless script for the same shape.  ``cpes`` is
            # not declared in :attr:`nested_fields`, so the
            # script reads the document fields directly.
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
            flt = self.flt_and(
                flt,
                self.searchcpe(
                    **{("cpe_type" if k == "type" else k): v for k, v in cpe_filters}
                ),
            )
            keep_count = max(cpe_keys.index(cpe_field) + 1, len(cpe_filters))
            kept_keys = cpe_keys[:keep_count]
            if len(kept_keys) == 1:
                field = {"field": f"cpes.{kept_keys[0]}"}
            else:

                def outputproc(value):  # noqa: F811
                    return tuple(value.split(":", len(kept_keys) - 1))

                # Painless concats the kept keys with ``:``
                # separators so the outputproc can split the
                # tuple back.  ``doc[...].size() == 0`` guards
                # against entries that lack a key (else ES
                # raises at script-runtime).
                source_parts = []
                for i, key in enumerate(kept_keys):
                    if i:
                        source_parts.append("':'")
                    source_parts.append(
                        f"(doc['cpes.{key}'].size() == 0 ? '' : "
                        f"doc['cpes.{key}'].value)"
                    )
                field = {
                    "script": {
                        "lang": "painless",
                        "source": " + ".join(source_parts),
                    }
                }
        elif field == "hop":
            # Mirrors :meth:`MongoDB.topvalues` ``hop``
            # branch: per-hop top values of
            # ``traces.hops.ipaddr`` (a native ``ip`` field on
            # the Elastic schema, no int128 split needed).
            # Wrapped in ``nested(traces.hops)`` so each
            # individual hop contributes one observation to
            # the bucket -- mirrors Mongo's ``$unwind traces`` /
            # ``$unwind traces.hops`` count semantics.  A flat
            # aggregation (the previous behaviour) deduped per
            # parent doc and produced host-wide counts instead
            # of per-hop counts.
            nested = {
                "nested": {"path": "traces.hops"},
                "aggs": {
                    "patterns": {
                        "terms": dict(baseterms, field="traces.hops.ipaddr"),
                    },
                },
            }
        elif field.startswith("hop") and field[3] in ":>":
            # ``hop:<ttl>`` -- equality on the TTL,
            # ``hop>N`` -- TTL strictly greater than ``N``.
            # The inner ``filter`` clause runs *inside* the
            # ``nested`` context, so cross-field correlation is
            # preserved: only hops where ``ttl`` matches the
            # predicate contribute their ``ipaddr`` to the
            # bucket.  A flat ``range`` / ``match`` on
            # ``traces.hops.ttl`` at the host-query level would
            # select hosts that have *some* hop at the right
            # TTL and then aggregate every hop's ``ipaddr`` --
            # the cross-field-correlation bug that produced the
            # ``view_top_hop_10+`` test failure.
            ttl = int(field[4:])
            if field[3] == ">":
                ttl_filter = {"range": {"traces.hops.ttl": {"gt": ttl}}}
            else:
                ttl_filter = {"match": {"traces.hops.ttl": ttl}}
            nested = {
                "nested": {"path": "traces.hops"},
                "aggs": {
                    "patterns": {
                        "filter": ttl_filter,
                        "aggs": {
                            "patterns": {
                                "terms": dict(baseterms, field="traces.hops.ipaddr"),
                            },
                        },
                    },
                },
            }
        elif field == "file" or (field.startswith("file") and field[4] in ".:"):
            # Mirrors :meth:`MongoDB.topvalues` ``file`` /
            # ``file.<key>`` / ``file:<scripts>`` /
            # ``file:<scripts>.<key>`` branches.  ``<scripts>``
            # is a comma-separated list of NSE-script ids the
            # file ingestion can come from (``nfs-ls`` /
            # ``smb-ls`` / ...); ``<key>`` defaults to
            # ``filename``.
            #
            # Two-level nested wrapper so each shared file
            # contributes one observation to the bucket; a
            # flat aggregation would dedupe per parent doc
            # and undercount hosts publishing the same file
            # on several ports.  The script-id constraint is
            # enforced by the host-level :meth:`searchfile`
            # filter.
            scripts: list[str] | None = None
            if field.startswith("file:"):
                scripts_part = field[5:]
                if "." in scripts_part:
                    scripts_part, subfield = scripts_part.split(".", 1)
                else:
                    subfield = "filename"
                scripts = scripts_part.split(",")
            else:
                subfield = field[5:] or "filename"
            flt = self.flt_and(flt, self.searchfile(scripts=scripts))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    field=(
                                        "ports.scripts.ls.volumes.files." f"{subfield}"
                                    ),
                                ),
                            },
                        },
                    },
                },
            }
        elif field == "vulns.id":
            # Mirrors :meth:`MongoDB.topvalues` ``vulns.id``
            # branch: per-script aggregation on
            # ``ports.scripts.vulns.id``.  Two-level nested
            # wrapper for per-script counting; the inner
            # ``exists`` filter restricts the bucket to
            # script subdocuments that actually carry a
            # ``vulns.id`` (else painless / terms would
            # iterate every script subdoc, including those
            # that have nothing to do with vulnerabilities,
            # and emit zero-key buckets that pollute the
            # count).
            flt = self.flt_and(flt, self.searchvuln())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "filter": {
                                    "exists": {"field": "ports.scripts.vulns.id"}
                                },
                                "aggs": {
                                    "patterns": {
                                        "terms": dict(
                                            baseterms,
                                            field="ports.scripts.vulns.id",
                                        ),
                                    },
                                },
                            },
                        },
                    },
                },
            }
        elif field.startswith("vulns."):
            # Mirrors :meth:`MongoDB.topvalues` ``vulns.<other>``
            # branch: tuple of ``(id, <other>)`` so the caller
            # can correlate the field back to the specific
            # vulnerability.  Painless concats the two with
            # ``:`` separator, outputproc splits back.  The
            # inner ``exists`` filter -- same as ``vulns.id``
            # -- prevents the painless from running on
            # script subdocuments that are not
            # vulnerability scans.
            subfield = field[6:]
            flt = self.flt_and(flt, self.searchvuln())

            def outputproc(value):  # noqa: F811
                return tuple(value.split(":", 1))

            terms_clause = dict(
                baseterms,
                script={
                    "lang": "painless",
                    "source": (
                        "(doc['ports.scripts.vulns.id'].size() == 0 ? '' "
                        ": doc['ports.scripts.vulns.id'].value) + ':' + "
                        f"(doc['ports.scripts.vulns.{subfield}'].size() "
                        f"== 0 ? '' : doc['ports.scripts.vulns.{subfield}']"
                        ".value)"
                    ),
                },
            )
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "filter": {
                                    "exists": {"field": "ports.scripts.vulns.id"}
                                },
                                "aggs": {
                                    "patterns": {"terms": terms_clause},
                                },
                            },
                        },
                    },
                },
            }
        elif field == "screenwords":
            # Mirrors :meth:`MongoDB.topvalues` ``screenwords``
            # branch: per-port top values of the OCR-derived
            # word list stored on ``ports.screenwords``.
            # ``ports`` is nested so a host advertising the
            # same word on several ports contributes one
            # observation per port (mirrors Mongo's
            # ``$unwind ports`` / ``$unwind ports.screenwords``
            # pipeline).
            flt = self.flt_and(flt, self.searchscreenshot(words=True))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "terms": dict(baseterms, field="ports.screenwords"),
                    },
                },
            }
        elif field == "sshkey.bits":
            # Mirrors :meth:`MongoDB.topvalues` ``sshkey.bits``
            # branch: tuple of ``(type, bits)`` from
            # ``ssh-hostkey``.  The Mongo helper concats the
            # two via a ``$project`` stage; painless emits the
            # same shape here.  Two-level nested wrapper so
            # each ``ssh-hostkey`` script subdocument
            # contributes one ``(type, bits)`` observation.
            flt = self.flt_and(flt, self.searchsshkey())

            def outputproc(value):  # noqa: F811
                return tuple(value.split(":", 1))

            terms_clause = dict(
                baseterms,
                script={
                    "lang": "painless",
                    "source": (
                        "(doc['ports.scripts.ssh-hostkey.type'].size() == "
                        "0 ? '' : doc['ports.scripts.ssh-hostkey.type']"
                        ".value) + ':' + "
                        "(doc['ports.scripts.ssh-hostkey.bits'].size() == "
                        "0 ? '' : doc['ports.scripts.ssh-hostkey.bits']"
                        ".value)"
                    ),
                },
            )
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "filter": {
                                    "match": {"ports.scripts.id": "ssh-hostkey"}
                                },
                                "aggs": {"patterns": {"terms": terms_clause}},
                            },
                        },
                    },
                },
            }
        elif field.startswith("sshkey."):
            # Mirrors :meth:`MongoDB.topvalues` ``sshkey.<other>``
            # branch: scalar value of a single key on each
            # ``ssh-hostkey`` script subdocument.
            subfield = field[7:]
            flt = self.flt_and(flt, self.searchsshkey())
            nested = self._build_script_nested_agg("ssh-hostkey", subfield, baseterms)
        elif field.startswith("scanner.port:"):
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = {"field": f"ports.scripts.scanner.ports.{field[13:]}.ports"}
        elif field == "scanner.name":
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = {"field": "ports.scripts.scanner.scanners.name"}
        elif field == "jarm":
            flt = self.flt_and(flt, self.searchjarm())
            field = {"field": "ports.scripts.ssl-jarm"}
        elif field.startswith("jarm:"):
            port = int(field[5:])
            flt = self.flt_and(flt, self.searchjarm(), self.searchport(port))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {"match": {"ports.protocol": "tcp"}},
                                    {"match": {"ports.port": port}},
                                ]
                            }
                        },
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts"},
                                "aggs": {
                                    "patterns": {
                                        "filter": {
                                            "match": {"ports.scripts.id": "ssl-jarm"}
                                        },
                                        "aggs": {
                                            "patterns": {
                                                "terms": dict(
                                                    baseterms,
                                                    field="ports.scripts.ssl-jarm",
                                                )
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field == "tag" and hasattr(self, "searchtag"):
            flt = self.flt_and(flt, self.searchtag())

            def outputproc(value):
                return tuple(value.split(":", 1))

            nested = {
                "nested": {"path": "tags"},
                "aggs": {
                    "patterns": {
                        "terms": dict(
                            baseterms,
                            script={
                                "lang": "painless",
                                "source": "doc['tags.value'].value + ':' + doc['tags.info'].value",
                            },
                        )
                    }
                },
            }
        elif field.startswith("tag.") and hasattr(self, "searchtag"):
            flt = self.flt_and(flt, self.searchtag())
            field = {"field": f"tags.{field[4:]}"}
        elif field.startswith("tag:") and hasattr(self, "searchtag"):
            subfield = field[4:]
            flt = self.flt_and(flt, self.searchtag(tag={"value": subfield}))
            nested = {
                "nested": {"path": "tags"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"tags.value": subfield}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(baseterms, field="tags.info", missing="")
                            }
                        },
                    },
                },
            }
        elif field == "script":
            # Mirrors :meth:`MongoDB.topvalues` ``script``
            # branch: top script ids across all hosts.  The
            # nested ``ports`` -> ``ports.scripts`` aggregation
            # ensures each script id is counted exactly once
            # per script subdoc rather than per host.
            flt = self.flt_and(flt, self.searchscript())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "terms": dict(baseterms, field="ports.scripts.id"),
                            }
                        },
                    }
                },
            }
        elif field.startswith("script:"):
            # Mirrors :meth:`MongoDB.topvalues` ``script:<id>``
            # branch: top values of ``ports.scripts.output``
            # for a specific script id.  ``script:<port>:<id>``
            # also constrains the matching port number.
            scriptid = field.split(":", 1)[1]
            port = None
            if ":" in scriptid:
                port_part, scriptid = scriptid.split(":", 1)
                if port_part.isdigit():
                    port = int(port_part)
            flt = self.flt_and(flt, self.searchscript(name=scriptid))
            if port is not None:
                flt = self.flt_and(flt, self.searchport(port))
            inner_filter = Q("match", **{"ports.scripts.id": scriptid}).to_dict()
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "filter": inner_filter,
                                "aggs": {
                                    "patterns": {
                                        "terms": dict(
                                            baseterms,
                                            field="ports.scripts.output",
                                        )
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field == "domains":
            # Mirrors :meth:`MongoDB.topvalues` ``domains``
            # branch: top values of the indexed
            # ``hostnames.domains`` field (every suffix of
            # every hostname).  ``searchhostname()`` (no
            # args) is the existence-check shape Mongo's
            # ``searchdomain({"$exists": True})`` produces.
            flt = self.flt_and(flt, self.searchhostname())
            field = {"field": "hostnames.domains"}
        elif field.startswith("domains:"):
            # Mirrors :meth:`MongoDB.topvalues` ``domains:<spec>``
            # branch.  ``<spec>`` is one of:
            #   - integer ``N`` -> match domains with exactly
            #     ``N`` levels (regex ``^([^.]+\\.){N-1}[^.]+$``);
            #   - ``<subdomain>`` -> match domains ending with
            #     ``.<subdomain>`` (regex
            #     ``\\.<re.escape(subdomain)>$``);
            #   - ``<subdomain>:<level>`` -> the level form
            #     scoped to the subdomain.
            # Mongo passes the regex into ``aggrflt`` which
            # filters the aggregation; the Elastic equivalent
            # is a ``regexp`` filter on the term aggregation
            # via ``include``.
            subfield = field[8:]
            flt = self.flt_and(flt, self.searchhostname())
            if subfield.isdigit():
                include_pattern = "([^.]+\\.){%d}[^.]+" % (int(subfield) - 1)
            elif ":" in subfield:
                sub, level = subfield.split(":", 1)
                flt = self.flt_and(flt, self.searchdomain(sub))
                include_pattern = "([^.]+\\.){%d}%s" % (
                    int(level) - sub.count(".") - 1,
                    re.escape(sub),
                )
            else:
                flt = self.flt_and(flt, self.searchdomain(subfield))
                include_pattern = ".*\\." + re.escape(subfield)
            field = {
                "field": "hostnames.domains",
                "include": include_pattern,
            }
        elif field.startswith("cert.") or field.startswith("cacert."):
            # Mirrors :meth:`MongoDB.topvalues` ``cert.<key>``
            # / ``cacert.<key>`` branches.
            #
            # Two shapes share this branch:
            #
            # * Scalar leaves (``md5``, ``sha1``, ``sha256``,
            #   ``pubkey.<hash>``, ``self_signed``, ...) use
            #   the standard ``nested(ports) ->
            #   nested(ports.scripts) -> filter(scripts.id =
            #   <scriptid>) -> terms(field=...)`` chain so the
            #   per-cert count matches Mongo's ``$unwind``
            #   semantics.
            #
            # * Object leaves -- ``subject`` and ``issuer`` --
            #   cannot use ``terms.field`` because Elastic's
            #   ``terms`` aggregation refuses object-shaped
            #   fields.  Instead, a painless script walks the
            #   host's ``_source`` directly, finds every
            #   ``ports[*].scripts[*][<scriptid>][*]`` entry,
            #   reads the ``subject`` / ``issuer`` dict and
            #   emits one ``\u0001``-separated bucket key per
            #   cert observation (the script returns an
            #   array, so each emission lands in its own
            #   bucket -- equivalent to Mongo's
            #   ``$unwind ports -> $unwind ports.scripts ->
            #   $group``).  Because the script handles the
            #   unwinding itself, no surrounding ``nested``
            #   wrapper is needed.  The client-side
            #   :func:`outputproc` splits on ``\u0001`` and
            #   zips the result into a dict matching Mongo's
            #   ``$group`` shape.
            cacert = field.startswith("cacert.")
            subkey = field[7:] if cacert else field[5:]
            scriptid = "ssl-cacert" if cacert else "ssl-cert"
            flt = self.flt_and(flt, self.searchcert(cacert=cacert))
            if subkey in ("subject", "issuer"):

                def outputproc(value):  # noqa: F811
                    if not value:
                        return {}
                    parts = value.split("\u0001")
                    return dict(zip(parts[0::2], parts[1::2]))

                field = {
                    "script": {
                        "lang": "painless",
                        "source": self._dn_painless_source(scriptid, subkey),
                    }
                }
            else:
                inner_filter = Q("match", **{"ports.scripts.id": scriptid}).to_dict()
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "nested": {"path": "ports.scripts"},
                            "aggs": {
                                "patterns": {
                                    "filter": inner_filter,
                                    "aggs": {
                                        "patterns": {
                                            "terms": dict(
                                                baseterms,
                                                field=(
                                                    "ports.scripts."
                                                    f"{scriptid}.{subkey}"
                                                ),
                                            )
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
        else:
            field = {"field": field}
        body = {"query": flt.to_dict()}
        if nested is None:
            body["aggs"] = {"patterns": {"terms": dict(baseterms, **field)}}
        else:
            body["aggs"] = {"patterns": nested}
        utils.LOGGER.debug("DB: Elasticsearch aggregation: %r", body)
        result = self.db_client.search(
            body=body, index=self.indexes[0], ignore_unavailable=True, size=0
        )
        result = result["aggregations"]
        while "patterns" in result:
            result = result["patterns"]
        result = result["buckets"]
        if outputproc is None:
            for res in result:
                yield {"_id": res["key"], "count": res["doc_count"]}
        else:
            for res in result:
                yield {"_id": outputproc(res["key"]), "count": res["doc_count"]}

    @staticmethod
    def searchhaslocation(neg=False):
        res = Q("exists", field="infos.coordinates")
        if neg:
            return ~res
        return res

    @classmethod
    def searchcategory(cls, cat, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular category
        (records may have zero, one or more categories).
        """
        return cls._search_field("categories", cat, neg=neg)

    @classmethod
    def searchsource(cls, src, neg=False):
        """Filter records by ``source`` (a free-form tag the
        scanner / ingestion pipeline assigns to each scan run).

        Mirrors :meth:`MongoDB.searchsource`: a ``match`` query
        against the ``source`` field, with the regex / list /
        scalar dispatch :meth:`_search_field` already provides.
        On the view backend ``source`` lands as an array of
        strings (one per merged scan); Elasticsearch's
        ``match`` against an array field returns a hit if any
        element matches, so the same predicate works for both
        Nmap and View shapes without a custom branch.
        """
        return cls._search_field("source", src, neg=neg)

    @classmethod
    def searchdomain(cls, name, neg=False):
        """Filter records by hostname domain (matches the
        domain at any level: ``foo.example.com`` matches
        ``example.com`` and ``com``).

        Mirrors :meth:`MongoDB.searchdomain`: a ``match`` query
        against the indexed ``hostnames.domains`` field (which
        ingestion populates with every suffix of every
        hostname).
        """
        return cls._search_field("hostnames.domains", name, neg=neg)

    @classmethod
    def searchhostname(cls, name=None, neg=False):
        """Filter records by hostname.

        With ``name=None`` the filter only checks for the
        existence (or absence, on ``neg=True``) of any hostname
        on the record.  With a ``name`` argument the predicate
        ANDs an indexed ``hostnames.domains`` lookup with the
        non-indexed ``hostnames.name`` match (so the hot path
        still goes through the index even though the exact
        ``hostnames.name`` field is not indexed).

        Mirrors :meth:`MongoDB.searchhostname`.
        """
        if name is None:
            # ``hostnames.domains`` is the indexed field; gate
            # on its existence rather than ``hostnames.name``
            # so a query without a specific hostname still
            # benefits from the index.
            res = Q("exists", field="hostnames.domains")
            if neg:
                return ~res
            return res
        if neg:
            return cls._search_field("hostnames.name", name, neg=True)
        # Positive match: combine the indexed domain lookup
        # (so the query goes through the index) with the
        # ``hostnames.name`` match.
        return cls.searchdomain(name) & cls._search_field("hostnames.name", name)

    # -- traces.hops -- mirroring :meth:`MongoDB.searchhop` /
    # ``searchhopname`` / ``searchhopdomain``.  ``traces.hops``
    # is declared in :attr:`nested_fields`, so every multi-field
    # predicate is wrapped in
    # ``Q("nested", path="traces.hops", query=...)`` to preserve
    # cross-field correlation inside a single hop array element
    # -- a ``searchhop(ip, ttl=N)`` query must match a single
    # array element where both ``ipaddr`` *and* ``ttl`` agree,
    # not different elements satisfying each predicate
    # separately.  Single-field helpers stay nested too for
    # consistency and so the ``neg=True`` shape produces the
    # ``$ne``-equivalent ("no hop matches") rather than the
    # flat-array ``"at least one hop does not match"`` form.
    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        """Filter records that have a traceroute hop with the
        supplied address (and optional TTL).

        Mirrors :meth:`MongoDB.searchhop`; ``traces.hops.ipaddr``
        is mapped as Elasticsearch's native ``ip`` type, so the
        match takes a printable IP string directly without the
        ``ip2internal`` split the Mongo helper applies.
        """
        inner = Q("match", **{"traces.hops.ipaddr": hop})
        if ttl is not None:
            inner &= Q("match", **{"traces.hops.ttl": ttl})
        res = Q("nested", path="traces.hops", query=inner)
        if neg:
            return ~res
        return res

    @classmethod
    def searchhopdomain(cls, hop, neg=False):
        """Filter records by traceroute-hop domain.

        Mirrors :meth:`MongoDB.searchhopdomain`: a ``match``
        against the indexed ``traces.hops.domains`` field,
        wrapped in a ``nested(traces.hops)`` query so negation
        means "no hop matches" rather than "at least one hop
        differs" (the flat-array semantics).
        """
        if isinstance(hop, utils.REGEXP_T):
            inner = Q("regexp", **{"traces.hops.domains": cls._get_pattern(hop)})
        elif isinstance(hop, list):
            if len(hop) == 1:
                inner = Q("match", **{"traces.hops.domains": hop[0]})
            else:
                inner = Q("terms", **{"traces.hops.domains": hop})
        else:
            inner = Q("match", **{"traces.hops.domains": hop})
        res = Q("nested", path="traces.hops", query=inner)
        if neg:
            return ~res
        return res

    @classmethod
    def searchhopname(cls, hop, neg=False):
        """Filter records by traceroute-hop hostname.

        Mirrors :meth:`MongoDB.searchhopname`: positive matches
        AND the indexed ``traces.hops.domains`` lookup with the
        non-indexed ``traces.hops.host`` match -- both clauses
        must be satisfied by the *same* hop array element, which
        the ``nested(traces.hops)`` wrapper guarantees.
        Negative matches only exclude ``traces.hops.host`` so
        the indexed-domain filter does not silently drop
        legitimate non-matches.
        """
        if neg:
            return ~Q(
                "nested",
                path="traces.hops",
                query=Q("match", **{"traces.hops.host": hop}),
            )
        inner = Q("match", **{"traces.hops.domains": hop}) & Q(
            "match", **{"traces.hops.host": hop}
        )
        return Q("nested", path="traces.hops", query=inner)

    # -- per-port "fingerprint" filters --------------------
    @staticmethod
    def searchldapanon():
        """Filter records exposing an LDAP service that allows
        anonymous binds.

        Mirrors :meth:`MongoDB.searchldapanon`: a single
        ``match`` against ``ports.service_extrainfo`` -- the
        nmap LDAP probe records ``"Anonymous bind OK"`` in
        the service extra-info string when the bind succeeds
        without credentials.
        """
        return Q("match", ports__service_extrainfo="Anonymous bind OK")

    @staticmethod
    def searchvsftpdbackdoor():
        """Filter records exposing the vsftpd 2.3.4 backdoor
        (CVE-2011-2523).

        Mirrors :meth:`MongoDB.searchvsftpdbackdoor`: a nested
        match on the canonical product / version / state
        fingerprint Metasploit's ``ftp/vsftpd_234_backdoor``
        module checks.
        """
        return Q(
            "nested",
            path="ports",
            query=(
                Q("match", ports__protocol="tcp")
                & Q("match", ports__state_state="open")
                & Q("match", ports__service_product="vsftpd")
                & Q("match", ports__service_version="2.3.4")
            ),
        )

    @staticmethod
    def searchwebmin():
        """Filter records exposing a Webmin admin interface.

        Mirrors :meth:`MongoDB.searchwebmin`: nmap's HTTP
        service probe identifies Webmin via
        ``service_product == "MiniServ"`` while leaving
        ``service_extrainfo`` set to something *other* than
        ``"Webmin httpd"`` (which is the regular Apache /
        nginx hosting the admin UI).
        """
        return Q(
            "nested",
            path="ports",
            query=(
                Q("match", ports__service_name="http")
                & Q("match", ports__service_product="MiniServ")
                & ~Q("match", ports__service_extrainfo="Webmin httpd")
            ),
        )

    @classmethod
    def searchhttptitle(cls, title):
        """Filter records by HTTP / HTML page title.

        Mirrors :meth:`MongoDB.searchhttptitle`: delegates to
        :meth:`searchscript` with ``name=["http-title",
        "html-title"]`` so both the modern http-title and the
        legacy html-title NSE script outputs are matched.
        """
        return cls.searchscript(name=["http-title", "html-title"], output=title)

    # -- screenshot / screenwords -----------------------------
    @classmethod
    def searchscreenshot(
        cls,
        port=None,
        protocol="tcp",
        service=None,
        words=None,
        neg=False,
    ):
        """Filter records that have (or, with ``neg=True``,
        lack) a screenshot on at least one port.

        Mirrors :meth:`MongoDB.searchscreenshot`.  ``port`` /
        ``protocol`` / ``service`` constrain the matching
        port; ``words`` filters on the OCR word list.  The
        Mongo-shape semantics are preserved: ``neg=True`` with
        no port / service constraint means *no* port has a
        screenshot (the existence check inverts at the host
        level), whereas ``neg=True`` with a port / service
        constraint inverts the inner predicate so other ports
        on the same host can still keep their screenshots.

        The Elastic implementation routes everything through a
        ``Nested(ports, ...)`` query so the per-port filter is
        evaluated against a single port subdoc; ``ports`` is
        in :attr:`nested_fields`.
        """
        # ``words=None``, no port / service: existence check
        # at the host level (inverts at the EXISTS level on
        # ``neg=True``).
        if words is None and port is None and service is None:
            res = Q(
                "nested",
                path="ports",
                query=Q("exists", field="ports.screenshot"),
            )
            if neg:
                return ~res
            return res
        # ``words`` is set: a screenshot must always exist;
        # the negation flips at the per-port predicate
        # (``screenwords`` excludes the words rather than the
        # whole match).
        port_query = Q("exists", field="ports.screenshot")
        if port is not None:
            port_query &= Q("match", ports__port=port)
            port_query &= Q("match", ports__protocol=protocol)
        if service is not None:
            port_query &= Q("match", ports__service_name=service)
        if words is not None:
            words_q = cls._screenshot_words_predicate(words, neg=neg)
            port_query &= words_q
        elif neg:
            # ``words=None`` with a port / service constraint:
            # invert the per-port screenshot existence.
            port_query = ~Q("exists", field="ports.screenshot")
            if port is not None:
                port_query &= Q("match", ports__port=port)
                port_query &= Q("match", ports__protocol=protocol)
            if service is not None:
                port_query &= Q("match", ports__service_name=service)
        return Q("nested", path="ports", query=port_query)

    @classmethod
    def _screenshot_words_predicate(cls, words, neg=False):
        """Build the ``ports.screenwords`` predicate for
        :meth:`searchscreenshot`.  Matches the four input
        shapes Mongo's helper supports: ``bool`` (existence),
        ``list`` (every word must be present), regex (any
        element matches the pattern), or scalar string (any
        element equals the value).  ``neg=True`` flips the
        polarity at the predicate level (Mongo's ``$ne`` /
        ``$not``); ``words=False`` short-circuits to the
        no-word existence check regardless of ``neg``.
        """
        if isinstance(words, bool):
            res = Q("exists", field="ports.screenwords")
            if not words:
                return ~res
            return res
        if isinstance(words, list):
            lowered = [w.lower() for w in words]
            res = cls.flt_and(*(Q("match", ports__screenwords=w) for w in lowered))
            if neg:
                return ~res
            return res
        if isinstance(words, utils.REGEXP_T):
            pattern = re.compile(words.pattern.lower(), flags=words.flags)
            res = Q("regexp", **{"ports.screenwords": cls._get_pattern(pattern)})
            if neg:
                return ~res
            return res
        # scalar string -- lower-cased to match the
        # pre-stored shape.
        res = Q("match", ports__screenwords=words.lower())
        if neg:
            return ~res
        return res

    # -- searchsmbshares -- direct ``ports.scripts.smb-enum-shares``
    # query; ``ElasticDBActive.searchscript`` cannot translate
    # the nested ``$elemMatch`` / ``$or`` / ``$nin`` shape the
    # Mongo helper builds, so we go via a hand-rolled
    # ``Nested(ports, Nested(ports.scripts, Bool(...)))`` query.
    @classmethod
    def searchsmbshares(cls, access="", hidden=None):
        """Filter SMB shares with the given ``access`` (default:
        either read or write, accepted values 'r', 'w', 'rw').

        ``hidden=True`` selects hidden shares only,
        ``hidden=False`` non-hidden only, ``None`` (the default)
        accepts either.

        Mirrors :meth:`MongoDB.searchsmbshares`.  The Mongo
        helper builds a ``$elemMatch`` / ``$or`` / ``$nin``
        block under ``searchscript(values=...)``;
        :meth:`ElasticDBActive.searchscript` does not translate
        that shape, so the predicate is built directly here.
        """
        access_pattern = {
            "": re.compile("^(READ|WRITE)"),
            "r": re.compile("^READ(/|$)"),
            "w": re.compile("(^|/)WRITE$"),
            "rw": "READ/WRITE",
            "wr": "READ/WRITE",
        }[access.lower()]
        excluded_share_types = (
            "STYPE_IPC_HIDDEN",
            "Not a file share",
            "STYPE_IPC",
            "STYPE_PRINTQ",
        )

        def _access_match(field):
            if isinstance(access_pattern, utils.REGEXP_T):
                return Q(
                    "regexp",
                    **{field: cls._get_pattern(access_pattern)},
                )
            return Q("match", **{field: access_pattern})

        access_q = _access_match(
            "ports.scripts.smb-enum-shares.shares.Anonymous access"
        ) | _access_match("ports.scripts.smb-enum-shares.shares.Current user access")
        if hidden is None:
            type_q = ~Q(
                "terms",
                **{
                    "ports.scripts.smb-enum-shares.shares.Type": list(
                        excluded_share_types
                    )
                },
            )
        elif hidden:
            type_q = Q(
                "match",
                **{
                    "ports.scripts.smb-enum-shares.shares.Type": (
                        "STYPE_DISKTREE_HIDDEN"
                    )
                },
            )
        else:
            type_q = Q(
                "match",
                **{"ports.scripts.smb-enum-shares.shares.Type": "STYPE_DISKTREE"},
            )
        share_q = ~Q(
            "match",
            **{"ports.scripts.smb-enum-shares.shares.Share": "IPC$"},
        )
        return Q(
            "nested",
            path="ports",
            query=Q(
                "nested",
                path="ports.scripts",
                query=Q("match", **{"ports.scripts.id": "smb-enum-shares"})
                & access_q
                & type_q
                & share_q,
            ),
        )

    @staticmethod
    def searchopenport(neg=False):
        "Filters records with at least one open port."
        res = Q("nested", path="ports", query=Q("match", ports__state_state="open"))
        if neg:
            return ~res
        return res

    @staticmethod
    def searchport(port, protocol="tcp", state="open", neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        if port == "host":
            res = Q("nested", path="ports", query=Q("match", ports__port=-1))
        elif state == "open":
            res = Q("match", **{f"openports.{protocol}.ports": port})
        else:
            res = Q(
                "nested",
                path="ports",
                query=(
                    Q("match", ports__port=port)
                    & Q("match", ports__protocol=protocol)
                    & Q("match", ports__state_state=state)
                ),
            )
        if neg:
            return ~res
        return res

    @classmethod
    def searchports(cls, ports, protocol="tcp", state="open", neg=False, any_=False):
        """Filter records that have all (or any, with
        ``any_=True``) of the listed ports in the given state.

        Mirrors :meth:`MongoDB.searchports`: defaults to
        AND-ing ``searchport(p)`` for every element (so every
        port must be open); ``any_=True`` returns the OR
        instead; ``neg=True`` AND-NOTs each match.

        ``any_`` and ``neg`` are mutually exclusive on Mongo;
        the same restriction applies here.
        """
        if any_ and neg:
            raise ValueError("searchports: cannot set both neg and any_")
        if any_:
            return cls.flt_or(
                *(cls.searchport(p, protocol=protocol, state=state) for p in ports)
            )
        return cls.flt_and(
            *(cls.searchport(p, protocol=protocol, state=state, neg=neg) for p in ports)
        )

    @classmethod
    def searchportsother(cls, ports, protocol="tcp", state="open"):
        """Filter records carrying at least one port (with the
        given ``state`` / ``protocol``) **other** than those
        listed.

        Mirrors :meth:`MongoDB.searchportsother`: a nested
        ``ports`` query with the same protocol / state
        constraints and ``ports.port NOT IN (...)``.  The
        Mongo helper uses ``$elemMatch + $nin`` on the openports
        map for ``state=open``; the Elastic implementation
        uses the same nested-ports path for both ``state=open``
        and other states so the predicate is uniform.
        """
        return Q(
            "nested",
            path="ports",
            query=(
                ~Q("terms", ports__port=ports)
                & Q("match", ports__protocol=protocol)
                & Q("match", ports__state_state=state)
            ),
        )

    @classmethod
    def searchcountopenports(cls, minn=None, maxn=None, neg=False):
        """Filter records whose ``openports.count`` falls in
        the ``[minn, maxn]`` range.

        Mirrors :meth:`MongoDB.searchcountopenports`: equal
        bounds collapse to a ``match`` (or ``must_not`` on
        ``neg=True``); a single bound emits ``range`` with
        ``gte`` / ``lte``; both bounds combine into a single
        ``range`` query (or, on ``neg=True``, an OR of the
        two individual range exclusions, mirroring Mongo's
        ``$or`` of ``$lt`` / ``$gt``).
        """
        if minn is None and maxn is None:
            raise AssertionError(
                "searchcountopenports: at least one of minn or maxn must be set"
            )
        if minn == maxn:
            res = Q("match", **{"openports.count": minn})
            if neg:
                return ~res
            return res
        if neg:
            # Mirror Mongo's ``$or`` of ``$lt`` / ``$gt``: the
            # row passes when ``count`` falls outside *either*
            # bound, so a host with very few open ports still
            # matches even if it has more than ``maxn``.
            clauses = []
            if minn is not None:
                clauses.append(Q("range", **{"openports.count": {"lt": minn}}))
            if maxn is not None:
                clauses.append(Q("range", **{"openports.count": {"gt": maxn}}))
            if len(clauses) == 1:
                return clauses[0]
            return cls.flt_or(*clauses)
        bounds: dict[str, int] = {}
        if minn is not None:
            bounds["gte"] = minn
        if maxn is not None:
            bounds["lte"] = maxn
        return Q("range", **{"openports.count": bounds})

    @classmethod
    def searchfile(cls, fname=None, scripts=None):
        """Filter records exposing a shared file by name (NSE
        ``ls`` module).

        Mirrors :meth:`MongoDB.searchfile`.  ``scripts``
        narrows the script-id space (string, list, or ``None``
        = any of the ``ls``-emitting scripts).
        """
        ls_path = "ports.scripts.ls.volumes.files.filename"
        if fname is None:
            file_q = Q("exists", field=ls_path)
        elif isinstance(fname, list):
            file_q = Q("terms", **{ls_path: fname})
        elif isinstance(fname, utils.REGEXP_T):
            file_q = Q("regexp", **{ls_path: cls._get_pattern(fname)})
        else:
            file_q = Q("match", **{ls_path: fname})
        if scripts is None:
            return Q(
                "nested",
                path="ports",
                query=Q("nested", path="ports.scripts", query=file_q),
            )
        if isinstance(scripts, str):
            scripts = [scripts]
        if len(scripts) == 1:
            id_q = Q("match", **{"ports.scripts.id": scripts[0]})
        else:
            id_q = Q("terms", **{"ports.scripts.id": scripts})
        return Q(
            "nested",
            path="ports",
            query=Q(
                "nested",
                path="ports.scripts",
                query=id_q & file_q,
            ),
        )

    @classmethod
    def searchvuln(cls, vulnid=None, state=None):
        """Filter records exposing a vulnerability matching
        ``vulnid`` and / or ``state``.

        Mirrors :meth:`MongoDB.searchvuln`: with neither
        argument the predicate matches any host with at least
        one ``ports.scripts.vulns.id`` field; with one or
        both, it constrains the matching field on the
        unwound vuln entry.
        """
        if state is None and vulnid is None:
            inner = Q("exists", field="ports.scripts.vulns.id")
        elif state is None:
            if isinstance(vulnid, utils.REGEXP_T):
                inner = Q(
                    "regexp",
                    **{"ports.scripts.vulns.id": cls._get_pattern(vulnid)},
                )
            else:
                inner = Q("match", **{"ports.scripts.vulns.id": vulnid})
        elif vulnid is None:
            inner = Q("match", **{"ports.scripts.vulns.state": state})
        else:
            inner = Q("match", **{"ports.scripts.vulns.id": vulnid}) & Q(
                "match", **{"ports.scripts.vulns.status": state}
            )
        return Q(
            "nested",
            path="ports",
            query=Q("nested", path="ports.scripts", query=inner),
        )

    @staticmethod
    def searchvulnintersil():
        """Filter records exposing the Intersil HTTPd password
        reset vulnerability (Boa HTTPd, MSF
        ``admin/http/intersil_pass_reset``).

        Mirrors :meth:`MongoDB.searchvulnintersil`: a nested
        ``ports`` match on the canonical product / version
        regex the MSF module checks.
        """
        return Q(
            "nested",
            path="ports",
            query=(
                Q("match", ports__protocol="tcp")
                & Q("match", ports__state_state="open")
                & Q("match", ports__service_product="Boa HTTPd")
                & Q(
                    "regexp",
                    ports__service_version=(
                        # Intersil firmware versions matching
                        # the MSF probe.
                        "0\\.9(3([^0-9]|).*"
                        "|4\\.([0-9]|0[0-9]|1[0-1])([^0-9]|).*)"
                    ),
                )
            ),
        )

    @classmethod
    def searchcpe(cls, cpe_type=None, vendor=None, product=None, version=None):
        """Filter records by CPE.  No argument matches any host
        with at least one CPE; otherwise the named fields are
        AND-ed against the same CPE entry (``cpes`` is a flat
        array of objects on the Elasticsearch schema -- not
        declared in :attr:`nested_fields` -- so a host with
        ``cpes = [{vendor: A, product: P}, {vendor: B, product:
        Q}]`` would match ``searchcpe(vendor="A", product="Q")``
        even though no single entry has both; this matches the
        existing schema's flat-array semantics for
        ``hostnames.*`` and the rest of the non-nested arrays).

        Mirrors :meth:`MongoDB.searchcpe`.
        """
        fields = [
            ("type", cpe_type),
            ("vendor", vendor),
            ("product", product),
            ("version", version),
        ]
        flt = [(name, value) for name, value in fields if value is not None]
        if not flt:
            return Q("exists", field="cpes")
        clauses = []
        for name, value in flt:
            if isinstance(value, utils.REGEXP_T):
                clauses.append(Q("regexp", **{f"cpes.{name}": cls._get_pattern(value)}))
            else:
                clauses.append(Q("match", **{f"cpes.{name}": value}))
        return cls.flt_and(*clauses)

    @classmethod
    def searchos(cls, txt):
        """Filter records by OS detection.  ``txt`` is matched
        against any of ``os.osclass.{vendor, osfamily, osgen,
        type}`` -- the same four sub-keys :meth:`MongoDB.searchos`
        ORs.
        """
        keys = ("vendor", "osfamily", "osgen", "type")
        if isinstance(txt, utils.REGEXP_T):
            pattern = cls._get_pattern(txt)
            return cls.flt_or(
                *(Q("regexp", **{f"os.osclass.{key}": pattern}) for key in keys)
            )
        return cls.flt_or(*(Q("match", **{f"os.osclass.{key}": txt}) for key in keys))

    @classmethod
    def searchscript(cls, name=None, output=None, values=None, neg=False):
        """Search a particular content in the scripts results.

        ``re.IGNORECASE`` on any user-supplied regex (``name``,
        ``output``, ``values``) translates to the
        ``case_insensitive`` parameter on the corresponding
        ``regexp`` clause via :meth:`_regexp_clause`, so the
        IVRE shorthand ``/pattern/i`` matches case-insensitive
        text the same way the Mongo backend does.
        """
        req = []
        if isinstance(name, list):
            req.append(Q("terms", **{"ports.scripts.id": name}))
        elif isinstance(name, utils.REGEXP_T):
            req.append(cls._regexp_clause("ports.scripts.id", name))
        elif name is not None:
            req.append(Q("match", **{"ports.scripts.id": name}))
        if output is not None:
            if isinstance(output, utils.REGEXP_T):
                req.append(cls._regexp_clause("ports.scripts.output", output))
            else:
                req.append(Q("match", **{"ports.scripts.output": output}))
        if values:
            if isinstance(name, list):
                all_keys = set(ALIASES_TABLE_ELEMS.get(n, n) for n in name)
                if len(all_keys) != 1:
                    raise TypeError(
                        ".searchscript() needs similar `name` values when using a `values` arg"
                    )
                key = all_keys.pop()
            elif not isinstance(name, str):
                raise TypeError(
                    ".searchscript() needs a `name` arg when using a `values` arg"
                )
            else:
                key = ALIASES_TABLE_ELEMS.get(name, name)
            if isinstance(values, Query):
                req.append(values)
            elif isinstance(values, str):
                req.append(Q("match", **{f"ports.scripts.{key}": values}))
            elif isinstance(values, utils.REGEXP_T):
                req.append(cls._regexp_clause(f"ports.scripts.{key}", values))
            else:
                for field, value in values.items():
                    if isinstance(value, utils.REGEXP_T):
                        req.append(
                            cls._regexp_clause(f"ports.scripts.{key}.{field}", value)
                        )
                    else:
                        req.append(
                            Q(
                                "match",
                                **{f"ports.scripts.{key}.{field}": value},
                            )
                        )
        if not req:
            res = Q(
                "nested",
                path="ports",
                query=Q(
                    "nested",
                    path="ports.scripts",
                    query=Q("exists", field="ports.scripts"),
                ),
            )
        else:
            query = cls.flt_and(*req)
            res = Q(
                "nested",
                path="ports",
                query=Q("nested", path="ports.scripts", query=query),
            )
        if neg:
            return ~res
        return res

    @staticmethod
    def searchservice(srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        if srv is False:
            res = ~Q("exists", field="ports.service_name")
        elif isinstance(srv, list):
            res = Q("terms", ports__service_name=srv)
        else:
            res = Q("match", ports__service_name=srv)
        if port is not None:
            res &= Q("match", ports__port=port)
        if protocol is not None:
            res &= Q("match", ports__protocol=protocol)
        return Q("nested", path="ports", query=res)

    @classmethod
    def searchproduct(
        cls, product=None, version=None, service=None, port=None, protocol=None
    ):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        res = []
        if product is not None:
            if product is False:
                res.append(~Q("exists", field="ports.service_product"))
            elif isinstance(product, list):
                res.append(Q("terms", ports__service_product=product))
            else:
                res.append(Q("match", ports__service_product=product))
        if version is not None:
            if version is False:
                res.append(~Q("exists", field="ports.service_version"))
            elif isinstance(version, list):
                res.append(Q("terms", ports__service_version=version))
            else:
                res.append(Q("match", ports__service_version=version))
        if service is not None:
            if service is False:
                res.append(~Q("exists", field="ports.service_name"))
            elif isinstance(service, list):
                res.append(Q("terms", ports__service_name=service))
            else:
                res.append(Q("match", ports__service_name=service))
        if port is not None:
            res.append(Q("match", ports__port=port))
        if protocol is not None:
            res.append(Q("match", ports__protocol=protocol))
        return Q("nested", path="ports", query=cls.flt_and(*res))

    @classmethod
    def searchcert(
        cls,
        keytype=None,
        md5=None,
        sha1=None,
        sha256=None,
        subject=None,
        issuer=None,
        self_signed=None,
        pkmd5=None,
        pksha1=None,
        pksha256=None,
        cacert=False,
        neg=False,
    ):
        req = []
        if keytype is not None:
            req.append(Q("match", **{"ports.scripts.ssl-cert.pubkey.type": keytype}))
        for hashtype in ["md5", "sha1", "sha256"]:
            hashval = locals()[hashtype]
            if hashval is None:
                continue
            key = f"ports.scripts.ssl-cert.{hashtype}"
            if isinstance(hashval, utils.REGEXP_T):
                req.append(Q("regexp", **{key: cls._get_pattern(hashval).lower()}))
                continue
            if isinstance(hashval, list):
                req.append(Q("terms", **{key: [val.lower() for val in hashval]}))
                continue
            req.append(Q("match", **{key: hashval.lower()}))
        if subject is not None:
            if isinstance(subject, utils.REGEXP_T):
                req.append(
                    Q(
                        "regexp",
                        **{
                            "ports.scripts.ssl-cert.subject_text": cls._get_pattern(
                                subject
                            )
                        },
                    )
                )
            else:
                req.append(
                    Q("match", **{"ports.scripts.ssl-cert.subject_text": subject})
                )
        if issuer is not None:
            if isinstance(issuer, utils.REGEXP_T):
                req.append(
                    Q(
                        "regexp",
                        **{
                            "ports.scripts.ssl-cert.issuer_text": cls._get_pattern(
                                issuer
                            )
                        },
                    )
                )
            else:
                req.append(Q("match", **{"ports.scripts.ssl-cert.issuer_text": issuer}))
        if self_signed is not None:
            req.append(
                Q("match", **{"ports.scripts.ssl-cert.self_signed": self_signed})
            )
        for hashtype in ["md5", "sha1", "sha256"]:
            hashval = locals()[f"pk{hashtype}"]
            if hashval is None:
                continue
            key = f"ports.scripts.ssl-cert.pubkey.{hashtype}"
            if isinstance(hashval, utils.REGEXP_T):
                req.append(Q("regexp", **{key: cls._get_pattern(hashval).lower()}))
                continue
            if isinstance(hashval, list):
                req.append(Q("terms", **{key: [val.lower() for val in hashval]}))
                continue
            req.append(Q("match", **{key: hashval.lower()}))
        if req:
            res = Q(
                "nested",
                path="ports",
                query=Q(
                    "nested",
                    path="ports.scripts",
                    query=cls.flt_and(
                        Q(
                            "match",
                            **{
                                "ports.scripts.id": (
                                    "ssl-cacert" if cacert else "ssl-cert"
                                )
                            },
                        ),
                        Q(
                            "nested",
                            path="ports.scripts.ssl-cert",
                            query=cls.flt_and(*req),
                        ),
                    ),
                ),
            )
        else:
            res = Q(
                "nested",
                path="ports",
                query=Q(
                    "nested",
                    path="ports.scripts",
                    query=Q(
                        "match",
                        **{"ports.scripts.id": "ssl-cacert" if cacert else "ssl-cert"},
                    ),
                ),
            )
        if neg:
            return ~res
        return res

    @classmethod
    def searchtext(cls, text, neg=False):
        """Filter records that match the free-text ``text``
        across every text-bearing field declared in
        :attr:`DBActive.text_fields`.

        Mirrors the contract of :meth:`MongoDB.searchtext`
        (``{"$text": {"$search": text}}``) and
        :meth:`SQLDBActive.searchtext` (the ``OR``-of-``EXISTS``
        over text-bearing child tables): a single
        ``searchtext("foo")`` matches any host with ``foo``
        somewhere in its hostnames, tags, ports, scripts,
        traces, categories, or OS / CPE attributes.

        Composes one ``multi_match`` query per nesting level:

        * Fields under a path declared in :attr:`nested_fields`
          (``ports.*``, ``ports.scripts.*``, ``tags.*``) are
          wrapped in a ``nested`` query against the appropriate
          path so Elasticsearch evaluates the match against the
          inner document; a top-level ``multi_match`` against a
          nested-typed field silently returns nothing.
        * Remaining fields (``categories``, ``cpes.*``,
          ``hostnames.*``, ``os.*``, ``traces.hops.host``)
          fan out under a single root-level ``multi_match``.

        The per-group queries are OR-combined; ``neg=True``
        wraps the whole result in :class:`elasticsearch_dsl.query.Bool`'s
        ``~`` (i.e. ``must_not``).
        """
        # Group :attr:`text_fields` by their nested ancestor
        # (longest prefix match in :attr:`nested_fields`).
        nested_paths = sorted(cls.nested_fields, key=len, reverse=True)
        flat_fields: list[str] = []
        nested_groups: dict[str, list[str]] = {}
        for field in cls.text_fields:
            for path in nested_paths:
                if field == path or field.startswith(f"{path}."):
                    nested_groups.setdefault(path, []).append(field)
                    break
            else:
                flat_fields.append(field)

        queries: list[Q] = []
        if flat_fields:
            queries.append(Q("multi_match", query=text, fields=flat_fields))
        for path, fields in nested_groups.items():
            queries.append(
                Q(
                    "nested",
                    path=path,
                    query=Q("multi_match", query=text, fields=fields),
                )
            )

        if not queries:
            # No text fields declared on this backend: a
            # ``searchtext`` call is a guaranteed mismatch
            # (positive search) or a tautology (negation).
            return cls.flt_empty if neg else cls.searchnonexistent()

        result = queries[0]
        for query in queries[1:]:
            result = result | query
        if neg:
            return ~result
        return result

    @classmethod
    def searchhassh(cls, value_or_hash=None, server=None):
        if server is None:
            return cls._searchhassh(value_or_hash=value_or_hash)
        if value_or_hash is None:
            baseflt = Q(
                "nested",
                path="ports.scripts",
                query=Q("match", ports__scripts__id="ssh2-enum-algos"),
            )
        else:
            # this is not JA3, but we have the exact same logic & needs
            key, value = cls._ja3keyvalue(value_or_hash)
            if isinstance(value, utils.REGEXP_T):
                valflt = Q(
                    "regexp",
                    **{
                        f"ports.scripts.ssh2-enum-algos.hassh.{key}": cls._get_pattern(
                            value
                        )
                    },
                )
            else:
                valflt = Q(
                    "match", **{f"ports.scripts.ssh2-enum-algos.hassh.{key}": value}
                )
            baseflt = Q(
                "nested",
                path="ports.scripts",
                query=Q("match", ports__scripts__id="ssh2-enum-algos") & Q(valflt),
            )
        if server:
            portflt = ~Q("match", ports__port=-1)
        else:
            portflt = Q("match", ports__port=-1)
        return Q("nested", path="ports", query=portflt & baseflt)


class ElasticDBView(ElasticDBActive, DBView):
    def __init__(self, url):
        super().__init__(url)
        self.indexes = [
            f"{self.index_prefix}{self.params.pop('indexname_hosts', 'views')}"
        ]

    def store_or_merge_host(self, host):
        if not self.merge_host(host):
            self.store_host(host)

    @classmethod
    def searchtag(cls, tag=None, neg=False):
        """Filters (if `neg` == True, filters out) one particular tag (records
        may have zero, one or more tags).

        `tag` may be the value (as a str) or the tag (as a Tag, e.g.:
        `{"value": value, "info": info}`).

        """
        if not tag:
            res = Q("exists", field="tags.value")
            if neg:
                return ~res
            return res
        if not isinstance(tag, dict):
            tag = {"value": tag}
        all_res = []
        for key, value in tag.items():
            if isinstance(value, list) and len(value) == 1:
                value = value[0]
            if isinstance(value, list):
                res = Q("terms", **{f"tags.{key}": value})
            elif isinstance(value, utils.REGEXP_T):
                res = Q("regexp", **{f"tags.{key}": cls._get_pattern(value)})
            else:
                res = Q("match", **{f"tags.{key}": value})
            if neg:
                all_res.append(~res)
            else:
                all_res.append(res)
        if neg:
            return cls.flt_or(
                ~Q("exists", field="tags.value"),
                Q("nested", path="tags", query=cls.flt_or(*all_res)),
            )
        return Q("nested", path="tags", query=cls.flt_and(*all_res))

    @classmethod
    def searchcountry(cls, country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        return cls._search_field(
            "infos.country_code", utils.country_unalias(country), neg=neg
        )

    @classmethod
    def searchcity(cls, city, neg=False):
        """Filter records by GeoIP city.  Mirrors
        :meth:`MongoDB.searchcity` (a ``match`` on
        ``infos.city`` with the regex / list / scalar dispatch
        :meth:`_search_field` provides).
        """
        return cls._search_field("infos.city", city, neg=neg)

    @classmethod
    def searchasnum(cls, asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s). The legacy form coerced every
        element to ``int(...)`` blindly; preserve that here so
        ``"AS1234"``-prefixed strings still raise the same
        ``ValueError`` they did before \u2014 callers that want
        the prefix-stripping shape can pre-process via the
        ``MongoDB`` backend's ``_coerce_asnum`` mirror.
        """
        if not isinstance(asnum, str) and hasattr(asnum, "__iter__"):
            asnum = [int(val) for val in asnum]
        else:
            asnum = int(asnum)
        return cls._search_field("infos.as_num", asnum, neg=neg)

    @classmethod
    def searchasname(cls, asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        return cls._search_field("infos.as_name", asname, neg=neg)

    def getlocations(self, flt):
        # Read the raw ``[lng, lat]`` array from ``_source``
        # (Elasticsearch stores ``infos.coordinates`` as a
        # native ``geo_point`` -- :meth:`store_host` flips
        # IVRE's ``[lat, lng]`` convention for the GeoJSON
        # ``[lng, lat]`` order ES expects).  ``doc[...].value``
        # would route through the indexed geo_point and lose
        # float precision (e.g. ``48.86`` round-trips as
        # ``48.85999997612089``), which makes the
        # ``/cgi/view/coordinates`` endpoint disagree with the
        # ``_source``-based ``get()`` path that the test
        # harness compares against.  ``params._source`` keeps
        # the original JSON literals intact.  The painless
        # script swaps the two components back to IVRE's
        # ``[lat, lng]`` order so :meth:`MongoDBView.getlocations`
        # parity holds and the ``r2res`` reversal in
        # ``web/app.py`` produces a GeoJSON ``[lng, lat]``
        # ``coordinates`` payload.
        query = {
            "size": PAGESIZE,
            "sources": [
                {
                    "coords": {
                        "terms": {
                            "script": {
                                "lang": "painless",
                                "source": (
                                    "def c = params._source.infos.coordinates;"
                                    " return c[1] + ',' + c[0];"
                                ),
                            }
                        }
                    }
                }
            ],
        }
        flt = self.flt_and(flt & self.searchhaslocation())
        while True:
            result = self.db_client.search(
                body={"query": flt.to_dict(), "aggs": {"values": {"composite": query}}},
                index=self.indexes[0],
                ignore_unavailable=True,
                size=0,
            )
            for value in result["aggregations"]["values"]["buckets"]:
                yield {
                    "_id": tuple(float(v) for v in value["key"]["coords"].split(",")),
                    "count": value["doc_count"],
                }
            if "after_key" not in result["aggregations"]["values"]:
                break
            query["after"] = result["aggregations"]["values"]["after_key"]


load_plugins("ivre.plugins.db.elastic", globals())
