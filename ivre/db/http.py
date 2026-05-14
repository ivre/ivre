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

"""This sub-module contains functions to interact with another IVRE
instance via an HTTP server.

"""

import json
import re
from datetime import datetime
from functools import update_wrapper
from getpass import getpass
from io import BytesIO
from urllib.parse import quote
from urllib.request import Request, build_opener

try:
    import pycurl
except ImportError:
    HAS_CURL = False
else:
    HAS_CURL = True


from ivre.db import DB, DBActive, DBData, DBFlow, DBNmap, DBPassive, DBRir, DBView

try:
    from ivre.db.maxmind import MaxMindDBData
except ImportError:
    MaxMindDBData = None
try:
    from ivre.db.mongo import (
        MongoDBActive,
        MongoDBFlow,
        MongoDBNmap,
        MongoDBPassive,
        MongoDBRir,
        MongoDBView,
    )
except ImportError:
    MongoDBActive = MongoDBFlow = MongoDBNmap = MongoDBPassive = MongoDBRir = (
        MongoDBView
    ) = None
from ivre import VERSION, utils

RESULTS_COUNT = 200

# Canonical datetime-valued keys shared by every flow record
# source (``ivre/tools/zeek2db.py:_zeek2flow``,
# ``ivre/parser/argus.py``, ``ivre/parser/netflow.py``,
# ``ivre/parser/iptables.py``).  ``ts`` is always renamed to
# ``start_time`` / ``end_time`` by ``_zeek2flow`` before the
# record reaches the bulk; we keep it in the list so future
# parsers that pre-date the rename keep round-tripping.
#
# :meth:`HttpDBFlow._serialize_record` and the server-side
# :func:`ivre.web.app._flow_record_from_payload` MUST honour the
# same set so a value that becomes a ``float`` on the wire ends
# up back as a :class:`datetime` on the receiving side.  Adding
# a new datetime-valued field anywhere in the ingestion pipeline
# requires updating this constant; any other ``datetime`` value
# in a record raises :class:`TypeError` at ``json.dumps`` time
# rather than silently arriving as a float on the server.
FLOW_DATETIME_KEYS: frozenset[str] = frozenset({"start_time", "end_time", "ts"})


def serialize(obj):
    """Return a JSON-compatible representation for `obj`"""
    if isinstance(obj, re.Pattern):
        return {
            "f": "regexp",
            "a": [
                f"/{obj.pattern}/{''.join((x.lower() for x in 'ILMSXU' if getattr(re, x) & obj.flags))}",
            ],
        }
    if isinstance(obj, datetime):
        return {"f": "datetime", "a": [obj.timestamp()]}
    if isinstance(obj, bytes):
        return {"f": "bytes", "a": [utils.encode_b64(obj).decode()]}
    raise TypeError(f"Don't know what to do with {obj!r} ({type(obj)!r})")


class HttpFetcher:
    def __init__(self, url):
        self.baseurl = url._replace(fragment="").geturl()

    @staticmethod
    def from_url(url):
        if HAS_CURL and "@" in url.netloc:
            # pylint: disable=possibly-used-before-assignment
            username, netloc = url.netloc.split("@", 1)
            if username == "GSSAPI":
                return HttpFetcherCurlGssapi(url._replace(netloc=netloc))
            if username == "PKCS11":
                return HttpFetcherCurlClientCertPkcs11(url._replace(netloc=netloc))
            if username.startswith("PKCS11:"):
                username = username[7:]
                if ":" in username:
                    username, pincode = username.split(":", 1)
                    return HttpFetcherCurlClientCertPkcs11(
                        url._replace(netloc=netloc), username=username, pincode=pincode
                    )
                return HttpFetcherCurlClientCertPkcs11(
                    url._replace(netloc=netloc), username=username
                )
        return HttpFetcherBasic(url)


class HttpFetcherBasic(HttpFetcher):
    def __init__(self, url):
        super().__init__(url)
        self.urlop = build_opener()
        self.urlop.addheaders = [("User-Agent", f"IVRE/{VERSION} +https://ivre.rocks/")]
        self.urlop.addheaders.extend(
            tuple(x.split("=", 1)) if "=" in x else (x, "")
            for x in url.fragment.split("&")
            if x
        )

    def open(self, url):
        return self.urlop.open(url)


if HAS_CURL:

    class FakeFdesc:
        def __init__(self, bytesio):
            self.bytesio = bytesio

        def __iter__(self):
            return (line for line in self.bytesio.getvalue().splitlines())

        def read(self, *args):
            return self.bytesio.getvalue()

    class HttpFetcherCurl(HttpFetcher):
        def __init__(self, url):
            super().__init__(url)
            self.headers = [
                # pylint: disable=consider-using-f-string
                "%s: %s" % (tuple(x.split("=", 1)) if "=" in x else (x, ""))
                for x in url.fragment.split("&")
                if x
            ]

        def _set_opts(self, curl):
            curl.setopt(pycurl.HTTPHEADER, self.headers)

        def open(self, url):
            fdesc = BytesIO()
            curl = pycurl.Curl()
            curl.setopt(pycurl.URL, url)
            curl.setopt(pycurl.WRITEDATA, fdesc)
            self._set_opts(curl)
            curl.perform()
            status_code = curl.getinfo(pycurl.HTTP_CODE)
            if status_code != 200:
                raise Exception(f"HTTP Error {status_code}")
            return FakeFdesc(fdesc)

    class HttpFetcherCurlGssapi(HttpFetcherCurl):
        def _set_opts(self, curl):
            super()._set_opts(curl)
            curl.setopt(pycurl.USERNAME, "")
            curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_GSSNEGOTIATE)

    class HttpFetcherCurlClientCertPkcs11(HttpFetcherCurl):
        def __init__(self, url, username=None, pincode=None):
            super().__init__(url)
            if username is not None:
                self._username = username
            if pincode is not None:
                self._pincode = pincode

        def _set_opts(self, curl):
            super()._set_opts(curl)
            curl.setopt(pycurl.USERNAME, "")
            curl.setopt(pycurl.SSLENGINE, "pkcs11")
            curl.setopt(pycurl.SSLCERTTYPE, "eng")
            curl.setopt(
                pycurl.SSLCERT,
                f"pkcs11:manufacturer=piv_II;token={self.username};pin-value={self.pincode}",
            )

        @property
        def username(self):
            try:
                return self._username
            except AttributeError:
                self._username = input("username> ")
            return self._username

        @property
        def pincode(self):
            try:
                return self._pincode
            except AttributeError:
                self._pincode = getpass("pincode> ")
            return self._pincode


class HttpDB(DB):
    flt_empty = {}
    no_limit = None

    def __init__(self, url):
        super().__init__()
        self.db = HttpFetcher.from_url(url)

    @staticmethod
    def _output_filter(spec):
        return quote(
            json.dumps(spec, separators=(",", ":"), indent=None, default=serialize)
        )

    def _get(self, spec, limit=None, skip=None, sort=None, fields=None):
        url_l = [f"{self.db.baseurl}/{self.route}?f={self._output_filter(spec)}&q="]
        for s_field, direction in sort or []:
            url_l.append(f"{'-' if direction < 0 else ''}sortby:{s_field}%20")
        if fields is not None:
            url_l.append(f"fields:{quote(','.join(fields))}%20")
        url_l.append("skip:")
        url = "".join(url_l)
        if skip is None:
            skip = 0
        while True:
            cururl = f"{url}{skip}"
            if limit is not None:
                cururl += f"%20limit:{limit}"
            else:
                cururl += f"%20limit:{RESULTS_COUNT}"
            req = self.db.open(cururl)
            data = json.loads(req.read().decode())
            if not data:
                break
            if limit is None:
                yield from data
            else:
                for rec in data:
                    yield rec
                    limit -= 1
                    if not limit:
                        break
                if not limit:
                    break
            skip += len(data)

    @staticmethod
    def fix_rec(rec):
        """This function may be used by purpose-specific subclasses to fix the
        record before it is sent to the user.

        """

    def _set_datetime_field(self, record, field, current=None):
        if current is None:
            current = []
        if "." not in field:
            if field in record:
                if ".".join(current + [field]) in self.list_fields:
                    record[field] = [
                        datetime.utcfromtimestamp(value) for value in record[field]
                    ]
                else:
                    record[field] = datetime.utcfromtimestamp(record[field])
            return
        nextfield, field = field.split(".", 1)
        if nextfield not in record:
            return
        current = current + [nextfield]
        if ".".join(current) in self.list_fields:
            for subrecord in record[nextfield]:
                self._set_datetime_field(subrecord, field, current=current)
        else:
            self._set_datetime_field(record[nextfield], field, current=current)

    def get(self, spec, limit=None, skip=None, sort=None, fields=None):
        for rec in self._get(spec, limit=limit, skip=skip, sort=sort, fields=fields):
            for fld in self.datetime_fields:
                self._set_datetime_field(rec, fld)
            self.fix_rec(rec)
            yield rec

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None):
        url_l = [
            f"{self.db.baseurl}/{self.route}/distinct/{field}?f={self._output_filter(flt or {})}&format=ndjson&q=limit:{limit or 0}"
        ]
        for s_field, direction in sort or []:
            url_l.append(f"%20{'-' if direction < 0 else ''}sortby:{s_field}")
        if skip is not None:
            url_l.append(f"%20skip:{skip}")
        url = "".join(url_l)
        for line in self.db.open(url):
            yield json.loads(line)

    def count(self, spec, **kargs):
        url = f"{self.db.baseurl}/{self.route}/count?f={self._output_filter(spec)}"
        req = self.db.open(url)
        return int(req.read().rstrip(b"\n"))

    def topvalues(
        self,
        field,
        flt=None,
        topnbr=10,
        sort=None,
        limit=None,
        skip=None,
        least=False,
    ):
        url = f"{self.db.baseurl}/{self.route}/top/{'-' if least else ''}{quote(field)}:{int(topnbr)}?f={self._output_filter(flt or self.flt_empty)}"
        for param in ["sort", "limit", "skip"]:
            if locals()[param] is not None:
                raise ValueError(f"Parameter {param} is not supported in HTTP backend")

        def output(x):
            return {"_id": outputproc(x["label"]), "count": x["value"]}

        if (
            field
            in {
                "country",
                "city",
                "as",
                "port",
                "product",
                "version",
                "cpe",
                "ja3-server",
                "sshkey.bits",
                "ike.vendor_ids",
                "ike.transforms",
                "httphdr",
                "httpapp",
            }
            or any(
                field.startswith(x)
                for x in ["port:", "product:", "version:", "ja3-server:", "ja3-server."]
            )
            or (field.startswith("vulns.") and field != "vulns.id")
        ):

            def outputproc(x):
                return tuple(x)

        elif field.startswith("portlist:"):

            def outputproc(x):
                return [tuple(y) for y in x]

        else:

            def outputproc(x):
                return x

        req = self.db.open(url)
        return [output(elt) for elt in json.load(req)]

    @staticmethod
    def flt_and(*args):
        return {"f": "and", "a": list(a for a in args if a)}

    @classmethod
    def flt_or(cls, *args):
        return {"f": "or", "a": list(args)}

    @staticmethod
    def _search(func, *args, **kargs):
        return {
            "f": func,
            **({"a": list(args)} if args else {}),
            **({"k": kargs} if kargs else {}),
        }

    def __getattribute__(self, attr):
        if attr.startswith("search") and attr[6:]:
            try:
                return getattr(self, f"_{attr}")
            except AttributeError:
                pass

            # avoid using partial here because it returns an object
            # and it breaks the help() output
            def function(*args, **kargs):
                return self._search(attr[6:], *args, **kargs)

            try:
                reference = getattr(self.reference, attr)
            except AttributeError:
                pass
            else:
                update_wrapper(function, reference)
            setattr(self, f"_{attr}", function)
            return function
        return super().__getattribute__(attr)


class HttpDBActive(HttpDB, DBActive):
    reference = MongoDBActive

    @staticmethod
    def fix_rec(rec):
        """This function may be used by purpose-specific subclasses to fix the
        record before it is sent to the user.

        """
        if "addresses" not in rec:
            return
        if "mac" not in rec["addresses"]:
            return
        rec["addresses"]["mac"] = [mac["addr"] for mac in rec["addresses"]["mac"]]


class HttpDBNmap(HttpDBActive, DBNmap):
    reference = MongoDBNmap

    route = "scans"


class HttpDBView(HttpDBActive, DBView):
    reference = MongoDBView

    route = "view"


class HttpDBPassive(HttpDB, DBPassive):
    reference = MongoDBPassive

    route = "passive"


class HttpDBData(HttpDB, DBData):
    reference = MaxMindDBData

    route = "ipdata"

    def infos_byip(self, addr):
        url = f"{self.db.baseurl}/{self.route}/{addr}"
        req = self.db.open(url)
        return {
            k: tuple(v) if isinstance(v, list) else v
            for k, v in (json.load(req) or {}).items()
        }

    def _infos_byip(self, fields, addr):
        infos = self.infos_byip(addr)
        return {key: infos[key] for key in fields if key in infos}

    def as_byip(self, addr):
        return self._infos_byip(["as_num", "as_name"], addr)

    def location_byip(self, addr):
        return self._infos_byip(
            [
                "region_code",
                "region_name",
                "continent_code",
                "continent_name",
                "country_code",
                "country_name",
                "registered_country_code",
                "registered_country_name",
                "city",
                "postal_code",
                "coordinates",
                "coordinates_accuracy_radius",
            ],
            addr,
        )

    def country_byip(self, addr):
        return self._infos_byip(["country_code", "country_name"], addr)


class HttpDBRir(HttpDB, DBRir):
    reference = MongoDBRir

    route = "rir"


class _HttpFlowQuery:
    """Opaque wrapper around the original :class:`HttpDBFlow.from_filters`
    inputs.

    Methods like :meth:`HttpDBFlow.count` / :meth:`HttpDBFlow.to_graph` /
    :meth:`HttpDBFlow.host_details` / :meth:`HttpDBFlow.flow_details`
    receive this wrapper and forward the captured ``filters`` (the raw
    ``{nodes, edges}`` dict the caller passed in) to the remote IVRE
    via the ``GET /flows`` endpoint.  Forwarding the *raw* query
    rather than the parsed :class:`ivre.flow.Query` keeps the wire
    format identical to the JSON the AngularJS UI already sends, so
    no server-side translation is needed.
    """

    __slots__ = ("filters", "kwargs")

    def __init__(self, filters, **kwargs):
        # ``filters`` is the ``{nodes, edges}`` dict the caller
        # passed in; ``kwargs`` holds the rest (``limit`` / ``skip``
        # / ``orderby`` / ``mode`` / ``timeline`` / ``after`` /
        # ``before`` / ``precision``).  The per-method overrides
        # (e.g. :meth:`HttpDBFlow.to_graph`'s own ``limit`` /
        # ``skip``) layer on top at request-build time.
        self.filters = filters or {}
        self.kwargs = kwargs


class HttpDBFlow(HttpDB, DBFlow):
    """HTTP proxy for the flow database.

    Forwards every query to the remote IVRE's ``/flows`` web endpoint
    (read-side) and ``/flows`` ``POST`` (ingestion).  The server-side
    backend (Mongo / PostgreSQL) handles the actual storage; this
    class only translates calls into HTTP requests.

    The ``reference`` attribute (used by :meth:`HttpDB.__getattribute__`
    to surface ``searchXXX`` helpers) points to :class:`MongoDBFlow`
    so search-clause names match the canonical Mongo backend.
    """

    reference = MongoDBFlow

    route = "flows"

    @staticmethod
    def _serialize_value(value):
        """JSON-friendly representation of a single Python value.

        The flow query format already uses ``"YYYY-MM-DD HH:MM"``
        strings for ``before`` / ``after`` (parsed server-side via
        :func:`datetime.strptime`); other ``datetime`` objects
        round-trip through the same shape so timeline / timeslot
        bounds keep working.  Other values pass through unchanged.
        """
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M")
        return value

    @classmethod
    def _build_query_dict(cls, flt, overrides=None):
        """Merge an :class:`_HttpFlowQuery` into the JSON payload
        the ``/flows`` endpoint expects.

        ``overrides`` are the per-method kwargs the caller passes
        on top of the ones captured by :meth:`from_filters` (e.g.
        :meth:`to_graph`'s own ``limit`` / ``skip`` block).  An
        override that resolves to ``None`` is dropped so the
        server-side defaults kick in (matching the way the
        AngularJS UI omits unset keys).
        """
        if flt is None:
            payload = {}
        else:
            # ``filters`` carries ``nodes`` / ``edges`` -- both go
            # at the top level of the JSON payload because that's
            # the shape ``ivre/web/app.py:get_flow`` reads.
            payload = dict(flt.filters)
            for key, value in flt.kwargs.items():
                if value is None:
                    continue
                payload[key] = cls._serialize_value(value)
        for key, value in (overrides or {}).items():
            if value is None:
                continue
            payload[key] = cls._serialize_value(value)
        return payload

    @classmethod
    def from_filters(
        cls,
        filters,
        limit=None,
        skip=0,
        orderby="",
        mode=None,
        timeline=False,
        after=None,
        before=None,
        precision=None,
    ):
        """Capture the inputs of a flow query without parsing them.

        The remote IVRE re-parses the same dict via its own
        :meth:`DBFlow.from_filters`; running the parser locally
        would only build a :class:`ivre.flow.Query` we'd then
        have to round-trip back to JSON, so we keep the original
        shape verbatim.
        """
        return _HttpFlowQuery(
            filters,
            limit=limit,
            skip=skip,
            orderby=orderby,
            mode=mode,
            timeline=timeline,
            after=after,
            before=before,
            precision=precision,
        )

    def _flow_get_url(self, payload, action=None):
        """Render the ``GET /flows`` URL for a JSON payload."""
        url = f"{self.db.baseurl}/{self.route}?q={quote(json.dumps(payload, default=utils.serialize))}"
        if action:
            url += f"&action={quote(action)}"
        return url

    def count(self, spec, **kargs):
        """Return ``{clients, servers, flows}`` for ``spec``.

        Mirrors :meth:`MongoDBFlow.count` over the wire by
        appending ``count=true`` to the ``/flows`` payload (which
        the server interprets in ``ivre/web/app.py:get_flow``).
        The ``spec`` parameter name matches :meth:`HttpDB.count`'s
        signature so the keyword-arg dispatch in shared call sites
        keeps working unchanged.
        """
        del kargs  # unused; signature parity with HttpDB.count
        payload = self._build_query_dict(spec, overrides={"count": True})
        url = self._flow_get_url(payload)
        req = self.db.open(url)
        return json.loads(req.read())

    def to_graph(
        self,
        flt,
        limit=None,
        skip=None,
        orderby=None,
        mode=None,
        timeline=False,
        after=None,
        before=None,
    ):
        """Forward a graph query to ``/flows`` and parse the JSON
        response.

        The server runs the equivalent of
        :meth:`DBFlow.cursor2json_graph` over its own backend so
        the returned dict has the canonical ``{"nodes": [...],
        "edges": [...]}`` shape, regardless of which engine the
        remote IVRE uses.
        """
        payload = self._build_query_dict(
            flt,
            overrides={
                "limit": limit,
                "skip": skip,
                "orderby": orderby,
                "mode": mode,
                "timeline": timeline,
                "after": after,
                "before": before,
            },
        )
        url = self._flow_get_url(payload)
        req = self.db.open(url)
        return json.loads(req.read())

    def host_details(self, node_id):
        """Forward a ``host_details`` query to the remote IVRE.

        Mirrors :meth:`MongoDBFlow.host_details`'s contract by
        wrapping the node id in the ``{type, id}`` payload
        ``ivre/web/app.py:get_flow`` reads when ``action=details``.
        Returns ``None`` if the server reports the host as
        missing (the endpoint emits a 404 in that case).
        """
        payload = {"type": "node", "id": node_id}
        url = self._flow_get_url(payload, action="details")
        try:
            req = self.db.open(url)
        except Exception:
            # 404 / network failure both surface as exceptions
            # from ``urllib`` / ``pycurl``; the caller (web UI
            # or CLI) treats ``None`` as "not found" already.
            utils.LOGGER.warning(
                "host_details %r failed against %r", node_id, url, exc_info=True
            )
            return None
        return json.loads(req.read())

    def flow_details(self, flow_id):
        """Forward a ``flow_details`` query to the remote IVRE.

        Mirrors :meth:`MongoDBFlow.flow_details` -- same wire
        shape as :meth:`host_details` but with ``type=edge``.
        """
        payload = {"type": "edge", "id": flow_id}
        url = self._flow_get_url(payload, action="details")
        try:
            req = self.db.open(url)
        except Exception:
            utils.LOGGER.warning(
                "flow_details %r failed against %r", flow_id, url, exc_info=True
            )
            return None
        return json.loads(req.read())

    # -- ingestion path ------------------------------------------------
    #
    # The bulk handle is opaque to callers (``zeek2db`` / ``flow2db``
    # treat it as a black box); we shape it as a list of JSON-friendly
    # dicts so :meth:`bulk_commit` can ``POST`` the whole bulk in a
    # single round-trip.

    @staticmethod
    def start_bulk_insert():
        """Allocate a fresh in-memory bulk-insert buffer."""
        return []

    @staticmethod
    def _serialize_record(rec):
        """Convert a parsed Zeek / NetFlow record to a JSON-safe
        dict.

        Only the canonical datetime keys listed in
        :data:`FLOW_DATETIME_KEYS` are converted to ``float``
        epoch seconds; other values pass through unchanged.
        Restricting the conversion keeps the wire contract
        symmetric with the server-side
        :func:`ivre.web.app._flow_record_from_payload` (which
        only rehydrates the same keys): a ``datetime`` value
        under any other key would silently arrive as a float
        on the server otherwise.

        Any other ``datetime`` value left in the record falls
        through to :func:`json.dumps` later, which raises
        :class:`TypeError` ("Object of type datetime is not
        JSON serializable") -- a loud failure that surfaces
        the missing key as a contract bug rather than letting
        it round-trip with the wrong type.
        """
        out = {}
        for key, value in rec.items():
            if key in FLOW_DATETIME_KEYS and isinstance(value, datetime):
                out[key] = value.timestamp()
            else:
                out[key] = value
        return out

    @classmethod
    def any2flow(cls, bulk, name, rec):
        """Queue a non-conn Zeek log record for remote ingestion.

        Mirrors :meth:`MongoDBFlow.any2flow`'s contract; the
        actual upsert happens on the remote IVRE when
        :meth:`bulk_commit` POSTs the bulk.
        """
        bulk.append({"kind": "any", "name": name, "rec": cls._serialize_record(rec)})

    @classmethod
    def conn2flow(cls, bulk, rec):
        """Queue a Zeek ``conn.log`` record for remote ingestion."""
        bulk.append({"kind": "conn", "rec": cls._serialize_record(rec)})

    @classmethod
    def flow2flow(cls, bulk, rec):
        """Queue a NetFlow / Argus record for remote ingestion."""
        bulk.append({"kind": "flow", "rec": cls._serialize_record(rec)})

    def _post(self, url, body):
        """Issue a ``POST`` request against the remote IVRE.

        Reuses the urllib opener configured by
        :class:`HttpFetcherBasic` (so the URL-fragment-derived
        headers -- ``X-API-Key`` / ``Authorization: Bearer ...``
        / ``Referer`` -- carry over to the write path) and adds
        an explicit ``Content-Type: application/json`` to the
        request itself.

        The pycurl-based fetchers (Kerberos / PKCS#11) are
        GET-only today; POST support requires extra
        ``POSTFIELDS`` / ``CUSTOMREQUEST`` curl options and is
        deferred.  Hitting this path against one of those
        fetchers raises a clear ``NotImplementedError`` so the
        operator can fall back to the basic auth flow.
        """
        opener = getattr(self.db, "urlop", None)
        if opener is None:
            raise NotImplementedError(
                "POST is not yet supported with the pycurl-based "
                "HTTP fetchers (Kerberos / PKCS#11); use the basic "
                "auth flow for flow ingestion until that lands"
            )
        req = Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        # Mirror the headers ``HttpFetcherBasic`` already
        # injected onto the opener (``User-Agent`` plus the
        # fragment-derived headers) so the auth posture
        # matches the GET path one-for-one.
        for hname, hval in opener.addheaders:
            req.add_header(hname, hval)
        return opener.open(req)

    def bulk_commit(self, bulk):
        """POST the queued records to the remote IVRE.

        Mirrors :meth:`MongoDBFlow.bulk_commit`'s contract: an
        empty bulk is a no-op (no HTTP round-trip), every other
        bulk hits ``POST /flows`` once.  The server-side handler
        (``ivre/web/app.py:post_flow``) deserialises the record
        timestamps and dispatches to the matching ``any2flow`` /
        ``conn2flow`` / ``flow2flow`` on its own backend,
        followed by a single ``bulk_commit`` at the end.
        """
        if not bulk:
            return
        url = f"{self.db.baseurl}/{self.route}"
        body = json.dumps({"records": bulk}).encode()
        self._post(url, body).read()

    def cleanup_flows(self):
        """Trigger the remote IVRE's ``cleanup_flows`` heuristic.

        Mirrors :meth:`MongoDBFlow.cleanup_flows`; the server
        runs its own backend's implementation (a no-op on the
        SQL backend until the host-swap heuristic is ported).
        """
        url = f"{self.db.baseurl}/{self.route}/cleanup"
        self._post(url, b"").read()

    # -- deferred read methods ----------------------------------------
    #
    # The existing ``GET /flows`` endpoint covers ``count`` /
    # ``to_graph`` / ``host_details`` / ``flow_details`` already; the
    # ``flowcli``-only methods below need new server-side action
    # handlers.  They raise a clear ``NotImplementedError`` until those
    # land in a follow-up sub-PR -- a silent fallthrough would either
    # hang on a missing endpoint or return mis-shaped JSON.

    def to_iter(self, *args, **kwargs):
        """Not implemented yet on the HTTP backend.

        Requires a new ``action=iter`` server route mirroring
        :meth:`DBFlow.cursor2json_iter`'s per-edge yield shape;
        the existing ``GET /flows`` only emits the aggregated
        graph or a single ``{clients, servers, flows}`` count.
        """
        del args, kwargs
        raise NotImplementedError("to_iter is not yet supported on the HTTP backend")

    def topvalues(self, *args, **kwargs):
        """Not implemented yet on the HTTP backend (deferred)."""
        del args, kwargs
        raise NotImplementedError("topvalues is not yet supported on the HTTP backend")

    def top(self, *args, **kwargs):
        """Not implemented yet on the HTTP backend (deferred)."""
        del args, kwargs
        raise NotImplementedError("top is not yet supported on the HTTP backend")

    def flow_daily(self, *args, **kwargs):
        """Not implemented yet on the HTTP backend (deferred)."""
        del args, kwargs
        raise NotImplementedError("flow_daily is not yet supported on the HTTP backend")

    def list_precisions(self):
        """Not implemented yet on the HTTP backend (deferred)."""
        raise NotImplementedError(
            "list_precisions is not yet supported on the HTTP backend"
        )

    def reduce_precision(self, *args, **kwargs):
        """Not implemented yet on the HTTP backend (deferred)."""
        del args, kwargs
        raise NotImplementedError(
            "reduce_precision is not yet supported on the HTTP backend"
        )

    def init(self):
        """No-op on the HTTP backend.

        The remote IVRE owns the schema; the operator must run
        ``ivre flowcli --init`` against the *real* backend host
        directly.  We log a warning rather than raising so
        ``ivre flowcli --init`` against a misconfigured ``DB =
        http://...`` does not abort with a confusing
        traceback.
        """
        utils.LOGGER.warning(
            "flow init is a no-op on the HTTP backend; "
            "run flowcli --init on the remote IVRE instead",
        )

    def ensure_indexes(self):
        """No-op on the HTTP backend (see :meth:`init`)."""
        utils.LOGGER.warning(
            "flow ensure_indexes is a no-op on the HTTP backend; "
            "run flowcli --ensure-indexes on the remote IVRE instead",
        )
