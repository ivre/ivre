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


"""
This module provides the dynamic (server-side) part of the Web
interface.

It is used by the integrated web server (ivre httpd) and by the WSGI
application.
"""

import datetime
import json
import os
import tempfile
from collections import namedtuple

from bottle import abort, request, response

from ivre import VERSION, config, utils
from ivre.db import db
from ivre.db.http import FLOW_DATETIME_KEYS
from ivre.tags.active import set_auto_tags, set_openports_attribute
from ivre.tools import iprange as iprange_tool
from ivre.view import nmap_record_to_view
from ivre.web import utils as webutils
from ivre.web.base import application, check_referer, check_upload_ok
from ivre.web.modules import enabled_modules, require_module

#
# Configuration
#


@application.get("/config")
@check_referer
def get_config():
    """Returns JavaScript code to set client-side configuration values

    :status 200: no error
    :status 400: invalid referer
    :>json object config: the configuration values

    """
    response.set_header("Content-Type", "application/javascript")
    for key, value in [
        ("notesbase", config.WEB_NOTES_BASE),
        ("dflt_limit", config.WEB_LIMIT),
        ("warn_dots_count", config.WEB_WARN_DOTS_COUNT),
        ("uploadok", config.WEB_UPLOAD_OK),
        ("flow_time_precision", config.FLOW_TIME_PRECISION),
        ("version", VERSION),
        ("auth_enabled", config.WEB_AUTH_ENABLED),
        ("sequential_loading", config.WEB_SEQUENTIAL_LOADING),
        ("modules", enabled_modules()),
    ]:
        yield f"config.{key} = {json.dumps(value)};\n"
    yield f'fetch("https://ivre.rocks/version?{VERSION}").then(r=>r.text()).then(d=>config.curver=d).catch(()=>{{}});\n'


#
# /nmap/
#

FilterParams = namedtuple(
    "flt_params",
    [
        "flt",
        "sortby",
        "unused",
        "skip",
        "limit",
        "fields",
        "ipsasnumbers",
        "datesasstrings",
        "fmt",
    ],
)


def get_base(dbase):
    # we can get filters from either q= (web interface) or f= (API);
    # both are used (logical and)
    query = webutils.query_from_params(request.params)
    flt, sortby, unused, skip, limit, fields = webutils.flt_from_query(dbase, query)
    flt = dbase.flt_and(
        flt, webutils.parse_filter(dbase, json.loads(request.params.pop("f", "{}")))
    )
    if limit is None:
        limit = config.WEB_LIMIT
    if config.WEB_MAXRESULTS is not None:
        limit = min(limit, config.WEB_MAXRESULTS)
    # type of result
    ipsasnumbers = request.params.get("ipsasnumbers")
    fmt = request.params.get("format") or "json"
    if fmt not in {"txt", "json", "ndjson"}:
        fmt = "txt"
    datesasstrings = request.params.get("datesasstrings")
    if fmt == "txt":
        response.set_header("Content-Type", "text/plain")
    elif fmt == "ndjson":
        response.set_header("Content-Type", "application/x-ndjson")
    else:
        response.set_header("Content-Type", "application/json")
    response.set_header(
        "Content-Disposition", f'attachment; filename="IVRE-results.{fmt}"'
    )
    return FilterParams(
        flt,
        sortby,
        unused,
        skip,
        limit,
        fields,
        ipsasnumbers,
        datesasstrings,
        fmt,
    )


# Maps the ``subdb`` URL placeholder used by the polymorphic Nmap /
# View / Passive / RIR routes to the corresponding ``WEB_MODULES``
# name. ``scans`` is the legacy URL token for the Nmap (active)
# database; the rest are 1:1 with the module names.
_SUBDB_TO_MODULE = {
    "scans": "active",
    "view": "view",
    "passive": "passive",
    "rir": "rir",
}


@application.get(
    "/<subdb:re:scans|view>/<action:re:"
    "onlyips|ipsports|timeline|coordinates|countopenports|diffcats>"
)
@check_referer
def get_nmap_action(subdb, action):
    """Get special values from Nmap & View databases

    :param str subdb: database to query (must be "scans" or "view")
    :param str action: specific value to get (must be one of "onlyips",
                      "ipsports", "timeline", "coordinates", "countopenports"
                      or "diffcats")
    :query str q: query (including limit/skip and sort)
    :query str f: filter
    :query bool ipsasnumbers: to get IP addresses as numbers rather than as
                             strings
    :query bool datesasstrings: to get dates as strings rather than as
                               timestamps
    :query str format: "json" (the default), "ndjson" or "txt"
    :status 200: no error
    :status 400: invalid referer
    :status 404: module is not exposed by this server
    :>jsonarr object: results

    """
    require_module(_SUBDB_TO_MODULE[subdb])
    subdb = db.view if subdb == "view" else db.nmap
    flt_params = get_base(subdb)
    preamble = "[\n"
    postamble = "]\n"
    if action == "timeline":
        result, _ = subdb.get_open_port_count(flt_params.flt)
        if request.params.get("modulo") is None:

            def r2time(r):
                return int(r["starttime"].timestamp())

        else:

            def r2time(r):
                return int(r["starttime"].timestamp()) % int(
                    request.params.get("modulo")
                )

        if flt_params.ipsasnumbers:

            def r2res(r):
                return [
                    r2time(r),
                    utils.ip2int(r["addr"]),
                    r.get("openports", {}).get("count", 0),
                ]

        else:

            def r2res(r):
                return [r2time(r), r["addr"], r.get("openports", {}).get("count", 0)]

    elif action == "coordinates":

        def r2res(r):
            return {
                "type": "Point",
                "coordinates": r["_id"][::-1],
                "properties": {"count": r["count"]},
            }

        preamble = '{"type": "GeometryCollection", "geometries": [\n'
        postamble = "]}\n"
        result = list(subdb.getlocations(flt_params.flt))
    elif action == "countopenports":
        result, _ = subdb.get_open_port_count(flt_params.flt)
        if flt_params.ipsasnumbers:

            def r2res(r):
                return [utils.ip2int(r["addr"]), r.get("openports", {}).get("count", 0)]

        else:

            def r2res(r):
                return [r["addr"], r.get("openports", {}).get("count", 0)]

    elif action == "ipsports":
        result, _ = subdb.get_ips_ports(flt_params.flt)
        if flt_params.ipsasnumbers:

            def r2res(r):
                return [
                    utils.ip2int(r["addr"]),
                    [
                        [p["port"], p["state_state"]]
                        for p in r.get("ports", [])
                        if "state_state" in p
                    ],
                ]

        else:

            def r2res(r):
                return [
                    r["addr"],
                    [
                        [p["port"], p["state_state"]]
                        for p in r.get("ports", [])
                        if "state_state" in p
                    ],
                ]

    elif action == "onlyips":
        result, _ = subdb.get_ips(flt_params.flt)
        if flt_params.ipsasnumbers:

            def r2res(r):
                return utils.ip2int(r["addr"])

        else:

            def r2res(r):
                return r["addr"]

    elif action == "diffcats":

        def r2res(r):
            return r

        if request.params.get("onlydiff"):
            output = subdb.diff_categories(
                request.params.get("cat1"),
                request.params.get("cat2"),
                flt=flt_params.flt,
                include_both_open=False,
            )
        else:
            output = subdb.diff_categories(
                request.params.get("cat1"),
                request.params.get("cat2"),
                flt=flt_params.flt,
            )
        result = {}
        if flt_params.ipsasnumbers:
            for res in output:
                result.setdefault(res["addr"], []).append([res["port"], res["value"]])
        else:
            for res in output:
                result.setdefault(utils.int2ip(res["addr"]), []).append(
                    [res["port"], res["value"]]
                )
        result = result.items()

    if flt_params.fmt == "txt":
        for rec in result:
            # pylint: disable=possibly-used-before-assignment
            yield f"{r2res(rec)}\n"
        return

    if flt_params.fmt == "ndjson":
        for rec in result:
            yield f"{json.dumps(r2res(rec))}\n"
        return

    yield preamble

    # hack to avoid a trailing comma
    result = iter(result)
    try:
        rec = next(result)
    except StopIteration:
        pass
    else:
        yield json.dumps(r2res(rec))
        for rec in result:
            yield f",\n{json.dumps(r2res(rec))}"
        yield "\n"

    yield postamble
    yield "\n"


@application.get("/<subdb:re:scans|view>/count")
@check_referer
def get_nmap_count(subdb):
    """Get special values from Nmap & View databases

    :param str subdb: database to query (must be "scans" or "view")
    :query str q: query (including limit/skip and sort)
    :query str f: filter
    :status 200: no error
    :status 400: invalid referer
    :status 404: module is not exposed by this server
    :>json int: count

    """
    require_module(_SUBDB_TO_MODULE[subdb])
    subdb = db.view if subdb == "view" else db.nmap
    flt_params = get_base(subdb)
    count = subdb.count(flt_params.flt)
    return f"{count}\n"


@application.get("/<subdb:re:scans|view|passive|rir>/top/<field:path>")
@check_referer
def get_top(subdb, field):
    """Get top values from Nmap, View, Passive & RIR databases

    :param str subdb: database to query (must be "scans", "view",
                      "passive" or "rir")
    :param str field: (pseudo-)field to get top values (e.g., "service")
    :query str q: query (including limit/skip and sort)
    :query str f: filter
    :query bool ipsasnumbers: to get IP addresses as numbers rather than as
                             strings
    :query bool datesasstrings: to get dates as strings rather than as
                               timestamps
    :query str format: "json" (the default) or "ndjson"
    :status 200: no error
    :status 400: invalid referer
    :status 404: module is not exposed by this server
    :>jsonarr str label: field value
    :>jsonarr int value: count for this value

    """
    require_module(_SUBDB_TO_MODULE[subdb])
    subdb = {
        "passive": db.passive,
        "rir": db.rir,
        "scans": db.nmap,
        "view": db.view,
    }[subdb]
    flt_params = get_base(subdb)
    if field[0] in "-!":
        field = field[1:]
        least = True
    else:
        least = False
    topnbr = 15
    if ":" in field:
        field, topnbr = field.rsplit(":", 1)
        try:
            topnbr = int(topnbr)
        except ValueError:
            field = f"{field}:{topnbr}"
            topnbr = 15
    cursor = subdb.topvalues(
        field,
        flt=flt_params.flt,
        least=least,
        topnbr=topnbr,
    )
    if flt_params.fmt == "ndjson":
        for rec in cursor:
            yield json.dumps({"label": rec["_id"], "value": rec["count"]})
        return
    yield "[\n"
    # hack to avoid a trailing comma
    cursor = iter(cursor)
    try:
        rec = next(cursor)
    except StopIteration:
        pass
    else:
        yield json.dumps({"label": rec["_id"], "value": rec["count"]})
        for rec in cursor:
            yield f",\n{json.dumps({'label': rec['_id'], 'value': rec['count']})}"
    yield "\n]\n"


@application.get("/<subdb:re:scans|view|passive|rir>/distinct/<field:path>")
@check_referer
def get_distinct(subdb, field):
    """Get distinct values from Nmap, View, Passive & RIR databases

    :param str subdb: database to query (must be "scans", "view",
                      "passive" or "rir")
    :param str field: (pseudo-)field to get distinct values (e.g., "service")
    :query str q: query (including limit/skip and sort)
    :query str f: filter
    :query bool ipsasnumbers: to get IP addresses as numbers rather than as
                             strings
    :query bool datesasstrings: to get dates as strings rather than as
                               timestamps
    :query str format: "json" (the default) or "ndjson"
    :status 200: no error
    :status 400: invalid referer
    :status 404: module is not exposed by this server
    :>jsonarr str label: field value
    :>jsonarr int value: count for this value

    """
    require_module(_SUBDB_TO_MODULE[subdb])
    subdb = {
        "passive": db.passive,
        "rir": db.rir,
        "scans": db.nmap,
        "view": db.view,
    }[subdb]
    flt_params = get_base(subdb)
    cursor = subdb.distinct(
        field,
        flt=flt_params.flt,
        sort=flt_params.sortby,
        limit=flt_params.limit or subdb.no_limit,
        skip=flt_params.skip,
    )
    if flt_params.fmt == "ndjson":
        for rec in cursor:
            yield f"{json.dumps(rec)}\n"
        return
    yield "[\n"
    # hack to avoid a trailing comma
    cursor = iter(cursor)
    try:
        rec = next(cursor)
    except StopIteration:
        pass
    else:
        yield json.dumps(rec)
        for rec in cursor:
            yield f",\n{json.dumps(rec)}"
    yield "\n]\n"


def _convert_datetime_value(value):
    """Coerce a passive-record datetime field to a Unix timestamp
    (seconds since epoch) for JSON serialisation.

    The fields covered by ``DBPassive.datetime_fields`` —
    ``firstseen``, ``lastseen``, ``infos.not_after``,
    ``infos.not_before`` — usually arrive here as
    ``datetime.datetime`` instances (BSON Date for the MongoDB
    backend), but real-world datasets also contain numeric
    timestamps (older ingestion paths stored cert validity dates
    as ``float`` seconds) and ISO-ish strings (cert dates emitted
    by some Zeek scripts as ``"YYYY-MM-DD HH:MM:SS"``). All three
    are accepted; anything else propagates as a ``TypeError`` so
    we do not silently mangle unexpected input.
    """
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        value = utils.all2datetime(value)
    return int(value.replace(tzinfo=datetime.timezone.utc).timestamp())


def _set_datetime_field(dbase, record, field, current=None):
    if current is None:
        current = []
    if "." not in field:
        if field in record:
            if ".".join(current + [field]) in dbase.list_fields:
                record[field] = [
                    _convert_datetime_value(value) for value in record[field]
                ]
            else:
                record[field] = _convert_datetime_value(record[field])
        return
    nextfield, field = field.split(".", 1)
    if nextfield not in record:
        return
    current = current + [nextfield]
    if ".".join(current) in dbase.list_fields:
        for subrecord in record[nextfield]:
            _set_datetime_field(dbase, subrecord, field, current=current)
    else:
        _set_datetime_field(dbase, record[nextfield], field, current=current)


@application.get("/<subdb:re:scans|view>")
@check_referer
def get_nmap(subdb):
    """Get records from Nmap & View databases

    :param str subdb: database to query (must be "scans" or "view")
    :query str q: query (including limit/skip and sort)
    :query str f: filter
    :query bool ipsasnumbers: to get IP addresses as numbers rather than as
                             strings
    :query bool datesasstrings: to get dates as strings rather than as
                               timestamps
    :query str format: "json" (the default) or "ndjson"
    :status 200: no error
    :status 400: invalid referer
    :status 404: module is not exposed by this server
    :>jsonarr object: results

    """
    require_module(_SUBDB_TO_MODULE[subdb])
    subdb_tool = "view" if subdb == "view" else "scancli"
    subdb = db.view if subdb == "view" else db.nmap
    flt_params = get_base(subdb)
    # PostgreSQL: the query plan if affected by the limit and gives
    # really poor results. This is a temporary workaround (look for
    # XXX-WORKAROUND-PGSQL).
    # result = subdb.get(flt_params.flt, limit=flt_params.limit,
    #                    skip=flt_params.skip, sort=flt_params.sortby)
    result = subdb.get(
        flt_params.flt,
        skip=flt_params.skip,
        sort=flt_params.sortby,
        fields=flt_params.fields,
    )

    if flt_params.unused:
        msg = f"Option{'s' if len(flt_params.unused) > 1 else ''} not understood: {', '.join(flt_params.unused)}"
        utils.LOGGER.warning(msg)

    if config.DEBUG:
        utils.LOGGER.debug("filter: %r", subdb.flt2str(flt_params.flt))
        utils.LOGGER.debug("user: %r", webutils.get_user())

    version_mismatch = {}
    if flt_params.fmt == "json":
        yield "[\n"
    # XXX-WORKAROUND-PGSQL
    # for rec in result:
    for i, rec in enumerate(result):
        try:
            del rec["_id"]
        except KeyError:
            pass
        if flt_params.ipsasnumbers:
            rec["addr"] = utils.force_ip2int(rec["addr"])
        if not flt_params.datesasstrings:
            for field in subdb.datetime_fields:
                _set_datetime_field(subdb, rec, field)
        for port in rec.get("ports", []):
            if "screendata" in port:
                port["screendata"] = utils.encode_b64(port["screendata"])
            for script in port.get("scripts", []):
                if "masscan" in script:
                    try:
                        del script["masscan"]["raw"]
                    except KeyError:
                        pass
        if not flt_params.ipsasnumbers:
            if "traces" in rec:
                for trace in rec["traces"]:
                    trace["hops"].sort(key=lambda x: x["ttl"])
                    for hop in trace["hops"]:
                        hop["ipaddr"] = utils.force_int2ip(hop["ipaddr"])
        addresses = rec.get("addresses", {}).get("mac")
        if addresses:
            newaddresses = []
            for addr in addresses:
                manuf = utils.mac2manuf(addr)
                if manuf and manuf[0]:
                    newaddresses.append({"addr": addr, "manuf": manuf[0]})
                else:
                    newaddresses.append({"addr": addr})
            rec["addresses"]["mac"] = newaddresses
        if flt_params.fmt == "ndjson":
            yield f"{json.dumps(rec, default=utils.serialize)}\n"
        else:
            yield "%s\t%s" % (
                ",\n" if i else "",
                json.dumps(rec, default=utils.serialize),
            )
        check = subdb.cmp_schema_version_host(rec)
        if check:
            version_mismatch[check] = version_mismatch.get(check, 0) + 1
        # XXX-WORKAROUND-PGSQL
        if flt_params.limit and i + 1 >= flt_params.limit:
            break
    if flt_params.fmt == "json":
        yield "\n]\n"

    messages = {
        1: lambda count: (
            f"{count} document{'s' if count > 1 else ''} displayed {'are' if count > 1 else 'is'} out-of-date. Please run the following command: 'ivre {subdb_tool} --update-schema;"
        ),
        -1: lambda count: (
            f"{count} document{'s' if count > 1 else ''} displayed ha{'ve' if count > 1 else 's'} been inserted by a more recent version of IVRE. Please update IVRE!"
        ),
    }
    for mismatch, count in version_mismatch.items():
        utils.LOGGER.warning(messages[mismatch](count))


#
# Upload scans
#


def parse_form():
    categories = request.forms.get("categories")
    categories = set(categories.split(",")) if categories else set()
    source = request.forms.get("source")
    if not source:
        utils.LOGGER.critical("source is mandatory")
        abort(400, "ERROR: source is mandatory\n")
    files = request.files.getall("result")
    return (request.forms.get("referer"), source, categories, files)


def import_files(subdb, source, categories, files):
    count = 0
    categories = sorted(categories)
    if subdb == "view":

        def callback(x):
            result = nmap_record_to_view(x)
            set_auto_tags(result, update_openports=False)
            set_openports_attribute(result)
            result["infos"] = {}
            for func in [
                db.data.country_byip,
                db.data.as_byip,
                db.data.location_byip,
            ]:
                result["infos"].update(func(result["addr"]) or {})
            db.view.store_or_merge_host(result)

        db.view.start_store_hosts()
    else:
        callback = None
    for fileelt in files:
        with tempfile.NamedTemporaryFile(delete=False) as fdesc:
            fileelt.save(fdesc)
        try:
            if db.nmap.store_scan(
                fdesc.name, categories=categories, source=source, callback=callback
            ):
                count += 1
                os.unlink(fdesc.name)
            else:
                utils.LOGGER.warning("Could not import %s", fdesc.name)
        except Exception:
            utils.LOGGER.warning("Could not import %s", fdesc.name, exc_info=True)
    if callback is not None:
        db.view.stop_store_hosts()
    return count


@application.post("/<subdb:re:scans|view>")
@check_referer
@check_upload_ok
def post_nmap(subdb):
    """Add records to Nmap & View databases

    :param str subdb: database to query (must be "scans" or "view")
    :form categories: a coma-separated list of categories
    :form source: the source of the scan results (mandatory)
    :form result: scan results (as XML or JSON files)
    :status 200: no error
    :status 400: invalid referer, source or username missing
    :status 403: uploads disabled (``WEB_UPLOAD_OK`` is ``False``)
    :status 404: module is not exposed by this server
    :>json int count: number of inserted results

    """
    require_module(_SUBDB_TO_MODULE[subdb])
    referer, source, categories, files = parse_form()
    count = import_files(subdb, source, categories, files)
    if request.params.get("output") == "html":
        response.set_header("Refresh", f"5;url={referer}")
        return f"""<html>
  <head>
    <title>IVRE Web UI</title>
  </head>
  <body style="padding-top: 2%; padding-left: 2%">
    <h1>{int(count)} result{'s' if count > 1 else ''} uploaded</h1>
  </body>
</html>"""
    return {"count": count}


#
# /flow/
#


@application.get("/flows")
@check_referer
def get_flow():
    """Get a flow graph, count, or details payload.

    The query is JSON-encoded under the ``q`` URL parameter and
    carries ``nodes`` / ``edges`` filter lists in the
    ``flow.Query`` grammar plus the pagination / mode knobs
    listed below. ``action=details`` returns details for a single
    node or edge instead of a graph.

    :query str q: JSON-encoded query object. Recognised keys:

         - ``nodes``   list of node-filter clauses
         - ``edges``   list of edge-filter clauses
         - ``limit``   cap on returned edges; defaults to
                       ``config.WEB_GRAPH_LIMIT`` (1000)
         - ``skip``    pagination offset; defaults to ``0``
         - ``mode``    ``default`` / ``flow_map`` / ``talk_map``
         - ``count``   ``true`` returns ``{clients, servers,
                       flows}`` instead of the graph
         - ``orderby`` ``src`` / ``dst`` / ``flow`` (or unset)
         - ``timeline`` ``true`` embeds ``data.meta.times`` per edge
         - ``before`` / ``after``  ``"YYYY-MM-DD HH:MM"`` time bounds
    :query str action: ``"details"`` to fetch
                       ``host_details`` / ``flow_details`` for the
                       node or edge id supplied in ``q.id``;
                       ``q.type`` is ``"node"`` or ``"edge"``.
    :status 200: no error
    :status 400: invalid referer
    :status 404: module is not exposed by this server, or
                 ``action=details`` and the entity does not exist
    :>json object: results

    """
    require_module("flow")
    response.set_header("Content-Type", "application/json")
    response.set_header(
        "Content-Disposition", 'attachment; filename="IVRE-results.json"'
    )
    action = request.params.get("action", "")
    utils.LOGGER.debug("Params: %r", dict(request.params))
    query = json.loads(request.params.get("q", "{}"))
    limit = query.get("limit", config.WEB_GRAPH_LIMIT)
    # Default ``skip`` to ``0`` (was historically the same as
    # ``WEB_GRAPH_LIMIT`` \u2014 a copy-paste bug that made callers
    # who omitted ``skip`` paginate past the entire result set).
    # Clients that want a non-zero offset must set it explicitly.
    skip = query.get("skip", 0)
    mode = query.get("mode", "default")
    count = query.get("count", False)
    orderby = query.get("orderby", None)
    timeline = query.get("timeline", False)
    try:
        before = datetime.datetime.strptime(query["before"], "%Y-%m-%d %H:%M")
    except (TypeError, ValueError) as e:
        utils.LOGGER.warning(str(e))
        before = None
    except KeyError:
        before = None
    try:
        after = datetime.datetime.strptime(query["after"], "%Y-%m-%d %H:%M")
    except (TypeError, ValueError) as e:
        utils.LOGGER.warning(str(e))
        after = None
    except KeyError:
        after = None

    utils.LOGGER.debug("Action: %r, Query: %r", action, query)
    if action == "details":
        # TODO: error
        if query["type"] == "node":
            res = db.flow.host_details(query["id"])
        else:
            res = db.flow.flow_details(query["id"])
        if res is None:
            abort(404, "Entity not found")
    else:
        cquery = db.flow.from_filters(
            query,
            limit=limit,
            skip=skip,
            orderby=orderby,
            mode=mode,
            timeline=timeline,
            after=after,
            before=before,
        )
        if count:
            res = db.flow.count(cquery)
        else:
            res = db.flow.to_graph(
                cquery,
                limit=limit,
                skip=skip,
                orderby=orderby,
                mode=mode,
                timeline=timeline,
                after=after,
                before=before,
            )
    yield json.dumps(res, default=utils.serialize)
    yield "\n"


def _flow_record_from_payload(rec):
    """Rebuild a parsed flow record from its JSON wire form.

    The :class:`ivre.db.http.HttpDBFlow` ingestion path serialises
    the canonical datetime keys listed in
    :data:`ivre.db.http.FLOW_DATETIME_KEYS` (``start_time`` /
    ``end_time`` / ``ts``) as epoch floats so the wire format
    stays JSON-native.  Convert them back to :class:`datetime`
    objects so the backend's ``any2flow`` / ``conn2flow`` /
    ``flow2flow`` helpers see the same shapes their direct
    callers (``zeek2db`` / ``flow2db``) produce.

    Sourcing the key set from
    :data:`~ivre.db.http.FLOW_DATETIME_KEYS` keeps the wire
    contract symmetric with the client-side
    :meth:`HttpDBFlow._serialize_record`: every key the client
    folds to a float is rebuilt here, and any other ``datetime``
    value would have raised at ``json.dumps`` time on the client
    rather than silently arriving as a float here.
    """
    if not isinstance(rec, dict):
        abort(400, "ERROR: record must be an object\n")
    out = dict(rec)
    for ts_key in FLOW_DATETIME_KEYS:
        if ts_key in out and isinstance(out[ts_key], (int, float)):
            out[ts_key] = datetime.datetime.fromtimestamp(out[ts_key])
    return out


@application.post("/flows")
@check_referer
@check_upload_ok
def post_flow():
    """Ingest a bulk of flow records.

    Mirrors the bulk-insert API documented in
    :class:`ivre.db.mongo.MongoDBFlow`: the request body is a
    JSON object ``{"records": [{"kind": "...", ...}, ...]}``
    where each entry carries one of the three ingestion kinds:

    * ``{"kind": "any", "name": "<zeek-log>", "rec": {...}}``
      maps to :meth:`db.flow.any2flow`,
    * ``{"kind": "conn", "rec": {...}}`` maps to
      :meth:`db.flow.conn2flow`,
    * ``{"kind": "flow", "rec": {...}}`` maps to
      :meth:`db.flow.flow2flow`.

    Records are dispatched in order, then a single
    :meth:`db.flow.bulk_commit` flushes the bulk.  Returns
    ``{"count": <records-ingested>}``.

    :status 200: no error
    :status 400: invalid referer or malformed body
    :status 403: uploads disabled (``WEB_UPLOAD_OK`` is ``False``)
    :status 404: module is not exposed by this server
    :>json int count: number of records ingested
    """
    require_module("flow")
    response.set_header("Content-Type", "application/json")
    try:
        payload = json.loads(request.body.read())
    except (TypeError, ValueError) as exc:
        abort(400, f"ERROR: invalid JSON body: {exc}\n")
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        abort(400, "ERROR: 'records' must be a list\n")
    bulk = db.flow.start_bulk_insert()
    count = 0
    for entry in records:
        if not isinstance(entry, dict):
            abort(400, "ERROR: each record must be an object\n")
        kind = entry.get("kind")
        rec = _flow_record_from_payload(entry.get("rec"))
        if kind == "any":
            name = entry.get("name")
            if not isinstance(name, str):
                abort(400, "ERROR: 'any' records must carry a string 'name'\n")
            db.flow.any2flow(bulk, name, rec)
        elif kind == "conn":
            db.flow.conn2flow(bulk, rec)
        elif kind == "flow":
            db.flow.flow2flow(bulk, rec)
        else:
            abort(400, f"ERROR: unknown record kind {kind!r}\n")
        count += 1
    db.flow.bulk_commit(bulk)
    return {"count": count}


@application.post("/flows/cleanup")
@check_referer
@check_upload_ok
def post_flow_cleanup():
    """Run the backend's ``cleanup_flows`` heuristic.

    The handler dispatches to the configured backend's
    :meth:`cleanup_flows` (a no-op on the SQL backend until
    the host-swap heuristic is ported); the response carries
    no body besides ``{"status": "ok"}`` so the
    :class:`ivre.db.http.HttpDBFlow` client can treat any
    non-2xx as an error.

    :status 200: cleanup completed
    :status 400: invalid referer
    :status 403: uploads disabled (``WEB_UPLOAD_OK`` is ``False``)
    :status 404: module is not exposed by this server
    """
    require_module("flow")
    response.set_header("Content-Type", "application/json")
    db.flow.cleanup_flows()
    return {"status": "ok"}


#
# /ipdata/
#


@application.get("/ipdata/<addr>")
@check_referer
def get_ipdata(addr):
    """Returns (estimated) geographical and AS data for a given IP address.

    :param str addr: IP address to query
    :status 200: no error
    :status 400: invalid referer
    :>json object: the result values

    """
    response.set_header("Content-Type", "application/json")
    return f"{json.dumps(db.data.infos_byip(addr))}\n"


#
# /iprange/ -- enumerate IPs from a selector
#


def _iprange_param(name: str) -> str | None:
    """Return the trimmed value of query parameter ``name`` or
    ``None`` when missing / empty.  Bottle keeps query strings as
    plain text; trimming here lets the helpers below treat a
    blank parameter the same as an unset one.
    """
    value = request.query.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


@application.get("/iprange")
@check_referer
def get_iprange():
    """Enumerate IP addresses matching a selector (country, AS,
    network, range, or all routable IPs).

    Exactly one selector must be set.  The response always
    carries ``count``; the additional fields depend on
    ``output``.

    :query country: comma-separated ISO 3166-1 alpha-2 codes
    :query registered_country: comma-separated ISO 3166-1 codes
        matched against the "registered" GeoIP attribute
    :query region: ``CC,REGION`` (country code, region code)
    :query city: ``CC,CITY`` (country code, city name)
    :query asnum: comma-separated AS numbers (``AS3215`` or ``3215``)
    :query range_start: start of an explicit address range
    :query range_stop: stop of an explicit address range
    :query network: CIDR network
    :query routable: any truthy value selects the full routable
        APNIC BGP set
    :query output: one of ``count`` / ``ranges`` / ``cidrs``
        (default) / ``addrs``
    :query limit: cap the number of returned entries
    :status 200: no error
    :status 400: invalid selector, output or input combination
    :>json int count: total number of IP addresses matched
    :>json array cidrs: list of CIDRs (``output=cidrs``)
    :>json array ranges: list of ``[start, stop]`` pairs (``output=ranges``)
    :>json array addrs: list of IP strings (``output=addrs``, capped)

    """
    response.set_header("Content-Type", "application/json")
    output = _iprange_param("output") or iprange_tool.OUTPUT_CIDRS
    if output not in iprange_tool.OUTPUT_FORMATS or output == iprange_tool.OUTPUT_JSON:
        # ``output=json`` is the CLI shortcut for "count + ranges
        # + cidrs in one payload"; over HTTP that is the natural
        # shape of every response, so the alias is rejected to
        # keep the response contract single-valued.
        abort(400, f"ERROR: invalid output mode {output!r}\n")

    region_raw = _iprange_param("region")
    city_raw = _iprange_param("city")
    range_start = _iprange_param("range_start")
    range_stop = _iprange_param("range_stop")
    routable_raw = _iprange_param("routable")

    def _parse_pair(name: str, raw: str) -> tuple[str, str]:
        parts = [p.strip() for p in raw.split(",", 1)]
        if len(parts) != 2 or not all(parts):
            abort(400, f"ERROR: {name}= expects two comma-separated values\n")
        return parts[0], parts[1]

    region = _parse_pair("region", region_raw) if region_raw else None
    city = _parse_pair("city", city_raw) if city_raw else None
    if (range_start is None) != (range_stop is None):
        abort(400, "ERROR: range_start and range_stop must both be set\n")
    address_range = (range_start, range_stop) if range_start else None
    routable = routable_raw is not None and routable_raw.lower() not in (
        "0",
        "false",
        "no",
    )

    limit_raw = _iprange_param("limit")
    try:
        limit = int(limit_raw) if limit_raw is not None else None
    except ValueError:
        abort(400, f"ERROR: limit must be an integer (got {limit_raw!r})\n")
    if limit is not None and limit < 0:
        abort(400, "ERROR: limit must be non-negative\n")

    try:
        ranges = iprange_tool.select_ipranges(
            country=_iprange_param("country"),
            registered_country=_iprange_param("registered_country"),
            region=region,
            city=city,
            asnum=_iprange_param("asnum"),
            address_range=address_range,
            network=_iprange_param("network"),
            routable=routable,
            file=None,  # file-based input is CLI-only
        )
        result = iprange_tool.format_ipranges(
            ranges,
            output,
            limit=limit,
            addrs_cap=config.WEB_IPRANGE_ADDR_CAP,
        )
    except iprange_tool.IPRangeError as exc:
        abort(400, f"ERROR: {exc}\n")
    # ``format_ipranges`` returns ``{"count": N, "value": ...}``;
    # the web contract surfaces ``count`` alongside an output-named
    # field, matching what the CLI's ``--json`` shape emits for
    # the count + cidrs + ranges combo.
    payload: dict[str, object] = {"count": result["count"]}
    if output == iprange_tool.OUTPUT_COUNT:
        return f"{json.dumps(payload)}\n"
    payload[output] = result["value"]
    return f"{json.dumps(payload)}\n"


#
# Passive (/passivedns/)
#


@application.get("/passivedns/<query:path>")
@check_referer
def get_passivedns(query):
    """Query passive DNS data. This API is compatible with the `Common
    Output Format
    <https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/>`_
    and implemented in CIRCL's `PyPDNS
    <https://github.com/CIRCL/PyPDNS>`_.

    It accepts two extra parameters, not supported (yet?) in PyPDNS:

      - `subdomains`: if this parameter exists and a domain name is
        queried, records for any subdomains will also be returned.

      - `reverse`: if this parameter exists and a domain name is queried,
        records pointing to the queried domain (CNAME, NS, MX) will be
        returned.

    It also returns additional information:

      - "sensor": the "sensor" field of the record; this is useful to know
        where this answer has been seen.

      - "source": the IP address of the DNS server sending the answer.

    :param str query: IP address or domains name to query
    :query bool subdomains: query subdomains (domain name only)
    :query bool reverse: use a reverse query (domain name only)
    :query str type: specify the DNS query type
    :status 200: no error
    :status 400: invalid referer
    :status 404: passive module is not exposed by this server
    :>json object: the result values (JSONL format: one JSON result per line)

    """
    require_module("passive")
    subdomains = request.params.get("subdomains") is not None
    reverse = request.params.get("reverse") is not None
    utils.LOGGER.debug("passivedns: query: %r, subdomains: %r", query, subdomains)

    if utils.IPADDR.search(query) or query.isdigit():
        flt = db.passive.flt_and(
            db.passive.searchdns(dnstype=request.params.get("type")),
            db.passive.searchhost(query),
        )
    elif utils.NETADDR.search(query):
        flt = db.passive.flt_and(
            db.passive.searchdns(dnstype=request.params.get("type")),
            db.passive.searchnet(query),
        )
    else:
        flt = db.passive.searchdns(
            name=query,
            dnstype=request.params.get("type"),
            subdomains=subdomains,
            reverse=reverse,
        )
    for rec in db.passive.get(flt):
        for k in ["_id", "infos", "recontype", "schema_version"]:
            try:
                del rec[k]
            except KeyError:
                pass
        rec["rrtype"], rec["source"], _ = rec["source"].split("-")
        rec["rrname"] = rec.pop("value")
        try:
            rec["rdata"] = rec.pop("addr")
        except KeyError:
            rec["rdata"] = rec.pop("targetval")
        for k in ["first", "last"]:
            try:
                rec[f"time_{k}"] = rec.pop(f"{k}seen")
            except KeyError:
                pass
        yield f"{json.dumps(rec, default=utils.serialize)}\n"


@application.get("/passive")
@check_referer
def get_passive():
    """Get records from Passive database

    :query str q: query (only used for limit/skip and sort)
    :query str f: filter
    :query bool ipsasnumbers: to get IP addresses as numbers rather than as
                             strings
    :query bool datesasstrings: to get dates as strings rather than as
                               timestamps
    :query str format: "json" (the default) or "ndjson"
    :status 200: no error
    :status 400: invalid referer
    :status 404: passive module is not exposed by this server
    :>jsonarr object: results

    """
    require_module("passive")
    flt_params = get_base(db.passive)
    # PostgreSQL: the query plan if affected by the limit and gives
    # really poor results. This is a temporary workaround (look for
    # XXX-WORKAROUND-PGSQL).
    # result = db.passive.get(flt_params.flt, limit=flt_params.limit,
    #                         skip=flt_params.skip, sort=flt_params.sortby)
    result = db.passive.get(
        flt_params.flt,
        skip=flt_params.skip,
        sort=flt_params.sortby,
        fields=flt_params.fields,
    )
    if flt_params.fmt == "json":
        yield "[\n"
    # XXX-WORKAROUND-PGSQL
    # for rec in result:
    for i, rec in enumerate(result):
        try:
            del rec["_id"]
        except KeyError:
            pass
        if "addr" in rec and flt_params.ipsasnumbers:
            rec["addr"] = utils.force_ip2int(rec["addr"])
        if not flt_params.datesasstrings:
            for field in db.passive.datetime_fields:
                _set_datetime_field(db.passive, rec, field)
        # Note: ``SSL_SERVER`` / ``SSL_CLIENT`` cert records
        # arrive here with ``value`` already base64-encoded as a
        # ``str`` — that conversion is the responsibility of the
        # ``db.passive`` backend (``MongoDBPassive.internal2rec``
        # for the production backend), not this route.
        if flt_params.fmt == "ndjson":
            yield f"{json.dumps(rec, default=utils.serialize)}\n"
        else:
            yield "%s\t%s" % (
                ",\n" if i else "",
                json.dumps(rec, default=utils.serialize),
            )
        if flt_params.limit and i + 1 >= flt_params.limit:
            break
    if flt_params.fmt == "json":
        yield "\n]\n"


@application.get("/passive/count")
@check_referer
def get_passive_count():
    """Get special values from Nmap & View databases

    :query str q: query (only used for limit/skip and sort)
    :query str f: filter
    :status 200: no error
    :status 400: invalid referer
    :status 404: passive module is not exposed by this server
    :>json int: count

    """
    require_module("passive")
    flt_params = get_base(db.passive)
    count = db.passive.count(flt_params.flt)
    return f"{count}\n"


#
# DNS (/dns/)
#


def _serialize_dns_record(rec, datesasstrings):
    """Convert a merged DNS pseudo-record (sets, datetimes) into a
    JSON-friendly dict."""
    out = dict(rec)
    out["types"] = sorted(out.get("types", ()))
    out["sources"] = sorted(out.get("sources", ()))
    for field in ("firstseen", "lastseen"):
        value = out.get(field)
        if value is None:
            continue
        if isinstance(value, datetime.datetime):
            if datesasstrings:
                out[field] = str(value)
            else:
                out[field] = int(
                    value.replace(tzinfo=datetime.timezone.utc).timestamp()
                )
    return out


@application.get("/dns")
@check_referer
def get_dns():
    """Return a merged DNS view across the active scan database
    (``db.nmap``) and the passive observation database
    (``db.passive``).

    Each result is a pseudo-record keyed on ``(name, addr)``:
    a single row aggregates every observation of that pair
    across both backends, with ``count`` being the sum of the
    per-source counts (``rec['count']`` on the passive side,
    one per matching nmap document on the active side).
    ``types`` and ``sources`` are unions of the contributing
    backend values (e.g. ``["A", "PTR", "user"]``,
    ``["sensor1", "scan-2024-Q1"]``); ``firstseen`` /
    ``lastseen`` extend the union of the contributing
    intervals.

    Results are sorted ``lastseen`` descending, then ``count``
    descending. The user's ``q=`` filter is applied to *both*
    backends — tokens that are meaningful only on one side
    (e.g. ``recontype:`` on passive, ``port:`` on nmap) are
    silently dropped on the other via the standard
    ``hasattr(dbase, "searchXXX")`` gate in
    ``flt_from_query``.

    Note: the merge happens in-process; every contributing
    record is materialised before sorting and pagination. The
    server-side ``MONGODB_QUERY_TIMEOUT_MS`` cap bounds the
    worst-case request time. For deployments where this
    matters, a future change can introduce a materialised
    summary collection updated at ingest time.

    :query str q: query (filter, plus ``skip``, ``limit`` meta-params)
    :query bool datesasstrings: emit ISO-ish date strings rather than Unix timestamps
    :query str format: ``"json"`` (default) or ``"ndjson"``
    :status 200: no error
    :status 400: invalid referer
    :status 404: dns module is not exposed by this server
    :>jsonarr object: pseudo-records as ``{name, addr, count, firstseen, lastseen, types, sources}``
    """
    require_module("dns")
    raw_query = webutils.query_from_params(request.params)
    # Extract limit / skip from the parsed query (they are the
    # same regardless of backend; ``flt_from_query`` consumes
    # them too, but we re-parse here so we own the pagination).
    skip = 0
    limit = None
    for neg, param, value in raw_query:
        if neg:
            continue
        if param == "skip":
            skip = int(value)
        elif param == "limit":
            limit = int(value)
    if limit is None:
        limit = config.WEB_LIMIT
    if config.WEB_MAXRESULTS is not None:
        limit = min(limit, config.WEB_MAXRESULTS)

    # Aggregate from each available backend, merging into a
    # single ``(name, addr) -> {types, sources, firstseen,
    # lastseen, count}`` dict. Each backend is consulted only
    # when ``db.<purpose>`` is wired — ``require_module("dns")``
    # above guarantees that *at least one* of the two is
    # present, but a partial deployment (only nmap, or only
    # passive) is supported.
    merged: dict = {}
    if db.nmap is not None:
        nmap_flt, _, _, _, _, _ = webutils.flt_from_query(db.nmap, raw_query)
        utils.merge_dns_results(merged, db.nmap.iter_dns(flt=nmap_flt))
    if db.passive is not None:
        passive_flt, _, _, _, _, _ = webutils.flt_from_query(db.passive, raw_query)
        utils.merge_dns_results(merged, db.passive.iter_dns(flt=passive_flt))

    # Sort lastseen DESC, count DESC. The lastseen tie-breaker
    # surfaces frequently-observed pairs above one-shots when
    # they were last seen at the same instant.
    items = [
        {"name": name, "addr": addr, **values}
        for (name, addr), values in merged.items()
    ]
    items.sort(key=lambda r: (r["lastseen"], r["count"]), reverse=True)
    items = items[skip : skip + limit]

    datesasstrings = bool(request.params.get("datesasstrings"))
    fmt = request.params.get("format") or "json"
    if fmt not in {"json", "ndjson"}:
        fmt = "json"
    if fmt == "ndjson":
        response.set_header("Content-Type", "application/x-ndjson")
    else:
        response.set_header("Content-Type", "application/json")
    response.set_header("Content-Disposition", f'attachment; filename="IVRE-dns.{fmt}"')

    serialized = [_serialize_dns_record(r, datesasstrings) for r in items]

    if fmt == "ndjson":
        for rec in serialized:
            yield f"{json.dumps(rec, default=utils.serialize)}\n"
    else:
        yield "[\n"
        for i, rec in enumerate(serialized):
            yield "%s%s" % (
                ",\n" if i else "",
                json.dumps(rec, default=utils.serialize),
            )
        yield "\n]\n"


#
# RIR (/rir/)
#


@application.get("/rir")
@check_referer
def get_rir():
    """Get records from the RIR database.

    Records are sorted narrowest-first by default (most-specific
    inet[6]num allocation at the top), so a ``host:`` / ``net:`` /
    ``range:`` filter naturally surfaces the leaf record covering the
    queried address. ``aut-num`` records (no range, no ``size``) sort
    to the end. Pass ``?sortby=<field>`` (or ``?sortby=~<field>`` for
    descending) to override.

    :query str q: query (only used for limit/skip and sort)
    :query str f: filter
    :query str format: "json" (the default) or "ndjson"
    :query str sortby: optional sort field; default is ``size``
                       ascending then ``start`` descending then
                       ``stop`` ascending (narrowest range first)
    :status 200: no error
    :status 400: invalid referer
    :status 404: rir module is not exposed by this server
    :>jsonarr object: results

    """
    require_module("rir")
    flt_params = get_base(db.rir)
    sortby = flt_params.sortby or [
        ("size", 1),
        ("start_0", -1),
        ("start_1", -1),
        ("stop_0", 1),
        ("stop_1", 1),
    ]
    result = db.rir.get(
        flt_params.flt,
        skip=flt_params.skip,
        sort=sortby,
        fields=flt_params.fields,
    )
    if flt_params.fmt == "json":
        yield "[\n"
    for i, rec in enumerate(result):
        try:
            del rec["_id"]
        except KeyError:
            pass
        if flt_params.fmt == "ndjson":
            yield f"{json.dumps(rec, default=utils.serialize)}\n"
        else:
            yield "%s\t%s" % (
                ",\n" if i else "",
                json.dumps(rec, default=utils.serialize),
            )
        if flt_params.limit and i + 1 >= flt_params.limit:
            break
    if flt_params.fmt == "json":
        yield "\n]\n"


@application.get("/rir/count")
@check_referer
def get_rir_count():
    """Count records from the RIR database.

    :query str q: query (only used for limit/skip and sort)
    :query str f: filter
    :status 200: no error
    :status 400: invalid referer
    :status 404: rir module is not exposed by this server
    :>json int: count

    """
    require_module("rir")
    flt_params = get_base(db.rir)
    count = db.rir.count(flt_params.flt)
    return f"{count}\n"


#
# /notes/  -- per-entity markdown annotations (replaces the legacy
# Dokuwiki integration).  Keyed by (entity_type, entity_key); see
# :class:`ivre.db.DBNotes` for the storage-layer contract.
#


def _require_authenticated_user() -> str:
    """Return the authenticated user email, aborting with
    HTTP 401 when no user could be resolved.

    Helper for the notes **write paths** (``PUT`` and
    ``DELETE``) -- they need an identified user so the
    resolved email can be stamped on the persisted note as
    ``updated_by`` and the operation can be audited.  Read
    paths (``GET`` on a single note, ``GET`` on the listing,
    ``GET`` on the revisions) do not call this helper and
    remain accessible without authentication; the write-side
    auth gate is what protects against anonymous tampering.

    User resolution itself is delegated to
    :func:`ivre.web.utils.get_user`, whose behaviour is
    asymmetric based on the ``WEB_AUTH_ENABLED`` config knob:

    * When ``WEB_AUTH_ENABLED`` is ``False`` (the default
      open-deployment mode), the helper short-circuits to the
      reverse-proxy-supplied ``REMOTE_USER`` only -- session
      cookies and API keys are not consulted (the deployment
      has not opted in to IVRE's own auth backend, so trying
      its session / API-key paths would be incoherent).
    * When ``WEB_AUTH_ENABLED`` is ``True``, the helper
      consults (in order) the ``_ivre_session`` cookie, then
      the ``X-API-Key`` header (or ``Authorization: Bearer
      <key>``), then the reverse-proxy ``REMOTE_USER``.  Each
      source is gated on ``db.auth`` being available; the
      first source that yields an active user wins.

    When no source yields a usable identity, the helper
    aborts with HTTP 401.
    """
    user = webutils.get_user()
    if user is None:
        abort(401, "Authentication required for note writes")
    return user


def _require_notes_backend() -> None:
    """Abort with HTTP 501 when the configured backend does not
    implement the notes purpose.

    Every notes web route calls this as its first line so a
    misconfigured deployment surfaces a clean 501 with a
    message naming the supported backend (and the config knob
    to set) rather than the cryptic 500 the catch-all WSGI
    handler would otherwise produce from
    ``AttributeError: 'NoneType' object has no attribute
    '<method>'``.

    501 is the correct HTTP semantic for "the route exists but
    the implementation is missing for this server's backend";
    404 would mislead operators into thinking they need to
    create a resource.  Mirrors the
    ``_require_notes_backend`` guards in
    :mod:`ivre.tools.mcp_server` and :mod:`ivre.tools.notes`.
    """
    if db.notes is None:
        abort(
            501,
            "Notes backend not available. The notes purpose is "
            "implemented on MongoDB only at v1; set DB_NOTES (or "
            "DB) to a mongodb:// URL to enable it.",
        )


def _validate_entity_type(entity_type: str) -> None:
    """Reject unknown entity types with HTTP 400 before reaching
    the storage layer so the error surfaces at the route edge
    with a friendlier message than the canonicaliser's
    registry-mismatch ``ValueError``.
    """
    from ivre.db import (  # pylint: disable=import-outside-toplevel
        _ENTITY_CANONICALIZERS,
    )

    if entity_type not in _ENTITY_CANONICALIZERS:
        abort(
            400,
            f"unknown entity_type {entity_type!r}; expected one of "
            f"{sorted(_ENTITY_CANONICALIZERS)}",
        )


def _parse_revision_param(raw: str | None) -> int | None:
    """Parse the ``If-Match`` header or ``?expected_revision=``
    query parameter into the integer the storage layer expects.
    Returns ``None`` when no precondition was requested (LWW).

    Handles three standard ``If-Match`` HTTP forms in addition
    to the bare integer:

    * **Weak validator** (``W/"7"``) -- the ``W/`` prefix is
      stripped and the value parsed as 7.  Weak vs strong
      distinction is meaningless for a monotonic revision
      counter, so we accept both transparently.
    * **Comma-list** (``"7", "8"``) -- the first ETag is taken;
      remaining values are ignored.  Strict "OR over revisions"
      semantics would require a multi-version :meth:`set_note`
      mode we do not implement; first-wins matches how most
      clients use commas in practice (a single value with
      stray middleware-injected whitespace).
    * **Wildcard** (``*``) -- rejected with HTTP 400.  Standard
      HTTP "must exist" semantics would require an
      update-if-exists-do-not-create :meth:`set_note` mode we
      do not have.  Surfacing the limitation explicitly is
      cleaner than silently mapping it to one of the existing
      modes.

    Quoted forms (``"7"`` / ``W/"7"``) are standard for ETag
    round-tripping; strip the quotes before integer parsing.
    """
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None
    if raw == "*":
        abort(
            400,
            "If-Match: * is not supported; use a numeric "
            "revision or omit the header for last-write-wins",
        )
    # Comma-list: first wins.  Subsequent values are
    # dropped silently.
    first = raw.split(",", 1)[0].strip()
    # Optional weak-validator prefix.
    if first.startswith("W/"):
        first = first[2:]
    # ETag canonical form is double-quoted; strip the quotes.
    first = first.strip('"')
    try:
        return int(first)
    except ValueError:
        abort(
            400,
            f"expected_revision must be an integer (with optional "
            f'W/ prefix and "..." quoting), got {raw!r}',
        )
    return None  # unreachable; keeps mypy happy


@application.get("/notes/<entity_type>/<entity_key>")
@check_referer
def get_note(entity_type: str, entity_key: str):
    """Read a single note.

    :param str entity_type: entity type registered with
        ``_ENTITY_CANONICALIZERS`` (``"host"`` only at v1)
    :param str entity_key: caller-facing entity key (e.g.
        printable IP string for ``host``)
    :status 200: note found; JSON body
    :status 400: invalid entity_type / entity_key
    :status 404: no note exists for this entity
    :status 501: notes backend not configured on this server

    """
    _require_notes_backend()
    _validate_entity_type(entity_type)
    try:
        note = db.notes.get_note(entity_type, entity_key)
    except ValueError as exc:
        abort(400, str(exc))
    if note is None:
        abort(404, f"no note for {entity_type}/{entity_key}")
    response.set_header("Content-Type", "application/json")
    response.set_header("ETag", f'"{note["revision"]}"')
    return json.dumps(note, default=utils.serialize)


@application.put("/notes/<entity_type>/<entity_key>")
@check_referer
def put_note(entity_type: str, entity_key: str):
    """Create or update a note.

    Body must be valid UTF-8 markdown; invalid byte sequences
    are rejected with HTTP 400 (no silent ``U+FFFD``
    substitution).  Optimistic concurrency is opt-in via
    ``If-Match`` (matching the ``ETag`` returned by ``GET``)
    or ``?expected_revision=<int>``.  ``If-None-Match: *``
    opts into create-only semantics (HTTP 409 if a note
    already exists).

    ``If-Match`` accepts the standard HTTP forms: bare integer
    (``7``), double-quoted (``"7"``), weak validator
    (``W/"7"``), and the first ETag of a comma-list
    (``"7", "8"`` is treated as 7).  ``If-Match: *`` (generic
    "must exist") is **not** supported and returns 400.

    :param str entity_type: entity type
    :param str entity_key: caller-facing entity key
    :reqheader If-Match: expected revision for optimistic
        concurrency
    :reqheader If-None-Match: ``*`` for create-only mode
    :status 200: persisted; JSON body of the note
    :status 400: invalid entity_type / entity_key / params /
        body not valid UTF-8 / unsupported ``If-Match`` form
    :status 401: authentication required
    :status 404: ``If-Match`` set but no note exists
    :status 409: concurrent edit (revision mismatch) or
        create-only collision
    :status 413: body exceeds
        ``WEB_HOST_NOTES_MAX_BYTES``
    :status 501: notes backend not configured on this server

    """
    from ivre.db import (  # pylint: disable=import-outside-toplevel
        NoteAlreadyExists,
        NoteBodyTooLarge,
        NoteConcurrencyError,
        NoteNotFound,
    )

    # Backend check first so a misconfigured deployment sees
    # the right error before being told to authenticate; an
    # operator's first fix is the backend, not the auth.
    _require_notes_backend()
    _validate_entity_type(entity_type)
    user = _require_authenticated_user()
    # Edge-enforce :data:`WEB_HOST_NOTES_MAX_BYTES` before the
    # body is fully buffered.  The storage layer's
    # :func:`_validate_note_body_size` is belt-and-suspenders;
    # without this header / read-bounded check a client could
    # PUT an arbitrarily large payload and force Bottle to
    # spill the whole thing to a temp file (``MEMFILE_MAX`` caps
    # in-memory buffering at ~100 KB but the disk path is
    # unbounded) before we ever look at the size.
    #
    # Two-layer defence:
    #   * ``request.content_length`` is parsed from the
    #     ``Content-Length`` header at WSGI handoff time --
    #     checking it costs nothing and lets us close the
    #     connection without touching ``wsgi.input`` when the
    #     declared length already overshoots the cap.
    #   * Reading ``cap + 1`` bytes bounds the post-read
    #     buffer even when the client omits ``Content-Length``
    #     (chunked encoding) or lies about it; if more than
    #     ``cap`` bytes are returned, the actual body
    #     overshoots and we abort.
    cap = config.WEB_HOST_NOTES_MAX_BYTES
    if cap is not None:
        # Bottle returns ``-1`` when the ``Content-Length``
        # header is absent (e.g. chunked encoding); the
        # ``>= 0`` guard skips the early check in that case
        # and relies on the bounded read below.
        declared = request.content_length
        if declared >= 0 and declared > cap:
            abort(
                413,
                f"note body declares {declared} bytes, exceeds cap {cap}",
            )
        raw_body = request.body.read(cap + 1)
        if len(raw_body) > cap:
            abort(413, f"note body exceeds cap {cap}")
    else:
        raw_body = request.body.read()
    # Strict UTF-8 decode: the route contract documents the body
    # as "UTF-8 markdown", so invalid bytes are a client error
    # (400) rather than something to silently substitute with
    # U+FFFD.  Strict mode also closes the
    # :class:`NoteBodyTooLarge` corner case at the storage layer
    # where invalid bytes inflate 1:3 on re-encode -- garbage
    # input is rejected at decode time and never reaches the
    # storage cap check.
    try:
        body = raw_body.decode("utf-8")
    except UnicodeDecodeError as exc:
        abort(400, f"note body must be valid UTF-8: {exc}")
    # Translate HTTP headers / query params into the storage-layer
    # ``expected_revision`` enum.  ``If-None-Match: *`` takes
    # precedence over ``If-Match`` because the two are mutually
    # exclusive in HTTP semantics; mixing them is a client bug.
    if request.headers.get("If-None-Match") == "*":
        expected_revision: int | None = 0
    else:
        expected_revision = _parse_revision_param(
            request.headers.get("If-Match") or request.params.get("expected_revision")
        )
    try:
        note = db.notes.set_note(
            entity_type,
            entity_key,
            body,
            user,
            expected_revision=expected_revision,
        )
    except NoteNotFound as exc:
        abort(404, str(exc))
    except (NoteConcurrencyError, NoteAlreadyExists) as exc:
        abort(409, str(exc))
    except NoteBodyTooLarge as exc:
        # Contract preservation: the route docstring declares
        # ``:status 413: body exceeds WEB_HOST_NOTES_MAX_BYTES``,
        # and that contract must hold regardless of how the
        # body got to this point.  Under the *current* edge
        # checks above (``Content-Length`` reject + ``cap + 1``
        # bounded read + strict UTF-8 decode) the storage-layer
        # ``_validate_note_body_size`` -> :class:`NoteBodyTooLarge`
        # path is unreachable from ``put_note``; the catch is
        # kept so that a future refactor (e.g. reverting strict
        # UTF-8 to ``errors="replace"``, loosening the wire
        # cap) cannot silently demote 413 to 400.  The catch
        # is by *type*, not by message substring, so any change
        # to the storage-layer wording is also safe.
        abort(413, str(exc))
    except ValueError as exc:
        # Remaining ``ValueError`` -- canonicaliser rejection
        # (unknown entity_type, malformed entity_key list, ...)
        # -- map to 400 Bad Request.
        abort(400, str(exc))
    response.set_header("Content-Type", "application/json")
    response.set_header("ETag", f'"{note["revision"]}"')
    return json.dumps(note, default=utils.serialize)


@application.delete("/notes/<entity_type>/<entity_key>")
@check_referer
def delete_note(entity_type: str, entity_key: str):
    """Delete a note (and its full revision history).

    :param str entity_type: entity type
    :param str entity_key: caller-facing entity key
    :status 204: deleted
    :status 400: invalid entity_type / entity_key
    :status 401: authentication required
    :status 404: no note exists for this entity
    :status 501: notes backend not configured on this server

    """
    _require_notes_backend()
    _validate_entity_type(entity_type)
    _require_authenticated_user()
    try:
        existed = db.notes.delete_note(entity_type, entity_key)
    except ValueError as exc:
        abort(400, str(exc))
    if not existed:
        abort(404, f"no note for {entity_type}/{entity_key}")
    response.status = 204
    return ""


@application.get("/notes/<entity_type>/<entity_key>/revisions")
@check_referer
def get_note_revisions(entity_type: str, entity_key: str):
    """Read the full revision history of a note, newest first.

    :param str entity_type: entity type
    :param str entity_key: caller-facing entity key
    :status 200: JSON array of ``{revision, body, created_at,
        created_by}`` entries
    :status 400: invalid entity_type / entity_key
    :status 501: notes backend not configured on this server

    """
    _require_notes_backend()
    _validate_entity_type(entity_type)
    try:
        revisions = db.notes.list_note_revisions(entity_type, entity_key)
    except ValueError as exc:
        abort(400, str(exc))
    response.set_header("Content-Type", "application/json")
    return json.dumps(revisions, default=utils.serialize)


@application.get("/notes/")
@check_referer
def list_notes():
    """List or search notes.

    With no parameters, returns every note in the database (full
    body included).  Add ``entity_type`` to narrow to one type,
    ``q`` to free-text search across note bodies (results
    ranked by relevance), or ``fields`` to skip the bodies and
    paginate cheaply.

    :query str entity_type: narrow to one entity type
    :query str q: free-text search query (``$text`` over
        note bodies; requires the
        ``notes_body_text`` index)
    :query str fields: comma-separated projection list (e.g.
        ``"entity_type,entity_key,updated_at,revision"``).
        The storage halves ``entity_key_0`` / ``entity_key_1``
        are always added internally so the caller-facing
        ``entity_key`` can be reassembled.
    :query int limit: cap on returned entries
        (default ``WEB_LIMIT``; capped by ``WEB_MAXRESULTS``)
    :query int skip: pagination offset (default 0)
    :status 200: JSON array
    :status 400: invalid parameters
    :status 501: notes backend not configured on this server

    """
    _require_notes_backend()
    entity_type = request.params.get("entity_type") or None
    if entity_type is not None:
        _validate_entity_type(entity_type)
    q = request.params.get("q") or None
    raw_fields = request.params.get("fields")
    fields = (
        [f.strip() for f in raw_fields.split(",") if f.strip()] if raw_fields else None
    )
    try:
        limit_raw = request.params.get("limit")
        limit = int(limit_raw) if limit_raw else config.WEB_LIMIT
        skip = int(request.params.get("skip") or 0)
    except ValueError as exc:
        abort(400, f"limit / skip must be integers: {exc}")
    if config.WEB_MAXRESULTS is not None:
        limit = min(limit, config.WEB_MAXRESULTS)
    # Clamp negative ``skip`` / non-positive ``limit`` to the
    # nearest sensible value before reaching the storage layer:
    # negative ``skip`` raises ``OperationFailure`` deep in
    # pymongo and the resulting 500 would obscure the
    # parameter problem.
    limit = max(1, limit)
    skip = max(0, skip)
    try:
        notes = db.notes.list_notes(
            entity_type=entity_type,
            q=q,
            fields=fields,
            limit=limit,
            skip=skip,
        )
    except ValueError as exc:
        abort(400, str(exc))
    response.set_header("Content-Type", "application/json")
    return json.dumps(notes, default=utils.serialize)


# Auth check route for nginx auth_request — always registered so that
# Dokuwiki (and other auth_request-protected locations) work even when
# authentication is disabled.
if config.WEB_AUTH_ENABLED:
    from ivre.web import auth as _auth  # noqa: F401
else:

    @application.get("/auth/check")
    def auth_check() -> str:
        """When auth is disabled, allow all requests."""
        user = request.environ.get("REMOTE_USER")
        if user:
            response.set_header("X-Auth-User", user)
        return ""
