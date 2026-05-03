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
from ivre.tags.active import set_auto_tags, set_openports_attribute
from ivre.view import nmap_record_to_view
from ivre.web import utils as webutils
from ivre.web.base import application, check_referer

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
    :>jsonarr object: results

    """
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
    :>json int: count

    """
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
    :>jsonarr str label: field value
    :>jsonarr int value: count for this value

    """
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
    :>jsonarr str label: field value
    :>jsonarr int value: count for this value

    """
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
    :>jsonarr object: results

    """
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
def post_nmap(subdb):
    """Add records to Nmap & View databases

    :param str subdb: database to query (must be "scans" or "view")
    :form categories: a coma-separated list of categories
    :form source: the source of the scan results (mandatory)
    :form result: scan results (as XML or JSON files)
    :status 200: no error
    :status 400: invalid referer, source or username missing
    :>json int count: number of inserted results

    """
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
    """Get special values from Nmap & View databases

    :query str q: query (including limit/skip, orderby, etc.)
    :query str action: can be set to "details"
    :status 200: no error
    :status 400: invalid referer
    :>json object: results

    """
    response.set_header("Content-Type", "application/json")
    response.set_header(
        "Content-Disposition", 'attachment; filename="IVRE-results.json"'
    )
    action = request.params.get("action", "")
    utils.LOGGER.debug("Params: %r", dict(request.params))
    query = json.loads(request.params.get("q", "{}"))
    limit = query.get("limit", config.WEB_GRAPH_LIMIT)
    skip = query.get("skip", config.WEB_GRAPH_LIMIT)
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
    :>json object: the result values (JSONL format: one JSON result per line)

    """
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
    :>jsonarr object: results

    """
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
    :>json int: count

    """
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
    :>jsonarr object: pseudo-records as ``{name, addr, count, firstseen, lastseen, types, sources}``
    """
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

    # Per-backend filters built from the same parsed query.
    nmap_flt, _, _, _, _, _ = webutils.flt_from_query(db.nmap, raw_query)
    passive_flt, _, _, _, _, _ = webutils.flt_from_query(db.passive, raw_query)

    # Aggregate from each backend, merging into a single
    # ``(name, addr) -> {types, sources, firstseen, lastseen,
    # count}`` dict.
    merged: dict = {}
    utils.merge_dns_results(merged, db.nmap.iter_dns(flt=nmap_flt))
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

    :query str q: query (only used for limit/skip and sort)
    :query str f: filter
    :query str format: "json" (the default) or "ndjson"
    :status 200: no error
    :status 400: invalid referer
    :>jsonarr object: results

    """
    flt_params = get_base(db.rir)
    result = db.rir.get(
        flt_params.flt,
        skip=flt_params.skip,
        sort=flt_params.sortby,
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
    :>json int: count

    """
    flt_params = get_base(db.rir)
    count = db.rir.count(flt_params.flt)
    return f"{count}\n"


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
