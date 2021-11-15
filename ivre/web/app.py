#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
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


from collections import namedtuple
import datetime
from functools import wraps
import json
import os
import tempfile


from bottle import abort, request, response, Bottle


from ivre import config, utils, VERSION
from ivre.db import db
from ivre.view import nmap_record_to_view
from ivre.web import utils as webutils


application = Bottle()


#
# Utils
#


def check_referer(func):
    """ "Wrapper for route functions to implement a basic anti-CSRF check
    based on the Referer: header.

        It will abort (status code 400) if the referer is invalid.

    """

    if config.WEB_ALLOWED_REFERERS is False:
        return func

    def _die(referer):
        utils.LOGGER.critical("Invalid Referer header [%r]", referer)
        response.set_header("Content-Type", "application/javascript")
        response.status = "400 Bad Request"
        return webutils.js_alert(
            "referer", "error", "Invalid Referer header. Check your configuration."
        )

    @wraps(func)
    def _newfunc(*args, **kargs):

        # Header with an existing X-API-Key header or an
        # Authorization: Bearer XXX are OK. Note: IVRE does not check
        # those values, they only serve as anti-CSRF protections.
        if request.headers.get("X-API-Key") or (
            request.headers.get("Authorization")
            and (
                request.headers.get("Authorization", "").split(None, 1)[0].lower()
                == "bearer"
            )
        ):
            return func(*args, **kargs)

        referer = request.headers.get("Referer")
        if not referer:
            return _die(referer)
        if config.WEB_ALLOWED_REFERERS is None:
            base_url = "/".join(request.url.split("/", 3)[:3]) + "/"
            if referer.startswith(base_url):
                return func(*args, **kargs)
        elif (
            # pylint: disable=unsupported-membership-test
            referer
            in config.WEB_ALLOWED_REFERERS
        ):
            return func(*args, **kargs)
        return _die(referer)

    return _newfunc


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
        ("publicsrv", config.WEB_PUBLIC_SRV),
        ("uploadok", config.WEB_UPLOAD_OK),
        ("flow_time_precision", config.FLOW_TIME_PRECISION),
        ("version", VERSION),
    ]:
        yield "config.%s = %s;\n" % (key, json.dumps(value))


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
        "callback",
        "ipsasnumbers",
        "datesasstrings",
        "fmt",
    ],
)


def get_base(dbase):
    # we can get filters from either q= (web interface) or f= (API);
    # both are used (logical and)
    query = webutils.query_from_params(request.params)
    flt, sortby, unused, skip, limit = webutils.flt_from_query(dbase, query)
    flt = dbase.flt_and(
        flt, webutils.parse_filter(dbase, json.loads(request.params.pop("f", "{}")))
    )
    if limit is None:
        limit = config.WEB_LIMIT
    if config.WEB_MAXRESULTS is not None:
        limit = min(limit, config.WEB_MAXRESULTS)
    callback = request.params.get("callback")
    # type of result
    ipsasnumbers = request.params.get("ipsasnumbers")
    if callback:
        fmt = "json"
    else:
        fmt = request.params.get("format") or "json"
        if fmt not in set(["txt", "json", "ndjson"]):
            fmt = "txt"
    datesasstrings = request.params.get("datesasstrings")
    if fmt == "txt":
        response.set_header("Content-Type", "text/plain")
    elif fmt == "ndjson":
        response.set_header("Content-Type", "application/x-ndjson")
    else:
        response.set_header("Content-Type", "application/javascript")
    if callback is None:
        response.set_header(
            "Content-Disposition", 'attachment; filename="IVRE-results.%s"' % fmt
        )
    return FilterParams(
        flt, sortby, unused, skip, limit, callback, ipsasnumbers, datesasstrings, fmt
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
    :query str callback: callback to use for JSONP results (forces "json"
                        format)
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
        result, count = subdb.get_open_port_count(flt_params.flt)
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
        count = len(result)
    elif action == "countopenports":
        result, count = subdb.get_open_port_count(flt_params.flt)
        if flt_params.ipsasnumbers:

            def r2res(r):
                return [utils.ip2int(r["addr"]), r.get("openports", {}).get("count", 0)]

        else:

            def r2res(r):
                return [r["addr"], r.get("openports", {}).get("count", 0)]

    elif action == "ipsports":
        result, count = subdb.get_ips_ports(flt_params.flt)
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
        result, count = subdb.get_ips(flt_params.flt)
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
        count = 0
        result = {}
        if flt_params.ipsasnumbers:
            for res in output:
                result.setdefault(res["addr"], []).append([res["port"], res["value"]])
                count += 1
        else:
            for res in output:
                result.setdefault(utils.int2ip(res["addr"]), []).append(
                    [res["port"], res["value"]]
                )
                count += 1
        result = result.items()

    if flt_params.fmt == "txt":
        for rec in result:
            yield "%s\n" % r2res(rec)
        return

    if flt_params.fmt == "ndjson":
        for rec in result:
            yield "%s\n" % json.dumps(r2res(rec))
        return

    if flt_params.callback is not None:
        if count >= config.WEB_WARN_DOTS_COUNT:
            yield (
                'if(confirm("You are about to ask your browser to display %d '
                "dots, which is a lot and might slow down, freeze or crash "
                'your browser. Do you want to continue?")) {\n' % count
            )
        yield "%s(\n" % flt_params.callback
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
            yield ",\n" + json.dumps(r2res(rec))
        yield "\n"

    yield postamble
    if flt_params.callback is not None:
        yield ");"
        if count >= config.WEB_WARN_DOTS_COUNT:
            yield "}\n"
    else:
        yield "\n"


@application.get("/<subdb:re:scans|view>/count")
@check_referer
def get_nmap_count(subdb):
    """Get special values from Nmap & View databases

    :param str subdb: database to query (must be "scans" or "view")
    :query str q: query (including limit/skip and sort)
    :query str f: filter
    :query str callback: callback to use for JSONP results
    :status 200: no error
    :status 400: invalid referer
    :>json int: count

    """
    subdb = db.view if subdb == "view" else db.nmap
    flt_params = get_base(subdb)
    count = subdb.count(flt_params.flt)
    if flt_params.callback is None:
        return "%d\n" % count
    return "%s(%d);\n" % (flt_params.callback, count)


@application.get("/<subdb:re:scans|view|passive>/top/<field:path>")
@check_referer
def get_top(subdb, field):
    """Get top values from Nmap, View & Passive databases

    :param str subdb: database to query (must be "scans" or "view")
    :param str field: (pseudo-)field to get top values (e.g., "service")
    :query str q: query (including limit/skip and sort)
    :query str f: filter
    :query str callback: callback to use for JSONP results
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
            field = "%s:%s" % (field, topnbr)
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
    if flt_params.callback is None:
        yield "[\n"
    else:
        yield "%s([\n" % flt_params.callback
    # hack to avoid a trailing comma
    cursor = iter(cursor)
    try:
        rec = next(cursor)
    except StopIteration:
        pass
    else:
        yield json.dumps({"label": rec["_id"], "value": rec["count"]})
        for rec in cursor:
            yield ",\n%s" % json.dumps({"label": rec["_id"], "value": rec["count"]})
    if flt_params.callback is None:
        yield "\n]\n"
    else:
        yield "\n]);\n"


@application.get("/<subdb:re:scans|view|passive>/distinct/<field:path>")
@check_referer
def get_distinct(subdb, field):
    """Get distinct values from Nmap, View & Passive databases

    :param str subdb: database to query (must be "scans" or "view")
    :param str field: (pseudo-)field to get distinct values (e.g., "service")
    :query str q: query (including limit/skip and sort)
    :query str f: filter
    :query str callback: callback to use for JSONP results
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
            yield "%s\n" % json.dumps(rec)
        return
    if flt_params.callback is None:
        yield "[\n"
    else:
        yield "%s([\n" % flt_params.callback
    # hack to avoid a trailing comma
    cursor = iter(cursor)
    try:
        rec = next(cursor)
    except StopIteration:
        pass
    else:
        yield json.dumps(rec)
        for rec in cursor:
            yield ",\n%s" % json.dumps(rec)
    if flt_params.callback is None:
        yield "\n]\n"
    else:
        yield "\n]);\n"


def _set_datetime_field(dbase, record, field, current=None):
    if current is None:
        current = []
    if "." not in field:
        if field in record:
            if ".".join(current + [field]) in dbase.list_fields:
                record[field] = [int(value.timestamp()) for value in record[field]]
            else:
                record[field] = int(record[field].timestamp())
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
    :query str callback: callback to use for JSONP results
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
    result = subdb.get(flt_params.flt, skip=flt_params.skip, sort=flt_params.sortby)

    if flt_params.unused:
        msg = "Option%s not understood: %s" % (
            "s" if len(flt_params.unused) > 1 else "",
            ", ".join(flt_params.unused),
        )
        if flt_params.callback is not None:
            yield webutils.js_alert("param-unused", "warning", msg)
        utils.LOGGER.warning(msg)
    elif flt_params.callback is not None:
        yield webutils.js_del_alert("param-unused")

    if config.DEBUG:
        msg1 = "filter: %s" % subdb.flt2str(flt_params.flt)
        msg2 = "user: %r" % webutils.get_user()
        utils.LOGGER.debug(msg1)
        utils.LOGGER.debug(msg2)
        if flt_params.callback is not None:
            yield webutils.js_alert("filter", "info", msg1)
            yield webutils.js_alert("user", "info", msg2)

    version_mismatch = {}
    if flt_params.callback is None:
        if flt_params.fmt == "json":
            yield "[\n"
    else:
        yield "%s([\n" % flt_params.callback
    # XXX-WORKAROUND-PGSQL
    # for rec in result:
    for i, rec in enumerate(result):
        for fld in ["_id", "scanid"]:
            try:
                del rec[fld]
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
            yield "%s\n" % json.dumps(rec, default=utils.serialize)
        else:
            yield "%s\t%s" % (
                "" if i == 0 else ",\n",
                json.dumps(rec, default=utils.serialize),
            )
        check = subdb.cmp_schema_version_host(rec)
        if check:
            version_mismatch[check] = version_mismatch.get(check, 0) + 1
        # XXX-WORKAROUND-PGSQL
        if flt_params.limit and i + 1 >= flt_params.limit:
            break
    if flt_params.callback is None:
        if flt_params.fmt == "json":
            yield "\n]\n"
    else:
        yield "\n]);\n"

    messages = {
        1: lambda count: (
            "%d document%s displayed %s out-of-date. Please run "
            "the following command: 'ivre %s "
            "--update-schema;"
            % (
                count,
                "s" if count > 1 else "",
                "are" if count > 1 else "is",
                subdb_tool,
            )
        ),
        -1: lambda count: (
            "%d document%s displayed ha%s been inserted by "
            "a more recent version of IVRE. Please update "
            "IVRE!" % (count, "s" if count > 1 else "", "ve" if count > 1 else "s")
        ),
    }
    for mismatch, count in version_mismatch.items():
        message = messages[mismatch](count)
        if flt_params.callback is not None:
            yield webutils.js_alert(
                "version-mismatch-%d" % ((mismatch + 1) // 2), "warning", message
            )
        utils.LOGGER.warning(message)


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
    if config.WEB_PUBLIC_SRV:
        if webutils.get_user() is None:
            utils.LOGGER.critical("username is mandatory on public instances")
            abort(400, "ERROR: username is mandatory on public instances")
        if request.forms.get("public") == "on":
            categories.add("Shared")
        user = webutils.get_anonymized_user()
        categories.add(user)
        source = "%s-%s" % (user, source)
    return (request.forms.get("referer"), source, categories, files)


def import_files(subdb, source, categories, files):
    count = 0
    categories = list(categories)
    if subdb == "view":

        def callback(x):
            return db.view.store_or_merge_host(nmap_record_to_view(x))

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
        response.set_header("Refresh", "5;url=%s" % referer)
        return """<html>
  <head>
    <title>IVRE Web UI</title>
  </head>
  <body style="padding-top: 2%%; padding-left: 2%%">
    <h1>%d result%s uploaded</h1>
  </body>
</html>""" % (
            count,
            "s" if count > 1 else "",
        )
    return {"count": count}


#
# /flow/
#


@application.get("/flows")
@check_referer
def get_flow():
    """Get special values from Nmap & View databases

    :query str q: query (including limit/skip, orderby, etc.)
    :query str callback: callback to use for JSONP results
    :query str action: can be set to "details"
    :status 200: no error
    :status 400: invalid referer
    :>json object: results

    """
    callback = request.params.get("callback")
    action = request.params.get("action", "")
    if callback is None:
        response.set_header(
            "Content-Disposition", 'attachment; filename="IVRE-results.json"'
        )
    else:
        yield callback + "(\n"
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
    if callback is not None:
        yield ");\n"


#
# /ipdata/
#


@application.get("/ipdata/<addr>")
@check_referer
def get_ipdata(addr):
    """Returns (estimated) geographical and AS data for a given IP address.

    :param str addr: IP address to query
    :query str callback: callback to use for JSONP results
    :status 200: no error
    :status 400: invalid referer
    :>json object: the result values

    """
    callback = request.params.get("callback")
    result = json.dumps(db.data.infos_byip(addr))
    if callback is None:
        return result + "\n"
    return "%s(%s);\n" % (callback, result)


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
                rec["time_%s" % k] = rec.pop("%sseen" % k)
            except KeyError:
                pass
        yield "%s\n" % json.dumps(rec, default=utils.serialize)


@application.get("/passive")
@check_referer
def get_passive():
    """Get records from Passive database

    :query str q: query (only used for limit/skip and sort)
    :query str f: filter
    :query str callback: callback to use for JSONP results
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
        flt_params.flt, skip=flt_params.skip, sort=flt_params.sortby
    )
    if flt_params.callback is None:
        if flt_params.fmt == "json":
            yield "[\n"
    else:
        yield "%s([\n" % flt_params.callback
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
        if rec.get("recontype") == "SSL_SERVER" and rec.get("source") in {
            "cert",
            "cacert",
        }:
            rec["value"] = utils.encode_b64(rec["value"]).decode()
        if flt_params.fmt == "ndjson":
            yield "%s\n" % json.dumps(rec, default=utils.serialize)
        else:
            yield "%s\t%s" % (
                "" if i == 0 else ",\n",
                json.dumps(rec, default=utils.serialize),
            )
        if flt_params.limit and i + 1 >= flt_params.limit:
            break
    if flt_params.callback is None:
        if flt_params.fmt == "json":
            yield "\n]\n"
    else:
        yield "\n]);\n"


@application.get("/passive/count")
@check_referer
def get_passive_count():
    """Get special values from Nmap & View databases

    :query str q: query (only used for limit/skip and sort)
    :query str f: filter
    :query str callback: callback to use for JSONP results
    :status 200: no error
    :status 400: invalid referer
    :>json int: count

    """
    flt_params = get_base(db.passive)
    count = db.passive.count(flt_params.flt)
    if flt_params.callback is None:
        return "%d\n" % count
    return "%s(%d);\n" % (flt_params.callback, count)
