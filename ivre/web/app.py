#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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
from functools import wraps
import json
import os
import tempfile


from bottle import abort, request, response, Bottle
from future.utils import viewitems


from ivre import config, utils, VERSION
from ivre.db import db
from ivre.web import utils as webutils


application = Bottle()


#
# Utils
#

def check_referer(func):
    """"Wrapper for route functions to implement a basic anti-CSRF check
based on the Referer: header.

    It will abort if the referer is invalid.

    """

    def _die(referer):
        utils.LOGGER.critical("Invalid Referer header [%r]", referer)
        response.set_header('Content-Type', 'application/javascript')
        response.status = '400 Bad Request'
        return webutils.js_alert(
            "referer", "error",
            "Invalid Referer header. Check your configuration."
        )

    @wraps(func)
    def _newfunc(*args, **kargs):
        if config.WEB_ALLOWED_REFERERS is False:
            return func(*args, **kargs)
        referer = request.headers.get('Referer')
        if not referer:
            return _die(referer)
        if config.WEB_ALLOWED_REFERERS is None:
            base_url = '/'.join(request.url.split('/', 3)[:3]) + '/'
            if referer.startswith(base_url):
                return func(*args, **kargs)
        elif referer in config.WEB_ALLOWED_REFERERS:
            return func(*args, **kargs)
        return _die(referer)

    return _newfunc


#
# Configuration
#

@application.get('/config')
@check_referer
def get_config():
    """This function returns JS code to set client-side config values."""
    response.set_header('Content-Type', 'application/javascript')
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

FilterParams = namedtuple("flt_params", ['flt', 'sortby', 'unused',
                                         'skip', 'limit', 'callback',
                                         'ipsasnumbers', 'datesasstrings'])


def get_nmap_base():
    response.set_header('Content-Type', 'application/javascript')
    query = webutils.query_from_params(request.params)
    flt, sortby, unused, skip, limit = webutils.flt_from_query(query)
    if limit is None:
        limit = config.WEB_LIMIT
    if config.WEB_MAXRESULTS is not None:
        limit = min(limit, config.WEB_MAXRESULTS)
    callback = request.params.get("callback")
    # type of result
    ipsasnumbers = request.params.get("ipsasnumbers")
    datesasstrings = request.params.get("datesasstrings")
    if callback is None:
        response.set_header('Content-Disposition',
                            'attachment; filename="IVRE-results.json"')
    return FilterParams(flt, sortby, unused, skip, limit, callback,
                        ipsasnumbers, datesasstrings)


@application.get(
    '/scans/<action:re:'
    'onlyips|ipsports|timeline|coordinates|countopenports|diffcats>'
)
@check_referer
def get_nmap_action(action):
    flt_params = get_nmap_base()
    preamble = "[\n"
    postamble = "]\n"
    r2res = lambda x: x
    if action == "timeline":
        result, count = db.view.get_open_port_count(flt_params.flt)
        if request.params.get("modulo") is None:
            r2time = lambda r: int(utils.datetime2timestamp(r['starttime']))
        else:
            r2time = lambda r: (int(utils.datetime2timestamp(r['starttime']))
                                % int(request.params.get("modulo")))
        if flt_params.ipsasnumbers:
            r2res = lambda r: [r2time(r), utils.ip2int(r['addr']),
                               r['openports']['count']]
        else:
            r2res = lambda r: [r2time(r), r['addr'], r['openports']['count']]
    elif action == "coordinates":
        preamble = '{"type": "GeometryCollection", "geometries": [\n'
        postamble = ']}\n'
        result = list(db.view.getlocations(flt_params.flt))
        count = len(result)
        r2res = lambda r: {
            "type": "Point",
            "coordinates": r['_id'],
            "properties": {"count": r['count']},
        }
    elif action == "countopenports":
        result, count = db.view.get_open_port_count(flt_params.flt)
        if flt_params.ipsasnumbers:
            r2res = lambda r: [utils.ip2int(r['addr']),
                               r['openports']['count']]
        else:
            r2res = lambda r: [r['addr'], r['openports']['count']]
    elif action == "ipsports":
        result, count = db.view.get_ips_ports(flt_params.flt)
        if flt_params.ipsasnumbers:
            r2res = lambda r: [
                utils.ip2int(r['addr']),
                [[p['port'], p['state_state']]
                 for p in r.get('ports', [])
                 if 'state_state' in p]
            ]
        else:
            r2res = lambda r: [
                r['addr'],
                [[p['port'], p['state_state']]
                 for p in r.get('ports', [])
                 if 'state_state' in p]
            ]
    elif action == "onlyips":
        result, count = db.view.get_ips(flt_params.flt)
        if flt_params.ipsasnumbers:
            r2res = lambda r: utils.ip2int(r['addr'])
        else:
            r2res = lambda r: r['addr']
    elif action == "diffcats":
        if request.params.get("onlydiff"):
            output = db.view.diff_categories(request.params.get("cat1"),
                                             request.params.get("cat2"),
                                             flt=flt_params.flt,
                                             include_both_open=False)
        else:
            output = db.view.diff_categories(request.params.get("cat1"),
                                             request.params.get("cat2"),
                                             flt=flt_params.flt)
        count = 0
        result = {}
        if flt_params.ipsasnumbers:
            for res in output:
                result.setdefault(res["addr"], []).append([res['port'],
                                                           res['value']])
                count += 1
        else:
            for res in output:
                result.setdefault(utils.int2ip(res["addr"]),
                                  []).append([res['port'], res['value']])
                count += 1
        result = viewitems(result)
    if flt_params.callback is not None:
        if count >= config.WEB_WARN_DOTS_COUNT:
            yield (
                'if(confirm("You are about to ask your browser to display %d '
                'dots, which is a lot and might slow down, freeze or crash '
                'your browser. Do you want to continue?")) {\n' % count
            )
        yield '%s(\n' % flt_params.callback
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
            yield '}\n'
    else:
        yield "\n"


@application.get('/scans/count')
@check_referer
def get_nmap_count():
    flt_params = get_nmap_base()
    count = db.view.count(flt_params.flt)
    if flt_params.callback is None:
        return "%d\n" % count
    return "%s(%d);\n" % (flt_params.callback, count)


@application.get('/scans/top/<field>')
@check_referer
def get_nmap_top(field):
    flt_params = get_nmap_base()
    if field[0] in '-!':
        field = field[1:]
        least = True
    else:
        least = False
    topnbr = 15
    if ':' in field:
        field, topnbr = field.rsplit(':', 1)
        try:
            topnbr = int(topnbr)
        except ValueError:
            field = '%s:%s' % (field, topnbr)
            topnbr = 15
    if flt_params.callback is None:
        yield "[\n"
    else:
        yield "%s([\n" % flt_params.callback
    # hack to avoid a trailing comma
    cursor = iter(db.view.topvalues(field, flt=flt_params.flt, least=least,
                                    topnbr=topnbr))
    try:
        rec = next(cursor)
    except StopIteration:
        pass
    else:
        yield json.dumps({"label": rec['_id'], "value": rec['count']})
        for rec in cursor:
            yield ",\n%s" % json.dumps({"label": rec['_id'],
                                        "value": rec['count']})
    if flt_params.callback is None:
        yield "\n]\n"
    else:
        yield "\n]);\n"


@application.get('/scans')
@check_referer
def get_nmap():
    flt_params = get_nmap_base()
    ## PostgreSQL: the query plan if affected by the limit and gives
    ## really poor results. This is a temporary workaround (look for
    ## XXX-WORKAROUND-PGSQL)
    # result = db.view.get(flt_params.flt, limit=flt_params.limit,
    #                      skip=flt_params.skip, sort=flt_params.sortby)
    result = db.view.get(flt_params.flt, skip=flt_params.skip,
                         sort=flt_params.sortby)

    if flt_params.unused:
        msg = 'Option%s not understood: %s' % (
            's' if len(flt_params.unused) > 1 else '',
            ', '.join(flt_params.unused),
        )
        if flt_params.callback is not None:
            yield webutils.js_alert("param-unused", "warning", msg)
        utils.LOGGER.warning(msg)
    elif flt_params.callback is not None:
        yield webutils.js_del_alert("param-unused")

    if config.DEBUG:
        msg1 = "filter: %s" % db.view.flt2str(flt_params.flt)
        msg2 = "user: %r" % webutils.get_user()
        utils.LOGGER.debug(msg1)
        utils.LOGGER.debug(msg2)
        if flt_params.callback is not None:
            yield webutils.js_alert("filter", "info", msg1)
            yield webutils.js_alert("user", "info", msg2)

    version_mismatch = {}
    if flt_params.callback is None:
        yield "[\n"
    else:
        yield "%s([\n" % flt_params.callback
    ## XXX-WORKAROUND-PGSQL
    # for rec in result:
    for i, rec in enumerate(result):
        for fld in ['_id', 'scanid']:
            try:
                del rec[fld]
            except KeyError:
                pass
        if not flt_params.ipsasnumbers:
            rec['addr'] = utils.force_int2ip(rec['addr'])
        for field in ['starttime', 'endtime']:
            if field in rec:
                if not flt_params.datesasstrings:
                    rec[field] = int(utils.datetime2timestamp(rec[field]))
        for port in rec.get('ports', []):
            if 'screendata' in port:
                port['screendata'] = utils.encode_b64(port['screendata'])
            for script in port.get('scripts', []):
                if "masscan" in script:
                    try:
                        del script['masscan']['raw']
                    except KeyError:
                        pass
        if not flt_params.ipsasnumbers:
            if 'traces' in rec:
                for trace in rec['traces']:
                    trace['hops'].sort(key=lambda x: x['ttl'])
                    for hop in trace['hops']:
                        hop['ipaddr'] = utils.force_int2ip(hop['ipaddr'])
        yield "%s\t%s" % ('' if i == 0 else ',\n',
                          json.dumps(rec, default=utils.serialize))
        check = db.view.cmp_schema_version_host(rec)
        if check:
            version_mismatch[check] = version_mismatch.get(check, 0) + 1
        # XXX-WORKAROUND-PGSQL
        if i + 1 >= flt_params.limit:
            break
    if flt_params.callback is None:
        yield "\n]\n"
    else:
        yield "\n]);\n"

    messages = {
        1: lambda count: ("%d document%s displayed %s out-of-date. Please run "
                          "the following command: 'ivre scancli "
                          "--update-schema;" % (count,
                                                's' if count > 1 else '',
                                                'are' if count > 1 else 'is')),
        -1: lambda count: ('%d document%s displayed ha%s been inserted by '
                           'a more recent version of IVRE. Please update '
                           'IVRE!' % (count, 's' if count > 1 else '',
                                      've' if count > 1 else 's')),
    }
    for mismatch, count in viewitems(version_mismatch):
        message = messages[mismatch](count)
        if flt_params.callback is not None:
            yield webutils.js_alert(
                "version-mismatch-%d" % ((mismatch + 1) // 2),
                "warning", message
            )
        utils.LOGGER.warning(message)


#
# Upload scans
#

def parse_form():
    categories = request.forms.get("categories")
    categories = (set(categories.split(',')) if categories else set())
    source = request.forms.get("source")
    if not source:
        utils.LOGGER.critical("source is mandatory")
        abort(400, "ERROR: source is mandatory\n")
    files = request.files.getall("result")
    if config.WEB_PUBLIC_SRV:
        if webutils.get_user() is None:
            utils.LOGGER.critical("username is mandatory on public instances")
            abort(400, "ERROR: username is mandatory on public instances")
        if request.forms.get('public') == 'on':
            categories.add('Shared')
        user = webutils.get_anonymized_user()
        categories.add(user)
        source = "%s-%s" % (user, source)
    return (request.forms.get('referer'), source, categories, files)


def import_files(source, categories, files):
    count = 0
    categories = list(categories)
    for fileelt in files:
        fdesc = tempfile.NamedTemporaryFile(delete=False)
        fileelt.save(fdesc)
        try:
            if db.nmap.store_scan(fdesc.name, categories=categories,
                                  source=source):
                count += 1
                os.unlink(fdesc.name)
            else:
                utils.LOGGER.warning("Could not import %s", fdesc.name)
        except Exception:
            utils.LOGGER.warning("Could not import %s", fdesc.name,
                                 exc_info=True)
    return count


@application.post('/scans')
@check_referer
def post_nmap():
    referer, source, categories, files = parse_form()
    count = import_files(source, categories, files)
    if request.params.get("output") == "html":
        response.set_header('Refresh', '5;url=%s' % referer)
        return """<html>
  <head>
    <title>IVRE Web UI</title>
  </head>
  <body style="padding-top: 2%%; padding-left: 2%%">
    <h1>%d result%s uploaded</h1>
  </body>
</html>""" % (count, 's' if count > 1 else '')
    return {"count": count}


#
# /flow/
#

@application.get('/flows')
@check_referer
def get_flow():
    callback = request.params.get("callback")
    action = request.params.get("action", "")
    if callback is None:
        response.set_header('Content-Disposition',
                            'attachment; filename="IVRE-results.json"')
    else:
        yield callback + "(\n"
    utils.LOGGER.debug("Params: %r", dict(request.params))
    query = json.loads(request.params.get('q', '{}'))
    limit = query.get("limit", config.WEB_GRAPH_LIMIT)
    skip = query.get("skip", config.WEB_GRAPH_LIMIT)
    mode = query.get("mode", "default")
    count = query.get("count", False)
    orderby = query.get("orderby", None)
    timeline = query.get("timeline", False)
    utils.LOGGER.debug("Action: %r, Query: %r", action, query)
    if action == "details":
        # TODO: error
        if "Host" in query["labels"]:
            res = db.flow.host_details(query["id"])
        else:
            res = db.flow.flow_details(query["id"])
    else:
        cquery = db.flow.from_filters(query, limit=limit, skip=skip,
                                      orderby=orderby, mode=mode,
                                      timeline=timeline)
        if count:
            res = db.flow.count(cquery)
        else:
            res = db.flow.to_graph(cquery)
    yield json.dumps(res, default=utils.serialize)
    if callback is not None:
        yield ");\n"
