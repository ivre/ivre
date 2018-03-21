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
This program runs a simple httpd server to provide an out-of-the-box
access to the web user interface.

This script should only be used for testing purposes. Production
deployments should use "real" web servers (IVRE has been successfully
tested with both Apache and Nginx).
"""


from functools import wraps
import json
import os
import tempfile


from bottle import abort, get, post, request, redirect, response, run, \
    static_file
from future.utils import viewitems


from ivre.db import db
from ivre import config, utils, webutils, VERSION


BASEDIR = config.guess_prefix(directory='web/static')
DOKUDIR = config.guess_prefix(directory='dokuwiki')


def check_referer(func):
    """"Wrapper for route functions to implement a basic anti-CSRF check
based on the Referer: header.

    It will abort if the referer is invalid.

    """

    def die(referer):
        utils.LOGGER.critical("Invalid Referer header [%r]", referer)
        response.set_header('Content-Type', 'application/javascript')
        response.status = '400 Bad Request'
        return webutils.js_alert(
            "referer", "error",
            "Invalid Referer header. Check your configuration."
        )

    @wraps(func)
    def newfunc(*args, **kargs):
        if config.WEB_ALLOWED_REFERERS is False:
            return func(*args, **kargs)
        referer = request.headers.get('Referer')
        if not referer:
            return die(referer)
        if config.WEB_ALLOWED_REFERERS is None:
            base_url = '/'.join(request.url.split('/', 3)[:3]) + '/'
            if referer.startswith(base_url):
                return func(*args, **kargs)
        elif referer in config.WEB_ALLOWED_REFERERS:
            return func(*args, **kargs)
        return die(referer)

    return newfunc


#
# Index page
#

@get('/')
def server_index():
    return redirect('/index.html')


#
# Compatibility with previous API
#

@get('/cgi-bin/flowjson.py')
def redir_cgi_flow():
    if request.urlparts.query:
        return redirect('/cgi/flows?' + request.urlparts.query)
    return redirect('/cgi/flows')


@get('/cgi-bin/jsconfig.py')
def redir_cgi_config():
    if request.urlparts.query:
        return redirect('/cgi/config?' + request.urlparts.query)
    return redirect('/cgi/config')


@post('/cgi-bin/scanupload.py')
def redir_cgi_upload():
    if request.urlparts.query:
        return redirect('/cgi/scans?output=html&' + request.urlparts.query, code=307)
    return redirect('/cgi/scans?output=html', code=307)


@get('/cgi-bin/scanjson.py')
def redir_cgi_nmap():
    if request.urlparts.query:
        action = request.params.get('action')
        if action:
            if action in ['count', 'onlyips', 'ipsports', 'timeline',
                          'coordinates', 'countopenports', 'diffcats']:
                return redirect('/cgi/scans/%s?%s' % (action,
                                                     request.urlparts.query))
            if action.startswith('topvalues:') and '..' not in action:
                field = action[10:]
                return redirect('/cgi/scans/top/%s?%s' % (
                    field,
                    request.urlparts.query,
                ))
        return redirect('/cgi/scans?' + request.urlparts.query)
    return redirect('/cgi/scans')


#
# Configuration
#

@get('/cgi/config')
@check_referer
def get_config():
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

def get_nmap_base():
    response.set_header('Content-Type', 'application/javascript')
    query = webutils.query_from_params(request.params)
    flt, archive, sortby, unused, skip, limit = webutils.flt_from_query(query)
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
    return flt, archive, sortby, unused, skip, limit, callback, ipsasnumbers, \
        datesasstrings


@get('/cgi/scans/<action:re:'
     'onlyips|ipsports|timeline|coordinates|countopenports|diffcats>')
@check_referer
def get_nmap_action(action):
    flt, archive, sortby, unused, skip, limit, callback, ipsasnumbers, \
        datesasstrings = get_nmap_base()
    preamble = "[\n"
    postamble = "]\n"
    r2res = lambda x: x
    if action == "timeline":
        if hasattr(db.nmap, "get_open_port_count"):
            result = list(db.nmap.get_open_port_count(flt, archive=archive))
            count = len(result)
        else:
            result = db.nmap.get(
                flt, archive=archive,
                fields=['addr', 'starttime', 'openports.count']
            )
            count = result.count()
        if request.params.get("modulo") is None:
            r2time = lambda r: int(r['starttime'].strftime('%s'))
        else:
            r2time = lambda r: (int(r['starttime'].strftime('%s'))
                                % int(request.params.get("modulo")))
        if ipsasnumbers:
            r2res = lambda r: [r2time(r), utils.force_ip2int(r['addr']),
                               r['openports']['count']]
        else:
            r2res = lambda r: [r2time(r), utils.force_int2ip(r['addr']),
                               r['openports']['count']]
    elif action == "coordinates":
        preamble = '{"type": "GeometryCollection", "geometries": [\n'
        postamble = ']}\n'
        result = list(db.nmap.getlocations(flt, archive=archive))
        count = len(result)
        r2res = lambda r: {
            "type": "Point",
            "coordinates": r['_id'],
            "properties": {"count": r['count']},
        }
    elif action == "countopenports":
        if hasattr(db.nmap, "get_open_port_count"):
            result = db.nmap.get_open_port_count(flt, archive=archive)
        else:
            result = db.nmap.get(flt, archive=archive,
                                 fields=['addr', 'openports.count'])
        if hasattr(result, "count"):
            count = result.count()
        else:
            count = db.nmap.count(flt, archive=archive,
                                  fields=['addr', 'openports.count'])
        if ipsasnumbers:
            r2res = lambda r: [utils.force_ip2int(r['addr']),
                               r['openports']['count']]
        else:
            r2res = lambda r: [utils.force_int2ip(r['addr']),
                               r['openports']['count']]
    elif action == "ipsports":
        if hasattr(db.nmap, "get_ips_ports"):
            result = list(db.nmap.get_ips_ports(flt, archive=archive))
            count = sum(len(host.get('ports', [])) for host in result)
        else:
            result = db.nmap.get(
                flt, archive=archive,
                fields=['addr', 'ports.port', 'ports.state_state']
            )
            count = sum(len(host.get('ports', [])) for host in result)
            result.rewind()
        if ipsasnumbers:
            r2res = lambda r: [
                utils.force_ip2int(r['addr']),
                [[p['port'], p['state_state']]
                 for p in r.get('ports', [])
                 if 'state_state' in p]
            ]
        else:
            r2res = lambda r: [
                utils.force_int2ip(r['addr']),
                [[p['port'], p['state_state']]
                 for p in r.get('ports', [])
                 if 'state_state' in p]
            ]
    elif action == "onlyips":
        result = db.nmap.get(flt, archive=archive, fields=['addr'])
        if hasattr(result, "count"):
            count = result.count()
        else:
            count = db.nmap.count(flt, archive=archive, fields=['addr'])
        if ipsasnumbers:
            r2res = lambda r: r['addr']
        else:
            r2res = lambda r: utils.int2ip(r['addr'])
    elif action == "diffcats":
        if request.params.get("onlydiff"):
            output = db.nmap.diff_categories(request.params.get("cat1"),
                                             request.params.get("cat2"),
                                             flt=flt,
                                             include_both_open=False)
        else:
            output = db.nmap.diff_categories(request.params.get("cat1"),
                                             request.params.get("cat2"),
                                             flt=flt)
        count = 0
        result = {}
        if ipsasnumbers:
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
    if callback is not None:
        if count >= config.WEB_WARN_DOTS_COUNT:
            yield (
                'if(confirm("You are about to ask your browser to display %d '
                'dots, which is a lot and might slow down, freeze or crash '
                'your browser. Do you want to continue?")) {\n' % count
            )
        yield '%s(\n' % callback
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
    if callback is not None:
        yield ");"
        if count >= config.WEB_WARN_DOTS_COUNT:
            yield '}\n'
    else:
        yield "\n"


@get('/cgi/scans/count')
@check_referer
def get_nmap_count():
    flt, archive, sortby, unused, skip, limit, callback, ipsasnumbers, \
        datesasstrings = get_nmap_base()
    count = db.nmap.count(flt, archive=archive)
    if callback is None:
        return "%d\n" % count
    return "%s(%d);\n" % (callback, count)


@get('/cgi/scans/top/<field>')
@check_referer
def get_nmap_top(field):
    flt, archive, sortby, unused, skip, limit, callback, ipsasnumbers, \
        datesasstrings = get_nmap_base()
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
    if callback is None:
        yield "[\n"
    else:
        yield "%s([\n" % callback
    # hack to avoid a trailing comma
    cursor = iter(db.nmap.topvalues(field, flt=flt, least=least, topnbr=topnbr,
                                    archive=archive))
    try:
        rec = next(cursor)
    except StopIteration:
        pass
    else:
        yield json.dumps({"label": rec['_id'], "value": rec['count']})
        for rec in cursor:
            yield ",\n%s" % json.dumps({"label": rec['_id'],
                                        "value": rec['count']})
    if callback is None:
        yield "\n]\n"
    else:
        yield "\n]);\n"


@get('/cgi/scans')
@check_referer
def get_nmap():
    flt, archive, sortby, unused, skip, limit, callback, ipsasnumbers, \
        datesasstrings = get_nmap_base()
    ## PostgreSQL: the query plan if affected by the limit and gives
    ## really poor results. This is a temporary workaround (look for
    ## XXX-WORKAROUND-PGSQL)
    # result = db.nmap.get(flt, archive=archive,
    #                      limit=limit, skip=skip, sort=sortby)
    result = db.nmap.get(flt, archive=archive,
                         skip=skip, sort=sortby)

    if unused:
        msg = 'Option%s not understood: %s' % (
            's' if len(unused) > 1 else '',
            ', '.join(unused),
        )
        if callback is not None:
            yield webutils.js_alert("param-unused", "warning", msg)
        utils.LOGGER.warning(msg)
    elif callback is not None:
        yield webutils.js_del_alert("param-unused")

    if config.DEBUG:
        msg1 = "filter: %r" % flt
        msg2 = "user: %r" % webutils.get_user()
        utils.LOGGER.debug(msg1)
        utils.LOGGER.debug(msg2)
        if callback is not None:
            yield webutils.js_alert("filter", "info", msg1)
            yield webutils.js_alert("user", "info", msg2)

    version_mismatch = {}
    if callback is None:
        tab, sep = "", "\n"
    else:
        tab, sep = "\t", ",\n"
        yield "%s([\n" % callback
    ## XXX-WORKAROUND-PGSQL
    # for rec in result:
    for i, rec in enumerate(result):
        for fld in ['_id', 'scanid']:
            try:
                del rec[fld]
            except KeyError:
                pass
        if not ipsasnumbers:
            try:
                rec['addr'] = utils.int2ip(rec['addr'])
            except:
                pass
        for field in ['starttime', 'endtime']:
            if field in rec:
                if not datesasstrings:
                    rec[field] = int(rec[field].strftime('%s'))
        for port in rec.get('ports', []):
            if 'screendata' in port:
                port['screendata'] = utils.encode_b64(port['screendata'])
            for script in port.get('scripts', []):
                if "masscan" in script:
                    try: del script['masscan']['raw']
                    except KeyError: pass
        if not ipsasnumbers:
            if 'traces' in rec:
                for trace in rec['traces']:
                    trace['hops'].sort(key=lambda x: x['ttl'])
                    for hop in trace['hops']:
                        try:
                            hop['ipaddr'] = utils.int2ip(hop['ipaddr'])
                        except:
                            pass
        yield "%s%s%s" % (
            tab, json.dumps(rec, default=utils.serialize), sep
        )
        check = db.nmap.cmp_schema_version_host(rec)
        if check:
            version_mismatch[check] = version_mismatch.get(check, 0) + 1
        # XXX-WORKAROUND-PGSQL
        if i + 1>= limit:
            break
    if callback is not None:
        yield "]);\n"

    messages = {
        1: lambda count: ("%d document%s displayed %s out-of-date. Please run "
                          "the following commands: 'ivre scancli "
                          "--update-schema; ivre scancli --update-schema "
                          "--archives'" % (count, 's' if count > 1 else '',
                                           'are' if count > 1 else 'is')),
        -1: lambda count: ('%d document%s displayed ha%s been inserted by '
                           'a more recent version of IVRE. Please update '
                           'IVRE!' % (count, 's' if count > 1 else '',
                                      've' if count > 1 else 's')),
    }
    for mismatch, count in viewitems(version_mismatch):
        message = messages[mismatch](count)
        if callback is not None:
            yield webutils.js_alert("version-mismatch-%d" % ((mismatch + 1) // 2),
                                    "warning", message)
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
    # archive records from same source
    def gettoarchive(addr, source):
        return db.nmap.get(
            db.nmap.flt_and(db.nmap.searchhost(addr),
                            db.nmap.searchsource(source))
        )
    count = 0
    categories = list(categories)
    for fileelt in files:
        fdesc = tempfile.NamedTemporaryFile(delete=False)
        fileelt.save(fdesc)
        try:
            if db.nmap.store_scan(fdesc.name, categories=categories,
                                  source=source, gettoarchive=gettoarchive):
                count += 1
                os.unlink(fdesc.name)
            else:
                utils.LOGGER.warning("Could not import %s" % fdesc.name)
        except:
            utils.LOGGER.warning("Could not import %s" % fdesc.name, exc_info=True)
    return count


@post('/cgi/scans')
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

@get('/cgi/flows')
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


@get('/dokuwiki/<filepath:path>')
def server_doku(filepath):
    if '.' not in os.path.basename(filepath):
        filepath += '.txt'
    utils.LOGGER.info("%r, %r", filepath, DOKUDIR)
    return static_file(filepath, root=DOKUDIR)


@get('/<filepath:path>')
def server_static(filepath):
    return static_file(filepath, root=BASEDIR)


def parse_args():
    """Imports the available module to parse the arguments and return
    the parsed arguments.

    """
    try:
        import argparse
        parser = argparse.ArgumentParser(description=__doc__)
    except ImportError:
        import optparse
        parser = optparse.OptionParser(description=__doc__)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
    parser.add_argument('--bind-address', '-b',
                        help='(IP) Address to bind the server to (defaults '
                        'to 127.0.0.1).',
                        default="127.0.0.1")
    parser.add_argument('--port', '-p', type=int, default=80,
                        help='(TCP) Port to use (defaults to 80)')
    return parser.parse_args()


def main():
    print(__doc__)
    args = parse_args()
    run(host=args.bind_address, port=args.port, debug=config.DEBUG)
