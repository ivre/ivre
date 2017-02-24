#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
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

import json
import socket
import struct
import sys

try:
    from ivre import utils, webutils, config
    from ivre.db import db
except Exception as exc:
    sys.stdout.write('Content-Type: application/javascript\r\n\r\n')
    sys.stdout.write(
        'alert("ERROR: Could not import ivre. Check the server\'s logs!");'
    )
    sys.stderr.write(
        "CRITICAL:ivre:Cannot import ivre [%s (%r)].\n" % (exc.message, exc)
    )
    sys.exit(1)

webutils.check_referer()

def force_ip_int(addr):
    try:
        return utils.ip2int(addr)
    except (TypeError, struct.error):
        return addr

def force_ip_str(addr):
    try:
        return utils.int2ip(addr)
    except (TypeError, socket.error):
        return addr

def main():
    # write headers
    sys.stdout.write(webutils.JS_HEADERS)
    params = webutils.parse_query_string()
    query = webutils.query_from_params(params)
    flt, archive, sortby, unused, skip, limit = webutils.flt_from_query(query)
    if limit is None:
        limit = config.WEB_LIMIT
    if config.WEB_MAXRESULTS is not None:
        limit = min(limit, config.WEB_MAXRESULTS)
    callback = params.get("callback")
    # type of result
    action = params.get("action", "")
    ipsasnumbers = params.get("ipsasnumbers")
    datesasstrings = params.get("datesasstrings")
    if callback is None:
        sys.stdout.write('Content-Disposition: attachment; '
                         'filename="IVRE-results.json"\r\n')
    sys.stdout.write("\r\n")

    # top values
    if action.startswith('topvalues:'):
        field = action[10:]
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
        series = [{"label": t['_id'], "value": t['count']} for t in
                  db.nmap.topvalues(field, flt=flt,
                                    least=least, topnbr=topnbr,
                                    archive=archive)]
        if callback is None:
            sys.stdout.write("%s\n" % json.dumps(series))
        else:
            sys.stdout.write("%s(%s);\n" % (callback, json.dumps(series)))
        exit(0)

    # extract info
    if action in ["onlyips", "ipsports", "timeline", "coordinates",
                  "countopenports", "diffcats"]:
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
            if params.get("modulo") is None:
                r2time = lambda r: int(r['starttime'].strftime('%s'))
            else:
                r2time = lambda r: (int(r['starttime'].strftime('%s'))
                                    % int(params.get("modulo")))
            if ipsasnumbers:
                r2res = lambda r: [r2time(r), force_ip_int(r['addr']),
                                   r['openports']['count']]
            else:
                r2res = lambda r: [r2time(r), force_ip_str(r['addr']),
                                   r['openports']['count']]
        elif action == "coordinates":
            preamble = '{"type": "GeometryCollection", "geometries": ['
            postamble = ']}'
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
                r2res = lambda r: [force_ip_int(r['addr']),
                                   r['openports']['count']]
            else:
                r2res = lambda r: [force_ip_str(r['addr']),
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
                    force_ip_int(r['addr']),
                    [[p['port'], p['state_state']]
                     for p in r.get('ports', [])
                     if 'state_state' in p]
                ]
            else:
                r2res = lambda r: [
                    force_ip_str(r['addr']),
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
            if params.get("onlydiff"):
                output = db.nmap.diff_categories(params.get("cat1"),
                                                 params.get("cat2"),
                                                 flt=flt,
                                                 include_both_open=False)
            else:
                output = db.nmap.diff_categories(params.get("cat1"),
                                                 params.get("cat2"),
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
            result = result.iteritems()
        if count >= config.WEB_WARN_DOTS_COUNT:
            sys.stdout.write(
                'if(confirm("You are about to ask your browser to display %d '
                'dots, which is a lot and might slow down, freeze or crash '
                'your browser. Do you want to continue?")) {\n' % count
            )
        if callback is not None:
            sys.stdout.write("%s(\n" % callback)
        sys.stdout.write(preamble)
        for rec in result:
            sys.stdout.write(json.dumps(r2res(rec)) + ",\n")
        sys.stdout.write(postamble)
        if callback is not None:
            sys.stdout.write(");")
        sys.stdout.write("\n")
        if count >= config.WEB_WARN_DOTS_COUNT:
            sys.stdout.write('}\n')
        exit(0)

    # generic request
    if action == "count":
        if callback is None:
            sys.stdout.write("%d\n" % db.nmap.count(flt, archive=archive))
        else:
            sys.stdout.write("%s(%d);\n" % (callback,
                                            db.nmap.count(flt,
                                                          archive=archive)))
        exit(0)

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
        sys.stdout.write(webutils.js_alert("param-unused", "warning", msg))
        utils.LOGGER.warning(msg)
    elif callback is not None:
        sys.stdout.write(webutils.js_del_alert("param-unused"))

    if config.DEBUG:
        msg = "filter: %r" % flt
        sys.stdout.write(webutils.js_alert("filter", "info", msg))
        utils.LOGGER.debug(msg)
        msg = "user: %r" % webutils.get_user()
        sys.stdout.write(webutils.js_alert("user", "info", msg))
        utils.LOGGER.debug(msg)

    version_mismatch = {}
    if callback is None:
        tab, sep = "", "\n"
    else:
        tab, sep = "\t", ",\n"
        sys.stdout.write("%s([\n" % callback)
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
                port['screendata'] = port['screendata'].encode('base64')
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
        sys.stdout.write("%s%s%s" % (
            tab, json.dumps(rec, default=utils.serialize), sep
        ))
        check = db.nmap.cmp_schema_version_host(rec)
        if check:
            version_mismatch[check] = version_mismatch.get(check, 0) + 1
        # XXX-WORKAROUND-PGSQL
        if i + 1>= limit:
            break
    if callback is not None:
        sys.stdout.write("]);\n")

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
    for mismatch, count in version_mismatch.iteritems():
        message = messages[mismatch](count)
        sys.stdout.write(
            webutils.js_alert("version-mismatch-%d" % ((mismatch + 1) / 2),
                              "warning", message)
        )
        utils.LOGGER.warning(message)


if __name__ == '__main__':
    main()
