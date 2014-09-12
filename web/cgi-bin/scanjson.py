#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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

# Configuration MUST be done in a NON-EXECUTABLE file stored in the
# same directory than this CGI file and called scanjsonconfig.py. A
# sample for this file is provided as scanjsonconfig-sample.py

try:
    import sys
    import json
    import os
    import re
    import shlex
    import urllib
    import datetime
except Exception as exc:
    print 'Content-Type: application/javascript\r\n\r'
    print 'alert("ERROR: %s (%r)");' % (exc.message, exc)
    sys.exit(0)

try:
    import ivre.utils
    from ivre.db import db
except Exception as exc:
    sys.stdout.write('Content-Type: application/javascript\r\n\r\n')
    sys.stdout.write(
        'alert("ERROR: could not import ivre. Is the DB server '
        'available? %s (%r)");\n' % (exc.message, exc)
    )
    sys.exit(0)

try:
    import scanjsonconfig
except ImportError:
    scanjsonconfig = None

for configval, defaultvalue in {
        'ALLOWED_REFERERS': ['http://localhost/'],
        'MAXRESULTS': None,
        'INIT_QUERIES': {},
        'DEFAULT_INIT_QUERY': db.nmap.flt_empty,
        'WARN_DOTS_COUNT': 20000,
        'skip': 0,
        'limit': 10,
        'get_notepad_pages': None,
}.iteritems():
    try:
        globals()[configval] = getattr(scanjsonconfig, configval)
    except AttributeError:
        globals()[configval] = defaultvalue

# headers
sys.stdout.write("Content-Type: application/json\r\n\r\n")

# the anti-CSRF check
if ALLOWED_REFERERS is not None and \
   os.getenv('HTTP_REFERER') not in ALLOWED_REFERERS:
    sys.stdout.write('alert("ERROR: invalid Referer header.");\n')
    sys.exit(0)

ipaddr = re.compile('^\\d+\\.\\d+\\.\\d+\\.\\d+$')
netaddr = re.compile('^\\d+\\.\\d+\\.\\d+\\.\\d+'
                     '/\\d+(\\.\\d+\\.\\d+\\.\\d+)?$')
params = []
query = []
try:
    params = dict([[x.split('=', 1)[0], urllib.unquote(x.split('=', 1)[1])]
                  for x in os.getenv('QUERY_STRING').split('&')])
    qu = params.get('q', '')
    qu = [x.split(':', 1) for x in shlex.split(qu)]
    for q in qu:
        if q and q[0]:
            if len(q) == 1:
                query.append([q[0], None])
            else:
                query.append([q[0], q[1]])
except Exception as exc:
    sys.stderr.write('WARNING: %s [%r]' % (exc.message, exc))

callback = None
count = None
countfield = None
countfieldlimit = None
countfieldskip = None
countnbr = 10
onlyips = False
timeline = False
countopenports = False
ipsasnumbers = False
modulo = None
coordinates = False
for p in params:
    if p in ["callback", "jsonp"]:
        callback = params[p]
    elif p == "count":
        count = params[p]
    elif p == "countfield":
        countfield = params[p]
    elif p == "countfieldlimit":
        countfieldlimit = int(params[p])
    elif p == "countfieldskip":
        countfieldskip = int(params[p])
    elif p == "countnbr":
        countnbr = int(params[p])
    elif p == "onlyips":
        onlyips = True
    elif p == "timeline":
        timeline = True
    elif p == "countopenports":
        countopenports = True
    elif p == "ipsasnumbers":
        ipsasnumbers = True
    elif p == "modulo":
        modulo = int(params[p])
    elif p == "coordinates":
        coordinates = True

flt = INIT_QUERIES.get(os.getenv('REMOTE_USER'), DEFAULT_INIT_QUERY)
unused = []
sortby = []
archive = False
for q in query:
    if q[0].startswith('-') or q[0].startswith('!'):
        neg = True
        nq = q[0][1:]
    else:
        neg = False
        nq = q[0]
    if q[0] == "skip":
        skip = int(q[1])
    elif q[0] == "limit":
        limit = int(q[1])
        if MAXRESULTS is not None and (limit == 0 or limit > MAXRESULTS):
            limit = MAXRESULTS
    elif nq == "archives":
        archive = not neg
    elif nq == "host":
        flt = db.nmap.flt_and(flt, db.nmap.searchhost(q[1], neg=neg))
    elif nq == "hostname":
        flt = db.nmap.flt_and(
            flt, db.nmap.searchhostname(ivre.utils.str2regexp(q[1]),
                                        neg=neg))
    elif nq == "domain":
        flt = db.nmap.flt_and(
            flt, db.nmap.searchdomain(ivre.utils.str2regexp(q[1]),
                                      neg=neg))
    elif nq == "category":
        flt = db.nmap.flt_and(flt, db.nmap.searchcategory(
            ivre.utils.str2regexp(q[1]), neg=neg))
    elif nq == "country":
        flt = db.nmap.flt_and(flt, db.nmap.searchcountry(q[1], neg=neg))
    elif nq == "city":
        flt = db.nmap.flt_and(flt, db.nmap.searchcity(
            ivre.utils.str2regexp(q[1]), neg=neg))
    elif nq == "asnum":
        flt = db.nmap.flt_and(flt, db.nmap.searchasnum(q[1], neg=neg))
    elif nq == "source":
        flt = db.nmap.flt_and(flt, db.nmap.searchsource(q[1], neg=neg))
    elif nq == "net":
        flt = db.nmap.flt_and(flt, db.nmap.searchnet(q[1], neg=neg))
    elif nq == "range":
        flt = db.nmap.flt_and(flt, db.nmap.searchrange(
            *q[1].replace('-', ',').split(','),
            neg=neg))
    elif nq == "timerange":
        flt = db.nmap.flt_and(flt, db.nmap.searchtimerange(
            *map(float, q[1].replace('-', ',').split(',')),
            neg=neg))
    elif q[0] in ["nfsexports", "nfs"]:
        flt = db.nmap.flt_and(flt, db.nmap.searchnfs())
    elif q[0] in ["ypserv", "yp", "nis"]:
        flt = db.nmap.flt_and(flt, db.nmap.searchypserv())
    elif q[0] == "webmin":
        flt = db.nmap.flt_and(flt, db.nmap.searchwebmin())
    elif q[0] == "service":
        if ':' in q[1]:
            port, req = q[1].split(':', 1)
            port = int(port)
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchservice(
                    ivre.utils.str2regexp(req), port=port))
        else:
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchservice(
                    ivre.utils.str2regexp(q[1])))
    elif q[0] == "probedservice":
        if ':' in q[1]:
            port, req = q[1].split(':', 1)
            port = int(port)
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchservice(
                    ivre.utils.str2regexp(req), port=port, probed=True))
        else:
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchservice(
                    ivre.utils.str2regexp(q[1]), probed=True))
    elif q[0] in ["script", "portscript"]:
        v = q[1].split(':', 1)
        if len(v) == 1:
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchscriptid(
                    ivre.utils.str2regexp(v[0])))
        else:
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchscriptidout(
                    ivre.utils.str2regexp(v[0]),
                    ivre.utils.str2regexp(v[1])))
    elif q[0] == "hostscript":
        v = q[1].split(':', 1)
        if len(v) == 1:
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchhostscriptid(
                    ivre.utils.str2regexp(v[0])))
        else:
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchhostscriptidout(
                    ivre.utils.str2regexp(v[0]),
                    ivre.utils.str2regexp(v[1])))
    elif q[0] == "svchostname":
        flt = db.nmap.flt_and(
            flt,
            db.nmap.searchsvchostname(ivre.utils.str2regexp(q[1])))
    elif q[0] == "os":
        flt = db.nmap.flt_and(
            flt,
            db.nmap.searchos(ivre.utils.str2regexp(q[1])))
    elif q[0] == "anonftp":
        flt = db.nmap.flt_and(flt, db.nmap.searchftpanon())
    elif q[0] == "authhttp":
        flt = db.nmap.flt_and(flt, db.nmap.searchhttpauth())
    elif q[0] == 'authbypassvnc':
        flt = db.nmap.flt_and(flt, db.nmap.searchvncauthbypass())
    elif q[0] == 'mssqlemptypwd':
        flt = db.nmap.flt_and(flt, db.nmap.searchmssqlemptypwd())
    elif q[0] == 'mysqlemptypwd':
        flt = db.nmap.flt_and(flt, db.nmap.searchmysqlemptypwd())
    elif q[0] == 'x11':
        flt = db.nmap.flt_and(flt, db.nmap.searchx11())
    elif q[0] == 'x11open':
        flt = db.nmap.flt_and(flt, db.nmap.searchx11access())
    elif q[0] == 'anonldap':
        flt = db.nmap.flt_and(flt, db.nmap.searchldapanon())
    elif q[0] == 'xp445':
        flt = db.nmap.flt_and(flt, db.nmap.searchxp445())
    elif q[0] == 'banner':
        flt = db.nmap.flt_and(
            flt,
            db.nmap.searchbanner(ivre.utils.str2regexp(q[1])))
    elif nq == 'timeago':
        if q[1] and q[1][-1].isalpha():
            unit = {
                's': 1,
                'm': 60,
                'h': 3600,
                'd': 86400,
                'y': 31557600,
            }[q[1][-1]]
            timeago = int(q[1][:-1]) * unit
        else:
            timeago = int(q[1])
        flt = db.nmap.flt_and(flt, db.nmap.searchtimeago(
            datetime.timedelta(0, timeago), neg=neg))
    elif nq == 'sshkey':
        flt = db.nmap.flt_and(flt, db.nmap.searchsshkey(q[1]))
    elif nq == 'file':
        flt = db.nmap.flt_and(
            flt,
            db.nmap.searchfile(ivre.utils.str2regexp(q[1])))
    elif nq == 'webfiles':
        flt = db.nmap.flt_and(flt, db.nmap.searchwebfiles())
    elif nq == 'httptitle':
        flt = db.nmap.flt_and(
            flt,
            db.nmap.searchhttptitle(ivre.utils.str2regexp(q[1])))
    elif nq == 'owa':
        flt = db.nmap.flt_and(flt, db.nmap.searchowa())
    elif nq == 'cookie':
        flt = db.nmap.flt_and(flt, db.nmap.searchcookie(q[1]))
    elif nq == 'phpmyadmin':
        flt = db.nmap.flt_and(flt, db.nmap.searchphpmyadmin())
    elif nq in ['devicetype', 'devtype']:
        flt = db.nmap.flt_and(
            flt,
            db.nmap.searchdevicetype(ivre.utils.str2regexp(q[1])))
    elif nq in ['netdev', 'networkdevice']:
        flt = db.nmap.flt_and(flt, db.nmap.searchnetdev())
    elif nq == 'phonedev':
        flt = db.nmap.flt_and(flt, db.nmap.searchphonedev())
    elif nq == 'geovision':
        flt = db.nmap.flt_and(flt, db.nmap.searchgeovision())
    elif nq == 'torcert':
        flt = db.nmap.flt_and(flt, db.nmap.searchtorcert_active())
    elif nq == 'hop':
        flt = db.nmap.flt_and(flt,
                              db.nmap.searchhop(q[1], neg=neg))
    elif nq == 'hopname':
        flt = db.nmap.flt_and(flt,
                              db.nmap.searchhopname(q[1], neg=neg))
    elif nq == 'hopdomain':
        flt = db.nmap.flt_and(flt,
                              db.nmap.searchhopdomain(q[1], neg=neg))
    elif nq == 'sortby':
        if neg:
            sortby.append((q[1], -1))
        else:
            sortby.append((q[1], 1))
    elif nq in ['open', 'filtered', 'closed']:
        if '_' in q[1]:
            q[1] = q[1].replace('_', '/')
        if '/' in q[1]:
            proto, port = q[1].split('/')
            port = int(port)
        else:
            proto, port = "tcp", int(q[1])
        flt = db.nmap.flt_and(flt,
                              db.nmap.searchport(port, protocol=proto,
                                                 state=nq))
    elif nq == 'display':
        # ignore this parameter
        pass
    elif q[1] is None:
        if nq.startswith('tcp_') or nq.startswith('tcp/') or \
           nq.startswith('udp_') or nq.startswith('udp/'):
            proto, port = nq.replace('_', '/').split('/', 1)
            port = int(port)
            flt = db.nmap.flt_and(flt, db.nmap.searchport(port,
                                                          protocol=proto,
                                                          neg=neg))
        elif q[0] == "openport":
            flt = db.nmap.flt_and(flt, db.nmap.searchopenport())
        elif nq.isdigit():
            flt = db.nmap.flt_and(flt, db.nmap.searchport(int(nq), neg=neg))
        elif all(x.isdigit() for x in nq.split(',')):
            flt = db.nmap.flt_and(
                flt,
                db.nmap.searchports(map(int, nq.split(',')), neg=neg)
            )
        elif ipaddr.match(nq):
            flt = db.nmap.flt_and(flt, db.nmap.searchhost(nq, neg=neg))
        elif netaddr.match(nq):
            flt = db.nmap.flt_and(flt, db.nmap.searchnet(nq, neg=neg))
        elif get_notepad_pages is not None and nq == 'notes':
            flt = db.nmap.flt_and(flt, db.nmap.searchhosts(get_notepad_pages(),
                                                           neg=neg))
        elif '<' in q[0]:
            q[0] = q[0].split('<', 1)
            if q[0][1] and q[0][1][0] == '=':
                flt = db.nmap.flt_and(flt, db.nmap.searchcmp(q[0][0],
                                                             int(q[0][1]),
                                                             '<='))
            else:
                flt = db.nmap.flt_and(flt, db.nmap.searchcmp(q[0][0],
                                                             int(q[0][1]),
                                                             '<'))
        elif '>' in q[0]:
            q[0] = q[0].split('>', 1)
            if q[0][1] and q[0][1][0] == '=':
                flt = db.nmap.flt_and(flt, db.nmap.searchcmp(q[0][0],
                                                             int(q[0][1]),
                                                             '>='))
            else:
                flt = db.nmap.flt_and(flt, db.nmap.searchcmp(q[0][0],
                                                             int(q[0][1]),
                                                             '>'))
        else:
            unused.append(q[0])
    else:
        unused.append("%s=%s" % (q[0], q[1]))

if countfield is not None:
    if countfield[:1] in '-!':
        countfield = countfield[1:]
        least = True
    else:
        least = False
    series = [{"label": t['_id'], "value": t['count']} for t in
              db.nmap.topvalues(countfield, flt,
                                least=least, topnbr=countnbr,
                                limit=countfieldlimit, skip=countfieldskip,
                                archive=archive)]
    if callback is not None:
        sys.stdout.write("%s(%s);\n" % (callback, json.dumps(series)))
    else:
        sys.stdout.write("%s;\n" % json.dumps(series))
    exit(0)

if onlyips or timeline or coordinates or countopenports:
    preamble = "[\n"
    postamble = "]\n"
    r2count = lambda r: len(
        [p for p in r['ports'] if p.get('state_state') == 'open']
    ) if 'ports' in r else 0
    if timeline:
        result = db.nmap.get(flt, archive=archive,
                             fields=['addr', 'starttime', 'ports'])
        count = result.count()
        if modulo is None:
            r2time = lambda r: int(r['starttime'].strftime('%s'))
        else:
            r2time = lambda r: (
                (int(r['starttime'].strftime('%s')) - 79200) % modulo) + 82800
        if ipsasnumbers:
            r2res = lambda r: [r2time(r), r['addr'], r2count(r)]
        else:
            r2res = lambda r: [r2time(r),
                               ivre.utils.int2ip(r['addr']),
                               r2count(r)]
    elif coordinates:
        preamble = '{"type": "GeometryCollection", "geometries": ['
        postamble = ']}'
        result = db.nmap.getlocations(flt,
                                      archive=archive)
        count = len(result)
        r2res = lambda r: {
            "type": "Point",
            "coordinates": r['_id'],
            "properties": {"count": r['count']},
        }
    elif countopenports:
        result = db.nmap.get(flt, archive=archive,
                             fields=['addr', 'ports'])
        count = result.count()
        if ipsasnumbers:
            r2res = lambda r: [r['addr'], r2count(r)]
        else:
            r2res = lambda r: [ivre.utils.int2ip(r['addr']), r2count(r)]
    else:
        result = db.nmap.get(flt, archive=archive,
                             fields=['addr'])
        count = result.count()
        if ipsasnumbers:
            r2res = lambda r: r['addr']
        else:
            r2res = lambda r: ivre.utils.int2ip(r['addr'])
    if count >= WARN_DOTS_COUNT:
        sys.stdout.write(
            'if(confirm("You are about to ask your browser to display %d '
            'dots, which is a lot and might slow down, freeze or crash your '
            'browser. Do you want to continue?")) {\n' % count
        )
    if callback is not None:
        sys.stdout.write("%s(\n" % callback)
    sys.stdout.write(preamble)
    for r in result:
        sys.stdout.write(json.dumps(r2res(r)) + ",\n")
    sys.stdout.write(postamble)
    if callback is not None:
        sys.stdout.write(")")
    sys.stdout.write(";\n")
    if count >= WARN_DOTS_COUNT:
        sys.stdout.write('}\n')
    exit(0)

result = db.nmap.get(flt, archive=archive,
                     limit=limit, skip=skip, sort=sortby)

if count is not None:
    if callback is not None:
        sys.stdout.write("%s(%d);\n" % (callback, result.count()))
    else:
        sys.stdout.write("%d;\n" % result.count())
    exit(0)

if unused:
    sys.stdout.write('alert("WARNING: following option%s not understood, '
                     'and thus not considered: %s");\n' % (
                         len(unused) != 1 and 's' or '',
                         ', '.join(unused)
                     ))

# sys.stdout.write('alert("%r");\n' % flt)

for r in result:
    del(r['_id'])
    try:
        r['addr'] = ivre.utils.int2ip(r['addr'])
    except:
        pass
    for f in ['starttime', 'endtime']:
        if f in r:
            r[f] = int(r[f].strftime('%s'))
    if 'traces' in r:
        for k in r['traces']:
            k['hops'].sort(key=lambda x: x['ttl'])
            for h in k['hops']:
                try:
                    h['ipaddr'] = ivre.utils.int2ip(h['ipaddr'])
                except:
                    pass
    if callback is not None:
        sys.stdout.write("%s(%s);\n" % (callback, json.dumps(r)))
    else:
        sys.stdout.write("%s;\n" % json.dumps(r))
