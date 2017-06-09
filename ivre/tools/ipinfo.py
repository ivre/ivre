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


from __future__ import print_function
import datetime
import functools
import os
import struct
import time
try:
    import argparse
    USING_ARGPARSE = True
except ImportError:
    import optparse
    USING_ARGPARSE = False
import sys
try:
    reload(sys)
except NameError:
    pass
else:
    sys.setdefaultencoding('utf-8')


from builtins import input


from ivre.db import db
import ivre.utils


def disp_rec(rec):
    print('\t', end=' ')
    if 'port' in rec and rec['port']:
        print(rec['port'], end=' ')
    if 'recontype' in rec:
        try:
            print(rec['recontype'].value, end=' ')
        except AttributeError:
            print(rec['recontype'], end=' ')
    if 'source' in rec:
        print(rec['source'], end=' ')
    if 'infos' not in rec and 'value' in rec:
        if 'fullvalue' in rec:
            rec['value'] = rec['fullvalue']
        print(rec['value'], end=' ')
    if 'version' in rec:
        print(rec['version'], end=' ')
    if 'signature' in rec:
        print('[%s]' % rec['signature'], end=' ')
    if 'distance' in rec:
        print("at %s hop%s" % (rec['distance'], rec['distance'] > 1 and 's' or ''), end=' ')
    if 'count' in rec:
        print("(%d time%s)" % (rec['count'], rec['count'] > 1 and 's' or ''), end=' ')
    if 'firstseen' in rec and 'lastseen' in rec:
        if isinstance(rec['firstseen'], datetime.datetime):
            print(rec['firstseen'], '-', rec['lastseen'], end=' ')
        else:
            print(datetime.datetime.fromtimestamp(int(rec['firstseen'])), '-', end=' ')
            print(datetime.datetime.fromtimestamp(int(rec['lastseen'])), end=' ')
    if 'sensor' in rec:
        print(rec['sensor'], end=' ')
    print()
    if 'infos' in rec:
        for i in rec['infos']:
            print('\t\t', i + ':', end=' ')
            if i == 'domainvalue':
                print(rec['infos'][i][0])
            else:
                print(rec['infos'][i])


def disp_recs_std(flt):
    oa = None
    c = db.passive.get(flt, sort=[('addr', 1), ('recontype', 1), ('source', 1),
                                  ('port', 1)])
    for rec in c:
        if not 'addr' in rec or rec['addr'] == 0:
            continue
        if oa != rec['addr']:
            if oa is not None:
                print()
            oa = rec['addr']
            try:
                print(ivre.utils.int2ip(oa))
            except (struct.error, TypeError):
                print(oa)
            c = db.data.infos_byip(oa)
            if c:
                if 'country_code' in c:
                    print('\t', end=' ')
                    print(c['country_code'], end=' ')
                    try:
                        print('[%s]' % db.data.country_name_by_code(
                            c['country_code']
                        ), end=' ')
                    except:
                        pass
                    print()
                if 'as_num' in c:
                    print('\t', end=' ')
                    print('AS%d' % c['as_num'], end=' ')
                    if 'as_name' in c:
                        print('[%s]' % c['as_name'], end=' ')
                    print()
                elif 'as_name' in c:
                    print('\t', end=' ')
                    print('AS???? [%s]' % c['as_name'], end=' ')
        disp_rec(rec)


def disp_recs_short(flt):
    for addr in db.passive.distinct('addr', flt=flt):
        print(ivre.utils.int2ip(addr))


def disp_recs_distinct(field, flt):
    for value in db.passive.distinct(field, flt=flt):
        print(value)


def disp_recs_count(flt):
    print(db.passive.count(flt))


def _disp_recs_tail(flt, field, n):
    recs = list(db.passive.get(
        flt, sort=[(field, -1)], limit=n))
    recs.reverse()
    for r in recs:
        if 'addr' in r:
            print(ivre.utils.int2ip(r['addr']), end=' ')
        else:
            if 'fulltargetval' in r:
                print(r['fulltargetval'], end=' ')
            else:
                print(r['targetval'], end=' ')
        disp_rec(r)


def disp_recs_tail(n):
    return lambda flt: _disp_recs_tail(flt, 'firstseen', n)


def disp_recs_tailnew(n):
    return lambda flt: _disp_recs_tail(flt, 'lastseen', n)


def _disp_recs_tailf(flt, field):
    # 1. init
    firstrecs = list(db.passive.get(
        flt, sort=[(field, -1)], limit=10))
    firstrecs.reverse()
    # in case we don't have (yet) records matching our criteria
    r = {'firstseen': 0, 'lastseen': 0}
    for r in firstrecs:
        if 'addr' in r:
            print(ivre.utils.int2ip(r['addr']), end=' ')
        else:
            if 'fulltargetval' in r:
                print(r['fulltargetval'], end=' ')
            else:
                print(r['targetval'], end=' ')
        disp_rec(r)
    # 2. loop
    try:
        while True:
            prevtime = r[field]
            time.sleep(1)
            for r in db.passive.get(
                    db.passive.flt_and(
                        baseflt, {field: {'$gt': prevtime}}),
                    sort=[(field, 1)]):
                if 'addr' in r:
                    print(ivre.utils.int2ip(r['addr']), end=' ')
                else:
                    if 'fulltargetval' in r:
                        print(r['fulltargetval'], end=' ')
                    else:
                        print(r['targetval'], end=' ')
                disp_rec(r)
    except KeyboardInterrupt:
        pass


def disp_recs_tailfnew():
    return lambda flt: _disp_recs_tailf(flt, 'firstseen')


def disp_recs_tailf():
    return lambda flt: _disp_recs_tailf(flt, 'lastseen')


def disp_recs_explain(flt):
    print(db.passive.explain(db.passive.get(flt), indent=4))

def main():
    global baseflt
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(
            description='Access and query the passive database.')
    else:
        parser = optparse.OptionParser(
            description='Access and query the passive database.')
        parser.parse_args_orig = parser.parse_args
        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('ips', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option
    baseflt = db.passive.flt_empty
    disp_recs = disp_recs_std
    # DB
    parser.add_argument('--init', '--purgedb', action='store_true',
                        help='Purge or create and initialize the database.')
    parser.add_argument('--ensure-indexes', action='store_true',
                        help='Create missing indexes (will lock the database).')
    # filters
    parser.add_argument('--sensor')
    parser.add_argument('--country')
    parser.add_argument('--asnum')
    parser.add_argument('--torcert', action='store_true')
    parser.add_argument('--dns')
    parser.add_argument('--dnssub')
    parser.add_argument('--cert')
    parser.add_argument('--basicauth', action='store_true')
    parser.add_argument('--auth', action='store_true')
    parser.add_argument('--java', action='store_true')
    parser.add_argument('--ua')
    parser.add_argument('--ftp', action='store_true')
    parser.add_argument('--pop', action='store_true')
    parser.add_argument('--timeago', type=int)
    parser.add_argument('--timeagonew', type=int)
    # display modes
    parser.add_argument('--short', action='store_true',
                        help='Output only IP addresses, one per line.')
    parser.add_argument('--tail', metavar='COUNT', type=int,
                        help='Output latest COUNT results.')
    parser.add_argument('--tailnew', metavar='COUNT', type=int,
                        help='Output latest COUNT new results.')
    parser.add_argument('--tailf', action='store_true',
                        help='Output continuously latest results.')
    parser.add_argument('--tailfnew', action='store_true',
                        help='Output continuously latest results.')
    parser.add_argument('--count', action='store_true',
                        help='Count matched results.')
    parser.add_argument('--explain', action='store_true',
                        help='MongoDB specific: .explain() the query.')
    parser.add_argument('--distinct', metavar='FIELD',
                        help='Output only unique FIELD part of the '
                        'results, one per line.')
    parser.add_argument('--delete', action='store_true',
                        help='DELETE the matched results instead of '
                        'displaying them.')
    if USING_ARGPARSE:
        parser.add_argument('ips', nargs='*',
                            help='Display results for specified IP addresses'
                            ' or ranges.')
    args = parser.parse_args()
    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will remove any passive information in your '
                'database. Process ? [y/N] '
            )
            ans = input()
            if ans.lower() != 'y':
                exit(0)
        db.passive.init()
        exit(0)
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will lock your database. Process ? [y/N] '
            )
            ans = input()
            if ans.lower() != 'y':
                exit(0)
        db.passive.ensure_indexes()
        exit(0)
    if args.sensor is not None:
        baseflt = db.passive.flt_and(
            baseflt,
            db.passive.searchsensor(args.sensor)
        )
    if args.asnum is not None:
        if args.asnum.startswith('!') or args.asnum.startswith('-'):
            baseflt = db.passive.flt_and(
                baseflt,
                db.passive.searchasnum(int(args.asnum[1:]), neg=True)
            )
        else:
            baseflt = db.passive.flt_and(
                baseflt,
                db.passive.searchasnum(int(args.asnum))
            )
    if args.country is not None:
        baseflt = db.passive.flt_and(
            baseflt,
            db.passive.searchcountry(args.country)
        )
    if args.torcert:
        baseflt = db.passive.flt_and(baseflt, db.passive.searchtorcert())
    if args.basicauth:
        baseflt = db.passive.flt_and(baseflt, db.passive.searchbasicauth())
    if args.auth:
        baseflt = db.passive.flt_and(baseflt, db.passive.searchhttpauth())
    if args.ua is not None:
        baseflt = db.passive.flt_and(
            baseflt,
            db.passive.searchuseragent(ivre.utils.str2regexp(args.ua))
        )
    if args.java:
        baseflt = db.passive.flt_and(
            baseflt,
            db.passive.searchjavaua()
        )
    if args.ftp:
        baseflt = db.passive.flt_and(baseflt, db.passive.searchftpauth())
    if args.pop:
        baseflt = db.passive.flt_and(baseflt, db.passive.searchpopauth())
    if args.dns is not None:
        baseflt = db.passive.flt_and(
            baseflt,
            db.passive.searchdns(
                ivre.utils.str2regexp(args.dns),
                subdomains=False))
    if args.dnssub is not None:
        baseflt = db.passive.flt_and(
            baseflt,
            db.passive.searchdns(
                ivre.utils.str2regexp(args.dnssub),
                subdomains=True))
    if args.cert is not None:
        baseflt = db.passive.flt_and(
            baseflt,
            db.passive.searchcertsubject(
                ivre.utils.str2regexp(args.cert)))
    if args.timeago is not None:
        baseflt = db.passive.flt_and(db.passive.searchtimeago(args.timeago,
                                                              new=False))
    if args.timeagonew is not None:
        baseflt = db.passive.flt_and(db.passive.searchtimeago(args.timeagonew,
                                                              new=True))
    if args.short:
        disp_recs = disp_recs_short
    elif args.distinct is not None:
        disp_recs = functools.partial(disp_recs_distinct, args.distinct)
    elif args.tail is not None:
        disp_recs = disp_recs_tail(args.tail)
    elif args.tailnew is not None:
        disp_recs = disp_recs_tailnew(args.tailnew)
    elif args.tailf:
        disp_recs = disp_recs_tailf()
    elif args.tailfnew:
        disp_recs = disp_recs_tailfnew()
    elif args.count:
        disp_recs = disp_recs_count
    elif args.delete:
        disp_recs = db.passive.remove
    elif args.explain:
        disp_recs = disp_recs_explain
    if not args.ips:
        if not baseflt and disp_recs == disp_recs_std:
            # default to tail -f mode
            disp_recs = disp_recs_tailfnew()
        disp_recs(baseflt)
        exit(0)
    first = True
    for a in args.ips:
        if first:
            first = False
        else:
            print()
        flt = baseflt.copy()
        if ':' in a:
            a = a.split(':', 1)
            if a[0].isdigit():
                a[0] = int(a[0])
            if a[1].isdigit():
                a[1] = int(a[1])
            flt = db.passive.flt_and(flt, db.passive.searchrange(a[0], a[1]))
        elif '-' in a:
            a = a.split('-', 1)
            if a[0].isdigit():
                a[0] = int(a[0])
            if a[1].isdigit():
                a[1] = int(a[1])
            flt = db.passive.flt_and(flt, db.passive.searchrange(a[0], a[1]))
        elif '/' in a:
            flt = db.passive.flt_and(flt, db.passive.searchnet(a))
        else:
            if a.isdigit():
                a = ivre.utils.int2ip(int(a))
            flt = db.passive.flt_and(flt, db.passive.searchhost(a))
        disp_recs(flt)
