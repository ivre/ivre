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


from __future__ import print_function
import functools
import json
import os
import time
try:
    import argparse
except ImportError:
    from itertools import chain
    import optparse
    USING_ARGPARSE = False
else:
    USING_ARGPARSE = True
import sys
try:
    reload(sys)
except NameError:
    pass
else:
    sys.setdefaultencoding('utf-8')


from builtins import input


from ivre.db import db
from ivre import utils


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
    if 'value' in rec:
        value = utils.printable(rec['value'])
        if isinstance(value, bytes):
            value = value.decode()
        print(value, end=' ')
    if 'version' in rec:
        print(rec['version'], end=' ')
    if 'signature' in rec:
        print('[%s]' % rec['signature'], end=' ')
    if 'distance' in rec:
        print("at %s hop%s" % (rec['distance'],
                               's' if rec['distance'] > 1 else ''), end=' ')
    if 'count' in rec:
        print("(%d time%s)" % (rec['count'], 's' if rec['count'] > 1 else ''),
              end=' ')
    if 'firstseen' in rec and 'lastseen' in rec:
        print(
            rec['firstseen'].replace(microsecond=0),
            '-',
            rec['lastseen'].replace(microsecond=0),
            end=' '
        )
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


def disp_recs_std(flt, sort, limit, skip):
    old_addr = None
    sort = sort or [('addr', 1), ('port', 1), ('recontype', 1), ('source', 1)]
    for rec in db.passive.get(flt, sort=sort, limit=limit, skip=skip):
        if 'addr' not in rec or not rec['addr']:
            continue
        if old_addr != rec['addr']:
            if old_addr is not None:
                print()
            old_addr = rec['addr']
            print(utils.force_int2ip(old_addr))
            ipinfo = db.data.infos_byip(old_addr)
            if ipinfo:
                if 'country_code' in ipinfo:
                    print('\t', end=' ')
                    print(ipinfo['country_code'], end=' ')
                    if 'country_name' in ipinfo:
                        cname = ipinfo['country_name']
                    else:
                        try:
                            cname = db.data.country_name_by_code(
                                ipinfo['country_code']
                            )
                        except AttributeError:
                            cname = None
                    if cname:
                        print('[%s]' % cname, end=' ')
                    print()
                if 'as_num' in ipinfo:
                    print('\t', end=' ')
                    print('AS%d' % ipinfo['as_num'], end=' ')
                    if 'as_name' in ipinfo:
                        print('[%s]' % ipinfo['as_name'], end=' ')
                    print()
                elif 'as_name' in ipinfo:
                    print('\t', end=' ')
                    print('AS???? [%s]' % ipinfo['as_name'], end=' ')
        disp_rec(rec)


def disp_recs_json(flt, sort, limit, skip):
    if os.isatty(sys.stdout.fileno()):
        indent = 4
    else:
        indent = None
    for rec in db.passive.get(flt, sort=sort, limit=limit, skip=skip):
        for fld in ['_id', 'scanid']:
            try:
                del rec[fld]
            except KeyError:
                pass
        if rec.get('recontype') == 'SSL_SERVER' and \
           rec.get('source') == 'cert':
            rec['value'] = utils.encode_b64(rec['value']).decode()
        print(json.dumps(rec, indent=indent, default=db.passive.serialize))


def disp_recs_short(flt, *_):
    for addr in db.passive.distinct('addr', flt=flt):
        print(db.passive.internal2ip(addr) if addr else None)


def disp_recs_distinct(field, flt, *_):
    for value in db.passive.distinct(field, flt=flt):
        print(value)


def disp_recs_top(top):
    return lambda flt, sort, limit, _: utils.display_top(db.passive, top, flt,
                                                         limit)


def disp_recs_count(flt, sort, limit, skip):
    print(db.passive.count(flt))


def _disp_recs_tail(flt, field, nbr):
    recs = list(db.passive.get(
        flt, sort=[(field, -1)], limit=nbr))
    recs.reverse()
    for r in recs:
        if 'addr' in r:
            print(utils.force_int2ip(r['addr']), end=' ')
        else:
            print(r['targetval'], end=' ')
        disp_rec(r)


def disp_recs_tail(nbr):
    return lambda flt, *_: _disp_recs_tail(flt, 'firstseen', nbr)


def disp_recs_tailnew(nbr):
    return lambda flt, *_: _disp_recs_tail(flt, 'lastseen', nbr)


def _disp_recs_tailf(flt, field):
    # 1. init
    firstrecs = list(db.passive.get(
        flt, sort=[(field, -1)], limit=10))
    firstrecs.reverse()
    # in case we don't have (yet) records matching our criteria
    r = {'firstseen': 0, 'lastseen': 0}
    for r in firstrecs:
        if 'addr' in r:
            print(utils.force_int2ip(r['addr']), end=' ')
        else:
            print(r['targetval'], end=' ')
        disp_rec(r)
        sys.stdout.flush()
    # 2. loop
    try:
        while True:
            prevtime = r[field]
            time.sleep(1)
            for r in db.passive.get(
                    db.passive.flt_and(
                        baseflt,
                        db.passive.searchnewer(prevtime,
                                               new=field == 'lastseen'),
                    ),
                    sort=[(field, 1)]):
                if 'addr' in r:
                    print(utils.force_int2ip(r['addr']), end=' ')
                else:
                    print(r['targetval'], end=' ')
                disp_rec(r)
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass


def disp_recs_tailfnew():
    return lambda flt, *_: _disp_recs_tailf(flt, 'firstseen')


def disp_recs_tailf():
    return lambda flt, *_: _disp_recs_tailf(flt, 'lastseen')


def disp_recs_explain(flt, sort, limit, skip):
    print(db.passive.explain(db.passive._get(flt, sort=sort, limit=limit,
                                             skip=skip), indent=4))


def main():
    global baseflt
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(
            description='Access and query the passive database.',
            parents=[db.passive.argparser, utils.CLI_ARGPARSER],
        )
    else:
        parser = optparse.OptionParser(
            description='Access and query the passive database.',
        )
        for args, kargs in chain(db.passive.argparser.args,
                                 utils.CLI_ARGPARSER):
            parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args

        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('ips', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option
    baseflt = db.passive.flt_empty
    disp_recs = disp_recs_std
    # display modes
    parser.add_argument('--tail', metavar='COUNT', type=int,
                        help='Output latest COUNT results.')
    parser.add_argument('--tailnew', metavar='COUNT', type=int,
                        help='Output latest COUNT new results.')
    parser.add_argument('--tailf', action='store_true',
                        help='Output continuously latest results.')
    parser.add_argument('--tailfnew', action='store_true',
                        help='Output continuously latest results.')
    parser.add_argument('--top', metavar='FIELD / ~FIELD',
                        help='Output most common (least common: ~) values for '
                        'FIELD, by default 10, use --limit to change that, '
                        '--limit 0 means unlimited.')
    if USING_ARGPARSE:
        parser.add_argument('ips', nargs='*',
                            help='Display results for specified IP addresses'
                            ' or ranges.')
    args = parser.parse_args()
    baseflt = db.passive.parse_args(args, baseflt)
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
    if args.update_schema:
        db.passive.migrate_schema(None)
        exit(0)
    if args.short:
        disp_recs = disp_recs_short
    elif args.distinct is not None:
        disp_recs = functools.partial(disp_recs_distinct, args.distinct)
    elif args.json:
        disp_recs = disp_recs_json
    elif args.top is not None:
        disp_recs = disp_recs_top(args.top)
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
    if args.sort is None:
        sort = []
    else:
        sort = [(field[1:], -1) if field.startswith('~') else (field, 1)
                for field in args.sort]
    if not args.ips:
        if not baseflt and not args.limit and disp_recs == disp_recs_std:
            # default to tail -f mode
            disp_recs = disp_recs_tailfnew()
        disp_recs(baseflt, sort, args.limit or db.passive.no_limit,
                  args.skip or 0)
        exit(0)
    first = True
    for a in args.ips:
        if first:
            first = False
        else:
            print()
        flt = baseflt.copy()
        if '/' in a:
            flt = db.passive.flt_and(flt, db.passive.searchnet(a))
        elif '-' in a:
            a = a.split('-', 1)
            if a[0].isdigit():
                a[0] = int(a[0])
            if a[1].isdigit():
                a[1] = int(a[1])
            flt = db.passive.flt_and(flt, db.passive.searchrange(a[0], a[1]))
        else:
            if a.isdigit():
                a = utils.force_int2ip(int(a))
            flt = db.passive.flt_and(flt, db.passive.searchhost(a))
        disp_recs(flt, sort, args.limit or db.passive.no_limit, args.skip or 0)
