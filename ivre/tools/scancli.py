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
try:
    import argparse
except ImportError:
    from itertools import chain
    import optparse
    USING_ARGPARSE = False
else:
    USING_ARGPARSE = True
import os
import sys
try:
    reload(sys)
except NameError:
    pass
else:
    sys.setdefaultencoding('utf-8')


from builtins import input

from ivre import db, graphroute, nmapout
from ivre.activecli import display_short, display_distinct, \
    displayfunction_json, displayfunction_honeyd, displayfunction_nmapxml, \
    displayfunction_gnmap, displayfunction_graphroute, \
    displayfunction_explain, displayfunction_remove, displayfunction_csv
from ivre.utils import display_top, CLI_ARGPARSER


def main():
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(
            description='Access and query the active scans database.',
            parents=[db.db.nmap.argparser, CLI_ARGPARSER],
        )
    else:
        parser = optparse.OptionParser(
            description='Access and query the active scans database.',
        )
        for args, kargs in chain(db.db.nmap.argparser.args,
                                 CLI_ARGPARSER.args):
            parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
    parser.add_argument('--no-screenshots', action='store_true',
                        help='When used with --json, do not output '
                        'screenshots data.')
    parser.add_argument('--honeyd', action='store_true',
                        help='Output results as a honeyd config file.')
    parser.add_argument('--nmap-xml', action='store_true',
                        help='Output results as a nmap XML output file.')
    parser.add_argument('--gnmap', action='store_true',
                        help='Output results as a nmap grepable output file.')
    parser.add_argument(
        '--graphroute',
        choices=["dot", "rtgraph3d"] if graphroute.HAVE_DBUS else ["dot"],
        help='Create a graph from traceroute results. '
        'dot: output result as Graphviz "dot" format to stdout.'
        '%s' % (" rtgraph3d: send results to rtgraph3d."
                if graphroute.HAVE_DBUS else "")
    )
    parser.add_argument('--graphroute-cluster', choices=['AS', 'Country'],
                        help='Cluster IP according to the specified criteria'
                        '(only for --graphroute dot)')
    if graphroute.HAVE_DBUS:
        parser.add_argument('--graphroute-dont-reset', action='store_true',
                            help='Do NOT reset graph (only for '
                            '--graphroute rtgraph3d)')
    parser.add_argument('--graphroute-include', choices=['last-hop', 'target'],
                        help='How far should graphroute go? Default if to '
                        'exclude the last hop and the target for each result.')
    parser.add_argument('--top', metavar='FIELD / ~FIELD',
                        help='Output most common (least common: ~) values for '
                        'FIELD, by default 10, use --limit to change that, '
                        '--limit 0 means unlimited.')
    parser.add_argument('--csv', metavar='TYPE',
                        help='Output result as a CSV file',
                        choices=['ports', 'hops'])
    parser.add_argument('--csv-separator', metavar='SEPARATOR',
                        default=",",
                        help='Select separator for --csv output')
    parser.add_argument('--csv-add-infos', action='store_true',
                        help="Include country_code and as_number"
                        "fields to CSV file")
    parser.add_argument('--csv-na-str', default="NA",
                        help='String to use for "Not Applicable" value '
                        '(defaults to "NA")')
    args = parser.parse_args()

    out = sys.stdout

    hostfilter = db.db.nmap.parse_args(args)
    sortkeys = []
    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will remove any scan result in your database. '
                'Process ? [y/N] ')
            ans = input()
            if ans.lower() != 'y':
                sys.exit(-1)
        db.db.nmap.init()
        sys.exit(0)
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will lock your database. '
                'Process ? [y/N] ')
            ans = input()
            if ans.lower() != 'y':
                sys.exit(-1)
        db.db.nmap.ensure_indexes()
        sys.exit(0)
    if args.top is not None:
        display_top(db.db.nmap, args.top, hostfilter, args.limit)
        sys.exit(0)
    if args.sort is not None:
        sortkeys = [(field[1:], -1) if field.startswith('~') else (field, 1)
                    for field in args.sort]
    if args.short:
        display_short(db.db.nmap, hostfilter, sortkeys, args.limit, args.skip)
        sys.exit(0)
    if args.distinct is not None:
        display_distinct(db.db.nmap, args.distinct, hostfilter, sortkeys,
                         args.limit, args.skip)
        sys.exit(0)
    if args.explain:
        displayfunction_explain(hostfilter, db.db.nmap)
        sys.exit(0)
    if args.json:
        def displayfunction(x):
            return displayfunction_json(
                x, db.db.nmap, args.no_screenshots
            )
    elif args.honeyd:
        displayfunction = displayfunction_honeyd
    elif args.nmap_xml:
        displayfunction = displayfunction_nmapxml
    elif args.gnmap:
        displayfunction = displayfunction_gnmap
    elif args.graphroute is not None:
        def displayfunction(x):
            return displayfunction_graphroute(
                x, args.graphroute, args.graphroute_include,
                args.graphroute_dont_reset
            )
    elif args.delete:
        def displayfunction(x):
            return displayfunction_remove(x, db.db.nmap)
    elif args.csv is not None:
        def displayfunction(x):
            return displayfunction_csv(
                x, args.csv, args.csv_separator, args.csv_na_str,
                args.csv_add_infos
            )
    else:

        def displayfunction(cursor):
            nmapout.displayhosts(cursor, out=out)

    if args.update_schema:
        db.db.nmap.migrate_schema(args.version)
    elif args.count:
        out.write(
            str(db.db.nmap.count(hostfilter)) + '\n'
        )
    else:
        kargs = {}
        if args.limit is not None:
            kargs["limit"] = args.limit
        if args.skip is not None:
            kargs["skip"] = args.skip
        if sortkeys:
            kargs["sort"] = sortkeys
        cursor = db.db.nmap.get(hostfilter, **kargs)
        displayfunction(cursor)
        sys.exit(0)
