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

"""Put selected results in views."""

from __future__ import print_function
import os
import sys

from builtins import input

from ivre import graphroute
from ivre.db import db
from ivre.activecli import display_short, display_distinct, \
    displayfunction_json, displayfunction_honeyd, displayfunction_nmapxml, \
    displayfunction_graphroute, displayfunction_explain, \
    displayfunction_remove, displayfunction_csv
from ivre.utils import display_top

try:
    import argparse
    USING_ARGPARSE = True
except ImportError:
    import optparse
    USING_ARGPARSE = False


def main():
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(
            description='Print out views.',
            parents=[db.view.argparser])
    else:
        parser = optparse.OptionParser(
            description='Print out views.')
        for args, kargs in db.view.argparser.args:
            parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args

        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('ips', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option

    flt = db.view.flt_empty

    parser.add_argument('--delete', action='store_true',
                        help='Remove results instead of displaying them.')
    parser.add_argument('--init', '--purgedb', action='store_true',
                        help='Purge or create and initialize view.')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print out formated results.')
    parser.add_argument('--count', action='store_true',
                        help='Output number of results.')
    parser.add_argument('--short', action='store_true',
                        help='Print only addresses of filtered results.')
    parser.add_argument('--distinct', metavar='FIELD',
                        help='Output only unique FIELD part of the results.')
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON documents.')
    parser.add_argument('--no-screenshots', action='store_true',
                        help='When used with --json, do not output '
                        'screenshots data.')
    parser.add_argument('--honeyd', action='store_true',
                        help='Output results as a honeyd config file.')
    parser.add_argument('--nmap-xml', action='store_true',
                        help='Output results as a nmap XML output file.')
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
    parser.add_argument('--explain', action='store_true',
                        help='MongoDB specific: .explain() the query.')
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
    if USING_ARGPARSE:
        parser.add_argument('--sort', metavar='FIELD / ~FIELD', nargs='+',
                            help='Sort results according to FIELD; use ~FIELD '
                            'to reverse sort order.')
    else:
        parser.add_argument('--sort', metavar='FIELD / ~FIELD',
                            help='Sort results according to FIELD; use ~FIELD '
                            'to reverse sort order.')
    parser.add_argument('--limit', type=int,
                        help='Ouput at most LIMIT results.')
    parser.add_argument('--skip', type=int,
                        help='Skip first SKIP results.')

    args = parser.parse_args()

    flt = db.view.parse_args(args)

    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will remove any view in your database. Process ? [y/N] '
            )
            ans = input()
            if ans.lower() not in ['y', 'yes']:
                exit(0)
        db.view.init()
        exit(0)

    if args.top is not None:
        display_top(db.view, args.top, flt, args.limit)
        sys.exit(0)
    if args.sort is not None:
        sortkeys = [(field[1:], -1) if field.startswith('~') else (field, 1)
                    for field in args.sort]
    else:
        sortkeys = []
    if args.short:
        display_short(db.view, flt, sortkeys, args.limit, args.skip)
        sys.exit(0)
    elif args.distinct is not None:
        display_distinct(db.view, args.distinct, flt, sortkeys,
                         args.limit, args.skip)
        sys.exit(0)
    if args.json:
        displayfunction = lambda x: displayfunction_json(
            x, db.view, args.no_screenshot
        )
    elif args.honeyd:
        displayfunction = displayfunction_honeyd
    elif args.nmap_xml:
        displayfunction = displayfunction_nmapxml
    elif args.graphroute is not None:
        displayfunction = lambda x: displayfunction_graphroute(
            x, args.graphroute, args.graphroute_include,
            args.graphroute_dont_reset
        )
    elif args.explain:
        displayfunction = lambda x: displayfunction_explain(x, db.view)
    elif args.delete:
        displayfunction = lambda x: displayfunction_remove(x, db.view)
    elif args.csv is not None:
        displayfunction = lambda x: displayfunction_csv(
            x, args.csv, args.csv_separator, args.csv_na_str,
            args.csv_add_infos
        )
    else:

        def displayfunction(cursor):
            for rec in cursor:
                sys.stdout.write(str(rec) + '\n')

    if args.count:
        sys.stdout.write(
            str(db.view.count(flt)) + '\n'
        )
    else:
        kargs = {}
        if args.limit is not None:
            kargs["limit"] = args.limit
        if args.skip is not None:
            kargs["skip"] = args.skip
        if sortkeys:
            kargs["sort"] = sortkeys
        cursor = db.view.get(flt, **kargs)
        displayfunction(cursor)
        sys.exit(0)
