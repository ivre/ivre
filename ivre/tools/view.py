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


"""Put selected results in views."""


import argparse
import os
import sys
from typing import Callable


from ivre import graphroute
from ivre.db import db
from ivre.nmapout import displayhosts
from ivre.activecli import (
    display_short,
    display_distinct,
    displayfunction_json,
    displayfunction_honeyd,
    displayfunction_http_urls,
    displayfunction_nmapxml,
    displayfunction_gnmap,
    displayfunction_graphroute,
    displayfunction_explain,
    displayfunction_remove,
    displayfunction_csv,
)
from ivre.types import DBCursor
from ivre.utils import CLI_ARGPARSER


def main() -> None:
    displayfunction: Callable[[DBCursor], None]
    parser = argparse.ArgumentParser(
        description="Print out views.",
        parents=[db.view.argparser, CLI_ARGPARSER],
    )

    flt = db.view.flt_empty

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print out formatted results."
    )
    parser.add_argument(
        "--no-screenshots",
        action="store_true",
        help="When used with --json, do not output " "screenshots data.",
    )
    parser.add_argument(
        "--honeyd", action="store_true", help="Output results as a honeyd config file."
    )
    parser.add_argument(
        "--nmap-xml",
        action="store_true",
        help="Output results as a nmap XML output file.",
    )
    parser.add_argument(
        "--gnmap",
        action="store_true",
        help="Output results as a nmap grepable output file.",
    )
    parser.add_argument(
        "--graphroute",
        choices=["dot", "rtgraph3d"] if graphroute.HAVE_DBUS else ["dot"],
        help="Create a graph from traceroute results. "
        'dot: output result as Graphviz "dot" format to stdout.'
        "%s"
        % (" rtgraph3d: send results to rtgraph3d." if graphroute.HAVE_DBUS else ""),
    )
    parser.add_argument(
        "--graphroute-cluster",
        choices=["AS", "Country"],
        help="Cluster IP according to the specified criteria"
        "(only for --graphroute dot)",
    )
    if graphroute.HAVE_DBUS:
        parser.add_argument(
            "--graphroute-dont-reset",
            action="store_true",
            help="Do NOT reset graph (only for " "--graphroute rtgraph3d)",
        )
    parser.add_argument(
        "--graphroute-include",
        choices=["last-hop", "target"],
        help="How far should graphroute go? Default if to "
        "exclude the last hop and the target for each result.",
    )
    parser.add_argument(
        "--top",
        metavar="FIELD / ~FIELD",
        help="Output most common (least common: ~) values for "
        "FIELD, by default 10, use --limit to change that, "
        "--limit 0 means unlimited.",
    )
    parser.add_argument(
        "--csv",
        metavar="TYPE",
        help="Output result as a CSV file",
        choices=["ports", "hops"],
    )
    parser.add_argument(
        "--csv-separator",
        metavar="SEPARATOR",
        default=",",
        help="Select separator for --csv output",
    )
    parser.add_argument(
        "--csv-add-infos",
        action="store_true",
        help="Include country_code and as_number" "fields to CSV file",
    )
    parser.add_argument(
        "--csv-na-str",
        default="NA",
        help='String to use for "Not Applicable" value ' '(defaults to "NA")',
    )

    args = parser.parse_args()

    flt = db.view.parse_args(args)

    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                "This will remove any view in your database. Process ? [y/N] "
            )
            ans = input()
            if ans.lower() not in ["y", "yes"]:
                sys.exit(0)
        db.view.init()
        sys.exit(0)
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write("This will lock your database. " "Process ? [y/N] ")
            ans = input()
            if ans.lower() != "y":
                sys.exit(-1)
        db.view.ensure_indexes()
        sys.exit(0)

    if args.top is not None:
        sys.stdout.writelines(db.view.display_top(args.top, flt, args.limit))
        sys.exit(0)
    if args.sort is not None:
        sortkeys = [
            (field[1:], -1) if field.startswith("~") else (field, 1)
            for field in args.sort
        ]
    else:
        sortkeys = []
    if args.short:
        display_short(db.view, flt, sortkeys, args.limit, args.skip)
        sys.exit(0)
    if args.distinct is not None:
        display_distinct(db.view, args.distinct, flt, sortkeys, args.limit, args.skip)
        sys.exit(0)
    if args.explain:
        displayfunction_explain(flt, db.view)
        sys.exit(0)
    if args.delete:
        displayfunction_remove(flt, db.view)
        sys.exit(0)
    if args.json:

        def displayfunction(cur: DBCursor) -> None:
            return displayfunction_json(cur, db.view, args.no_screenshots)

    elif args.honeyd:
        displayfunction = displayfunction_honeyd
    elif args.http_urls:
        displayfunction = displayfunction_http_urls
    elif args.nmap_xml:
        displayfunction = displayfunction_nmapxml
    elif args.gnmap:
        displayfunction = displayfunction_gnmap
    elif args.graphroute is not None:

        def displayfunction(cur: DBCursor) -> None:
            return displayfunction_graphroute(
                cur,
                args.graphroute,
                args.graphroute_cluster,
                args.graphroute_include,
                args.graphroute_dont_reset,
            )

    elif args.csv is not None:

        def displayfunction(cur: DBCursor) -> None:
            return displayfunction_csv(
                cur, args.csv, args.csv_separator, args.csv_na_str, args.csv_add_infos
            )

    else:

        def displayfunction(cur: DBCursor) -> None:
            displayhosts(cur, out=sys.stdout)

    if args.update_schema:
        db.view.migrate_schema(args.version)
    elif args.count:
        sys.stdout.write(str(db.view.count(flt)) + "\n")
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
