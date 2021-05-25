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


"""Create views from nmap and passive databases."""


import argparse
from typing import Generator, List


from ivre.activecli import displayfunction_json
from ivre.db import db, DB
from ivre.types import Record
from ivre.view import from_passive, from_nmap, to_view


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, parents=[DB().argparser])
    if db.nmap is None:
        fltnmap = None
    else:
        fltnmap = db.nmap.flt_empty
    if db.passive is None:
        fltpass = None
    else:
        fltpass = db.passive.flt_empty
    _from: List[Generator[Record, None, None]] = []

    parser.add_argument(
        "--view-category",
        metavar="CATEGORY",
        help="Choose a different category than the default",
    )
    parser.add_argument(
        "--test",
        "-t",
        action="store_true",
        help="Give results in standard output instead of "
        "inserting them in database.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="For test output, print out formatted results.",
    )
    parser.add_argument(
        "--no-merge",
        action="store_true",
        help="Do **not** " "merge with existing results for same host and " "source.",
    )

    subparsers = parser.add_subparsers(
        dest="view_source",
        help=(
            "Accepted values are 'nmap' and 'passive'. " "None or 'all' will do both"
        ),
    )
    if db.nmap is not None:
        subparsers.add_parser("nmap", parents=[db.nmap.argparser])
    if db.passive is not None:
        subparsers.add_parser("passive", parents=[db.passive.argparser])
    subparsers.add_parser("all")

    args = parser.parse_args()

    view_category = args.view_category
    if not args.view_source:
        args.view_source = "all"
    if args.view_source == "all":
        _from = []
        if db.nmap is not None:
            fltnmap = DB().parse_args(args, flt=fltnmap)
            _from.append(from_nmap(fltnmap, category=view_category))
        if db.passive is not None:
            fltpass = DB().parse_args(args, flt=fltpass)
            _from.append(from_passive(fltpass, category=view_category))
    elif args.view_source == "nmap":
        if db.nmap is None:
            parser.error('Cannot use "nmap" (no Nmap database exists)')
        fltnmap = db.nmap.parse_args(args, fltnmap)
        _from = [from_nmap(fltnmap, category=view_category)]
    elif args.view_source == "passive":
        if db.passive is None:
            parser.error('Cannot use "passive" (no Passive database exists)')
        fltpass = db.passive.parse_args(args, fltpass)
        _from = [from_passive(fltpass, category=view_category)]
    if args.test:

        def output(host: Record) -> None:
            return displayfunction_json([host], db.view)

    elif args.no_merge:
        output = db.view.store_host
    else:
        output = db.view.store_or_merge_host
    # Output results
    itr = to_view(_from)
    if not itr:
        return
    for elt in itr:
        output(elt)
