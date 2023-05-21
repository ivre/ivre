#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2023 Pierre LALET <pierre@droids-corp.org>
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
from functools import reduce
from multiprocessing import Pool, cpu_count
from typing import Generator, List, Optional

from ivre.active.data import merge_host_docs
from ivre.activecli import displayfunction_json
from ivre.db import DB, DBView, db
from ivre.types import Record
from ivre.view import (
    nmap_to_view,
    passive_to_view,
    prepare_record,
    to_view,
    to_view_parallel,
)


def merge_and_output(records: List[Record]) -> None:
    result = reduce(
        lambda r1, r2: merge_host_docs(
            r1, r2, auto_tags=False, openports_attribute=False
        ),
        records,
    )
    w_output(prepare_record(result, w_datadb))  # type: ignore


def worker_initializer(dburl: Optional[str], no_merge: bool) -> None:
    # pylint: disable=global-variable-undefined
    global w_datadb, w_outdb, w_output
    w_outdb = db.view if dburl is None else DBView.from_url(dburl)  # type: ignore
    if no_merge:
        w_output = w_outdb.store_host  # type: ignore
    else:
        w_output = w_outdb.store_or_merge_host  # type: ignore
    try:
        w_datadb = w_outdb.globaldb.data  # type: ignore
    except AttributeError:
        w_datadb = None  # type: ignore
    w_outdb.start_store_hosts()  # type: ignore


def worker_destroyer(_: None) -> None:
    w_outdb.stop_store_hosts()  # type: ignore


def main() -> None:
    default_processes = max(1, cpu_count())
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
        help="Do **not** merge with existing results for same host and source.",
    )
    parser.add_argument(
        "--to-db",
        metavar="DB_URL",
        help="Store data to the provided URL instead of the default DB for view.",
    )
    parser.add_argument(
        "--processes",
        metavar="COUNT",
        type=int,
        help=f"The number of processes to use to build the records. Default on this system is {default_processes}.",
        default=default_processes,
    )

    subparsers = parser.add_subparsers(
        dest="view_source",
        help=("Accepted values are 'nmap' and 'passive'. None or 'all' will do both"),
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
            fltnmap = db.nmap.parse_args(args, flt=fltnmap)
            _from.append(nmap_to_view(fltnmap, category=view_category))
        if db.passive is not None:
            fltpass = db.passive.parse_args(args, flt=fltpass)
            _from.append(passive_to_view(fltpass, category=view_category))
    elif args.view_source == "nmap":
        if db.nmap is None:
            parser.error('Cannot use "nmap" (no Nmap database exists)')
        fltnmap = db.nmap.parse_args(args, fltnmap)
        _from = [nmap_to_view(fltnmap, category=view_category)]
    elif args.view_source == "passive":
        if db.passive is None:
            parser.error('Cannot use "passive" (no Passive database exists)')
        fltpass = db.passive.parse_args(args, fltpass)
        _from = [passive_to_view(fltpass, category=view_category)]
    if args.test:
        args.processes = 1
    outdb = db.view if args.to_db is None else DBView.from_url(args.to_db)

    # Output results

    if args.processes > 1:
        nprocs = max(args.processes - 1, 1)
        with Pool(
            nprocs,
            initializer=worker_initializer,
            initargs=(args.to_db, args.no_merge),
        ) as pool:
            for _ in pool.imap(merge_and_output, to_view_parallel(_from)):
                pass
            for _ in pool.imap(worker_destroyer, [None] * nprocs):
                pass
    else:
        if args.test:

            def output(host: Record) -> None:
                return displayfunction_json([host], outdb)

        elif args.no_merge:
            output = outdb.store_host
        else:
            output = outdb.store_or_merge_host
        try:
            datadb = outdb.globaldb.data
        except AttributeError:
            datadb = None
        outdb.start_store_hosts()
        for record in to_view(_from, datadb):
            output(record)
        outdb.stop_store_hosts()
