#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2022 Pierre LALET <pierre@droids-corp.org>
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


import argparse
import os
import sys
from glob import glob
from typing import Dict

from ivre.config import RIR_PATH
from ivre.db import DBRir, db
from ivre.utils import CLI_ARGPARSER, range2nets


def printrec_full(rec: Dict[str, str]) -> None:
    for fld in ["_id", "source_file", "source_hash"]:
        try:
            del rec[fld]
        except KeyError:
            pass
    try:
        start, stop = rec.pop("start"), rec.pop("stop")
    except KeyError:
        asnum = rec.pop("aut-num")
        print(f"aut-num: AS{asnum}")
    else:
        nets = list(range2nets((start, stop)))
        if len(nets) == 1:
            print(f"inetnum: {nets[0]}")
        else:
            print(f"inetnum: {start} - {stop}")
    for k, v in sorted(rec.items()):
        if "\n" in v:
            print(f"{k}:")
            for line in v.split("\n"):
                print(f"    {line}")
        else:
            print(f"{k}: {v}")
    print()


def printrec_short(rec: Dict[str, str]) -> None:
    try:
        start, stop = rec["start"], rec["stop"]
    except KeyError:
        asnum = rec.pop("aut-num")
        obj = f"AS{asnum}"
        info = " - ".join(
            [
                rec["as-name"].replace("\n", " / "),
                rec.get("country", "").replace("\n", " / "),
            ]
        )
    else:
        nets = list(range2nets((start, stop)))
        if len(nets) == 1:
            obj = nets[0]
        else:
            obj = f"{start} - {stop}"
        info = " - ".join(
            [
                rec["netname"].replace("\n", " / "),
                rec.get("country", "").replace("\n", " / "),
            ]
        )
    print(f"{obj}: {info}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lookup & manage RIR databases.",
        parents=[CLI_ARGPARSER],
        conflict_handler="resolve",
    )
    if hasattr(db.rir, "searchtext"):  # FIXME, move to DBRir
        parser.add_argument(
            "--search", metavar="FREE TEXT", help="perform a full-text search"
        )
    parser.add_argument(
        "ips",
        nargs="*",
        help="Display results for specified IP addresses.",
    )
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--insert", action="store_true")
    # inherited from CLI_ARGPARSER but meaningless here
    parser.add_argument("--to-db", help=argparse.SUPPRESS)
    parser.add_argument("--http-urls", help=argparse.SUPPRESS)
    parser.add_argument("--delete", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.from_db:
        dbase = DBRir.from_url(args.from_db)
        dbase.globaldb = db
    else:
        dbase = db.rir
    printrec = printrec_short if args.short else printrec_full
    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                "This will remove any scan result in your database. Process ? [y/N] "
            )
            ans = input()
            if ans.lower() != "y":
                sys.exit(-1)
        dbase.init()
        sys.exit(0)
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write("This will lock your database. Process ? [y/N] ")
            ans = input()
            if ans.lower() != "y":
                sys.exit(-1)
        dbase.ensure_indexes()
        sys.exit(0)
    if args.sort is None:
        sortkeys = [("start", 1), ("stop", -1)]
    else:
        sortkeys = [
            (field[1:], -1) if field.startswith("~") else (field, 1)
            for field in args.sort
        ]
    if args.update_schema:
        dbase.migrate_schema(args.version)
        sys.exit(0)
    kargs = {}
    if args.limit is not None:
        kargs["limit"] = args.limit
    if args.skip is not None:
        kargs["skip"] = args.skip
    if sortkeys:
        kargs["sort"] = sortkeys
    if args.download or args.insert:
        if args.download:
            filenames = dbase.fetch()
        if args.insert:
            if args.download:
                dbase.import_files(filenames)
            else:
                if RIR_PATH is None:
                    base_path = "."
                else:
                    base_path = RIR_PATH
                dbase.import_files(glob(os.path.join(base_path, "*.db*")))
        elif args.download:
            print("\n".join(sorted(filenames)))
        sys.exit(0)
    if args.distinct is not None:
        flt = dbase.flt_empty
        if hasattr(dbase, "searchtext") and args.search is not None:
            flt = dbase.flt_and(flt, dbase.searchtext(args.search))
        if args.ips:
            flt = dbase.flt_and(
                flt, dbase.flt_or(dbase.searchhost(addr for addr in args.ips))
            )
        for val in dbase.distinct(args.distinct, flt=flt, **kargs):
            print(val)
        sys.exit(0)
    if hasattr(dbase, "searchtext") and args.search is not None:
        print(args.search)
        print()
        for res in dbase.get(dbase.searchtext(args.search), **kargs):
            printrec(res)
        print()
    # For IP addresses, we only output the "best" (smallest) match, so
    # no limit, skip or sort
    for addr in args.ips:
        print(addr)
        res = dbase.get_best(dbase.searchhost(addr))
        if res is None:
            print("UNKNOWN")
            if not args.short:
                print()
        else:
            printrec(res)
