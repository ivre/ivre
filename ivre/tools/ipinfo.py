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


"Access and query the passive database."


import functools
import json
import os
import time
import argparse
import sys
from typing import Callable, Optional, cast


from ivre.db import db
from ivre.types import Filter, Record, Sort, SortKey
from ivre import utils


baseflt: Filter
Displayer = Callable[[Filter, Sort, Optional[int], Optional[int]], None]


def disp_rec(rec: Record) -> None:
    print("\t", end=" ")
    if "port" in rec and rec["port"]:
        print(rec["port"], end=" ")
    if "recontype" in rec:
        try:
            print(rec["recontype"].value, end=" ")
        except AttributeError:
            print(rec["recontype"], end=" ")
    if "source" in rec:
        print(rec["source"], end=" ")
    if "value" in rec:
        value = utils.printable(rec["value"])
        if isinstance(value, bytes):
            value = value.decode()
        print(value, end=" ")
    if "version" in rec:
        print(rec["version"], end=" ")
    if "signature" in rec:
        print("[%s]" % rec["signature"], end=" ")
    if "distance" in rec:
        print(
            "at %s hop%s" % (rec["distance"], "s" if rec["distance"] > 1 else ""),
            end=" ",
        )
    if "count" in rec:
        print("(%d time%s)" % (rec["count"], "s" if rec["count"] > 1 else ""), end=" ")
    if "firstseen" in rec and "lastseen" in rec:
        print(
            rec["firstseen"].replace(microsecond=0),
            "-",
            rec["lastseen"].replace(microsecond=0),
            end=" ",
        )
    if "sensor" in rec:
        print(rec["sensor"], end=" ")
    print()
    if "infos" in rec:
        for i in rec["infos"]:
            print("\t\t", i + ":", end=" ")
            if i == "domainvalue":
                print(rec["infos"][i][0])
            else:
                print(rec["infos"][i])


def disp_recs_std(
    flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    old_addr = None
    sort = sort or [("addr", 1), ("port", 1), ("recontype", 1), ("source", 1)]
    for rec in db.passive.get(flt, sort=sort, limit=limit, skip=skip):
        if "addr" not in rec or not rec["addr"]:
            continue
        if old_addr != rec["addr"]:
            if old_addr is not None:
                print()
            old_addr = rec["addr"]
            print(utils.force_int2ip(old_addr))
            ipinfo = db.data.infos_byip(old_addr)
            if ipinfo:
                if "address_type" in ipinfo:
                    print("\t", end=" ")
                    print(ipinfo["address_type"], end=" ")
                    print()
                if "country_code" in ipinfo:
                    print("\t", end=" ")
                    print(ipinfo["country_code"], end=" ")
                    if "country_name" in ipinfo:
                        cname = ipinfo["country_name"]
                    else:
                        try:
                            cname = db.data.country_name_by_code(ipinfo["country_code"])
                        except AttributeError:
                            cname = None
                    if cname:
                        print("[%s]" % cname, end=" ")
                    print()
                if "as_num" in ipinfo:
                    print("\t", end=" ")
                    print("AS%d" % ipinfo["as_num"], end=" ")
                    if "as_name" in ipinfo:
                        print("[%s]" % ipinfo["as_name"], end=" ")
                    print()
                elif "as_name" in ipinfo:
                    print("\t", end=" ")
                    print("AS????? [%s]" % ipinfo["as_name"], end=" ")
                    print()
        disp_rec(rec)


def disp_recs_json(
    flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    indent: Optional[int]
    if os.isatty(sys.stdout.fileno()):
        indent = 4
    else:
        indent = None
    for rec in db.passive.get(flt, sort=sort, limit=limit, skip=skip):
        try:
            del rec["_id"]
        except KeyError:
            pass
        if rec.get("recontype") == "SSL_SERVER" and rec.get("source") in {
            "cert",
            "cacert",
        }:
            rec["value"] = utils.encode_b64(rec["value"]).decode()
        print(json.dumps(rec, indent=indent, default=db.passive.serialize))


def disp_recs_short(
    flt: Filter, _sort: Sort, _limit: Optional[int], _skip: Optional[int]
) -> None:
    for addr in db.passive.distinct("addr", flt=flt):
        if addr is not None:
            print(addr)


def disp_recs_distinct(
    field: str, flt: Filter, _sort: Sort, _limit: Optional[int], _skip: Optional[int]
) -> None:
    for value in db.passive.distinct(field, flt=flt):
        print(value)


def disp_recs_top(top: str) -> Displayer:
    return lambda flt, sort, limit, _: sys.stdout.writelines(
        db.passive.display_top(top, flt, limit)
    )


def disp_recs_count(
    flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    print(db.passive.count(flt))


def _disp_recs_tail(flt: Filter, field: str, nbr: Optional[int]) -> None:
    recs = list(db.passive.get(flt, sort=[(field, -1)], limit=nbr))
    recs.reverse()
    for r in recs:
        if "addr" in r:
            print(utils.force_int2ip(r["addr"]), end=" ")
        else:
            print(r["targetval"], end=" ")
        disp_rec(r)


def disp_recs_tail(nbr: int) -> Displayer:
    return lambda flt, *_: _disp_recs_tail(flt, "firstseen", nbr)


def disp_recs_tailnew(nbr: int) -> Displayer:
    return lambda flt, *_: _disp_recs_tail(flt, "lastseen", nbr)


def _disp_recs_tailf(flt: Filter, field: str) -> None:
    global baseflt
    # 1. init
    firstrecs = list(db.passive.get(flt, sort=[(field, -1)], limit=10))
    firstrecs.reverse()
    # in case we don't have (yet) records matching our criteria
    r = {"firstseen": 0, "lastseen": 0}
    for r in firstrecs:
        if "addr" in r:
            print(utils.force_int2ip(r["addr"]), end=" ")
        else:
            print(r["targetval"], end=" ")
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
                    db.passive.searchnewer(prevtime, new=field == "firstseen"),
                ),
                sort=[(field, 1)],
            ):
                if "addr" in r:
                    print(utils.force_int2ip(r["addr"]), end=" ")
                else:
                    print(r["targetval"], end=" ")
                disp_rec(r)
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass


def disp_recs_tailfnew() -> Displayer:
    return lambda flt, *_: _disp_recs_tailf(flt, "firstseen")


def disp_recs_tailf() -> Displayer:
    return lambda flt, *_: _disp_recs_tailf(flt, "lastseen")


def disp_recs_explain(
    flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    print(
        db.passive.explain(
            db.passive._get(flt, sort=sort, limit=limit, skip=skip), indent=4
        )
    )


def disp_recs_delete(
    flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    db.passive.remove(flt)


def main() -> None:
    global baseflt
    parser = argparse.ArgumentParser(
        description=__doc__,
        parents=[db.passive.argparser, utils.CLI_ARGPARSER],
    )
    baseflt = db.passive.flt_empty
    disp_recs: Displayer = disp_recs_std
    # display modes
    parser.add_argument(
        "--tail", metavar="COUNT", type=int, help="Output latest COUNT results."
    )
    parser.add_argument(
        "--tailnew", metavar="COUNT", type=int, help="Output latest COUNT new results."
    )
    parser.add_argument(
        "--tailf", action="store_true", help="Output continuously latest results."
    )
    parser.add_argument(
        "--tailfnew", action="store_true", help="Output continuously latest results."
    )
    parser.add_argument(
        "--top",
        metavar="FIELD / ~FIELD",
        help="Output most common (least common: ~) values for "
        "FIELD, by default 10, use --limit to change that, "
        "--limit 0 means unlimited.",
    )
    parser.add_argument(
        "--dnsbl-update",
        action="store_true",
        help="Update the current database with DNS Blacklist",
    )
    args = parser.parse_args()
    baseflt = db.passive.parse_args(args, baseflt)
    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                "This will remove any passive information in your "
                "database. Process ? [y/N] "
            )
            ans = input()
            if ans.lower() != "y":
                sys.exit(0)
        db.passive.init()
        sys.exit(0)
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write("This will lock your database. Process ? [y/N] ")
            ans = input()
            if ans.lower() != "y":
                sys.exit(0)
        db.passive.ensure_indexes()
        sys.exit(0)
    if args.update_schema:
        db.passive.migrate_schema(None)
        sys.exit(0)
    if args.dnsbl_update:
        db.passive.update_dns_blacklist()
        sys.exit(0)
    if args.short:
        disp_recs = disp_recs_short
    elif args.distinct is not None:
        disp_recs = functools.partial(disp_recs_distinct, args.distinct)
    elif args.json:
        disp_recs = disp_recs_json
    elif args.top is not None:
        disp_recs = disp_recs_top(args.top)
        if args.limit is None:
            args.limit = 10
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
        disp_recs = disp_recs_delete
    elif args.explain:
        disp_recs = disp_recs_explain
    sort: Sort
    if args.sort is None:
        sort = []
    else:
        sort = [
            cast(SortKey, (field[1:], -1) if field.startswith("~") else (field, 1))
            for field in args.sort
        ]
    if not args.ips:
        if not baseflt and not args.limit and disp_recs is disp_recs_std:
            # default to tail -f mode
            disp_recs = disp_recs_tailfnew()
        disp_recs(baseflt, sort, args.limit or db.passive.no_limit, args.skip or 0)
        sys.exit(0)
    disp_recs(baseflt, sort, args.limit or db.passive.no_limit, args.skip or 0)
