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


"Access and query the passive database."


import functools
import json
import os
import time
import argparse
import sys
from typing import Callable, Optional, cast


from ivre.db import DBPassive, db
from ivre.types import Filter, Record, Sort, SortKey
from ivre import utils


Displayer = Callable[[DBPassive, Filter, Sort, Optional[int], Optional[int]], None]


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
    dbase: DBPassive, flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    old_addr = None
    sort = sort or [("addr", 1), ("port", 1), ("recontype", 1), ("source", 1)]
    for rec in dbase.get(flt, sort=sort, limit=limit, skip=skip):
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
    dbase: DBPassive, flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    indent: Optional[int]
    if os.isatty(sys.stdout.fileno()):
        indent = 4
    else:
        indent = None
    for rec in dbase.get(flt, sort=sort, limit=limit, skip=skip):
        try:
            del rec["_id"]
        except KeyError:
            pass
        print(json.dumps(rec, indent=indent, default=dbase.serialize))


def disp_recs_short(
    dbase: DBPassive,
    flt: Filter,
    _sort: Sort,
    _limit: Optional[int],
    _skip: Optional[int],
) -> None:
    for addr in dbase.distinct("addr", flt=flt):
        if addr is not None:
            print(addr)


def disp_recs_distinct(
    field: str,
    dbase: DBPassive,
    flt: Filter,
    _sort: Sort,
    _limit: Optional[int],
    _skip: Optional[int],
) -> None:
    for value in dbase.distinct(field, flt=flt):
        print(value)


def disp_recs_top(top: str) -> Displayer:
    return lambda dbase, flt, sort, limit, _: sys.stdout.writelines(
        dbase.display_top(top, flt, limit)
    )


def disp_recs_count(
    dbase: DBPassive, flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    print(dbase.count(flt))


def _disp_recs_tail(
    dbase: DBPassive, flt: Filter, field: str, nbr: Optional[int]
) -> None:
    recs = list(dbase.get(flt, sort=[(field, -1)], limit=nbr))
    recs.reverse()
    for r in recs:
        if "addr" in r:
            print(utils.force_int2ip(r["addr"]), end=" ")
        else:
            print(r["targetval"], end=" ")
        disp_rec(r)


def disp_recs_tail(nbr: int) -> Displayer:
    return lambda dbase, flt, *_: _disp_recs_tail(dbase, flt, "firstseen", nbr)


def disp_recs_tailnew(nbr: int) -> Displayer:
    return lambda dbase, flt, *_: _disp_recs_tail(dbase, flt, "lastseen", nbr)


def _disp_recs_tailf(dbase: DBPassive, flt: Filter, field: str) -> None:
    # 1. init
    firstrecs = list(dbase.get(flt, sort=[(field, -1)], limit=10))
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
            for r in dbase.get(
                dbase.flt_and(
                    flt,
                    dbase.searchnewer(prevtime, new=field == "firstseen"),
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
    return lambda dbase, flt, *_: _disp_recs_tailf(dbase, flt, "firstseen")


def disp_recs_tailf() -> Displayer:
    return lambda dbase, flt, *_: _disp_recs_tailf(dbase, flt, "lastseen")


def disp_recs_explain(
    dbase: DBPassive, flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    print(dbase.explain(dbase._get(flt, sort=sort, limit=limit, skip=skip), indent=4))


def disp_recs_delete(
    dbase: DBPassive, flt: Filter, sort: Sort, limit: Optional[int], skip: Optional[int]
) -> None:
    dbase.remove(flt)


def disp_recs_todb(to_db: DBPassive) -> Displayer:
    def disp_recs(
        dbase: DBPassive,
        flt: Filter,
        sort: Sort,
        limit: Optional[int],
        skip: Optional[int],
    ) -> None:
        for rec in dbase.get(flt, sort=sort, limit=limit, skip=skip):
            try:
                del rec["_id"]
            except KeyError:
                pass
            lastseen = rec.pop("lastseen", None)
            timestamp = rec.pop("firstseen")
            try:
                to_db.insert_or_update(timestamp, rec, lastseen=lastseen)
            except Exception:
                utils.LOGGER.warning("Cannot insert record %r", rec, exc_info=True)

    return disp_recs


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        # We use db.passive rather than DBPassive here because we need an instance...
        parents=[db.passive.argparser, utils.CLI_ARGPARSER],
    )
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
    if args.from_db:
        dbase = DBPassive.from_url(args.from_db)
        dbase.globaldb = db
    else:
        dbase = db.passive
    flt = dbase.parse_args(args, dbase.flt_empty)
    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                "This will remove any passive information in your "
                "database. Process ? [y/N] "
            )
            ans = input()
            if ans.lower() != "y":
                sys.exit(0)
        dbase.init()
        sys.exit(0)
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write("This will lock your database. Process ? [y/N] ")
            ans = input()
            if ans.lower() != "y":
                sys.exit(0)
        dbase.ensure_indexes()
        sys.exit(0)
    if args.update_schema:
        dbase.migrate_schema(None)
        sys.exit(0)
    if args.dnsbl_update:
        dbase.update_dns_blacklist()
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
    elif args.to_db:
        disp_recs = disp_recs_todb(DBPassive.from_url(args.to_db))
    sort: Sort
    if args.sort is None:
        sort = []
    else:
        sort = [
            cast(SortKey, (field[1:], -1) if field.startswith("~") else (field, 1))
            for field in args.sort
        ]
    if not args.ips:
        if not flt and not args.limit and disp_recs is disp_recs_std:
            # default to tail -f mode
            disp_recs = disp_recs_tailfnew()
        disp_recs(dbase, flt, sort, args.limit or dbase.no_limit, args.skip or 0)
        sys.exit(0)
    disp_recs(dbase, flt, sort, args.limit or dbase.no_limit, args.skip or 0)
