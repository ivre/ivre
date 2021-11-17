#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2020 Pierre LALET <pierre@droids-corp.org>
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


"Query the passive database to perform ARP resolutions."


import argparse
import re
from typing import List, Tuple


from ivre.db import db
from ivre import utils


MAC_ADDR = re.compile(
    "^([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})"
    "[:-]([0-9a-f]{1,2})[:-]([0-9a-f]{1,2})$",
    re.I,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "ips_or_macs",
        nargs="*",
        help=(
            "Display results for specified IP (or networks) or MAC addresses"
            " (or MAC address regexps)."
        ),
    )
    parser.add_argument("-s", "--sensor")
    parser.add_argument("-c", "--count", action="store_true")
    parser.add_argument(
        "-r", "--resolve", action="store_true", help="Resolve MAC manufacturer"
    )
    args = parser.parse_args()
    flts: Tuple[List[str], List[str]] = ([], [])  # MAC & IP filters
    for arg in args.ips_or_macs:
        if arg[:1] in "-!~":
            neg = True
            arg = arg[1:]
        else:
            neg = False
        match = MAC_ADDR.search(arg)
        if match:
            flts[0].append(
                db.passive.searchmac(mac=arg.lower(), neg=neg),
            )
        elif arg.startswith("/") and "/" in arg[1:]:
            flts[0].append(
                db.passive.searchmac(mac=utils.str2regexp(arg.lower()), neg=neg),
            )
        elif "/" in arg:
            flts[1].append(db.passive.searchnet(arg, neg=neg))
        else:
            flts[1].append(db.passive.searchhost(arg, neg=neg))
    if not flts[0]:
        flts[0].append(db.passive.searchmac())
    flt = db.passive.flt_or(*flts[0])
    if flts[1]:
        flt = db.passive.flt_and(flt, db.passive.flt_or(*flts[1]))
    if args.sensor is not None:
        flt = db.passive.flt_and(flt, db.passive.searchsensor(args.sensor))
    if args.count:
        print(db.passive.count(flt))
        return
    for rec in db.passive.get(
        flt, sort=[("value", 1), ("recontype", 1), ("source", 1), ("addr", 1)]
    ):
        rec["times"] = "s" if rec["count"] > 1 else ""
        if not rec.get("sensor"):
            rec["sensor"] = "-"
        if args.resolve:
            try:
                manuf_res = utils.mac2manuf(rec["value"])
                assert manuf_res is not None
                manuf = manuf_res[0]
            except (TypeError, ValueError, AssertionError):
                pass
            else:
                rec["value"] = "%s (%s)" % (rec["value"], manuf)
        if "addr" in rec:
            print(
                "%(value)s %(source)s %(addr)s on %(sensor)s (%(recontype)s %(count)s "
                "time%(times)s, %(firstseen)s - %(lastseen)s)" % rec
            )
            continue
        if rec["source"] == "WLAN_ASSOCIATED" and args.resolve:
            try:
                manuf_res = utils.mac2manuf(rec["targetval"])
                assert manuf_res is not None
                manuf = manuf_res[0]
            except (TypeError, ValueError, AssertionError):
                pass
            else:
                rec["targetval"] = "%s (%s)" % (rec["targetval"], manuf)
        print(
            "%(value)s %(source)s %(targetval)s on %(sensor)s (%(recontype)s %(count)s "
            "time%(times)s, %(firstseen)s - %(lastseen)s)" % rec
        )
