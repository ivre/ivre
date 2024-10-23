#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
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


"""Update the passive database from Airodump CSV files"""


from argparse import ArgumentParser
from collections.abc import Generator, Iterable
from functools import partial
from sys import stdin
from typing import Any, BinaryIO

from ivre.db import DBPassive, db
from ivre.parser.airodump import Airodump
from ivre.passive import _prepare_rec, get_ignore_rules, getinfos
from ivre.types import Record
from ivre.utils import recursive_filelisting


def _handle_rec(
    ignore_rules: dict[str, dict[str, list[tuple[int, int]]]],
    line: dict[str, Any],
) -> Generator[Record, None, None]:
    yield from _prepare_rec(
        line, ignore_rules.get("IGNORENETS", {}), ignore_rules.get("NEVERIGNORE", {})
    )


def rec_iter(
    filenames: Iterable[BinaryIO | str],
    sensor: str | None,
    ignore_rules: dict[str, dict[str, list[tuple[int, int]]]],
) -> Generator[Record, None, None]:
    for fname in filenames:
        with Airodump(fname) as fdesc:
            for line in fdesc:
                baserec = {
                    "recontype": "MAC_ADDRESS",
                    "firstseen": line["First time seen"],
                    "lastseen": line["Last time seen"],
                    "count": 1,
                }
                if sensor is not None:
                    baserec["sensor"] = sensor
                if "Station MAC" in line:
                    if line["BSSID"] == "(not associated)":
                        continue
                    yield from _handle_rec(
                        ignore_rules,
                        dict(
                            baserec,
                            source="WLAN_ASSOCIATED",
                            value=line["Station MAC"].lower(),
                            targetval=line["BSSID"].lower(),
                            # count=line["# packets"],
                        ),
                    )
                    if not line.get("Probed ESSIDs"):
                        continue
                    for probed in line["Probed ESSIDs"].split(","):
                        yield from _handle_rec(
                            ignore_rules,
                            dict(
                                baserec,
                                source="WLAN_PROBED_ESSID",
                                value=line["Station MAC"].lower(),
                                targetval=probed,
                                # count=line["# packets"],
                            ),
                        )
                    continue
                baserec["value"] = line["BSSID"].lower()
                for fld, none_val in [
                    ("ESSID", None),
                    ("channel", -1),
                    ("LAN IP", "0.0.0.0"),
                ]:
                    if not line.get(fld) or line[fld] == none_val:
                        continue
                    yield from _handle_rec(
                        ignore_rules,
                        dict(
                            baserec,
                            source="WLAN_AP_%s" % fld.upper().replace(" ", "_"),
                            # count=line["# beacons"],
                            **{
                                "addr" if fld == "LAN IP" else "targetval": str(
                                    line[fld]
                                )
                            },
                        ),
                    )
                if not line.get("Privacy"):
                    continue
                privacy = line["Privacy"].replace(" ", "_")
                for fld in ["Cipher", "Authentication"]:
                    if line.get(fld):
                        privacy = "%s-%s" % (privacy, line[fld])
                yield from _handle_rec(
                    ignore_rules,
                    dict(
                        baserec,
                        source="WLAN_AP_PRIVACY",
                        # count=line["# beacons"],
                        targetval=privacy,
                    ),
                )


def main() -> None:
    """Update the flow database from Airodump CSV files"""
    parser = ArgumentParser(description=__doc__, parents=[db.passive.argparser_insert])
    parser.add_argument("files", nargs="*", metavar="FILE", help="Airodump CSV files")
    args = parser.parse_args()
    ignore_rules = get_ignore_rules(args.ignore_spec)
    if args.test:
        function = DBPassive().insert_or_update_local_bulk
    elif (not (args.no_bulk or args.local_bulk)) or args.bulk:
        function = db.passive.insert_or_update_bulk
    elif args.local_bulk:
        function = db.passive.insert_or_update_local_bulk
    else:
        function = partial(
            DBPassive.insert_or_update_bulk,
            db.passive,
        )
    files: Iterable[BinaryIO | str]
    if not args.files:
        files = [stdin.buffer]
    elif args.recursive:
        files = recursive_filelisting(args.files)
    else:
        files = args.files
    function(
        rec_iter(files, args.sensor, ignore_rules),
        getinfos=getinfos,
        separated_timestamps=False,
    )
