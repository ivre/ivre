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


"""Update the passive database from Airodump CSV files"""


from argparse import ArgumentParser
from functools import partial
from typing import Any, Dict, Generator, List, Optional, Tuple


from ivre.db import DBPassive, db
from ivre.parser.airodump import Airodump
from ivre.passive import _prepare_rec, getinfos
from ivre.tools.passiverecon2db import _get_ignore_rules
from ivre.types import Record


def _handle_rec(
    sensor: Optional[str],
    ignore_rules: Dict[str, Dict[str, List[Tuple[int, int]]]],
    line: Dict[str, Any],
) -> Generator[Record, None, None]:
    yield from _prepare_rec(
        line, ignore_rules.get("IGNORENETS", {}), ignore_rules.get("NEVERIGNORE", {})
    )


def rec_iter(
    filenames: List[str],
    sensor: Optional[str],
    ignore_rules: Dict[str, Dict[str, List[Tuple[int, int]]]],
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
                if "Station MAC" in line:
                    if line["BSSID"] == "(not associated)":
                        continue
                    yield from _handle_rec(
                        sensor,
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
                            sensor,
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
                        sensor,
                        ignore_rules,
                        dict(
                            baserec,
                            source="WLAN_AP_%s" % fld.upper().replace(" ", "_"),
                            # count=line["# beacons"],
                            **{
                                "addr"
                                if fld == "LAN IP"
                                else "targetval": str(line[fld])
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
                    sensor,
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
    ignore_rules = _get_ignore_rules(args.ignore_spec)
    if (not (args.no_bulk or args.local_bulk)) or args.bulk:
        function = db.passive.insert_or_update_bulk
    elif args.local_bulk:
        function = db.passive.insert_or_update_local_bulk
    else:
        function = partial(
            DBPassive.insert_or_update_bulk,
            db.passive,
        )
    function(
        rec_iter(args.files, args.sensor, ignore_rules),
        getinfos=getinfos,
        separated_timestamps=False,
    )
