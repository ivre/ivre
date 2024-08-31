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


"""Query the passive & scans databases to perform DNS resolutions (passive DNS)."""


import json
from argparse import ArgumentParser
from typing import Any, Callable, Dict, List, Tuple, Union

from ivre.db import db
from ivre.utils import serialize, str2regexp


def merge_results(
    result: Dict[Tuple[str, str], Any], new_result: Dict[Tuple[str, str], Any]
) -> None:
    for key, value in new_result.items():
        cur_res = result.setdefault(
            key,
            {
                "types": set(),
                "sources": set(),
                "firstseen": value["firstseen"],
                "lastseen": value["lastseen"],
            },
        )
        cur_res["types"].update(value["types"])
        cur_res["sources"].update(value["sources"])
        cur_res["firstseen"] = min(cur_res["firstseen"], value["firstseen"])
        cur_res["lastseen"] = max(cur_res["lastseen"], value["lastseen"])


def serialize_sets(obj: Any) -> Union[str, list]:
    if isinstance(obj, set):
        return sorted(obj)
    return serialize(obj)


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--sub", action="store_true", help="Include subdomains.")
    parser.add_argument("--json", action="store_true", help="Output JSON data.")
    parser.add_argument(
        "--passive",
        action="store_true",
        help="Use passive (direct and reverse) results.",
    )
    parser.add_argument(
        "--passive-direct", action="store_true", help="Use passive (direct) results."
    )
    parser.add_argument(
        "--passive-reverse", action="store_true", help="Use passive (reverse) results."
    )
    parser.add_argument(
        "--nmap", "--scans", action="store_true", help="Use scans (nmap) results."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Use passive (direct and reverse) and scans (nmap) results. This is the default.",
    )
    parser.add_argument(
        "names_or_addresses",
        nargs="*",
        metavar="VALUES",
        help="Names or addresses to resolve",
    )
    args = parser.parse_args()
    resolvers: List[Callable[[str], Dict[Tuple[str, str], Any]]] = []
    if args.passive:
        args.passive_direct = True
        args.passive_reverse = True
    if args.all or not (args.passive_direct or args.passive_reverse or args.nmap):
        args.passive_direct = True
        args.passive_reverse = True
        args.nmap = True
    if db.passive is not None:
        if args.passive_direct:
            resolvers.append(
                lambda value: db.passive.getdns(value, subdomains=args.sub),
            )
        if args.passive_reverse:
            resolvers.append(
                lambda value: db.passive.getdns(
                    value, subdomains=args.sub, reverse=True
                )
            )
    if db.nmap is not None and args.nmap:
        resolvers.append(lambda value: db.nmap.getdns(value, subdomains=args.sub))

    for addr_or_name in args.names_or_addresses:
        addr_or_name = str2regexp(addr_or_name)
        result: Dict[Tuple[str, str], Any] = {}
        for resolver in resolvers:
            merge_results(result, resolver(addr_or_name))
        for (name, target), values in result.items():
            if args.json:
                print(
                    json.dumps(
                        dict(values, name=name, target=target), default=serialize_sets
                    )
                )
            else:
                print(f"{name} -> {target}\t{', '.join(sorted(values['types']))}")
                print(f"\tfrom: {', '.join(sorted(values['sources']))}")
                print(f"\tfirstseen: {values['firstseen']}")
                print(f"\tlastseen: {values['lastseen']}")
                print()
