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


"""Fetches IP addresses lists from public websites and creates
data files to add tags to scan results. For now, the following lists are used:

  - CDN providers, from <https://cdn.nuclei.sh/>

  - Tor Exit nodes, from
    <https://check.torproject.org/torbulkexitlist>

  - Scanners operated by the French ANSSI, from
    <https://cert.ssi.gouv.fr/scans/>

"""


import argparse
import json
import os
from typing import BinaryIO, Iterable, List, Optional, Tuple, cast


from ivre import config
from ivre.utils import download_if_newer, generic_ipaddr_processor, ip2int, net2range


def _fix_range(start: str, stop: str, label: str) -> Tuple[int, int, str]:
    return (
        ip2int(start) if ":" in start else ip2int(f"::ffff:{start}"),
        ip2int(stop) if ":" in stop else ip2int(f"::ffff:{stop}"),
        label,
    )


def make_range_tables(
    ranges: Iterable[Tuple[str, str, str]]
) -> List[Tuple[int, Optional[str]]]:
    ranges_sorted: List[Tuple[int, int, str]] = sorted(
        (_fix_range(start, stop, label) for start, stop, label in ranges), reverse=True
    )
    result: List[Tuple[int, Optional[str]]] = []
    prev = 0
    while ranges_sorted:
        start, stop, label = ranges_sorted.pop()
        if start > prev:
            result.append((start - 1, None))
        result.append((stop, label))
        prev = stop
    return result


def cdnjson2table(infd: BinaryIO, outfd: BinaryIO) -> None:
    table = make_range_tables(
        [
            net2range(net) + (cast(str, name),)
            for name, nets in json.load(infd).items()
            for net in nets
        ]
    )
    outfd.write(b"[\n    (\n")
    outfd.writelines(f"        {elt[0]!r},\n".encode() for elt in table)
    outfd.write(b"    ),\n    (\n")
    outfd.writelines(f"        {elt[1]!r},\n".encode() for elt in table)
    outfd.write(b"    ),\n]\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    assert config.DATA_PATH is not None
    download_if_newer(
        "https://cdn.nuclei.sh/",
        os.path.join(config.DATA_PATH, "cdn_nuclei.py"),
        processor=cdnjson2table,
    )
    download_if_newer(
        "https://check.torproject.org/torbulkexitlist",
        os.path.join(config.DATA_PATH, "tor_exit_nodes.txt"),
        processor=generic_ipaddr_processor,
    )
    download_if_newer(
        "https://cert.ssi.gouv.fr/scans/",
        os.path.join(config.DATA_PATH, "ssigouvfr_scanners.txt"),
        processor=generic_ipaddr_processor,
    )
