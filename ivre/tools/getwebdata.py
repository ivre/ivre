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

  - Scanners operated by the Censys, from
    <https://support.censys.io/hc/en-us/articles/360043177092-from-faq>

"""


import argparse
import functools
import json
import os
import re
from typing import BinaryIO, Callable, Generator, List, Tuple, cast


from ivre import config
from ivre.utils import (
    IPADDR,
    download_if_newer,
    generic_ipaddr_extractor,
    generic_processor,
    make_range_tables,
    net2range,
)


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


def censys_net_extractor(fdesc: BinaryIO) -> Generator[str, None, None]:
    expr = re.compile(f"<code>{IPADDR.pattern[1:-1]}(/[0-9]+)?</code>")
    for line in fdesc:
        for m in expr.finditer(line.decode()):
            addr, mask = m.groups()
            if mask is None:
                if ":" in addr:
                    yield f"{addr}/128"
                else:
                    yield f"{addr}/32"
            else:
                yield f"{addr}{mask}"


assert config.DATA_PATH is not None
URLS: List[Tuple[str, str, Callable[[BinaryIO, BinaryIO], None]]] = [
    (
        "https://cdn.nuclei.sh/",
        os.path.join(config.DATA_PATH, "cdn_nuclei.py"),
        cdnjson2table,
    ),
    (
        "https://check.torproject.org/torbulkexitlist",
        os.path.join(config.DATA_PATH, "tor_exit_nodes.txt"),
        functools.partial(generic_processor, generic_ipaddr_extractor),
    ),
    (
        "https://cert.ssi.gouv.fr/scans/",
        os.path.join(config.DATA_PATH, "ssigouvfr_scanners.txt"),
        functools.partial(generic_processor, generic_ipaddr_extractor),
    ),
    (
        "https://support.censys.io/hc/en-us/articles/360043177092-from-faq",
        os.path.join(config.DATA_PATH, "censys_scanners.txt"),
        functools.partial(generic_processor, censys_net_extractor),
    ),
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    for url, fname, processor in URLS:
        try:
            download_if_newer(url, fname, processor=processor)
        except Exception:
            pass
