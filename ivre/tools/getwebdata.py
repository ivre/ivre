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
pseudo-scan records with tags. For now, the following lists are used:

  - Tor Exit nodes, from
    <https://check.torproject.org/torbulkexitlist>

  - Scanners operated by the French ANSSI, from
    <https://cert.ssi.gouv.fr/scans/>

"""


import argparse
from datetime import datetime
import json
from urllib.request import urlopen
import pipes
import re
import sys
from typing import Any, Generator, Iterable, Optional, cast


from ivre import VERSION
from ivre.active.data import TAG_SCANNER, TAG_TOR
from ivre.types import Record, Tag
from ivre.utils import IPADDR, LOGGER, serialize
from ivre.xmlnmap import SCHEMA_VERSION


class Extractor:
    expr = re.compile(f"(?:^|\\W){IPADDR.pattern[1:-1]}(?:$|\\W)")
    url: str
    tag: Tag

    def get_ips(self) -> Generator[str, None, None]:
        with urlopen(self.url) as fdesc:
            for line in fdesc:
                for m in self.expr.finditer(line.decode()):
                    yield from m.groups()


class TorExitExtractor(Extractor):
    url = "https://check.torproject.org/torbulkexitlist"
    tag = cast(
        Tag,
        dict(
            TAG_TOR,
            info=["Exit node listed at <https://check.torproject.org/torbulkexitlist>"],
        ),
    )


class AnssiScannerExtractor(Extractor):
    url = "https://cert.ssi.gouv.fr/scans/"
    tag = cast(
        Tag,
        dict(
            TAG_SCANNER,
            info=["French ANSSI scanner listed at <https://cert.ssi.gouv.fr/scans/>"],
        ),
    )


EXTRACTORS = [TorExitExtractor(), AnssiScannerExtractor()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

    # JSON output only for now, as tags are not supported

    def displayfunction(cur: Iterable[Record], scan: Optional[Any] = None) -> None:
        if scan is not None:
            LOGGER.debug("Scan not displayed in JSON mode")
        for rec in cur:
            print(json.dumps(rec, default=serialize))

    # we create a list so that we can know the start and stop time
    start = datetime.now()
    scan = {
        "scanner": "ivre fetchiplists",
        "start": start.strftime("%s"),
        "startstr": str(start),
        "version": VERSION,
        "xmloutputversion": "1.04",
        # argv[0] does not need quotes due to how it is handled by ivre
        "args": " ".join(sys.argv[:1] + [pipes.quote(arg) for arg in sys.argv[1:]]),
        "scaninfos": [{"type": "fetches IP lists from public websites"}],
    }
    results = [
        {
            "addr": addr,
            "schema_version": SCHEMA_VERSION,
            "starttime": datetime.now(),
            "endtime": datetime.now(),
            "tags": [extractor.tag],
        }
        for extractor in EXTRACTORS
        for addr in extractor.get_ips()
    ]
    end = datetime.now()
    scan["end"] = end.strftime("%s")
    scan["endstr"] = str(end)
    scan["elapsed"] = str((end - start).total_seconds())
    displayfunction(results, scan=scan)
