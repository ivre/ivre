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


"""Fetches https://check.torproject.org/torbulkexitlist and create
pseudo-scan records.

"""


import argparse
from datetime import datetime
import json
from urllib.request import urlopen
import pipes
import sys
from typing import Any, Iterable, Optional


from ivre import VERSION
from ivre.active.data import TAG_TOR
from ivre.types import Record
from ivre.utils import LOGGER, serialize
from ivre.xmlnmap import SCHEMA_VERSION


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
        "scanner": "ivre audittor",
        "start": start.strftime("%s"),
        "startstr": str(start),
        "version": VERSION,
        "xmloutputversion": "1.04",
        # argv[0] does not need quotes due to how it is handled by ivre
        "args": " ".join(sys.argv[:1] + [pipes.quote(arg) for arg in sys.argv[1:]]),
        "scaninfos": [{"type": "list TOR exit nodes"}],
    }
    with urlopen("https://check.torproject.org/torbulkexitlist") as fdesc:
        results = [
            {
                "addr": line.decode().strip(),
                "schema_version": SCHEMA_VERSION,
                "starttime": datetime.now(),
                "endtime": datetime.now(),
                "tags": [
                    dict(
                        TAG_TOR,
                        info=[
                            "Exit node listed at <https://check.torproject.org/torbulkexitlist>"
                        ],
                    )
                ],
            }
            for line in fdesc
        ]
    end = datetime.now()
    scan["end"] = end.strftime("%s")
    scan["endstr"] = str(end)
    scan["elapsed"] = str((end - start).total_seconds())
    displayfunction(results, scan=scan)
