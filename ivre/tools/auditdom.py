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


"""Audit a DNS domain to produce an XML or JSON result similar to an
Nmap script result."""


import argparse
from datetime import datetime
import json
import pipes
import sys
from typing import Any, Iterable, Optional


from ivre import VERSION
from ivre.activecli import displayfunction_nmapxml
from ivre.analyzer.dns import AXFRChecker, DNSSRVChecker, TLSRPTChecker
from ivre.types import Record
from ivre.utils import LOGGER, serialize


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="Output as JSON rather than XML."
    )
    parser.add_argument("--ipv4", "-4", action="store_true", help="Use only IPv4.")
    parser.add_argument("--ipv6", "-6", action="store_true", help="Use only IPv6.")
    parser.add_argument("domains", metavar="DOMAIN", nargs="+", help="domains to check")
    args = parser.parse_args()
    if args.json:

        def displayfunction(cur: Iterable[Record], scan: Optional[Any] = None) -> None:
            if scan is not None:
                LOGGER.debug("Scan not displayed in JSON mode")
            for rec in cur:
                print(json.dumps(rec, default=serialize))

    else:
        displayfunction = displayfunction_nmapxml
    # we create a list so that we can know the start and stop time
    start = datetime.now()
    scan = {
        "scanner": "ivre auditdom",
        "start": start.strftime("%s"),
        "startstr": str(start),
        "version": VERSION,
        "xmloutputversion": "1.04",
        # argv[0] does not need quotes due to how it is handled by ivre
        "args": " ".join(sys.argv[:1] + [pipes.quote(arg) for arg in sys.argv[1:]]),
        "scaninfos": [
            {
                "type": "audit DNS domain",
                "protocol": "dig",
                "numservices": 1,
                "services": "53",
            }
        ],
    }
    results = [
        rec
        for domain in args.domains
        for test in [AXFRChecker, DNSSRVChecker, TLSRPTChecker]
        for rec in test(domain).test(v4=not args.ipv6, v6=not args.ipv4)
    ]
    end = datetime.now()
    scan["end"] = end.strftime("%s")
    scan["endstr"] = str(end)
    scan["elapsed"] = str((end - start).total_seconds())
    displayfunction(results, scan=scan)
