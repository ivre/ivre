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


"""Parse NMAP scan results and add them in DB."""


import os
import sys
from argparse import ArgumentParser

import ivre.db
import ivre.utils
import ivre.xmlnmap
from ivre.tags.active import set_auto_tags, set_openports_attribute
from ivre.types import Record
from ivre.view import nmap_record_to_view


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("scan", nargs="*", metavar="SCAN", help="Scan results")
    parser.add_argument("-c", "--categories", default="", help="Scan categories.")
    parser.add_argument("-s", "--source", default=None, help="Scan source.")
    parser.add_argument(
        "-t", "--test", action="store_true", help="Test mode (JSON output)."
    )
    parser.add_argument(
        "--tags",
        metavar="TAG:LEVEL:INFO[,TAG:LEVEL:INFO]",
        help="Add tags to the results; e.g. "
        '--tags=CDN:info:"My CDN",Honeypot:warning:"My Masscanned Honeypot"',
    )
    parser.add_argument(
        "--test-normal", action="store_true", help='Test mode ("normal" Nmap output).'
    )
    parser.add_argument(
        "--ports",
        "--port",
        action="store_true",
        help='Store only hosts with a "ports" element.',
    )
    parser.add_argument(
        "--open-ports", action="store_true", help="Store only hosts with open ports."
    )
    parser.add_argument(
        "--masscan-probes",
        nargs="+",
        metavar="PROBE",
        help="Additional Nmap probes to use when trying to "
        "match Masscan results against Nmap service "
        "fingerprints.",
    )
    parser.add_argument(
        "--zgrab-port",
        metavar="PORT",
        help="Port used for the zgrab scan. This might be "
        "needed since the port number does not appear in the"
        "result.",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Import all files from given directories.",
    )
    parser.add_argument(
        "--update-view", action="store_true", help="Merge hosts in current view"
    )
    parser.add_argument(
        "--no-update-view",
        action="store_true",
        help="Do not merge hosts in current view (default)",
    )
    args = parser.parse_args()
    database = ivre.db.db.nmap
    categories = sorted(set(args.categories.split(","))) if args.categories else []
    tags = [
        (
            {
                "value": value,
                "type": type_,
                "info": [info],
            }
            if info
            else {
                "value": value,
                "type": type_,
            }
        )
        for value, type_, info in (
            tag.split(":", 3) for tag in (args.tags.split(",") if args.tags else [])
        )
    ]
    if args.test:
        args.update_view = False
        args.no_update_view = True
        database = ivre.db.DBNmap()
    if args.test_normal:
        args.update_view = False
        args.no_update_view = True
        database = ivre.db.DBNmap(output_mode="normal")
    # Ugly hack: we use a one-element list so that
    # recursive_filelisting can modify its value
    error = [False]
    if args.recursive:
        scans = ivre.utils.recursive_filelisting(args.scan, error=error)
    else:
        scans = args.scan
    if not args.update_view or args.no_update_view:
        callback = None
    else:

        def callback(x: Record) -> None:
            result = nmap_record_to_view(x)
            set_auto_tags(result, update_openports=False)
            set_openports_attribute(result)
            result["infos"] = {}
            for func in [
                ivre.db.db.data.country_byip,
                ivre.db.db.data.as_byip,
                ivre.db.db.data.location_byip,
            ]:
                result["infos"].update(func(result["addr"]) or {})
            ivre.db.db.view.store_or_merge_host(result)

        ivre.db.db.view.start_store_hosts()

    count = 0
    for scan in scans:
        if not os.path.exists(scan):
            ivre.utils.LOGGER.warning("file %r does not exist", scan)
            error[0] = True
            continue
        try:
            if database.store_scan(
                scan,
                categories=categories,
                source=args.source,
                tags=tags,
                needports=args.ports,
                needopenports=args.open_ports,
                masscan_probes=args.masscan_probes,
                callback=callback,
                zgrab_port=args.zgrab_port,
            ):
                count += 1
        except Exception:
            ivre.utils.LOGGER.warning("Exception (file %r)", scan, exc_info=True)
            error[0] = True
    if callback is not None:
        ivre.db.db.view.stop_store_hosts()
    ivre.utils.LOGGER.info("%d results imported.", count)
    sys.exit(error[0])
