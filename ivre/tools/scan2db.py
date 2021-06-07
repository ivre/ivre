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


"""Parse NMAP scan results and add them in DB."""


from argparse import ArgumentParser
import os
import sys
from typing import Generator, Iterable, List


import ivre.db
from ivre.types import Record
import ivre.utils
from ivre.view import nmap_record_to_view
import ivre.xmlnmap


def recursive_filelisting(
    base_directories: Iterable[str], error: List[bool]
) -> Generator[str, None, None]:
    """Iterator on filenames in base_directories. Ugly hack: error is a
    one-element list that will be set to True if one of the directories in
    base_directories does not exist.

    """

    for base_directory in base_directories:
        if not os.path.exists(base_directory):
            ivre.utils.LOGGER.warning("directory %r does not exist", base_directory)
            error[0] = True
            continue
        if not os.path.isdir(base_directory):
            yield base_directory
            continue
        for root, _, files in os.walk(base_directory):
            for leaffile in files:
                yield os.path.join(root, leaffile)


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("scan", nargs="*", metavar="SCAN", help="Scan results")
    parser.add_argument("-c", "--categories", default="", help="Scan categories.")
    parser.add_argument("-s", "--source", default=None, help="Scan source.")
    parser.add_argument(
        "-t", "--test", action="store_true", help="Test mode (JSON output)."
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
        "--force-info",
        action="store_true",
        help="Force information (AS, country, city, etc.)"
        " renewal (only useful with JSON format)",
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
    categories = args.categories.split(",") if args.categories else []
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
        scans = recursive_filelisting(args.scan, error)
    else:
        scans = args.scan
    if not args.update_view or args.no_update_view:
        callback = None
    else:

        def callback(x: Record) -> None:
            ivre.db.db.view.store_or_merge_host(nmap_record_to_view(x))

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
                needports=args.ports,
                needopenports=args.open_ports,
                force_info=args.force_info,
                masscan_probes=args.masscan_probes,
                callback=callback,
                zgrab_port=args.zgrab_port,
            ):
                count += 1
        except Exception:
            ivre.utils.LOGGER.warning("Exception (file %r)", scan, exc_info=True)
            error[0] = True
    ivre.utils.LOGGER.info("%d results imported.", count)
    sys.exit(error[0])
