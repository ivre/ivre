#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2020 Pierre LALET <pierre@droids-corp.org>
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

"""Update the flow database from log files"""


from argparse import ArgumentParser


from ivre import config
from ivre import utils
from ivre.db import db

# from ivre.parser.airodump import Airodump
from ivre.parser.argus import Argus
from ivre.parser.netflow import NetFlow
from ivre.parser.iptables import Iptables

PARSERS_CHOICE = {
    # 'airodump': Airodump,
    "argus": Argus,
    "netflow": NetFlow,
    "iptables": Iptables,
}


PARSERS_MAGIC = {
    # NetFlow
    b"\x0c\xa5\x01\x00": NetFlow,
    # Argus
    b"\x83\x10\x00\x20": Argus,
}


def main() -> None:
    """Update the flow database from log files"""
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        "files", nargs="*", metavar="FILE", help="Files to import in the flow database"
    )
    parser.add_argument("-v", "--verbose", help="verbose mode", action="store_true")
    parser.add_argument("-t", "--type", help="file type", choices=list(PARSERS_CHOICE))
    parser.add_argument(
        "-f", "--pcap-filter", help="pcap filter to apply (when supported)"
    )
    parser.add_argument(
        "-C", "--no-cleanup", help="avoid port cleanup heuristics", action="store_true"
    )
    args = parser.parse_args()

    if args.verbose:
        config.DEBUG = True

    for fname in args.files:
        try:
            fileparser = PARSERS_CHOICE[args.type]
        except KeyError:
            with utils.open_file(fname) as fdesc_tmp:
                try:
                    fileparser = PARSERS_MAGIC[fdesc_tmp.read(4)]
                except KeyError:
                    utils.LOGGER.warning(
                        "Cannot find the appropriate parser for file %r",
                        fname,
                    )
                    continue
        bulk = db.flow.start_bulk_insert()
        with fileparser(fname, args.pcap_filter) as fdesc:
            for rec in fdesc:
                if not rec:
                    continue
                db.flow.flow2flow(bulk, rec)
        db.flow.bulk_commit(bulk)

    if not args.no_cleanup:
        db.flow.cleanup_flows()
