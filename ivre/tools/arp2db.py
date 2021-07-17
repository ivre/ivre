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

"""Update the flow database from ARP requests in PCAP files"""


from argparse import ArgumentParser
from datetime import datetime
import subprocess
from typing import cast, Iterable


from scapy.all import ARP, Packet, PcapReader  # type: ignore


from ivre import config
from ivre.db import db


def reader(fname: str) -> Iterable[Packet]:
    # pylint: disable=consider-using-with
    proc = subprocess.Popen(
        ["tcpdump", "-n", "-r", fname, "-w", "-", "arp"], stdout=subprocess.PIPE
    )
    return cast(Iterable[Packet], PcapReader(proc.stdout))


def main() -> None:
    """Update the flow database from ARP requests in PCAP files"""
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", metavar="FILE", help="PCAP files")
    parser.add_argument("-v", "--verbose", help="verbose mode", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        config.DEBUG = True

    bulk = db.flow.start_bulk_insert()
    for fname in args.files:
        for pkt in reader(fname):
            rec = {
                "dst": pkt[ARP].pdst,
                "src": pkt[ARP].psrc,
                "mac_src": pkt[ARP].hwsrc,
                "mac_dst": pkt[ARP].hwdst,
                "start_time": datetime.fromtimestamp(pkt.time),
                "end_time": datetime.fromtimestamp(pkt.time),
                "op": pkt.sprintf("%ARP.op%").upper().replace("-", "_"),
                "proto": "arp",
            }
            if rec["dst"] != "0.0.0.0" and rec["src"] != "0.0.0.0":
                db.flow.any2flow(bulk, "arp", rec)
    db.flow.bulk_commit(bulk)
