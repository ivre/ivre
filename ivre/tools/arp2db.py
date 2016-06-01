#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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

import subprocess
import sys

from scapy.layers.l2 import Ether, ARP
from scapy.utils import PcapReader

from ivre import config
from ivre.db import db

def reader(fname):
    proc = subprocess.Popen(['tcpdump', '-n', '-r', fname, '-w', '-', 'arp'],
                            stdout=subprocess.PIPE)
    return PcapReader(proc.stdout)

def main():
    """Update the flow database from Airodump CSV files"""
    try:
        import argparse
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('files', nargs='*', metavar='FILE',
                            help='PCAP files')
    except ImportError:
        import optparse
        parser = optparse.OptionParser(description=__doc__)
        parser.parse_args_orig = parser.parse_args
        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('files', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option

    parser.add_argument("-v", "--verbose", help="verbose mode",
                        action="store_true")
    args = parser.parse_args()

    if args.verbose:
        config.DEBUG = True

    bulk = db.flow.start_bulk_insert()
    for fname in args.files:
        for pkt in reader(fname):
            for rec in [{"dst": pkt.hwsrc, "src": pkt.psrc},
                        {"dst": pkt.hwdst, "src": pkt.pdst}]:
                if rec["dst"] != "00:00:00:00:00:00" and rec["src"] != "0.0.0.0":
                    db.flow.bulk_add_flow(
                        bulk, rec, "ARP", {},
                        srcnode=("Host", {"addr": "{src}"}),
                        dstnode=("Intel:Mac", {"addr": "{dst}"}),
                    )
    bulk.close()
