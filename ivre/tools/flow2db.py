#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
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

import sys
import time

from ivre import config
from ivre import utils
from ivre.db import db
# from ivre.parser.airodump import Airodump
from ivre.parser.argus import Argus
# from ivre.parser.bro import BroFile
from ivre.parser.netflow import NetFlow

# Associates a list of fields that must be present to the
# link attributes and the accumulators
FIELD_REQUEST_EXT = [
    (('sport', 'dport'), ('proto', 'dport'), {'sports': ('{sport}', 5)}),
    (('type', 'code'), ('proto', 'type'), {'codes': ('{code}', None)}),
    (('type'), ('proto', 'type'), {}),
]
COUNTERS = ["cspkts", "scpkts", "csbytes", "scbytes"]

PARSERS_CHOICE = {
    #'airodump': Airodump,
    'argus': Argus,
    #'bro': BroFile,
    'netflow': NetFlow,
}

PARSERS_MAGIC = {
    # Pcap: ARP
    #'\xa1\xb2\xd3\xc4': None,
    #'\xd4\xc3\xb2\xa1': None,
    # NetFlow
    '\x0c\xa5\x01\x00': NetFlow,
    # Argus
    '\x83\x10\x00\x20': Argus,
    # Bro
    #'#sep': BroFile,
    # Airodump CSV
    #'\x0d\x0aBS': Airodump,
}

def main():
    """Update the flow database from log files"""
    try:
        import argparse
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('files', nargs='*', metavar='FILE',
                            help='Files to import in the flow database')
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
    parser.add_argument("-t", "--type", help="file type",
                        choices=PARSERS_CHOICE.keys())
    parser.add_argument("-f", "--pcap-filter",
                        help="pcap filter to apply (when supported)")
    parser.add_argument("-C", "--no-cleanup",
                        help="avoid port cleanup heuristics",
                        action="store_true")
    args = parser.parse_args()

    if args.verbose:
        config.DEBUG = True

    query_cache = {}
    for fname in args.files:
        try:
            fileparser = PARSERS_CHOICE[args.type]
        except KeyError:
            with utils.open_file(fname) as fdesc:
                try:
                    fileparser = PARSERS_MAGIC[fdesc.read(4)]
                except KeyError:
                    utils.LOGGING.warning(
                        'Cannot find the appropriate parser for file %r', fname,
                    )
                    continue
        bulk = db.flow.start_bulk_insert()
        with fileparser(fname, args.pcap_filter) as fdesc:
            for rec in fdesc:
                if not rec:
                    continue
                linkattrs = ('proto',)
                accumulators = {}
                for (fields, sp_linkattrs, sp_accumulators) in FIELD_REQUEST_EXT:
                    if all(field in rec for field in fields):
                        linkattrs = sp_linkattrs
                        accumulators = sp_accumulators
                        break
                if linkattrs not in query_cache:
                    query_cache[linkattrs] = db.flow.add_flow(
                        ["Flow"], linkattrs, counters=COUNTERS,
                        accumulators=accumulators)
                bulk.append(query_cache[linkattrs], rec)
        bulk.close()

    if not args.no_cleanup:
        db.flow.cleanup_flows()

