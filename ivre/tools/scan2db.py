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

import ivre.db
import ivre.utils
import ivre.xmlnmap

import os
import sys

def recursive_filelisting(base_directories):
    "Iterator on filenames in base_directories"

    for base_directory in base_directories:
        for root, _, files in os.walk(base_directory):
            for leaffile in files:
                yield os.path.join(root, leaffile)

def main():
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='Parse NMAP scan results and add them in DB.')
        parser.add_argument('scan', nargs='*', metavar='SCAN',
                            help='Scan results')

    except ImportError:
        import optparse
        parser = optparse.OptionParser(
            description='Parse NMAP scan results and add them in DB.')
        parser.parse_args_orig = parser.parse_args

        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('scan', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option

    parser.add_argument('-c', '--categories', default='',
                        help='Scan categories.')
    parser.add_argument('-s', '--source', default=None,
                        help='Scan source.')
    parser.add_argument('-t', '--test', action='store_true',
                        help='Test mode (JSON output).')
    parser.add_argument('--test-normal', action='store_true',
                        help='Test mode ("normal" Nmap output).')
    parser.add_argument('--ports', '--port', action='store_true',
                        help='Store only hosts with a "ports" element.')
    parser.add_argument('--open-ports', action='store_true',
                        help='Store only hosts with open ports.')
    parser.add_argument('--never-archive', action='store_true',
                        help='Never archive.')
    parser.add_argument('--archive', '--archive-same-host', action='store_true',
                        help='Archive results for the same host.')
    parser.add_argument('--archive-same-host-and-source', action='store_true',
                        help='Archive results with both the same host and'
                        ' source (this is the default).')
    parser.add_argument('--merge', action='store_true', help='Merge '
                        'result with previous scan result for same host '
                        'and source. Useful to use multiple partial '
                        'scan results (e.g., one with -p 80, another '
                        'with -p 21).')
    parser.add_argument('--masscan-probes', nargs='+', metavar='PROBE',
                        help='Additional Nmap probes to use when trying to '
                        'match Masscan results against Nmap service '
                        'fingerprints.')
    parser.add_argument('--force-info', action='store_true',
                        help='Force information (AS, country, city, etc.)'
                        ' renewal (only useful with JSON format)')
    parser.add_argument('-r', '--recursive', action='store_true',
                        help='Import all files from given directories.')
    args = parser.parse_args()
    database = ivre.db.db.nmap
    categories = args.categories.split(',') if args.categories else []
    if args.test:
        database = ivre.db.DBNmap()
    if args.test_normal:
        database = ivre.db.DBNmap(output_mode="normal")
    if args.never_archive:
        def gettoarchive(addr, _):
            return []
    elif args.archive:
        def gettoarchive(addr, _):
            return database.get(database.searchhost(addr))
    else:  #args.archive_same_host_and_source
        def gettoarchive(addr, source):
            return database.get(
                database.flt_and(database.searchhost(addr),
                                 database.searchsource(source))
            )
    if args.recursive:
        scans = recursive_filelisting(args.scan)
    else:
        scans = args.scan
    count = 0
    for scan in scans:
        try:
            if database.store_scan(
                    scan,
                    categories=categories, source=args.source,
                    needports=args.ports, needopenports=args.open_ports,
                    gettoarchive=gettoarchive, force_info=args.force_info,
                    merge=args.merge, masscan_probes=args.masscan_probes,
            ):
                count += 1
        except Exception:
            ivre.utils.LOGGER.warning("Exception (file %r)", scan,
                                      exc_info=True)
    print "%d results imported." % count
