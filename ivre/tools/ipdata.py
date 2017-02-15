#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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

"""This tool can be used to manage IP addresses related data, such as
AS number and country information.

"""

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import os
try:
    import argparse
    USING_ARGPARSE = True
except ImportError:
    import optparse
    USING_ARGPARSE = False

import ivre.db
import ivre.geoiputils
import ivre.config

def main():
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(description=__doc__)
    else:
        parser = optparse.OptionParser(
            description=__doc__)
        parser.parse_args_orig = parser.parse_args
        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('ip', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option
    TORUN = []
    parser.add_argument('--init', '--purgedb', action='store_true',
                        help='Purge or create and initialize the database.')
    parser.add_argument('--ensure-indexes', action='store_true',
                        help='Create missing indexes (will lock the database).')
    parser.add_argument('--download', action='store_true',
                        help='Fetch all data files.')
    parser.add_argument('--country-csv', metavar='FILE',
                        help='Import FILE into countries database.')
    parser.add_argument('--asnum-csv', metavar='FILE',
                        help='Import FILE into AS database.')
    parser.add_argument('--city-csv', metavar='FILE',
                        help='Import FILE into cities database.')
    parser.add_argument('--location-csv', metavar='FILE',
                        help='Import FILE into locations database.')
    parser.add_argument('--import-all', action='store_true',
                        help='Import all files into databases.')
    parser.add_argument('--no-update-passive-db', action='store_true',
                        help='Do not update the passive database.')
    parser.add_argument('--update-nmap-db', action='store_true',
                        help='Update the active database.')
    parser.add_argument('--quiet', "-q", action='store_true',
                        help='Quiet mode.')
    if USING_ARGPARSE:
        parser.add_argument('ip', nargs='*', metavar='IP',
                            help='Display results for specified IP addresses.')
    args = parser.parse_args()
    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will remove any country/AS information in your '
                'database. Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() != 'y':
                exit(0)
        ivre.db.db.data.init()
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will lock your database. Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() == 'y':
                ivre.db.db.data.ensure_indexes()
    if args.download:
        ivre.geoiputils.download_all(verbose=not args.quiet)
    dbtofeed = {}
    if not args.no_update_passive_db:
        dbtofeed["feedipdata"] = [ivre.db.db.passive]
    if args.update_nmap_db:
        dbtofeed.setdefault("feedipdata", []).append(ivre.db.db.nmap)
    if args.city_csv is not None:
        TORUN.append((ivre.db.db.data.feed_geoip_city,
                      [args.city_csv],
                      dbtofeed))
    if args.country_csv:
        TORUN.append((ivre.db.db.data.feed_geoip_country,
                      [args.country_csv],
                      dbtofeed))
    if args.asnum_csv:
        TORUN.append((ivre.db.db.data.feed_geoip_asnum,
                      [args.asnum_csv],
                      dbtofeed))
    if args.location_csv:
        TORUN.append((ivre.db.db.data.feed_city_location,
                      [args.location_csv], {}))
    if args.import_all:
        for function, fname, kwargs in [
                (ivre.db.db.data.feed_geoip_country,
                 'GeoIPCountry.csv',
                 dbtofeed),
                (ivre.db.db.data.feed_country_codes,
                 'iso3166.csv', {}),
                (ivre.db.db.data.feed_city_location,
                 'GeoIPCity-Location.csv', {}),
                (ivre.db.db.data.feed_geoip_city,
                 'GeoIPCity-Blocks.csv',
                 dbtofeed),
                (ivre.db.db.data.feed_geoip_asnum,
                 'GeoIPASNum.csv',
                 dbtofeed),
        ]:
            TORUN.append((function,
                          [os.path.join(ivre.config.GEOIP_PATH,
                                        fname)],
                          kwargs))
    for r in TORUN:
        r[0](*r[1], **r[2])
    for a in args.ip:
        if a.isdigit():
            a = int(a)
        print a
        for i in [ivre.db.db.data.as_byip(a),
                  ivre.db.db.data.location_byip(a)]:
            if i:
                for f in i:
                    print '    ', f, i[f]
