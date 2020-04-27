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


"""This tool can be used to manage IP addresses related data, such as
AS number and country information.

"""


from __future__ import print_function
from argparse import ArgumentParser
import sys
try:
    reload(sys)
except NameError:
    pass
else:
    sys.setdefaultencoding('utf-8')


from future.utils import viewitems


from ivre.db import db
from ivre import geoiputils, utils


def main():
    parser = ArgumentParser(description=__doc__)
    torun = []
    parser.add_argument('--download', action='store_true',
                        help='Fetch all data files.')
    parser.add_argument('--import-all', action='store_true',
                        help='Create all CSV files for reverse lookups.')
    parser.add_argument('--quiet', "-q", action='store_true',
                        help='Quiet mode.')
    parser.add_argument('ip', nargs='*', metavar='IP',
                        help='Display results for specified IP addresses.')
    args = parser.parse_args()
    if args.download:
        geoiputils.download_all(verbose=not args.quiet)
        db.data.reload_files()
    if args.import_all:
        torun.append((db.data.build_dumps, [], {}))
    for function, fargs, fkargs in torun:
        function(*fargs, **fkargs)
    for addr in args.ip:
        if addr.isdigit():
            addr = utils.int2ip(int(addr))
        print(addr)
        info = utils.get_addr_type(addr)
        if info:
            print('    address_type %s' % info)
        for info in [db.data.as_byip(addr), db.data.location_byip(addr)]:
            for key, value in viewitems(info or {}):
                print('    %s %s' % (key, value))
