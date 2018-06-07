#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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
try:
    import argparse
    USING_ARGPARSE = True
except ImportError:
    import optparse
    USING_ARGPARSE = False
import sys
try:
    reload(sys)
except NameError:
    pass
else:
    sys.setdefaultencoding('utf-8')


from future.utils import viewitems


import ivre.config
import ivre.db
import ivre.geoiputils
import ivre.utils


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
    torun = []
    parser.add_argument('--download', action='store_true',
                        help='Fetch all data files.')
    parser.add_argument('--import-all', action='store_true',
                        help='Create all CSV files for reverse lookups.')
    parser.add_argument('--quiet', "-q", action='store_true',
                        help='Quiet mode.')
    if USING_ARGPARSE:
        parser.add_argument('ip', nargs='*', metavar='IP',
                            help='Display results for specified IP addresses.')
    args = parser.parse_args()
    if args.download:
        ivre.geoiputils.download_all(verbose=not args.quiet)
    if args.import_all:
        torun.append((ivre.db.db.data.build_dumps, [], {}))
    for function, fargs, fkargs in torun:
        function(*fargs, **fkargs)
    for addr in args.ip:
        if addr.isdigit():
            addr = int(addr)
        print(addr)
        for info in [ivre.db.db.data.as_byip(addr),
                     ivre.db.db.data.location_byip(addr)]:
            if info:
                for key, value in viewitems(info):
                    print('    %s %s' % (key, value))
