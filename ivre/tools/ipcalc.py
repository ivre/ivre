#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2019 Pierre LALET <pierre.lalet@cea.fr>
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


from __future__ import print_function

try:
    import argparse
except ImportError:
    import optparse
    USING_ARGPARSE = False
else:
    USING_ARGPARSE = True
import sys
try:
    reload(sys)
except NameError:
    pass
else:
    sys.setdefaultencoding('utf-8')


from ivre import utils


def main():
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(
            description='Tool for ip addresses manipulation.',
        )
    else:
        parser = optparse.OptionParser(
            description='Tool for ip addresses manipulation.',)
        parser.parse_args_orig = parser.parse_args

        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('ips', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option

    if USING_ARGPARSE:
        parser.add_argument('ips', nargs='*',
                            help='Display results for specified IP addresses'
                            ' or ranges.')
    args = parser.parse_args()

    for a in args.ips:
        if '/' in a:
            a = utils.net2range(a)
            print("%s-%s" % (a[0], a[1]))
        elif '-' in a:
            a = a.split('-', 1)
            if a[0].isdigit():
                a[0] = int(a[0])
            if a[1].isdigit():
                a[1] = int(a[1])
            for n in utils.range2nets((a[0], a[1])):
                print(n)
        else:
            if a.isdigit():
                a = utils.force_int2ip(int(a))
            else:
                a = utils.force_ip2int(a)
            print(a)
