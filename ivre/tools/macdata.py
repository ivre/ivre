#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2023 Pierre LALET <pierre@droids-corp.org>
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


"""This tool can be used to query manufacturers for MAC addresses.

"""


import json
from argparse import ArgumentParser
from sys import stdout

from ivre import utils


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--json", "-j", action="store_true", help="Output JSON data.")
    parser.add_argument(
        "mac",
        nargs="*",
        metavar="MAC",
        help="Display manufacturers for specified MAC addresses.",
    )
    args = parser.parse_args()
    for addr in args.mac:
        info = utils.mac2manuf(addr)
        if args.json:
            res = {"addr": addr}
            if info:
                if isinstance(info, tuple):
                    if info[0]:
                        res["manufacturer_code"] = info[0]
                    if info[1:] and info[1]:
                        res["manufacturer_name"] = info[1]
                else:
                    res["manufacturer_name"] = info
            json.dump(res, stdout)
            print()
        else:
            if isinstance(info, tuple):
                print(f"{addr} {' / '.join(i for i in info if i)}")
            else:
                print(f"{addr} {info}")
