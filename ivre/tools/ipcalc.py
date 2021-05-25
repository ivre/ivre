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


import argparse


from ivre import utils


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tool for ip addresses manipulation.",
    )
    parser.add_argument(
        "ips",
        nargs="*",
        help="Display results for specified IP addresses or ranges.",
    )
    args = parser.parse_args()
    while "-" in args.ips:
        idx = args.ips.index("-")
        args.ips = (
            args.ips[: idx - 1]
            + ["%s-%s" % (args.ips[idx - 1], args.ips[idx + 1])]
            + args.ips[idx + 2 :]
        )

    for a in args.ips:
        if "/" in a:
            a = utils.net2range(a)
            print("%s-%s" % (a[0], a[1]))
        elif "-" in a:
            a = a.split("-", 1)
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
