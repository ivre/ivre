#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2022 Pierre LALET <pierre@droids-corp.org>
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
from sys import stdin
from typing import Iterable


from ivre.utils import key_sort_dom_addr


def main() -> None:
    parser = argparse.ArgumentParser(description="Sort IP addresses and domain names.")
    parser.add_argument(
        "-u",
        "--unique",
        action="store_true",
    )
    args = parser.parse_args()
    data: Iterable[str] = (line.strip() for line in stdin)
    if args.unique:
        data = set(data)
    for line in sorted(data, key=key_sort_dom_addr):
        print(line)
