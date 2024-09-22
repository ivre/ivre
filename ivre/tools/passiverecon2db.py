#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
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


"""Update the database from output of the Zeek script 'passiverecon'"""


import functools
import signal
import sys
from argparse import ArgumentParser
from typing import (
    Any,
    BinaryIO,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Tuple,
    Union,
)

from ivre.db import DBPassive, db
from ivre.parser.zeek import ZeekFile
from ivre.passive import get_ignore_rules, getinfos, handle_rec
from ivre.types import Record
from ivre.utils import recursive_filelisting

signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)


def rec_iter(
    zeek_parser: Iterable[Dict[str, Any]],
    sensor: Optional[str],
    ignore_rules: Dict[str, Dict[str, List[Tuple[int, int]]]],
) -> Generator[Tuple[Optional[int], Record], None, None]:
    for line in zeek_parser:
        line["timestamp"] = line.pop("ts")
        # skip PassiveRecon::
        line["recon_type"] = line["recon_type"][14:]
        yield from handle_rec(
            sensor,
            ignore_rules.get("IGNORENETS", {}),
            ignore_rules.get("NEVERIGNORE", {}),
            **line,
        )


def main() -> None:
    parser = ArgumentParser(description=__doc__, parents=[db.passive.argparser_insert])
    parser.add_argument(
        "files", nargs="*", metavar="FILE", help="passive_recon log files"
    )
    args = parser.parse_args()
    ignore_rules = get_ignore_rules(args.ignore_spec)
    if args.test:
        function = DBPassive().insert_or_update_local_bulk
    elif (not (args.no_bulk or args.local_bulk)) or args.bulk:
        function = db.passive.insert_or_update_bulk
    elif args.local_bulk:
        function = db.passive.insert_or_update_local_bulk
    else:
        function = functools.partial(
            DBPassive.insert_or_update_bulk,
            db.passive,
        )
    files: Iterable[Union[BinaryIO, str]]
    if not args.files:
        files = [sys.stdin.buffer]
    elif args.recursive:
        files = recursive_filelisting(args.files)
    else:
        files = args.files
    for fdesc in files:
        function(
            rec_iter(ZeekFile(fdesc), args.sensor, ignore_rules), getinfos=getinfos
        )
