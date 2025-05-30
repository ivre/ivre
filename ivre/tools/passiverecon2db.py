#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2025 Pierre LALET <pierre@droids-corp.org>
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
import json
import os
import signal
import sys
from argparse import ArgumentParser
from collections.abc import Generator, Iterable
from typing import Any, BinaryIO, Callable

from ivre.db import DBPassive, db
from ivre.parser.zeek import ZeekFile
from ivre.passive import get_ignore_rules, getinfos, handle_rec
from ivre.types import Record
from ivre.utils import LOGGER, open_file, recursive_filelisting

signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)


def rec_iter(
    zeek_parser: Iterable[dict[str, Any]],
    sensor: str | None,
    ignore_rules: dict[str, dict[str, list[tuple[int, int]]]],
) -> Generator[tuple[int | None, Record], None, None]:
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
    files: Iterable[BinaryIO | str]
    if not args.files:
        files = [sys.stdin.buffer]
    elif args.recursive:
        files = recursive_filelisting(args.files)
    else:
        files = args.files
    error = 0
    generator: Callable[[BinaryIO | str], Iterable[dict[str, Any]]]
    for fname in files:
        if isinstance(fname, str):
            if not os.path.exists(fname):
                LOGGER.warning("file %r does not exist", fname)
                error += 1
                continue
            with open_file(fname) as fdesc:
                fchar = fdesc.read(1)
            try:
                generator = {
                    b"{": lambda fname: (json.loads(line) for line in open_file(fname)),  # type: ignore
                    b"#": ZeekFile,
                }[fchar]
            except KeyError:
                LOGGER.warning("file %r is invalid", fname)
                error += 1
                continue
        else:
            generator = ZeekFile
        try:
            function(
                rec_iter(generator(fname), args.sensor, ignore_rules), getinfos=getinfos
            )
        except Exception:
            LOGGER.warning("failed to import file %r", fname, exc_info=True)
            error += 1
            continue
        sys.exit(error)
