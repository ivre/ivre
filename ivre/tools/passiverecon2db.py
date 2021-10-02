#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
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


from argparse import ArgumentParser
import functools
import signal
import sys
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple


from ivre.db import db, DBPassive
import ivre.passive
import ivre.parser.zeek
from ivre.types import Record
from ivre.utils import force_ip2int


signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)


def _get_ignore_rules(
    ignore_spec: Optional[str],
) -> Dict[str, Dict[str, List[Tuple[int, int]]]]:
    """Executes the ignore_spec file and returns the ignore_rules
    dictionary.

    """
    ignore_rules: Dict[str, Dict[str, List[Tuple[int, int]]]] = {}
    if ignore_spec is not None:
        with open(ignore_spec, "rb") as fdesc:
            # pylint: disable=exec-used
            exec(compile(fdesc.read(), ignore_spec, "exec"), ignore_rules)
    subdict = ignore_rules.get("IGNORENETS")
    if subdict:
        for subkey, values in subdict.items():
            subdict[subkey] = [
                (force_ip2int(val[0]), force_ip2int(val[1])) for val in values
            ]
    return ignore_rules


def rec_iter(
    zeek_parser: Iterable[Dict[str, Any]],
    sensor: Optional[str],
    ignore_rules: Dict[str, Dict[str, List[Tuple[int, int]]]],
) -> Generator[Tuple[Optional[int], Record], None, None]:
    for line in zeek_parser:
        line["timestamp"] = line.pop("ts")
        # skip PassiveRecon::
        line["recon_type"] = line["recon_type"][14:]
        yield from ivre.passive.handle_rec(
            sensor,
            ignore_rules.get("IGNORENETS", {}),
            ignore_rules.get("NEVERIGNORE", {}),
            **line,
        )


def main() -> None:
    parser = ArgumentParser(description=__doc__, parents=[db.passive.argparser_insert])
    args = parser.parse_args()
    ignore_rules = _get_ignore_rules(args.ignore_spec)
    if (not (args.no_bulk or args.local_bulk)) or args.bulk:
        function = db.passive.insert_or_update_bulk
    elif args.local_bulk:
        function = db.passive.insert_or_update_local_bulk
    else:
        function = functools.partial(
            DBPassive.insert_or_update_bulk,
            db.passive,
        )
    zeek_parser = ivre.parser.zeek.ZeekFile(sys.stdin.buffer)
    function(
        rec_iter(zeek_parser, args.sensor, ignore_rules), getinfos=ivre.passive.getinfos
    )
