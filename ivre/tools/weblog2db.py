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


"""Update the passive database from http server log files"""


from argparse import ArgumentParser
from functools import partial
from sys import stdin
from typing import Dict, Generator, List, Optional, Tuple


from ivre.db import DBPassive, db
from ivre.parser.weblog import WeblogFile
from ivre.passive import handle_rec, getinfos
from ivre.tools.passiverecon2db import _get_ignore_rules
from ivre.types import Record


def rec_iter(
    filenames: List[str],
    sensor: Optional[str],
    ignore_rules: Dict[str, Dict[str, List[Tuple[int, int]]]],
) -> Generator[Tuple[Optional[int], Record], None, None]:
    ignorenets = ignore_rules.get("IGNORENETS", {})
    neverignore = ignore_rules.get("NEVERIGNORE", {})
    for fname in filenames:
        with WeblogFile(fname) as fdesc:
            for line in fdesc:
                if not line:
                    continue
                if line.get("useragent") and line["useragent"] != "-":
                    yield from handle_rec(
                        # sensor
                        sensor,
                        # ignorenets,
                        ignorenets,
                        # neverignore,
                        neverignore,
                        # timestamp
                        timestamp=line["ts"],
                        # uid
                        uid=None,
                        # host
                        host=line["host"],
                        # srvport
                        srvport=None,
                        # recon_type
                        recon_type="HTTP_CLIENT_HEADER",
                        # source
                        source="USER-AGENT",
                        # value
                        value=line["useragent"],
                        # targetval
                        targetval=None,
                    )


def main() -> None:
    """Update the flow database from http server log files"""
    parser = ArgumentParser(description=__doc__, parents=[db.passive.argparser_insert])
    parser.add_argument(
        "files", nargs="*", metavar="FILE", help="http server log files"
    )
    args = parser.parse_args()
    ignore_rules = _get_ignore_rules(args.ignore_spec)
    if args.test:
        function = DBPassive().insert_or_update_local_bulk
    elif (not (args.no_bulk or args.local_bulk)) or args.bulk:
        function = db.passive.insert_or_update_bulk
    elif args.local_bulk:
        function = db.passive.insert_or_update_local_bulk
    else:
        function = partial(
            DBPassive.insert_or_update_bulk,
            db.passive,
        )
    function(
        rec_iter(args.files or [stdin.buffer], args.sensor, ignore_rules),
        getinfos=getinfos,
    )


if __name__ == "__main__":
    main()
