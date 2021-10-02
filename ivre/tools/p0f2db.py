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


"""Update the passive database from p0f log files"""


from argparse import ArgumentParser
from functools import partial
from typing import Dict, Generator, List, Optional, Tuple


from ivre.db import DBPassive, db
from ivre.parser.p0f import P0fFile
from ivre.passive import handle_rec, getinfos
from ivre.tools.passiverecon2db import _get_ignore_rules
from ivre.types import Record
from ivre.utils import LOGGER


def rec_iter(
    filenames: List[str],
    sensor: Optional[str],
    ignore_rules: Dict[str, Dict[str, List[Tuple[int, int]]]],
) -> Generator[Tuple[Optional[int], Record], None, None]:
    ignorenets = ignore_rules.get("IGNORENETS", {})
    neverignore = ignore_rules.get("NEVERIGNORE", {})
    for fname in filenames:
        with P0fFile(fname) as fdesc:
            for line in fdesc:
                if not line:
                    continue
                if "mod" not in line:
                    LOGGER.warning("no mod detected [%r]", line)
                    continue
                if line["mod"] not in ["syn", "syn+ack"]:
                    continue
                if "subj" not in line or line["subj"] not in line:
                    LOGGER.warning("no subj detected [%r]", line)
                    continue
                if "raw_sig" not in line:
                    LOGGER.warning("no raw_sig detected [%r]", line)
                    continue
                infos = {}
                if "os" in line and line["os"] != "???":
                    infos["os"] = line["os"]
                if "dist" in line:
                    infos["dist"] = line["dist"]
                if "params" in line and line["params"].lower() != "none":
                    infos["params"] = line["params"]
                host = line[line["subj"]].split("/")[0]
                srvport = int(line["srv"].split("/")[1])
                for tstamp, rec in handle_rec(
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
                    host=host,
                    # srvport
                    srvport=srvport,
                    # recon_type
                    recon_type="P0FV3_%s" % line["mod"].upper(),
                    # source
                    source="P0FV3",
                    # value
                    value=line["raw_sig"],
                    # targetval
                    targetval=None,
                ):
                    if infos:
                        rec["infos"] = infos
                    yield (tstamp, rec)


def main() -> None:
    """Update the flow database from p0f log files"""
    parser = ArgumentParser(description=__doc__, parents=[db.passive.argparser_insert])
    parser.add_argument("files", nargs="*", metavar="FILE", help="p0f log files")
    args = parser.parse_args()
    ignore_rules = _get_ignore_rules(args.ignore_spec)
    if (not (args.no_bulk or args.local_bulk)) or args.bulk:
        function = db.passive.insert_or_update_bulk
    elif args.local_bulk:
        function = db.passive.insert_or_update_local_bulk
    else:
        function = partial(
            DBPassive.insert_or_update_bulk,
            db.passive,
        )
    function(
        rec_iter(args.files, args.sensor, ignore_rules),
        getinfos=getinfos,
    )


if __name__ == "__main__":
    main()
