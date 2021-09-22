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

"""Support for p0f log files"""

import datetime
import re
from typing import Any, BinaryIO, Dict, List, Optional, Union


from ivre.parser import Parser
from ivre.utils import LOGGER


CONTAINER_TYPE = re.compile(b"^(table|set|vector)\\[([a-z]+)\\]$")
LINE_RE = re.compile(r"^\[(?P<time>[^\]]+)\] (?P<data>.*)$")


class P0fFile(Parser):
    """p0f log generator"""

    def __init__(self, fname: Union[BinaryIO, str]) -> None:
        self.sep = b" "  # b"\t"
        self.set_sep = b","
        self.empty_field = b"(empty)"
        self.unset_field = b"-"
        self.fields: List[bytes] = []
        self.types: List[bytes] = []
        self.path: Optional[str] = None
        super().__init__(fname)

    def __enter__(self) -> "P0fFile":
        return self

    def __next__(self) -> Dict[str, Any]:
        return self.parse_line(next(self.fdesc).strip())

    def parse_line(self, line: bytes) -> Dict[str, Any]:
        m = LINE_RE.match(line.decode())
        if not m:
            return {}
        res: Dict[str, Any] = {}
        # time of event
        res["ts"] = datetime.datetime.strptime(m.group("time"), "%Y/%m/%d %H:%M:%S")
        # data of event
        for entry in m.group("data").split("|"):
            k, v = entry.split("=", 1)
            if k in res:
                LOGGER.warning("Duplicate key in line [%r]", line)
                return {}
            res[k] = v
        return res

    def __str__(self) -> str:
        return "\n".join(
            [
                "%s = %r" % (k, getattr(self, k))
                for k in [
                    "sep",
                    "set_sep",
                    "empty_field",
                    "unset_field",
                    "fields",
                    "types",
                ]
            ]
        )
