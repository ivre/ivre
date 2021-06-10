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

"""Support for Zeek log files"""

import datetime
import re
from typing import Any, BinaryIO, Dict, List, Optional, Tuple, Union


from ivre.parser import Parser
from ivre.utils import LOGGER, decode_hex


CONTAINER_TYPE = re.compile(b"^(table|set|vector)\\[([a-z]+)\\]$")


class ZeekFile(Parser):
    """Zeek log generator"""

    int_types = set([b"port", b"count"])
    float_types = set([b"interval"])
    time_types = set([b"time"])

    def __init__(self, fname: Union[BinaryIO, str]) -> None:
        self.sep = b" "  # b"\t"
        self.set_sep = b","
        self.empty_field = b"(empty)"
        self.unset_field = b"-"
        self.fields: List[bytes] = []
        self.types: List[bytes] = []
        self.path: Optional[str] = None
        self.nextlines = []
        super().__init__(fname)
        for line in self.fdesc:
            line = line.strip()
            if not line.startswith(b"#"):
                self.nextlines.append(line)
                break
            self.parse_header_line(line)

    def __enter__(self) -> "ZeekFile":
        return self

    def __next__(self) -> Dict[str, Any]:
        return self.parse_line(
            self.nextlines.pop(0) if self.nextlines else next(self.fdesc).strip()
        )

    def parse_header_line(self, line: bytes) -> None:
        if not line:
            return
        if line[:1] != b"#":
            LOGGER.warning("Not a header line")
            return

        keyval = line[1:].split(self.sep, 1)
        if len(keyval) < 2:
            if line.startswith(b"#separator "):
                keyval = [b"separator", line[11:]]
            else:
                LOGGER.warning("Invalid header line")
                return

        directive = keyval[0]
        arg = keyval[1]

        if directive == b"separator":
            self.sep = decode_hex(arg[2:]) if arg.startswith(b"\\x") else arg
        elif directive == b"set_separator":
            self.set_sep = arg
        elif directive == b"empty_field":
            self.empty_field = arg
        elif directive == b"unset_field":
            self.unset_field = arg
        elif directive == b"path":
            self.path = arg.decode()
        elif directive == b"open":
            pass
        elif directive == b"fields":
            self.fields = arg.split(self.sep)
        elif directive == b"types":
            self.types = arg.split(self.sep)

    def parse_line(self, line: bytes) -> Dict[str, Any]:
        if line.startswith(b"#"):
            self.parse_header_line(line)
            return next(self)
        res = {}
        fields = line.split(self.sep)

        for field, name, typ in zip(fields, self.fields, self.types):
            res[name.replace(b".", b"_").decode()] = self.fix_value(field, typ)
        return res

    def fix_value(
        self, val: bytes, typ: bytes
    ) -> Optional[Union[bool, str, int, float, datetime.datetime, list]]:
        if val == self.unset_field:
            return None
        if typ == b"bool":
            return val == b"T"
        container_type = CONTAINER_TYPE.search(typ)
        if container_type is not None:
            if val == self.empty_field:
                return []
            _, elt_type = container_type.groups()
            return [self.fix_value(x, elt_type) for x in val.split(self.set_sep)]
        if typ in self.int_types:
            return int(val)
        if typ in self.float_types:
            return float(val)
        if typ in self.time_types:
            return datetime.datetime.fromtimestamp(float(val))
        if val == self.empty_field:
            return ""
        return val.decode()

    @property
    def field_types(self) -> List[Tuple[bytes, bytes]]:
        return list(zip(self.fields, self.types))

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
