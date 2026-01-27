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

"""Support for http server log files"""

import datetime
import re
from typing import Any

from ivre.parser import Parser
from ivre.utils import LOGGER


class WeblogFile(Parser):
    """Http server log generator"""

    line_re = re.compile(
        r'^(?P<addr>[^ ]*) (?P<identity>[^ ]*) (?P<username>[^ ]*) \[(?P<datetime>[^]]*)\] "(?P<request>[^"]*)" (?P<status>[^ ]*) (?P<size>[^ ]*) "(?P<referer>[^"]*)" "(?P<useragent>[^"]*)"(?: "(?P<x_forwarded_for>[^"]*)")?\r?$'
    )

    def parse_line(self, line: bytes) -> dict[str, Any]:
        m = self.line_re.match(line.decode())
        if not m:
            LOGGER.warning("Cannot parse line [%r]", line)
            return {}
        try:
            # Timestamp, without timezone specification
            timestamp = datetime.datetime.strptime(
                m.group("datetime").split()[0], "%d/%b/%Y:%H:%M:%S"
            )
        except ValueError:
            LOGGER.warning("Cannot parse timestamp from line [%r]", line)
            return {}
        # data of event
        result = {
            "host": m.group("addr"),
            "ts": timestamp,
        }
        if (useragent := m.group("useragent")) != "-":
            result["user-agent"] = useragent
        xff = m.group("x_forwarded_for")
        if xff and xff != "-":
            result["x-forwarded-for"] = xff
        return result
