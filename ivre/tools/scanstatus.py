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


import datetime
import re
import sys
import time


def main() -> None:
    statusline = re.compile(
        '<task(?P<status>begin|end|progress) task="(?P<task>[^"]*)" '
        'time="(?P<time>[^"]*)"(?P<otherinfo>.*)/>'
    )
    progressinfo = re.compile(
        'percent="(?P<percent>[^"]*)" remaining="(?P<remaining>[^"]*)" '
        'etc="(?P<etc>[^"]*)"'
    )
    endinfo = re.compile('extrainfo="(?P<extrainfo>[^"]*)"')
    curtask = None
    curprogress = None
    for line_raw in sys.stdin:
        line_m = statusline.match(line_raw)
        if line_m is None:
            continue
        line = line_m.groupdict()
        if line["status"] == "begin":
            curtask = (line["task"], int(line["time"]))
            curprogress = None
            continue
        if curtask is None:
            raise Exception(f"curtask is None, task is  {line['task']!r}")
        if curtask[0] != line["task"]:
            raise Exception(f"curtask != task ({curtask!r} != {line['task']!r})")
        if line["status"] == "progress":
            progress_m = progressinfo.search(line["otherinfo"])
            if progress_m is None:
                raise Exception(f"progress line not understood [{line['otherinfo']!r}]")
            progress = progress_m.groupdict()
            curprogress = (
                int(line["time"]),
                float(progress["percent"]),
                int(progress["remaining"]),
                int(progress["etc"]),
            )
        elif line["status"] == "end":
            end_m = endinfo.search(line["otherinfo"])
            if end_m is None:
                end = ""
            else:
                end = f" {end_m.group('extrainfo')}."
            print(
                f"task {curtask[0]} completed in {int(line['time']) - curtask[1]} seconds.{end}"
            )
            curtask = None
            curprogress = None

    if curtask is not None:
        now = int(time.time())
        if curprogress is None:
            progress_str = ""
        else:
            progress_str = f"\n     {now - curprogress[0]} seconds ago: {curprogress[1]:.2f} % done, remaining {curprogress[2]} seconds.\n     ETC {datetime.datetime.fromtimestamp(curprogress[3])}."
        print(
            f"task {curtask[0]} running for {now - curtask[1]} seconds.{progress_str}"
        )
