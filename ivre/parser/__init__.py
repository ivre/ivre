#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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

"""Parsers for file formats / tool outputs"""

import subprocess

from ivre.utils import FileOpener

class Parser(FileOpener):
    """Parent class for file parsers"""

    def next(self):
        return self.parse_line(super(Parser, self).next())


class CmdParser(object):
    """Parent class for file parsers with commands"""

    def __init__(self, cmd, cmdkargs):
        cmdkargs["stdout"] = subprocess.PIPE
        self.proc = subprocess.Popen(cmd, **cmdkargs)
        self.fdesc = self.proc.stdout

    def __iter__(self):
        return self

    def next(self):
        return self.parse_line(self.fdesc.next())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.fdesc.close()
        if self.proc is not None:
            self.proc.wait()
