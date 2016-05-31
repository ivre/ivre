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

"""Support for Bro log files"""

import datetime
from itertools import izip

from ivre.parser import Parser

class BroFile(Parser):
    """Bro log generator"""

    int_types = set(["port", "count"])
    float_types = set(["interval"])
    time_types = set(["time"])

    def __init__(self, fname):
        self.sep = " "#"\t"
        self.set_sep = ","
        self.empty_field = "(empty)"
        self.unset_field = "-"
        self.fields = []
        self.types = []
        self.path = None
        self.nextlines = []
        super(BroFile, self).__init__(fname)
        for line in self.fdesc:
            line = line.strip()
            if not line.startswith('#'):
                self.nextlines.append(line)
                break
            self.parse_header_line(line)

    def next(self):
        return self.parse_line(self.nextlines.pop(0)
                               if self.nextlines else
                               next(self.fdesc))

    def parse_header_line(self, line):
        if not line:
            return
        if line[0] != "#":
            log.warning("Not a header line")
            return

        keyval = line[1:].split(self.sep, 1)
        if len(keyval) < 2:
            log.warn("Invalid header line")

        directive = keyval[0]
        arg = keyval[1]

        if directive == "separator":
            self.sep = arg[2:].decode("hex") if arg.startswith('\\x') else arg
        elif directive == "set_separator":
            self.set_sep = arg
        elif directive == "empty_field":
            self.empty_field = arg
        elif directive == "unset_field":
            self.unset_field = arg
        elif directive == "path":
            self.path = arg
        elif directive == "open":
            pass
        elif directive == "fields":
            self.fields = arg.split(self.sep)
        elif directive == "types":
            self.types = arg.split(self.sep)

        return None

    def parse_line(self, line):
        if line.startswith('#'):
            return self.next()
        res = {}
        fields = line.strip().split(self.sep)

        for field, name, typ in izip(fields, self.fields, self.types):
            name = name.replace(".", "_")
            res[name] = self.bro2neo(field, typ)
        return res

    def bro2neo(self, val, typ):
        if val == self.unset_field:
            return None
        if typ == "bool":
            return val == "T"
        elif typ.startswith("vector["):
            if val in self.empty_field:
                return "[]"
            elt_type = typ[len("vector["):-1]
            return [self.bro2neo(x, elt_type)
                    for x in val.split(self.set_sep)]
        elif typ in self.int_types:
            return int(val)
        elif typ in self.float_types:
            return float(val)
        elif typ in self.time_types:
            return datetime.datetime.fromtimestamp(float(val))
        else:
            return val

    @property
    def field_types(self):
        return [(f, t) for f, t in zip(self.fields, self.types)]

    def __str__(self):
        return "\n".join(["%s = %r" % (k, getattr(self, k))
                    for k in ["sep", "set_sep", "empty_field", "unset_field",
                              "fields", "types"]])
