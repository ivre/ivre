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

"""Support for Airodump csv files"""

import datetime
from itertools import izip

from ivre.parser import Parser


TYPE_INT = 0
TYPE_DATE = 1
TYPE_IP = 2
TYPE_MAC = 3


class Airodump(Parser):
    """Airodump-neg log generator from a file descriptor"""
    types = {
        "# IV": TYPE_INT,
        'BSSID': TYPE_MAC,
        'ID-length': TYPE_INT,
        'First time seen': TYPE_DATE,
        'Last time seen': TYPE_DATE,
        'LAN IP': TYPE_IP,
        'Power': TYPE_INT,
        'Speed': TYPE_INT,
        'channel': TYPE_INT,
        '# beacons': TYPE_INT,
    }
    converters = {
        TYPE_INT: int,
        TYPE_DATE: lambda val: datetime.datetime.strptime(val,
                                                          '%Y-%m-%d %H:%M:%S'),
        TYPE_IP: lambda val: '.'.join(elt.strip() for elt in val.split('.')),
        TYPE_MAC: lambda val: val.lower(),
        None: lambda val: val.strip(),
    }

    def __init__(self, fname):
        super(Parser, self).__init__(fname)
        self.nextline_headers = False

    def next(self):
        line = super(Parser, self).next().rstrip('\r\n')
        if not line:
            self.nextline_headers = True
            return self.next()
        line = [elt.strip() for elt in line.split(',')]
        if self.nextline_headers:
            self.fields = line
            self.nextline_headers = False
            return self.next()
        return dict(izip(
            self.fields,
            (self.converters.get(self.types.get(self.fields[i]))(val)
             for (i, val) in enumerate(line)),
        ))
