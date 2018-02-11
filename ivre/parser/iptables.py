#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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
#
# Maintainers:
#   - 2018 Francois CHENAIS <francois.chenais@cea.fr>
#

"""Support for Iptables log from syslog files


Feb  4 05:30:11 pi01 kernel: [3240403.495065] IPTABLES/UDP/IN=enxb827eb8f8a4f OUT= MAC=ff:ff:ff:ff:ff:ff:18:62:2c:7e:45:d0:08:00:45:00:00:ec:00:00:40:00:40:11:df:e3 SRC=192.168.0.254 DST=192.168.0.255 LEN=236 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=UDP SPT=138 DPT=138 LEN=216

TODO:
 - the log does not contain the Year so it's necessary to set it using parameter
   or changing input with new field 'YEAR' or using current year.
 - The log contains mac addr from source and destination, is this inifo can be
   added to neo db ?

"""

import datetime
from builtins import zip
from ivre.parser import Parser


class Iptables(Parser):
    """Iptables log generator from a syslog file descriptor"""

    def __init__(self, fname, pcap_filter=None):
        super(Iptables, self).__init__(fname)


    def parse_line(self, line):

        field_idx=line.find('IN=')
        if field_idx<0:
            # It's not an iptables log
            return next(self)

        # Converts the syslog iptables log into hash
        fields = dict((key.lower(), value)
                for key, value in (val.split('=', 1) if '=' in val else (val, '')
                    for val in line[field_idx:].rstrip('\r\n').split()))

        # Because day of month can be on 1 or 2 char(s)
        try:
            fields['start_time'] = datetime.datetime.strptime(line[:15], '%b  %d %H:%M:%S')
        except:
            fields['start_time'] = datetime.datetime.strptime(line[:15], '%b %d %H:%M:%S')

        # sanitized
        fields['proto'] = fields['proto'].lower()
        # Rename fields according to flow2db specifications.
        if fields['proto'] in ('udp', 'tcp'):
            fields['sport'] = int(fields['spt'])
            fields['dport'] = int(fields['dpt'])

        # This data is mandatory but undefined in iptables logs, so make my/a choice.
        fields['cspkts'] = fields['scpkts'] = fields['scbytes'] = fields['csbytes'] = 0
        fields['end_time'] = fields['start_time']

        return fields
