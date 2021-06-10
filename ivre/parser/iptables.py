#!/usr/bin/env python

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
#
# Maintainers:
#   - 2018 Francois CHENAIS <francois.chenais@cea.fr>
#
#
# Feb  4 05:30:11 pi01 kernel: [3240403.495065]
# IPTABLES/UDP/IN=enxb827eb8f8a4f
# OUT=
# MAC=ff:ff:ff:ff:ff:ff:18:62:2c:7e:45:d0:08:00:45:00:00:ec:00:00:40:00:...
# SRC=192.168.0.254
# DST=192.168.0.255
# LEN=236 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=UDP SPT=138 DPT=138 LEN=216
#
# TODO:
#  - the log does not contain the Year so it's necessary to set it using
#    parameter or changing input with new field 'YEAR' or using current year.
#
"""Support for Iptables log from syslog files."""

import datetime
from typing import Any, Dict, Optional


from ivre.parser import Parser
from ivre.utils import LOGGER


class Iptables(Parser):
    """Iptables log generator from a syslog file descriptor."""

    def __init__(self, fname: str, pcap_filter: Optional[str] = None) -> None:
        """Init Ipatbles class."""
        if pcap_filter is not None:
            LOGGER.warning("PCAP filter not supported in Iptables")
        super().__init__(fname)

    def parse_line(self, line: bytes) -> Dict[str, Any]:
        """Process current line in Parser.__next__."""
        field_idx = line.find(b"IN=")
        if field_idx < 0:
            # It's not an iptables log
            return next(self)

        # Converts the syslog iptables log into hash
        fields: Dict[str, Any] = dict(
            (key.decode().lower(), value.decode())
            for key, value in (
                val.split(b"=", 1) if b"=" in val else (val, b"")
                for val in line[field_idx:].rstrip(b"\r\n").split()
            )
        )

        try:
            fields["start_time"] = datetime.datetime.strptime(
                line[:15].decode(), "%b %d %H:%M:%S"
            )
        except ValueError:
            # Bad Date format
            return next(self)

        # sanitized
        fields["proto"] = fields["proto"].lower()
        # Rename fields according to flow2db specifications.
        if fields["proto"] in ("udp", "tcp"):
            fields["sport"] = int(fields.pop("spt"))
            fields["dport"] = int(fields.pop("dpt"))

        # This data is mandatory but undefined in iptables logs, so make
        # a choice.
        fields["cspkts"] = fields["scpkts"] = 0
        fields["scbytes"] = fields["csbytes"] = 0
        fields["end_time"] = fields["start_time"]

        return fields
