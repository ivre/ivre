#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2020 Pierre LALET <pierre@droids-corp.org>
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

"""This sub-module contains data used to identify network scanners.

"""

# pylint: disable=line-too-long


JA3_CLIENT_VALUES = {
    # Masscan has three values because it will send its static client
    # hello message three times if it does not get an answer (which is
    # weird).
    "18e9afaf91db6f8a2470e7435c2a1d6b": ("Masscan", None),
    "2351bc927776c12aff03dcf9f1c12270": ("Masscan", None),
    "5f8552974406f5edd94290c87c3f9f24": ("Masscan", None),
    "8951236eca85955755e4946572ef32bb": ("Censys", "DTLS"),
}


USER_AGENT_VALUES = {
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; "
    "https://nmap.org/book/nse.html)": ("Nmap", None),
    "Mozilla/5.0 zgrab/0.x": ("Zgrab", None),
    "masscan/1.0 (https://github.com/robertdavidgraham/masscan)": ("Masscan", None),
    "HTTP Banner Detection (https://security.ipip.net)": ("ipip.net", None),
    "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/": (
        "Censys",
        None,
    ),
}


UDP_PROBES = {
    b"\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00~\x01\x00\x00r\x00\x00\x00\x00\x00\x00\x00r\xfe\xfd_\x06\x07BnS\xder\xd8\xef3~_\xeeY\x10\x19I\x8b-N\x7f\xde>\x09\xf4\xa8?\x03\xf9W\x06\x00\x00\x00\x0c\xc0\xac\xc0\xae\xc0+\xc0/\xc0\x0a\xc0\x14\x01\x00\x00<\x00\x0d\x00\x10\x00\x0e\x04\x03\x05\x03\x06\x03\x04\x01\x05\x01\x06\x01\x08\x07\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x17\x00\x00\x00\x00\x00\x0e\x00\x0c\x00\x00\x09127.0.0.1": (  # noqa: E501
        "Censys",
        "DTLS",
    ),
    b"\x93\xd5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03213\x011\x03168\x03192\x07in-addr\x04arpa\x00\x00\x0c\x00\x01": (
        "Censys",
        "DNS",
    ),  # DNS query IN PTR 213.1.168.192.in-addr.arpa.  # noqa: E501
}


TCP_PROBES = {
    b"\x16\x03\x02\x01o\x01\x00\x01k\x03\x02RH\xc5\x1a#\xf7:N\xdf\xe2\xb4\x82/\xff\tT\x9f\xa7\xc4y\xb0h\xc6\x13\x8c\xa4\x1c=\"\xe1\x1a\x98 \x84\xb4,\x85\xafn\xe3Y\xbbbhl\xff(=':\xa9\x82\xd9o\xc8\xa2\xd7\x93\x98\xb4\xef\x80\xe5\xb9\x90\x00(\xc0\n\xc0\x14\x009\x00k\x005\x00=\xc0\x07\xc0\t\xc0#\xc0\x11\xc0\x13\xc0'\x003\x00g\x002\x00\x05\x00\x04\x00/\x00<\x00\n\x01\x00\x00\xfa\xef\x00\x00\x1a\x00\x18\x00\x00\x15syndication.twimg.com\xff\x01\x00\x01\x00\x00\n\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\xb0\x81\x01\x19g`\x1e\x04B\x9a\xf3\xe2<\x86XO\x87iD\xb0\x1d\x8e\x01\xfa\xa5\x87=]\xdc\x16L\xb4 \xda\xd3B\xb0\x88\xec\n\x13\xc3\xc6LDt}\xf5\x83\x93\xeb\x16`~G\x07\x15\xaeh?2\xfc(q\xdd\x8d*\xe0\x9e\x03\xad(\xd9\x89/\x0f\x07\xaf\xc1'\x8e\xf1W\xfb\xc6\xc4\xd4V:\xf6\xedYaJ\x17\x14\x0b\xd7|\xae\xfeU\xd9z\xa6\xf6\xc6W\xb5<\xedx\x9d\xee9\xd8g\x02\t\x92\xcb\xa5f\xa3H=\x06\xed\xa5\x02.\x9b\x16\xf6+\xe7?ye\x1a\xcbl\\\xbdk\xad\x11\xde\xbe\xdf5\xdb\x0b\xff,\x90\x942\xb5\x94W=^%\xd2\x1b\xd2D\x85\x961(i\xd7J\x13\n3t\x00\x00uO\x00\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00": (  # noqa: E501
        "Masscan",
        "TLS",
    ),
    b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:2\n};;\n": (
        "Nmap-modified",
        "niagara-fox-modified",
    ),
}
