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


"""
Specific type definitions for IVRE (active)
"""

from typing import Any

try:
    from typing import TypedDict
except ImportError:
    HAS_TYPED_DICT = False
else:
    HAS_TYPED_DICT = True


from ivre.types import NmapServiceMatch

NmapHost = dict[str, Any]  # TODO (see below)
NmapAddress = dict[str, Any]  # TODO & TO FIX...
NmapScript = dict[str, Any]  # seems hard to do better for now (lots of keys)


if HAS_TYPED_DICT:

    class HttpHeader(TypedDict):
        name: str
        value: str

    class NmapPort(NmapServiceMatch, total=False):
        protocol: str
        port: int
        state_state: str
        state_reason: str
        state_reason_ttl: int
        scripts: list[NmapScript]
        screendata: bytes
        screenwords: list[str]
        screenshot: str

    class NmapHostname(TypedDict):
        type: str
        name: str
        domains: list[str]

    # TODO
    # class NmapHost(TypedDict, total=False):
    #     addr: str
    #     addresses: list[NmapAddress]
    #     hostnames: list[NmapHostname]
    #     ports: list[NmapPort]
    #     state: str
    #     tags: list[Tag]


else:
    HttpHeader = dict[str, str]  # type: ignore
    NmapPort = dict[str, str | int | list[NmapScript] | bytes | list[str]]  # type: ignore
    NmapHostname = dict[str, str | list[str]]  # type: ignore
    # NmapHost = dict[str, Any]  # type: ignore
