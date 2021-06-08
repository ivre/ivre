#! /usr/bin/env python
# -*- coding: utf-8 -*-

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


"""
Specific type definitions for IVRE (active)
"""


from typing import Any, Dict, List, Union

try:
    from typing import TypedDict
except ImportError:
    HAS_TYPED_DICT = False
else:
    HAS_TYPED_DICT = True


from ivre.types import NmapServiceMatch


NmapHost = Dict[str, Any]  # TODO (see below)
NmapAddress = Dict[str, Any]  # TODO & TO FIX...
NmapScript = Dict[str, Any]  # seems hard to do better for now (lots of keys)


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
        scripts: List[NmapScript]
        screendata: bytes
        screenwords: List[str]
        screenshot: str

    class NmapHostname(TypedDict):
        type: str
        name: str
        domains: List[str]

    # TODO
    # class NmapHost(TypedDict, total=False):
    #     addr: str
    #     addresses: List[NmapAddress]
    #     hostnames: List[NmapHostname]
    #     ports: List[NmapPort]
    #     state: str


else:
    HttpHeader = Dict[str, str]  # type: ignore
    NmapPort = Dict[str, Union[str, int, List[NmapScript], bytes, List[str]]]  # type: ignore
    NmapHostname = Dict[str, Union[str, List[str]]]  # type: ignore
    # NmapHost = Dict[str, Any]  # type: ignore
