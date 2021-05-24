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
Specific type definitions for IVRE
"""


from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

try:
    from typing import TypedDict
except ImportError:
    HAS_TYPED_DICT = False
else:
    HAS_TYPED_DICT = True


NmapProbe = List[Tuple[str, Dict[str, Any]]]

if HAS_TYPED_DICT:

    class CpeDict(TypedDict, total=False):
        type: str
        vendor: str
        product: str
        version: str
        origins: Set[str]

    class NmapProbeRec(TypedDict, total=False):
        probe: bytes
        fp: NmapProbe
        fallbacks: List[str]

    class NmapServiceMatch(TypedDict, total=False):
        service_name: str
        service_product: str
        service_version: str
        service_devicetype: str
        service_extrainfo: str
        service_hostname: str
        service_ostype: str
        service_tunnel: str
        cpe: List[str]
        soft: bool

    class NmapScanTemplate(TypedDict, total=False):
        nmap: str
        pings: str
        scans: str
        osdetect: bool
        traceroute: bool
        resolve: int
        verbosity: int
        ports: Optional[str]
        top_ports: Optional[int]
        host_timeout: Optional[str]
        script_timeout: Optional[str]
        scripts_categories: Optional[Iterable[str]]
        scripts_exclude: Optional[Iterable[str]]
        scripts_force: Optional[Iterable[str]]
        extra_options: Optional[Iterable[str]]


else:
    CpeDict = Dict[str, Union[str, Set[str]]]  # type: ignore
    NmapProbeRec = Dict[str, Union[bytes, NmapProbe, List[str]]]  # type: ignore
    NmapServiceMatch = Dict[str, Union[str, List[str]]]  # type: ignore
    NmapScanTemplate = Dict[  # type: ignore
        str,
        Union[str, bool, int, Optional[str], Optional[int], Optional[Iterable[str]]],
    ]
