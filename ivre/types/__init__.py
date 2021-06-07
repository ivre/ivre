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


from typing import (
    Any,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

try:
    from typing import Literal, Protocol, TypedDict
except ImportError:
    HAS_TYPED_DICT = False
else:
    HAS_TYPED_DICT = True


NmapProbe = List[Tuple[str, Dict[str, Any]]]
ParsedCertificate = Dict[str, Any]  # TODO: TypedDict


# Filters

MongoFilter = Dict[str, Any]  # TODO: TypedDict
# TODO
ElasticFilter = Any
HttpFilter = Any
SqlFilter = Any
TinyFilter = Any
Filter = Union[MongoFilter, SqlFilter, HttpFilter, ElasticFilter, TinyFilter]


# Records (TODO)
Record = Dict[str, Any]


# Sort
if HAS_TYPED_DICT:
    SortKey = Tuple[str, Literal[-1, 1]]
else:
    SortKey = Tuple[str, int]  # type: ignore
Sort = Iterable[SortKey]


# DB objects

DBCursor = Generator[Record, None, None]


if HAS_TYPED_DICT:

    class CpeDict(TypedDict, total=False):
        type: str
        vendor: str
        product: str
        version: str
        origins: Set[str]

    # class ParsedCertificate(TypedDict, total=False):
    #     TODO

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
        service_method: str
        service_servicefp: str
        service_conf: int
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

    class DB(Protocol):
        flt_empty: Filter

        def distinct(
            self,
            field: str,
            flt: Optional[Filter] = None,
            sort: Optional[Any] = None,
            limit: Optional[int] = None,
            skip: Optional[int] = None,
        ) -> Iterable:
            ...

        @classmethod
        def flt_and(cls, *args: Filter) -> Filter:
            ...

        def from_binary(self, data: Any) -> bytes:
            ...

        def get(self, spec: Filter, **kargs: Any) -> Generator[Record, None, None]:
            ...

        def _get(self, spec: Filter, **kargs: Any) -> DBCursor:
            ...

        def explain(self, cur: DBCursor, **kargs: Any) -> str:
            ...

        def remove_many(self, spec: Filter) -> None:
            ...

        def searchcert(
            self,
            keytype: Optional[str] = None,
            md5: Optional[str] = None,
            sha1: Optional[str] = None,
            sha256: Optional[str] = None,
            subject: Optional[str] = None,
            issuer: Optional[str] = None,
            self_signed: Optional[bool] = None,
            pkmd5: Optional[str] = None,
            pksha1: Optional[str] = None,
            pksha256: Optional[str] = None,
            cacert: bool = False,
        ) -> Filter:
            ...

        @staticmethod
        def serialize(obj: Any) -> str:
            ...

    class DBAgent(DB, Protocol):
        pass

    class DBData(DB, Protocol):
        pass

    class DBFlow(DB, Protocol):
        pass

    class DBActive(DB, Protocol):
        def searchsshkey(
            self,
            fingerprint: Optional[str] = None,
            key: Optional[str] = None,
            keytype: Optional[str] = None,
            bits: Optional[int] = None,
            output: Optional[str] = None,
        ) -> Filter:
            ...

    class DBNmap(DBActive, Protocol):
        pass

    class DBPassive(DB, Protocol):
        def searchsshkey(self, keytype: Optional[str] = None) -> Filter:
            ...

    class DBView(DBActive, Protocol):
        pass

    class MetaDB(Protocol):
        agent: DBAgent
        data: DBData
        db_types: Dict[str, Dict[str, Tuple[str, str]]]
        flow: DBFlow
        nmap: DBNmap
        passive: DBPassive
        url: str
        urls: Dict[str, str]
        view: DBView

        def get_class(self, purpose: str) -> DB:
            ...

    class Target(Iterable[int], Protocol):
        targetscount: int


else:
    CpeDict = Dict[str, Union[str, Set[str]]]  # type: ignore
    NmapProbeRec = Dict[str, Union[bytes, NmapProbe, List[str]]]  # type: ignore
    NmapServiceMatch = Dict[str, Union[str, List[str]]]  # type: ignore
    NmapScanTemplate = Dict[  # type: ignore
        str,
        Union[str, bool, int, Optional[str], Optional[int], Optional[Iterable[str]]],
    ]
    DB = Any  # type: ignore
    DBAgent = Any  # type: ignore
    DBData = Any  # type: ignore
    DBFlow = Any  # type: ignore
    DBActive = Any  # type: ignore
    DBNmap = Any  # type: ignore
    DBPassive = Any  # type: ignore
    DBView = Any  # type: ignore
    MetaDB = Any  # type: ignore
    Target = Any  # type: ignore
