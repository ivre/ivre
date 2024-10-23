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
Specific type definitions for IVRE
"""

from __future__ import annotations

from collections.abc import Generator, Iterable
from typing import Any

try:
    from typing import Literal, Protocol, TypedDict
except ImportError:
    HAS_TYPED_DICT = False
else:
    HAS_TYPED_DICT = True


NmapProbe = list[tuple[str, dict[str, Any]]]
ParsedCertificate = dict[str, Any]  # TODO: TypedDict


# Filters

MongoFilter = dict[str, Any]  # TODO: TypedDict
# TODO
ElasticFilter = Any
HttpFilter = Any
SqlFilter = Any
TinyFilter = Any
Filter = MongoFilter | SqlFilter | HttpFilter | ElasticFilter | TinyFilter


# Records (TODO)
Record = dict[str, Any]


# Sort
if HAS_TYPED_DICT:
    SortKey = tuple[str, Literal[-1, 1]]
    IndexKey = tuple[str, Literal[-1, 1, "text"]]
else:
    SortKey = tuple[str, int]  # type: ignore
    IndexKey = tuple[str, int | str]  # type: ignore
Sort = Iterable[SortKey]


# DB objects

DBCursor = Generator[Record, None, None]


if HAS_TYPED_DICT:

    class CpeDict(TypedDict, total=False):
        type: str
        vendor: str
        product: str
        version: str
        origins: set[str]

    # class ParsedCertificate(TypedDict, total=False):
    #     TODO

    class Tag(TypedDict, total=False):
        value: str
        type: str
        info: list[str]

    class NmapProbeRec(TypedDict, total=False):
        probe: bytes
        fp: NmapProbe
        fallbacks: list[str]

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
        cpe: list[str]
        soft: bool

    class NmapScanTemplate(TypedDict, total=False):
        nmap: str
        pings: str
        scans: str
        osdetect: bool
        traceroute: bool
        resolve: int
        verbosity: int
        ports: str | None
        top_ports: int | None
        host_timeout: str | None
        script_timeout: str | None
        scripts_categories: Iterable[str] | None
        scripts_exclude: Iterable[str] | None
        scripts_force: Iterable[str] | None
        extra_options: Iterable[str] | None

    class DB(Protocol):
        flt_empty: Filter

        def distinct(
            self,
            field: str,
            flt: Filter | None = None,
            sort: Any | None = None,
            limit: int | None = None,
            skip: int | None = None,
        ) -> Iterable: ...

        @classmethod
        def flt_and(cls, *args: Filter) -> Filter: ...

        def from_binary(self, data: Any) -> bytes: ...

        def get(self, spec: Filter, **kargs: Any) -> Generator[Record, None, None]: ...

        def _get(self, spec: Filter, **kargs: Any) -> DBCursor: ...

        def explain(self, cur: DBCursor, **kargs: Any) -> str: ...

        def remove_many(self, spec: Filter) -> None: ...

        def searchcert(
            self,
            keytype: str | None = None,
            md5: str | None = None,
            sha1: str | None = None,
            sha256: str | None = None,
            subject: str | None = None,
            issuer: str | None = None,
            self_signed: bool | None = None,
            pkmd5: str | None = None,
            pksha1: str | None = None,
            pksha256: str | None = None,
            cacert: bool = False,
        ) -> Filter: ...

        @staticmethod
        def serialize(obj: Any) -> str: ...

    class DBAgent(DB, Protocol):
        pass

    class DBData(DB, Protocol):
        pass

    class DBFlow(DB, Protocol):
        pass

    class DBActive(DB, Protocol):
        def searchsshkey(
            self,
            fingerprint: str | None = None,
            key: str | None = None,
            keytype: str | None = None,
            bits: int | None = None,
            output: str | None = None,
        ) -> Filter: ...

    class DBNmap(DBActive, Protocol):
        pass

    class DBPassive(DB, Protocol):
        def searchsshkey(
            self,
            fingerprint: str | None = None,
            key: str | None = None,
            keytype: str | None = None,
            bits: int | None = None,
        ) -> Filter: ...

    class DBView(DBActive, Protocol):
        pass

    class MetaDB(Protocol):
        agent: DBAgent
        data: DBData
        db_types: dict[str, dict[str, tuple[str, str]]]
        flow: DBFlow
        nmap: DBNmap
        passive: DBPassive
        url: str
        urls: dict[str, str]
        view: DBView

        def get_class(self, purpose: str) -> DB: ...

    class Target(Iterable[int], Protocol):
        targetscount: int

else:
    CpeDict = dict[str, str | set[str]]  # type: ignore
    NmapProbeRec = dict[str, bytes | NmapProbe | list[str]]  # type: ignore
    NmapServiceMatch = dict[str, str | list[str]]  # type: ignore
    NmapScanTemplate = dict[  # type: ignore
        str,
        str | bool | int | Iterable[str] | None,
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
    Tag = dict[str, str | list[str]]  # type: ignore
