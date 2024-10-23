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

"""This submodule contains functions to handle tags.

"""


import os
from bisect import bisect_left
from collections.abc import Callable, Generator, Iterable
from typing import (
    Any,
    TypeVar,
    cast,
)

from ivre.config import DATA_PATH
from ivre.plugins import load_plugins
from ivre.types import Tag
from ivre.utils import LOGGER, get_addr_type, ip2int, make_range_tables, net2range

TAG_CDN: Tag = {"value": "CDN", "type": "info"}
TAG_GOVCLOUD: Tag = {"value": "GovCloud", "type": "info"}
TAG_DEFAULT_PASSWORD: Tag = {"value": "Default password", "type": "danger"}
TAG_HONEYPOT: Tag = {"value": "Honeypot", "type": "warning"}
TAG_MALWARE: Tag = {"value": "Malware", "type": "danger"}
TAG_RESERVED: Tag = {"value": "Reserved address", "type": "info"}
TAG_SCANNER: Tag = {"value": "Scanner", "type": "warning"}
TAG_TOR: Tag = {"value": "TOR", "type": "info"}
TAG_VULN: Tag = {"value": "Vulnerable", "type": "danger"}
TAG_VULN_LIKELY: Tag = {"value": "Likely vulnerable", "type": "warning"}
TAG_VULN_CANNOT_TEST: Tag = {"value": "Cannot test vuln", "type": "info"}


_TOR_NODES: set[str] | None = None
_CDN_TABLE: tuple[list[int], list[tuple[str, str] | None]] | None = None
_GOVCLOUD_TABLE: tuple[list[int], list[list[str] | None]] | None = None
_SCANNERS_TABLE: tuple[list[int], list[str | None]] | None = None


TAGS_GENERATOR_PLUGINS_ADDR: list[Callable[[str], Generator[Tag, None, None]]] = []
TAGS_GENERATOR_PLUGINS_HOSTNAME: list[Callable[[str], Generator[Tag, None, None]]] = []


def _get_data() -> None:
    global _TOR_NODES, _SCANNERS_TABLE, _CDN_TABLE, _GOVCLOUD_TABLE
    assert DATA_PATH is not None
    if _TOR_NODES is None:
        try:
            with open(
                os.path.join(DATA_PATH, "tor_exit_nodes.txt"), encoding="utf8"
            ) as fdesc:
                _TOR_NODES = {line.strip() for line in fdesc}
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [tor_exit_nodes.txt]. Try running `ivre getwebdata`"
            )
            _TOR_NODES = set()
    if _SCANNERS_TABLE is None:
        ranges: list[tuple[str, str, str]] = []
        try:
            with open(
                os.path.join(DATA_PATH, "ssigouvfr_scanners.txt"), encoding="utf8"
            ) as fdesc:
                ranges.extend(
                    (addr, addr, "ANSSI") for addr in (line.strip() for line in fdesc)
                )
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [ssigouvfr_scanners.txt]. Try running `ivre getwebdata`"
            )
        try:
            with open(
                os.path.join(DATA_PATH, "ukncsc_scanners.txt"), encoding="utf8"
            ) as fdesc:
                ranges.extend(
                    (addr, addr, "UK-NCSC") for addr in (line.strip() for line in fdesc)
                )
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [ukncsc_scanners.txt]. Try running `ivre getwebdata`"
            )
        try:
            with open(
                os.path.join(DATA_PATH, "censys_scanners.txt"), encoding="utf8"
            ) as fdesc:
                ranges.extend(net2range(line.strip()) + ("Censys",) for line in fdesc)
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [censys_scanners.txt]. Try running `ivre getwebdata`"
            )
        parsed_ranges = make_range_tables(ranges)
        _SCANNERS_TABLE = (
            [elt[0] for elt in parsed_ranges],
            [elt[1] for elt in parsed_ranges],
        )
    if _CDN_TABLE is None:
        try:
            with open(
                os.path.join(DATA_PATH, "cdn_nuclei.py"), encoding="utf8"
            ) as fdesc:
                # pylint: disable=eval-used
                _CDN_TABLE = eval(compile(fdesc.read(), "cdn_nuclei", "eval"))
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [cdn_nuclei.py]. Try running `ivre getwebdata`"
            )
            _CDN_TABLE = ([], [])
    if _GOVCLOUD_TABLE is None:
        try:
            with open(os.path.join(DATA_PATH, "govcloud.py"), encoding="utf8") as fdesc:
                # pylint: disable=eval-used
                _GOVCLOUD_TABLE = eval(compile(fdesc.read(), "gov_cloud", "eval"))
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [govcloud.py]. Try running `ivre getwebdata`"
            )
            _GOVCLOUD_TABLE = ([], [])


T = TypeVar("T")


def _get_name(table: tuple[list[int], list[T | None]], addr: str) -> T | None:
    """Devs: please make sure _get_data() has been called before calling me!"""
    addr_i = ip2int(addr) if ":" in addr else ip2int(f"::ffff:{addr}")
    try:
        return table[1][bisect_left(table[0], addr_i)]
    except IndexError:
        return None


def _prepare_tag(tag: dict[str, Any]) -> dict[str, Any]:
    """This function uses a set() for the "info" value, while a list() is
    used to store it. It is used in add_tags().

    """
    if "info" in tag:
        tag["info"] = set(tag["info"])
    return tag


def _clean_tag(tag: dict[str, Any]) -> dict[str, Any]:
    """This function is the opposite of `_prepare_tag()`. It is used in
    add_tags().

    """
    if "info" in tag:
        tag["info"] = sorted(tag["info"])
    return tag


def add_tags(record: dict[str, Any], tags: Iterable[Tag]) -> None:
    """This function sets or update the "tags" attribute in `record` by
    adding or updating the provided `tags`.

    """
    cur_tags = {tag["value"]: _prepare_tag(tag) for tag in record.get("tags", [])}
    for tag in tags:
        cur_tag = cur_tags.setdefault(
            tag["value"], {"value": tag["value"], "type": tag["type"]}
        )
        if "info" in tag:
            cur_tag.setdefault("info", set()).update(tag["info"])
    if cur_tags:
        record["tags"] = [_clean_tag(cur_tags[key]) for key in sorted(cur_tags)]


def gen_addr_tags(addr: str) -> Generator[Tag, None, None]:
    """This function generates the automatically-generated tags based
    on an IP address.

    """
    _get_data()
    assert _TOR_NODES is not None
    assert _SCANNERS_TABLE is not None
    assert _CDN_TABLE is not None
    assert _GOVCLOUD_TABLE is not None
    for plugin in TAGS_GENERATOR_PLUGINS_ADDR:
        yield from plugin(addr)
    if isinstance(addr, str):
        if addr in _TOR_NODES:
            yield cast(
                Tag,
                dict(
                    TAG_TOR,
                    info=[
                        "Exit node listed at <https://check.torproject.org/torbulkexitlist>"
                    ],
                ),
            )
        cdn_type_name = _get_name(_CDN_TABLE, addr)
        if cdn_type_name is not None:
            cdn_type, cdn_name = cdn_type_name
            yield cast(
                Tag,
                dict(
                    TAG_CDN,
                    value=cdn_type.upper(),
                    info=[f"{cdn_name} as listed by cdncheck (projectdiscovery)"],
                ),
            )
        govcloud_data = _get_name(_GOVCLOUD_TABLE, addr)
        if govcloud_data is not None:
            yield cast(
                Tag,
                dict(
                    TAG_GOVCLOUD,
                    info=govcloud_data,
                ),
            )
        scanner_name = _get_name(_SCANNERS_TABLE, addr)
        if scanner_name is not None:
            yield cast(
                Tag,
                dict(
                    TAG_SCANNER,
                    info=[f"Listed as a {scanner_name} scanner"],
                ),
            )
        addr_type = get_addr_type(addr)
        if addr_type is not None:
            yield cast(
                Tag,
                dict(
                    TAG_RESERVED,
                    info=[f"Address type {addr_type}"],
                ),
            )


def gen_hostname_tags(hostname: str) -> Generator[Tag, None, None]:
    """This function generates the automatically-generated tags based
    on a hostname.

    """
    for plugin in TAGS_GENERATOR_PLUGINS_HOSTNAME:
        yield from plugin(hostname)
    if hostname.endswith(".shodan.io") and "census" in hostname:
        yield cast(
            Tag,
            dict(
                TAG_SCANNER,
                info=[f"Hostname {hostname} suggests a Shodan scanner"],
            ),
        )
    elif hostname.endswith(".binaryedge.ninja"):
        yield cast(
            Tag,
            dict(
                TAG_SCANNER,
                info=[f"Hostname {hostname} suggests a BinaryEdge scanner"],
            ),
        )
    elif hostname.endswith(".probe.onyphe.net"):
        yield cast(
            Tag,
            dict(
                TAG_SCANNER,
                info=[f"Hostname {hostname} suggests an Onyphe scanner"],
            ),
        )


load_plugins("ivre.plugins.tags", globals())
