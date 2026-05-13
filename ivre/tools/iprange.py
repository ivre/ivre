#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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


"""Enumerate the IP addresses matching a selector (country, AS,
network, range, or all routable IPs).

The country / AS / region / city selectors are backed by the
MaxMind GeoIP CSV dumps populated by ``ivre ipdata --download``;
the routable selector is backed by the APNIC BGP dump shipped
alongside.  The ``--network`` / ``--range`` / ``--file`` selectors
are pure arithmetic and need no external data.

The output can be just the count, the matching CIDRs, the
matching start-stop ranges, or every individual address (capped
for safety).
"""

import argparse
import functools
import json
import os
import sys
from collections.abc import Iterable, Iterator
from typing import Any, TextIO

from ivre import config, geoiputils, utils

# Hard ceiling on ``--addrs`` output to avoid accidental
# multi-gigabyte stdout floods (``--routable --addrs`` would
# print ~3.7 billion lines without it).  Users can lift the cap
# with ``--force``.
_DEFAULT_ADDRS_CAP = 1_000_000

# Output format identifiers; kept as module-level constants so the
# CLI, the web route and the MCP tool agree on the valid set.
OUTPUT_COUNT = "count"
OUTPUT_RANGES = "ranges"
OUTPUT_CIDRS = "cidrs"
OUTPUT_ADDRS = "addrs"
OUTPUT_JSON = "json"
OUTPUT_FORMATS = (OUTPUT_COUNT, OUTPUT_RANGES, OUTPUT_CIDRS, OUTPUT_ADDRS, OUTPUT_JSON)


class IPRangeError(ValueError):
    """Raised on invalid selector / output / GeoIP-state
    combinations.

    The web route and the MCP tool catch this and map it to a
    400 / structured error response; the CLI prints the message
    to stderr and exits with status 1.
    """


def _normalise_asnum(value: str) -> int:
    """Accept ``AS3215`` or ``3215``; raise on anything else."""
    value = value.strip()
    if value.upper().startswith("AS"):
        value = value[2:]
    try:
        return int(value)
    except ValueError as exc:
        raise IPRangeError(f"invalid AS number {value!r}") from exc


def _split_csv(value: str) -> list[str]:
    """Split a ``"FR,DE"`` / ``"FR, DE"`` argument into a list of
    non-empty stripped tokens.
    """
    return [tok for tok in (t.strip() for t in value.split(",")) if tok]


def _require_geoip() -> None:
    """Pre-check ``config.GEOIP_PATH`` for the GeoIP-backed
    selectors so callers get a friendly :class:`IPRangeError`
    instead of an ``AssertionError`` from
    :func:`geoiputils._get_by_data`.
    """
    if config.GEOIP_PATH is None:
        raise IPRangeError(
            "GeoIP data is not configured (GEOIP_PATH is unset); "
            "run ``ivre ipdata --download`` first"
        )
    if not os.path.isdir(config.GEOIP_PATH):
        raise IPRangeError(
            f"GeoIP data directory {config.GEOIP_PATH!r} does not exist; "
            "run ``ivre ipdata --download`` first"
        )


def _ranges_from_file(path: str) -> geoiputils.IPRanges:
    """Parse a line-oriented file of IPs / CIDRs / ranges into a
    single :class:`~ivre.geoiputils.IPRanges` instance.

    Recognised line shapes (``#`` introduces an end-of-line
    comment; blank lines are skipped):

    * ``192.0.2.0`` -- single address (range of size 1).
    * ``192.0.2.0/24`` -- CIDR network.
    * ``192.0.2.0-192.0.2.255`` -- explicit range.
    """
    res = geoiputils.IPRanges()
    with open(path, encoding="utf-8") as fdesc:
        for lineno, raw in enumerate(fdesc, start=1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                if "/" in line:
                    start, stop = utils.net2range(line)
                elif "-" in line:
                    start, stop = (tok.strip() for tok in line.split("-", 1))
                else:
                    start = stop = line
                res.append(utils.ip2int(start), utils.ip2int(stop))
            except (ValueError, OSError) as exc:
                raise IPRangeError(
                    f"{path}:{lineno}: cannot parse {line!r} ({exc})"
                ) from exc
    return res


def _union(parts: Iterable[geoiputils.IPRanges]) -> geoiputils.IPRanges:
    """Merge an iterable of :class:`IPRanges`; raises
    :class:`IPRangeError` when the iterable is empty (covers the
    ``--country FR,XX`` case with an unknown alias yielding zero
    tokens).
    """
    parts = list(parts)
    if not parts:
        raise IPRangeError("selector resolved to an empty set of values")
    return functools.reduce(lambda a, b: a.union(b), parts[1:], parts[0])


def select_ipranges(
    *,
    country: str | None = None,
    registered_country: str | None = None,
    region: tuple[str, str] | None = None,
    city: tuple[str, str] | None = None,
    asnum: str | None = None,
    address_range: tuple[str, str] | None = None,
    network: str | None = None,
    routable: bool = False,
    file: str | None = None,
) -> geoiputils.IPRanges:
    """Resolve exactly one selector into a
    :class:`~ivre.geoiputils.IPRanges` instance.

    ``country`` / ``registered_country`` / ``asnum`` accept a
    single value or a comma-separated list (``"FR,DE"`` /
    ``"AS3215, AS12876"``).  Multi-value selectors compose via
    :meth:`IPRanges.union`.

    Raises :class:`IPRangeError` when zero or multiple selectors
    are set, on malformed inputs, or when a GeoIP-backed selector
    is invoked without :data:`config.GEOIP_PATH` configured.
    """
    selectors = {
        "country": country,
        "registered_country": registered_country,
        "region": region,
        "city": city,
        "asnum": asnum,
        "range": address_range,
        "network": network,
        "routable": routable or None,
        "file": file,
    }
    set_selectors = [name for name, value in selectors.items() if value]
    if not set_selectors:
        raise IPRangeError(
            "exactly one selector is required: country / "
            "registered-country / region / city / asnum / range / "
            "network / routable / file"
        )
    if len(set_selectors) > 1:
        raise IPRangeError(
            f"selectors are mutually exclusive ({', '.join(set_selectors)})"
        )

    if country is not None:
        _require_geoip()
        codes = utils.country_unalias(_split_csv(country))
        if isinstance(codes, str):
            codes = [codes]
        return _union(geoiputils.get_ranges_by_country(code) for code in codes)
    if registered_country is not None:
        _require_geoip()
        codes = utils.country_unalias(_split_csv(registered_country))
        if isinstance(codes, str):
            codes = [codes]
        return _union(
            geoiputils.get_ranges_by_registered_country(code) for code in codes
        )
    if region is not None:
        _require_geoip()
        cc, rc = region
        return geoiputils.get_ranges_by_region(cc, rc)
    if city is not None:
        _require_geoip()
        cc, name = city
        return geoiputils.get_ranges_by_city(cc, name)
    if asnum is not None:
        _require_geoip()
        return _union(
            geoiputils.get_ranges_by_asnum(_normalise_asnum(tok))
            for tok in _split_csv(asnum)
        )
    if address_range is not None:
        start, stop = address_range
        try:
            start_int = utils.ip2int(start)
            stop_int = utils.ip2int(stop)
        except (ValueError, OSError) as exc:
            raise IPRangeError(f"invalid range {start!r}-{stop!r} ({exc})") from exc
        if stop_int < start_int:
            raise IPRangeError(f"range {start!r}-{stop!r} is empty (stop < start)")
        return geoiputils.IPRanges(ranges=[(start_int, stop_int)])
    if network is not None:
        try:
            start, stop = utils.net2range(network)
        except (ValueError, OSError) as exc:
            raise IPRangeError(f"invalid network {network!r} ({exc})") from exc
        return geoiputils.IPRanges(ranges=[(utils.ip2int(start), utils.ip2int(stop))])
    if routable:
        _require_geoip()
        return geoiputils.get_routable_ranges()
    if file is not None:
        return _ranges_from_file(file)
    # Unreachable: the selector dispatch above is exhaustive over
    # the set of truthy entries in ``selectors``.
    raise IPRangeError("unreachable: selector dispatch fell through")


def _iter_limited(items: Iterable[str], limit: int | None) -> Iterator[str]:
    """Yield at most ``limit`` items from ``items``; pass-through
    when ``limit`` is None.
    """
    if limit is None:
        yield from items
        return
    for index, value in enumerate(items):
        if index >= limit:
            return
        yield value


def format_ipranges(
    ranges: geoiputils.IPRanges,
    output: str,
    *,
    limit: int | None = None,
    addrs_cap: int | None = _DEFAULT_ADDRS_CAP,
) -> dict[str, Any]:
    """Render ``ranges`` according to the ``output`` mode.

    Returns a dict whose ``"value"`` entry is the rendered
    payload (an ``int`` for ``count``, a ``list[str]`` for
    ``cidrs`` / ``addrs``, a ``list[list[str]]`` for ``ranges``)
    plus a ``"count"`` field always carrying the underlying IP
    count.  For ``output="json"`` the ``"value"`` entry mirrors
    the full structured response surfaced by the web route /
    MCP tool.

    ``addrs_cap`` bounds the ``addrs`` output; ``None`` disables
    the cap (the CLI ``--force`` flag passes ``None`` through).
    Exceeded caps raise :class:`IPRangeError`.
    """
    if output not in OUTPUT_FORMATS:
        raise IPRangeError(
            f"invalid output mode {output!r}; expected one of "
            f"{', '.join(OUTPUT_FORMATS)}"
        )
    count = len(ranges)
    if output == OUTPUT_COUNT:
        return {"count": count, "value": count}
    if output == OUTPUT_RANGES:
        pairs = [[start, stop] for start, stop in ranges.iter_ranges()]
        if limit is not None:
            pairs = pairs[:limit]
        return {"count": count, "value": pairs}
    if output == OUTPUT_CIDRS:
        cidrs = list(_iter_limited(ranges.iter_nets(), limit))
        return {"count": count, "value": cidrs}
    if output == OUTPUT_ADDRS:
        effective_cap = count if addrs_cap is None else min(count, addrs_cap)
        if (
            addrs_cap is not None
            and count > addrs_cap
            and (limit is None or limit > addrs_cap)
        ):
            raise IPRangeError(
                f"refusing to enumerate {count} addresses (> cap {addrs_cap}); "
                f"raise the cap or pick a narrower selector"
            )
        effective_limit = effective_cap if limit is None else min(limit, effective_cap)
        addrs = list(_iter_limited(ranges.iter_addrs(), effective_limit))
        return {"count": count, "value": addrs}
    # OUTPUT_JSON: the structured response surfaced by the web
    # route / MCP tool.  Skips ``addrs`` (subject to the cap) so
    # JSON callers opt in via ``output="addrs"`` explicitly.
    pairs = [[start, stop] for start, stop in ranges.iter_ranges()]
    cidrs = list(ranges.iter_nets())
    if limit is not None:
        pairs = pairs[:limit]
        cidrs = cidrs[:limit]
    payload = {"count": count, "ranges": pairs, "cidrs": cidrs}
    return {"count": count, "value": payload}


def _print_value(value: Any, stream: TextIO) -> None:
    """Render the formatted ``"value"`` payload on ``stream``."""
    if isinstance(value, int):
        print(value, file=stream)
        return
    if isinstance(value, dict):
        json.dump(value, stream)
        stream.write("\n")
        return
    for item in value:
        if isinstance(item, list):
            print(f"{item[0]}-{item[1]}", file=stream)
        else:
            print(item, file=stream)


def _build_argparser() -> argparse.ArgumentParser:
    """Construct the ``ivre iprange`` argparser.

    Selectors and output formats use mutually-exclusive groups so
    conflicting flags fail fast at parse time rather than
    surfacing later as an :class:`IPRangeError`.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    selectors = parser.add_mutually_exclusive_group(required=True)
    selectors.add_argument(
        "--country",
        "-c",
        metavar="CODE[,CODE...]",
        help="select IPs registered in this country (ISO 3166-1 alpha-2)",
    )
    selectors.add_argument(
        "--registered-country",
        metavar="CODE[,CODE...]",
        help="select IPs registered (not assigned) in this country",
    )
    selectors.add_argument(
        "--region",
        nargs=2,
        metavar=("COUNTRY_CODE", "REGION_CODE"),
        help="select IPs in this region",
    )
    selectors.add_argument(
        "--city",
        nargs=2,
        metavar=("COUNTRY_CODE", "CITY"),
        help="select IPs in this city",
    )
    selectors.add_argument(
        "--asnum",
        "-a",
        metavar="AS[,AS...]",
        help="select IPs in this autonomous system "
        "(accepts ``ASnnnn`` or bare integers)",
    )
    selectors.add_argument(
        "--range",
        nargs=2,
        metavar=("START", "STOP"),
        help="select an explicit address range",
    )
    selectors.add_argument(
        "--network", "-n", metavar="NET/MASK", help="select a CIDR network"
    )
    selectors.add_argument(
        "--routable",
        action="store_true",
        help="select every routable IP (from the APNIC BGP dump)",
    )
    selectors.add_argument(
        "--file",
        "-f",
        metavar="FILENAME",
        help="read IPs / CIDRs / ranges from a file (one per line, "
        "``#`` introduces a comment)",
    )
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument(
        "--cidrs",
        dest="output",
        action="store_const",
        const=OUTPUT_CIDRS,
        help="print one CIDR per line (default)",
    )
    outputs.add_argument(
        "--ranges",
        "-r",
        dest="output",
        action="store_const",
        const=OUTPUT_RANGES,
        help="print one ``start-stop`` range per line",
    )
    outputs.add_argument(
        "--count",
        dest="output",
        action="store_const",
        const=OUTPUT_COUNT,
        help="print just the IP count",
    )
    outputs.add_argument(
        "--addrs",
        dest="output",
        action="store_const",
        const=OUTPUT_ADDRS,
        help=f"print every address on its own line (capped at "
        f"{_DEFAULT_ADDRS_CAP} unless ``--force`` is set)",
    )
    outputs.add_argument(
        "--json",
        "-j",
        dest="output",
        action="store_const",
        const=OUTPUT_JSON,
        help="print a JSON object with ``count``, ``ranges`` and ``cidrs``",
    )
    parser.set_defaults(output=OUTPUT_CIDRS)
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        metavar="N",
        help="cap the output to the first ``N`` ranges / cidrs / addresses "
        "(``--count`` ignores this)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=f"lift the {_DEFAULT_ADDRS_CAP}-address safety cap on ``--addrs``",
    )
    return parser


def main() -> None:
    args = _build_argparser().parse_args()
    try:
        ranges = select_ipranges(
            country=args.country,
            registered_country=args.registered_country,
            region=tuple(args.region) if args.region else None,
            city=tuple(args.city) if args.city else None,
            asnum=args.asnum,
            address_range=tuple(args.range) if args.range else None,
            network=args.network,
            routable=args.routable,
            file=args.file,
        )
        result = format_ipranges(
            ranges,
            args.output,
            limit=args.limit,
            addrs_cap=None if args.force else _DEFAULT_ADDRS_CAP,
        )
    except IPRangeError as exc:
        utils.LOGGER.error("%s", exc)
        sys.exit(1)
    _print_value(result["value"], sys.stdout)


# Re-export for callers (web / MCP) that wrap the helpers but do
# not need the argparser; keeping the surface explicit reduces
# the risk of accidental coupling to the CLI internals.
__all__ = [
    "IPRangeError",
    "OUTPUT_ADDRS",
    "OUTPUT_CIDRS",
    "OUTPUT_COUNT",
    "OUTPUT_FORMATS",
    "OUTPUT_JSON",
    "OUTPUT_RANGES",
    "format_ipranges",
    "main",
    "select_ipranges",
]
