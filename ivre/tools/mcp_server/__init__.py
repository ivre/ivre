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


"""MCP (Model Context Protocol) server exposing IVRE to LLM agents.

Requires the ``mcp`` optional dependency (install IVRE with the
``[mcp]`` extra). The server communicates over stdio and is intended
to be launched by an MCP-capable client (Claude Code, Claude Desktop,
Cursor, OpenCode, ...).
"""

import argparse
import base64
import glob
import ipaddress
import json
import logging
import os
import re
import zlib
from typing import Any, Literal
from urllib.parse import urlparse

from ivre import config
from ivre.db import db
from ivre.db.http import HttpDBNmap, HttpDBPassive, HttpDBView, serialize
from ivre.plugins import load_plugins
from ivre.utils import _NMAP_PROBES, get_nmap_svc_fp, str2regexp
from ivre.web.utils import get_init_flt_for, parse_filter

from .schemas import SCHEMAS


class _McpErrorFallback(Exception):
    """Placeholder used when the optional ``mcp`` dependency is missing.

    The real ``mcp.shared.exceptions.McpError`` is only available when IVRE
    is installed with the ``[mcp]`` extra. We expose a distinct subclass of
    :class:`Exception` here so that code paths catching ``McpError`` remain
    structurally valid without the optional package.
    """


try:
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.fastmcp import FastMCP
    from mcp.shared.exceptions import McpError
    from mcp.types import INTERNAL_ERROR, INVALID_PARAMS, ErrorData
except ImportError as exc:  # pragma: no cover - optional dependency
    _MCP_IMPORT_ERROR: ImportError | None = exc
    FastMCP = None
    AuthSettings = None
    McpError = _McpErrorFallback
    ErrorData = None
    INVALID_PARAMS = 0
    INTERNAL_ERROR = 0
else:
    _MCP_IMPORT_ERROR = None

FilterType = str

AllPurpose = Literal["nmap", "passive", "view"]
ActivePurpose = Literal["nmap", "view"]
PassivePurpose = Literal["passive"]


def seal(flt: dict[str, Any] | list[Any]) -> str:
    return (
        base64.urlsafe_b64encode(
            zlib.compress(json.dumps(flt, default=serialize).encode())
        )
        .rstrip(b"=")
        .decode()
    )


def _unseal(token: str) -> dict[str, Any] | list[Any]:
    try:
        decoded = json.loads(
            zlib.decompress(base64.urlsafe_b64decode(token.encode() + b"=="))
        )
    except Exception as exc:
        raise McpError(
            ErrorData(code=INVALID_PARAMS, message="Invalid filter")
        ) from exc
    if isinstance(decoded, (dict, list)):
        return decoded
    raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid filter"))


_INSTRUCTIONS = (
    "IVRE is a network reconnaissance framework. Data can be queried with three "
    "purposes: 'nmap' (active scan results), 'passive' (passively collected traffic "
    "data), and 'view' (a consolidated, deduplicated merge of nmap and passive). "
    "Always prefer the 'view' purpose unless the user explicitly requests a "
    "different one or the needed data is only available in 'nmap' or 'passive'.\n\n"
    "IMPORTANT: Filters are opaque values. Always use the filter-building tools "
    "(searchnet, searchhost, searchcountry, searchport, etc.) to create filters, "
    "and flt_and / flt_or to combine them. Never manually construct, modify, or "
    "guess the internal structure of filter objects.\n\n"
    "When exploring a scope or answering broad security questions, read the "
    "ivre://guides/scope-discovery resource first for recommended steps.\n\n"
    "IMPORTANT: For topvalues(), always use the field aliases documented in "
    "that tool's description (e.g. 'product:ssh', 'product:22', "
    "'version:ssh:OpenSSH') rather than raw document paths from "
    "describe_schema(). Raw paths like 'ports.service_product' aggregate "
    "across all ports and produce misleading mixed-service results."
)


def _build_server(**fastmcp_kwargs: Any) -> Any:
    """Build a :class:`FastMCP` instance with the IVRE tools registered.

    Extra keyword arguments are forwarded to :class:`FastMCP` (e.g. to
    enable HTTP auth or to configure the Streamable-HTTP transport).
    """
    global mcp  # noqa: PLW0603
    mcp = FastMCP("ivre", instructions=_INSTRUCTIONS, **fastmcp_kwargs)
    _register_tools()
    load_plugins("ivre.plugins.mcp_server", globals())
    return mcp


mcp: Any = None  # populated by _build_server() at startup time

_DUMMY_URL = urlparse("http://127.0.0.1")

HTTP_DB = {
    "nmap": HttpDBNmap(_DUMMY_URL),
    "passive": HttpDBPassive(_DUMMY_URL),
    "view": HttpDBView(_DUMMY_URL),
}

REAL_DB = {
    "nmap": db.nmap,
    "passive": db.passive,
    "view": db.view,
}


def _parse(purpose: str, flt: FilterType | None) -> Any:
    real = REAL_DB[purpose]
    # Resolve the authenticated user (HTTP transport only; None on stdio).
    from .auth import current_user_email  # pylint: disable=import-outside-toplevel

    user = current_user_email()
    # Enforce authentication when WEB_AUTH_ENABLED is set and the call
    # arrives over an HTTP transport (i.e. auth context is expected).
    if config.WEB_AUTH_ENABLED and _HTTP_AUTH_REQUIRED and user is None:
        raise McpError(
            ErrorData(code=INVALID_PARAMS, message="Authentication required")
        )
    base_flt = get_init_flt_for(user, real)
    if flt is None:
        return base_flt
    raw = _unseal(flt)
    try:
        return real.flt_and(base_flt, parse_filter(real, raw))
    except ValueError as exc:
        raise McpError(ErrorData(code=INVALID_PARAMS, message=str(exc))) from exc


def _parse_sort(sort_list: list[str] | None) -> list[tuple[str, int]] | None:
    if not sort_list:
        return None
    result: list[tuple[str, int]] = []
    for field in sort_list:
        if field.startswith("-"):
            result.append((field[1:], -1))
        else:
            result.append((field, 1))
    return result


def _register_tools() -> None:
    """Register all MCP tools and resources on the module-level ``mcp``.

    Called from :func:`main` after verifying that the ``mcp`` package is
    importable. Keeping the decorators inside a function lets the module
    import cleanly when the optional ``[mcp]`` dependency is not installed.
    """

    # --- Filter combinators ---

    @mcp.tool()
    def flt_and(purpose: AllPurpose, flt1: FilterType, flt2: FilterType) -> FilterType:
        """Combine two filters with a logical AND."""
        return seal(HTTP_DB[purpose].flt_and(_unseal(flt1), _unseal(flt2)))

    @mcp.tool()
    def flt_or(purpose: AllPurpose, flt1: FilterType, flt2: FilterType) -> FilterType:
        """Combine two filters with a logical OR."""
        return seal(HTTP_DB[purpose].flt_or(_unseal(flt1), _unseal(flt2)))

    @mcp.tool()
    def flt_empty(purpose: AllPurpose) -> FilterType:
        """Return the empty filter (matches all records)."""
        return seal(HTTP_DB[purpose].flt_empty)

    # --- Filter construction: Host / Network ---

    @mcp.tool()
    def searchnet(purpose: AllPurpose, net: str) -> FilterType:
        """Filter records whose address belongs to a network (CIDR) or equals a host."""
        return seal(HTTP_DB[purpose].searchnet(net))

    @mcp.tool()
    def searchhost(purpose: AllPurpose, host: str) -> FilterType:
        """Filter records for an exact host address."""
        return seal(HTTP_DB[purpose].searchhost(host))

    @mcp.tool()
    def searchhostname(purpose: AllPurpose, hostname: str) -> FilterType:
        """Filter records matching a hostname (exact or "/regex/")."""
        return seal(HTTP_DB[purpose].searchhostname(str2regexp(hostname)))

    @mcp.tool()
    def searchdomain(purpose: AllPurpose, domain: str) -> FilterType:
        """Filter records whose hostname belongs to a domain (exact or "/regex/")."""
        return seal(HTTP_DB[purpose].searchdomain(str2regexp(domain)))

    # --- Filter construction: Port / Service ---

    @mcp.tool()
    def searchport(
        purpose: AllPurpose, port: int, protocol: Literal["tcp", "udp"] = "tcp"
    ) -> FilterType:
        """Filter records with an open port."""
        return seal(HTTP_DB[purpose].searchport(port, protocol=protocol))

    @mcp.tool()
    def searchservice(
        purpose: AllPurpose,
        service: str,
        port: int | None = None,
        protocol: Literal["tcp", "udp"] = "tcp",
    ) -> FilterType:
        """Filter records with a detected service name on any port."""
        kwargs: dict[str, int | str] = {}
        if port is not None:
            kwargs["port"] = port
            kwargs["protocol"] = protocol
        return seal(HTTP_DB[purpose].searchservice(service, **kwargs))

    @mcp.tool()
    def searchproduct(
        purpose: AllPurpose,
        product: str | None,
        version: str | None,
        service: str | None = None,
        port: int | None = None,
        protocol: Literal["tcp", "udp"] = "tcp",
    ) -> FilterType:
        """Filter records with a detected service, product and/or version.

        product, version, and service accept exact values or "/regex/" patterns.
        """
        kwargs: dict[str, Any] = {}
        if product is not None:
            kwargs["product"] = str2regexp(product)
        if version is not None:
            kwargs["version"] = str2regexp(version)
        if service is not None:
            kwargs["service"] = str2regexp(service)
        if port is not None:
            kwargs["port"] = port
        if protocol is not None:
            kwargs["protocol"] = protocol
        return seal(HTTP_DB[purpose].searchproduct(**kwargs))

    @mcp.tool()
    def searchdevicetype(purpose: ActivePurpose, devtype: str) -> FilterType:
        """Filter records by device type (exact or "/regex/")."""
        return seal(HTTP_DB[purpose].searchdevicetype(str2regexp(devtype)))

    # --- Filter construction: Geolocation / ASN ---

    @mcp.tool()
    def searchcountry(purpose: AllPurpose, country: str) -> FilterType:
        """Filter records by country code (ISO 3166-1 alpha-2)."""
        return seal(HTTP_DB[purpose].searchcountry(country))

    @mcp.tool()
    def searchasnum(purpose: AllPurpose, asnum: int | str) -> FilterType:
        """Filter records by Autonomous System number or name."""
        return seal(HTTP_DB[purpose].searchasnum(asnum))

    # --- Filter construction: OS / Script / CVE ---

    @mcp.tool()
    def searchos(purpose: ActivePurpose, os_name: str) -> FilterType:
        """Filter records by detected operating system (exact or "/regex/")."""
        return seal(HTTP_DB[purpose].searchos(str2regexp(os_name)))

    @mcp.tool()
    def searchscript(
        purpose: ActivePurpose,
        name: str | None = None,
        output: str | None = None,
    ) -> FilterType:
        """Filter records having a specific Nmap script result.

        The name and output can be exact values or regular expressions
        passed as "/expr/". Flags can be added as "/expr/i" for
        example.

        Warning: regular expressions can be expensive. Anchor patterns
        with "/^expr/" when possible. When filtering by output, also
        specify the script name to avoid scanning all script outputs.

        """
        kwargs: dict[str, Any] = {}
        if name is not None:
            kwargs["name"] = str2regexp(name)
        if output is not None:
            kwargs["output"] = str2regexp(output)
        return seal(HTTP_DB[purpose].searchscript(**kwargs))

    @mcp.tool()
    def searchcve(purpose: ActivePurpose, cve: str) -> FilterType:
        """Filter records associated with a CVE identifier.

        Matches hosts tagged "Vulnerable" whose tag info contains the given
        CVE identifier (e.g., "CVE-2022-22897"). The match is a substring
        regex against the tag info field, so passing "CVE-2022-22" will also
        match "CVE-2022-22897"; pass the full CVE identifier to narrow down.

        To find the detailed scan output for a vulnerability, use
        distinct("ports.scripts.id", flt) on the matching hosts: the
        vulnerability may have been found by different tools — an Nmap NSE
        script (many possible names) or a Nuclei template stored under a
        script ID ending in "-nuclei" (e.g., "http-nuclei").
        """
        # No IVRE backend implements a dedicated searchcve method. CVE IDs
        # are stored in the info field of the "Vulnerable" tag
        # (see ivre/tags/active.py), so we match via searchtag with a
        # CVE substring regex against tag info.
        return seal(
            HTTP_DB[purpose].searchtag(
                {"value": "Vulnerable", "info": re.compile(re.escape(cve))}
            )
        )

    # --- Filter construction: Category / Tag ---

    @mcp.tool()
    def searchcategory(purpose: ActivePurpose, category: str) -> FilterType:
        """Filter records belonging to a category (exact or "/regex/")."""
        return seal(HTTP_DB[purpose].searchcategory(str2regexp(category)))

    @mcp.tool()
    def searchtag(
        purpose: ActivePurpose,
        tag: str | None = None,
        info: str | None = None,
    ) -> FilterType:
        """Filter records by tag value, and optionally by tag info.

        IVRE automatically tags hosts based on scan results. The severity
        markers below (danger / warning / info) mirror the IVRE web UI color
        coding and are a hint for prioritizing findings -- "danger" tags are
        the ones to triage first.

        Well-known tags:

        - "Vulnerable" (danger): host has known vulnerabilities found by a scanning tool
        - "Likely vulnerable" (warning): host is likely vulnerable based on version detection
        - "Cannot test vuln" (info): vulnerability test was inconclusive
        - "Default password" (danger): a default password was detected
        - "Malware" (danger): malware detected on the host
        - "CDN" (info): host belongs to a CDN provider (e.g., Cloudflare, Akamai)
        - "CLOUD" (info): host belongs to a cloud provider (e.g., aws, gcp, azure)
        - "WAF" (info): host is behind a Web Application Firewall (e.g., cloudflare, incapsula)
        - "Organization" (info): host is associated with a known organization
        - "Scanner" (warning): host is a known scanner (Shodan, Censys, etc.)
        - "Honeypot" (warning): host appears to be a honeypot
        - "TOR" (info): host is a TOR exit node
        - "GovCloud" (info): host belongs to a government cloud range
        - "Reserved address" (info): host uses a reserved IP range

        If tag is None and info is None, matches any record that has at
        least one tag.

        When info is provided, it is matched as a substring regex against
        the tag info field (e.g., `searchtag(tag="CLOUD", info="azure")` to
        find hosts tagged CLOUD with info mentioning azure).
        """
        if info is None:
            return seal(HTTP_DB[purpose].searchtag(tag))
        tag_dict: dict[str, Any] = {"info": re.compile(re.escape(info))}
        if tag is not None:
            tag_dict["value"] = tag
        return seal(HTTP_DB[purpose].searchtag(tag_dict))

    # --- Filter construction: Passive-specific ---

    @mcp.tool()
    def searchrecontype(purpose: PassivePurpose, recontype: str) -> FilterType:
        """Filter passive records by reconnaissance type."""
        return seal(HTTP_DB[purpose].searchrecontype(recontype))

    @mcp.tool()
    def searchsensor(purpose: PassivePurpose, sensor: str) -> FilterType:
        """Filter passive records by sensor name."""
        return seal(HTTP_DB[purpose].searchsensor(sensor))

    # --- Action tools ---

    @mcp.tool()
    def count(purpose: AllPurpose, flt: FilterType | None = None) -> int:
        """Count records matching a filter."""
        try:
            return int(REAL_DB[purpose].count(_parse(purpose, flt)))
        except McpError:
            raise
        except Exception as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc

    @mcp.tool()
    def get(
        purpose: AllPurpose,
        flt: FilterType | None = None,
        limit: int = 10,
        skip: int = 0,
        sort: list[str] | None = None,
        fields: list[str] | None = None,
    ) -> str:
        """Retrieve records matching a filter. Returns JSON array."""
        limit = max(1, min(limit, 100))
        try:
            parsed_flt = _parse(purpose, flt)
            records = [
                _clean_record(rec)
                for rec in REAL_DB[purpose].get(
                    parsed_flt,
                    limit=limit,
                    skip=skip,
                    sort=_parse_sort(sort),
                    fields=fields,
                )
            ]
            return json.dumps(records, default=serialize)
        except McpError:
            raise
        except Exception as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc

    @mcp.tool()
    def topvalues(
        purpose: AllPurpose,
        field: str,
        flt: FilterType | None = None,
        topnbr: int = 10,
    ) -> str:
        """Return the most frequent values of a field. Returns JSON array of {value, count}.

        The field parameter accepts both raw document paths (from describe_schema)
        and the following higher-level aliases that are more precise:

          "service"              — service names across all ports
          "port"                 — open port numbers
          "product"              — software products across all ports
          "version"              — software versions across all ports
          "product:<port>"       — products on a specific port number
                                   e.g. "product:22" for SSH, "product:443" for HTTPS
          "product:<service>"    — products for a named service on any port
                                   e.g. "product:ssh", "product:http"
          "version:<svc>:<prod>" — versions of a specific product
                                   e.g. "version:ssh:OpenSSH"
          "country"              — country codes
          "as"                   — autonomous systems
          "domains"              — hostnames / domain names
          "os"                   — operating systems
          "devicetype"           — device types
          "openports"            — full open-port profiles (port count + port list)
          "tag"                  — [value, info] tag pairs
          "tag.value"            — tag names only (equivalent to "tags.value")

        Always prefer these aliases over raw document paths such as
        "ports.service_product": raw paths aggregate across all ports and return
        misleading mixed-service results for service-specific queries.
        """
        try:
            parsed_flt = _parse(purpose, flt)
            raw = REAL_DB[purpose].topvalues(field, flt=parsed_flt, topnbr=topnbr)
            results = [
                {"value": entry["_id"], "count": entry["count"]} for entry in raw
            ]
            return json.dumps(results, default=serialize)
        except McpError:
            raise
        except Exception as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc

    @mcp.tool()
    def distinct(
        purpose: AllPurpose,
        field: str,
        flt: FilterType | None = None,
        limit: int = 100,
    ) -> str:
        """Return distinct values of a field. Returns JSON array.

        Tip: use distinct("ports.scripts.id") to list all Nmap scripts that have
        produced results in a given scope. This is useful to understand what data
        is available before drilling down with searchscript.
        """
        try:
            parsed_flt = _parse(purpose, flt)
            values = list(REAL_DB[purpose].distinct(field, flt=parsed_flt, limit=limit))
            return json.dumps(values, default=serialize)
        except McpError:
            raise
        except Exception as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc

    @mcp.tool()
    def describe_schema(purpose: AllPurpose) -> str:
        """Return the document schema for a given purpose, listing raw field paths.

        Raw paths are usable with distinct() and get() (sort parameter). For
        topvalues(), prefer the higher-level field aliases documented in
        topvalues() — e.g. "product:ssh" instead of "ports.service_product".
        Raw paths in topvalues() aggregate across all ports and return misleading
        mixed-service results for service-specific queries.

        See also nmap_service_values() to discover valid service names and product
        names for use with searchservice / searchproduct.
        """
        return json.dumps(SCHEMAS[purpose])

    # --- Nmap service value discovery ---

    @mcp.tool()
    def nmap_service_values(
        field: Literal["service_name", "service_product"],
        service: str | None = None,
    ) -> str:
        """List known Nmap values for service_name or service_product.

        For service_name: returns the comprehensive list of all possible service names.
        For service_product: returns known product names (not exhaustive — banner
        extraction may produce unlisted values). Use the optional service parameter
        to filter products by service name.
        """
        try:
            cache = _get_nmap_service_values()
        except Exception as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc

        if field == "service_name":
            return json.dumps(sorted(cache.get("service_names", set())))

        # field == "service_product"
        if service is not None:
            values = cache.get(f"products:{service}", set())
        else:
            values = cache.get("products_all", set())
        return json.dumps(sorted(values))

    # --- RIR (Regional Internet Registry) lookups ---

    @mcp.tool()
    def rir_lookup(addr: str) -> str:
        """Return the most-specific RIR record for an IP address.

        Looks up the smallest range covering ``addr`` in the RIR
        database (built from AfriNIC / APNIC / ARIN / LACNIC / RIPE
        whois dumps). Returns a JSON object with whois fields such as
        ``netname``, ``descr``, ``country``, ``org``, ``start``,
        ``stop``. Returns JSON ``null`` when no record matches.

        Equivalent to the ``ivre rirlookup <addr>`` CLI.
        """
        try:
            rec = db.rir.get_best(addr)
        except Exception as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc
        if rec is None:
            return json.dumps(None)
        rec.pop("_id", None)
        return json.dumps(rec, default=serialize)

    def _rir_filter(query: str | None, country: str | None) -> Any:
        flt = db.rir.flt_empty
        if query is not None:
            flt = db.rir.flt_and(flt, db.rir.searchtext(query))
        if country is not None:
            flt = db.rir.flt_and(flt, db.rir.searchcountry(country))
        return flt

    @mcp.tool()
    def rir_search(
        query: str | None = None,
        country: str | None = None,
        limit: int = 10,
    ) -> str:
        """Search RIR records by free text and/or country code.

        ``query`` is a free-text search across the ``netname``,
        ``descr``, ``remarks``, ``notify`` and ``org`` fields (only
        available with backends that index those fields, e.g.
        MongoDB). ``country`` is a 2-letter ISO 3166-1 country code.
        Returns up to ``limit`` records (max 100) as a JSON array.

        Equivalent to ``ivre rirlookup --search ... --country ...``.
        """
        limit = max(1, min(limit, 100))
        try:
            records = []
            for rec in db.rir.get(_rir_filter(query, country), limit=limit):
                rec.pop("_id", None)
                records.append(rec)
            return json.dumps(records, default=serialize)
        except Exception as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc

    @mcp.tool()
    def rir_count(
        query: str | None = None,
        country: str | None = None,
    ) -> int:
        """Count RIR records matching free-text and/or country criteria.

        Same filter semantics as :func:`rir_search`.
        """
        try:
            return int(db.rir.count(_rir_filter(query, country)))
        except Exception as exc:
            raise McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from exc

    # --- Resources ---

    @mcp.resource("ivre://guides/scope-discovery")
    def scope_discovery_guide() -> str:
        """Guide: recommended steps when discovering or analyzing a scope."""
        return _SCOPE_DISCOVERY_GUIDE


def _clean_record(record: dict[str, Any]) -> dict[str, Any]:
    try:
        del record["_id"]
    except KeyError:
        pass
    return record


# --- Nmap service value discovery ---

_NMAP_SVC_CACHE: dict[str, set[str]] = {}

_NSE_VERSION_NAME_RE = re.compile(r'\.version\.name\s*=\s*([\'"])([^\'"]*)\1')
_NSE_VERSION_PRODUCT_RE = re.compile(r'\.version\.product\s*=\s*([\'"])([^\'"]*)\1')


def _get_nmap_service_values() -> dict[str, set[str]]:
    if _NMAP_SVC_CACHE:
        return _NMAP_SVC_CACHE

    service_names: set[str] = set()
    products: dict[str, set[str]] = {}

    # Trigger lazy loading of _NMAP_PROBES
    try:
        get_nmap_svc_fp("tcp", "NULL")
    except KeyError:
        pass

    # Extract from nmap-service-probes fingerprints
    for probes in _NMAP_PROBES.values():
        for probe_rec in probes.values():
            for svc_name, info in probe_rec.get("fp", []):
                service_names.add(svc_name)
                if "p" in info:
                    product_str = info["p"][0]
                    if "$" not in product_str:
                        products.setdefault(svc_name, set()).add(product_str)

    # Extract from NSE scripts
    nmap_scripts = os.path.join(config.NMAP_SHARE_PATH, "scripts")
    if os.path.isdir(nmap_scripts):
        for nse_path in glob.glob(os.path.join(nmap_scripts, "*.nse")):
            try:
                with open(nse_path, encoding="utf-8", errors="replace") as fdesc:
                    content = fdesc.read()
            except OSError:
                continue
            for match in _NSE_VERSION_NAME_RE.finditer(content):
                service_names.add(match.group(2))
            for match in _NSE_VERSION_PRODUCT_RE.finditer(content):
                value = match.group(2)
                if "$" not in value:
                    products.setdefault("", set()).add(value)

    _NMAP_SVC_CACHE["service_names"] = service_names
    _NMAP_SVC_CACHE["products_all"] = {p for ps in products.values() for p in ps}
    for svc_name, prods in products.items():
        _NMAP_SVC_CACHE[f"products:{svc_name}"] = prods

    return _NMAP_SVC_CACHE


_SCOPE_DISCOVERY_GUIDE = """\
# Scope Discovery Guide

When exploring a new scope or answering broad security questions, follow these
steps. They work with any filter (flt_empty for the whole database, or a
specific filter built with searchnet, searchcountry, searchasnum, etc.).

## 1. Get an overview

- `count(purpose, flt)` — how many hosts are in scope?
- `topvalues(purpose, "openports", flt)` — most common port profiles; each
  value is a full open-ports structure with port count and port list, so you
  see the typical "shapes" of hosts in the scope (e.g., 71k hosts with only
  tcp/80 + tcp/443 open)
- `distinct(purpose, "tags.value", flt)` — list which tags are present in the
  scope (e.g., Vulnerable, CDN, CLOUD, Organization, …)

## 2. Understand the services

- `topvalues(purpose, "service", flt)` — most common service names
- `topvalues(purpose, "port", flt)` — most common open ports
- `topvalues(purpose, "product", flt)` — most common software products
- `topvalues(purpose, "version", flt)` — most common product versions
- `topvalues(purpose, "product:<port>", flt)` — products on a specific port
  (e.g., "product:443" for HTTPS, "product:22" for SSH)
- `topvalues(purpose, "product:<service>", flt)` — products for a service on
  any port (e.g., "product:http" to cover HTTP on all ports, not just 80/443)
- `topvalues(purpose, "version:<service>:<product>", flt)` — versions of a
  specific product (e.g., "version:http:Microsoft IIS httpd" to see which IIS
  versions are deployed)

## 3. Discover what scan data is available

- `distinct(purpose, "ports.scripts.id", flt)` — list all Nmap scripts that
  produced results in the scope. This tells you what data you can drill into
  with searchscript (e.g., "ssl-cert", "http-title", "vulners", "ftp-anon").

## 4. Assess security posture

- `searchtag(purpose, "Vulnerable")` — hosts with confirmed vulnerabilities
- `searchtag(purpose, "Likely vulnerable")` — hosts likely vulnerable (version-based)
- `searchtag(purpose, "Default password")` — hosts with default credentials
- `searchcve(purpose, "CVE-YYYY-NNNN")` — hosts vulnerable to a specific CVE
  (shortcut for searchtag with a CVE substring match on tag info)
- `topvalues(purpose, "tag.value", flt)` — just the tag names with host counts
  (equivalent to `tags.value`); use this for a quick tag histogram
- `topvalues(purpose, "tag", flt)` — full tag `[value, info]` pairs with
  counts; use this for a detailed breakdown (e.g., which specific cloud
  providers, which CVEs on vulnerable hosts)
- `searchtag(purpose, tag="Vulnerable", info="CVE-2021-")` — narrow a tag
  query by an info substring; any tag supports this pattern
- Look for risky exposed services: telnet, ftp-anon, ms-wbt-server (RDP), vnc,
  netbios-ssn (SMB), mysql, postgresql, mongodb

## 5. Identify infrastructure

- `topvalues(purpose, "country", flt)` — geographic distribution
- `topvalues(purpose, "as", flt)` — autonomous systems
- `topvalues(purpose, "domains", flt)` — most common domains
- `topvalues(purpose, "os", flt)` — operating systems
- `topvalues(purpose, "devicetype", flt)` — device types
- `searchtag(purpose, "CDN")` — hosts behind CDNs
- `searchtag(purpose, "CLOUD")` — hosts in cloud providers
- `searchtag(purpose, "WAF")` — hosts behind WAFs

## Tips

- Always start broad (topvalues, count) before drilling into individual hosts.
- Combine filters with flt_and to narrow down (e.g., country + service).
- Use the `fields` parameter in get() to limit output to relevant fields.
- Use describe_schema(purpose) to discover all available field paths.
- Many Nmap scripts store parsed, structured data in `ports.scripts[i]`
  under keys other than `id` and `output` (e.g., `ssl-cert`, `http-nuclei`,
  `nuclei`, `vulners`). Prefer these keys when drilling into a host — they
  are easier to parse than the raw `output` string.
"""


logger = logging.getLogger(__name__)


# Set to True by main() when the HTTP transport is started with a
# token verifier; consulted by :func:`_parse` to enforce authentication
# on every tool call. Stays False under the stdio transport.
_HTTP_AUTH_REQUIRED = False


def _is_loopback(addr: str) -> bool:
    """Return True if ``addr`` is a loopback IP address."""
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def main() -> None:
    """Entry point for ``ivre mcp-server``."""
    parser = argparse.ArgumentParser(
        description=(
            "Start the IVRE MCP (Model Context Protocol) server. By "
            "default it runs over stdio, meant to be launched by an "
            "MCP-capable client (Claude Code, Claude Desktop, Cursor, "
            "OpenCode, ...). Use --http to expose it over HTTP "
            "(Streamable HTTP transport). See doc/usage/mcp-server.rst "
            "for client configuration."
        ),
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help=(
            "Serve over HTTP (Streamable HTTP transport) instead of "
            "stdio. Clients connect with `Authorization: Bearer "
            "<api-key>`. See --bind / --port / --path."
        ),
    )
    parser.add_argument(
        "--bind",
        default=config.MCP_HTTP_BIND,
        help=f"HTTP bind address (default: {config.MCP_HTTP_BIND}).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=config.MCP_HTTP_PORT,
        help=f"HTTP port (default: {config.MCP_HTTP_PORT}).",
    )
    parser.add_argument(
        "--path",
        default=config.MCP_HTTP_PATH,
        help=f"HTTP path prefix (default: {config.MCP_HTTP_PATH}).",
    )
    parser.add_argument(
        "--allow-anonymous",
        action="store_true",
        default=config.MCP_HTTP_ALLOW_ANONYMOUS,
        help=(
            "Disable bearer-token auth on the HTTP transport. Required "
            "to bind a non-loopback address when the IVRE Web auth "
            "backend is not configured (acknowledges that every client "
            "will have full unauthenticated access to the database)."
        ),
    )
    args = parser.parse_args()
    if _MCP_IMPORT_ERROR is not None:
        raise SystemExit(
            "The 'mcp' Python package is required. Install IVRE with the "
            "[mcp] extra: pip install 'ivre[mcp]'.\n"
            f"Original import error: {_MCP_IMPORT_ERROR}"
        )
    if args.http:
        _run_http(args)
    else:
        _build_server()
        mcp.run(transport="stdio")


def _run_http(args: argparse.Namespace) -> None:
    """Start the Streamable-HTTP transport."""
    global _HTTP_AUTH_REQUIRED  # noqa: PLW0603

    loopback = _is_loopback(args.bind)
    auth_backend_ok = config.WEB_AUTH_ENABLED and db.auth is not None
    use_auth = auth_backend_ok and not args.allow_anonymous

    if not use_auth and not loopback and not args.allow_anonymous:
        raise SystemExit(
            "Refusing to start the MCP HTTP transport on a non-loopback "
            f"address ({args.bind}) without authentication. Either:\n"
            "  - enable the IVRE Web auth backend (WEB_AUTH_ENABLED = True "
            "in ivre.conf) and create an API key via the admin UI, or\n"
            "  - bind explicitly to a loopback address (e.g. --bind "
            "127.0.0.1), or\n"
            "  - pass --allow-anonymous to acknowledge the risk."
        )

    if args.allow_anonymous and auth_backend_ok:
        logger.warning(
            "MCP HTTP: --allow-anonymous was passed while the auth backend "
            "is configured; every client will have full (unauthenticated) "
            "access to the database.",
        )

    fastmcp_kwargs: dict[str, Any] = {
        "host": args.bind,
        "port": args.port,
        "streamable_http_path": args.path,
    }

    if use_auth:
        from .auth import IvreTokenVerifier  # pylint: disable=import-outside-toplevel

        # AuthSettings.issuer_url / resource_server_url are advertised
        # to clients in the WWW-Authenticate header (on 401) and the
        # /.well-known/oauth-protected-resource{path} JSON document.
        # The bind address is the *internal* one (typically loopback,
        # behind nginx) and is not what clients use to reach us. To
        # avoid a config knob, set the URLs at startup to a fixed
        # sentinel rooted at the RFC 2606 reserved
        # ``placeholder.invalid`` TLD; PublicUrlRewriteMiddleware (see
        # below) substitutes the sentinel scheme+host with the
        # request-derived public origin on the way out, the same trust
        # surface as ivre.web.base.check_referer.
        sentinel_origin = "http://placeholder.invalid"
        fastmcp_kwargs["token_verifier"] = IvreTokenVerifier()
        fastmcp_kwargs["auth"] = AuthSettings(
            issuer_url=sentinel_origin,
            resource_server_url=f"{sentinel_origin}{args.path}",
        )
        _HTTP_AUTH_REQUIRED = True
        logger.info(
            "MCP HTTP: bearer-token auth enabled (API keys from db.auth)",
        )
    else:
        _HTTP_AUTH_REQUIRED = False
        logger.warning(
            "MCP HTTP: running without authentication on %s:%d%s",
            args.bind,
            args.port,
            args.path,
        )

    _build_server(**fastmcp_kwargs)
    if use_auth:
        # pylint: disable=import-outside-toplevel
        import asyncio

        import uvicorn

        from .middleware import PublicUrlRewriteMiddleware

        app = mcp.streamable_http_app()
        app.add_middleware(PublicUrlRewriteMiddleware)
        uvicorn_config = uvicorn.Config(
            app,
            host=args.bind,
            port=args.port,
            log_level="info",
        )
        asyncio.run(uvicorn.Server(uvicorn_config).serve())
    else:
        mcp.run(transport="streamable-http")
