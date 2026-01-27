#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2025 Pierre LALET <pierre@droids-corp.org>
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

"""This submodule contains functions to manipulate documents from the
active (nmap & view) purposes.

"""

import json
import os
import re
from collections.abc import Callable
from datetime import datetime
from itertools import chain
from textwrap import wrap
from typing import Any, cast
from urllib.parse import urlparse

from ivre.active.cpe import add_cpe_values
from ivre.active.nmap import ALIASES_TABLE_ELEMS
from ivre.config import VIEW_MAX_HOSTNAMES_COUNT, VIEW_SYNACK_HONEYPOT_COUNT
from ivre.data.microsoft.exchange import EXCHANGE_BUILDS
from ivre.plugins import load_plugins
from ivre.tags import TAG_CDN, TAG_HONEYPOT, add_tags
from ivre.tags.active import (
    has_toomany_hostnames,
    is_real_service_port,
    is_synack_honeypot,
    set_auto_tags,
    set_openports_attribute,
)
from ivre.types import NmapServiceMatch, ParsedCertificate, Tag
from ivre.types.active import (
    HttpHeader,
    NmapAddress,
    NmapHost,
    NmapHostname,
    NmapPort,
    NmapScript,
)
from ivre.utils import (
    _CERTKEYS,
    IPV4ADDR,
    LOGGER,
    decode_b64,
    encode_b64,
    get_cert_info,
    get_domains,
    key_sort_dom,
    nmap_encode_data,
    parse_cert_subject_string,
    ports2nmapspec,
)


def create_ssl_output(info: ParsedCertificate) -> list[str]:
    out = []
    for key, name in [("subject_text", "Subject"), ("issuer_text", "Issuer")]:
        try:
            out.append("%s: %s" % (name, info[key]))
        except KeyError:
            pass
    try:
        pubkey = info["pubkey"]
    except KeyError:
        pass
    else:
        try:
            out.append("Public Key type: %s" % pubkey["type"])
        except KeyError:
            pass
        try:
            out.append("Public Key bits: %d" % pubkey["bits"])
        except KeyError:
            pass
    for key, name in [
        ("not_before", "Not valid before: "),
        ("not_after", "Not valid after:  "),
    ]:
        try:
            out.append("%s%s" % (name, info[key]))
        except KeyError:
            pass
    for san in info.get("san", []):
        out.append("Subject Alternative Name: %s" % san)
    for key, name in [("md5", "MD5:"), ("sha1", "SHA-1:"), ("sha256", "SHA-256:")]:
        # NB: SHA-256 is not (yet) reported by Nmap, but it might help.
        try:
            out.append("%-7s%s" % (name, " ".join(wrap(info[key], 4))))
        except KeyError:
            pass
    try:
        out.append(info["pem"])
    except KeyError:
        pass
    return out


def create_ssl_cert(
    data: bytes, b64encoded: bool = True
) -> tuple[str, list[ParsedCertificate]]:
    """Produces an output similar to Nmap script ssl-cert from Masscan
    X509 "service" tag.

    """
    if b64encoded:
        cert = decode_b64(data)
    else:
        cert = data
        data = encode_b64(cert)
    info = get_cert_info(cert)
    b64cert = data.decode()
    pem = []
    pem.append("-----BEGIN CERTIFICATE-----")
    pem.extend(wrap(b64cert, 64))
    pem.append("-----END CERTIFICATE-----")
    pem.append("")
    info["pem"] = "\n".join(pem)
    return "\n".join(create_ssl_output(info)), [info]


def san2hostname(san: str) -> tuple[str, str] | None:
    """Extract a hostname from a Subject Alt Name value when possible."""
    if san.startswith("DNS:"):
        return "dns", san[4:]
    if san.startswith("URI:"):
        url = san[4:]
        if url.startswith("://"):
            url = f"x{url}"  # add a fake scheme for URL parsing
        try:
            hostname = urlparse(url).hostname
        except Exception:
            LOGGER.warning("Invalid URL in SAN %r", san, exc_info=True)
            return None
        if hostname:
            return "uri", hostname
        return None
    if san.startswith("DirName:"):
        dir_name = san[8:]
        try:
            key, value = dir_name.split("=", 1)
        except ValueError:
            LOGGER.warning("Invalid DirName in SAN %r", san, exc_info=True)
            return None
        if key.strip().lower() != "cn":
            return None
        return "dirname-cn", value.strip()
    if san.startswith("othername:UPN:"):
        upn = san[14:]
        if upn.startswith("S-1-"):
            # SID
            return None
        if "/" in upn:
            hostname = upn.split("/", 1)[1].split("@", 1)[0]
        else:
            hostname = upn
        return "othername-upn", hostname
    if san.startswith("othername:"):
        name = san[10:]
        if ":" not in name:
            return None
        subtype, hostname = name.split(":", 1)
        return f"othername-{subtype.lower()}", hostname
    return None


def add_cert_hostnames(cert: ParsedCertificate, hostnames: list[NmapHostname]) -> None:
    if "commonName" in cert.get("subject", {}):
        add_hostname(cert["subject"]["commonName"], "cert-subject-cn", hostnames)
    for san in cert.get("san", []):
        if (type_hostname := san2hostname(san)) is not None:
            add_hostname(type_hostname[1], f"cert-san-{type_hostname[0]}", hostnames)


def merge_ja3_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def is_server(script_id: str) -> bool:
        return script_id == "ssl-ja3-server"

    def ja3_equals(a: dict[str, Any], b: dict[str, Any], script_id: str) -> bool:
        return a["md5"] == b["md5"] and (
            not is_server(script_id) or a["client"]["md5"] == b["client"]["md5"]
        )

    def ja3_output(ja3: dict[str, Any], script_id: str) -> str:
        output = cast(str, ja3["md5"])
        if is_server(script_id):
            output += " - " + ja3["client"]["md5"]
        return output

    return _merge_scripts(curscript, script, script_id, ja3_equals, ja3_output)


def merge_ja4_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def ja4_equals(a: dict[str, Any], b: dict[str, Any], script_id: str) -> bool:
        return cast(bool, a["ja4"] == b["ja4"])

    def ja4_output(ja4: dict[str, Any], script_id: str) -> str:
        return cast(str, ja4["ja4"])

    return _merge_scripts(curscript, script, script_id, ja4_equals, ja4_output)


def merge_http_app_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def http_app_equals(a: dict[str, Any], b: dict[str, Any], script_id: str) -> bool:
        return cast(
            bool, a["application"] == b["application"] and a["path"] == b["path"]
        )

    def http_app_output(app: dict[str, Any], script_id: str) -> str:
        output = ["%(application)s: path %(path)s" % app]
        if app.get("version") is not None:
            output.append(", version %(version)s" % app)
            if app.get("parsed_version") is not None:
                output.append(" (%(parsed_version)s)" % app)
            elif app.get("application") == "OWA":
                app["parsed_version"] = EXCHANGE_BUILDS.get(
                    app["version"], "unknown build number"
                )
                output.append(" (%(parsed_version)s)" % app)
        return "".join(output)

    return _merge_scripts(
        curscript, script, script_id, http_app_equals, http_app_output
    )


def merge_ua_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def ua_equals(a: str, b: str, script_id: str) -> bool:
        return a == b

    def ua_output(ua: str, script_id: str) -> str:
        return ua

    return _merge_scripts(curscript, script, script_id, ua_equals, ua_output)


def merge_ssl_cert_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def cert_equals(a: ParsedCertificate, b: ParsedCertificate, script_id: str) -> bool:
        return cast(bool, a["sha256"] == b["sha256"])

    def cert_output(cert: dict[str, Any], script_id: str) -> str:
        return "\n".join(create_ssl_output(cert))

    return _merge_scripts(
        curscript,
        script,
        script_id,
        cert_equals,
        cert_output,
        outsep="\n------------------------------------------------------------"
        "----\n",
    )


def merge_axfr_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    # If one results has no structured output, keep the other
    # one. Prefer curscript over script.
    if script_id not in script:
        return curscript
    if script_id not in curscript:
        curscript["output"] = script["output"]
        curscript[script_id] = script[script_id]
        return script
    res: list[dict[str, Any]] = []
    for data in chain(curscript[script_id], script[script_id]):
        if any(data["domain"] == r["domain"] for r in res):
            continue
        res.append(data)
    res = sorted(res, key=lambda r: key_sort_dom(r["domain"]))
    line_fmt = "| %%-%ds  %%-%ds  %%s" % (
        max(len(r["name"]) for data in res for r in data["records"]),
        max(len(r["type"]) for data in res for r in data["records"]),
    )
    curscript["output"] = "\n".join(
        "\nDomain: %s\n%s\n\\\n"
        % (
            data["domain"],
            "\n".join(
                line_fmt % (r["name"], r["type"], r["data"]) for r in data["records"]
            ),
        )
        for data in res
    )
    curscript[script_id] = res
    return curscript


def merge_scanner_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    # If one results has no structured output, keep the other
    # one. Prefer curscript over script.
    if script_id not in script:
        return curscript
    if script_id not in curscript:
        curscript["output"] = script["output"]
        curscript[script_id] = script[script_id]
        return script
    res: dict[str, Any] = {}
    for data in [curscript[script_id], script[script_id]]:
        for proto, ports in data.get("ports", {}).items():
            if proto == "count":
                continue
            res.setdefault("ports", {}).setdefault(proto, {}).setdefault(
                "ports", set()
            ).update(ports.get("ports", []))
        for uri in data.get("http_uris", []):
            res.setdefault("http_uris", set()).add(
                (
                    uri["uri"],
                    uri["method"],
                    uri["version"],
                )
            )
        for query in data.get("dns_queries", []):
            res.setdefault("dns_queries", set()).add(
                (
                    query["query"],
                    query["qtype"],
                    query["qclass"],
                )
            )
        for scanner in data.get("scanners", []):
            res.setdefault("scanners", {}).setdefault(scanner["name"], set()).update(
                (probe["proto"], probe.get("name"))
                for probe in scanner.get("probes", [])
            )
        res.setdefault("probes", set()).update(
            (probe["proto"], probe["value"]) for probe in data.get("probes", [])
        )
    for proto, ports in list(res.get("ports", {}).items()):
        res["ports"][proto]["ports"] = sorted(ports["ports"])
        nports = len(ports["ports"])
        res["ports"][proto]["count"] = nports
        res["ports"]["count"] = res["ports"].get("count", 0) + nports
    if "http_uris" in res:
        res["http_uris"] = [
            {"uri": uri, "method": method, "version": version}
            for uri, method, version in sorted(res["http_uris"])
        ]
    if "dns_queries" in res:
        res["dns_queries"] = [
            {"query": query, "qtype": qtype, "qclass": qclass}
            for query, qtype, qclass in sorted(res["dns_queries"])
        ]
    scanners = []
    for name, probes in res.get("scanners", {}).items():
        scanner = {"name": name}
        if probes:
            scanner["probes"] = [
                {"proto": proto, "name": name} for proto, name in sorted(probes)
            ]
        scanners.append(scanner)
    if scanners:
        res["scanners"] = scanners
    if "probes" in res:
        res["probes"] = [
            {"proto": proto, "value": value} for proto, value in sorted(res["probes"])
        ]
    curscript[script_id] = res
    output = []
    if res.get("ports"):
        output.append(
            "Scanned port%s: %s"
            % (
                "s" if res["ports"]["count"] > 1 else "",
                ", ".join(
                    "%s: %s" % (proto, ports2nmapspec(ports["ports"]))
                    for proto, ports in res.get("ports", {}).items()
                    if proto != "count"
                ),
            )
        )
    if res.get("http_uris"):
        uris_methods: dict[str, set[str]] = {}
        uris_versions: dict[str, set[str]] = {}
        for uri in res["http_uris"]:
            uris_methods.setdefault(uri["uri"], set()).add(uri["method"])
            uris_versions.setdefault(uri["uri"], set()).add(uri["version"])
        output.append(
            "Scanned URI%s: %s"
            % (
                "s" if len(uris_versions) > 1 else "",
                ", ".join(
                    "%s (%s %s)"
                    % (
                        uri,
                        ", ".join(uris_methods[uri]),
                        ", ".join(uris_versions[uri]),
                    )
                    for uri in sorted(uris_versions)
                ),
            )
        )
    if res.get("dns_queries"):
        queries_qtype: dict[str, set[str]] = {}
        queries_qclass: dict[str, set[str]] = {}
        for query in res["dns_queries"]:
            queries_qtype.setdefault(query["query"], set()).add(query["qtype"])
            queries_qclass.setdefault(query["query"], set()).add(query["qclass"])
        output.append(
            "DNS quer%s: %s"
            % (
                "ies" if len(queries_qtype) > 1 else "y",
                ", ".join(
                    "%s (type: %s, class: %s)"
                    % (
                        query,
                        ", ".join(queries_qtype[query]),
                        ", ".join(queries_qclass[query]),
                    )
                    for query in sorted(queries_qtype)
                ),
            )
        )
    if scanners:

        def _fmt_sc(sc: dict[str, Any]) -> str:
            res = sc["name"]  # type: str
            if "probes" in sc:
                res += " [%s]" % ", ".join(
                    "%s/%s" % (x["name"], x["proto"]) for x in sc["probes"]
                )
            return res

        output.append(
            "Scanner%s: \n - %s"
            % (
                "s" if len(scanners) > 1 else "",
                "\n - ".join(_fmt_sc(scanner) for scanner in scanners),
            )
        )
    curscript["output"] = "\n".join(output)
    return curscript


def merge_nuclei_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def nuclei_equals(a: dict[str, Any], b: dict[str, Any], script_id: str) -> bool:
        return all(
            a.get(key) == b.get(key)
            for key in ["name", "url", "template", "host", "path"]
        )

    def nuclei_output(nuclei: dict[str, Any], script_id: str) -> str:
        return "[%(severity)s] %(name)s found at %(url)s" % nuclei

    return _merge_scripts(curscript, script, script_id, nuclei_equals, nuclei_output)


def merge_http_git_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    repos: dict[str, Any] = {}
    for scr in [script, curscript]:
        for rep in scr.get(script_id, []):
            repos.setdefault(rep["repository"], set()).update(
                rep.get("files-found", [])
            )
    repos_order = sorted(repos)
    data = [
        {"repository": rep, "files-found": sorted(repos[rep])} for rep in repos_order
    ]
    output = "\n".join(
        "\n  %s\n    Git repository found!\n" % rep for rep in repos_order
    )
    curscript["output"] = output
    curscript[script_id] = data
    return curscript


def merge_dns_domains_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    domains = {
        res["domain"]: (
            res["parents"] if "parents" in res else list(get_domains(res["domain"]))
        )
        for scr in [script, curscript]
        for res in scr.get(script_id, [])
        if "domain" in res
    }
    domains_order = sorted(domains, key=key_sort_dom)
    if len(domains_order) == 1:
        output = "Server is authoritative for %s" % domains_order[0]
    else:
        output = "Server is authoritative for:\n%s" % "\n".join(
            "  %s" % dom for dom in domains_order
        )
    curscript["output"] = output
    curscript[script_id] = [
        {"domain": dom, "parents": domains[dom]} for dom in domains_order
    ]
    return curscript


def merge_dns_domains_mx_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    domains_prios = {
        (res["domain"], res["priority"]): (
            res["parents"] if "parents" in res else list(get_domains(res["domain"]))
        )
        for scr in [script, curscript]
        for res in scr.get(script_id, [])
        if "domain" in res and "priority" in res
    }
    domains_order = sorted(
        domains_prios, key=lambda dom_prio: (key_sort_dom(dom_prio[0]), dom_prio[1])
    )
    if len(domains_order) == 1:
        output = f"Server is Mail eXchanger for {domains_order[0][0]} (priority {domains_order[0][1]})"
    else:
        output = "Server is Mail eXchanger for:\n%s" % "\n".join(
            f"  {dom} (priority {prio})" for dom, prio in domains_order
        )
    curscript["output"] = output
    curscript[script_id] = [
        {
            "domain": dom_prio[0],
            "parents": domains_prios[dom_prio],
            "priority": dom_prio[1],
        }
        for dom_prio in domains_order
    ]
    return curscript


def merge_dns_tls_rpt_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    # overwrite results from script by those from curscript
    domains = {
        res["domain"]: res
        for scr in [script, curscript]
        for res in scr.get(script_id, [])
        if "domain" in res
    }
    domains_order = sorted(domains, key=key_sort_dom)
    output = []
    for dom in domains_order:
        cur_data = domains[dom]
        if "warnings" not in cur_data:
            output.append("Domain %s has a valid TLS-RPT configuration" % dom)
            continue
        warnings = cur_data["warnings"]
        if warnings == ["Domain has no TLS-RPT configuration"]:
            output.append("Domain %s has no TLS-RPT configuration" % dom)
            continue
        if warnings == ["Domain has more than one TLS-RPT configuration"]:
            output.append("Domain %s has more than one TLS-RPT configuration" % dom)
            continue
        output.append(
            "Domain %s has a TLS-RPT configuration with warnings:\n%s"
            % (
                dom,
                "\n".join(warnings),
            )
        )
    curscript["output"] = "\n".join(output)
    curscript[script_id] = [domains[dom] for dom in domains_order]
    return curscript


def merge_dns_check_consistency_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    # overwrite results from script by those from curscript
    domains_name_type = {
        (res["domain"], res["name"], res["rtype"]): res
        for scr in [script, curscript]
        for res in scr.get(script_id, [])
        if "domain" in res
    }
    domains_name_type_order = sorted(
        domains_name_type,
        key=lambda v: (
            key_sort_dom(v[0]),
            key_sort_dom(v[1]),
            v[2],
        ),
    )
    curscript["output"] = "DNS inconsistency\n\n%s" % "\n\n".join(
        "%s (%s)\nThis server:\n%s\nMost common answer:\n%s"
        % (
            name,
            rtype,
            "\n".join("  %r" % r for r in cur_data["value"]),
            "\n".join("  %r" % r for r in cur_data["reference_value"]),
        )
        for domain, name, rtype, cur_data in (
            (domain, name, rtype, domains_name_type[(domain, name, rtype)])
            for domain, name, rtype in domains_name_type_order
        )
    )
    curscript[script_id] = [domains_name_type[dnt] for dnt in domains_name_type_order]
    return curscript


def _merge_scripts(
    curscript: NmapScript,
    script: NmapScript,
    script_id: str,
    script_equals: (
        Callable[[dict[str, Any], dict[str, Any], str], bool]
        | Callable[[str, str, str], bool]
    ),
    script_output: Callable[[dict[str, Any], str], str] | Callable[[str, str], str],
    outsep: str = "\n",
) -> NmapScript:
    """Helper function to merge two scripts and return the result, using
    specific functions `script_equals` and `script_output`.

    """
    to_merge_list = []
    script_id_alias = ALIASES_TABLE_ELEMS.get(script_id, script_id)
    for to_add in script.setdefault(script_id_alias, []):
        to_merge = True
        for cur in curscript.get(script_id_alias, []):
            if script_equals(to_add, cur, script_id):
                to_merge = False
                break
        if to_merge:
            to_merge_list.append(to_add)
    curscript.setdefault(script_id_alias, []).extend(to_merge_list)
    # Compute output from curscript[script_id_alias]
    output = []
    for el in curscript[script_id_alias]:
        output.append(script_output(el, script_id))
    if output:
        curscript["output"] = outsep.join(output) + "\n"
    else:
        curscript["output"] = ""
    return curscript


_SCRIPT_MERGE = {
    "dns-check-consistency": merge_dns_check_consistency_scripts,
    "dns-domains": merge_dns_domains_scripts,
    "dns-domains-mx": merge_dns_domains_mx_scripts,
    "dns-tls-rpt": merge_dns_tls_rpt_scripts,
    "dns-zone-transfer": merge_axfr_scripts,
    "http-app": merge_http_app_scripts,
    "http-git": merge_http_git_scripts,
    "http-nuclei": merge_nuclei_scripts,
    "http-user-agent": merge_ua_scripts,
    "network-nuclei": merge_nuclei_scripts,
    "scanner": merge_scanner_scripts,
    "ssl-cacert": merge_ssl_cert_scripts,
    "ssl-cert": merge_ssl_cert_scripts,
    "ssl-ja3-client": merge_ja3_scripts,
    "ssl-ja3-server": merge_ja3_scripts,
    "ssl-ja4-client": merge_ja4_scripts,
}


def merge_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    """Merge curscript with script"""
    try:
        func = _SCRIPT_MERGE[script_id]
    except KeyError:
        return {}
    return func(curscript, script, script_id)


def merge_host_docs(
    rec1: NmapHost,
    rec2: NmapHost,
    auto_tags: bool = True,
    openports_attribute: bool = True,
) -> NmapHost:
    """Merge two host records and return the result. Unmergeable /
    hard-to-merge fields are lost (e.g., extraports).

    """
    if not rec2:
        return rec1
    if not rec1:
        return rec2
    if rec1.get("schema_version") != rec2.get("schema_version"):
        raise ValueError(
            "Cannot merge host documents. "
            "Schema versions differ (%r != %r)"
            % (rec1.get("schema_version"), rec2.get("schema_version"))
        )
    rec = {}
    if "schema_version" in rec1:
        rec["schema_version"] = rec1["schema_version"]
    # When we have different values, we will use the one from the
    # most recent scan, rec2. If one result has no "endtime", we
    # consider it as older.
    if (rec1.get("endtime") or datetime.fromtimestamp(0)) > (
        rec2.get("endtime") or datetime.fromtimestamp(0)
    ):
        rec1, rec2 = rec2, rec1
    for fname, function in [("starttime", min), ("endtime", max)]:
        try:
            rec[fname] = function(
                record[fname] for record in [rec1, rec2] if fname in record
            )
        except ValueError:
            pass
    sa_honeypot = is_synack_honeypot(rec1) or is_synack_honeypot(rec2)
    rec["state"] = "up" if rec1.get("state") == "up" else rec2.get("state")
    if rec["state"] is None:
        del rec["state"]
    rec["state_reason"] = rec2.get("state_reason", rec1.get("state_reason"))
    if rec["state_reason"] is None:
        del rec["state_reason"]
    rec["categories"] = sorted(
        set(rec1.get("categories", [])).union(rec2.get("categories", []))
    )
    for field in ["addr", "os"]:
        rec[field] = rec2[field] if rec2.get(field) else rec1.get(field)
        if not rec[field]:
            del rec[field]
    rec["source"] = sorted(
        set(rec1.get("source", [])).union(set(rec2.get("source", [])))
    )
    rec["traces"] = rec2.get("traces", [])
    for trace in rec1.get("traces", []):
        # Skip this result (from rec1) if a more recent traceroute
        # result exists using the same protocol and port in the
        # most recent scan (rec2).
        if any(
            other["protocol"] == trace["protocol"]
            and other.get("port") == trace.get("port")
            for other in rec["traces"]
        ):
            continue
        rec["traces"].append(trace)
    rec["cpes"] = rec2.get("cpes", [])
    for cpe in rec1.get("cpes", []):
        origins = set(cpe.pop("origins", []))
        cpe["origins"] = None
        try:
            other = next(
                ocpe for ocpe in rec["cpes"] if dict(ocpe, origins=None) == cpe
            )
        except StopIteration:
            rec["cpes"].append(dict(cpe, origins=origins))
        else:
            other["origins"] = set(other.get("origins", [])).union(origins)
    for cpe in rec["cpes"]:
        cpe["origins"] = list(cpe.get("origins", []))
    rec["infos"] = {}
    for record in [rec1, rec2]:
        rec["infos"].update(record.get("infos", {}))
    if not (has_toomany_hostnames(rec1) or has_toomany_hostnames(rec2)):
        # We want to make sure of (type, name) unicity
        hostnames = {
            (h["type"], h["name"]): h.get("domains")
            for h in chain(rec1.get("hostnames", []), rec2.get("hostnames", []))
        }
        if VIEW_MAX_HOSTNAMES_COUNT and len(hostnames) > VIEW_MAX_HOSTNAMES_COUNT:
            add_tags(rec, [cast(Tag, dict(TAG_CDN, info=["Too many hostnames"]))])
        elif hostnames:
            rec["hostnames"] = [
                {"type": h[0], "name": h[1], "domains": d} for h, d in hostnames.items()
            ]
    addresses: NmapAddress = {}
    for record in [rec1, rec2]:
        for atype, addrs in record.get("addresses", {}).items():
            cur_addrs = addresses.setdefault(atype, [])
            for addr in addrs:
                addr = addr.lower()
                if addr not in cur_addrs:
                    cur_addrs.append(addr)
        if "tags" in record:
            add_tags(rec, record["tags"])
    if addresses:
        rec["addresses"] = addresses
    if sa_honeypot:
        for record in [rec1, rec2]:
            if not is_synack_honeypot(record):
                record["ports"] = [
                    port
                    for port in record.get("ports", [])
                    if is_real_service_port(port)
                ]
    if "extraports" in rec1 and "extraports" not in rec2:
        rec["extraports"] = rec1["extraports"]
    elif "extraports" in rec2 and "extraports" not in rec1:
        rec["extraports"] = rec2["extraports"]
    ports = {
        (port.get("protocol"), port["port"]): port.copy()
        for port in rec2.get("ports", [])
    }
    for port in rec1.get("ports", []):
        if (port.get("protocol"), port["port"]) in ports:
            curport = ports[(port.get("protocol"), port["port"])]
            if "scripts" in curport:
                curport["scripts"] = curport["scripts"][:]
            else:
                curport["scripts"] = []
            present_scripts = set(script["id"] for script in curport["scripts"])
            for script in port.get("scripts", []):
                if script["id"] not in present_scripts:
                    curport["scripts"].append(script)
                elif script["id"] in _SCRIPT_MERGE:
                    # Merge scripts
                    curscript = next(
                        x for x in curport["scripts"] if x["id"] == script["id"]
                    )
                    merge_scripts(curscript, script, script["id"])
            if not curport["scripts"]:
                del curport["scripts"]
            if "service_name" in port:
                if "service_name" not in curport:
                    for key in port:
                        if key.startswith("service_"):
                            curport[key] = port[key]
                elif port["service_name"] == curport["service_name"]:
                    # if the "old" record has information missing
                    # from the "new" record and information from
                    # both records is consistent, let's keep the
                    # "old" data.
                    for key in port:
                        if key.startswith("service_") and key not in curport:
                            curport[key] = port[key]
            if "screenshot" in port and "screenshot" not in curport:
                for key in ["screenshot", "screendata", "screenwords"]:
                    if key in port:
                        curport[key] = port[key]
        else:
            ports[(port.get("protocol"), port["port"])] = port
    rec["ports"] = sorted(
        ports.values(),
        key=lambda port: (
            port.get("protocol") or "~",
            port.get("port"),
        ),
    )
    if auto_tags:
        set_auto_tags(rec, update_openports=False)
    else:
        # we at least need to clean-up the ports
        # first: syn-ack honeypot
        n_ports = sum(
            1 for port in rec.get("ports", []) if port.get("state_state") == "open"
        )
        if (
            VIEW_SYNACK_HONEYPOT_COUNT is not None
            and n_ports >= VIEW_SYNACK_HONEYPOT_COUNT
        ):
            # check if we have too many open ports that could be
            # "syn-ack honeypots"...
            newports = [
                port
                for port in rec["ports"]
                if port.get("state_state") != "open" or is_real_service_port(port)
            ]
            if (
                n_ports
                - sum(1 for port in newports if port.get("state_state") == "open")
                > VIEW_SYNACK_HONEYPOT_COUNT
            ):
                # ... if so, keep only the ports that cannot be "syn-ack
                # honeypots"
                rec["ports"] = newports
                add_tags(
                    rec, [cast(Tag, dict(TAG_HONEYPOT, info=["SYN+ACK honeypot"]))]
                )
    if openports_attribute:
        set_openports_attribute(rec)
    for field in ["traces", "infos", "ports", "cpes"]:
        if not rec[field]:
            del rec[field]
    return rec


_EXPR_INDEX_OF = re.compile(
    b"<title[^>]*> *(?:index +of|directory +listing +(?:of|for))",
    re.I,
)
_EXPR_FILES = [
    re.compile(
        b'<a href="(?P<filename>[^"]+)">[^<]+</a></td><td[^>]*> *'
        b"(?P<time>[0-9]+-[a-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *"
        b"</td><td[^>]*> *(?P<size>[^<]+)</td>",
        re.I,
    ),
    re.compile(
        b'<a href="(?P<filename>[^"]+)">[^<]+</a> *'
        b"(?P<time>[0-9]+-[a-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *"
        b"(?P<size>[^ \r\n]+)",
        re.I,
    ),
    re.compile(b'<li><a href="(?P<filename>[^"]+)">(?P=filename)</a>'),
]


def create_http_ls(data: bytes, volname: str = "???") -> NmapScript | None:
    """Produces an http-ls script output (both structured and human
    readable) from the content of an HTML page. Used for Zgrab and Masscan
    results.

    """
    if (match := _EXPR_INDEX_OF.search(data)) is None:
        return None
    files = []
    for pattern in _EXPR_FILES:
        for match in pattern.finditer(data):
            files.append(
                {
                    key: nmap_encode_data(value)
                    for key, value in match.groupdict().items()
                }
            )
    if not files:
        return None
    output = []
    output.append("Volume %s" % volname)
    title = ["size", "time", "filename"]
    column_width = [len(t) for t in title[:-1]]
    for fobj in files:
        for i, t in enumerate(title[:-1]):
            column_width[i] = max(column_width[i], len(fobj.get(t, "-")))
    line_fmt = "%%(size)-%ds  %%(time)-%ds  %%(filename)s" % tuple(column_width)
    output.append(line_fmt % {t: t.upper() for t in title})
    for fobj in files:
        output.append(line_fmt % {"size": "-", "time": "-", **fobj})
    output.append("")
    return {
        "id": "http-ls",
        "output": "\n".join(output),
        "ls": {"volumes": [{"volume": volname, "files": files}]},
    }


def create_elasticsearch_service(data: bytes) -> NmapServiceMatch | None:
    """Produces the service_* attributes from the (JSON) content of an
    HTTP response. Used for Zgrab and Masscan results.

    """
    try:
        data_p = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data_p, dict):
        return None
    if "tagline" not in data_p:
        if "error" not in data_p:
            return None
        error = data_p["error"]
        if isinstance(error, str):
            if data_p.get("status") == 401 and error.startswith(
                "AuthenticationException"
            ):
                return {
                    "service_name": "http",
                    "service_product": "Elasticsearch REST API",
                    "service_extrainfo": "Authentication required",
                    "cpe": ["cpe:/a:elasticsearch:elasticsearch"],
                }
            return None
        if not isinstance(error, dict):
            return None
        if not (data_p.get("status") == 401 or error.get("status") == 401):
            return None
        if "root_cause" in error:
            return {
                "service_name": "http",
                "service_product": "Elasticsearch REST API",
                "service_extrainfo": "Authentication required",
                "cpe": ["cpe:/a:elasticsearch:elasticsearch"],
            }
        return None
    if data_p["tagline"] != "You Know, for Search":
        return None
    result: NmapServiceMatch = {
        "service_name": "http",
        "service_product": "Elasticsearch REST API",
    }
    cpe = []
    if "version" in data_p and "number" in data_p["version"]:
        result["service_version"] = data_p["version"]["number"]
        cpe.append(
            "cpe:/a:elasticsearch:elasticsearch:%s" % data_p["version"]["number"]
        )
    extrainfo = []
    if "name" in data_p:
        extrainfo.append("name: %s" % data_p["name"])
        result["service_hostname"] = data_p["name"]
    if "cluster_name" in data_p:
        extrainfo.append("cluster: %s" % data_p["cluster_name"])
    if "version" in data_p and "lucene_version" in data_p["version"]:
        extrainfo.append("Lucene %s" % data_p["version"]["lucene_version"])
        cpe.append("cpe:/a:apache:lucene:%s" % data_p["version"]["lucene_version"])
    if extrainfo:
        result["service_extrainfo"] = "; ".join(extrainfo)
    if cpe:
        result["cpe"] = cpe
    return result


# This is not a real hostname regexp, but a simple way to exclude
# obviously wrong values. Underscores should not exist in (DNS)
# hostnames, but since they happen to exist anyway, we allow them
# here.
_HOSTNAME = re.compile("^[a-z0-9_\\.\\*\\-]+$", re.I)


def add_hostname(name: str, name_type: str, hostnames: list[NmapHostname]) -> None:
    name = name.rstrip(".").lower()
    if not _HOSTNAME.search(name):
        return
    # exclude IPv4 addresses
    if IPV4ADDR.search(name):
        return
    if any(hn["name"] == name and hn["type"] == name_type for hn in hostnames):
        return
    hostnames.append(
        {
            "type": name_type,
            "name": name,
            "domains": list(get_domains(name)),
        }
    )


def handle_tlsx_result(
    host: NmapHost,
    port: NmapPort,
    result: dict[str, Any],
) -> None:
    cert_added = False
    if "certificate" in result:
        try:
            output_cert, info_cert = create_ssl_cert(
                "".join(result["certificate"].splitlines()[1:-1]).encode(),
                b64encoded=True,
            )
        except Exception:
            LOGGER.warning(
                "Cannot parse certificate %r",
                result["certificate"],
                exc_info=True,
            )
        else:
            cert_added = True
            if info_cert:
                port.setdefault("scripts", []).append(
                    {
                        "id": "ssl-cert",
                        "output": output_cert,
                        "ssl-cert": info_cert,
                    }
                )
                for cert in info_cert:
                    add_cert_hostnames(cert, host.setdefault("hostnames", []))
    if not cert_added:
        # add at least parsed info when the raw certificate is not
        # available or could not be parsed
        cert_object = dict(result.get("fingerprint_hash", {}))
        for fld in ["subject", "issuer"]:
            try:
                flddata = [
                    (_CERTKEYS.get(key, key), value)
                    for key, value in parse_cert_subject_string(result[f"{fld}_dn"])
                ]
            except KeyError:
                continue
            cert_object[fld] = {key.replace(".", "_"): value for key, value in flddata}
            cert_object[f"{fld}_text"] = "/".join("%s=%s" % item for item in flddata)
        if "self_signed" in result:
            cert_object["self_signed"] = result["self_signed"]
        elif "subject_text" in cert_object and "issuer_text" in cert_object:
            cert_object["self_signed"] = (
                cert_object["subject_text"] == cert_object["issuer_text"]
            )
        for fld in ["not_before", "not_after"]:
            try:
                cert_object[fld] = result["fld"][:19].replace("T", " ")
            except (KeyError, ValueError):
                pass
        if "not_before" in result and "not_after" in result:
            cert_object["lifetime"] = int(
                (
                    datetime.fromisoformat(result["not_after"])
                    - datetime.fromisoformat(result["not_before"])
                ).total_seconds()
            )
        try:
            cert_object["serial_number"] = str(
                int(result["serial"].replace(":", ""), 16)
            )
        except (KeyError, ValueError):
            pass
        if "subject_an" in result:
            # tlsx (used by httpx for TLS) only stores DNS SANs
            cert_object["san"] = [f"DNS:{value}" for value in result["subject_an"]]
        if cert_object:
            port.setdefault("scripts", []).append(
                {
                    "id": "ssl-cert",
                    "output": "\n".join(create_ssl_output(cert_object)),
                    "ssl-cert": [cert_object],
                }
            )
            add_cert_hostnames(cert_object, host.setdefault("hostnames", []))
    if "jarm_hash" in result:
        port.setdefault("scripts", []).append(
            {
                "id": "ssl-jarm",
                "output": result["jarm_hash"],
                "ssl-jarm": result["jarm_hash"],
            }
        )
    structured = {}
    output = []
    for fld in ["tls_version", "cipher", "tls_connection"]:
        if fld in result:
            structured[fld] = result[fld]
            output.append(
                f"{fld.replace('_', ' ').capitalize().replace('Tls', 'TLS')}: {result[fld]}"
            )
    if structured:
        port.setdefault("scripts", []).append(
            {
                "id": "ssl-tlsx",
                "output": "\n".join(output),
                "ssl-tlsx": structured,
            }
        )


_EXPR_TITLE = re.compile(b"<title[^>]*>([^<]*)</title>", re.I)


def handle_http_content(
    host: NmapHost,
    port: NmapPort,
    data: bytes,
    path: str = "/",
) -> None:
    if (title_m := _EXPR_TITLE.search(data)) is not None and not any(
        s["id"] == "http-title" for s in port.get("scripts", [])
    ):
        title = nmap_encode_data(title_m.groups()[0])
        port.setdefault("scripts", []).append(
            {
                "id": "http-title",
                "output": title,
                "http-title": {"title": title},
            }
        )
    script_http_ls = create_http_ls(data, volname=path)
    if script_http_ls is not None:
        port.setdefault("scripts", []).append(script_http_ls)
    service_elasticsearch = create_elasticsearch_service(data)
    if service_elasticsearch:
        if "service_hostname" in service_elasticsearch:
            add_hostname(
                service_elasticsearch["service_hostname"],
                "service",
                host.setdefault("hostnames", []),
            )
        add_cpe_values(
            host, "ports.port:%s" % port, service_elasticsearch.pop("cpe", [])
        )
        port.update(cast(NmapPort, service_elasticsearch))


def handle_http_headers(
    host: NmapHost,
    port: NmapPort,
    headers: list[HttpHeader],
    path: str = "/",
    handle_server: bool = True,
) -> None:
    """This function enriches scan results based on HTTP headers reported
    by the Nmap script http-headers or any similar report, such as
    Masscan or Zgrab(2).

    """
    # * Add a script "http-server-header" if it does not exist
    if handle_server:
        srv_headers = [
            h["value"] for h in headers if h["name"] == "server" and h["value"]
        ]
        if srv_headers and not any(
            s["id"] == "http-server-header" for s in port.get("scripts", [])
        ):
            port.setdefault("scripts", []).append(
                {
                    "id": "http-server-header",
                    "output": "\n".join(srv_headers),
                    "http-server-header": srv_headers,
                }
            )
    # * Add a script "http-app" for MS SharePoint, and merge it if
    # necessary
    try:
        header = next(
            h["value"]
            for h in headers
            if h["name"] == "microsoftsharepointteamservices" and h["value"]
        )
    except StopIteration:
        pass
    else:
        version = header.split(":", 1)[0]
        add_cpe_values(
            host,
            "ports.port:%s" % port.get("port", -1),
            ["cpe:/a:microsoft:sharepoint_server:%s" % version],
        )
        script = {
            "id": "http-app",
            "output": "SharePoint: path %s, version %s" % (path, version),
            "http-app": [
                {"path": path, "application": "SharePoint", "version": version}
            ],
        }
        try:
            cur_script = next(
                s for s in port.get("scripts", []) if s["id"] == "http-app"
            )
        except StopIteration:
            port.setdefault("scripts", []).append(script)
        else:
            merge_http_app_scripts(cur_script, script, "http-app")
    # * Add a script "http-app" for Kibana, and merge it if necessary
    try:
        header = next(
            h["value"] for h in headers if h["name"] == "kbn-name" and h["value"]
        )
    except StopIteration:
        pass
    else:
        try:
            location = next(
                h["value"] for h in headers if h["name"] == "location" and h["value"]
            )
        except StopIteration:
            path_k = path
        else:
            path_k = os.path.join(path, location)
        structured = {"path": path_k, "application": "Kibana"}
        try:
            version = next(
                h["value"] for h in headers if h["name"] == "kbn-version" and h["value"]
            )
        except StopIteration:
            output = f"Kibana: path {path_k}"
            add_cpe_values(
                host,
                "ports.port:%s" % port.get("port", -1),
                ["cpe:/a:elasticsearch:kibana"],
            )
        else:
            output = f"Kibana: path {path_k}, version {version}"
            structured["version"] = version
            add_cpe_values(
                host,
                "ports.port:%s" % port.get("port", -1),
                [f"cpe:/a:elasticsearch:kibana:{version}"],
            )
        script = {"id": "http-app", "output": output, "http-app": [structured]}
        try:
            cur_script = next(
                s for s in port.get("scripts", []) if s["id"] == "http-app"
            )
        except StopIteration:
            port.setdefault("scripts", []).append(script)
        else:
            merge_http_app_scripts(cur_script, script, "http-app")


load_plugins("ivre.plugins.active.data", globals())
