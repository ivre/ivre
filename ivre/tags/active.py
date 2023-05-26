#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2023 Pierre LALET <pierre@droids-corp.org>
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

"""This submodule contains functions to handle tags in active (nmap &
view) records.

For the sake of code "simplicity", this sub-module also handles the
`openports` attribute of active records.

"""


import re
from collections import Counter
from typing import Generator, cast

from ivre.config import VIEW_MAX_HOSTNAMES_COUNT, VIEW_SYNACK_HONEYPOT_COUNT
from ivre.data.abuse_ch.sslbl import SSLBL_CERTIFICATES, SSLBL_JA3
from ivre.tags import (
    TAG_CDN,
    TAG_DEFAULT_PASSWORD,
    TAG_HONEYPOT,
    TAG_MALWARE,
    TAG_SCANNER,
    TAG_TOR,
    TAG_VULN,
    TAG_VULN_CANNOT_TEST,
    TAG_VULN_LIKELY,
    add_tags,
    gen_addr_tags,
    gen_hostname_tags,
)
from ivre.types import Tag
from ivre.types.active import NmapHost, NmapPort
from ivre.utils import TORCERT_SUBJECT

_SERVICE_FIELDS = [
    "service_name",
    "service_product",
    "service_version",
    "service_extrainfo",
]
_TOR_SERVICES = {
    "tor",
    "tor-control",
    "tor-info",
    "tor-orport",
    "tor-socks",
}
_TOR_HTTP_PRODUCTS = {
    "Tor directory",
    "Tor directory server",
    "Tor built-in httpd",
}


BIG_IP_ERROR_BANNER = re.compile("^BIG-IP: \\[0x[0-9a-f]{7}:[0-9]{1,5}\\] ")
SONICWALL_ERROR_BANNER = re.compile("^\\(Ref.Id: \\?.*\\?\\)$")


def is_synack_honeypot(host: NmapHost) -> bool:
    """Returns True iff the host has the "Honeypot" tag with "SYN+ACK
    honeypot" info.

    """
    return any(
        tag["value"] == "Honeypot" and "SYN+ACK honeypot" in tag.get("info", [])
        for tag in host.get("tags", [])
    )


def has_toomany_hostnames(host: NmapHost) -> bool:
    """Returns True iff the host has the "Too many hostnames" tag."""
    return any(
        tag["value"] == "CDN" and "Too many hostnames" in tag.get("info", [])
        for tag in host.get("tags", [])
    )


def gen_auto_tags(
    host: NmapHost, update_openports: bool = True
) -> Generator[Tag, None, None]:
    """This function generates the automatically-generated tags ("TOR",
    "Scanner", "Honeypot" and "Vulnerable" / "Likely vulnerable" /
    "Cannot test vuln", for now).

    If the host has too many (at least `VIEW_SYNACK_HONEYPOT_COUNT`)
    open ports that may be "syn-ack" honeypots (which means, ports for
    which is_real_service_port() returns False), this function will
    generate the "Honeypot" / "SYN+ACK honeypot" tag **and** clean the
    `host` record from the probable "SYN+ACK honeypot" ports.

    If the "ports" field of the host document has changed, the
    "openports" field is updated unless `update_openports` is False.

    """
    addr = host.get("addr")
    if addr is not None:
        yield from gen_addr_tags(addr)
    for hname in host.get("hostnames", []):
        yield from gen_hostname_tags(hname["name"])
    if (
        VIEW_MAX_HOSTNAMES_COUNT
        and len(host.get("hostnames", [])) > VIEW_MAX_HOSTNAMES_COUNT
    ):
        del host["hostnames"]
        yield cast(Tag, dict(TAG_CDN, info=["Too many hostnames"]))
    for port in host.get("ports", []):
        if any("honeypot" in port.get(field, "").lower() for field in _SERVICE_FIELDS):
            cur_info = []
            for fld in _SERVICE_FIELDS:
                if fld in port:
                    cur_info.append(port[fld])
            yield cast(
                Tag,
                dict(
                    TAG_HONEYPOT,
                    info=[
                        f"{' / '.join(cur_info)} on port {port['protocol']}/{port['port']}"
                    ],
                ),
            )
        if port.get("service_name") in _TOR_SERVICES:
            yield cast(
                Tag,
                dict(
                    TAG_TOR,
                    info=[
                        f"Service {port['service_name']} found on port {port['protocol']}/{port['port']}"
                    ],
                ),
            )
        elif port.get("service_name") == "ssl":
            if port.get("service_product") == "Tor over SSL":
                yield cast(
                    Tag,
                    dict(
                        TAG_TOR,
                        info=[
                            f"ssl / {port['service_product']} found on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                )
        elif port.get("service_name") == "http":
            if port.get("service_product") in _TOR_HTTP_PRODUCTS:
                yield cast(
                    Tag,
                    dict(
                        TAG_TOR,
                        info=[
                            f"http / {port['service_product']} found on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                )
        for script in port.get("scripts", []):
            if script["id"] == "ssl-cert":
                for cert in script.get("ssl-cert", []):
                    if cert.get("sha1") in SSLBL_CERTIFICATES:
                        yield cast(
                            Tag,
                            dict(
                                TAG_MALWARE,
                                info=[
                                    f"{SSLBL_CERTIFICATES[cert['sha1']]} certificate on port {port['protocol']}/{port['port']} (SSL Blacklist by abuse.ch)"
                                ],
                            ),
                        )
                    elif (
                        TORCERT_SUBJECT.search(cert.get("subject_text", ""))
                        and TORCERT_SUBJECT.search(cert.get("issuer_text", ""))
                        and cert.get("subject_text") != cert.get("issuer_text")
                    ):
                        yield cast(
                            Tag,
                            dict(
                                TAG_TOR,
                                info=[
                                    f"TOR certificate on port {port['protocol']}/{port['port']}"
                                ],
                            ),
                        )
            elif script["id"] == "ssl-ja3-client":
                for ja3fp in script.get("ssl-ja3-client", []):
                    if ja3fp.get("md5") in SSLBL_JA3:
                        yield cast(
                            Tag,
                            dict(
                                TAG_MALWARE,
                                info=[
                                    f"{SSLBL_JA3[ja3fp['md5']]} JA3 client fingerprint (SSL Blacklist by abuse.ch)"
                                ],
                            ),
                        )
            elif script["id"] == "http-title":
                tag = {
                    "This is a Tor Exit Router": dict(
                        TAG_TOR,
                        info=[
                            f"TOR exit node notice on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                    "This is a SOCKS Proxy, Not An HTTP Proxy": dict(
                        TAG_TOR,
                        info=[
                            f"TOR SOCKS Proxy notice on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                    "This is an HTTP CONNECT tunnel, not a full HTTP Proxy": dict(
                        TAG_TOR,
                        info=[
                            f"TOR HTTP CONNECT tunnel notice on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                }.get(script["output"])
                if tag is not None:
                    yield cast(Tag, tag)
            elif script["id"] == "scanner":
                if port["port"] != -1:
                    continue
                scanners = sorted(
                    set(
                        scanner["name"]
                        for scanner in script.get("scanner", {}).get("scanners", [])
                    )
                )
                if scanners:
                    yield cast(Tag, dict(TAG_SCANNER, info=scanners))
                else:
                    yield TAG_SCANNER
            elif script["id"] == "http-default-accounts":
                for app in script.get("http-default-accounts", []):
                    if not app.get("credentials"):
                        continue
                    creds = [
                        f"{cred['username']} / {cred['password']}"
                        for cred in app["credentials"]
                    ]
                    yield cast(
                        Tag,
                        dict(
                            TAG_DEFAULT_PASSWORD,
                            info=[f"{app['name']}: {', '.join(creds)}"],
                        ),
                    )
            elif "vulns" in script:
                for vuln in script["vulns"]:
                    state = vuln.get("state", "")
                    if state.startswith("VULNERABLE"):
                        if "id" in vuln:
                            yield cast(Tag, dict(TAG_VULN, info=[vuln["id"]]))
                        else:
                            yield TAG_VULN
                    elif state.startswith("LIKELY VULNERABLE"):
                        if "id" in vuln:
                            yield cast(Tag, dict(TAG_VULN_LIKELY, info=[vuln["id"]]))
                        else:
                            yield TAG_VULN_LIKELY
                    elif state.startswith("UNKNOWN"):
                        if "id" in vuln:
                            yield cast(
                                Tag, dict(TAG_VULN_CANNOT_TEST, info=[vuln["id"]])
                            )
                        else:
                            yield TAG_VULN_CANNOT_TEST
            elif "nuclei" in script:
                for template in script["nuclei"]:
                    template_id = template.get("template", "")
                    template_name = template.get("name", "")
                    info = (
                        template_id
                        if template_id == template_name
                        else f"{template_id} / {template_name}"
                    )
                    if template_id.startswith("CVE-"):
                        yield cast(Tag, dict(TAG_VULN, info=[info]))
                    elif template_name.startswith("CVE-"):
                        yield cast(Tag, dict(TAG_VULN, info=[info]))
                    elif any(
                        template_id.endswith(f"-{suffix}")
                        for suffix in [
                            "default-login",
                            "weak-login",
                            "weak-password",
                            "default-admin",
                        ]
                    ) or template_id in {
                        "google-earth-dlogin",
                        "oracle-business-intelligence-login",
                        "trilithic-viewpoint-default",
                    }:
                        yield cast(Tag, dict(TAG_DEFAULT_PASSWORD, info=[info]))
                    elif template_name.endswith("Default Password"):
                        yield cast(Tag, dict(TAG_DEFAULT_PASSWORD, info=[info]))
    # Now the "Honeypot" / "SYN+ACK honeypot" tag:
    n_ports = sum(
        1 for port in host.get("ports", []) if port.get("state_state") == "open"
    )
    if n_ports and is_synack_honeypot(host):
        # 1. If the host is already considered a SYN+ACK honeypot,
        # let's just clean the ports
        newports = [
            port
            for port in host["ports"]
            if port.get("state_state") != "open" or is_real_service_port(port)
        ]
        if n_ports != sum(1 for port in newports if port.get("state_state") == "open"):
            host["ports"] = newports
            if update_openports:
                set_openports_attribute(host)
    # 2. ... Else, let's see if we should add the tag
    elif (
        VIEW_SYNACK_HONEYPOT_COUNT is not None and n_ports >= VIEW_SYNACK_HONEYPOT_COUNT
    ):
        # check if we have too many open ports that could be "syn-ack
        # honeypots"...
        newports = [
            port
            for port in host["ports"]
            if port.get("state_state") != "open" or is_real_service_port(port)
        ]
        if (
            n_ports - sum(1 for port in newports if port.get("state_state") == "open")
            > VIEW_SYNACK_HONEYPOT_COUNT
        ):
            # ... if so, keep only the ports that cannot be "syn-ack
            # honeypots"
            host["ports"] = newports
            if update_openports:
                set_openports_attribute(host)
        yield cast(Tag, dict(TAG_HONEYPOT, info=["SYN+ACK honeypot"]))
    # Now the "closed" / "filtered" ports. Note: this won't create any
    # tag but it is probably the best place to have this code!
    clean_nonopen_ports(host)


def clean_nonopen_ports(host: NmapHost) -> None:
    for status in ["closed", "filtered"]:
        n_ports = sum(
            1 for port in host.get("ports", []) if port.get("state_state") == status
        )
        if status in host.get("extraports", {}):
            # 1. If the host already has too many ports in `status`,
            # let's just update and clean the ports
            host["extraports"][status]["total"] += n_ports
            reasons = Counter(
                port.get("state_reason")
                for port in host.get("ports", [])
                if port.get("state_state") == status and port.get("state_reason")
            )
            for reason, count in reasons.items():
                host["extraports"][status].setdefault("reasons", {})[reason] = (
                    host["extraports"][status].get("reasons", {}).get(reason, 0) + count
                )
            if host.get("ports"):
                host["ports"] = [
                    port for port in host["ports"] if port.get("state_state") != status
                ]
        # 2. ... Else, let's see if we should remove some ports in
        # `status`.
        elif (
            VIEW_SYNACK_HONEYPOT_COUNT is not None
            and n_ports >= VIEW_SYNACK_HONEYPOT_COUNT
        ):
            host.setdefault("extraports", {})[status] = {"total": n_ports}
            reasons = Counter(
                port.get("state_reason")
                for port in host.get("ports", [])
                if port.get("state_state") == status and port.get("state_reason")
            )
            for reason, count in reasons.items():
                host["extraports"][status].setdefault("reasons", {})[reason] = count
            if host.get("ports"):
                host["ports"] = [
                    port for port in host["ports"] if port.get("state_state") != status
                ]


def set_auto_tags(host: NmapHost, update_openports: bool = True) -> None:
    """This function sets the automatically-generated tags ("TOR",
    "Scanner", "Honeypot" and "Vulnerable" / "Likely vulnerable" /
    "Cannot test vuln", for now).

    """
    add_tags(host, gen_auto_tags(host, update_openports=update_openports))


def is_real_service_port(port: NmapPort) -> bool:
    """Decides whether a port has a "real" service (=> True) or if it is
    **possibly** a SYN-ACK "honeypot" (=> False).

    The idea is that a port is "real" if it has a reason that is not
    "syn-ack" (or similar), or if it has a service_name, or if it has a
    least one script.

    Host scripts (port == -1) are also considered True.

    """
    if port.get("port") == -1:
        return True
    if port.get("state_reason") and not (
        # might be "syn-ack" but might as
        # well be "syn-ack-cwr" or
        # "syn-psh-ack"
        port["state_reason"].startswith("syn-")
        or port["state_reason"] == "passive"
    ):
        return True
    if port.get("service_name") and port["service_name"] != "tcpwrapped":
        return True
    if port.get("scripts"):
        # Ports with scripts usually are "real" service ports, **but**
        # when a port only has a banner script, the output of which
        # matches a known SYN-ACK responder answser, we consider it is
        # **possibly** a SYN-ACK "honeypot" (or responder) and return
        # False
        if len(port["scripts"]) == 1 and port["scripts"][0]["id"] == "banner":
            banner = port["scripts"][0]["output"]
            if banner == "\n":
                return False
            if BIG_IP_ERROR_BANNER.search(banner):
                return False
            if SONICWALL_ERROR_BANNER.search(banner):
                return False
        return True
    return False


def set_openports_attribute(host: NmapHost) -> None:
    """This function sets the "openports" value in the `host` record,
    based on the elements of the "ports" list. This is used in MongoDB to
    speed up queries based on open ports.

    """
    openports = host["openports"] = {"count": 0}
    for port in host.get("ports", []):
        if port.get("state_state") != "open":
            continue
        cur = openports.setdefault(port["protocol"], {"count": 0, "ports": []})
        if port["port"] not in cur["ports"]:
            openports["count"] += 1
            cur["count"] += 1
            cur["ports"].append(port["port"])
