#! /usr/bin/env python
# -*- coding: utf-8 -*-

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


import hashlib
from typing import Any, Dict, List, Optional, Tuple

from ivre import utils

HAS_SCAPY = None


# https://datatracker.ietf.org/doc/html/draft-ietf-tls-grease
GREASE = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}

JA4_VERSIONS = {
    0x0002: "s2",
    0x0300: "s3",
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
    0xFEFF: "d1",
    0xFEFD: "d2",
    0xFEFC: "d3",
}


def banner2ja34c(
    banner: bytes, protocol: str
) -> Optional[Tuple[str, str, str, str, str]]:
    # "lazy" import for scapy, as this import is slow.
    # TLS is assigned by the import statement, but pylint seems to miss it.
    global HAS_SCAPY, TLS
    if HAS_SCAPY is None:
        try:
            # noqa: E402
            # pylint: disable=import-outside-toplevel
            from scapy.layers.tls.record import TLS  # type: ignore
        except ImportError:
            HAS_SCAPY = False
        else:
            HAS_SCAPY = True
    if not HAS_SCAPY:
        utils.LOGGER.warning("Scapy not found: cannot parse TLS banners")
        return None
    data = TLS(banner)  # type: ignore  # pylint: disable=possibly-used-before-assignment
    try:
        if data.type != 22:  # handshake
            return None
    except AttributeError:
        return None
    output_ja3 = []
    for msg in data.msg:
        try:
            if msg.msgtype != 1:  # TLSClientHello
                continue
        except AttributeError:
            utils.LOGGER.warning("Cannot parse TLS message [%r]", msg)
            continue
        output_ja3.append(str(msg.version))
        ciphers = [c for c in msg.ciphers if c not in GREASE]
        output_ja3.append("-".join(str(c) for c in ciphers))
        exts = [e.type for e in msg.ext or [] if e.type not in GREASE]
        output_ja3.append("-".join(str(e) for e in exts))
        ecsg: List[int] = []
        ecpf: List[int] = []
        sni = "i"
        alpn = "00"
        version = msg.version
        signatures = []
        for ext in msg.ext or []:
            if ext.type == 0:  # sni
                if ext.servernames and not utils.is_valid_ip(ext.servernames[0].name):
                    sni = "d"
            elif ext.type == 10:  # supported_groups / elliptic_curves
                ecsg.extend(g for g in ext.groups if g not in GREASE)
            elif ext.type == 11:  # ec_point_formats
                ecpf.extend(p for p in ext.ecpl if p not in GREASE)
            elif ext.type == 13:  # signatures
                if ext.sig_algs:
                    signatures = [s for s in ext.sig_algs if s not in GREASE]
            elif ext.type == 16:  # ALPN
                if ext.protocols:
                    alpn = ext.protocols[0] + ext.protocols[-1]
                    if not alpn.isascii():
                        alpn = "99"
            elif ext.type == 43:  # supported_versions
                if ext.versions:
                    version = ext.versions[0]
        output_ja3.append("-".join(str(v) for v in ecsg))
        output_ja3.append("-".join(str(v) for v in ecpf))
        output_ja4_a = f"{protocol}{JA4_VERSIONS.get(version, '??')}{sni}{min(len(ciphers), 99)}{min(len(exts), 99)}{alpn}"
        output_ja4_b = ",".join("%04x" % c for c in sorted(ciphers))
        output_ja4_c1 = ",".join("%04x" % c for c in sorted(exts) if c not in {0, 16})
        output_ja4_c2 = ",".join("%04x" % c for c in signatures)
        break
    if not output_ja3:
        return None
    return (
        ",".join(output_ja3),
        output_ja4_a,
        output_ja4_b,
        output_ja4_c1,
        output_ja4_c2,
    )


def banner2scripts(
    banner: bytes,
    protocol: Optional[str] = None,
    service: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    try:
        output_ja3, output_ja4_a, output_ja4_b, output_ja4_c1, output_ja4_c2 = (
            banner2ja34c(
                banner,
                (
                    "t"
                    if protocol == "tcp"
                    else "q" if protocol == "udp" and service == "quic" else "?"
                ),
            )
        )
    except TypeError:
        return None
    structured_ja3 = {"raw": output_ja3}
    for hashtype in ["md5", "sha1", "sha256"]:
        structured_ja3[hashtype] = hashlib.new(
            hashtype, output_ja3.encode()
        ).hexdigest()
    script_ja3 = {
        "id": "ssl-ja3-client",
        "output": structured_ja3["md5"],
        "ssl-ja3-client": [structured_ja3],
    }
    ja4_b = hashlib.new("sha256", data=output_ja4_b.encode()).hexdigest()[:12]
    ja4_c = hashlib.new(
        "sha256", data=f"{output_ja4_c1}_{output_ja4_c2}".encode()
    ).hexdigest()[:12]
    ja4 = f"{output_ja4_a}_{ja4_b}_{ja4_c}"
    script_ja4 = {
        "id": "ssl-ja4-client",
        "output": ja4,
        "ssl-ja4-client": [
            {
                "ja4": ja4,
                "ja4_a": output_ja4_a,
                "ja4_b": ja4_b,
                "ja4_b_raw": output_ja4_b,
                "ja4_c": ja4_c,
                "ja4_c1_raw": output_ja4_c1,
                "ja4_c2_raw": output_ja4_c2,
            }
        ],
    }
    return [script_ja3, script_ja4]
