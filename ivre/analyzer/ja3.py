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


import hashlib
from typing import Any, Dict, List, Optional


try:
    from scapy.layers.tls.record import TLS  # type: ignore
except ImportError:
    HAS_SCAPY = False
else:
    HAS_SCAPY = True


from ivre import utils


# https://tools.ietf.org/html/draft-davidben-tls-grease-01
GREASE = {
    2570,
    6682,
    10794,
    14906,
    19018,
    23130,
    27242,
    31354,
    35466,
    39578,
    43690,
    47802,
    51914,
    56026,
    60138,
    64250,
}


def banner2ja3c(banner: bytes) -> Optional[str]:
    if not HAS_SCAPY:
        utils.LOGGER.warning("Scapy not found: cannot parse TLS banners")
        return None
    data = TLS(banner)
    try:
        if data.type != 22:  # handshake
            return None
    except AttributeError:
        return None
    output = []
    for msg in data.msg:
        try:
            if msg.msgtype != 1:  # TLSClientHello
                continue
        except AttributeError:
            utils.LOGGER.warning("Cannot parse TLS message [%r]", msg)
            continue
        output.append(str(msg.version))
        output.append("-".join(str(c) for c in msg.ciphers or [] if c not in GREASE))
        output.append(
            "-".join(str(e.type) for e in msg.ext or [] if e.type not in GREASE)
        )
        ecsg: List[str] = []
        ecpf: List[str] = []
        for ext in msg.ext or []:
            if ext.type == 10:  # supported_groups / elliptic_curves
                ecsg.extend(str(g) for g in ext.groups if g not in GREASE)
            elif ext.type == 11:  # ec_point_formats
                ecpf.extend(str(p) for p in ext.ecpl if p not in GREASE)
        output.append("-".join(ecsg))
        output.append("-".join(ecpf))
        break
    if not output:
        return None
    return ",".join(output)


def banner2script(banner: bytes) -> Optional[Dict[str, Any]]:
    ja3c = banner2ja3c(banner)
    if not ja3c:
        return None
    structured = {"raw": ja3c}
    script: Dict[str, Any] = {"id": "ssl-ja3-client"}
    for hashtype in ["md5", "sha1", "sha256"]:
        structured[hashtype] = hashlib.new(hashtype, ja3c.encode()).hexdigest()
    script["output"] = structured["md5"]
    script["ssl-ja3-client"] = [structured]
    return script
