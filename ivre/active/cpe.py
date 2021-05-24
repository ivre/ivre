#! /usr/bin/env python

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

"""This submodule contains functions to manipulate CPE values for
documents from the active (nmap & view) purposes.

"""


from typing import Any, Dict, List


from ivre.utils import LOGGER
from ivre.types import CpeDict


def cpe2dict(cpe_str: str) -> CpeDict:
    """Helper function to parse CPEs. This is a very partial/simple parser.

    Raises:
        ValueError if the cpe string is not parsable.

    """
    # Remove prefix
    if not cpe_str.startswith("cpe:/"):
        raise ValueError("invalid cpe format (%s)\n" % cpe_str)
    cpe_body = cpe_str[5:]
    parts = cpe_body.split(":", 3)
    nparts = len(parts)
    if nparts < 2:
        raise ValueError("invalid cpe format (%s)\n" % cpe_str)
    cpe_type = parts[0]
    cpe_vend = parts[1]
    cpe_prod = parts[2] if nparts > 2 else ""
    cpe_vers = parts[3] if nparts > 3 else ""

    ret: CpeDict = {
        "type": cpe_type,
        "vendor": cpe_vend,
        "product": cpe_prod,
        "version": cpe_vers,
    }
    return ret


def add_cpe_values(hostrec: Dict[str, Any], path: str, cpe_values: List[str]) -> None:
    """Add CPE values (`cpe_values`) to the `hostrec` at the given `path`.

    CPEs are indexed in a dictionary to agglomerate origins, but this dict
    is replaced with its values() in ._pre_addhost() or in
    .store_scan_json_zgrab(), or in the function that calls
    add_cpe_values(), depending on the context.

    """
    cpes = hostrec.setdefault("cpes", {})
    for cpe in cpe_values:
        if cpe not in cpes:
            try:
                cpeobj = cpe2dict(cpe)
            except ValueError:
                LOGGER.warning("Invalid cpe format (%s)", cpe)
                continue
            cpes[cpe] = cpeobj
        else:
            cpeobj = cpes[cpe]
        cpeobj.setdefault("origins", set()).add(path)
