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

"""This submodule contains functions to manipulate CPE values for
documents from the active (nmap & view) purposes.

"""

from typing import Any

from ivre.types import CpeDict
from ivre.utils import LOGGER


def cpe2dict(cpe_str: str) -> CpeDict:
    """Helper function to parse CPEs. Supports both 2.2 (`cpe:/...`) and
    2.3 (`cpe:2.3:...`) formats. This is a very partial/simple parser.

    Raises:
        ValueError if the cpe string is not parsable.

    """
    if cpe_str.startswith("cpe:2.3:"):
        cpe_body = cpe_str[8:]
    elif cpe_str.startswith("cpe:/"):
        cpe_body = cpe_str[5:]
    else:
        raise ValueError("invalid cpe format (%s)\n" % cpe_str)
    # Keep anything after the version field grouped together to avoid losing
    # update/edition components present in 2.2/2.3 strings.
    parts = cpe_body.split(":", 3)
    if len(parts) < 2:
        raise ValueError("invalid cpe format (%s)\n" % cpe_str)
    parts += [""] * (4 - len(parts))
    cpe_type, cpe_vend, cpe_prod, cpe_vers = parts[:4]

    ret: CpeDict = {
        "type": cpe_type,
        "vendor": cpe_vend,
        "product": cpe_prod,
        "version": cpe_vers,
    }
    return ret


def add_cpe_values(hostrec: dict[str, Any], path: str, cpe_values: list[str]) -> None:
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
