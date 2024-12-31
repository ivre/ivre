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
    """Parse a CPE string (2.2 or 2.3) into a dictionary.

    Supports:
    - CPE 2.2 format: cpe:/<type>:<vendor>:<product>:<version>
    - CPE 2.3 format: cpe:2.3:<type>:<vendor>:<product>:<version>:...

    Raises:
        ValueError: If the CPE string is invalid or unsupported.
    """
    # Initialize default values
    cpe_data = CpeDict(type="", vendor="", product="", version="")

    if cpe_str.startswith("cpe:2.3:"):
        # CPE 2.3: Remove 'cpe:2.3:' and split
        parts = cpe_str[8:].split(":")
    elif cpe_str.startswith("cpe:/"):
        # CPE 2.2: Remove 'cpe:/' and split
        parts = cpe_str[5:].split(":")
    else:
        raise ValueError(f"Unsupported CPE format: {cpe_str}")

    # Ensure the required fields exist
    if len(parts) < 2:
        raise ValueError(f"Invalid CPE format: {cpe_str}")

    # Remove wildcard elements (*) after the version field
    parts = parts[:4]  # Limit to 'type', 'vendor', 'product', 'version'
    # Assign values from the parsed parts
    for key, value in zip(cpe_data.keys(), parts):
        cpe_data[key] = value

    return cpe_data


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
