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

"""Handles data from (US) GovCloud, based on
<https://github.com/daehee/govcloud/> (but we do not use code or data
from this repository).

"""


import json
import os
import re
from typing import List, Tuple

from ivre import VERSION, config
from ivre.utils import build_opener, download_if_newer, make_range_tables, net2range

AZURE_URL = re.compile(b'<a href="(https://download.microsoft.com/download/[^"]*)"')


def get_azure_url() -> str:
    opener = build_opener()
    opener.addheaders = [("User-Agent", "IVRE/%s +https://ivre.rocks/" % VERSION)]
    with opener.open(
        "https://www.microsoft.com/en-us/download/confirmation.aspx?id=57063"
    ) as udesc:
        for line in udesc:
            match = AZURE_URL.search(line)
            if match is None:
                continue
            return match.group(1).decode()
    raise ValueError("URL for Azure US Government Cloud not found")


def get_all_files() -> float:
    assert config.DATA_PATH is not None
    most_recent = 0.0
    fname = os.path.join(config.DATA_PATH, "govcloud_azure.json")
    download_if_newer(get_azure_url(), fname)
    most_recent = max(most_recent, os.stat(fname).st_mtime)
    fname = os.path.join(config.DATA_PATH, "govcloud_aws.json")
    download_if_newer("https://ip-ranges.amazonaws.com/ip-ranges.json", fname)
    most_recent = max(most_recent, os.stat(fname).st_mtime)
    return most_recent


def build_table() -> List[Tuple[str, str, List[str]]]:
    assert config.DATA_PATH is not None
    all_ranges = []

    # Azure
    with open(
        os.path.join(config.DATA_PATH, "govcloud_azure.json"), encoding="utf8"
    ) as fdesc:
        all_entries = json.load(fdesc)["values"]
    for entry in all_entries:
        data = []
        properties = entry.get("properties", {})
        for fld, name in [
            ("platform", "Platform"),
            ("region", "Region"),
            ("systemService", "Service"),
        ]:
            if properties.get(fld):
                data.append(f"{name}: {properties[fld]}")
        data = sorted(data)
        for net in properties.get("addressPrefixes", []):
            start, stop = net2range(net)
            all_ranges.append((start, stop, data))

    # AWS
    with open(
        os.path.join(config.DATA_PATH, "govcloud_aws.json"), encoding="utf8"
    ) as fdesc:
        all_entries = json.load(fdesc)["prefixes"]
    for entry in all_entries:
        if not entry.get("region", "").startswith("us-gov-"):
            continue
        start, stop = net2range(entry["ip_prefix"])
        data = ["Platform: AWS"]
        for fld, name in [("region", "Region"), ("service", "Service")]:
            if entry.get(fld):
                data.append(f"{name}: {entry[fld]}")
        data = sorted(data)
        all_ranges.append((start, stop, data))

    return all_ranges


def fetch_and_build() -> None:
    assert config.DATA_PATH is not None
    most_recent = get_all_files()
    fname = os.path.join(config.DATA_PATH, "govcloud.py")
    try:
        current = os.stat(fname).st_mtime
    except FileNotFoundError:
        current = 0.0
    if current > most_recent:
        return
    table = make_range_tables(build_table())
    with open(fname, "w", encoding="utf8") as fdesc:
        fdesc.write("[\n    (\n")
        fdesc.writelines(f"        {elt[0]!r},\n" for elt in table)
        fdesc.write("    ),\n    (\n")
        fdesc.writelines(f"        {elt[1]!r},\n" for elt in table)
        fdesc.write("    ),\n]\n")
