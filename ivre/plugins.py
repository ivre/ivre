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


"""Tools to handle IVRE plugins."""


from typing import Any, Dict

try:
    from importlib.metadata import entry_points
except ImportError:
    HAS_PLUGINS = False
else:
    HAS_PLUGINS = True


def load_plugins(group: str, scope: Dict[str, Any]) -> None:
    try:
        my_entry_points = entry_points(group=group)
    except TypeError:
        my_entry_points = entry_points().get(group, [])  # type: ignore
    for entry_point in my_entry_points:
        if entry_point.name.startswith("_install_"):
            entry_point.load()(scope)
