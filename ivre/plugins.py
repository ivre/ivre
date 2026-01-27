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

from typing import Any

try:
    from importlib import import_module
    from importlib.metadata import entry_points
except ImportError:
    HAS_PLUGINS = False
else:
    HAS_PLUGINS = True


CATEGORIES = [
    "active.data",
    "db",
    "db.elastic",
    "db.mongo",
    "tags",
    "tags.active",
    "tools",
    "view",
]


def load_plugins(group: str, scope: dict[str, Any]) -> None:
    if not HAS_PLUGINS:
        return
    try:
        my_entry_points = entry_points(group=group)
    except TypeError:
        my_entry_points = entry_points().get(group, [])  # type: ignore
    for entry_point in my_entry_points:
        if entry_point.name.startswith("_install_"):
            entry_point.load()(scope)


def get_version(module: str) -> str | None:
    try:
        mod = import_module(module)
    except ImportError:
        return None
    for attr in ["__version__", "VERSION", "version"]:
        try:
            data = getattr(mod, attr)
        except AttributeError:
            continue
        if isinstance(data, tuple):
            return ".".join(str(value) for value in data)
        return str(data)
    return "[unknown version]"


def list_plugins() -> dict[str, list[tuple[str, str | None]]]:
    if not HAS_PLUGINS:
        return {}
    modules: dict[str, set[str]] = {}
    for category in CATEGORIES:
        group = f"ivre.plugins.{category}"
        try:
            my_entry_points = entry_points(group=group)
        except TypeError:
            my_entry_points = entry_points().get(group, [])  # type: ignore
        for entry_point in my_entry_points:
            modules.setdefault(category, set()).add(entry_point.module)
    return {
        category: sorted((module, get_version(module)) for module in sorted(modules))
        for category, modules in modules.items()
    }
