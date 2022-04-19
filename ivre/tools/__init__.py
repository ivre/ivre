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


"""This sub-module contains functions to implement ivre commands."""

from collections.abc import Callable
from itertools import chain
from typing import cast

from ivre.plugins import load_plugins

__all__ = [
    "airodump2db",
    "arp2db",
    "auditdom",
    "db2view",
    "flow2db",
    "flowcli",
    "getmoduli",
    "getwebdata",
    "httpd",
    "ipcalc",
    "ipdata",
    "ipinfo",
    "iphost",
    "localscan",
    "macdata",
    "macinfo",
    "p0f2db",
    "passiverecon2db",
    "passivereconworker",
    "plotdb",
    "rirlookup",
    "runscans",
    "runscansagent",
    "runscansagentdb",
    "scan2db",
    "scancli",
    "scanstatus",
    "sort",
    "version",
    "view",
    "weblog2db",
    "zeek2db",
]


ALIASES = {
    "bro2db": "zeek2db",
    "httpd-ivre": "httpd",
    "ipinfohost": "iphost",
    "runscans-agent": "runscansagent",
    "runscans-agentdb": "runscansagentdb",
    "nmap2db": "scan2db",
}


PLUGINS: dict[str, Callable[[], None]] = {}


def get_command(name: str) -> Callable[[], None] | None:
    if name in __all__:
        return cast(
            Callable[[], None],
            getattr(__import__("%s.%s" % (__name__, name)).tools, name).main,
        )
    if name in ALIASES:
        name = ALIASES[name]
        return cast(
            Callable[[], None],
            getattr(__import__("%s.%s" % (__name__, name)).tools, name).main,
        )
    if name in PLUGINS:
        return PLUGINS[name]
    return None


def guess_command(name: str) -> list[str]:
    if name in __all__:
        return [name]
    if name in ALIASES:
        return [name]
    if name in PLUGINS:
        return [name]
    possible = sorted({cmd for cmd in chain(__all__, PLUGINS) if cmd.startswith(name)})
    if possible:
        return possible
    return sorted(set(cmd for cmd in ALIASES if cmd.startswith(name)))


load_plugins("ivre.plugins.tools", globals())
