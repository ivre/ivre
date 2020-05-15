#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2020 Pierre LALET <pierre@droids-corp.org>
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


__all__ = set([
    'airodump2db',
    'arp2db',
    'auditdom',
    'db2view',
    'flow2db',
    'flowcli',
    'getmoduli',
    'httpd',
    'ipcalc',
    'ipdata',
    'ipinfo',
    'iphost',
    'macinfo',
    'passiverecon2db',
    'passivereconworker',
    'plotdb',
    'runscans',
    'runscansagent',
    'runscansagentdb',
    'scan2db',
    'scancli',
    'scanstatus',
    'version',
    'view',
    'zeek2db',
])


ALIASES = {
    "bro2db": "zeek2db",
    "httpd-ivre": "httpd",
    "ipinfohost": "iphost",
    "runscans-agent": "runscansagent",
    "runscans-agentdb": "runscansagentdb",
    "nmap2db": "scan2db",
}


def get_command(name):
    if name in __all__:
        return getattr(__import__("%s.%s" % (__name__, name)).tools, name).main
    if name in ALIASES:
        name = ALIASES[name]
        return getattr(__import__("%s.%s" % (__name__, name)).tools, name).main
    return None


def guess_command(name):
    if name in __all__:
        return [name]
    possible = set(cmd for cmd in __all__ if cmd.startswith(name))
    if possible:
        return possible
    if name in ALIASES:
        return [name]
    return set(cmd for cmd in ALIASES if cmd.startswith(name))
