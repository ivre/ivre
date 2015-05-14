#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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

"""
This module is part of IVRE.
Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>

This sub-module handles configuration values.

It contains the (hard-coded) default values, which can be overwritten
by ~/.ivre.conf, /usr/local/etc/ivre.conf and/or /etc/ivre.conf.

"""

from ivre import utils

import os

# Default values:
DB = "mongodb:///ivre"
BULK_UPSERTS_MAXSIZE = 100
DEBUG = False
# specific: if no value is specified for *_PATH variables, they are
# going to be constructed by guessing the installation PREFIX (see the
# end of this file).
GEOIP_PATH = None
HONEYD_IVRE_SCRIPTS_PATH = None
AGENT_MASTER_PATH = "/var/lib/ivre/master"
NMAP_CMD = "nmap"
NMAP_SCAN_TYPE = ['sS', 'A']
NMAP_PING_TYPE = ['PS', 'PE']
NMAP_VERBOSITY = 2
NMAP_RESOLVE_LEVEL = 1
NMAP_PORTSPEC = "normal"
NMAP_OPT_PORTS = {
    'fast': ['-F'],
    'normal': [],
    'more': ['--top-ports', '2000'],
    'all': ['-p', '-'],
}
NMAP_HOST_TIMEOUT = "15m"
NMAP_SCRIPT_CATEGORIES = ['default', 'discovery', 'auth']
NMAP_SCRIPT_EXCLUDE = [
    # Categories we don't want
    'broadcast', 'brute', 'dos', 'exploit', 'external', 'fuzzer',
    'intrusive',
]
NMAP_SCRIPT_FORCE = []
NMAP_EXTRA_OPTIONS = None
TESSERACT_CMD = "tesseract"


def get_config_file(paths=None):
    """Generates (yields) the available config files, in the correct order."""
    if paths is None:
        paths = [os.path.join(path, 'ivre.conf')
                 for path in ['/etc', '/usr/local/etc']]
        paths.append(os.path.join(os.path.expanduser('~'), '.ivre.conf'))
    for path in paths:
        if os.path.isfile(path):
            yield path

for f in get_config_file():
    execfile(f)

if GEOIP_PATH is None:
    GEOIP_PATH = utils.guess_prefix('geoip')

if HONEYD_IVRE_SCRIPTS_PATH is None:
    HONEYD_IVRE_SCRIPTS_PATH = utils.guess_prefix('honeyd')
