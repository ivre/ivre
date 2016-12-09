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

"""This sub-module is responsible for generating Nmap options."""

from ivre import config

import shlex

try:
    import argparse
    argparser = argparse.ArgumentParser(add_help=False)
    USING_ARGPARSE = True
except ImportError:
    from ivre import utils
    argparser = utils.FakeArgparserParent()
    USING_ARGPARSE = False

if USING_ARGPARSE:
    argparser.add_argument('--nmap-template', help="Select Nmap scan template",
                           choices=config.NMAP_SCAN_TEMPLATES,
                           default="default")

NMAP_OPT_PORTS = {
    None: [],
    'fast': ['-F'],
    'more': ['--top-ports', '2000'],
    'all': ['-p', '-'],
}

class Scan(object):
    def __init__(self, nmap="nmap", pings='SE', scans='SV', osdetect=True,
                 traceroute=True, resolve=1, verbosity=2, ports=None,
                 host_timeout=None, scripts_categories=None,
                 scripts_exclude=None, scripts_force=None,
                 extra_options=None):
        self.nmap = nmap
        self.pings = set(pings)
        self.scans = set(scans)
        self.osdetect = osdetect
        self.traceroute = traceroute
        self.resolve = resolve
        self.verbosity = verbosity
        self.ports = ports
        self.host_timeout = host_timeout
        if scripts_categories is None:
            self.scripts_categories = []
        else:
            self.scripts_categories = scripts_categories
        if scripts_exclude is None:
            self.scripts_exclude = []
        else:
            self.scripts_exclude = scripts_exclude
        if scripts_force is None:
            self.scripts_force = []
        else:
            self.scripts_force = scripts_force
        self.extra_options = extra_options
    @property
    def options(self):
        options = [self.nmap]
        # use -A instead of many options when possible
        if (('C' in self.scans or self.scripts_categories or
             self.scripts_exclude or self.scripts_force) and
            'V' in self.scans and self.osdetect and self.traceroute):
            options.append('-A')
            self.scans.difference_update('CV')
            self.osdetect = False
            self.traceroute = False
        # build --script value based on self.scripts_*
        scripts = ''
        if self.scripts_categories:
            scripts = ' or '.join(self.scripts_categories)
        if self.scripts_exclude:
            if scripts:
                scripts = '(%s) and not (%s)' % (
                    scripts if scripts else '',
                    ' or '.join(self.scripts_exclude)
                )
            else:
                scripts = 'not (%s)' % ' or '.join(self.scripts_exclude)
        if self.scripts_force:
            if scripts:
                scripts = '(%s) or %s' % (scripts if scripts else '',
                                          ' or '.join(self.scripts_force))
            else:
                scripts = ' or '.join(self.scripts_force)
        # remove unnecessary options
        if scripts == 'default':
            scripts = ''
            if '-A' not in options:
                self.scans.add('C')
        elif scripts and 'C' in self.scans:
            self.scans.remove('C')
        options.extend('-P%s' % x for x in self.pings)
        options.extend('-s%s' % x for x in self.scans)
        if self.osdetect:
            options.append('-O')
        if self.traceroute:
            options.append('--traceroute')
        if self.resolve == 0:
            options.append('-n')
        elif self.resolve == 2:
            options.append('-R')
        if self.verbosity:
            options.append('-%s' % ('v' * self.verbosity))
        options.extend(NMAP_OPT_PORTS.get(self.ports, ['-p', self.ports]))
        if self.host_timeout is not None:
            options.extend(['--host-timeout', self.host_timeout])
        if scripts:
            options.extend(['--script', scripts])
        if self.extra_options:
            options.extend(self.extra_options)
        return options

def build_nmap_options(args):
    return Scan(**config.NMAP_SCAN_TEMPLATES[args.nmap_template]).options
