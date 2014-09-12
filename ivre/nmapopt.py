#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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
Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>

This sub-module is responsible for generating Nmap options.
"""

from ivre import config, utils

import shlex

try:
    import argparse
    argparser = argparse.ArgumentParser(add_help=False)
    USING_ARGPARSE = True
except ImportError:
    argparser = utils.FakeArgparserParent()
    USING_ARGPARSE = False

argparser.add_argument('--nmap-cmd', metavar='CMD',
                       help="select Nmap's command", default=config.NMAP_CMD)
argparser.add_argument('--nmap-scan-types', metavar='SCANTYPE',
                       nargs='+', default=config.NMAP_SCAN_TYPE)
argparser.add_argument('--nmap-ping-types', metavar='PINGTYPE',
                       nargs='+', default=config.NMAP_PING_TYPE)
argparser.add_argument('--nmap-verbosity', metavar='LEVEL', type=int,
                       help="select Nmap's verbosity level (default: 2)",
                       default=config.NMAP_VERBOSITY)
if USING_ARGPARSE:
    argparser.add_argument('--resolve', metavar='LEVEL', type=int,
                           choices=[0, 1, 2],
                           help="Host resolution level "
                           "(default: 1 -- sometimes)",
                           default=config.NMAP_RESOLVE_LEVEL)
else:
    argparser.add_argument('--resolve', metavar='LEVEL', type=int,
                           help="Host resolution level "
                           "(default: 1 -- sometimes)",
                           default=config.NMAP_RESOLVE_LEVEL)
argparser.add_argument('--nmap-ports', metavar="PORTSPEC",
                       default=config.NMAP_PORTSPEC)
argparser.add_argument('--nmap-host-timeout', metavar='TIME',
                       default=config.NMAP_HOST_TIMEOUT)
argparser.add_argument('--nmap-script-categories', metavar='CAT', nargs='*',
                       default=config.NMAP_SCRIPT_CATEGORIES)
argparser.add_argument('--nmap-script-exclude', metavar='SCRIPT/CAT',
                       nargs='*',
                       default=config.NMAP_SCRIPT_EXCLUDE)
argparser.add_argument('--nmap-script-force', metavar='SCRIPT/CAT', nargs='*',
                       default=config.NMAP_SCRIPT_FORCE)
argparser.add_argument('--nmap-extra-options', metavar='OPTIONS',
                       default=config.NMAP_EXTRA_OPTIONS)


def build_nmap_options(args):
    options = [args.nmap_cmd]
    options.extend('-%s' % x for x in args.nmap_scan_types)
    options.extend('-%s' % x for x in args.nmap_ping_types)
    if args.nmap_verbosity:
        options.append('-' + 'v' * args.nmap_verbosity)
    if args.resolve == 0:
        options.append('-n')
    elif args.resolve == 2:
        options.append('-R')
    options += config.NMAP_OPT_PORTS.get(args.nmap_ports,
                                         ['-p', args.nmap_ports])
    if args.nmap_host_timeout.lower() not in ['0', 'no']:
        options += ['--host-timeout', args.nmap_host_timeout]
    scripts = ''
    if args.nmap_script_categories and args.nmap_script_categories != ['']:
        scripts = ' or '.join(args.nmap_script_categories)
    if args.nmap_script_exclude and args.nmap_script_exclude != ['']:
        scripts = '(%s) and ' % scripts if scripts else ''
        scripts += 'not (%s)' % ' or '.join(args.nmap_script_exclude)
    if args.nmap_script_force and args.nmap_script_force != ['']:
        scripts = '(%s) or ' % scripts if scripts else ''
        scripts += ' or '.join(args.nmap_script_force)
    if scripts:
        options.append('--script=%s' % scripts)
    if args.nmap_extra_options is not None:
        options += shlex.split(args.nmap_extra_options)
    return options
