#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
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

"""This sub-module handles configuration values.

It contains the (hard-coded) default values, which can be overwritten
by ~/.ivre.conf, /usr/local/etc/ivre/ivre.conf,
/usr/local/etc/ivre.conf, /etc/ivre/ivre.conf and/or
/etc/ivre.conf.

"""

import os
import stat

# Default values:
DB = "mongodb:///ivre"
DB_FLOW = "neo4j://neo4j:neo4j@localhost:7474/"
BULK_UPSERTS_MAXSIZE = 100
NEO4J_BATCH_SIZE = 1000
POSTGRES_BATCH_SIZE = 10000
DEBUG = False
DEBUG_DB = False
# specific: if no value is specified for *_PATH variables, they are
# going to be constructed by guessing the installation PREFIX (see the
# end of this file).
DATA_PATH = None
GEOIP_PATH = None
HONEYD_IVRE_SCRIPTS_PATH = None
AGENT_MASTER_PATH = "/var/lib/ivre/master"
TESSERACT_CMD = "tesseract"
GZ_CMD = "zcat"
BZ2_CMD = "bzcat"
MD5_CMD = "md5sum"
SHA1_CMD = "sha1sum"
SHA256_CMD = "sha256sum"
# specific: if no value is specified, tries /usr/local/share/<soft>,
# /opt/<soft>/share/<soft>, then /usr/share/<soft>.
NMAP_SHARE_PATH = None

# Default Nmap scan template, see below how to add templates:
NMAP_SCAN_TEMPLATES = {
    "default": {
        ## Commented values are default values and to not need to be
        ## specified
        #"nmap": "nmap",
        #"pings": "SE",
        #"scans": "SV",
        #"osdetect": True,
        #"traceroute": True,
        #"resolve": 1,
        #"verbosity": 2,
        #"ports": None,
        "host_timeout": "15m", # default value: None
        "scripts_categories": ['default', 'discovery',
                               'auth'], # default value: None
        "scripts_exclude": ['broadcast', 'brute', 'dos',
                            'exploit', 'external', 'fuzzer',
                            'intrusive'], # default value: None
        #"scripts_force": None,
        #"extra_options": None,
    }
}

## Example: to define an "aggressive" template that "inherits" from
## the default template and runs more scripts with a more important
## host timeout value, add the following lines to your ivre.conf,
## uncommented of course.
# NMAP_SCAN_TEMPLATES["aggressive"] = NMAP_SCAN_TEMPLATES["default"].copy()
# NMAP_SCAN_TEMPLATES["aggressive"].update({
#     "host_timeout": "30m",
#     "scripts_categories": ['default', 'discovery', 'auth', 'brute',
#                            'exploit', 'intrusive'],
#     "scripts_exclude": ['broadcast', 'external']
# })

## Dictionary that helps determine server ports of communications. Each entry is
## {proto: {port: proba}}. The when two ports are known, the port with the
## highest probability is used.
## When /usr/share/nmap/nmap-services is available, these probas are taken,
## otherwise /etc/services is used with proba=0.5 for each entry.
## KNOWN_PORTS entries have the highest priority.
## Example:
#  KNOWN_PORTS = {
#      "udp": {
#          9999: 1.0,
#          12345: 0.5,
#      },
#      "tcp": {
#          20202: 0.8,
#      },
#  }
KNOWN_PORTS = {}

# Enable the recording of appearance times for flows. Will slow down a bit the
# insertion rate
FLOW_TIME = True
# Precision (in seconds) to use when recording times when flows appear
FLOW_TIME_PRECISION = 3600
# When recording flow times, record the whole range from start_time to end_time
# This option is experimental and possibly useless in practice
FLOW_TIME_FULL_RANGE = False

WEB_ALLOWED_REFERERS = None
WEB_NOTES_BASE = "/dokuwiki/#IP#"
WEB_MAXRESULTS = None
WEB_WARN_DOTS_COUNT = 20000
WEB_GET_NOTEPAD_PAGES = None
WEB_LIMIT = 10
WEB_GRAPH_LIMIT = 1000
# access control disabled by default:
WEB_INIT_QUERIES = {}
# Warning: None means no access control, and is equivalent to "full"
WEB_DEFAULT_INIT_QUERY = None
# upload disabled by default
WEB_UPLOAD_OK = False
# Is this a public server? This setting affects result uploading and
# access control
## When this is set to True:
### 1. The user will, by default, only access to results that are either
###    in the "Shared" category or that he has uploaded.
### 2. The upload page, if enabled, is modified to explain that
WEB_PUBLIC_SRV = False
# Feed with a random value, like `openssl rand -base64 42`.
# *Mandatory* when WEB_PUBLIC_SRV == True
WEB_SECRET = None

## Basic ACL example
# WEB_INIT_QUERIES = {
#     'admin': 'full',
#     'admin-site-a': 'category:site-a',
#     'admin-scanner-a': 'source:scanner-a',
# }
# WEB_DEFAULT_INIT_QUERY = 'noaccess'

## More complex ACL example with realm handling
# WEB_INIT_QUERIES = {
#     "admin": 'full',
#     "@admin.sitea": 'category:sitea',
# )
# WEB_DEFAULT_INIT_QUERY = 'noaccess'

def get_config_file(paths=None):
    """Generates (yields) the available config files, in the correct order."""
    if paths is None:
        paths = [os.path.join(path, 'ivre.conf')
                 for path in ['/etc', '/etc/ivre', '/usr/local/etc',
                              '/usr/local/etc/ivre']]
        paths.append(os.path.join(os.path.expanduser('~'), '.ivre.conf'))
    for path in paths:
        if os.path.isfile(path):
            yield path

for fname in get_config_file():
    execfile(fname)

def guess_prefix(directory=None):
    """Attempts to find the base directory where IVRE components are
    installed.

    """
    def check_candidate(path, directory=None):
        """Auxilliary function that checks whether a particular
        path is a good candidate.

        """
        candidate = os.path.join(path, 'share', 'ivre')
        if directory is not None:
            candidate = os.path.join(candidate, directory)
        try:
            if stat.S_ISDIR(os.stat(candidate).st_mode):
                return candidate
        except OSError:
            pass
    if __file__.startswith('/'):
        path = '/'
        # absolute path
        for elt in __file__.split('/')[1:]:
            if elt in ['lib', 'lib32', 'lib64']:
                candidate = check_candidate(path, directory=directory)
                if candidate is not None:
                    return candidate
            path = os.path.join(path, elt)
    for path in ['/usr', '/usr/local', '/opt', '/opt/ivre']:
        candidate = check_candidate(path, directory=directory)
        if candidate is not None:
            return candidate

def guess_share(soft):
    for path in ['/usr/local/share/%s' % soft,
                 '/opt/%s/share/%s' % (soft, soft),
                 '/usr/share/%s' % soft]:
        if os.path.isdir(path):
            return path

if GEOIP_PATH is None:
    GEOIP_PATH = guess_prefix('geoip')

if DATA_PATH is None:
    DATA_PATH = guess_prefix('data')

if HONEYD_IVRE_SCRIPTS_PATH is None and DATA_PATH is not None:
    HONEYD_IVRE_SCRIPTS_PATH = os.path.join(DATA_PATH, 'honeyd')

if NMAP_SHARE_PATH is None:
    NMAP_SHARE_PATH = guess_share('nmap')
