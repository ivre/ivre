#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
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

# The comment lines "Begin XXX" and "End XXX" are used to include
# parts of this files in the documentation.


import os
import stat
from typing import Dict, Generator, List, Optional


from ivre.types import NmapScanTemplate


# Default values:
DEBUG = False
DEBUG_DB = False
DB = "mongodb:///ivre"
DB_DATA = None  # specific: maxmind:///<ivre_share_path>/geoip
# Begin batch sizes
LOCAL_BATCH_SIZE = 10000  # used with --local-bulk
MONGODB_BATCH_SIZE = 100
POSTGRES_BATCH_SIZE = 10000
# End batch sizes
# specific: if no value is specified for *_PATH variables, they are
# going to be constructed by guessing the installation PREFIX (see the
# end of this file).
DATA_PATH = None
GEOIP_PATH = None
HONEYD_IVRE_SCRIPTS_PATH = None
WEB_STATIC_PATH = None
WEB_DOKU_PATH = None
AGENT_MASTER_PATH = "/var/lib/ivre/master"
# specific: if no value is specified, tries /usr/local/share/nmap,
# /opt/nmap/share/nmap, then /usr/share/nmap; same for wireshark.
NMAP_SHARE_PATH = None
WIRESHARK_SHARE_PATH = None
# Begin commands
TESSERACT_CMD = "tesseract"
OPENSSL_CMD = "openssl"
# End commands

# Begin default Nmap scan template
NMAP_SCAN_TEMPLATES: Dict[str, NmapScanTemplate] = {
    "default": {
        # Commented values are default values and to not need to be
        # specified:
        # "nmap": "nmap",
        # "pings": "SE",
        # "scans": "SV",
        # "osdetect": True,
        # "traceroute": True,
        # "resolve": 1,
        # "verbosity": 2,
        # "ports": None,
        # "top_ports": None,
        "host_timeout": "15m",  # default value: None
        "script_timeout": "2m",  # default value: None
        "scripts_categories": ["default", "discovery", "auth"],  # default value: None
        "scripts_exclude": [
            "broadcast",
            "brute",
            "dos",
            "exploit",
            "external",
            "fuzzer",
            "intrusive",
        ],  # default value: None
        # "scripts_force": None,
        # "extra_options": None,
    }
}
# End default Nmap scan template

# Begin DNSBL
# Domains used for DNS blacklists (RFC 5782)
DNS_BLACKLIST_DOMAINS = set(
    [
        "blacklist.woody.ch",
        "zen.spamhaus.org",
    ]
)
# End DNSBL

# Begin flows
# Dictionary that helps determine server ports of communications. Each entry
# is {proto: {port: proba}}. The when two ports are known, the port with the
# highest probability is used.
# When /usr/share/nmap/nmap-services is available, these probas are taken,
# otherwise /etc/services is used with proba=0.5 for each entry.
# KNOWN_PORTS entries have the highest priority.
# Example:
#  KNOWN_PORTS = {
#      "udp": {
#          9999: 1.0,
#          12345: 0.5,
#      },
#      "tcp": {
#          20202: 0.8,
#      },
#  }
KNOWN_PORTS: Dict[str, Dict[int, float]] = {}
# Enable the recording of appearance times for flows. Will slow down a
# bit the insertion rate
FLOW_TIME = True
# Precision (in seconds) to use when recording times when flows appear
FLOW_TIME_PRECISION = 3600
# When recording flow times, record the whole range from start_time to end_time
# This option is experimental and possibly useless in practice
FLOW_TIME_FULL_RANGE = True
# When recording flow times, represents the beginning of the first timeslot
# as a Unix timestamp shifted to local time.
# 0 means that the first timeslot starts at 1970-01-01 00:00 (Local time).
FLOW_TIME_BASE = 0
# Store high level protocols metadata in flows. It may take much more space.
FLOW_STORE_METADATA = True
# End flows

# Begin IPDATA_URLS
IPDATA_URLS = {
    # None has a special meaning:
    # https://download.maxmind.com/app/geoip_download?edition_id=XXX&suffix=XXX&license_key=XXX
    #
    # You can use this value for the GeoLite2-* files (and set
    # MAXMIND_LICENSE_KEY below) to download files from MaxMind
    # instead of ivre.rocks directly. Maxmind license keys are free
    # and can be obtained from <https://www.maxmind.com/>
    "GeoLite2-City.tar.gz": "https://ivre.rocks/data/geolite/GeoLite2-City.tar.gz",
    "GeoLite2-City-CSV.zip": "https://ivre.rocks/data/geolite/GeoLite2-City-CSV.zip",
    "GeoLite2-Country.tar.gz": "https://ivre.rocks/data/geolite/GeoLite2-Country.tar.gz",
    "GeoLite2-Country-CSV.zip": "https://ivre.rocks/data/geolite/GeoLite2-Country-CSV.zip",
    "GeoLite2-ASN.tar.gz": "https://ivre.rocks/data/geolite/GeoLite2-ASN.tar.gz",
    "GeoLite2-ASN-CSV.zip": "https://ivre.rocks/data/geolite/GeoLite2-ASN-CSV.zip",
    # For other files, None has a special meaning "do not
    # download". The following file can be computed based the
    # GeoLite2-* files using `ivre ipdata --import-all`. You should do
    # that if you get your files from Maxmind.
    "GeoLite2-dumps.tar.gz": "https://ivre.rocks/data/geolite/GeoLite2-dumps.tar.gz",
    "iso3166.csv": "https://dev.maxmind.com/csv-files/codes/iso3166.csv",
    # This one is not from maxmind -- see http://thyme.apnic.net/
    "BGP.raw": "http://thyme.apnic.net/current/data-raw-table",
}
MAXMIND_LICENSE_KEY = None
# End IPDATA_URLS

GEOIP_LANG = "en"

# Some IP ranges send syn-ack answers for any
# port. VIEW_SYNACK_HONEYPOT_COUNT is the number of open ports with
# only syn-ack (no script, no service identified). The value you need
# to set here highly depends on the number of ports you usually scan
# and/or see.
#
# The default value, 200 seems high enough to work fine with most
# situations. None means that no host should be treated as a "syn-ack
# honeypot".
VIEW_SYNACK_HONEYPOT_COUNT = 200

WEB_ALLOWED_REFERERS = None
WEB_NOTES_BASE = "/dokuwiki/#IP#"
WEB_MAXRESULTS = None
WEB_WARN_DOTS_COUNT = 20000
WEB_GET_NOTEPAD_PAGES = None
WEB_LIMIT = 10
WEB_GRAPH_LIMIT = 1000
# access control disabled by default:
WEB_INIT_QUERIES: Dict[str, str] = {}
# Warning: None means no access control, and is equivalent to "full"
WEB_DEFAULT_INIT_QUERY = None
# upload disabled by default
WEB_UPLOAD_OK = False
# Is this a public server? This setting affects result uploading and
# access control.
# When this is set to True:
#   1. The user will, by default, only access to results that are either
#      in the "Shared" category or that he has uploaded.
#   2. The upload page, if enabled, is modified to explain that
WEB_PUBLIC_SRV = False
# Feed with a random value, like `openssl rand -base64 42`.
# *Mandatory* when WEB_PUBLIC_SRV == True
WEB_SECRET = None


def get_config_file(paths: Optional[List[str]] = None) -> Generator[str, None, None]:
    """Generates (yields) the available config files, in the correct order."""
    if paths is None:
        paths = [
            os.path.join(path, "ivre.conf")
            for path in ["/etc", "/etc/ivre", "/usr/local/etc", "/usr/local/etc/ivre"]
        ]
        paths.append(os.path.join(os.path.expanduser("~"), ".ivre.conf"))
        if "IVRE_CONF" in os.environ:
            paths.append(os.environ["IVRE_CONF"])
    for path in paths:
        if os.path.isfile(path):
            yield path


for fname in get_config_file():
    # pylint: disable=exec-used
    with open(fname, "rb") as fdesc:
        exec(compile(fdesc.read(), fname, "exec"))


def guess_prefix(directory: Optional[str] = None) -> Optional[str]:
    """Attempts to find the base directory where IVRE components are
    installed.

    """

    def check_candidate(path: str, directory: Optional[str] = None) -> Optional[str]:
        """Auxiliary function that checks whether a particular path is a good
        candidate.

        """
        candidate = os.path.join(path, "share", "ivre")
        if directory is not None:
            candidate = os.path.join(candidate, directory)
        try:
            if stat.S_ISDIR(os.stat(candidate).st_mode):
                return candidate
        except OSError:
            pass
        return None

    if __file__.startswith("/"):
        path = "/"
        # absolute path
        for elt in __file__.split(os.path.sep)[1:]:
            if elt in ["lib", "lib32", "lib64"]:
                candidate = check_candidate(path, directory=directory)
                if candidate is not None:
                    return candidate
            path = os.path.join(path, elt)
    for path in ["/usr", "/usr/local", "/opt", "/opt/ivre"]:
        candidate = check_candidate(path, directory=directory)
        if candidate is not None:
            return candidate
    return None


def guess_share(soft: str) -> Optional[str]:
    for path in [
        "/usr/local/share/%s" % soft,
        "/opt/%s/share/%s" % (soft, soft),
        "/usr/share/%s" % soft,
    ]:
        if os.path.isdir(path):
            return path
    return None


if GEOIP_PATH is None:
    GEOIP_PATH = guess_prefix("geoip")


if DB_DATA is None and GEOIP_PATH is not None:
    DB_DATA = "maxmind:///%s" % GEOIP_PATH


if DATA_PATH is None:
    DATA_PATH = guess_prefix("data")


if WEB_STATIC_PATH is None:
    WEB_STATIC_PATH = guess_prefix(directory="web/static")


if WEB_DOKU_PATH is None:
    WEB_DOKU_PATH = guess_prefix(directory="dokuwiki")


if HONEYD_IVRE_SCRIPTS_PATH is None and DATA_PATH is not None:
    HONEYD_IVRE_SCRIPTS_PATH = os.path.join(DATA_PATH, "honeyd")


if NMAP_SHARE_PATH is None:
    NMAP_SHARE_PATH = guess_share("nmap")


if WIRESHARK_SHARE_PATH is None:
    WIRESHARK_SHARE_PATH = guess_share("wireshark")
