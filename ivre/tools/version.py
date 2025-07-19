#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2025 Pierre LALET <pierre@droids-corp.org>
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


"""Display IVRE's version"""


import os
import sys

from ivre import VERSION
from ivre.plugins import get_version, list_plugins


def main() -> None:
    """Display IVRE's version"""
    print("IVRE - Network recon framework")
    print("Copyright 2011 - 2025 Pierre LALET <pierre@droids-corp.org>")
    print("Version %s" % VERSION)
    print()
    print("Python %s" % sys.version)
    print()
    try:
        print(" ".join(str(elt) for elt in os.uname()))
    except AttributeError:
        # Windows OS don't have os.uname()
        print(sys.platform)
    print()
    print("Dependencies:")
    for module in [
        "MySQLdb",
        "OpenSSL",
        "PIL",
        "bottle",
        "cryptography",
        "dbus",
        "krbV",
        "matplotlib",
        "psycopg2",
        "pycurl",
        "pymongo",
        "sqlalchemy",
        "tinydb",
        "elasticsearch",
        "elasticsearch_dsl",
    ]:
        version = get_version(module)
        if version is None:
            version = "*missing*"
        print(f"    {module}: {version}")
    print()
    cat_plugins = list_plugins()
    if cat_plugins:
        print("Plugins:")
        for cat in sorted(cat_plugins):
            print(f"    {cat}:")
            plugins = cat_plugins[cat]
            for plugin, version in plugins:
                print(f"        {plugin}: {version}")
        print()
