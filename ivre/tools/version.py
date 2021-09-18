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


"""Display IVRE's version"""


import os
import sys


from ivre import VERSION


def main() -> None:
    """Display IVRE's version"""
    print("IVRE - Network recon framework")
    print("Copyright 2011 - 2020 Pierre LALET <pierre@droids-corp.org>")
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
        "pymongo",
        "sqlalchemy",
        "psycopg2",
        "cryptography",
        "krbV",
        "pycurl",
        "PIL",
        "MySQLdb",
        "dbus",
        "matplotlib",
        "bottle",
        "OpenSSL",
        "tinydb",
    ]:
        try:
            version = __import__(module).__version__
        except AttributeError:
            try:
                version = __import__(module).version
            except AttributeError:
                version = "[unknown version]"
        except ImportError:
            print("    Python module %s: missing" % (module,))
            continue
        print("    Python module %s: %s" % (module, version))
    print()
