#! /usr/bin/env python

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

"""This tool's output can be used with the tool fastgcd (available
here: https://factorable.net/resources.html) to efficiently perform
the attack described in the paper "Mining your Ps and Qs: Detection of
Widespread Weak Keys in Network Devices"
(https://factorable.net/paper.html).

To do so, you need to strip the output from the information after the
moduli. A simple sed with 's# .*##' will do the trick."""


import getopt
import sys
from typing import Dict, Set, Tuple, Type, Union


import ivre.db
import ivre.keys
import ivre.utils


def main() -> None:
    # FIXME: this will not work if .nmap and .passive have different
    # backends
    bases: Set[Type[Union[ivre.keys.PassiveKey, ivre.keys.NmapKey]]] = set()
    try:
        opts, _ = getopt.getopt(
            sys.argv[1:],
            "p:h",
            ["passive-ssl", "active-ssl", "passive-ssh", "active-ssh", "help"],
        )
    except getopt.GetoptError as err:
        sys.stderr.write(str(err) + "\n")
        sys.exit(-1)
    for o, a in opts:
        if o == "--passive-ssl":
            bases.add(ivre.keys.SSLRsaPassiveKey)
        elif o == "--active-ssl":
            bases.add(ivre.keys.SSLRsaNmapKey)
        elif o == "--passive-ssh":
            bases.add(ivre.keys.SSHRsaPassiveKey)
        elif o == "--active-ssh":
            bases.add(ivre.keys.SSHRsaNmapKey)
        elif o in ["-h", "--help"]:
            sys.stdout.write(
                "usage: %s [-h] [--passive-ssl] [--active-ssl] "
                "[--passive-ssh] [--active-ssh]\n\n" % sys.argv[0]
            )
            sys.stdout.write(__doc__)
            sys.stdout.write("\n\n")
            sys.exit(0)
        else:
            sys.stderr.write(
                "%r %r not understood (this is probably a bug).\n" % (o, a)
            )
            sys.exit(-1)
    moduli: Dict[int, Set[Tuple[str, int, str]]] = {}
    if not bases:
        bases = {
            ivre.keys.SSLRsaPassiveKey,
            ivre.keys.SSLRsaNmapKey,
            ivre.keys.SSHRsaNmapKey,
            ivre.keys.SSHRsaPassiveKey,
        }
    for base in bases:
        for key in base():
            moduli.setdefault(key.key.public_numbers().n, set()).add(
                (key.ip, key.port, key.service)
            )
    for mod, used in moduli.items():
        sys.stdout.write(
            "%x %d %s\n"
            % (
                mod,
                len(used),
                ",".join("%s:%d" % (rec[0], rec[1]) for rec in used),
            )
        )
