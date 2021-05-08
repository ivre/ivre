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


"""Generate scan results (XML or JSON) from local commands such as
netstat or ss

"""

import argparse
from datetime import datetime
import json
import re
import subprocess
import sys

from ivre.activecli import displayfunction_nmapxml
from ivre import utils


class LocalPorts:

    cmd_addrs = ["ip", "addr", "show"]
    cmd_openports = ["ss", "-ltunp"]
    match_addrs = re.compile("^ +inet (?P<addr>[0-9\\.]+)/")
    match_openports = re.compile(
        "^(?P<proto>tcp|udp) +(?P<state>[A-Z-]+) +[0-9]+ +[0-9]+ +(?P<addr>[0-9\\.]+):(?P<port>[0-9]+) +"
        + re.escape("0.0.0.0:*")
        + ' +(users:\\(\\("(?P<progname>[^"]*)",pid=[0-9]+,fd=[0-9]+\\)\\))?'
    )

    def get_addrs(self):
        for line in subprocess.Popen(self.cmd_addrs, stdout=subprocess.PIPE).stdout:
            m = self.match_addrs.search(line.decode())
            if m is None:
                continue
            m = m.groupdict()
            yield m["addr"]

    def parse(self):
        addresses = set(self.get_addrs())
        results = {}
        for line in subprocess.Popen(self.cmd_openports, stdout=subprocess.PIPE).stdout:
            m = self.match_openports.search(line.decode())
            if m is None:
                continue
            m = m.groupdict()
            if {"tcp": "LISTEN", "udp": "UNCONN"}[m["proto"]] != m["state"]:
                print("Weird state %(state)s (proto %(proto)s)" % m)  # XXX warn
            for addr in addresses if m["addr"] == "0.0.0.0" else [m["addr"]]:
                progs = results.setdefault(addr, {}).setdefault(
                    (m["proto"], int(m["port"])), set()
                )
                if m["progname"] is not None:
                    progs.add(m["progname"])
        return results

    def get_scan_results(self):
        starttime = datetime.now()
        results = sorted(self.parse().items(), key=lambda a_p: utils.ip2int(a_p[0]))
        endtime = datetime.now()
        for addr, ports in results:
            rec = {"addr": addr, "starttime": starttime, "endtime": endtime}
            for (proto, port), progs in sorted(ports.items()):
                port = {"protocol": proto, "port": port}
                if progs:
                    port["scripts"] = [
                        {
                            "id": "localscan",
                            "output": "Program%s: %s"
                            % ("s" if len(progs) > 1 else "", ", ".join(sorted(progs))),
                            "localscan": {"programs": sorted(progs)},
                        },
                    ]
                rec.setdefault("ports", []).append(port)
            yield rec


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="Output as JSON rather than XML."
    )
    args = parser.parse_args()
    if args.json:

        def displayfunction(cur):
            for rec in cur:
                json.dump(rec, sys.stdout, default=utils.serialize)
                sys.stdout.write("\n")

    else:
        displayfunction = displayfunction_nmapxml
    displayfunction(LocalPorts().get_scan_results())
