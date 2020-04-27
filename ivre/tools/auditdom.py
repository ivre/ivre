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


"""Audit a DNS domain to produce an XML or JSON result similar to an
Nmap script result."""


import argparse
from collections import namedtuple
from datetime import datetime
import json
import pipes
import subprocess
import sys
try:
    reload(sys)
except NameError:
    pass
else:
    sys.setdefaultencoding('utf-8')


from future.utils import viewitems


from ivre import VERSION
from ivre.activecli import displayfunction_nmapxml
from ivre.utils import LOGGER, get_domains
from ivre.xmlnmap import SCHEMA_VERSION


nsrecord = namedtuple('nsrecord', ['name', 'ttl', 'rclass', 'rtype', 'data'])


def _dns_do_query(name, rtype=None, srv=None):
    cmd = ['dig', '+noquestion', '+nocomments', '+nocmd', '+nostat']
    if rtype:
        cmd.extend(['-t', rtype])
    cmd.append(name)
    if srv:
        cmd.append('@%s' % srv)
    for line in subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout:
        line = line.decode()[:-1]
        if line and line[:1] != ';':
            try:
                yield nsrecord(*line.split(None, 4))
            except TypeError:
                LOGGER.warning('Cannot read line %r', line)


def _dns_query(name, rtype=None, srv=None, getall=False, getfull=False):
    for ans in _dns_do_query(name, rtype=rtype, srv=srv):
        if ans.rclass == 'IN' and (getall or (rtype is None) or
                                   (ans.rtype == rtype)):
            if getfull:
                yield ans
            else:
                yield ans.data


class Checker(object):

    def __init__(self, domain):
        self.domain = domain

    @property
    def ns_servers(self):
        try:
            return self._ns
        except AttributeError:
            self._ns = list(_dns_query(self.domain, rtype='NS'))
            return self._ns

    @property
    def ns4_servers(self):
        try:
            return self._ns4
        except AttributeError:
            self._ns4 = list((srv, addr)
                             for srv in self.ns_servers
                             for addr in _dns_query(srv, rtype='A'))
            return self._ns4

    @property
    def ns6_servers(self):
        try:
            return self._ns6
        except AttributeError:
            self._ns6 = list((srv, addr)
                             for srv in self.ns_servers
                             for addr in _dns_query(srv, rtype='AAAA'))
            return self._ns6

    def do_test(self, v4=True, v6=True):
        servers = []
        if v4:
            servers.append(self.ns4_servers)
        if v6:
            servers.append(self.ns6_servers)
        for srvlist in servers:
            for srv, addr in srvlist:
                yield (srv, addr, self._test(addr))


class AXFRChecker(Checker):

    def _test(self, addr):
        return list(_dns_query(self.domain, rtype='AXFR', srv=addr,
                               getall=True, getfull=True))

    def test(self, v4=True, v6=True):
        start = datetime.now()
        for srvname, addr, res in self.do_test(v4=v4, v6=v6):
            srvname = srvname.rstrip('.')
            if not res:
                continue
            if (
                    len(res) == 1 and
                    res[0].rtype == 'SOA'
            ):
                # SOA only: transfer failed
                continue
            LOGGER.info('AXFR success for %r on %r', self.domain, addr)
            line_fmt = "| %%-%ds  %%-%ds  %%s" % (
                max(len(r.name) for r in res),
                max(len(r.rtype) for r in res),
            )
            yield {
                "addr": addr,
                "hostnames": [{"name": srvname, "type": "user",
                               "domains": list(get_domains(srvname))}],
                "schema_version": SCHEMA_VERSION,
                "starttime": start,
                "endtime": datetime.now(),
                "ports": [{"port": 53, "protocol": "tcp",
                           "service_name": "domain", "state_state": "open",
                           "scripts": [{
                               "id": "dns-zone-transfer",
                               "output": '\nDomain: %s\n%s\n\\\n' % (
                                   self.domain,
                                   '\n'.join(
                                       line_fmt % (r.name, r.rtype, r.data)
                                       for r in res
                                   ),
                               ),
                               "dns-zone-transfer": [
                                   {"domain": self.domain,
                                    "records": [
                                        {"name": r.name,
                                         "ttl": r.ttl,
                                         "class": r.rclass,
                                         "type": r.rtype,
                                         "data": r.data}
                                        for r in res
                                    ]}
                               ]
                           }]}],
            }
            hosts = {}
            for r in res:
                if r.rclass != 'IN':
                    continue
                if r.rtype in ['A', 'AAAA']:
                    name = r.name.rstrip('.')
                    hosts.setdefault(r.data, set()).add((r.rtype, name))
            for host, records in viewitems(hosts):
                yield {
                    "addr": host,
                    "hostnames": [{"name": rec[1], "type": rec[0],
                                   "domains": list(get_domains(rec[1]))}
                                  for rec in records],
                    "schema_version": SCHEMA_VERSION,
                    "starttime": start,
                    "endtime": datetime.now()
                }
            start = datetime.now()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON rather than XML.')
    parser.add_argument('--ipv4', '-4', action='store_true',
                        help='Use only IPv4.')
    parser.add_argument('--ipv6', '-6', action='store_true',
                        help='Use only IPv6.')
    parser.add_argument('domains', metavar='DOMAIN', nargs='+',
                        help='domains to check')
    args = parser.parse_args()
    if args.json:
        def displayfunction(cur, scan=None):
            if scan is not None:
                LOGGER.debug("Scan not displayed in JSON mode")
            for rec in cur:
                print(json.dumps(rec))
    else:
        displayfunction = displayfunction_nmapxml
    # we create a list so that we can know the start and stop time
    start = datetime.now()
    scan = {
        "scanner": "ivre auditdom",
        "start": start.strftime('%s'),
        "startstr": str(start),
        "version": VERSION,
        "xmloutputversion": "1.04",
        # argv[0] does not need quotes due to how it is handled by ivre
        "args": " ".join(sys.argv[:1] +
                         [pipes.quote(arg) for arg in sys.argv[1:]]),
        "scaninfos": [{"type": "audit DNS domain", "protocol": "dig",
                       "numservices": 1, "services": "53"}],
    }
    results = [
        rec
        for domain in args.domains
        for test in [AXFRChecker]
        for rec in test(domain).test(v4=not args.ipv6, v6=not args.ipv4)
    ]
    end = datetime.now()
    scan["end"] = end.strftime('%s')
    scan["endstr"] = str(end)
    scan["elapsed"] = str((end - start).total_seconds())
    displayfunction(results, scan=scan)
