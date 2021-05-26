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


"""Sub-module to run DNS checks."""


from ast import literal_eval
from collections import namedtuple
from datetime import datetime
import re
import subprocess
from typing import (
    Dict,
    FrozenSet,
    Generator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)


from ivre.types.active import NmapHost
from ivre.utils import LOGGER, get_domains
from ivre.xmlnmap import SCHEMA_VERSION


nsrecord = namedtuple("nsrecord", ["name", "ttl", "rclass", "rtype", "data"])


# URL parse - see https://stackoverflow.com/a/7160778
HTTPS_REGEXP = re.compile(
    r"^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::\d+)?"
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)
MAIL_REGEXP = re.compile(r"[^@]+@[^@]+\.[^@]+", re.IGNORECASE)


def _dns_do_query(
    name: str, rtype: Optional[str] = None, srv: Optional[str] = None
) -> Generator[nsrecord, None, None]:
    cmd = ["dig", "+noquestion", "+nocomments", "+nocmd", "+nostat"]
    if rtype:
        cmd.extend(["-t", rtype])
    cmd.append(name)
    if srv:
        cmd.append("@%s" % srv)
    with subprocess.Popen(cmd, stdout=subprocess.PIPE) as proc:
        assert proc.stdout is not None
        for line_bytes in proc.stdout:
            line = line_bytes.decode()[:-1]
            if line and line[:1] != ";":
                try:
                    yield nsrecord(*line.split(None, 4))
                except TypeError:
                    LOGGER.warning("Cannot read line %r", line)


def _dns_query_full(
    name: str,
    rtype: Optional[str] = None,
    srv: Optional[str] = None,
    getall: Optional[bool] = False,
) -> Generator[nsrecord, None, None]:
    for ans in _dns_do_query(name, rtype=rtype, srv=srv):
        if ans.rclass == "IN" and (getall or (rtype is None) or (ans.rtype == rtype)):
            yield ans


def _dns_query(
    name: str,
    rtype: Optional[str] = None,
    srv: Optional[str] = None,
    getall: Optional[bool] = False,
) -> Generator[str, None, None]:
    for ans in _dns_query_full(name, rtype=rtype, srv=srv, getall=getall):
        yield ans.data


class Checker:
    _ns: List[str]
    _ns4: List[Tuple[str, str]]
    _ns6: List[Tuple[str, str]]

    def __init__(self, domain: str) -> None:
        self.domain = domain

    @property
    def ns_servers(self) -> List[str]:
        try:
            return self._ns
        except AttributeError:
            self._ns = list(_dns_query(self.domain, rtype="NS"))
            return self._ns

    @property
    def ns4_servers(self) -> List[Tuple[str, str]]:
        try:
            return self._ns4
        except AttributeError:
            self._ns4 = list(
                (srv, addr)
                for srv in self.ns_servers
                for addr in _dns_query(srv, rtype="A")
            )
            return self._ns4

    @property
    def ns6_servers(self) -> List[Tuple[str, str]]:
        try:
            return self._ns6
        except AttributeError:
            self._ns6 = list(
                (srv, addr)
                for srv in self.ns_servers
                for addr in _dns_query(srv, rtype="AAAA")
            )
            return self._ns6

    def _test(self, addr: str) -> List[nsrecord]:
        raise NotImplementedError

    def test(self, v4: bool = True, v6: bool = True) -> Generator[NmapHost, None, None]:
        raise NotImplementedError

    def do_test(
        self, v4: bool = True, v6: bool = True
    ) -> Generator[Tuple[str, str, Sequence[nsrecord]], None, None]:
        servers = []
        if v4:
            servers.append(self.ns4_servers)
        if v6:
            servers.append(self.ns6_servers)
        for srvlist in servers:
            for srv, addr in srvlist:
                yield (srv, addr, self._test(addr))


class AXFRChecker(Checker):
    def _test(self, addr: str) -> List[nsrecord]:
        return list(_dns_query_full(self.domain, rtype="AXFR", srv=addr, getall=True))

    def test(self, v4: bool = True, v6: bool = True) -> Generator[NmapHost, None, None]:
        start = datetime.now()
        for srvname, addr, res in self.do_test(v4=v4, v6=v6):
            srvname = srvname.rstrip(".")
            if not res:
                continue
            if len(res) == 1 and res[0].rtype == "SOA":
                # SOA only: transfer failed
                continue
            LOGGER.info("AXFR success for %r on %r", self.domain, addr)
            line_fmt = "| %%-%ds  %%-%ds  %%s" % (
                max(len(r.name) for r in res),
                max(len(r.rtype) for r in res),
            )
            yield {
                "addr": addr,
                "hostnames": [
                    {
                        "name": srvname,
                        "type": "user",
                        "domains": list(get_domains(srvname)),
                    }
                ],
                "schema_version": SCHEMA_VERSION,
                "starttime": start,
                "endtime": datetime.now(),
                "ports": [
                    {
                        "port": 53,
                        "protocol": "tcp",
                        "service_name": "domain",
                        "state_state": "open",
                        "scripts": [
                            {
                                "id": "dns-zone-transfer",
                                "output": "\nDomain: %s\n%s\n\\\n"
                                % (
                                    self.domain,
                                    "\n".join(
                                        line_fmt % (r.name, r.rtype, r.data)
                                        for r in res
                                    ),
                                ),
                                "dns-zone-transfer": [
                                    {
                                        "domain": self.domain,
                                        "records": [
                                            {
                                                "name": r.name,
                                                "ttl": r.ttl,
                                                "class": r.rclass,
                                                "type": r.rtype,
                                                "data": r.data,
                                            }
                                            for r in res
                                        ],
                                    }
                                ],
                            },
                        ],
                    },
                ],
            }
            hosts: Dict[str, Set[Tuple[str, str]]] = {}
            for r in res:
                if r.rclass != "IN":
                    continue
                if r.rtype in ["A", "AAAA"]:
                    name = r.name.rstrip(".")
                    hosts.setdefault(r.data, set()).add((r.rtype, name))
            for host, records in hosts.items():
                yield {
                    "addr": host,
                    "hostnames": [
                        {
                            "name": rec[1],
                            "type": rec[0],
                            "domains": list(get_domains(rec[1])),
                        }
                        for rec in records
                    ],
                    "schema_version": SCHEMA_VERSION,
                    "starttime": start,
                    "endtime": datetime.now(),
                }
            start = datetime.now()


class SameValueChecker(Checker):
    name: Optional[str] = None
    rtype: Optional[str] = None

    def _sv_test(self, addr: str) -> FrozenSet[str]:
        assert self.name is not None
        return frozenset(_dns_query(self.name, rtype=self.rtype, srv=addr))

    def do_sv_test(
        self, v4: bool = True, v6: bool = True
    ) -> Generator[Tuple[str, str, FrozenSet[str]], None, None]:
        servers = []
        if v4:
            servers.append(self.ns4_servers)
        if v6:
            servers.append(self.ns6_servers)
        for srvlist in servers:
            for srv, addr in srvlist:
                yield (srv, addr, self._sv_test(addr))

    def test(self, v4: bool = True, v6: bool = True) -> Generator[NmapHost, None, None]:
        self.start = datetime.now()
        results: Dict[FrozenSet[str], Dict[str, List[str]]] = {}
        self.results = list(self.do_sv_test(v4=v4, v6=v6))
        for srvname, addr, res in self.results:
            srvname = srvname.rstrip(".")
            results.setdefault(res, {}).setdefault(addr, []).append(srvname)
        if len(results) < 1:
            return
        self.stop = datetime.now()
        good_value = max(results, key=lambda val: len(results[val]))
        good_value_repr = "\n".join("  %r" % r for r in sorted(good_value))
        good_value_sorted = sorted(good_value)
        for val, servers in results.items():
            if val == good_value:
                continue
            for addr, names in servers.items():
                yield {
                    "addr": addr,
                    "hostnames": [
                        {
                            "name": name,
                            "type": "user",
                            "domains": list(get_domains(name)),
                        }
                        for name in names
                    ],
                    "schema_version": SCHEMA_VERSION,
                    "starttime": self.start,
                    "endtime": self.stop,
                    "ports": [
                        {
                            "port": 53,
                            "protocol": "udp",
                            "service_name": "domain",
                            "state_state": "open",
                            "scripts": [
                                {
                                    "id": "dns-check-consistency",
                                    "output": "DNS inconsistency\n\n%s (%s)\nThis server:\n%s\nMost common answer:\n%s"
                                    % (
                                        self.name,
                                        self.rtype,
                                        "\n".join("  %r" % r for r in sorted(val)),
                                        good_value_repr,
                                    ),
                                    "dns-check-consistency": [
                                        {
                                            "domain": self.domain,
                                            "name": self.name,
                                            "rtype": self.rtype,
                                            "value": sorted(val),
                                            "reference_value": good_value_sorted,
                                        }
                                    ],
                                },
                            ],
                        }
                    ],
                }


class DNSSRVChecker(SameValueChecker):
    rtype = "NS"

    def __init__(self, domain: str) -> None:
        super().__init__(domain)
        self.name = domain

    def test(self, v4: bool = True, v6: bool = True) -> Generator[NmapHost, None, None]:
        yield from super().test(v4=v4, v6=v6)
        for srvname, addr, _ in self.results:
            srvname = srvname.rstrip(".")
            yield {
                "addr": addr,
                "hostnames": [
                    {
                        "name": srvname,
                        "type": "user",
                        "domains": list(get_domains(srvname)),
                    }
                ],
                "schema_version": SCHEMA_VERSION,
                "starttime": self.start,
                "endtime": self.stop,
                "ports": [
                    {
                        "port": 53,
                        "protocol": "udp",
                        "service_name": "domain",
                        "state_state": "open",
                        "scripts": [
                            {
                                "id": "dns-domains",
                                "output": "Server is authoritative for %s"
                                % self.domain,
                                "dns-domains": [
                                    {
                                        "domain": self.domain,
                                        "parents": list(get_domains(self.domain)),
                                    }
                                ],
                            },
                        ],
                    }
                ],
            }


class TLSRPTChecker(SameValueChecker):
    rtype = "TXT"

    def __init__(self, domain: str) -> None:
        super().__init__(domain)
        self.name = "_smtp._tls.%s" % domain

    def test(self, v4: bool = True, v6: bool = True) -> Generator[NmapHost, None, None]:
        yield from super().test(v4=v4, v6=v6)
        for srvname, addr, raw_res in self.results:
            srvname = srvname.rstrip(".")
            res = [literal_eval(r) for r in sorted(raw_res)]
            if not res:
                output = "Domain %s has no TLS-RPT configuration" % self.domain
                structured = {
                    "domain": self.domain,
                    "warnings": ["Domain has no TLS-RPT configuration"],
                }
            elif len(res) > 1:
                output = (
                    "Domain %s has more than one TLS-RPT configuration" % self.domain
                )
                structured = {
                    "domain": self.domain,
                    "value": " / ".join(res),
                    "warnings": ["Domain has more than one TLS-RPT configuration"],
                }
            else:
                value = res[0]
                structured = {
                    "domain": self.domain,
                    "value": value,
                }
                warnings = []
                if value.startswith("v=TLSRPTv1;"):
                    if not value[11:].startswith("rua="):
                        warnings.append(
                            "TLS-RPT configuration should contain 'rua=' after 'v=TLSRPTv1;'"
                        )
                else:
                    warnings.append(
                        "TLS-RPT configuration should start with 'v=TLSRPTv1;'"
                    )
                    if not (value.startswith("rua=") or ";rua=" in value):
                        warnings.append(
                            "TLS-RPT configuration should contain 'rua=' after 'v=TLSRPTv1;'"
                        )
                if "rua=" in value:
                    ruas = value.split("rua=", 1)[1]
                    for rua_val in ruas.split(","):
                        if rua_val.startswith("https://"):
                            if HTTPS_REGEXP.search(rua_val[8:]) is None:
                                warnings.append(
                                    "TLS-RPT contains an invalid HTTPS URL: %r"
                                    % rua_val
                                )
                        elif rua_val.startswith("mailto:"):
                            if MAIL_REGEXP.search(rua_val[7:]) is None:
                                warnings.append(
                                    "TLS-RPT contains an invalid e-mail URL: %r"
                                    % rua_val
                                )
                        else:
                            warnings.append(
                                "TLS-RPT contains an invalid URL: %r" % rua_val
                            )
                else:
                    warnings.append("TLS-RPT does not contain an rua entry: %r" % value)
                if warnings:
                    structured["warnings"] = warnings
                    output = (
                        "Domain %s has a TLS-RPT configuration with warnings:\n%s"
                        % (self.domain, "\n".join(warnings))
                    )
                else:
                    output = "Domain %s has a valid TLS-RPT configuration" % self.domain
            yield {
                "addr": addr,
                "hostnames": [
                    {
                        "name": srvname,
                        "type": "user",
                        "domains": list(get_domains(srvname)),
                    }
                ],
                "schema_version": SCHEMA_VERSION,
                "starttime": self.start,
                "endtime": self.stop,
                "ports": [
                    {
                        "port": 53,
                        "protocol": "udp",
                        "service_name": "domain",
                        "state_state": "open",
                        "scripts": [
                            {
                                "id": "dns-tls-rpt",
                                "output": output,
                                "dns-tls-rpt": [structured],
                            },
                        ],
                    }
                ],
            }
