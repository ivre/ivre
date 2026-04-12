#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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


import json
import os
import sys
from collections import OrderedDict
from collections.abc import Callable, Iterable
from typing import Any, TextIO, cast
from xml.sax import saxutils

from ivre import graphroute, utils
from ivre.active.nmap import ALIASES_TABLE_ELEMS
from ivre.config import HONEYD_IVRE_SCRIPTS_PATH
from ivre.db import db
from ivre.types import DB, Filter, Record
from ivre.types.active import NmapHost, NmapPort, NmapScript

HONEYD_ACTION_FROM_NMAP_STATE = {
    "resets": "reset",
    "no-responses": "block",
}
HONEYD_DEFAULT_ACTION = "block"
HONEYD_STD_SCRIPTS_BASE_PATH = "/usr/share/honeyd"
HONEYD_SSL_CMD = "honeydssl --cert-subject %(subject)s -- %(command)s"


def _display_honeyd_preamble(out: TextIO = sys.stdout) -> None:
    out.write("""create default
set default default tcp action block
set default default udp action block
set default default icmp action block

""")


def _getscript(port: NmapPort, sname: str) -> NmapScript | None:
    for s in port.get("scripts", []):
        if s["id"] == sname:
            return s
    return None


def _nmap_port2honeyd_action(port: NmapPort) -> str:
    if port["state_state"] == "closed":
        return "reset"
    if port["state_state"] != "open":
        return "block"
    # if 'service_tunnel' in port and port['service_tunnel'] == 'ssl':
    #     sslrelay = True
    # else:
    #     sslrelay = False
    if "service_name" in port:
        if port["service_name"] == "tcpwrapped":
            return '"true"'
        if port["service_name"] == "ssh":
            assert HONEYD_IVRE_SCRIPTS_PATH is not None
            s = _getscript(port, "banner")
            if s is not None:
                banner = s["output"]
            else:
                banner = f"SSH-{port.get('service_version', '2.0')}-{'_'.join(k for k in port.get('service_product', 'OpenSSH').split() if k != 'SSH')}"
            return f'"{os.path.join(HONEYD_IVRE_SCRIPTS_PATH, "sshd")} {banner}"'
    return "open"


HoneydRoutes = dict[tuple[str, str], dict[str, Any]]
HoneydNodes = set[str]


def _display_honeyd_conf(
    host: NmapHost,
    honeyd_routes: HoneydRoutes,
    honeyd_entries: HoneydNodes,
    out: TextIO = sys.stdout,
) -> tuple[HoneydRoutes, HoneydNodes]:
    addr = host["addr"]
    hname = f"host_{addr.replace('.', '_').replace(':', '_')}"
    out.write(f"create {hname}\n")
    defaction = HONEYD_DEFAULT_ACTION
    if "extraports" in host:
        extra = host["extraports"]
        defaction = max(
            max(
                extra.values(), key=lambda state: cast(int, cast(dict, state)["total"])
            )["reasons"].items(),
            key=lambda reason: cast(tuple[str, int], reason)[1],
        )[0]
        try:
            defaction = HONEYD_ACTION_FROM_NMAP_STATE[defaction]
        except KeyError:
            pass
    out.write(f"set {hname} default tcp action {defaction}\n")
    for p in host.get("ports", []):
        try:
            out.write(
                f"add {hname} {p['protocol']} port {int(p['port'])} {_nmap_port2honeyd_action(p)}\n"
            )
        except KeyError:
            # let's skip pseudo-port records that are only containers for host
            # scripts.
            pass
    if host.get("traces"):
        trace = max(host["traces"], key=lambda x: len(x["hops"]))["hops"]
        if trace:
            trace.sort(key=lambda x: x["ttl"])
            curhop = trace[0]
            honeyd_entries.add(curhop["ipaddr"])
            for t in trace[1:]:
                key = (curhop["ipaddr"], t["ipaddr"])
                latency = max(t["rtt"] - curhop["rtt"], 0)
                route = honeyd_routes.get(key)
                if route is None:
                    honeyd_routes[key] = {
                        "count": 1,
                        "high": latency,
                        "low": latency,
                        "mean": latency,
                        "targets": set([host["addr"]]),
                    }
                else:
                    route["targets"].add(host["addr"])
                    honeyd_routes[key] = {
                        "count": route["count"] + 1,
                        "high": max(route["high"], latency),
                        "low": min(route["low"], latency),
                        "mean": (route["mean"] * route["count"] + latency)
                        / float(route["count"] + 1),
                        "targets": route["targets"],
                    }
                curhop = t
    out.write(f"bind {addr} {hname}\n\n")
    return honeyd_routes, honeyd_entries


def _display_honeyd_epilogue(
    honeyd_routes: HoneydRoutes, honeyd_entries: HoneydNodes, out: TextIO = sys.stdout
) -> None:
    for node in honeyd_entries:
        out.write(f"route entry {node}\n")
        out.write(f"route {node} link {node}/32\n")
    out.write("\n")
    for src, dst in honeyd_routes:
        out.write(f"route {src} link {dst}/32\n")
        for target in honeyd_routes[(src, dst)]["targets"]:
            out.write(
                f"route {src} add net {target}/32 {dst} latency {round(honeyd_routes[src, dst]['mean'])}ms\n"
            )


def _display_xml_preamble(out: TextIO = sys.stdout) -> None:
    out.write(
        '<?xml version="1.0"?>\n'
        "<?xml-stylesheet "
        'href="file:///usr/local/bin/../share/nmap/nmap.xsl" '
        'type="text/xsl"?>\n'
    )


def _display_xml_scan(scan: dict[str, Any], out: TextIO = sys.stdout) -> None:
    if "scaninfos" in scan and scan["scaninfos"]:
        for k in scan["scaninfos"][0]:
            scan[f"scaninfo.{k}"] = scan["scaninfos"][0][k]
        del scan["scaninfos"]
    for k in [
        "version",
        "start",
        "startstr",
        "args",
        "scanner",
        "xmloutputversion",
        "scaninfo.type",
        "scaninfo.protocol",
        "scaninfo.numservices",
        "scaninfo.services",
    ]:
        if k not in scan:
            scan[k] = ""
        elif isinstance(scan[k], str):
            scan[k] = scan[k].replace('"', "&quot;").replace("--", "-&#45;")
    out.write(
        f"<!DOCTYPE nmaprun PUBLIC \"-//IDN nmap.org//DTD Nmap XML 1.04//EN\" \"https://svn.nmap.org/nmap/docs/nmap.dtd\">\n<?xml-stylesheet href=\"file:///usr/local/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?>\n<!-- {scan['scanner']} {scan['version']} scan initiated {scan['startstr']} as: {scan['args']} -->\n<nmaprun scanner=\"{scan['scanner']}\" args=\"{scan['args']}\" start=\"{scan['start']}\" startstr=\"{scan['startstr']}\" version=\"{scan['version']}\" xmloutputversion=\"{scan['xmloutputversion']}\">\n<scaninfo type=\"{scan['scaninfo.type']}\" protocol=\"{scan['scaninfo.protocol']}\" numservices=\"{scan['scaninfo.numservices']}\" services=\"{scan['scaninfo.services']}\"/>\n"
    )


def _display_xml_table_elem(
    doc: NmapHost,
    first: bool = False,
    name: str | None = None,
    out: TextIO = sys.stdout,
) -> None:
    if first:
        assert name is None
    name = "" if name is None else f" key={saxutils.quoteattr(name)}"
    if isinstance(doc, list):
        if not first:
            out.write(f"<table{name}>\n")
        for subdoc in doc:
            _display_xml_table_elem(subdoc, out=out)
        if not first:
            out.write("</table>\n")
    elif isinstance(doc, dict):
        if not first:
            out.write(f"<table{name}>\n")
        for key, subdoc in doc.items():
            _display_xml_table_elem(subdoc, name=key, out=out)
        if not first:
            out.write("</table>\n")
    else:
        out.write(
            f"<elem{name}>{saxutils.escape(str(doc), entities={'\n': '&#10;'})}</elem>\n"
        )


def _display_xml_script(script: NmapScript, out: TextIO = sys.stdout) -> None:
    out.write(f"<script id={saxutils.quoteattr(script['id'])}")
    if "output" in script:
        out.write(f" output={saxutils.quoteattr(script['output'])}")
    key = ALIASES_TABLE_ELEMS.get(script["id"], script["id"])
    if key in script:
        out.write(">")
        _display_xml_table_elem(script[key], first=True, out=out)
        out.write("</script>")
    else:
        out.write("/>")


def _display_xml_host(host: NmapHost, out: TextIO = sys.stdout) -> None:
    out.write("<host")
    for k in ["timedout", "timeoutcounter"]:
        if k in host:
            out.write(f" {k}={saxutils.quoteattr(host[k])}")
    for k in ["starttime", "endtime"]:
        if k in host:
            out.write(f" {k}={saxutils.quoteattr(host[k].strftime('%s'))}")
    out.write(">")
    if "state" in host:
        out.write(f"<status state=\"{host['state']}\"")
        for k in ["reason", "reason_ttl"]:
            kk = f"state_{k}"
            if kk in host:
                out.write(f' {k}="{host[kk]}"')
        out.write("/>")
    out.write("\n")
    if "addr" in host:
        out.write(
            f"<address addr=\"{host['addr']}\" addrtype=\"ipv{int(6 if ':' in host['addr'] else 4)}\"/>\n"
        )
    for atype, addrs in host.get("addresses", {}).items():
        for addr in addrs:
            extra = ""
            if atype == "mac":
                manuf = utils.mac2manuf(addr)
                # if manuf:
                #     if len(manuf) > 1 and manuf[1]:
                #         manuf = manuf[1]
                #     else:
                #         manuf = manuf[0]
                #     extra = ' vendor=%s' % saxutils.quoteattr(manuf[0])
                if manuf and manuf[0]:
                    extra = f" vendor={saxutils.quoteattr(manuf[0])}"
            out.write(f'<address addr="{addr}" addrtype="{atype}"{extra}/>\n')
    if "hostnames" in host:
        out.write("<hostnames>\n")
        for hostname in host["hostnames"]:
            out.write("<hostname")
            for k in ["name", "type"]:
                if k in hostname:
                    out.write(f' {k}="{hostname[k]}"')
            out.write("/>\n")
        out.write("</hostnames>\n")
    out.write("<ports>")
    for state, counts in host.get("extraports", {}).items():
        out.write(f"<extraports state=\"{state}\" count=\"{counts['total']}\">\n")
        for reason, count in counts["reasons"].items():
            out.write(f'<extrareasons reason="{reason}" count="{count}"/>\n')
        out.write("</extraports>\n")
    hostscripts: list[NmapScript] = []
    for p in host.get("ports", []):
        if p.get("port") == -1:
            hostscripts = p["scripts"]
            continue
        out.write("<port")
        if "protocol" in p:
            out.write(f" protocol=\"{p['protocol']}\"")
        if "port" in p:
            out.write(f" portid=\"{p['port']}\"")
        out.write("><state")
        for k in ["state", "reason", "reason_ttl"]:
            kk = f"state_{k}"
            if kk in p:
                out.write(f" {k}={saxutils.quoteattr(str(p[kk]))}")
        out.write("/>")
        if "service_name" in p:
            out.write(f"<service name=\"{p['service_name']}\"")
            for k in [
                "servicefp",
                "product",
                "version",
                "extrainfo",
                "ostype",
                "method",
                "conf",
            ]:
                kk = f"service_{k}"
                if kk in p:
                    if isinstance(p[kk], str):
                        out.write(f" {k}={saxutils.quoteattr(p[kk])}")
                    else:
                        out.write(f' {k}="{p[kk]}"')
            # TODO: CPE
            out.write("></service>")
        for s in p.get("scripts", []):
            _display_xml_script(s, out=out)
        out.write("</port>\n")
    out.write("</ports>\n")
    if hostscripts:
        out.write("<hostscript>")
        for s in hostscripts:
            _display_xml_script(s, out=out)
        out.write("</hostscript>")
    for trace in host.get("traces", []):
        out.write("<trace")
        if "port" in trace:
            out.write(f" port={saxutils.quoteattr(str(trace['port']))}")
        if "protocol" in trace:
            out.write(f" proto={saxutils.quoteattr(trace['protocol'])}")
        out.write(">\n")
        for hop in sorted(trace.get("hops", []), key=lambda hop: cast(int, hop["ttl"])):
            out.write("<hop")
            if "ttl" in hop:
                out.write(f" ttl={saxutils.quoteattr(str(hop['ttl']))}")
            if "ipaddr" in hop:
                out.write(f" ipaddr={saxutils.quoteattr(hop['ipaddr'])}")
            if "rtt" in hop:
                rtt = saxutils.quoteattr(
                    f"{hop['rtt']:.2f}" if isinstance(hop["rtt"], float) else hop["rtt"]
                )
                out.write(f" rtt={rtt}")
            if "host" in hop:
                out.write(f" host={saxutils.quoteattr(hop['host'])}")
            out.write("/>\n")
        out.write("</trace>\n")
    out.write("</host>\n")


def _display_xml_epilogue(out: TextIO = sys.stdout) -> None:
    out.write("</nmaprun>\n")


def _displayhost_csv(
    fields: dict[str, Any],
    separator: str,
    nastr: str,
    dic: NmapHost,
    out: TextIO = sys.stdout,
) -> None:
    out.write(
        "\n".join(
            separator.join(elt for elt in line)
            for line in utils.doc2csv(dic, fields, nastr=nastr)
        )
    )
    out.write("\n")


def _display_gnmap_scan(scan: dict[str, Any], out: TextIO = sys.stdout) -> None:
    if "scaninfos" in scan and scan["scaninfos"]:
        for k in scan["scaninfos"][0]:
            scan[f"scaninfo.{k}"] = scan["scaninfos"][0][k]
        del scan["scaninfos"]
    for k in ["version", "startstr", "args"]:
        if k not in scan:
            scan[k] = ""
        elif isinstance(scan[k], str):
            scan[k] = scan[k].replace('"', "&quot;").replace("--", "-&#45;")
    out.write(
        f"# Nmap {scan['version']} scan initiated {scan['startstr']} as: {scan['args']}\n"
    )


def _display_gnmap_host(host: NmapHost, out: TextIO = sys.stdout) -> None:
    addr = host["addr"]
    hostname = None
    for name in host.get("hostnames", []):
        if name.get("type") == "PTR":
            hostname = name.get("name")
            if hostname is not None:
                break
    if hostname is None:
        name = addr
    else:
        name = f"{addr} ({hostname})"
    if host.get("state"):
        out.write(f"Host: {name} Status: {host['state'].capitalize()}\n")
    ports = []
    info = []
    for port in host.get("ports", []):
        if port.get("port") == -1:
            continue
        if "service_product" in port:
            version = port["service_product"]
            for key in ["version", "extrainfo"]:
                key = f"service_{key}"
                if key in port:
                    version += f" {port[key]}"
            version = version.replace("/", "|")
        else:
            version = ""
        ports.append(
            f"{port['port']}/{port['state_state']}/{port['protocol']}//{port.get('service_name', '')}//{version}/"
        )
    if ports:
        info.append(f"Ports: {', '.join(ports)}")
    extraports = []
    for state, counts in host.get("extraports", {}).items():
        extraports.append(f"{state} ({counts['total']})")
    if extraports:
        info.append(f"Ignored State: {', '.join(extraports)}")
    for osmatch in host.get("os", {}).get("osmatch", []):
        info.append(f"OS: {osmatch['name']}")
        break
    # TODO: data from tcpsequence and ipidsequence is currently
    # missing
    if info:
        out.write("Host: %s %s\n" % (name, "\t".join(info)))


def displayfunction_honeyd(cur: Iterable[NmapHost]) -> None:
    _display_honeyd_preamble(sys.stdout)
    honeyd_routes: HoneydRoutes = {}
    honeyd_entries: HoneydNodes = set()
    for h in cur:
        honeyd_routes, honeyd_entries = _display_honeyd_conf(
            h, honeyd_routes, honeyd_entries, sys.stdout
        )
    _display_honeyd_epilogue(honeyd_routes, honeyd_entries, sys.stdout)


def displayfunction_http_urls(
    cur: Iterable[NmapHost],
    with_addrs: bool = True,
    with_names: bool = False,
    add_addrs: bool = False,
) -> None:
    for h in cur:
        addr = h["addr"]
        names = []
        if with_addrs:
            if ":" in addr:
                names.append(f"[{addr}]")
            else:
                names.append(addr)
        if with_names:
            names.extend(
                sorted(
                    {
                        hn["name"]
                        for hn in h.get("hostnames", [])
                        if "*" not in hn["name"]
                    },
                    key=utils.key_sort_dom,
                )
            )
        prefix = f"{addr}, " if add_addrs else ""
        for p in h.get("ports", []):
            if p.get("service_name") not in {
                "http",
                "http-proxy",
                "http-alt",
                "https",
                "https-alt",
            }:
                continue
            if p.get("service_tunnel") == "ssl" or p.get("service_name") in {
                "https",
                "https-alt",
            }:
                if p.get("port") == 443:
                    for name in names:
                        sys.stdout.write(f"{prefix}https://{name}/\n")
                else:
                    for name in names:
                        sys.stdout.write(f"{prefix}https://{name}:{p['port']}/\n")
            else:
                if p.get("port") == 80:
                    for name in names:
                        sys.stdout.write(f"{prefix}http://{name}/\n")
                else:
                    for name in names:
                        sys.stdout.write(f"{prefix}http://{name}:{p['port']}/\n")


def displayfunction_nmapxml(
    cur: Iterable[NmapHost], scan: dict[str, Any] | None = None
) -> None:
    _display_xml_preamble(out=sys.stdout)
    _display_xml_scan(scan or {}, out=sys.stdout)
    for h in cur:
        _display_xml_host(h, out=sys.stdout)
    _display_xml_epilogue(out=sys.stdout)


def displayfunction_gnmap(cur: Iterable[NmapHost]) -> None:
    _display_gnmap_scan({}, out=sys.stdout)
    for h in cur:
        _display_gnmap_host(h, out=sys.stdout)


def displayfunction_explain(flt: Filter, dbase: DB) -> None:
    sys.stdout.write(f"{dbase.explain(dbase._get(flt), indent=4)}\n")


def displayfunction_remove(flt: Filter, dbase: DB) -> None:
    dbase.remove_many(flt)


def displayfunction_graphroute(
    cur: Iterable[NmapHost],
    arg: str,
    cluster: str | None,
    gr_include: str | None,
    gr_dont_reset: bool,
) -> None:
    cluster_f: Callable[[str], tuple[int | str, str] | None] | None
    graph, entry_nodes = graphroute.buildgraph(
        cur,
        include_last_hop=gr_include == "last-hop",
        include_target=gr_include == "target",
    )
    if arg == "dot":
        if cluster == "AS":

            def cluster_f(ipaddr: str) -> tuple[int, str] | None:
                res = db.data.as_byip(ipaddr)
                if res is None:
                    return None
                return (res["as_num"], f"{res['as_num']}\n[{res['as_name']}]")

        elif cluster == "Country":

            def cluster_f(ipaddr: str) -> tuple[str, str] | None:
                res = db.data.country_byip(ipaddr)
                if res is None:
                    return None
                return (
                    res["country_code"],
                    f"{res['country_code']} - {res['country_name']}",
                )

        else:
            cluster_f = None
        graphroute.writedotgraph(graph, sys.stdout, cluster=cluster_f)
    elif arg == "rtgraph3d":
        g = graphroute.display3dgraph(graph, reset_world=not gr_dont_reset)
        for n in entry_nodes:
            g.glow(n)


def displayfunction_csv(
    cur: Iterable[NmapHost], arg: str, csv_sep: str, csv_na_str: str, add_infos: bool
) -> None:
    fields: OrderedDict | None = {
        "ports": OrderedDict(
            [
                ("addr", True),
                ("ports", OrderedDict([("port", str), ("state_state", True)])),
            ]
        ),
        "hops": OrderedDict(
            [
                ("addr", True),
                (
                    "traces",
                    OrderedDict(
                        [
                            (
                                "hops",
                                OrderedDict(
                                    [
                                        ("ipaddr", True),
                                        ("ttl", str),
                                        (
                                            "rtt",
                                            lambda x: (
                                                csv_na_str if x == "--" else str(x)
                                            ),
                                        ),
                                    ]
                                ),
                            )
                        ]
                    ),
                ),
            ]
        ),
        "rtt": OrderedDict(
            [
                ("addr", True),
                (
                    "traces",
                    OrderedDict(
                        [
                            (
                                "hops",
                                OrderedDict(
                                    [
                                        (
                                            "rtt",
                                            lambda x: (
                                                csv_na_str if x == "--" else str(x)
                                            ),
                                        ),
                                    ]
                                ),
                            )
                        ]
                    ),
                ),
            ]
        ),
    }.get(arg)
    if fields is None:
        # active_parser.error("Invalid choice for --csv.")
        sys.stderr.write("Invalid choice for --csv.\n")
        return
    if add_infos:
        fields["infos"] = OrderedDict(
            [
                ("country_code", True),
                ("city", True),
                ("as_num", str),
            ]
        )
    sys.stdout.write(csv_sep.join(utils.fields2csv_head(fields)))
    sys.stdout.write("\n")
    for h in cur:
        _displayhost_csv(fields, csv_sep, csv_na_str, h, out=sys.stdout)


def displayfunction_json(
    cur: Iterable[Record], dbase: DB, no_screenshots: bool = False
) -> None:
    indent: int | None
    if os.isatty(sys.stdout.fileno()):
        indent = 4
    else:
        indent = None
    for h in cur:
        try:
            del h["_id"]
        except KeyError:
            pass
        for port in h.get("ports", []):
            if no_screenshots:
                for fname in ["screenshot", "screendata"]:
                    if fname in port:
                        del port[fname]
            elif "screendata" in port:
                port["screendata"] = utils.encode_b64(
                    dbase.from_binary(port["screendata"])
                )
            for script in port.get("scripts", []):
                if "masscan" in script and "raw" in script["masscan"]:
                    script["masscan"]["raw"] = utils.encode_b64(
                        dbase.from_binary(script["masscan"]["raw"])
                    )
        json.dump(h, sys.stdout, indent=indent, default=dbase.serialize)
        sys.stdout.write("\n")


def display_short(
    dbase: DB, flt: Filter, srt: Any | None, lmt: int | None, skp: int | None
) -> None:
    for val in dbase.distinct("addr", flt=flt, sort=srt, limit=lmt, skip=skp):
        sys.stdout.write(f"{val}\n")


def display_distinct(
    dbase: DB,
    arg: str,
    flt: Filter,
    srt: Any | None,
    lmt: int | None,
    skp: int | None,
) -> None:
    for val in dbase.distinct(arg, flt=flt, sort=srt, limit=lmt, skip=skp):
        sys.stdout.write(f"{val!s}\n")
