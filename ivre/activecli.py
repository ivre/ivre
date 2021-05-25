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


from collections import OrderedDict
import json
import os
import sys
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    TextIO,
    Tuple,
    Union,
    cast,
)
from xml.sax import saxutils


from ivre.active.data import ALIASES_TABLE_ELEMS
from ivre.config import HONEYD_IVRE_SCRIPTS_PATH
from ivre.db import db
from ivre import graphroute
from ivre.types import DB, Filter, Record
from ivre.types.active import NmapHost, NmapPort, NmapScript
from ivre import utils


HONEYD_ACTION_FROM_NMAP_STATE = {
    "resets": "reset",
    "no-responses": "block",
}
HONEYD_DEFAULT_ACTION = "block"
HONEYD_STD_SCRIPTS_BASE_PATH = "/usr/share/honeyd"
HONEYD_SSL_CMD = "honeydssl --cert-subject %(subject)s -- %(command)s"


def _display_honeyd_preamble(out: TextIO = sys.stdout) -> None:
    out.write(
        """create default
set default default tcp action block
set default default udp action block
set default default icmp action block

"""
    )


def _getscript(port: NmapPort, sname: str) -> Optional[NmapScript]:
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
                banner = "SSH-%s-%s" % (
                    port.get("service_version", "2.0"),
                    "_".join(
                        [
                            k
                            for k in port.get("service_product", "OpenSSH").split()
                            if k != "SSH"
                        ]
                    ),
                )
            return '''"%s %s"''' % (
                os.path.join(HONEYD_IVRE_SCRIPTS_PATH, "sshd"),
                banner,
            )
    return "open"


HoneydRoutes = Dict[Tuple[str, str], Dict[str, Any]]
HoneydNodes = Set[str]


def _display_honeyd_conf(
    host: NmapHost,
    honeyd_routes: HoneydRoutes,
    honeyd_entries: HoneydNodes,
    out: TextIO = sys.stdout,
) -> Tuple[HoneydRoutes, HoneydNodes]:
    addr = host["addr"]
    hname = "host_%s" % addr.replace(".", "_").replace(":", "_")
    out.write("create %s\n" % hname)
    defaction = HONEYD_DEFAULT_ACTION
    if "extraports" in host:
        extra = host["extraports"]
        defaction = max(
            max(
                extra.values(), key=lambda state: cast(int, cast(dict, state)["total"])
            )["reasons"].items(),
            key=lambda reason: cast(Tuple[str, int], reason)[1],
        )[0]
        try:
            defaction = HONEYD_ACTION_FROM_NMAP_STATE[defaction]
        except KeyError:
            pass
    out.write("set %s default tcp action %s\n" % (hname, defaction))
    for p in host.get("ports", []):
        try:
            out.write(
                "add %s %s port %d %s\n"
                % (
                    hname,
                    p["protocol"],
                    p["port"],
                    _nmap_port2honeyd_action(p),
                )
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
    out.write("bind %s %s\n\n" % (addr, hname))
    return honeyd_routes, honeyd_entries


def _display_honeyd_epilogue(
    honeyd_routes: HoneydRoutes, honeyd_entries: HoneydNodes, out: TextIO = sys.stdout
) -> None:
    for node in honeyd_entries:
        out.write("route entry %s\n" % node)
        out.write("route %s link %s/32\n" % (node, node))
    out.write("\n")
    for src, dst in honeyd_routes:
        out.write("route %s link %s/32\n" % (src, dst))
        for target in honeyd_routes[(src, dst)]["targets"]:
            out.write(
                "route %s add net %s/32 %s latency %dms\n"
                % (
                    src,
                    target,
                    dst,
                    int(round(honeyd_routes[(src, dst)]["mean"])),
                )
            )


def _display_xml_preamble(out: TextIO = sys.stdout) -> None:
    out.write(
        '<?xml version="1.0"?>\n'
        "<?xml-stylesheet "
        'href="file:///usr/local/bin/../share/nmap/nmap.xsl" '
        'type="text/xsl"?>\n'
    )


def _display_xml_scan(scan: Dict[str, Any], out: TextIO = sys.stdout) -> None:
    if "scaninfos" in scan and scan["scaninfos"]:
        for k in scan["scaninfos"][0]:
            scan["scaninfo.%s" % k] = scan["scaninfos"][0][k]
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
        "<!DOCTYPE nmaprun PUBLIC "
        '"-//IDN nmap.org//DTD Nmap XML 1.04//EN" '
        '"https://svn.nmap.org/nmap/docs/nmap.dtd">\n'
        "<?xml-stylesheet "
        'href="file:///usr/local/bin/../share/nmap/nmap.xsl" '
        'type="text/xsl"?>\n'
        "<!-- %(scanner)s %(version)s scan initiated %(startstr)s "
        "as: %(args)s -->\n"
        '<nmaprun scanner="%(scanner)s" args="%(args)s" '
        'start="%(start)s" startstr="%(startstr)s" '
        'version="%(version)s" '
        'xmloutputversion="%(xmloutputversion)s">\n'
        '<scaninfo type="%(scaninfo.type)s" '
        'protocol="%(scaninfo.protocol)s" '
        'numservices="%(scaninfo.numservices)s" '
        'services="%(scaninfo.services)s"/>\n' % scan
    )


def _display_xml_table_elem(
    doc: NmapHost,
    first: bool = False,
    name: Optional[str] = None,
    out: TextIO = sys.stdout,
) -> None:
    if first:
        assert name is None
    name = "" if name is None else " key=%s" % saxutils.quoteattr(name)
    if isinstance(doc, list):
        if not first:
            out.write("<table%s>\n" % name)
        for subdoc in doc:
            _display_xml_table_elem(subdoc, out=out)
        if not first:
            out.write("</table>\n")
    elif isinstance(doc, dict):
        if not first:
            out.write("<table%s>\n" % name)
        for key, subdoc in doc.items():
            _display_xml_table_elem(subdoc, name=key, out=out)
        if not first:
            out.write("</table>\n")
    else:
        out.write(
            "<elem%s>%s</elem>\n"
            % (
                name,
                saxutils.escape(
                    str(doc),
                    entities={"\n": "&#10;"},
                ),
            )
        )


def _display_xml_script(script: NmapScript, out: TextIO = sys.stdout) -> None:
    out.write("<script id=%s" % saxutils.quoteattr(script["id"]))
    if "output" in script:
        out.write(" output=%s" % saxutils.quoteattr(script["output"]))
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
            out.write(" %s=%s" % (k, saxutils.quoteattr(host[k])))
    for k in ["starttime", "endtime"]:
        if k in host:
            out.write(" %s=%s" % (k, saxutils.quoteattr(host[k].strftime("%s"))))
    out.write(">")
    if "state" in host:
        out.write('<status state="%s"' % host["state"])
        for k in ["reason", "reason_ttl"]:
            kk = "state_%s" % k
            if kk in host:
                out.write(' %s="%s"' % (k, host[kk]))
        out.write("/>")
    out.write("\n")
    if "addr" in host:
        out.write(
            '<address addr="%s" addrtype="ipv%d"/>\n'
            % (
                host["addr"],
                6 if ":" in host["addr"] else 4,
            )
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
                    extra = " vendor=%s" % saxutils.quoteattr(manuf[0])
            out.write('<address addr="%s" addrtype="%s"%s/>\n' % (addr, atype, extra))
    if "hostnames" in host:
        out.write("<hostnames>\n")
        for hostname in host["hostnames"]:
            out.write("<hostname")
            for k in ["name", "type"]:
                if k in hostname:
                    out.write(' %s="%s"' % (k, hostname[k]))
            out.write("/>\n")
        out.write("</hostnames>\n")
    out.write("<ports>")
    for state, counts in host.get("extraports", {}).items():
        out.write('<extraports state="%s" count="%d">\n' % (state, counts["total"]))
        for reason, count in counts["reasons"].items():
            out.write('<extrareasons reason="%s" count="%d"/>\n' % (reason, count))
        out.write("</extraports>\n")
    hostscripts: List[NmapScript] = []
    for p in host.get("ports", []):
        if p.get("port") == -1:
            hostscripts = p["scripts"]
            continue
        out.write("<port")
        if "protocol" in p:
            out.write(' protocol="%s"' % p["protocol"])
        if "port" in p:
            out.write(' portid="%s"' % p["port"])
        out.write("><state")
        for k in ["state", "reason", "reason_ttl"]:
            kk = "state_%s" % k
            if kk in p:
                out.write(" %s=%s" % (k, saxutils.quoteattr(str(p[kk]))))
        out.write("/>")
        if "service_name" in p:
            out.write('<service name="%s"' % p["service_name"])
            for k in [
                "servicefp",
                "product",
                "version",
                "extrainfo",
                "ostype",
                "method",
                "conf",
            ]:
                kk = "service_%s" % k
                if kk in p:
                    if isinstance(p[kk], str):
                        out.write(" %s=%s" % (k, saxutils.quoteattr(p[kk])))
                    else:
                        out.write(' %s="%s"' % (k, p[kk]))
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
            out.write(" port=%s" % (saxutils.quoteattr(str(trace["port"]))))
        if "protocol" in trace:
            out.write(" proto=%s" % (saxutils.quoteattr(trace["protocol"])))
        out.write(">\n")
        for hop in sorted(trace.get("hops", []), key=lambda hop: cast(int, hop["ttl"])):
            out.write("<hop")
            if "ttl" in hop:
                out.write(" ttl=%s" % (saxutils.quoteattr(str(hop["ttl"]))))
            if "ipaddr" in hop:
                out.write(" ipaddr=%s" % (saxutils.quoteattr(hop["ipaddr"])))
            if "rtt" in hop:
                out.write(
                    " rtt=%s"
                    % (
                        saxutils.quoteattr(
                            "%.2f" % hop["rtt"]
                            if isinstance(hop["rtt"], float)
                            else hop["rtt"]
                        )
                    )
                )
            if "host" in hop:
                out.write(" host=%s" % (saxutils.quoteattr(hop["host"])))
            out.write("/>\n")
        out.write("</trace>\n")
    out.write("</host>\n")


def _display_xml_epilogue(out: TextIO = sys.stdout) -> None:
    out.write("</nmaprun>\n")


def _displayhost_csv(
    fields: Dict[str, Any],
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


def _display_gnmap_scan(scan: Dict[str, Any], out: TextIO = sys.stdout) -> None:
    if "scaninfos" in scan and scan["scaninfos"]:
        for k in scan["scaninfos"][0]:
            scan["scaninfo.%s" % k] = scan["scaninfos"][0][k]
        del scan["scaninfos"]
    for k in ["version", "startstr", "args"]:
        if k not in scan:
            scan[k] = ""
        elif isinstance(scan[k], str):
            scan[k] = scan[k].replace('"', "&quot;").replace("--", "-&#45;")
    out.write("# Nmap %(version)s scan initiated %(startstr)s as: %(args)s\n")


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
        name = "%s (%s)" % (addr, hostname)
    if host.get("state"):
        out.write("Host: %s Status: %s\n" % (name, host["state"].capitalize()))
    ports = []
    info = []
    for port in host.get("ports", []):
        if port.get("port") == -1:
            continue
        if "service_product" in port:
            version = port["service_product"]
            for key in ["version", "extrainfo"]:
                key = "service_%s" % key
                if key in port:
                    version += " %s" % port[key]
            version = version.replace("/", "|")
        else:
            version = ""
        ports.append(
            "%d/%s/%s//%s//%s/"
            % (
                port["port"],
                port["state_state"],
                port["protocol"],
                port.get("service_name", ""),
                version,
            )
        )
    if ports:
        info.append("Ports: %s" % ", ".join(ports))
    extraports = []
    for state, counts in host.get("extraports", {}).items():
        extraports.append("%s (%d)" % (state, counts["total"]))
    if extraports:
        info.append("Ignored State: %s" % ", ".join(extraports))
    for osmatch in host.get("os", {}).get("osmatch", []):
        info.append("OS: %s" % osmatch["name"])
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


def displayfunction_http_urls(cur: Iterable[NmapHost]) -> None:
    for h in cur:
        for p in h.get("ports", []):
            if p.get("service_name") not in {"http", "http-proxy", "https"}:
                continue
            if p.get("service_tunnel") == "ssl" or p.get("service_name") == "https":
                if p.get("port") == 443:
                    sys.stdout.write("https://%s/\n" % h["addr"])
                else:
                    sys.stdout.write("https://%s:%d/\n" % (h["addr"], p["port"]))
            else:
                if p.get("port") == 80:
                    sys.stdout.write("http://%s/\n" % h["addr"])
                else:
                    sys.stdout.write("http://%s:%d/\n" % (h["addr"], p["port"]))


def displayfunction_nmapxml(
    cur: Iterable[NmapHost], scan: Optional[Dict[str, Any]] = None
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
    sys.stdout.write(dbase.explain(dbase._get(flt), indent=4) + "\n")


def displayfunction_remove(flt: Filter, dbase: DB) -> None:
    dbase.remove_many(flt)


def displayfunction_graphroute(
    cur: Iterable[NmapHost],
    arg: str,
    cluster: Optional[str],
    gr_include: Optional[str],
    gr_dont_reset: bool,
) -> None:
    cluster_f: Optional[Callable[[str], Optional[Tuple[Union[int, str], str]]]]
    graph, entry_nodes = graphroute.buildgraph(
        cur,
        include_last_hop=gr_include == "last-hop",
        include_target=gr_include == "target",
    )
    if arg == "dot":
        if cluster == "AS":

            def cluster_f(ipaddr: str) -> Optional[Tuple[int, str]]:
                res = db.data.as_byip(ipaddr)
                if res is None:
                    return None
                return (res["as_num"], "%(as_num)d\n[%(as_name)s]" % res)

        elif cluster == "Country":

            def cluster_f(ipaddr: str) -> Optional[Tuple[str, str]]:
                res = db.data.country_byip(ipaddr)
                if res is None:
                    return None
                return (
                    res["country_code"],
                    "%(country_code)s - %(country_name)s" % res,
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
    fields: Optional[OrderedDict] = {
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
    indent: Optional[int]
    if os.isatty(sys.stdout.fileno()):
        indent = 4
    else:
        indent = None
    for h in cur:
        for fld in ["_id", "scanid"]:
            try:
                del h[fld]
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
    dbase: DB, flt: Filter, srt: Optional[Any], lmt: Optional[int], skp: Optional[int]
) -> None:
    for val in dbase.distinct("addr", flt=flt, sort=srt, limit=lmt, skip=skp):
        sys.stdout.write(val + "\n")


def display_distinct(
    dbase: DB,
    arg: str,
    flt: Filter,
    srt: Optional[Any],
    lmt: Optional[int],
    skp: Optional[int],
) -> None:
    for val in dbase.distinct(arg, flt=flt, sort=srt, limit=lmt, skip=skp):
        sys.stdout.write(str(val) + "\n")
