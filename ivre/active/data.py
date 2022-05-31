#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2022 Pierre LALET <pierre@droids-corp.org>
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

"""This submodule contains functions to manipulate documents from the
active (nmap & view) purposes.

"""


from bisect import bisect_left
from datetime import datetime
from itertools import chain
import json
import os
import re
from textwrap import wrap
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
    cast,
)


from ivre.active.cpe import add_cpe_values
from ivre.config import DATA_PATH, VIEW_SYNACK_HONEYPOT_COUNT
from ivre.data.microsoft.exchange import EXCHANGE_BUILDS
from ivre.data.abuse_ch.sslbl import SSLBL_CERTIFICATES, SSLBL_JA3
from ivre.types import NmapServiceMatch, ParsedCertificate, Tag
from ivre.types.active import (
    HttpHeader,
    NmapAddress,
    NmapHost,
    NmapHostname,
    NmapPort,
    NmapScript,
)
from ivre.utils import (
    IPV4ADDR,
    LOGGER,
    TORCERT_SUBJECT,
    get_domains,
    ip2int,
    key_sort_dom,
    make_range_tables,
    net2range,
    nmap_encode_data,
    ports2nmapspec,
)


ALIASES_TABLE_ELEMS = {
    # Use the same structured output for both ssl-cert and ssl-cacert
    "ssl-cacert": "ssl-cert",
    # Use the same structured output for all the Nuclei scripts
    "http-nuclei": "nuclei",
    "network-nuclei": "nuclei",
    # ls unified output (ls NSE module + ftp-anon)
    #   grep -lF 'ls.new_vol' * | sed 's#^#    "#;s#.nse$#": "ls",#'
    "afp-ls": "ls",
    "http-ls": "ls",
    "nfs-ls": "ls",
    "smb-ls": "ls",
    #   + ftp-anon
    "ftp-anon": "ls",
    # vulns unified output (vulns NSE module)
    #   grep -l -F vulns.Report * | sed 's#^#    "#;s#.nse$#": "vulns",#'
    "afp-path-vuln": "vulns",
    "clamav-exec": "vulns",
    "distcc-cve2004-2687": "vulns",
    "ftp-libopie": "vulns",
    "ftp-vsftpd-backdoor": "vulns",
    "ftp-vuln-cve2010-4221": "vulns",
    "http-avaya-ipoffice-users": "vulns",
    "http-cross-domain-policy": "vulns",
    "http-dlink-backdoor": "vulns",
    "http-frontpage-login": "vulns",
    "http-huawei-hg5xx-vuln": "vulns",
    "http-iis-short-name-brute": "vulns",
    "http-method-tamper": "vulns",
    "http-phpmyadmin-dir-traversal": "vulns",
    "http-phpself-xss": "vulns",
    "http-sap-netweaver-leak": "vulns",
    "http-shellshock": "vulns",
    "http-slowloris-check": "vulns",
    "http-tplink-dir-traversal": "vulns",
    "http-vuln-cve2006-3392": "vulns",
    "http-vuln-cve2009-3960": "vulns",
    "http-vuln-cve2010-2861": "vulns",
    "http-vuln-cve2011-3192": "vulns",
    "http-vuln-cve2011-3368": "vulns",
    "http-vuln-cve2012-1823": "vulns",
    "http-vuln-cve2013-0156": "vulns",
    "http-vuln-cve2013-6786": "vulns",
    "http-vuln-cve2013-7091": "vulns",
    "http-vuln-cve2014-2126": "vulns",
    "http-vuln-cve2014-2127": "vulns",
    "http-vuln-cve2014-2128": "vulns",
    "http-vuln-cve2014-2129": "vulns",
    "http-vuln-cve2014-3704": "vulns",
    "http-vuln-cve2014-8877": "vulns",
    "http-vuln-cve2015-1427": "vulns",
    "http-vuln-cve2015-1635": "vulns",
    "http-vuln-cve2017-1001000": "vulns",
    "http-vuln-cve2017-5638": "vulns",
    "http-vuln-cve2017-5689": "vulns",
    "http-vuln-cve2017-8917": "vulns",
    "http-vuln-misfortune-cookie": "vulns",
    "http-vuln-wnr1000-creds": "vulns",
    "ipmi-cipher-zero": "vulns",
    "mysql-vuln-cve2012-2122": "vulns",
    "qconn-exec": "vulns",
    "rdp-vuln-ms12-020": "vulns",
    "realvnc-auth-bypass": "vulns",
    "rmi-vuln-classloader": "vulns",
    "rsa-vuln-roca": "vulns",
    "samba-vuln-cve-2012-1182": "vulns",
    "smb-double-pulsar-backdoor": "vulns",
    "smb-vuln-conficker": "vulns",
    "smb-vuln-cve-2017-7494": "vulns",
    "smb-vuln-cve2009-3103": "vulns",
    "smb-vuln-ms06-025": "vulns",
    "smb-vuln-ms07-029": "vulns",
    "smb-vuln-ms08-067": "vulns",
    "smb-vuln-ms10-054": "vulns",
    "smb-vuln-ms10-061": "vulns",
    "smb-vuln-ms17-010": "vulns",
    "smb-vuln-regsvc-dos": "vulns",
    "smb-vuln-webexec": "vulns",
    "smb2-vuln-uptime": "vulns",
    "smtp-vuln-cve2011-1720": "vulns",
    "smtp-vuln-cve2011-1764": "vulns",
    "ssl-ccs-injection": "vulns",
    "ssl-dh-params": "vulns",
    "ssl-heartbleed": "vulns",
    "ssl-poodle": "vulns",
    "sslv2-drown": "vulns",
    "supermicro-ipmi-conf": "vulns",
    "tls-ticketbleed": "vulns",
    # ntlm unified output (*-ntlm-info modules)
    #   ls *ntlm* | sed 's#^#    "#;s#.nse$#": "ntlm-info",#'
    "http-ntlm-info": "ntlm-info",
    "imap-ntlm-info": "ntlm-info",
    "ms-sql-ntlm-info": "ntlm-info",
    "nntp-ntlm-info": "ntlm-info",
    "pop3-ntlm-info": "ntlm-info",
    "rdp-ntlm-info": "ntlm-info",
    "smtp-ntlm-info": "ntlm-info",
    "telnet-ntlm-info": "ntlm-info",
}


BIG_IP_ERROR_BANNER = re.compile("^BIG-IP: \\[0x[0-9a-f]{7}:[0-9]{1,5}\\] ")
SONICWALL_ERROR_BANNER = re.compile("^\\(Ref.Id: \\?.*\\?\\)$")


def create_ssl_output(info: ParsedCertificate) -> List[str]:
    out = []
    for key, name in [("subject_text", "Subject"), ("issuer_text", "Issuer")]:
        try:
            out.append("%s: %s" % (name, info[key]))
        except KeyError:
            pass
    try:
        pubkey = info["pubkey"]
    except KeyError:
        pass
    else:
        try:
            out.append("Public Key type: %s" % pubkey["type"])
        except KeyError:
            pass
        try:
            out.append("Public Key bits: %d" % pubkey["bits"])
        except KeyError:
            pass
    for key, name in [
        ("not_before", "Not valid before: "),
        ("not_after", "Not valid after:  "),
    ]:
        try:
            out.append("%s%s" % (name, info[key]))
        except KeyError:
            pass
    for san in info.get("san", []):
        out.append("Subject Alternative Name: %s" % san)
    for key, name in [("md5", "MD5:"), ("sha1", "SHA-1:"), ("sha256", "SHA-256:")]:
        # NB: SHA-256 is not (yet) reported by Nmap, but it might help.
        try:
            out.append("%-7s%s" % (name, " ".join(wrap(info[key], 4))))
        except KeyError:
            pass
    try:
        out.append(info["pem"])
    except KeyError:
        pass
    return out


def is_real_service_port(port: NmapPort) -> bool:
    """Decides whether a port has a "real" service (=> True) or if it is
    **possibly** a SYN-ACK "honeypot" (=> False).

    The idea is that a port is "real" if it has a reason that is not
    "syn-ack" (or similar), or if it has a service_name, or if it has a
    least one script.

    Host scripts (port == -1) are also considered True.

    """
    if port.get("port") == -1:
        return True
    if port.get("state_reason") and not (
        # might be "syn-ack" but might as
        # well be "syn-ack-cwr" or
        # "syn-psh-ack"
        port["state_reason"].startswith("syn-")
        or port["state_reason"] == "passive"
    ):
        return True
    if port.get("service_name") and port["service_name"] != "tcpwrapped":
        return True
    if port.get("scripts"):
        # Ports with scripts usually are "real" service ports, **but**
        # when a port only has a banner script, the output of which
        # matches a known SYN-ACK responder answser, we consider it is
        # **possibly** a SYN-ACK "honeypot" (or responder) and return
        # False
        if len(port["scripts"]) == 1 and port["scripts"][0]["id"] == "banner":
            banner = port["scripts"][0]["output"]
            if banner == "\n":
                return False
            if BIG_IP_ERROR_BANNER.search(banner):
                return False
            if SONICWALL_ERROR_BANNER.search(banner):
                return False
        return True
    return False


def set_openports_attribute(host: NmapHost) -> None:
    """This function sets the "openports" value in the `host` record,
    based on the elements of the "ports" list. This is used in MongoDB to
    speed up queries based on open ports.

    """
    openports = host["openports"] = {"count": 0}
    for port in host.get("ports", []):
        if port.get("state_state") != "open":
            continue
        cur = openports.setdefault(port["protocol"], {"count": 0, "ports": []})
        if port["port"] not in cur["ports"]:
            openports["count"] += 1
            cur["count"] += 1
            cur["ports"].append(port["port"])


def _prepare_tag(tag: Dict[str, Any]) -> Dict[str, Any]:
    """This function uses a set() for the "info" value, while a list() is
    used to store it. It is used in add_tags().

    """
    if "info" in tag:
        tag["info"] = set(tag["info"])
    return tag


def _clean_tag(tag: Dict[str, Any]) -> Dict[str, Any]:
    """This function is the opposite of `_prepare_tag()`. It is used in
    add_tags().

    """
    if "info" in tag:
        tag["info"] = sorted(tag["info"])
    return tag


def add_tags(host: NmapHost, tags: Iterable[Tag]) -> None:
    """This function sets or update the "tags" attribute in `host` by
    adding or updating the provided `tags`.

    """
    cur_tags = {tag["value"]: _prepare_tag(tag) for tag in host.get("tags", [])}
    for tag in tags:
        cur_tag = cur_tags.setdefault(
            tag["value"], {"value": tag["value"], "type": tag["type"]}
        )
        if "info" in tag:
            cur_tag.setdefault("info", set()).update(tag["info"])
    if cur_tags:
        host["tags"] = [_clean_tag(cur_tags[key]) for key in sorted(cur_tags)]


def is_synack_honeypot(host: NmapHost) -> bool:
    """Returns True iff the host has the "Honeypot" tag with "SYN+ACK
    honeypot" info.

    """
    return any(
        tag["value"] == "Honeypot" and "SYN+ACK honeypot" in tag.get("info", [])
        for tag in host.get("tags", [])
    )


TAG_DEFAULT_PASSWORD: Tag = {"value": "Default password", "type": "danger"}
TAG_HONEYPOT: Tag = {"value": "Honeypot", "type": "warning"}
TAG_MALWARE: Tag = {"value": "Malware", "type": "danger"}
TAG_SCANNER: Tag = {"value": "Scanner", "type": "warning"}
TAG_TOR: Tag = {"value": "TOR", "type": "info"}
TAG_CDN: Tag = {"value": "CDN", "type": "info"}
TAG_VULN: Tag = {"value": "Vulnerable", "type": "danger"}
TAG_VULN_LIKELY: Tag = {"value": "Likely vulnerable", "type": "warning"}
TAG_VULN_CANNOT_TEST: Tag = {"value": "Cannot test vuln", "type": "info"}


_SERVICE_FIELDS = [
    "service_name",
    "service_product",
    "service_version",
    "service_extrainfo",
]
_TOR_SERVICES = {
    "tor",
    "tor-control",
    "tor-info",
    "tor-orport",
    "tor-socks",
}
_TOR_HTTP_PRODUCTS = {
    "Tor directory",
    "Tor directory server",
    "Tor built-in httpd",
}


_TOR_NODES: Optional[Set[str]] = None
_CDN_TABLE: Optional[Tuple[List[int], List[Optional[str]]]] = None
_SCANNERS_TABLE: Optional[Tuple[List[int], List[Optional[str]]]] = None


def _get_data() -> None:
    global _TOR_NODES, _SCANNERS_TABLE, _CDN_TABLE
    assert DATA_PATH is not None
    if _TOR_NODES is None:
        try:
            with open(
                os.path.join(DATA_PATH, "tor_exit_nodes.txt"), encoding="utf8"
            ) as fdesc:
                _TOR_NODES = {line.strip() for line in fdesc}
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [tor_exit_nodes.txt]. Try running `ivre getwebdata`"
            )
            _TOR_NODES = set()
    if _SCANNERS_TABLE is None:
        ranges: List[Tuple[str, str, str]] = []
        try:
            with open(
                os.path.join(DATA_PATH, "ssigouvfr_scanners.txt"), encoding="utf8"
            ) as fdesc:
                ranges.extend(
                    (addr, addr, "ANSSI") for addr in (line.strip() for line in fdesc)
                )
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [ssigouvfr_scanners.txt]. Try running `ivre getwebdata`"
            )
        try:
            with open(
                os.path.join(DATA_PATH, "censys_scanners.txt"), encoding="utf8"
            ) as fdesc:
                ranges.extend(net2range(line.strip()) + ("Censys",) for line in fdesc)
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [censys_scanners.txt]. Try running `ivre getwebdata`"
            )
        parsed_ranges = make_range_tables(ranges)
        _SCANNERS_TABLE = (
            [elt[0] for elt in parsed_ranges],
            [elt[1] for elt in parsed_ranges],
        )
    if _CDN_TABLE is None:
        try:
            with open(
                os.path.join(DATA_PATH, "cdn_nuclei.py"), encoding="utf8"
            ) as fdesc:
                # pylint: disable=eval-used
                _CDN_TABLE = eval(compile(fdesc.read(), "cdn_nuclei", "eval"))
        except FileNotFoundError:
            LOGGER.warning(
                "Cannot find file [cdn_nuclei.py]. Try running `ivre getwebdata`"
            )
            _CDN_TABLE = ([], [])


def _get_name(table: Tuple[List[int], List[Optional[str]]], addr: str) -> Optional[str]:
    """Devs: please make sure _get_data() has been called before calling me!"""
    addr_i = ip2int(addr) if ":" in addr else ip2int(f"::ffff:{addr}")
    try:
        return table[1][bisect_left(table[0], addr_i)]
    except IndexError:
        return None


def gen_auto_tags(
    host: NmapHost, update_openports: bool = True
) -> Generator[Tag, None, None]:
    """This function generates the automatically-generated tags ("TOR",
    "Scanner", "Honeypot" and "Vulnerable" / "Likely vulnerable" /
    "Cannot test vuln", for now).

    If the host has too many (at least `VIEW_SYNACK_HONEYPOT_COUNT`)
    open ports that may be "syn-ack" honeypots (which means, ports for
    which is_real_service_port() returns False), this function will
    generate the "Honeypot" / "SYN+ACK honeypot" tag **and** clean the
    `host` record from the probable "SYN+ACK honeypot" ports.

    If the "ports" field of the host document has changed, the
    "openports" field is updated unless `update_openports` is False.

    """
    _get_data()
    assert _TOR_NODES is not None
    assert _SCANNERS_TABLE is not None
    assert _CDN_TABLE is not None
    addr = host.get("addr")
    if isinstance(addr, str):
        if addr in _TOR_NODES:
            yield cast(
                Tag,
                dict(
                    TAG_TOR,
                    info=[
                        "Exit node listed at <https://check.torproject.org/torbulkexitlist>"
                    ],
                ),
            )
        cdn_name = _get_name(_CDN_TABLE, addr)
        if cdn_name is not None:
            yield cast(
                Tag,
                dict(
                    TAG_CDN,
                    info=[f"{cdn_name} as listed at <https://cdn.nuclei.sh/>"],
                ),
            )
        scanner_name = _get_name(_SCANNERS_TABLE, addr)
        if scanner_name is not None:
            yield cast(
                Tag,
                dict(
                    TAG_SCANNER,
                    info=[f"Listed as a {scanner_name} scanner"],
                ),
            )
    for hname in host.get("hostnames", []):
        name = hname["name"]
        if name.endswith(".shodan.io") and "census" in name:
            yield cast(
                Tag,
                dict(
                    TAG_SCANNER,
                    info=[f"Hostname {name} suggests a Shodan scanner"],
                ),
            )
    for port in host.get("ports", []):
        if any("honeypot" in port.get(field, "").lower() for field in _SERVICE_FIELDS):
            cur_info = []
            for fld in _SERVICE_FIELDS:
                if fld in port:
                    cur_info.append(port[fld])
            yield cast(
                Tag,
                dict(
                    TAG_HONEYPOT,
                    info=[
                        f"{' / '.join(cur_info)} on port {port['protocol']}/{port['port']}"
                    ],
                ),
            )
        if port.get("service_name") in _TOR_SERVICES:
            yield cast(
                Tag,
                dict(
                    TAG_TOR,
                    info=[
                        f"Service {port['service_name']} found on port {port['protocol']}/{port['port']}"
                    ],
                ),
            )
        elif port.get("service_name") == "ssl":
            if port.get("service_product") == "Tor over SSL":
                yield cast(
                    Tag,
                    dict(
                        TAG_TOR,
                        info=[
                            f"ssl / {port['service_product']} found on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                )
        elif port.get("service_name") == "http":
            if port.get("service_product") in _TOR_HTTP_PRODUCTS:
                yield cast(
                    Tag,
                    dict(
                        TAG_TOR,
                        info=[
                            f"http / {port['service_product']} found on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                )
        for script in port.get("scripts", []):
            if script["id"] == "ssl-cert":
                for cert in script.get("ssl-cert", []):
                    if cert.get("sha1") in SSLBL_CERTIFICATES:
                        yield cast(
                            Tag,
                            dict(
                                TAG_MALWARE,
                                info=[
                                    f"{SSLBL_CERTIFICATES[cert['sha1']]} certificate on port {port['protocol']}/{port['port']} (SSL Blacklist by abuse.ch)"
                                ],
                            ),
                        )
                    elif (
                        TORCERT_SUBJECT.search(cert.get("subject_text", ""))
                        and TORCERT_SUBJECT.search(cert.get("issuer_text", ""))
                        and cert.get("subject_text") != cert.get("issuer_text")
                    ):
                        yield cast(
                            Tag,
                            dict(
                                TAG_TOR,
                                info=[
                                    f"TOR certificate on port {port['protocol']}/{port['port']}"
                                ],
                            ),
                        )
            elif script["id"] == "ssl-ja3-client":
                for ja3fp in script.get("ssl-ja3-client", []):
                    if ja3fp.get("md5") in SSLBL_JA3:
                        yield cast(
                            Tag,
                            dict(
                                TAG_MALWARE,
                                info=[
                                    f"{SSLBL_JA3[ja3fp['md5']]} JA3 client fingerprint (SSL Blacklist by abuse.ch)"
                                ],
                            ),
                        )
            elif script["id"] == "http-title":
                tag = {
                    "This is a Tor Exit Router": dict(
                        TAG_TOR,
                        info=[
                            f"TOR exit node notice on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                    "This is a SOCKS Proxy, Not An HTTP Proxy": dict(
                        TAG_TOR,
                        info=[
                            f"TOR SOCKS Proxy notice on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                    "This is an HTTP CONNECT tunnel, not a full HTTP Proxy": dict(
                        TAG_TOR,
                        info=[
                            f"TOR HTTP CONNECT tunnel notice on port {port['protocol']}/{port['port']}"
                        ],
                    ),
                }.get(script["output"])
                if tag is not None:
                    yield cast(Tag, tag)
            elif script["id"] == "scanner":
                if port["port"] != -1:
                    continue
                scanners = sorted(
                    set(
                        scanner["name"]
                        for scanner in script.get("scanner", {}).get("scanners", [])
                    )
                )
                if scanners:
                    yield cast(Tag, dict(TAG_SCANNER, info=scanners))
                else:
                    yield TAG_SCANNER
            elif script["id"] == "http-default-accounts":
                for app in script.get("http-default-accounts", []):
                    if not app.get("credentials"):
                        continue
                    creds = [
                        f"{cred['username']} / {cred['password']}"
                        for cred in app["credentials"]
                    ]
                    yield cast(
                        Tag,
                        dict(
                            TAG_DEFAULT_PASSWORD,
                            info=[f"{app['name']}: {', '.join(creds)}"],
                        ),
                    )
            elif "vulns" in script:
                for vuln in script["vulns"]:
                    state = vuln.get("state", "")
                    if state.startswith("VULNERABLE"):
                        if "id" in vuln:
                            yield cast(Tag, dict(TAG_VULN, info=[vuln["id"]]))
                        else:
                            yield TAG_VULN
                    elif state.startswith("LIKELY VULNERABLE"):
                        if "id" in vuln:
                            yield cast(Tag, dict(TAG_VULN_LIKELY, info=[vuln["id"]]))
                        else:
                            yield TAG_VULN_LIKELY
                    elif state.startswith("UNKNOWN"):
                        if "id" in vuln:
                            yield cast(
                                Tag, dict(TAG_VULN_CANNOT_TEST, info=[vuln["id"]])
                            )
                        else:
                            yield TAG_VULN_CANNOT_TEST
            elif "nuclei" in script:
                for template in script["nuclei"]:
                    template_id = template.get("template", "")
                    template_name = template.get("name", "")
                    info = (
                        template_id
                        if template_id == template_name
                        else f"{template_id} / {template_name}"
                    )
                    if template_id.startswith("CVE-"):
                        yield cast(Tag, dict(TAG_VULN, info=[info]))
                    elif template_name.startswith("CVE-"):
                        yield cast(Tag, dict(TAG_VULN, info=[info]))
                    elif any(
                        template_id.endswith(f"-{suffix}")
                        for suffix in [
                            "default-login",
                            "weak-login",
                            "weak-password",
                            "default-admin",
                        ]
                    ) or template_id in {
                        "google-earth-dlogin",
                        "oracle-business-intelligence-login",
                        "trilithic-viewpoint-default",
                    }:
                        yield cast(Tag, dict(TAG_DEFAULT_PASSWORD, info=[info]))
                    elif template_name.endswith("Default Password"):
                        yield cast(Tag, dict(TAG_DEFAULT_PASSWORD, info=[info]))
    # Now the "Honeypot" / "SYN+ACK honeypot" tag:
    n_ports = len(host.get("ports", []))
    if n_ports and is_synack_honeypot(host):
        # 1. If the host is already considered a SYN+ACK honeypot,
        # let's just clean the ports
        newports = [port for port in host["ports"] if is_real_service_port(port)]
        if len(newports) != n_ports:
            host["ports"] = newports
            if update_openports:
                set_openports_attribute(host)
        return
    # 2. ... Else, let's see if we should add the tag
    if VIEW_SYNACK_HONEYPOT_COUNT is None:
        return
    if n_ports < VIEW_SYNACK_HONEYPOT_COUNT:
        return
    # check if we have too many open ports that could be "syn-ack
    # honeypots"...
    newports = [port for port in host["ports"] if is_real_service_port(port)]
    if n_ports - len(newports) > VIEW_SYNACK_HONEYPOT_COUNT:
        # ... if so, keep only the ports that cannot be "syn-ack
        # honeypots"
        host["ports"] = newports
        if update_openports:
            set_openports_attribute(host)
        yield cast(Tag, dict(TAG_HONEYPOT, info=["SYN+ACK honeypot"]))


def set_auto_tags(host: NmapHost, update_openports: bool = True) -> None:
    """This function sets the automatically-generated tags ("TOR",
    "Scanner", "Honeypot" and "Vulnerable" / "Likely vulnerable" /
    "Cannot test vuln", for now).

    """
    add_tags(host, gen_auto_tags(host, update_openports=update_openports))


def merge_ja3_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def is_server(script_id: str) -> bool:
        return script_id == "ssl-ja3-server"

    def ja3_equals(a: Dict[str, Any], b: Dict[str, Any], script_id: str) -> bool:
        return a["raw"] == b["raw"] and (
            not is_server(script_id) or a["client"]["raw"] == b["client"]["raw"]
        )

    def ja3_output(ja3: Dict[str, Any], script_id: str) -> str:
        output = cast(str, ja3["md5"])
        if is_server(script_id):
            output += " - " + ja3["client"]["md5"]
        return output

    return _merge_scripts(curscript, script, script_id, ja3_equals, ja3_output)


def merge_http_app_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def http_app_equals(a: Dict[str, Any], b: Dict[str, Any], script_id: str) -> bool:
        return cast(
            bool, a["application"] == b["application"] and a["path"] == b["path"]
        )

    def http_app_output(app: Dict[str, Any], script_id: str) -> str:
        output = ["%(application)s: path %(path)s" % app]
        if app.get("version") is not None:
            output.append(", version %(version)s" % app)
            if app.get("parsed_version") is not None:
                output.append(" (%(parsed_version)s)" % app)
            elif app.get("application") == "OWA":
                app["parsed_version"] = EXCHANGE_BUILDS.get(
                    app["version"], "unknown build number"
                )
                output.append(" (%(parsed_version)s)" % app)
        return "".join(output)

    return _merge_scripts(
        curscript, script, script_id, http_app_equals, http_app_output
    )


def merge_ua_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def ua_equals(a: str, b: str, script_id: str) -> bool:
        return a == b

    def ua_output(ua: str, script_id: str) -> str:
        return ua

    return _merge_scripts(curscript, script, script_id, ua_equals, ua_output)


def merge_ssl_cert_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def cert_equals(a: ParsedCertificate, b: ParsedCertificate, script_id: str) -> bool:
        return cast(bool, a["sha256"] == b["sha256"])

    def cert_output(cert: Dict[str, Any], script_id: str) -> str:
        return "\n".join(create_ssl_output(cert))

    return _merge_scripts(
        curscript,
        script,
        script_id,
        cert_equals,
        cert_output,
        outsep="\n------------------------------------------------------------"
        "----\n",
    )


def merge_axfr_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    # If one results has no structured output, keep the other
    # one. Prefer curscript over script.
    if script_id not in script:
        return curscript
    if script_id not in curscript:
        curscript["output"] = script["output"]
        curscript[script_id] = script[script_id]
        return script
    res: List[Dict[str, Any]] = []
    for data in chain(curscript[script_id], script[script_id]):
        if any(data["domain"] == r["domain"] for r in res):
            continue
        res.append(data)
    res = sorted(res, key=lambda r: key_sort_dom(r["domain"]))
    line_fmt = "| %%-%ds  %%-%ds  %%s" % (
        max(len(r["name"]) for data in res for r in data["records"]),
        max(len(r["type"]) for data in res for r in data["records"]),
    )
    curscript["output"] = "\n".join(
        "\nDomain: %s\n%s\n\\\n"
        % (
            data["domain"],
            "\n".join(
                line_fmt % (r["name"], r["type"], r["data"]) for r in data["records"]
            ),
        )
        for data in res
    )
    curscript[script_id] = res
    return curscript


def merge_scanner_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    # If one results has no structured output, keep the other
    # one. Prefer curscript over script.
    if script_id not in script:
        return curscript
    if script_id not in curscript:
        curscript["output"] = script["output"]
        curscript[script_id] = script[script_id]
        return script
    res: Dict[str, Any] = {}
    for data in [curscript[script_id], script[script_id]]:
        for proto, ports in data.get("ports", {}).items():
            if proto == "count":
                continue
            res.setdefault("ports", {}).setdefault(proto, {}).setdefault(
                "ports", set()
            ).update(ports.get("ports", []))
        for uri in data.get("http_uris", []):
            res.setdefault("http_uris", set()).add(
                (
                    uri["uri"],
                    uri["method"],
                    uri["version"],
                )
            )
        for query in data.get("dns_queries", []):
            res.setdefault("dns_queries", set()).add(
                (
                    query["query"],
                    query["qtype"],
                    query["qclass"],
                )
            )
        for scanner in data.get("scanners", []):
            res.setdefault("scanners", {}).setdefault(scanner["name"], set()).update(
                (probe["proto"], probe.get("name"))
                for probe in scanner.get("probes", [])
            )
        res.setdefault("probes", set()).update(
            (probe["proto"], probe["value"]) for probe in data.get("probes", [])
        )
    for proto, ports in list(res.get("ports", {}).items()):
        res["ports"][proto]["ports"] = sorted(ports["ports"])
        nports = len(ports["ports"])
        res["ports"][proto]["count"] = nports
        res["ports"]["count"] = res["ports"].get("count", 0) + nports
    if "http_uris" in res:
        res["http_uris"] = [
            {"uri": uri, "method": method, "version": version}
            for uri, method, version in sorted(res["http_uris"])
        ]
    if "dns_queries" in res:
        res["dns_queries"] = [
            {"query": query, "qtype": qtype, "qclass": qclass}
            for query, qtype, qclass in sorted(res["dns_queries"])
        ]
    scanners = []
    for name, probes in res.get("scanners", {}).items():
        scanner = {"name": name}
        if probes:
            scanner["probes"] = [
                {"proto": proto, "name": name} for proto, name in sorted(probes)
            ]
        scanners.append(scanner)
    if scanners:
        res["scanners"] = scanners
    if "probes" in res:
        res["probes"] = [
            {"proto": proto, "value": value} for proto, value in sorted(res["probes"])
        ]
    curscript[script_id] = res
    output = []
    if res.get("ports"):
        output.append(
            "Scanned port%s: %s"
            % (
                "s" if res["ports"]["count"] > 1 else "",
                ", ".join(
                    "%s: %s" % (proto, ports2nmapspec(ports["ports"]))
                    for proto, ports in res.get("ports", {}).items()
                    if proto != "count"
                ),
            )
        )
    if res.get("http_uris"):
        uris_methods: Dict[str, Set[str]] = {}
        uris_versions: Dict[str, Set[str]] = {}
        for uri in res["http_uris"]:
            uris_methods.setdefault(uri["uri"], set()).add(uri["method"])
            uris_versions.setdefault(uri["uri"], set()).add(uri["version"])
        output.append(
            "Scanned URI%s: %s"
            % (
                "s" if len(uris_versions) > 1 else "",
                ", ".join(
                    "%s (%s %s)"
                    % (
                        uri,
                        ", ".join(uris_methods[uri]),
                        ", ".join(uris_versions[uri]),
                    )
                    for uri in sorted(uris_versions)
                ),
            )
        )
    if res.get("dns_queries"):
        queries_qtype: Dict[str, Set[str]] = {}
        queries_qclass: Dict[str, Set[str]] = {}
        for query in res["dns_queries"]:
            queries_qtype.setdefault(query["query"], set()).add(query["qtype"])
            queries_qclass.setdefault(query["query"], set()).add(query["qclass"])
        output.append(
            "DNS quer%s: %s"
            % (
                "ies" if len(queries_qtype) > 1 else "y",
                ", ".join(
                    "%s (type: %s, class: %s)"
                    % (
                        query,
                        ", ".join(queries_qtype[query]),
                        ", ".join(queries_qclass[query]),
                    )
                    for query in sorted(queries_qtype)
                ),
            )
        )
    if scanners:

        def _fmt_sc(sc: Dict[str, Any]) -> str:
            res = sc["name"]  # type: str
            if "probes" in sc:
                res += " [%s]" % ", ".join(
                    "%s/%s" % (x["name"], x["proto"]) for x in sc["probes"]
                )
            return res

        output.append(
            "Scanner%s: \n - %s"
            % (
                "s" if len(scanners) > 1 else "",
                "\n - ".join(_fmt_sc(scanner) for scanner in scanners),
            )
        )
    curscript["output"] = "\n".join(output)
    return curscript


def merge_nuclei_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    def nuclei_equals(a: Dict[str, Any], b: Dict[str, Any], script_id: str) -> bool:
        return a == b

    def nuclei_output(nuclei: Dict[str, Any], script_id: str) -> str:
        return "[%(severity)s] %(name)s found at %(url)s" % nuclei

    return _merge_scripts(curscript, script, script_id, nuclei_equals, nuclei_output)


def merge_http_git_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    repos: Dict[str, Any] = {}
    for scr in [script, curscript]:
        for rep in scr.get(script_id, []):
            repos.setdefault(rep["repository"], set()).update(
                rep.get("files-found", [])
            )
    repos_order = sorted(repos)
    data = [
        {"repository": rep, "files-found": sorted(repos[rep])} for rep in repos_order
    ]
    output = "\n".join(
        "\n  %s\n    Git repository found!\n" % rep for rep in repos_order
    )
    curscript["output"] = output
    curscript[script_id] = data
    return curscript


def merge_dns_domains_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    domains = {
        res["domain"]: (
            res["parents"] if "parents" in res else list(get_domains(res["domain"]))
        )
        for scr in [script, curscript]
        for res in scr.get(script_id, [])
        if "domain" in res
    }
    domains_order = sorted(domains, key=key_sort_dom)
    if len(domains_order) == 1:
        output = "Server is authoritative for %s" % domains_order[0]
    else:
        output = "Server is authoritative for:\n%s" % "\n".join(
            "  %s" % dom for dom in domains_order
        )
    curscript["output"] = output
    curscript[script_id] = [
        {"domain": dom, "parents": domains[dom]} for dom in domains_order
    ]
    return curscript


def merge_dns_tls_rpt_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    # overwrite results from script by those from curscript
    domains = {
        res["domain"]: res
        for scr in [script, curscript]
        for res in scr.get(script_id, [])
        if "domain" in res
    }
    domains_order = sorted(domains, key=key_sort_dom)
    output = []
    for dom in domains_order:
        cur_data = domains[dom]
        if "warnings" not in cur_data:
            output.append("Domain %s has a valid TLS-RPT configuration" % dom)
            continue
        warnings = cur_data["warnings"]
        if warnings == ["Domain has no TLS-RPT configuration"]:
            output.append("Domain %s has no TLS-RPT configuration" % dom)
            continue
        if warnings == ["Domain has more than one TLS-RPT configuration"]:
            output.append("Domain %s has more than one TLS-RPT configuration" % dom)
            continue
        output.append(
            "Domain %s has a TLS-RPT configuration with warnings:\n%s"
            % (
                dom,
                "\n".join(warnings),
            )
        )
    curscript["output"] = "\n".join(output)
    curscript[script_id] = [domains[dom] for dom in domains_order]
    return curscript


def merge_dns_check_consistency_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    # overwrite results from script by those from curscript
    domains_name_type = {
        (res["domain"], res["name"], res["rtype"]): res
        for scr in [script, curscript]
        for res in scr.get(script_id, [])
        if "domain" in res
    }
    domains_name_type_order = sorted(
        domains_name_type,
        key=lambda v: (
            key_sort_dom(v[0]),
            key_sort_dom(v[1]),
            v[2],
        ),
    )
    curscript["output"] = "DNS inconsistency\n\n%s" % "\n\n".join(
        "%s (%s)\nThis server:\n%s\nMost common answer:\n%s"
        % (
            name,
            rtype,
            "\n".join("  %r" % r for r in cur_data["value"]),
            "\n".join("  %r" % r for r in cur_data["reference_value"]),
        )
        for domain, name, rtype, cur_data in (
            (domain, name, rtype, domains_name_type[(domain, name, rtype)])
            for domain, name, rtype in domains_name_type_order
        )
    )
    curscript[script_id] = [domains_name_type[dnt] for dnt in domains_name_type_order]
    return curscript


def _merge_scripts(
    curscript: NmapScript,
    script: NmapScript,
    script_id: str,
    script_equals: Union[
        Callable[[Dict[str, Any], Dict[str, Any], str], bool],
        Callable[[str, str, str], bool],
    ],
    script_output: Union[
        Callable[[Dict[str, Any], str], str], Callable[[str, str], str]
    ],
    outsep: str = "\n",
) -> NmapScript:
    """Helper function to merge two scripts and return the result, using
    specific functions `script_equals` and `script_output`.

    """
    to_merge_list = []
    script_id_alias = ALIASES_TABLE_ELEMS.get(script_id, script_id)
    for to_add in script.setdefault(script_id_alias, []):
        to_merge = True
        for cur in curscript.get(script_id_alias, []):
            if script_equals(to_add, cur, script_id):
                to_merge = False
                break
        if to_merge:
            to_merge_list.append(to_add)
    curscript.setdefault(script_id_alias, []).extend(to_merge_list)
    # Compute output from curscript[script_id_alias]
    output = []
    for el in curscript[script_id_alias]:
        output.append(script_output(el, script_id))
    if output:
        curscript["output"] = outsep.join(output) + "\n"
    else:
        curscript["output"] = ""
    return curscript


_SCRIPT_MERGE = {
    "dns-check-consistency": merge_dns_check_consistency_scripts,
    "dns-domains": merge_dns_domains_scripts,
    "dns-tls-rpt": merge_dns_tls_rpt_scripts,
    "dns-zone-transfer": merge_axfr_scripts,
    "http-app": merge_http_app_scripts,
    "http-git": merge_http_git_scripts,
    "http-nuclei": merge_nuclei_scripts,
    "http-user-agent": merge_ua_scripts,
    "network-nuclei": merge_nuclei_scripts,
    "scanner": merge_scanner_scripts,
    "ssl-cacert": merge_ssl_cert_scripts,
    "ssl-cert": merge_ssl_cert_scripts,
    "ssl-ja3-client": merge_ja3_scripts,
    "ssl-ja3-server": merge_ja3_scripts,
}


def merge_scripts(
    curscript: NmapScript, script: NmapScript, script_id: str
) -> NmapScript:
    """Merge curscript with script"""
    try:
        func = _SCRIPT_MERGE[script_id]
    except KeyError:
        return {}
    return func(curscript, script, script_id)


def merge_host_docs(rec1: NmapHost, rec2: NmapHost) -> NmapHost:
    """Merge two host records and return the result. Unmergeable /
    hard-to-merge fields are lost (e.g., extraports).

    """
    if rec1.get("schema_version") != rec2.get("schema_version"):
        raise ValueError(
            "Cannot merge host documents. "
            "Schema versions differ (%r != %r)"
            % (rec1.get("schema_version"), rec2.get("schema_version"))
        )
    rec = {}
    if "schema_version" in rec1:
        rec["schema_version"] = rec1["schema_version"]
    # When we have different values, we will use the one from the
    # most recent scan, rec2. If one result has no "endtime", we
    # consider it as older.
    if (rec1.get("endtime") or datetime.fromtimestamp(0)) > (
        rec2.get("endtime") or datetime.fromtimestamp(0)
    ):
        rec1, rec2 = rec2, rec1
    for fname, function in [("starttime", min), ("endtime", max)]:
        try:
            rec[fname] = function(
                record[fname] for record in [rec1, rec2] if fname in record
            )
        except ValueError:
            pass
    sa_honeypot = is_synack_honeypot(rec1) or is_synack_honeypot(rec2)
    rec["state"] = "up" if rec1.get("state") == "up" else rec2.get("state")
    if rec["state"] is None:
        del rec["state"]
    rec["state_reason"] = rec2.get("state_reason", rec1.get("state_reason"))
    if rec["state_reason"] is None:
        del rec["state_reason"]
    rec["categories"] = list(
        set(rec1.get("categories", [])).union(rec2.get("categories", []))
    )
    for field in ["addr", "os"]:
        rec[field] = rec2[field] if rec2.get(field) else rec1.get(field)
        if not rec[field]:
            del rec[field]
    rec["source"] = list(set(rec1.get("source", [])).union(set(rec2.get("source", []))))
    rec["traces"] = rec2.get("traces", [])
    for trace in rec1.get("traces", []):
        # Skip this result (from rec1) if a more recent traceroute
        # result exists using the same protocol and port in the
        # most recent scan (rec2).
        if any(
            other["protocol"] == trace["protocol"]
            and other.get("port") == trace.get("port")
            for other in rec["traces"]
        ):
            continue
        rec["traces"].append(trace)
    rec["cpes"] = rec2.get("cpes", [])
    for cpe in rec1.get("cpes", []):
        origins = set(cpe.pop("origins", []))
        cpe["origins"] = None
        try:
            other = next(
                ocpe for ocpe in rec["cpes"] if dict(ocpe, origins=None) == cpe
            )
        except StopIteration:
            rec["cpes"].append(dict(cpe, origins=origins))
        else:
            other["origins"] = set(other.get("origins", [])).union(origins)
    for cpe in rec["cpes"]:
        cpe["origins"] = list(cpe.get("origins", []))
    rec["infos"] = {}
    for record in [rec1, rec2]:
        rec["infos"].update(record.get("infos", {}))
    # We want to make sure of (type, name) unicity
    hostnames = dict(
        ((h["type"], h["name"]), h.get("domains"))
        for h in (rec1.get("hostnames", []) + rec2.get("hostnames", []))
    )
    rec["hostnames"] = [
        {"type": h[0], "name": h[1], "domains": d} for h, d in hostnames.items()
    ]
    addresses: NmapAddress = {}
    for record in [rec1, rec2]:
        for atype, addrs in record.get("addresses", {}).items():
            cur_addrs = addresses.setdefault(atype, [])
            for addr in addrs:
                addr = addr.lower()
                if addr not in cur_addrs:
                    cur_addrs.append(addr)
        if "tags" in record:
            add_tags(rec, record["tags"])
    if addresses:
        rec["addresses"] = addresses
    if sa_honeypot:
        add_tags(
            rec,
            [{"value": "Honeypot", "type": "warning", "info": ["SYN+ACK honeypot"]}],
        )
        for record in [rec1, rec2]:
            if not is_synack_honeypot(record):
                record["ports"] = [
                    port
                    for port in record.get("ports", [])
                    if is_real_service_port(port)
                ]
    ports = dict(
        ((port.get("protocol"), port["port"]), port.copy())
        for port in rec2.get("ports", [])
    )
    for port in rec1.get("ports", []):
        if (port.get("protocol"), port["port"]) in ports:
            curport = ports[(port.get("protocol"), port["port"])]
            if "scripts" in curport:
                curport["scripts"] = curport["scripts"][:]
            else:
                curport["scripts"] = []
            present_scripts = set(script["id"] for script in curport["scripts"])
            for script in port.get("scripts", []):
                if script["id"] not in present_scripts:
                    curport["scripts"].append(script)
                elif script["id"] in _SCRIPT_MERGE:
                    # Merge scripts
                    curscript = next(
                        x for x in curport["scripts"] if x["id"] == script["id"]
                    )
                    merge_scripts(curscript, script, script["id"])
            if not curport["scripts"]:
                del curport["scripts"]
            if "service_name" in port:
                if "service_name" not in curport:
                    for key in port:
                        if key.startswith("service_"):
                            curport[key] = port[key]
                elif port["service_name"] == curport["service_name"]:
                    # if the "old" record has information missing
                    # from the "new" record and information from
                    # both records is consistent, let's keep the
                    # "old" data.
                    for key in port:
                        if key.startswith("service_") and key not in curport:
                            curport[key] = port[key]
            if "screenshot" in port and "screenshot" not in curport:
                for key in ["screenshot", "screendata", "screenwords"]:
                    if key in port:
                        curport[key] = port[key]
        else:
            ports[(port.get("protocol"), port["port"])] = port
    rec["ports"] = sorted(
        ports.values(),
        key=lambda port: (
            port.get("protocol") or "~",
            port.get("port"),
        ),
    )
    set_auto_tags(rec, update_openports=False)
    set_openports_attribute(rec)
    for field in ["traces", "infos", "ports", "cpes"]:
        if not rec[field]:
            del rec[field]
    return rec


_EXPR_INDEX_OF = re.compile(
    b"<title[^>]*> *(?:index +of|directory +listing +(?:of|for))",
    re.I,
)
_EXPR_FILES = [
    re.compile(
        b'<a href="(?P<filename>[^"]+)">[^<]+</a></td><td[^>]*> *'
        b"(?P<time>[0-9]+-[a-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *"
        b"</td><td[^>]*> *(?P<size>[^<]+)</td>",
        re.I,
    ),
    re.compile(
        b'<a href="(?P<filename>[^"]+)">[^<]+</a> *'
        b"(?P<time>[0-9]+-[a-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *"
        b"(?P<size>[^ \r\n]+)",
        re.I,
    ),
    re.compile(b'<li><a href="(?P<filename>[^"]+)">(?P=filename)</a>'),
]


def create_http_ls(data: bytes, volname: str = "???") -> Optional[NmapScript]:
    """Produces an http-ls script output (both structured and human
    readable) from the content of an HTML page. Used for Zgrab and Masscan
    results.

    """
    match = _EXPR_INDEX_OF.search(data)
    if match is None:
        return None
    files = []
    for pattern in _EXPR_FILES:
        for match in pattern.finditer(data):
            files.append(
                {
                    key: nmap_encode_data(value)
                    for key, value in match.groupdict().items()
                }
            )
    if not files:
        return None
    output = []
    output.append("Volume %s" % volname)
    title = ["size", "time", "filename"]
    column_width = [len(t) for t in title[:-1]]
    for fobj in files:
        for i, t in enumerate(title[:-1]):
            column_width[i] = max(column_width[i], len(fobj.get(t, "-")))
    line_fmt = "%%(size)-%ds  %%(time)-%ds  %%(filename)s" % tuple(column_width)
    output.append(line_fmt % dict((t, t.upper()) for t in title))
    for fobj in files:
        output.append(line_fmt % dict({"size": "-", "time": "-"}, **fobj))
    output.append("")
    return {
        "id": "http-ls",
        "output": "\n".join(output),
        "ls": {"volumes": [{"volume": volname, "files": files}]},
    }


def create_elasticsearch_service(data: bytes) -> Optional[NmapServiceMatch]:
    """Produces the service_* attributes from the (JSON) content of an
    HTTP response. Used for Zgrab and Masscan results.

    """
    try:
        data_p = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data_p, dict):
        return None
    if "tagline" not in data_p:
        if "error" not in data_p:
            return None
        error = data_p["error"]
        if isinstance(error, str):
            if data_p.get("status") == 401 and error.startswith(
                "AuthenticationException"
            ):
                return {
                    "service_name": "http",
                    "service_product": "Elasticsearch REST API",
                    "service_extrainfo": "Authentication required",
                    "cpe": ["cpe:/a:elasticsearch:elasticsearch"],
                }
            return None
        if not isinstance(error, dict):
            return None
        if not (data_p.get("status") == 401 or error.get("status") == 401):
            return None
        if "root_cause" in error:
            return {
                "service_name": "http",
                "service_product": "Elasticsearch REST API",
                "service_extrainfo": "Authentication required",
                "cpe": ["cpe:/a:elasticsearch:elasticsearch"],
            }
        return None
    if data_p["tagline"] != "You Know, for Search":
        return None
    result: NmapServiceMatch = {
        "service_name": "http",
        "service_product": "Elasticsearch REST API",
    }
    cpe = []
    if "version" in data_p and "number" in data_p["version"]:
        result["service_version"] = data_p["version"]["number"]
        cpe.append(
            "cpe:/a:elasticsearch:elasticsearch:%s" % data_p["version"]["number"]
        )
    extrainfo = []
    if "name" in data_p:
        extrainfo.append("name: %s" % data_p["name"])
        result["service_hostname"] = data_p["name"]
    if "cluster_name" in data_p:
        extrainfo.append("cluster: %s" % data_p["cluster_name"])
    if "version" in data_p and "lucene_version" in data_p["version"]:
        extrainfo.append("Lucene %s" % data_p["version"]["lucene_version"])
        cpe.append("cpe:/a:apache:lucene:%s" % data_p["version"]["lucene_version"])
    if extrainfo:
        result["service_extrainfo"] = "; ".join(extrainfo)
    if cpe:
        result["cpe"] = cpe
    return result


# This is not a real hostname regexp, but a simple way to exclude
# obviously wrong values. Underscores should not exist in (DNS)
# hostnames, but since they happen to exist anyway, we allow them
# here.
_HOSTNAME = re.compile("^[a-z0-9_\\.\\*\\-]+$", re.I)


def add_hostname(name: str, name_type: str, hostnames: List[NmapHostname]) -> None:
    name = name.rstrip(".").lower()
    if not _HOSTNAME.search(name):
        return
    # exclude IPv4 addresses
    if IPV4ADDR.search(name):
        return
    if any(hn["name"] == name and hn["type"] == name_type for hn in hostnames):
        return
    hostnames.append(
        {
            "type": name_type,
            "name": name,
            "domains": list(get_domains(name)),
        }
    )


_EXPR_TITLE = re.compile(b"<title[^>]*>([^<]*)</title>", re.I)


def handle_http_content(
    host: NmapHost,
    port: NmapPort,
    data: bytes,
    path: str = "/",
) -> None:
    title_m = _EXPR_TITLE.search(data)
    if title_m is not None:
        title = nmap_encode_data(title_m.groups()[0])
        port.setdefault("scripts", []).append(
            {
                "id": "http-title",
                "output": title,
                "http-title": {"title": title},
            }
        )
    script_http_ls = create_http_ls(data, volname=path)
    if script_http_ls is not None:
        port.setdefault("scripts", []).append(script_http_ls)
    service_elasticsearch = create_elasticsearch_service(data)
    if service_elasticsearch:
        if "service_hostname" in service_elasticsearch:
            add_hostname(
                service_elasticsearch["service_hostname"],
                "service",
                host.setdefault("hostnames", []),
            )
        add_cpe_values(
            host, "ports.port:%s" % port, service_elasticsearch.pop("cpe", [])
        )
        port.update(cast(NmapPort, service_elasticsearch))


def handle_http_headers(
    host: NmapHost,
    port: NmapPort,
    headers: List[HttpHeader],
    path: str = "/",
    handle_server: bool = True,
) -> None:
    """This function enriches scan results based on HTTP headers reported
    by the Nmap script http-headers or any similar report, such as
    Masscan or Zgrab(2).

    """
    # * Add a script "http-server-header" if it does not exist
    if handle_server:
        srv_headers = [
            h["value"] for h in headers if h["name"] == "server" and h["value"]
        ]
        if srv_headers and not any(
            s["id"] == "http-server-header" for s in port.get("scripts", [])
        ):
            port.setdefault("scripts", []).append(
                {
                    "id": "http-server-header",
                    "output": "\n".join(srv_headers),
                    "http-server-header": srv_headers,
                }
            )
    # * Add a script "http-app" for MS SharePoint, and merge it if
    # necessary
    try:
        header = next(
            h["value"]
            for h in headers
            if h["name"] == "microsoftsharepointteamservices" and h["value"]
        )
    except StopIteration:
        pass
    else:
        version = header.split(":", 1)[0]
        add_cpe_values(
            host,
            "ports.port:%s" % port.get("port", -1),
            ["cpe:/a:microsoft:sharepoint_server:%s" % version],
        )
        script = {
            "id": "http-app",
            "output": "SharePoint: path %s, version %s" % (path, version),
            "http-app": [
                {"path": path, "application": "SharePoint", "version": version}
            ],
        }
        try:
            cur_script = next(
                s for s in port.get("scripts", []) if s["id"] == "http-app"
            )
        except StopIteration:
            port.setdefault("scripts", []).append(script)
        else:
            merge_http_app_scripts(cur_script, script, "http-app")
    # * Add a script "http-app" for Kibana, and merge it if necessary
    try:
        header = next(
            h["value"] for h in headers if h["name"] == "kbn-name" and h["value"]
        )
    except StopIteration:
        pass
    else:
        try:
            location = next(
                h["value"] for h in headers if h["name"] == "location" and h["value"]
            )
        except StopIteration:
            path_k = path
        else:
            path_k = os.path.join(path, location)
        structured = {"path": path_k, "application": "Kibana"}
        try:
            version = next(
                h["value"] for h in headers if h["name"] == "kbn-version" and h["value"]
            )
        except StopIteration:
            output = f"Kibana: path {path_k}"
            add_cpe_values(
                host,
                "ports.port:%s" % port.get("port", -1),
                ["cpe:/a:elasticsearch:kibana"],
            )
        else:
            output = f"Kibana: path {path_k}, version {version}"
            structured["version"] = version
            add_cpe_values(
                host,
                "ports.port:%s" % port.get("port", -1),
                [f"cpe:/a:elasticsearch:kibana:{version}"],
            )
        script = {"id": "http-app", "output": output, "http-app": [structured]}
        try:
            cur_script = next(
                s for s in port.get("scripts", []) if s["id"] == "http-app"
            )
        except StopIteration:
            port.setdefault("scripts", []).append(script)
        else:
            merge_http_app_scripts(cur_script, script, "http-app")
