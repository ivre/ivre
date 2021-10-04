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


"""Put selected results in views."""


from datetime import datetime
from textwrap import wrap


from ivre.active.cpe import add_cpe_values
from ivre.active.data import create_ssl_output, set_openports_attribute
from ivre.data import scanners
from ivre.db import db
from ivre.passive import SCHEMA_VERSION as PASSIVE_SCHEMA_VERSION
from ivre import utils
from ivre.xmlnmap import SCHEMA_VERSION as ACTIVE_SCHEMA_VERSION, add_hostname


def _extract_passive_HTTP_CLIENT_HEADER_SERVER(rec):
    """Handle http client header about server."""
    return {
        "ports": [
            {
                "state_state": "open",
                "state_reason": "passive",
                "port": rec["port"],
                "protocol": rec.get("protocol", "tcp"),
                "service_name": "http",
            }
        ]
    }
    # TODO: (?) handle Host: header for DNS
    # FIXME: catches ip addresses as domain name.
    # if 'source' in rec and rec['source'] == 'HOST':
    #     values = rec['value'].split(".")
    #     domains = [values.pop()]
    #     while values:
    #         domains.insert(0, values.pop() + "." + domains[0])
    #     return {'hostnames': [{'domains': domains,
    #                            'type': "?",
    #                            'name': domains[0]}]}


def _extract_passive_HTTP_SERVER_HEADER(rec):
    """Handle http server headers."""
    if (
        rec["value"]
        and rec.get("source") in ["WWW-AUTHENTICATE", "PROXY-AUTHENTICATE"]
        and rec["value"].split(None, 1)[0].lower() in {"ntlm", "negotiate"}
        and len(rec["value"].split(None, 1)) > 1
    ):
        return _extract_passive_NTLM(rec, service="http")
    port = {
        "state_state": "open",
        "state_reason": "passive",
        "port": rec["port"],
        "protocol": rec.get("protocol", "tcp"),
        "service_name": "http",
    }
    host = {"ports": [port]}
    if rec.get("source") == "MICROSOFTSHAREPOINTTEAMSERVICES":
        version = rec["value"].split(":", 1)[0]
        add_cpe_values(
            host,
            "ports.port:%s" % port["port"],
            ["cpe:/a:microsoft:sharepoint_server:%s" % version],
        )
        host["cpes"] = list(host["cpes"].values())
        # Let's pretend the application is on '/UNKNOWN/'
        port["scripts"] = [
            {
                "id": "http-app",
                "output": "SharePoint: path /UNKNOWN/, version %s" % (version),
                "http-app": [
                    {
                        "path": "/UNKNOWN/",
                        "application": "SharePoint",
                        "version": version,
                    }
                ],
            }
        ]
        return host
    # TODO: handle other header values and merge them
    if rec.get("source") != "SERVER":
        return host
    value = rec["value"]
    script = {"id": "http-server-header", "output": value}
    port["scripts"] = [script]
    banner = (
        b"HTTP/1.1 200 OK\r\nServer: " + utils.nmap_decode_data(value) + b"\r\n\r\n"
    )
    nmap_info = utils.match_nmap_svc_fp(
        output=banner, proto=rec.get("protocol", "tcp"), probe="GetRequest"
    )
    add_cpe_values(host, "ports.port:%s" % port, nmap_info.pop("cpe", []))
    host["cpes"] = list(host["cpes"].values())
    for cpe in host["cpes"]:
        cpe["origins"] = sorted(cpe["origins"])
    if not host["cpes"]:
        del host["cpes"]
    port.update(nmap_info)
    return host


def _extract_passive_HTTP_CLIENT_HEADER(rec):
    """Handle http client headers."""
    # TODO: handle other header values
    if (
        rec["value"]
        and rec.get("source") in ["AUTHORIZATION", "PROXY-AUTHORIZATION"]
        and rec["value"].split(None, 1)[0].lower() in {"ntlm", "negotiate"}
        and len(rec["value"].split(None, 1)) > 1
    ):
        return _extract_passive_NTLM(rec, service="http")
    if rec.get("source") != "USER-AGENT":
        return {}
    scripts = [
        {
            "id": "http-user-agent",
            "output": rec["value"],
            "http-user-agent": [rec["value"]],
        }
    ]
    if rec["value"] in scanners.USER_AGENT_VALUES:
        scanner, probe = scanners.USER_AGENT_VALUES[rec["value"]]
        structured_output = {"scanners": [{"name": scanner}]}
        if probe is not None:
            structured_output["scanners"][0]["probes"] = [
                {"proto": "http", "name": probe}
            ]
        structured_output["probes"] = [{"proto": "http", "value": rec["value"]}]
        scripts.append(
            {
                "id": "scanner",
                "output": "Scanner: \n - %s" % scanner + " [%s/http]" % probe
                if probe is not None
                else "",
                "scanner": structured_output,
            }
        )
    return {"ports": [{"port": -1, "scripts": scripts}]}


def _extract_passive_TCP_SERVER_BANNER(rec):
    """Handle banners from tcp servers."""
    value = rec["value"]
    if rec["recontype"] == "SSH_SERVER":
        value += "\r\n"
    port = {
        "state_state": "open",
        "state_reason": "passive",
        "port": rec["port"],
        "protocol": rec.get("protocol", "tcp"),
        "scripts": [{"id": "banner", "output": value}],
    }
    host = {"ports": [port]}
    port.update(rec.get("infos", {}))
    nmap_info = utils.match_nmap_svc_fp(
        output=utils.nmap_decode_data(value),
        proto=rec.get("protocol", "tcp"),
        probe="NULL",
    )
    add_cpe_values(host, "ports.port:%s" % port, nmap_info.pop("cpe", []))
    host["cpes"] = list(host["cpes"].values())
    for cpe in host["cpes"]:
        cpe["origins"] = sorted(cpe["origins"])
    if not host["cpes"]:
        del host["cpes"]
    port.update(nmap_info)
    return host


def _extract_passive_HONEYPOT_HIT(rec):
    """Handle {TCP,UDP}_HONEYPOT_HIT records"""
    try:
        scanned_proto, scanned_port = rec["source"].split("/", 1)
    except ValueError:
        utils.LOGGER.warning("Unknown source in record [%r]", rec)
        return {}
    scanned_port = int(scanned_port)
    output = "Scanned port: %s" % rec["source"].replace("/", ": ")
    structured_output = {
        "ports": {"count": 1, scanned_proto: {"count": 1, "ports": [scanned_port]}}
    }
    if rec.get("infos", {}).get("service_name") == "scanner":
        structured_output["scanners"] = [
            {
                "name": rec["infos"]["service_product"],
                "probes": [
                    {"proto": scanned_proto, "name": rec["infos"]["service_extrainfo"]}
                ],
            }
        ]
        output += "\nScanner:\n - %s [%s/%s]" % (
            rec["infos"]["service_product"],
            rec["infos"]["service_extrainfo"],
            scanned_proto,
        )
    if rec.get("value"):
        structured_output["probes"] = [{"proto": scanned_proto, "value": rec["value"]}]
    return {
        "ports": [
            {
                "port": -1,
                "scripts": [
                    {
                        "id": "scanner",
                        "output": output,
                        "scanner": structured_output,
                    }
                ],
            }
        ]
    }


def _extract_passive_HTTP_HONEYPOT_REQUEST(rec):
    """Handle HTTP_HONEYPOT_REQUEST records"""
    try:
        method, version, proto_port = rec["source"].rsplit("-", 2)
        proto, port = proto_port.split("/", 1)
        port = int(port)
    except ValueError:
        utils.LOGGER.warning("Cannot parse record [%r]", rec)
        return {}
    port = int(port)
    output = "Scanned port: %s: %d\nScanned HTTP URI: %s (%s %s)" % (
        proto,
        port,
        rec["value"],
        method,
        version,
    )
    structured_output = {
        "ports": {"count": 1, proto: {"count": 1, "ports": [port]}},
        "http_uris": [{"method": method, "version": version, "uri": rec["value"]}],
    }
    return {
        "ports": [
            {
                "port": -1,
                "scripts": [
                    {
                        "id": "scanner",
                        "output": output,
                        "scanner": structured_output,
                    }
                ],
            }
        ]
    }


_KEYS = {
    "ecdsa-sha2-nistp256": "ECDSA",
}


def _extract_passive_SSH_SERVER_HOSTKEY(rec):
    """Handle SSH host keys."""
    # TODO: should (probably) be merged, sorted by date/time, keep one
    # entry per key type.
    #
    # (MAYBE) we should add a "lastseen" tag to every intel in view.
    value = utils.encode_b64(utils.nmap_decode_data(rec["value"])).decode()
    fingerprint = rec["infos"]["md5"]
    key = {"type": rec["infos"]["algo"], "key": value, "fingerprint": fingerprint}
    if "bits" in rec["infos"]:  # FIXME
        key["bits"] = rec["infos"]["bits"]
    fingerprint = utils.decode_hex(fingerprint)
    script = {
        "id": "ssh-hostkey",
        "ssh-hostkey": [key],
        "output": "\n  %s %s (%s)\n%s %s"
        % (
            key.get("bits", "-"),  # FIXME
            ":".join(
                "%02x" % (ord(i) if isinstance(i, (bytes, str)) else i)
                for i in fingerprint
            ),
            _KEYS.get(
                key["type"],
                (key["type"][4:] if key["type"][:4] == "ssh-" else key["type"]).upper(),
            ),
            key["type"],
            value,
        ),
        "key": key,
    }
    return {
        "ports": [
            {
                "state_state": "open",
                "state_reason": "passive",
                "port": rec["port"],
                "protocol": rec.get("protocol", "tcp"),
                "service_name": "ssh",
                "scripts": [script],
            }
        ]
    }


def _extract_passive_SSH_HASSH(rec):
    """Handle SSH HASSH data to build an output somehow similar to
    ssh2-enum-algos Nmap script (with less data).

    """
    script = {"id": "ssh2-enum-algos"}
    script_structured = {}
    try:
        (
            script_structured["kex_algorithms"],
            script_structured["encryption_algorithms"],
            script_structured["mac_algorithms"],
            script_structured["compression_algorithms"],
        ) = (v.split(",") for v in rec["infos"]["raw"].split(";"))
    except (KeyError, TypeError, ValueError):
        return {}
    script_output = []
    for key in [
        "kex_algorithms",
        "encryption_algorithms",
        "mac_algorithms",
        "compression_algorithms",
    ]:
        if key in script_structured:
            value = script_structured[key]
            script_output.append("  %s (%d)" % (key, len(value)))
            script_output.extend("      %s" % v for v in value)
    script_structured["hassh"] = {
        "version": "1.1",
        "raw": rec["infos"]["raw"],
        "md5": rec["value"],
        "sha1": rec["infos"]["sha1"],
        "sha256": rec["infos"]["sha256"],
    }
    script_output.extend(
        [
            "",
            "  HASSH",
            "    version: 1.1",
            "    raw: %s" % rec["infos"]["raw"],
            "    md5: %s" % rec["value"],
            "    sha1: %s" % rec["infos"]["sha1"],
            "    sha256: %s" % rec["infos"]["sha256"],
        ]
    )
    script["output"] = "\n".join(script_output)
    script["ssh2-enum-algos"] = script_structured
    port = {
        "service_name": "ssh",
        "scripts": [script],
    }
    if rec.get("port"):
        port["port"] = rec["port"]
        port["protocol"] = rec.get("protocol", "tcp")
        port["state_state"] = "open"
        port["state_reason"] = "passive"
    else:
        port["port"] = -1
    return {"ports": [port]}


def _extract_passive_SSL_SERVER(rec):
    """Handle ssl server headers."""
    source = rec.get("source")
    if source == "cert":
        return _extract_passive_SSL_cert(rec)
    if source == "cacert":
        return _extract_passive_SSL_cert(rec, cacert=True)
    if source.startswith("ja3-"):
        return _extract_passive_SSL_SERVER_ja3(rec)
    return {}


def _extract_passive_SSL_CLIENT(rec):
    """Handle ssl server headers."""
    source = rec.get("source")
    if source == "cert":
        return _extract_passive_SSL_cert(rec, server=False)
    if source == "cacert":
        return _extract_passive_SSL_cert(rec, cacert=True, server=False)
    if source == "ja3":
        return _extract_passive_SSL_CLIENT_ja3(rec)
    return {}


def _extract_passive_SSL_cert(rec, cacert=False, server=True):
    script = {"id": "ssl-cacert" if cacert else "ssl-cert"}
    if server:
        port = {
            "state_state": "open",
            "state_reason": "passive",
            "port": rec["port"],
            "protocol": rec.get("protocol", "tcp"),
            "service_tunnel": "ssl",
        }
    else:
        port = {
            "port": -1,
        }
    info = rec["infos"]
    if info:
        pem = []
        pem.append("-----BEGIN CERTIFICATE-----")
        pem.extend(wrap(utils.encode_b64(rec["value"]).decode(), 64))
        pem.append("-----END CERTIFICATE-----")
        pem.append("")
        info["pem"] = "\n".join(pem)
        script["output"] = "\n".join(create_ssl_output(info))
        script["ssl-cert"] = [info]
        port["scripts"] = [script]
    elif not server:
        # nothing interesting on a client w/o cert
        return {}
    return {"ports": [port]}


def _extract_passive_SSL_SERVER_ja3(rec):
    script = {"id": "ssl-ja3-server"}
    port = {
        "state_state": "open",
        "state_reason": "passive",
        "port": rec["port"],
        "protocol": rec.get("protocol", "tcp"),
    }
    script["output"] = rec["value"] + " - " + rec["source"][4:]
    info = {
        "raw": rec["infos"]["raw"],
        "sha256": rec["infos"]["sha256"],
        "sha1": rec["infos"]["sha1"],
        "md5": rec["value"],
        "client": {
            "raw": rec["infos"]["client"]["raw"],
            "sha256": rec["infos"]["client"]["sha256"],
            "sha1": rec["infos"]["client"]["sha1"],
            "md5": rec["source"][4:],
        },
    }
    script["ssl-ja3-server"] = [info]
    port["scripts"] = [script]
    return {"ports": [port]}


def _extract_passive_DNS_ANSWER(rec):
    """Handle dns server headers."""
    name = rec["value"]
    domains = rec["infos"]["domain"]
    return {
        "hostnames": [
            {"domains": domains, "type": rec["source"].split("-", 1)[0], "name": name}
        ]
    }


def _extract_passive_DNS_HONEYPOT_QUERY(rec):
    """Handle DNS_HONEYPOT_QUERY records"""
    try:
        proto_port, qtype, qclass = rec["source"].rsplit("-", 2)
        proto, port = proto_port.split("/", 1)
        port = int(port)
    except ValueError:
        utils.LOGGER.warning("Cannot parse record [%r]", rec)
        return {}
    output = "Scanned port: %s: %d\nDNS query: %s (type: %s, class: %s)" % (
        proto,
        port,
        rec["value"],
        qtype,
        qclass,
    )
    structured_output = {
        "ports": {"count": 1, proto: {"count": 1, "ports": [port]}},
        "dns_queries": [{"qtype": qtype, "qclass": qclass, "query": rec["value"]}],
    }
    return {
        "ports": [
            {
                "port": -1,
                "scripts": [
                    {
                        "id": "scanner",
                        "output": output,
                        "scanner": structured_output,
                    }
                ],
            }
        ]
    }


def _extract_passive_SSL_CLIENT_ja3(rec):
    """Handle SSL client ja3 extraction."""
    script = {"id": "ssl-ja3-client"}
    script["output"] = rec["value"]
    script["ssl-ja3-client"] = [
        {
            "raw": rec["infos"]["raw"],
            "sha256": rec["infos"]["sha256"],
            "sha1": rec["infos"]["sha1"],
            "md5": rec["value"],
        }
    ]
    port = {"port": -1, "scripts": [script]}
    if rec["value"] in scanners.JA3_CLIENT_VALUES:
        scanner, probe = scanners.JA3_CLIENT_VALUES[rec["value"]]
        structured_output = {"scanners": [{"name": scanner}]}
        if probe is not None:
            structured_output["scanners"][0]["probes"] = [
                {"proto": "tls", "name": probe}
            ]
        structured_output["probes"] = [{"proto": "tls", "value": rec["value"]}]
        port["scripts"].append(
            {
                "id": "scanner",
                "output": "Scanner:\n - %s [%s/tls]" % (scanner, rec["value"]),
                "scanner": structured_output,
            }
        )
    return {"ports": [port]}


def _extract_passive_MAC_ADDRESS(rec):
    """Handle MAC addresses"""
    return {"addresses": {"mac": [rec["value"].lower()]}}


def _extract_passive_OPEN_PORT(rec):
    """Handle open ports"""
    port = {
        "state_state": "open",
        "state_reason": "passive",
        "port": rec["port"],
        "protocol": rec.get("source", "tcp").lower(),
    }
    return {"ports": [port]}


def _extract_passive_NTLM(rec, service=None):
    """Handle NTLM"""
    script = {}
    script["id"] = "ntlm-info"
    script["ntlm-info"] = rec["infos"]
    script["output"] = "\n".join("{}: {}".format(k, v) for k, v in rec["infos"].items())

    port = {}
    if "port" in rec:
        port["state_state"] = "open"
        port["state_reason"] = "passive"
        port["port"] = rec["port"]
    else:
        port["port"] = -1
    if service is None:
        proto, services = rec.get("source").split("-", 1)
        if "SMB" in services:
            script["ntlm-info"]["protocol"] = "smb"
        elif "DCE_RPC" in services:
            script["ntlm-info"]["protocol"] = "dce-rpc"
        else:
            utils.LOGGER.warning("Unknown NTLM services: %r", rec.get("source"))
            script["ntlm-info"]["protocol"] = "unknown"
    else:
        port["service_name"] = service
        script["ntlm-info"]["protocol"] = service
        proto = "tcp"
    port["scripts"] = [script]
    if port["port"] != -1:
        port["protocol"] = proto
    hostnames = []
    if "DNS_Computer_Name" in script["ntlm-info"]:
        add_hostname(script["ntlm-info"]["DNS_Computer_Name"], "ntlm", hostnames)
    return {"ports": [port], "hostnames": hostnames}


smb_values = ["OS", "LAN Manager"]
smb_keys = ["os", "lanmanager"]


def _extract_passive_SMB_SESSION_SETUP(rec):
    """Handle SMB Session Setup Request and Response"""
    keyvals = zip(
        smb_values, (rec["infos"][k] if k in rec["infos"] else "" for k in smb_keys)
    )
    script = {"id": "smb-os-discovery"}
    script["smb-os-discovery"] = rec["infos"]
    script["output"] = "\n".join(
        ("{}: {}".format(k, v) if v else "") for k, v in keyvals
    )
    port = {}
    if "port" in rec:
        port["state_state"] = "open"
        port["state_reason"] = "passive"
        port["port"] = rec["port"]
        port["protocol"] = rec["source"].split("-", 1)[0]
    else:
        port["port"] = -1
    port["scripts"] = [script]
    return {"ports": [port]}


_EXTRACTORS = {
    # 'HTTP_CLIENT_HEADER_SERVER': _extract_passive_HTTP_CLIENT_HEADER_SERVER,
    "HTTP_CLIENT_HEADER": _extract_passive_HTTP_CLIENT_HEADER,
    "HTTP_SERVER_HEADER": _extract_passive_HTTP_SERVER_HEADER,
    "SSL_SERVER": _extract_passive_SSL_SERVER,
    "SSL_CLIENT": _extract_passive_SSL_CLIENT,
    # FIXME: see db/prostgres while hostnames are not merged, it is useless
    # to add DNS answers. It creates empty results.
    "DNS_ANSWER": _extract_passive_DNS_ANSWER,
    "SSH_SERVER": _extract_passive_TCP_SERVER_BANNER,
    "SSH_SERVER_HOSTKEY": _extract_passive_SSH_SERVER_HOSTKEY,
    "SSH_CLIENT_HASSH": _extract_passive_SSH_HASSH,
    "SSH_SERVER_HASSH": _extract_passive_SSH_HASSH,
    "TCP_SERVER_BANNER": _extract_passive_TCP_SERVER_BANNER,
    "MAC_ADDRESS": _extract_passive_MAC_ADDRESS,
    "OPEN_PORT": _extract_passive_OPEN_PORT,
    "TCP_HONEYPOT_HIT": _extract_passive_HONEYPOT_HIT,
    "UDP_HONEYPOT_HIT": _extract_passive_HONEYPOT_HIT,
    "HTTP_HONEYPOT_REQUEST": _extract_passive_HTTP_HONEYPOT_REQUEST,
    "DNS_HONEYPOT_QUERY": _extract_passive_DNS_HONEYPOT_QUERY,
    "NTLM_CHALLENGE": _extract_passive_NTLM,
    "NTLM_AUTHENTICATE": _extract_passive_NTLM,
    "SMB": _extract_passive_SMB_SESSION_SETUP,
}


def passive_record_to_view(rec, category=None):
    """Return a passive entry in the View format.

    Note that this entry is likely to have no sense in itself. This
    function is intended to be used to format results for the merge
    function.

    """
    rec = dict(rec)
    if not rec.get("addr"):
        return None
    outrec = {
        "addr": rec["addr"],
        "state_reason": "passive",
        "schema_version": ACTIVE_SCHEMA_VERSION,
    }
    # a DNS_ANSWER record is not enough to mark a host as up
    if rec["recontype"] != "DNS_ANSWER":
        outrec["state"] = "up"
    sensor = rec.get("sensor")
    if sensor:
        outrec["source"] = [sensor]
    # This (using "lastseen" from the passive record as both "starttime" and
    # "endtime" in the view record) might be surprising **but** it makes sense
    # when you think about it: it avoids having a scan record with
    # exceptionally long "scan durations"
    try:
        outrec["starttime"] = outrec["endtime"] = datetime.fromtimestamp(
            rec["lastseen"]
        )
    except TypeError:
        outrec["starttime"] = outrec["endtime"] = rec["lastseen"]
    function = _EXTRACTORS.get(rec["recontype"], lambda _: {})
    if isinstance(function, dict):
        function = function.get(rec["source"], lambda _: {})
    outrec.update(function(rec))
    set_openports_attribute(outrec)
    if category is not None:
        outrec["categories"] = [category]
    return outrec


def passive_to_view(flt, category=None):
    """Generates passive entries in the View format.

    Note that this entry is likely to have no sense in itself. This
    function is intended to be used to format results for the merge
    function.

    """
    for rec in db.passive.get(flt, sort=[("addr", 1)]):
        if rec.get("schema_version") != PASSIVE_SCHEMA_VERSION:
            utils.LOGGER.warning(
                "Will not handle record with schema_version %d (%d needed) " "[%r]",
                rec.get("schema_version", 0),
                PASSIVE_SCHEMA_VERSION,
                rec,
            )
            continue
        outrec = passive_record_to_view(rec, category=category)
        if outrec is not None:
            yield outrec


def from_passive(flt, category=None):
    """Iterator over passive results, by address."""
    records = passive_to_view(flt, category=category)
    cur_addr = None
    cur_rec = {}
    for rec in records:
        if cur_addr is None:
            cur_addr = rec["addr"]
            cur_rec = rec
        elif cur_addr != rec["addr"]:
            # TODO: add_addr_info should be optional
            cur_rec["infos"] = {}
            for func in [db.data.country_byip, db.data.as_byip, db.data.location_byip]:
                cur_rec["infos"].update(func(cur_addr) or {})
            yield cur_rec
            cur_rec = rec
            cur_addr = rec["addr"]
        else:
            cur_rec = db.view.merge_host_docs(cur_rec, rec)
    if cur_rec:
        yield cur_rec


def nmap_record_to_view(rec, category=None):
    """Convert an nmap result in view."""
    if "_id" in rec:
        del rec["_id"]
    if "scanid" in rec:
        del rec["scanid"]
    if "source" in rec:
        if not rec["source"]:
            rec["source"] = []
        elif not isinstance(rec["source"], list):
            rec["source"] = [rec["source"]]
    rec.setdefault("categories", [])
    if category is not None:
        rec["categories"].append(category)
    for port in rec.get("ports", []):
        if "screendata" in port:
            port["screendata"] = db.nmap.from_binary(port["screendata"])
        for script in port.get("scripts", []):
            if "masscan" in script and "raw" in script["masscan"]:
                script["masscan"]["raw"] = db.nmap.from_binary(script["masscan"]["raw"])
    return rec


def from_nmap(flt, category=None):
    """Return an Nmap entry in the View format."""
    cur_addr = None
    cur_rec = None
    result = None
    for rec in db.nmap.get(flt, sort=[("addr", 1)]):
        if rec.get("schema_version") != ACTIVE_SCHEMA_VERSION:
            utils.LOGGER.warning(
                "Will not handle record with schema_version %d (%d needed) " "[%r]",
                rec.get("schema_version", 0),
                ACTIVE_SCHEMA_VERSION,
                rec,
            )
            continue
        if "addr" not in rec:
            continue
        rec = nmap_record_to_view(rec, category=category)
        if cur_addr is None:
            cur_addr = rec["addr"]
            cur_rec = rec
            continue
        if cur_addr != rec["addr"]:
            result = cur_rec
            cur_rec = rec
            cur_addr = rec["addr"]
            yield result
        else:
            cur_rec = db.view.merge_host_docs(cur_rec, rec)
            continue
    if cur_rec is not None:
        yield cur_rec


def to_view(itrs):
    """Takes a list of iterators over view-formated results, and returns an
    iterator over merged results, sorted by ip.

    """

    def next_record(rec, updt):
        if rec is None:
            return updt
        return db.view.merge_host_docs(rec, updt)

    next_recs = []

    def prepare_record(rec):
        for port in rec.get("ports", []):
            if "screendata" in port:
                port["screendata"] = db.view.to_binary(port["screendata"])
            for script in port.get("scripts", []):
                if "masscan" in script and "raw" in script["masscan"]:
                    script["masscan"]["raw"] = db.view.to_binary(
                        script["masscan"]["raw"]
                    )
        return rec

    # We cannot use a `for itr in itrs` loop here because itrs is
    # modified in the loop.
    i = 0
    while i < len(itrs):
        try:
            next_recs.append(next(itrs[i]))
        except StopIteration:
            # We need to remove the corresponding iterator from itrs,
            # which happens to be the n-th where n is the current
            # length of next_recs.
            del itrs[len(next_recs)]  # Do not increment i here
        else:
            i += 1
    next_addrs = [rec["addr"] for rec in next_recs]
    cur_rec = None
    try:
        cur_addr = min(next_addrs, key=utils.ip2int)
    except ValueError:
        # next_addrs is empty
        cur_addr = None
    while next_recs:
        # We cannot use a `for i in range(len(itrs))` loop because
        # itrs is modified in the loop.
        i = 0
        while i < len(itrs):
            if next_addrs[i] == cur_addr:
                cur_rec = next_record(cur_rec, next_recs[i])
                try:
                    next_recs[i] = next(itrs[i])
                except StopIteration:
                    del next_addrs[i]
                    del next_recs[i]
                    del itrs[i]
                    continue  # Do not increment i here
                next_addrs[i] = next_recs[i]["addr"]
            i += 1
        if next_addrs and cur_addr not in next_addrs:
            yield prepare_record(cur_rec)
            cur_rec = None
            cur_addr = min(next_addrs)
    if cur_rec is not None:
        yield prepare_record(cur_rec)
