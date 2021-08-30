#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

"""This sub-module contains functions used for passive recon.

"""


import hashlib
import re
import struct
import binascii


from ivre import utils, config
from ivre.analyzer import ntlm
from ivre.data import scanners


SCHEMA_VERSION = 2

DNSBL_START = re.compile(
    "^(?:"
    "(?:[0-9a-f]\\.){32}"
    "|"
    "(?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}"
    "(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))."
    ")",
    re.I,
)


# Zeek specific

SYMANTEC_UA = re.compile("[a-zA-Z0-9/+]{32,33}AAAAA$")
SYMANTEC_SEP_UA = re.compile(
    "(SEP/[0-9\\.]+),? MID/\\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-"
    "[A-F0-9]{12}\\},? SID/[0-9]+(?: SEQ/[0-9]+)?(.*)$"
)
KASPERSKY_UA = re.compile("AAAAA[a-zA-Z0-9_-]{1,2}AB$")
DIGEST_AUTH_INFOS = re.compile("(username|realm|algorithm|qop|domain)=")


def _fix_mysql_banner(match):
    # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
    plugin_data_len = max(13, struct.unpack("B", match.group(3)[-1:])[0] - 8)
    return (
        match.group(1)
        + b"\x00\x00"
        + b"\x00"
        + b"\x0a"
        + match.group(2)
        + b"\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        + match.group(3)
        + match.group(4)
        + b"\x00" * plugin_data_len
        + match.group(5)[plugin_data_len:]
    )


TCP_SERVER_PATTERNS = [
    (re.compile(b"You are user number [0-9]+ of "), b"You are user number 1 of "),
    (
        re.compile(
            b"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [ 0-3]?[0-9] "
            b"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
            b"[12][0123456789]{3} [0-2][0-9]:[0-9][0-9]:[0-9][0-9]"
        ),
        b"Thu, 1 Jan 1970 00:00:00",
    ),
    (
        re.compile(b"Local time is now [0-2][0-9]:[0-9][0-9]"),
        b"Local time is now 00:00",
    ),
    (
        re.compile(
            # MySQL banner
            # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html
            # packet length
            b"^(.)\x00\x00"
            # packet number
            b"\x00"
            # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
            # protocol
            b"\x0a"
            # version
            b"([3456]\\.[-_~\\.\\+\\w]+)\x00"
            # Thread ID (4) + auth-plugin-data-part-1 (8) + filler (\x00)
            b".{12}\x00"
            # capabilities 1 (2) + language (1) + status (2) +
            # capabilities 2 (2) + auth_plugin_data_len or 0 (1)
            b"(.{8})"
            # reserved
            b"(.{10})"
            # auth-plugin-data-part-2 + auth_plugin_name
            b"(.*)",
            re.DOTALL,
        ),
        _fix_mysql_banner,
    ),
    # based on Nmap fingerprint
    (
        re.compile(
            b"^220 ([\\w._-]+) ESMTP "
            b"[a-z]{0,2}[0-9]{1,3}((?:-v6)?)([a-z]{2})[0-9]+[a-z]{3}\\.[0-9]{1,3}"
            b" - gsmtp"
        ),
        b"220 \\1 ESMTP xx000\\2\\g<3>00000000xxx.000",
    ),
    # OVH
    (re.compile(b"220([ -][\\w._-]+) in[0-9]{1,2}($|[\\r\\n])"), b"220\\1 in00\\2"),
    # Outlook
    (
        re.compile(
            b"^220 ([A-Z]{2})[0-9]([A-Z]{3,4})[0-9]{2}([A-Z]{2,3})[0-9]{3}\\.mail"
            b"\\.protection\\.outlook\\.com "
        ),
        b"220 \\g<1>0\\g<2>00\\g<3>000.mail.protection.outlook.com ",
    ),
    # Yahoo
    (
        re.compile(b"^220 mta[0-9]{4}\\.mail\\.([a-z0-9]+)\\.yahoo\\.com ESMTP ready"),
        b"220 mta0000.mail.\\1.yahoo.com ESMTP ready",
    ),
    # Communigate & other POP3 servers
    (
        re.compile(b"^\\+OK (.*) ready \\<[0-9]+\\.[0-9]+@"),
        b"+OK \\1 ready <000000.0000000000@",
    ),
    # IMAP servers
    (
        re.compile(b"^\\* OK (.*) IMAP Service ([0-9]+) imapd (.*) at (.*) ready"),
        b"* OK \\1 IMAP Service \\2 imapd \\3 at \\4 ready",
    ),
]


def _split_digest_auth(data):
    """This function handles (Proxy-)Authorization: Digest values"""
    values = []
    curdata = []
    state = 0  # state init
    for char in data:
        if state == 0:
            if char == ",":
                values.append("".join(curdata).strip())
                curdata = []
            else:
                if char == '"':
                    state = 1  # inside " "
                curdata.append(char)
        elif state == 1:
            if char == '"':
                state = 0
            curdata.append(char)
    values.append("".join(curdata).strip())
    if state == 1:
        utils.LOGGER.debug("Could not parse Digest auth data [%r]", data)
    return values


def _prepare_rec_ntlm(spec, new_recontype):
    """
    Decode NTLM messages in HTTP headers and split fingerprint from the other
    NTLM info in the spec
    """
    try:
        auth = utils.decode_b64(spec["value"].split(None, 1)[1].encode())
    except (UnicodeDecodeError, TypeError, ValueError, binascii.Error):
        utils.LOGGER.warning(
            "_prepare_rec_ntlm(): cannot decode %r", spec["value"], exc_info=True
        )
        return
    spec["value"] = "%s %s" % (
        spec["value"].split(None, 1)[0],
        ntlm._ntlm_dict2string(ntlm.ntlm_extract_info(auth)),
    )
    # Separate the NTLM flags from the rest of the message's info
    # for NTLMSSP_NEGOTIAGE and NTLMSSP_CHALLENGE messages
    if spec["value"].startswith("NTLM ntlm-fingerprint"):
        fingerprint = spec.copy()
        fingerprint["recontype"] = new_recontype
        try:
            fingerprint["value"], spec["value"] = spec["value"].split(",", 1)
        except ValueError:
            spec["value"] = ""
        else:
            spec["value"] = "NTLM %s" % spec["value"]
        fingerprint["value"] = fingerprint["value"][5:]
        yield fingerprint
    yield spec


def _prepare_rec(spec, ignorenets, neverignore):
    # First of all, let's see if we are supposed to ignore this spec,
    # and if so, do so.
    if "addr" in spec and spec.get("source") not in neverignore.get(
        spec["recontype"], []
    ):
        for start, stop in ignorenets.get(spec["recontype"], []):
            if start <= utils.force_ip2int(spec["addr"]) <= stop:
                return
    # Then, let's clean up the records.
    # Change Symantec's random user agents (matching SYMANTEC_UA) to
    # the constant string "SymantecRandomUserAgent".
    if spec["recontype"] == "HTTP_CLIENT_HEADER" and spec.get("source") == "USER-AGENT":
        if SYMANTEC_UA.match(spec["value"]):
            spec["value"] = "SymantecRandomUserAgent"
        elif KASPERSKY_UA.match(spec["value"]):
            spec["value"] = "KasperskyWeirdUserAgent"
        else:
            match = SYMANTEC_SEP_UA.match(spec["value"])
            if match is not None:
                spec["value"] = "%s%s" % match.groups()
    # Change any Digest authorization header to remove non-constant
    # information. On one hand we loose the necessary information to
    # try to recover the passwords, but on the other hand we store
    # specs with different challenges but the same username, realm,
    # host and sensor in the same records.
    elif (
        spec["recontype"]
        in {
            "HTTP_CLIENT_HEADER",
            "HTTP_CLIENT_HEADER_SERVER",
        }
        and spec.get("source") in {"AUTHORIZATION", "PROXY-AUTHORIZATION"}
    ):
        value = spec["value"]
        if value:
            authtype = value.split(None, 1)[0]
            if authtype.lower() == "digest":
                try:
                    # we only keep relevant info
                    spec["value"] = "%s %s" % (
                        authtype,
                        ",".join(
                            val
                            for val in _split_digest_auth(value[6:].strip())
                            if DIGEST_AUTH_INFOS.match(val)
                        ),
                    )
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot parse digest error for %r", spec, exc_info=True
                    )
            elif ntlm._is_ntlm_message(value):
                # NTLM_NEGOTIATE and NTLM_AUTHENTICATE
                yield from _prepare_rec_ntlm(spec, "NTLM_CLIENT_FLAGS")
                return
            elif authtype.lower() in {"negotiate", "kerberos", "oauth"}:
                spec["value"] = authtype
    elif spec["recontype"] == "HTTP_SERVER_HEADER" and spec.get("source") in {
        "WWW-AUTHENTICATE",
        "PROXY-AUTHENTICATE",
    }:
        value = spec["value"]
        if value:
            authtype = value.split(None, 1)[0]
            if authtype.lower() == "digest":
                try:
                    # we only keep relevant info
                    spec["value"] = "%s %s" % (
                        authtype,
                        ",".join(
                            val
                            for val in _split_digest_auth(value[6:].strip())
                            if DIGEST_AUTH_INFOS.match(val)
                        ),
                    )
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot parse digest error for %r", spec, exc_info=True
                    )
            elif ntlm._is_ntlm_message(value):
                # NTLM_CHALLENGE
                yield from _prepare_rec_ntlm(spec, "NTLM_SERVER_FLAGS")
                return
            elif authtype.lower() in {"negotiate", "kerberos", "oauth"}:
                spec["value"] = authtype
    # TCP server banners: try to normalize data
    elif spec["recontype"] == "TCP_SERVER_BANNER":
        newvalue = value = utils.nmap_decode_data(spec["value"])
        for pattern, replace in TCP_SERVER_PATTERNS:
            if pattern.search(newvalue):
                newvalue = pattern.sub(replace, newvalue)
        if newvalue != value:
            spec["value"] = utils.nmap_encode_data(newvalue)
    elif spec["recontype"] in {"TCP_CLIENT_BANNER", "TCP_HONEYPOT_HIT"}:
        if spec["value"]:
            data = utils.nmap_decode_data(spec["value"])
            if data in scanners.TCP_PROBES:
                scanner, probe = scanners.TCP_PROBES[data]
                info = {
                    "service_name": "scanner",
                    "service_product": scanner,
                }
                if probe is not None:
                    info["service_extrainfo"] = "TCP probe %s" % probe
                spec.setdefault("infos", {}).update(info)
            else:
                probe = utils.get_nmap_probes("tcp").get(data)
                if probe is not None:
                    spec.setdefault("infos", {}).update(
                        {
                            "service_name": "scanner",
                            "service_product": "Nmap",
                            "service_extrainfo": "TCP probe %s" % probe,
                        }
                    )
    elif spec["recontype"] == "UDP_HONEYPOT_HIT":
        data = utils.nmap_decode_data(spec["value"])
        if data in scanners.UDP_PROBES:
            scanner, probe = scanners.UDP_PROBES[data]
            info = {
                "service_name": "scanner",
                "service_product": scanner,
            }
            if probe is not None:
                info["service_extrainfo"] = "UDP probe %s" % probe
            spec.setdefault("infos", {}).update(info)
        else:
            probe = utils.get_nmap_probes("udp").get(data)
            if probe is not None:
                spec.setdefault("infos", {}).update(
                    {
                        "service_name": "scanner",
                        "service_product": "Nmap",
                        "service_extrainfo": "UDP probe %s" % probe,
                    }
                )
            else:
                payload = utils.get_nmap_udp_payloads().get(data)
                if payload is not None:
                    spec.setdefault("infos", {}).update(
                        {
                            "service_name": "scanner",
                            "service_product": "Nmap",
                            "service_extrainfo": "UDP payload %s" % payload,
                        }
                    )
    # SSL_{CLIENT,SERVER} JA3
    elif (spec["recontype"] == "SSL_CLIENT" and spec["source"] == "ja3") or (
        spec["recontype"] == "SSL_SERVER" and spec["source"].startswith("ja3-")
    ):
        value = spec["value"]
        spec.setdefault("infos", {})["raw"] = value
        spec["value"] = hashlib.new("md5", value.encode()).hexdigest()
        if spec["recontype"] == "SSL_SERVER":
            clientvalue = spec["source"][4:]
            spec["infos"].setdefault("client", {})["raw"] = clientvalue
            spec["source"] = (
                "ja3-%s"
                % hashlib.new(
                    "md5",
                    clientvalue.encode(),
                ).hexdigest()
            )
    # SSH_{CLIENT,SERVER}_HASSH
    elif spec["recontype"] in ["SSH_CLIENT_HASSH", "SSH_SERVER_HASSH"]:
        value = spec["value"]
        spec.setdefault("infos", {})["raw"] = value
        spec["value"] = hashlib.new("md5", value.encode()).hexdigest()
    # Check DNS Blacklist answer
    elif spec["recontype"] == "DNS_ANSWER":
        if any(
            (spec.get("value") or "").endswith(dnsbl)
            for dnsbl in config.DNS_BLACKLIST_DOMAINS
        ):
            dnsbl_val = spec["value"]
            match = DNSBL_START.search(dnsbl_val)
            if match is not None:
                spec["recontype"] = "DNS_BLACKLIST"
                spec["value"] = spec.get("addr")
                spec["source"] = "%s-%s" % (dnsbl_val[match.end() :], spec["source"])
                addr = match.group()
                # IPv4
                if addr.count(".") == 4:
                    spec["addr"] = ".".join(addr.split(".")[3::-1])
                # IPv6
                else:
                    spec["addr"] = utils.int2ip6(int(addr.replace(".", "")[::-1], 16))
    yield spec


def handle_rec(
    sensor,
    ignorenets,
    neverignore,
    # these argmuments are provided by **bro_line
    timestamp=None,
    uid=None,
    host=None,
    srvport=None,
    recon_type=None,
    source=None,
    value=None,
    targetval=None,
):
    spec = {
        "schema_version": SCHEMA_VERSION,
        "recontype": recon_type,
        "value": value,
    }
    if host is None:
        spec["targetval"] = targetval
    else:
        spec["addr"] = host
    if sensor is not None:
        spec["sensor"] = sensor
    if srvport is not None:
        spec["port"] = srvport
    if source is not None:
        spec["source"] = source
    for rec in _prepare_rec(spec, ignorenets, neverignore):
        yield timestamp, rec


def _getinfos_http_client_authorization(spec):
    """Extract (for now) the usernames and passwords from Basic
    authorization headers
    """
    infos = {}
    data = spec["value"].split(None, 1)
    value = spec["value"]
    if data[1:]:
        if data[0].lower() == "basic":
            try:
                infos["username"], infos["password"] = (
                    utils.nmap_encode_data(v)
                    for v in utils.decode_b64(data[1].strip().encode()).split(b":", 1)
                )
            except Exception:
                pass
        elif data[0].lower() == "digest":
            try:
                infos = dict(
                    value.split("=", 1) if "=" in value else [value, None]
                    for value in _split_digest_auth(data[1].strip())
                )
                for key, value in list(infos.items()):
                    if value.startswith('"') and value.endswith('"'):
                        infos[key] = value[1:-1]
            except Exception:
                pass
        else:
            try:
                val1, val2 = value.split(None, 1)
            except ValueError:
                pass
            else:
                if val1.lower() in {"ntlm", "negotiate"} and val2:
                    return _getinfos_ntlm(spec)
    res = {}
    if infos:
        res["infos"] = infos
    return res


def _getinfos_http_server(spec):
    header = utils.nmap_decode_data(spec["value"])
    banner = b"HTTP/1.1 200 OK\r\nServer: " + header + b"\r\n\r\n"
    res = _getinfos_from_banner(banner, probe="GetRequest")
    return res


def _getinfos_dns(spec):
    """Extract domain names in an handy-to-index-and-query form."""
    infos = {}
    fields = {"domain": "value", "domaintarget": "targetval"}
    for field, value in fields.items():
        try:
            if value not in spec:
                continue
            infos[field] = []
            for domain in utils.get_domains(spec[value]):
                infos[field].append(domain)
            if not infos[field]:
                del infos[field]
        except Exception:
            pass
    res = {}
    if infos:
        res["infos"] = infos
    return res


def _getinfos_dns_blacklist(spec):
    """Extract and properly format DNSBL records."""
    infos = {}
    try:
        if "source" in spec:
            infos["domain"] = []
            for domain in utils.get_domains(spec["source"].split("-")[-4]):
                infos["domain"].append(domain)
            if not infos["domain"]:
                del infos["domain"]
    except Exception:
        pass
    res = {}
    if infos:
        res["infos"] = infos
    return res


def _getinfos_sslsrv(spec):
    """Calls a source specific function for SSL_SERVER recontype
    records.

    """
    source = spec.get("source")
    if source in {"cert", "cacert"}:
        return _getinfos_cert(spec)
    if source.startswith("ja3-"):
        return _getinfos_ja3_hassh(spec)
    return {}


def _getinfos_cert(spec):
    """Extract info from a certificate (hash values, issuer, subject,
    algorithm) in an handy-to-index-and-query form.

    """
    # TODO: move to mongodb specific functions.
    try:
        cert = utils.decode_b64(spec["value"].encode())
    except Exception:
        utils.LOGGER.info("Cannot parse certificate for record %r", spec, exc_info=True)
        return {}
    info = utils.get_cert_info(cert)
    res = {}
    if info:
        res["infos"] = info
    return res


def _getinfos_ja3_hassh(spec):
    """Extract hashes from JA3 & HASSH fingerprint strings."""
    value = spec["infos"]["raw"]
    data = value.encode()

    info = dict(
        (
            (hashtype, hashlib.new(hashtype, data).hexdigest())
            for hashtype in ["sha1", "sha256"]
        ),
        **spec["infos"],
    )

    if spec.get("recontype") == "SSL_SERVER":
        clientvalue = spec["infos"]["client"]["raw"]
        clientdata = clientvalue.encode()
        info["client"].update(
            (hashtype, hashlib.new(hashtype, clientdata).hexdigest())
            for hashtype in ["sha1", "sha256"]
        )

    return {"infos": info}


def _getinfos_from_banner(banner, proto="tcp", probe="NULL"):
    infos = utils.match_nmap_svc_fp(banner, proto=proto, probe=probe) or {}
    try:
        del infos["cpe"]
    except KeyError:
        pass
    if not infos:
        return {}
    return {"infos": infos}


def _getinfos_tcp_srv_banner(spec):
    """Extract info from a TCP server banner using Nmap database."""
    return _getinfos_from_banner(utils.nmap_decode_data(spec["value"]))


def _getinfos_ssh(spec):
    """Convert an SSH server banner to a TCP banner and use
    _getinfos_tcp_srv_banner().

    Since client and server banners are essentially the same thing, we
    use this for both client and server banners.

    """
    return _getinfos_from_banner(utils.nmap_decode_data(spec["value"]) + b"\r\n")


def _getinfos_ssh_hostkey(spec):
    """Parse SSH host keys."""
    infos = {}
    data = utils.nmap_decode_data(spec["value"])
    for hashtype in ["md5", "sha1", "sha256"]:
        infos[hashtype] = hashlib.new(hashtype, data).hexdigest()
    info = utils.parse_ssh_key(data)
    return {"infos": info}


def _getinfos_authentication(spec):
    """
    Parse value of *-AUTHENTICATE headers depending on the protocol used
    """
    value = spec["value"]
    try:
        val1, val2 = value.split(None, 1)
    except ValueError:
        pass
    else:
        if val1.lower() in {"ntlm", "negotiate"} and val2:
            return _getinfos_ntlm(spec)

    return {}


def _getinfos_ntlm(spec):
    """
    Get information from NTLMSSP messages
    """
    value = spec["value"]
    try:
        val1, val2 = value.split(None, 1)
    except ValueError:
        pass
    else:
        if val1.lower() in {"ntlm", "negotiate"} and val2:
            value = val2
    info = {}
    try:
        for k, v in (item.split(":", 1) for item in value.split(",")):
            if k == "NTLM_Version":
                info[k] = v
            else:
                try:
                    info[k] = utils.nmap_encode_data(utils.decode_b64(v.encode()))
                except (UnicodeDecodeError, TypeError, ValueError, binascii.Error):
                    utils.LOGGER.warning(
                        "Incorrect value for field %r in record %r", k, spec
                    )
    except ValueError:
        utils.LOGGER.warning("Incorrect value in message: %r", spec)
        return {}

    return {"infos": info}


def _getinfos_ntlm_flags(spec):
    """
    Get the Negotiate Flags information from an NTLMSSP message
    """
    k, v = spec["value"].split(":", 1)
    return {"infos": {k: v}}


def _getinfos_smb(spec):
    """
    Get information on an OS from SMB `Session Setup Request` and
    `Session Setup Response`
    """
    info = {}
    try:
        for k, v in (item.split(":", 1) for item in spec["value"].split(",")):
            if k == "is_guest":
                try:
                    info[k] = v == "true"
                except ValueError:
                    utils.LOGGER.warning(
                        "Incorrect value for field %r in record %r", k, spec
                    )
            else:
                try:
                    info[k] = utils.nmap_encode_data(utils.decode_b64(v.encode()))
                except (UnicodeDecodeError, TypeError, ValueError, binascii.Error):
                    utils.LOGGER.warning(
                        "Incorrect value for field %r in record %r", k, spec
                    )
    except ValueError:
        utils.LOGGER.warning("Incorrect value in message: %r", spec)
        return {}

    return {"infos": info}


_GETINFOS_FUNCTIONS = {
    "HTTP_CLIENT_HEADER": {
        "AUTHORIZATION": _getinfos_http_client_authorization,
        "PROXY-AUTHORIZATION": _getinfos_http_client_authorization,
    },
    "HTTP_CLIENT_HEADER_SERVER": {
        "AUTHORIZATION": _getinfos_http_client_authorization,
        "PROXY-AUTHORIZATION": _getinfos_http_client_authorization,
    },
    "HTTP_SERVER_HEADER": {
        "SERVER": _getinfos_http_server,
        "WWW-AUTHENTICATE": _getinfos_authentication,
        "PROXY-AUTHENTICATE": _getinfos_authentication,
    },
    "DNS_ANSWER": _getinfos_dns,
    "DNS_BLACKLIST": _getinfos_dns_blacklist,
    "SSL_SERVER": _getinfos_sslsrv,
    "SSL_CLIENT": {
        "cacert": _getinfos_cert,
        "cert": _getinfos_cert,
        "ja3": _getinfos_ja3_hassh,
    },
    "TCP_SERVER_BANNER": _getinfos_tcp_srv_banner,
    "SSH_CLIENT": _getinfos_ssh,
    "SSH_SERVER": _getinfos_ssh,
    "SSH_SERVER_HOSTKEY": _getinfos_ssh_hostkey,
    "SSH_CLIENT_HASSH": _getinfos_ja3_hassh,
    "SSH_SERVER_HASSH": _getinfos_ja3_hassh,
    "NTLM_NEGOTIATE": _getinfos_ntlm,
    "NTLM_CHALLENGE": _getinfos_ntlm,
    "NTLM_AUTHENTICATE": _getinfos_ntlm,
    "NTLM_SERVER_FLAGS": _getinfos_ntlm_flags,
    "NTLM_CLIENT_FLAGS": _getinfos_ntlm_flags,
    "SMB": _getinfos_smb,
}


def getinfos(spec):
    """This functions takes a document from a passive sensor, and
    prepares its "infos" field (which is not added but returned).

    """
    function = _GETINFOS_FUNCTIONS.get(spec.get("recontype"))
    if isinstance(function, dict):
        function = function.get(spec.get("source"))
    if function is None:
        return {}
    return function(spec)
