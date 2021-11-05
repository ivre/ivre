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


"""This sub-module contains functions to handle JSON output from zgrab.

"""


import binascii
import re
from typing import Any, Dict, List, Optional, cast


from ivre.analyzer import ntlm
from ivre.active.cpe import add_cpe_values
from ivre.active.data import handle_http_headers
from ivre.data.microsoft.exchange import EXCHANGE_BUILDS
from ivre.types import NmapServiceMatch
from ivre.types.active import HttpHeader, NmapHost, NmapPort
from ivre import utils
from ivre.xmlnmap import (
    add_cert_hostnames,
    add_hostname,
    create_elasticsearch_service,
    create_http_ls,
    create_ssl_cert,
)


_EXPR_TITLE = re.compile("<title[^>]*>([^<]*)</title>", re.I)
_EXPR_OWA_VERSION = re.compile('"/owa/(?:auth/)?((?:[0-9]+\\.)+[0-9]+)/')
_EXPR_CENTREON_VERSION = re.compile(
    re.escape('<td class="LoginInvitVersion"><br />')
    + "\\s+((?:[0-9]+\\.)+[0-9]+)\\s+"
    + re.escape("</td>")
    + "|"
    + re.escape("<span>")
    + "\\s+v\\.\\ ((?:[0-9]+\\.)+[0-9]+)\\s+"
    + re.escape("</span>")
)

ntlm_values = [
    "Target_Name",
    "NetBIOS_Domain_Name",
    "NetBIOS_Computer_Name",
    "DNS_Domain_Name",
    "DNS_Computer_Name",
    "DNS_Tree_Name",
    "Product_Version",
    "NTLM_Version",
]


def zgrap_parser_http(
    data: Dict[str, Any], hostrec: NmapHost, port: Optional[int] = None
) -> NmapPort:
    """This function handles data from `{"data": {"http": [...]}}`
    records. `data` should be the content, i.e. the `[...]`. It should
    consist of simple dictionary, that may contain a `"response"` key
    and/or a `"redirect_response_chain"` key.

    The output is a port dict (i.e., the content of the "ports" key of an
    `nmap` of `view` record in IVRE), that may be empty.

    """
    if not data:
        return {}
    # for zgrab2 results
    if "result" in data:
        data.update(data.pop("result"))
    if "response" not in data:
        utils.LOGGER.warning('Missing "response" field in zgrab HTTP result')
        return {}
    resp = data["response"]
    needed_fields = set(["request", "status_code", "status_line"])
    missing_fields = needed_fields.difference(resp)
    if missing_fields:
        utils.LOGGER.warning(
            "Missing field%s %s in zgrab HTTP result",
            "s" if len(missing_fields) > 1 else "",
            ", ".join(repr(fld) for fld in missing_fields),
        )
        return {}
    req = resp["request"]
    url = req.get("url")
    res: NmapPort = {
        "service_name": "http",
        "service_method": "probed",
        "state_state": "open",
        "state_reason": "response",
        "protocol": "tcp",
    }
    tls = None
    try:
        tls = req["tls_handshake"]
    except KeyError:
        # zgrab2
        try:
            tls = req["tls_log"]["handshake_log"]
        except KeyError:
            pass
    if tls is not None:
        res["service_tunnel"] = "ssl"
        try:
            cert = tls["server_certificates"]["certificate"]["raw"]
        except KeyError:
            pass
        else:
            output, info_cert = create_ssl_cert(cert.encode(), b64encoded=True)
            if info_cert:
                res.setdefault("scripts", []).append(
                    {
                        "id": "ssl-cert",
                        "output": output,
                        "ssl-cert": info_cert,
                    }
                )
                for cert in info_cert:
                    add_cert_hostnames(cert, hostrec.setdefault("hostnames", []))
    if url:
        try:
            _, guessed_port = utils.url2hostport("%(scheme)s://%(host)s" % url)
        except ValueError:
            utils.LOGGER.warning("Cannot guess port from url %r", url)
            guessed_port = 80  # because reasons
        else:
            if port is not None and port != guessed_port:
                utils.LOGGER.warning(
                    "Port %d found from the URL %s differs from the provided port "
                    "value %d",
                    guessed_port,
                    url.get("path"),
                    port,
                )
                port = guessed_port
        if port is None:
            port = guessed_port
        # Specific paths
        if url.get("path").endswith("/.git/index"):
            if resp.get("status_code") != 200:
                return {}
            if not resp.get("body", "").startswith("DIRC"):
                return {}
            # Due to an issue with ZGrab2 output, we cannot, for now,
            # process the content of the file. See
            # <https://github.com/zmap/zgrab2/issues/263>.
            repository = "%s:%d%s" % (hostrec["addr"], port, url["path"][:-5])
            res["port"] = port
            res.setdefault("scripts", []).append(
                {
                    "id": "http-git",
                    "output": "\n  %s\n    Git repository found!\n" % repository,
                    "http-git": [
                        {"repository": repository, "files-found": [".git/index"]},
                    ],
                }
            )
            return res
        if url.get("path").endswith("/owa/auth/logon.aspx"):
            if resp.get("status_code") != 200:
                return {}
            version_set = set(
                m.group(1) for m in _EXPR_OWA_VERSION.finditer(resp.get("body", ""))
            )
            if not version_set:
                return {}
            version_list = sorted(
                version_set, key=lambda v: [int(x) for x in v.split(".")]
            )
            res["port"] = port
            path = url["path"][:-15]
            if version_list:
                parsed_version = EXCHANGE_BUILDS.get(
                    version_list[0], "unknown build number"
                )
                if len(version_list) > 1:
                    version_list = [
                        "%s (%s)"
                        % (vers, EXCHANGE_BUILDS.get(vers, "unknown build number"))
                        for vers in version_list
                    ]
                    output = "OWA: path %s, version %s (multiple versions found!)" % (
                        path,
                        " / ".join(version_list),
                    )
                else:
                    output = "OWA: path %s, version %s (%s)" % (
                        path,
                        version_list[0],
                        parsed_version,
                    )
            res.setdefault("scripts", []).append(
                {
                    "id": "http-app",
                    "output": output,
                    "http-app": [
                        {
                            "path": path,
                            "application": "OWA",
                            "version": version_list[0],
                            "parsed_version": parsed_version,
                        }
                    ],
                }
            )
            return res
        if url.get("path").endswith("/centreon/"):
            if resp.get("status_code") != 200:
                return {}
            if not resp.get("body"):
                return {}
            body = resp["body"]
            res["port"] = port
            path = url["path"]
            match = _EXPR_TITLE.search(body)
            if match is None:
                return {}
            if match.groups()[0] != "Centreon - IT & Network Monitoring":
                return {}
            match = _EXPR_CENTREON_VERSION.search(body)
            version: Optional[str]
            if match is None:
                version = None
            else:
                version = match.group(1) or match.group(2)
            res.setdefault("scripts", []).append(
                {
                    "id": "http-app",
                    "output": "Centreon: path %s%s"
                    % (
                        path,
                        "" if version is None else (", version %s" % version),
                    ),
                    "http-app": [
                        dict(
                            {"path": path, "application": "Centreon"},
                            **({} if version is None else {"version": version}),
                        )
                    ],
                }
            )
            return res
        if url.get("path").endswith("/.well-known/security.txt"):
            if resp.get("status_code") != 200:
                return {}
            if not resp.get("headers"):
                return {}
            if not any(
                ctype.split(";", 1)[0].lower() == "text/plain"
                for ctype in resp["headers"].get("content_type", [])
            ):
                return {}
            if not resp.get("body"):
                return {}
            body = resp["body"]
            res["port"] = port
            parsed: Dict[str, List[str]] = {}
            for line in body.splitlines():
                line = line.strip().split("#", 1)[0]
                if not line:
                    continue
                if ":" not in line:
                    utils.LOGGER.warning("Invalid line in security.txt file [%r]", line)
                    continue
                key, value = line.split(":", 1)
                parsed.setdefault(key.strip().lower(), []).append(value.strip())
            res.setdefault("scripts", []).append(
                {
                    "id": "http-securitytxt",
                    "output": body,
                    "http-securitytxt": {
                        key: " / ".join(value) for key, value in parsed.items()
                    },
                }
            )
            return res
        if url.get("path") != "/":
            utils.LOGGER.warning("URL path not supported yet: %s", url.get("path"))
            return {}
    elif port is None:
        if req.get("tls_handshake") or req.get("tls_log"):
            port = 443
        else:
            port = 80
    res["port"] = port
    # Since Zgrab does not preserve the order of the headers, we need
    # to reconstruct a banner to use Nmap fingerprints
    banner = (
        utils.nmap_decode_data(resp["protocol"]["name"])
        + b" "
        + utils.nmap_decode_data(resp["status_line"])
        + b"\r\n"
    )
    if resp.get("headers"):
        headers = resp["headers"]
        # Check the Authenticate header first: if we requested it with
        # an Authorization header, we don't want to gather other information
        if headers.get("www_authenticate"):
            auths = headers.get("www_authenticate")
            for auth in auths:
                if ntlm._is_ntlm_message(auth):
                    try:
                        infos = ntlm.ntlm_extract_info(
                            utils.decode_b64(auth.split(None, 1)[1].encode())
                        )
                    except (UnicodeDecodeError, TypeError, ValueError, binascii.Error):
                        continue
                    if not infos:
                        continue
                    keyvals = zip(ntlm_values, [infos.get(k) for k in ntlm_values])
                    output = "\n".join("{}: {}".format(k, v) for k, v in keyvals if v)
                    res.setdefault("scripts", []).append(
                        {
                            "id": "ntlm-info",
                            "output": output,
                            "ntlm-info": dict(infos, protocol="http"),
                        }
                    )
                    if "DNS_Computer_Name" in infos:
                        add_hostname(
                            infos["DNS_Computer_Name"],
                            "ntlm",
                            hostrec.setdefault("hostnames", []),
                        )
        if any(
            val.lower().startswith("ntlm")
            for val in req.get("headers", {}).get("authorization", [])
        ):
            return res
        # the order will be incorrect!
        line = "%s %s" % (resp["protocol"]["name"], resp["status_line"])
        http_hdrs: List[HttpHeader] = [{"name": "_status", "value": line}]
        output_list = [line]
        for unk in headers.pop("unknown", []):
            headers[unk["key"]] = unk["value"]
        for hdr, values in headers.items():
            hdr = hdr.replace("_", "-")
            for val in values:
                http_hdrs.append({"name": hdr, "value": val})
                output_list.append("%s: %s" % (hdr, val))
        if http_hdrs:
            method = req.get("method")
            if method:
                output_list.append("")
                output_list.append("(Request type: %s)" % method)
            res.setdefault("scripts", []).append(
                {
                    "id": "http-headers",
                    "output": "\n".join(output_list),
                    "http-headers": http_hdrs,
                }
            )
            handle_http_headers(hostrec, res, http_hdrs, path=url.get("path"))
        if headers.get("server"):
            banner += (
                b"Server: " + utils.nmap_decode_data(headers["server"][0]) + b"\r\n\r\n"
            )
    info: NmapServiceMatch = utils.match_nmap_svc_fp(
        banner, proto="tcp", probe="GetRequest"
    )
    if info:
        add_cpe_values(hostrec, "ports.port:%s" % port, info.pop("cpe", []))
        res.update(cast(NmapPort, info))
    if resp.get("body"):
        body = resp["body"]
        res.setdefault("scripts", []).append(
            {
                "id": "http-content",
                "output": utils.nmap_encode_data(body.encode()),
            }
        )
        match = _EXPR_TITLE.search(body)
        if match is not None:
            title = match.groups()[0]
            res["scripts"].append(
                {
                    "id": "http-title",
                    "output": title,
                    "http-title": {"title": title},
                }
            )
        script_http_ls = create_http_ls(body, url=url)
        if script_http_ls is not None:
            res.setdefault("scripts", []).append(script_http_ls)
        service_elasticsearch = create_elasticsearch_service(body)
        if service_elasticsearch:
            if "service_hostname" in service_elasticsearch:
                add_hostname(
                    service_elasticsearch["service_hostname"],
                    "service",
                    hostrec.setdefault("hostnames", []),
                )
            add_cpe_values(
                hostrec, "ports.port:%s" % port, service_elasticsearch.pop("cpe", [])
            )
            res.update(cast(NmapPort, service_elasticsearch))
    return res


def zgrap_parser_jarm(
    data: Dict[str, Any], hostrec: NmapHost, port: Optional[int] = None
) -> NmapPort:
    """This function handles data from `{"data": {"jarm": [...]}}`
    records. `data` should be the content, i.e. the `[...]`. It should
    consist of simple dictionary, that must contain a `"status"` key and a
    `"fingerprint"` key (that may be in a `"result"` sub-document).

    The output is a port dict (i.e., the content of the "ports" key of an
    `nmap` of `view` record in IVRE), that may be empty.

    """
    if not data:
        return {}
    # for zgrab2 results
    if "result" in data:
        data.update(data.pop("result"))
    if data.get("status") != "success":
        return {}
    if "fingerprint" not in data:
        utils.LOGGER.warning('Missing "fingerprint" field in zgrab JARM result')
        return {}
    if (
        data["fingerprint"]
        == "00000000000000000000000000000000000000000000000000000000000000"
    ):
        utils.LOGGER.warning('Null "fingerprint" in zgrab JARM result')
        return {}
    if port is None:
        port = 443  # default
        utils.LOGGER.warning(
            "No port provided; using default %d. " "Use --zgrab-port to change it.",
            port,
        )
    return {
        "state_state": "open",
        "state_reason": "response",
        "port": port,
        "protocol": "tcp",
        "service_tunnel": "ssl",
        "scripts": [{"id": "ssl-jarm", "output": data["fingerprint"]}],
    }


ZGRAB_PARSERS = {
    "http": zgrap_parser_http,
    "jarm": zgrap_parser_jarm,
}
