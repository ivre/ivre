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


"""This sub-module contains functions to handle JSON output from zgrab.

"""


from future.utils import viewitems
import re
import binascii


from ivre import utils
from ivre.analyzer import ntlm
from ivre.active.cpe import add_cpe_values
from ivre.active.data import handle_http_headers
from ivre.xmlnmap import add_cert_hostnames, add_hostname, \
    create_elasticsearch_service, create_http_ls, create_ssl_cert


_EXPR_TITLE = re.compile('<title[^>]*>([^<]*)</title>', re.I)
_EXPR_OWA_VERSION = re.compile('"/owa/(?:auth/)?((?:[0-9]+\\.)+[0-9]+)/')
_EXPR_CENTREON_VERSION = re.compile(
    re.escape('<td class="LoginInvitVersion"><br />') +
    '\\s+((?:[0-9]+\\.)+[0-9]+)\\s+' + re.escape('</td>') + '|' +
    re.escape('<span>') + '\\s+v\\.\\ ((?:[0-9]+\\.)+[0-9]+)\\s+' +
    re.escape('</span>')
)

ntlm_values = ['Target_Name', 'NetBIOS_Domain_Name', 'NetBIOS_Computer_Name',
               'DNS_Domain_Name', 'DNS_Computer_Name', 'DNS_Tree_Name',
               'Product_Version', 'NTLM_Version']


def zgrap_parser_http(data, hostrec):
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
    if 'result' in data:
        data.update(data.pop('result'))
    if 'response' not in data:
        utils.LOGGER.warning('Missing "response" field in zgrab HTTP result')
        return {}
    resp = data['response']
    needed_fields = set(["request", "status_code", "status_line"])
    missing_fields = needed_fields.difference(resp)
    if missing_fields:
        utils.LOGGER.warning(
            'Missing field%s %s in zgrab HTTP result',
            's' if len(missing_fields) > 1 else '',
            ', '.join(repr(fld) for fld in missing_fields),
        )
        return {}
    req = resp['request']
    url = req.get('url')
    res = {"service_name": "http", "service_method": "probed",
           "state_state": "open", "state_reason": "response",
           "protocol": "tcp"}
    tls = None
    try:
        tls = req['tls_handshake']
    except KeyError:
        # zgrab2
        try:
            tls = req['tls_log']['handshake_log']
        except KeyError:
            pass
    if tls is not None:
        res['service_tunnel'] = 'ssl'
        try:
            cert = tls['server_certificates']['certificate']['raw']
        except KeyError:
            pass
        else:
            output, info = create_ssl_cert(cert.encode(), b64encoded=True)
            if info:
                res.setdefault('scripts', []).append({
                    'id': 'ssl-cert',
                    'output': output,
                    'ssl-cert': info,
                })
                for cert in info:
                    add_cert_hostnames(cert,
                                       hostrec.setdefault('hostnames', []))
    if url:
        port = None
        if ':' in url.get('host', ''):
            try:
                port = int(url['host'].split(':', 1)[1])
            except ValueError:
                pass
        if port is None:
            if url.get('scheme') == 'https':
                port = 443
            else:
                port = 80
        # Specific paths
        if url.get('path').endswith('/.git/index'):
            if resp.get('status_code') != 200:
                return {}
            if not resp.get('body', '').startswith('DIRC'):
                return {}
            # Due to an issue with ZGrab2 output, we cannot, for now,
            # process the content of the file. See
            # <https://github.com/zmap/zgrab2/issues/263>.
            repository = '%s:%d%s' % (hostrec['addr'], port, url['path'][:-5])
            res['port'] = port
            res.setdefault('scripts', []).append({
                'id': 'http-git',
                'output': '\n  %s\n    Git repository found!\n' % repository,
                'http-git': [{'repository': repository,
                              'files-found': [".git/index"]}],
            })
            return res
        if url.get('path').endswith('/owa/auth/logon.aspx'):
            if resp.get('status_code') != 200:
                return {}
            version = set(
                m.group(1)
                for m in _EXPR_OWA_VERSION.finditer(resp.get('body', ''))
            )
            if not version:
                return {}
            version = sorted(version,
                             key=lambda v: [int(x) for x in v.split('.')])
            res['port'] = port
            path = url['path'][:-15]
            if len(version) > 1:
                output = (
                    'OWA: path %s, version %s (multiple versions found!)' % (
                        path,
                        ' / '.join(version),
                    )
                )
            else:
                output = 'OWA: path %s, version %s' % (path, version[0])
            res.setdefault('scripts', []).append({
                'id': 'http-app',
                'output': output,
                'http-app': [{'path': path,
                              'application': 'OWA',
                              'version': version[0]}],
            })
            return res
        if url.get('path').endswith('/centreon/'):
            if resp.get('status_code') != 200:
                return {}
            if not resp.get('body'):
                return {}
            body = resp['body']
            res['port'] = port
            path = url['path']
            match = _EXPR_TITLE.search(body)
            if match is None:
                return {}
            if match.groups()[0] != "Centreon - IT & Network Monitoring":
                return {}
            match = _EXPR_CENTREON_VERSION.search(body)
            if match is None:
                version = None
            else:
                version = match.group(1) or match.group(2)
            res.setdefault('scripts', []).append({
                'id': 'http-app',
                'output': 'Centreon: path %s%s' % (
                    path,
                    '' if version is None else (', version %s' % version),
                ),
                'http-app': [dict(
                    {'path': path,
                     'application': 'Centreon'},
                    **({} if version is None else {'version': version})
                )],
            })
            return res
        if url.get('path') != '/':
            utils.LOGGER.warning('URL path not supported yet: %s',
                                 url.get('path'))
            return {}
    elif req.get('tls_handshake') or req.get('tls_log'):
        # zgrab / zgrab2
        port = 443
    else:
        port = 80
    res['port'] = port
    # Since Zgrab does not preserve the order of the headers, we need
    # to reconstruct a banner to use Nmap fingerprints
    banner = (utils.nmap_decode_data(resp['protocol']['name']) + b' ' +
              utils.nmap_decode_data(resp['status_line']) + b"\r\n")
    if resp.get('headers'):
        headers = resp['headers']
        # Check the Authenticate header first: if we requested it with
        # an Authorization header, we don't want to gather other information
        if headers.get('www_authenticate'):
            auths = headers.get('www_authenticate')
            for auth in auths:
                if ntlm._is_ntlm_message(auth):
                    try:
                        infos = ntlm.ntlm_extract_info(
                            utils.decode_b64(auth.split(None, 1)[1].encode()))
                    except (UnicodeDecodeError, TypeError, ValueError,
                            binascii.Error):
                        pass
                    keyvals = zip(ntlm_values,
                                  [infos.get(k) for k in ntlm_values])
                    output = '\n'.join("{}: {}".format(k, v)
                                       for k, v in keyvals if v)
                    res.setdefault('scripts', []).append({
                        'id': 'http-ntlm-info',
                        'output': output,
                        'ntlm-info': infos
                    })
                    if 'DNS_Computer_Name' in infos:
                        add_hostname(infos['DNS_Computer_Name'], 'ntlm',
                                     hostrec.setdefault('hostnames', []))
        if any(val.lower().startswith('ntlm')
               for val in req.get('headers', {}).get('authorization', [])):
            return res
        # the order will be incorrect!
        line = '%s %s' % (resp['protocol']['name'], resp['status_line'])
        http_hdrs = [{'name': '_status', 'value': line}]
        output = [line]
        for unk in headers.pop('unknown', []):
            headers[unk['key']] = unk['value']
        for hdr, values in viewitems(headers):
            hdr = hdr.replace('_', '-')
            for val in values:
                http_hdrs.append({'name': hdr, 'value': val})
                output.append('%s: %s' % (hdr, val))
        if http_hdrs:
            method = req.get('method')
            if method:
                output.append('')
                output.append('(Request type: %s)' % method)
            res.setdefault('scripts', []).append({
                'id': 'http-headers', 'output': '\n'.join(output),
                'http-headers': http_hdrs,
            })
            handle_http_headers(hostrec, res, http_hdrs, path=url.get('path'))
        if headers.get('server'):
            banner += (
                b"Server: " +
                utils.nmap_decode_data(headers['server'][0]) +
                b"\r\n\r\n"
            )
    info = utils.match_nmap_svc_fp(banner, proto="tcp", probe="GetRequest")
    if info:
        add_cpe_values(hostrec, 'ports.port:%s' % port, info.pop('cpe', []))
        res.update(info)
    if resp.get('body'):
        body = resp['body']
        res.setdefault('scripts', []).append({
            'id': 'http-content',
            'output': utils.nmap_encode_data(body.encode()),
        })
        match = _EXPR_TITLE.search(body)
        if match is not None:
            title = match.groups()[0]
            res['scripts'].append({
                'id': 'http-title', 'output': title,
                'http-title': {'title': title},
            })
        script_http_ls = create_http_ls(body, url=url)
        if script_http_ls is not None:
            res.setdefault('scripts', []).append(script_http_ls)
        service_elasticsearch = create_elasticsearch_service(body)
        if service_elasticsearch:
            if 'hostname' in service_elasticsearch:
                add_hostname(service_elasticsearch.pop('hostname'), 'service',
                             hostrec.setdefault('hostnames', []))
            add_cpe_values(hostrec, 'ports.port:%s' % port,
                           service_elasticsearch.pop('cpe', []))
            res.update(service_elasticsearch)
    return res


ZGRAB_PARSERS = {'http': zgrap_parser_http}
