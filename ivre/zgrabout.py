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


from ivre import utils
from ivre.xmlnmap import create_ssl_cert


_EXPR_TITLE = re.compile('<title[^>]*>([^<]*)</title>', re.I)
_EXPR_INDEX_OF = re.compile('<title[^>]*> *index +of', re.I)
_EXPR_FILES = [
    re.compile('<a href="(?P<filename>[^"]+)">[^<]+</a></td><td[^>]*> *'
               '(?P<time>[0-9]+-[a-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *'
               '</td><td[^>]*> *(?P<size>[^<]+)</td>', re.I),
    re.compile('<a href="(?P<filename>[^"]+)">[^<]+</a> *'
               '(?P<time>[0-9]+-[a-z0-9]+-[0-9]+ [0-9]+:[0-9]+) *'
               '(?P<size>[^ \r\n]+)', re.I),
]


def zgrap_parser_http(data):
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
    res = {"service_name": "http", "service_method": "probed",
           "state_state": "open", "state_reason": "syn-ack", "protocol": "tcp"}
    url = req.get('url')
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
        # the order will be incorrect!
        http_hdrs = []
        output = []
        if 'unknown' in headers:
            for unk in headers.pop('unknown'):
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
        if headers.get('server'):
            server = resp['headers']['server']
            res.setdefault('scripts', []).append({
                'id': 'http-server-header', 'output': server[0],
                'http-server-header': server,
            })
            banner += (b"Server: " + utils.nmap_decode_data(server[0]) +
                       b"\r\n\r\n")
    info = utils.match_nmap_svc_fp(banner, proto="tcp", probe="GetRequest")
    if info:
        res.update(info)
    if resp.get('body'):
        body = resp['body']
        match = _EXPR_TITLE.search(body)
        if match is not None:
            title = match.groups()[0]
            res.setdefault('scripts', []).append({
                'id': 'http-title', 'output': title,
                'http-title': {'title': title},
            })
        match = _EXPR_INDEX_OF.search(body)
        if match is not None:
            files = []
            for pattern in _EXPR_FILES:
                for match in pattern.finditer(body):
                    files.append(match.groupdict())
            if files:
                output = []
                if url is None or 'path' not in url:
                    volname = "???"
                else:
                    volname = url['path']
                output.append('Volume %s' % volname)
                title = ['size', 'time', 'filename']
                column_width = [len(t) for t in title[:-1]]
                for fobj in files:
                    for i, t in enumerate(title[:-1]):
                        column_width[i] = max(column_width[i],
                                              len(fobj.get(t, "")))
                line_fmt = ('%%(size)-%ds  %%(time)-%ds  %%(filename)s' %
                            tuple(column_width))
                output.append(line_fmt % dict((t, t.upper()) for t in title))
                for fobj in files:
                    output.append(line_fmt % fobj)
                output.append("")
                res.setdefault('scripts', []).append({
                    'id': 'http-ls', 'output': '\n'.join(output),
                    'ls': {'volumes': [{'volume': volname, 'files': files}]},
                })
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
                    'output': "\n".join(output),
                    'ssl-cert': info,
                })
    return res


ZGRAB_PARSERS = {'http': zgrap_parser_http}
