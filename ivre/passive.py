#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2019 Pierre LALET <pierre.lalet@cea.fr>
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

"""
This module is part of IVRE.
Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains functions used for passive recon.
"""


from datetime import datetime
import hashlib
import re
import struct


from future.utils import viewitems


from ivre import utils, config


SCHEMA_VERSION = 1

# p0f specific

P0F_MODES = {
    'SYN': {
        'options': [],
        'name': 'SYN',
        'filter': 'tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) == 2'
    },
    'SYN+ACK': {
        'options': ['-A'],
        'name': 'SYN+ACK',
        'filter': 'tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) == 18'},
    'RST+': {
        'options': ['-R'],
        'name': 'RST+',
        'filter': 'tcp and tcp[tcpflags] & (tcp-rst) == 4'},
    'ACK': {
        'options': ['-O'],
        'name': 'ACK',
        'filter': 'tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) == 16'}
}

P0F_DIST = re.compile(b'distance ([0-9]+),')


def parse_p0f_line(line, include_port=False, sensor=None, recontype=None):
    line = [line.split(b' - ')[0]] + line.split(b' - ')[1].split(b' -> ')
    if line[1].startswith(b'UNKNOWN '):
        sig = line[1][line[1].index(b'UNKNOWN ') + 8:][1:-1].split(b':')[:6]
        osname, version, dist = b'?', b'?', -1
    else:
        sig = line[1][line[1].index(b' Signature: ') + 12:][
            1:-1].split(b':')[:6]
        if b' (up: ' in line[1]:
            osname = line[1][:line[1].index(b' (up: ')]
        else:
            osname = line[1][:line[1].index(b' Signature: ')]
        osname = osname.split(b' ')
        osname, version = osname[0], b' '.join(osname[1:])
        dist = int(P0F_DIST.search(line[2]).groups()[0])
    # We wildcard any window size which is not Sxxx or Tyyy
    if sig[0][0] not in b'ST':
        sig[0] = b'*'
    spec = {
        'schema_version': SCHEMA_VERSION,
        'addr': line[0][line[0].index(b'> ') + 2:line[0].index(b':')].decode(),
        'distance': dist,
        'value': osname.decode(),
        'version': version.decode(),
        'signature': ':'.join(str(elt) for elt in sig),
    }
    if include_port:
        spec.update({'port': int(line[0][line[0].index(b':') + 1:])})
    if sensor is not None:
        spec['sensor'] = sensor
    if recontype is not None:
        spec['recontype'] = recontype
    return datetime.fromtimestamp(float(line[0][1:line[0].index(b'>')])), spec


# Bro specific

SYMANTEC_UA = re.compile('[a-zA-Z0-9/+]{32,33}AAAAA$')
SYMANTEC_SEP_UA = re.compile(
    '(SEP/[0-9\\.]+),? MID/\\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-'
    '[A-F0-9]{12}\\},? SID/[0-9]+(?: SEQ/[0-9]+)?(.*)$'
)
KASPERSKY_UA = re.compile('AAAAA[a-zA-Z0-9_-]{1,2}AB$')
DIGEST_AUTH_INFOS = re.compile('(username|realm|algorithm|qop)=')


def _fix_mysql_banner(match):
    # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
    plugin_data_len = max(13, struct.unpack('B', match.group(3)[-1:])[0] - 8)
    return (
        match.group(1) + b'\x00\x00' +
        b'\x00' +
        b'\x0a' +
        match.group(2) + b'\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        match.group(3) +
        match.group(4) +
        b'\x00' * plugin_data_len +
        match.group(5)[plugin_data_len:]
    )


TCP_SERVER_PATTERNS = [
    (re.compile(b'You are user number [0-9]+ of '),
     b'You are user number 1 of '),
    (re.compile(
        b'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [ 0-3]?[0-9] '
        b'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) '
        b'[12][0123456789]{3} [0-2][0-9]:[0-9][0-9]:[0-9][0-9]'
    ), b'Thu 1 Jan 1970 00:00:00'),
    (re.compile(b'Local time is now [0-2][0-9]:[0-9][0-9]'),
     b'Local time is now 00:00'),
    (re.compile(
        # MySQL banner
        # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html
        b'^(.)\x00\x00'  # packet length
        b'\x00'  # packet number
        # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
        b'\x0a'  # protocol
        b'([3456]\\.[-_~\\.\\+\\w]+)\x00'  # version
        # Thread ID (4) + auth-plugin-data-part-1 (8) + filler (\x00)
        b'.{12}\x00'
        # capabilities 1 (2) + language (1) + status (2) +
        # capabilities 2 (2) + auth_plugin_data_len or 0 (1)
        b'(.{8})'
        b'(.{10})'  # reserved
        b'(.*)',  # auth-plugin-data-part-2 + auth_plugin_name
        re.DOTALL
    ), _fix_mysql_banner),
    # based on Nmap fingerprint
    (re.compile(
        b'^220 ([\\w._-]+) ESMTP '
        b'[a-z]{0,2}[0-9]{1,3}((?:-v6)?)([a-z]{2})[0-9]+[a-z]{3}\\.[0-9]{1,3}'
        b' - gsmtp'
    ), b'220 \\1 ESMTP xx000\\2\\g<3>00000000xxx.000'),
    # OVH
    (re.compile(
        b'220([ -][\\w._-]+) in[0-9]{1,2}($|[\\r\\n])'
    ), b'220\\1 in00\\2'),
    # Outlook
    (re.compile(
        b'^220 ([A-Z]{2})[0-9]([A-Z]{3,4})[0-9]{2}([A-Z]{2,3})[0-9]{3}\\.mail'
        b'\\.protection\\.outlook\\.com '
    ), b'220 \\g<1>0\\g<2>00\\g<3>000.mail.protection.outlook.com '),
    # Yahoo
    (re.compile(
        b'220 mta[0-9]{4}\\.mail\\.([a-z0-9]+)\\.yahoo\\.com ESMTP ready'
    ), b'220 mta0000.mail.\\1.yahoo.com ESMTP ready'),
]


def _split_digest_auth(data):
    """This function handles (Proxy-)Authorization: Digest values"""
    values = []
    curdata = []
    state = 0  # state init
    for char in data:
        if state == 0:
            if char == ',':
                values.append(''.join(curdata).strip())
                curdata = []
            else:
                if char == '"':
                    state = 1  # inside " "
                curdata.append(char)
        elif state == 1:
            if char == '"':
                state = 0
            curdata.append(char)
    values.append(''.join(curdata).strip())
    if state == 1:
        utils.LOGGER.debug("Could not parse Digest auth data [%r]", data)
    return values


def _prepare_rec(spec, ignorenets, neverignore):
    # First of all, let's see if we are supposed to ignore this spec,
    # and if so, do so.
    if 'addr' in spec and \
       spec.get('source') not in neverignore.get(spec['recontype'], []):
        for start, stop in ignorenets.get(spec['recontype'], ()):
            if start <= utils.force_ip2int(spec['addr']) <= stop:
                return None
    # Then, let's clean up the records.
    # Change Symantec's random user agents (matching SYMANTEC_UA) to
    # the constant string 'SymantecRandomUserAgent'.
    if spec['recontype'] == 'HTTP_CLIENT_HEADER' and \
       spec.get('source') == 'USER-AGENT':
        if SYMANTEC_UA.match(spec['value']):
            spec['value'] = 'SymantecRandomUserAgent'
        elif KASPERSKY_UA.match(spec['value']):
            spec['value'] = 'KasperskyWeirdUserAgent'
        else:
            match = SYMANTEC_SEP_UA.match(spec['value'])
            if match is not None:
                spec['value'] = '%s%s' % match.groups()
    # Change any Digest authorization header to remove non-constant
    # information. On one hand we loose the necessary information to
    # try to recover the passwords, but on the other hand we store
    # specs with different challenges but the same username, realm,
    # host and sensor in the same records.
    elif spec['recontype'] in ['HTTP_CLIENT_HEADER',
                               'HTTP_CLIENT_HEADER_SERVER'] and \
        spec.get('source') in ['AUTHORIZATION',
                               'PROXY-AUTHORIZATION']:
        authtype = spec['value'].split(None, 1)[0]
        if authtype.lower() == 'digest':
            try:
                # we only keep relevant info
                value = [val for val in
                         _split_digest_auth(spec['value'][6:].strip())
                         if DIGEST_AUTH_INFOS.match(val)]
                spec['value'] = '%s %s' % (authtype, ','.join(value))
            except Exception:
                utils.LOGGER.warning("Cannot parse digest error for %r", spec,
                                     exc_info=True)
        elif authtype.lower() in ['negotiate', 'kerberos', 'oauth', 'ntlm']:
            spec['value'] = authtype
    # p0f in Bro hack: we use the "source" field to provide the
    # "distance" and "version" values
    elif spec['recontype'] == 'P0F':
        distance, version = spec.pop('source').split('-', 1)
        try:
            spec['distance'] = int(distance)
        except ValueError:
            pass
        if version:
            spec['version'] = version
    # TCP server banners: try to normalize data
    elif spec['recontype'] == 'TCP_SERVER_BANNER':
        newvalue = value = utils.nmap_decode_data(spec['value'])
        for pattern, replace in TCP_SERVER_PATTERNS:
            if pattern.search(newvalue):
                newvalue = pattern.sub(replace, newvalue)
        if newvalue != value:
            spec['value'] = utils.nmap_encode_data(newvalue)
    # SSL_{CLIENT,SERVER} JA3
    elif ((spec['recontype'] == 'SSL_CLIENT' and spec['source'] == 'ja3') or
          (spec['recontype'] == 'SSL_SERVER' and
           spec['source'].startswith('ja3-'))):
        value = spec['value']
        spec.setdefault('infos', {})['raw'] = value
        spec['value'] = hashlib.new("md5", value.encode()).hexdigest()
        if spec['recontype'] == 'SSL_SERVER':
            clientvalue = spec['source'][4:]
            spec['infos'].setdefault('client', {})['raw'] = clientvalue
            spec['source'] = 'ja3-%s' % hashlib.new(
                "md5",
                clientvalue.encode(),
            ).hexdigest()
    # Check DNS Blacklist answer
    elif spec['recontype'] == 'DNS_ANSWER':
        if any(spec['value'].endswith(dnsbl)
               for dnsbl in config.DNS_BLACKLIST_DOMAINS):
            dnsbl_val = spec['value']
            spec['recontype'] = 'DNS_BLACKLIST'
            spec['value'] = spec['addr']
            spec.update({'source': "%s-%s" %
                         (dnsbl_val.split('.', 4)[4], spec['source'])})
            spec['addr'] = '.'.join(dnsbl_val.split('.')[3::-1])
    return spec


def handle_rec(sensor, ignorenets, neverignore,
               # these argmuments are provided by **bro_line
               timestamp=None, uid=None, host=None, srvport=None,
               recon_type=None, source=None, value=None, targetval=None):
    spec = {
        'schema_version': SCHEMA_VERSION,
        'recontype': recon_type,
        'value': value,
    }
    if host is None:
        spec['targetval'] = targetval
    else:
        spec['addr'] = host
    if sensor is not None:
        spec.update({'sensor': sensor})
    if srvport is not None:
        spec.update({'port': srvport})
    if source is not None:
        spec.update({'source': source})
    spec = _prepare_rec(spec, ignorenets, neverignore)
    return timestamp, spec


def _getinfos_http_client_authorization(spec):
    """Extract (for now) the usernames and passwords from Basic
    authorization headers
    """
    infos = {}
    data = spec['value'].split(None, 1)
    if data[1:]:
        if data[0].lower() == b'basic':
            try:
                infos['username'], infos['password'] = utils.decode_b64(
                    data[1].strip()
                ).decode('latin-1').split(':', 1)
            except Exception:
                pass
        elif data[0].lower() == 'digest':
            try:
                infos = dict(
                    value.split('=', 1) if '=' in value else [value, None]
                    for value in _split_digest_auth(data[1].strip())
                )
                for key, value in list(viewitems(infos)):
                    if value.startswith('"') and value.endswith('"'):
                        infos[key] = value[1:-1]
            except Exception:
                pass
    res = {}
    if infos:
        res['infos'] = infos
    return res


def _getinfos_http_server(spec):
    header = utils.nmap_decode_data(spec['value'])
    banner = b"HTTP/1.1 200 OK\r\nServer: " + header + b"\r\n\r\n"
    res = _getinfos_from_banner(banner, probe="GetRequest")
    return res


def _getinfos_dns(spec):
    """Extract domain names in an handy-to-index-and-query form."""
    infos = {}
    fields = {'domain': 'value', 'domaintarget': 'targetval'}
    for field in fields:
        try:
            if fields[field] not in spec:
                continue
            infos[field] = []
            for domain in utils.get_domains(spec[fields[field]]):
                infos[field].append(domain)
            if not infos[field]:
                del infos[field]
        except Exception:
            pass
    res = {}
    if infos:
        res['infos'] = infos
    return res


def _getinfos_dns_blacklist(spec):
    """Extract and properly format DNSBL records."""
    infos = {}
    try:
        if 'source' in spec:
            infos['domain'] = []
            for domain in utils.get_domains(spec['source'].split('-')[-4]):
                infos['domain'].append(domain)
            if not infos['domain']:
                del infos['domain']
    except Exception:
        pass
    res = {}
    if infos:
        res['infos'] = infos
    return res


def _getinfos_sslsrv(spec):
    """Calls a source specific function for SSL_SERVER recontype
records.

    """
    source = spec.get('source')
    if source == 'cert':
        return _getinfos_cert(spec)
    if source.startswith('ja3-'):
        return _getinfos_ja3(spec)
    return {}


def _getinfos_cert(spec):
    """Extract info from a certificate (hash values, issuer, subject,
    algorithm) in an handy-to-index-and-query form.

    """
    # TODO: move to mongodb specific functions.
    try:
        cert = utils.decode_b64(spec['value'].encode())
    except Exception:
        utils.LOGGER.info("Cannot parse certificate for record %r", spec,
                          exc_info=True)
        return {}
    info = utils.get_cert_info(cert)
    res = {}
    if info:
        res['infos'] = info
    return res


def _getinfos_ja3(spec):
    """Extract hashes from JA3 fingerprint strings.

    """
    value = spec['infos']['raw']
    data = value.encode()

    info = dict(((hashtype, hashlib.new(hashtype, data).hexdigest())
                 for hashtype in ['sha1', 'sha256']),
                **spec['infos'])

    if spec.get('recontype') == 'SSL_SERVER':
        clientvalue = spec['infos']['client']['raw']
        clientdata = clientvalue.encode()
        info['client'].update(
            (hashtype, hashlib.new(hashtype, clientdata).hexdigest())
            for hashtype in ['sha1', 'sha256']
        )

    return {'infos': info}


def _getinfos_from_banner(banner, proto="tcp", probe="NULL"):
    infos = utils.match_nmap_svc_fp(banner, proto=proto, probe=probe)
    if not infos:
        return {}
    return {'infos': infos}


def _getinfos_tcp_srv_banner(spec):
    """Extract info from a TCP server banner using Nmap database.

    """
    return _getinfos_from_banner(utils.nmap_decode_data(spec['value']))


def _getinfos_ssh_server(spec):
    """Convert an SSH server banner to a TCP banner and use
_getinfos_tcp_srv_banner()"""
    return _getinfos_from_banner(utils.nmap_decode_data(
        spec['value']
    ) + b'\r\n')


def _getinfos_ssh_hostkey(spec):
    """Parse SSH host keys."""
    infos = {}
    data = utils.nmap_decode_data(spec['value'])
    for hashtype in ['md5', 'sha1', 'sha256']:
        infos[hashtype] = hashlib.new(hashtype, data).hexdigest()
    info = utils.parse_ssh_key(data)
    return {'infos': info}


_GETINFOS_FUNCTIONS = {
    'HTTP_CLIENT_HEADER':
    {'AUTHORIZATION': _getinfos_http_client_authorization,
     'PROXY-AUTHORIZATION': _getinfos_http_client_authorization},
    'HTTP_CLIENT_HEADER_SERVER':
    {'AUTHORIZATION': _getinfos_http_client_authorization,
     'PROXY-AUTHORIZATION': _getinfos_http_client_authorization},
    'HTTP_SERVER_HEADER':
    {'SERVER': _getinfos_http_server},
    'DNS_ANSWER': _getinfos_dns,
    'DNS_BLACKLIST': _getinfos_dns_blacklist,
    'SSL_SERVER': _getinfos_sslsrv,
    'SSL_CLIENT': {'ja3': _getinfos_ja3},
    'TCP_SERVER_BANNER': _getinfos_tcp_srv_banner,
    'SSH_SERVER': _getinfos_ssh_server,
    'SSH_SERVER_HOSTKEY': _getinfos_ssh_hostkey,
}


def getinfos(spec):
    """This functions takes a document from a passive sensor, and
    prepares its 'infos' field (which is not added but returned).

    """
    function = _GETINFOS_FUNCTIONS.get(spec.get('recontype'))
    if isinstance(function, dict):
        function = function.get(spec.get('source'))
    if function is None:
        return {}
    return function(spec)
