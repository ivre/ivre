#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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


import hashlib
import math
import re
import struct
import subprocess


from future.utils import viewitems
from past.builtins import long


from ivre import utils


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
        'addr': utils.ip2int(line[0][line[0].index(b'> ') + 2:
                                     line[0].index(b':')]),
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
    return float(line[0][1:line[0].index(b'>')]), spec


# Bro specific

SYMANTEC_UA = re.compile('[a-zA-Z0-9/+]{32,33}AAAAA$')
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
        for n in ignorenets.get(spec['recontype'], ()):
            if n[0] <= spec['addr'] <= n[1]:
                return None
    # Then, let's clean up the records.
    # Change Symantec's random user agents (matching SYMANTEC_UA) to
    # the constant string 'SymantecRandomUserAgent'.
    if spec['recontype'] == 'HTTP_CLIENT_HEADER' and \
       spec.get('source') == 'USER-AGENT':
        if SYMANTEC_UA.match(spec['value']):
            spec['value'] = 'SymantecRandomUserAgent'
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
    # Finally we prepare the record to be stored. For that, we make
    # sure that no indexed value has a size greater than MAXVALLEN. If
    # so, we replace the value with its SHA1 hash and store the
    # original value in full[original column name].
    if len(spec['value']) > utils.MAXVALLEN:
        spec['fullvalue'] = spec['value']
        spec['value'] = hashlib.sha1(spec['fullvalue'].encode()).hexdigest()
    if 'targetval' in spec and len(spec['targetval']) > utils.MAXVALLEN:
        spec['fulltargetval'] = spec['targetval']
        spec['targetval'] = hashlib.sha1(
            spec['fulltargetval'].encode()
        ).hexdigest()
    return spec


def handle_rec(sensor, ignorenets, neverignore,
               # these argmuments are provided by **bro_line
               timestamp, uid, host, srvport, recon_type, source, value,
               targetval):
    if host is None:
        spec = {
            'targetval': targetval,
            'recontype': recon_type,
            'value': value
        }
    else:
        host = utils.force_ip2int(host)
        spec = {
            'addr': host,
            'recontype': recon_type,
            'value': value
        }
    if sensor is not None:
        spec.update({'sensor': sensor})
    if srvport is not None:
        spec.update({'port': srvport})
    if source is not None:
        spec.update({'source': source})
    spec = _prepare_rec(spec, ignorenets, neverignore)
    float_ts = utils.datetime2timestamp(timestamp)
    return float_ts, spec


def _getinfos_http_client_authorization(spec):
    """Extract (for now) the usernames and passwords from Basic
    authorization headers
    """
    infos = {}
    fullinfos = {}
    data = spec.get('fullvalue', spec['value']).split(None, 1)
    if data[1:]:
        if data[0].lower() == b'basic':
            try:
                infos['username'], infos['password'] = utils.decode_b64(
                    data[1].strip()
                ).decode('latin-1').split(':', 1)
                for field in ['username', 'password']:
                    if len(infos[field]) > utils.MAXVALLEN:
                        fullinfos[field] = infos[field]
                        infos[field] = infos[field][:utils.MAXVALLEN]
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
    if fullinfos:
        res['fullinfos'] = fullinfos
    return res


def _getinfos_http_server(spec):
    header = utils.nmap_decode_data(spec.get('fullvalue', spec['value']))
    banner = b"HTTP/1.1 200 OK\r\nServer: " + header + b"\r\n\r\n"
    res = _getinfos_from_banner(banner, probe="GetRequest")
    return res


def _getinfos_dns(spec):
    """Extract domain names in an handy-to-index-and-query form."""
    infos = {}
    fullinfos = {}
    fields = {'domain': 'value', 'domaintarget': 'targetval'}
    for field in fields:
        try:
            if fields[field] not in spec:
                continue
            infos[field] = []
            fullinfos[field] = []
            for domain in utils.get_domains(
                    spec.get('full' + fields[field],
                             spec[fields[field]])):
                infos[field].append(domain[:utils.MAXVALLEN])
                if len(domain) > utils.MAXVALLEN:
                    fullinfos[field].append(domain)
            if not infos[field]:
                del infos[field]
            if not fullinfos[field]:
                del fullinfos[field]
        except Exception:
            pass
    res = {}
    if infos:
        res['infos'] = infos
    if fullinfos:
        res['fullinfos'] = fullinfos
    return res


_CERTINFOS = re.compile(
    b'\n *'
    b'Issuer: (?P<issuer>.*)'
    b'\n(?:.*\n)* *'
    b'Subject: (?P<subject>.*)'
    b'\n(?:.*\n)* *'
    b'Public Key Algorithm: (?P<pubkeyalgo>.*)'
    b'(?:\n|$)'
)


def _getinfos_cert(spec):
    """Extract info from a certificate (hash values, issuer, subject,
    algorithm) in an handy-to-index-and-query form.

    """
    infos = {}
    fullinfos = {}
    try:
        cert = utils.decode_b64(spec.get('fullvalue', spec['value']).encode())
    except Exception:
        utils.LOGGER.info("Cannot parse certificate for record %r", spec,
                          exc_info=True)
        return {}
    for hashtype in ['md5', 'sha1']:
        infos['%shash' % hashtype] = hashlib.new(hashtype, cert).hexdigest()
    proc = subprocess.Popen(['openssl', 'x509', '-noout', '-text',
                             '-inform', 'DER'], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    proc.stdin.write(cert)
    proc.stdin.close()
    try:
        newinfos = _CERTINFOS.search(proc.stdout.read()).groupdict()
        newfullinfos = {}
        for field in newinfos:
            data = newinfos[field] = newinfos[field].decode()
            if len(data) > utils.MAXVALLEN:
                newfullinfos[field] = data
                newinfos[field] = data[:utils.MAXVALLEN]
        infos.update(newinfos)
        fullinfos.update(newfullinfos)
    except Exception:
        utils.LOGGER.info("Cannot parse certificate for record %r", spec,
                          exc_info=True)
    res = {}
    if infos:
        res['infos'] = infos
    if fullinfos:
        res['fullinfos'] = fullinfos
    return res


def _fix_infos_size(spec):
    for field in list(spec.get("infos", {})):
        value = spec["infos"]
        if len(value) > utils.MAXVALLEN:
            spec.setdefault("fullinfos", {})[field] = value
            spec["infos"][field] = value[:utils.MAXVALLEN]


def _getinfos_from_banner(banner, proto="tcp", probe="NULL"):
    infos = utils.match_nmap_svc_fp(banner, proto=proto, probe=probe)
    if not infos:
        return {}
    res = {'infos': infos}
    _fix_infos_size(res)
    return res


def _getinfos_tcp_srv_banner(spec):
    """Extract info from a TCP server banner using Nmap database.

    """
    return _getinfos_from_banner(utils.nmap_decode_data(
        spec.get('fullvalue', spec['value'])
    ))


def _getinfos_ssh_server(spec):
    """Convert an SSH server banner to a TCP banner and use
_getinfos_tcp_srv_banner()"""
    return _getinfos_from_banner(utils.nmap_decode_data(
        spec.get('fullvalue', spec['value'])
    ) + b'\n')


def _getinfos_ssh_hostkey(spec):
    """Parse SSH host keys."""
    infos = {}
    data = utils.nmap_decode_data(spec.get('fullvalue', spec['value']))
    infos["md5hash"] = hashlib.md5(data).hexdigest()
    infos["sha1hash"] = hashlib.sha1(data).hexdigest()
    infos["sha256hash"] = hashlib.sha256(data).hexdigest()
    data = utils.parse_ssh_key(data)
    keytype = infos["algo"] = next(data).decode()
    if keytype == "ssh-rsa":
        try:
            infos["exponent"], infos["modulus"] = (
                long(utils.encode_hex(elt), 16) for elt in data
            )
        except Exception:
            utils.LOGGER.info("Cannot parse SSH host key for record %r", spec,
                              exc_info=True)
        else:
            infos["bits"] = math.ceil(math.log(infos["modulus"], 2))
            # convert integer to strings to prevent overflow errors
            # (e.g., "MongoDB can only handle up to 8-byte ints")
            for val in ["exponent", "modulus"]:
                infos[val] = str(infos[val])
    res = {'infos': infos}
    _fix_infos_size(res)
    return res


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
    'SSL_SERVER': _getinfos_cert,
    'TCP_SERVER_BANNER': _getinfos_tcp_srv_banner,
    'SSH_SERVER': _getinfos_ssh_server,
    'SSH_SERVER_HOSTKEY': _getinfos_ssh_hostkey,
}


def getinfos(spec):
    """This functions takes a document from a passive sensor, and
    prepares its 'infos' and 'fullinfos' fields (which are not added
    but returned).

    """
    function = _GETINFOS_FUNCTIONS.get(spec.get('recontype'))
    if isinstance(function, dict):
        function = function.get(spec.get('source'))
    if function is None:
        return {}
    if hasattr(function, '__call__'):
        return function(spec)
