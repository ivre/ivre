#! /usr/bin/env python

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

"""Put selected results in views."""

from datetime import datetime

from ivre import utils
from ivre.xmlnmap import SCHEMA_VERSION, create_ssl_cert
from ivre.db import db


def _extract_passive_HTTP_CLIENT_HEADER_SERVER(rec):
    """Handle http client header about server."""
    return {'ports': [{
        'state_state': 'open',
        'state_reason': "passive",
        'port': rec['port'],
        'protocol': rec.get('protocol', 'tcp'),
        'service_name': 'http',
    }]}
    # TODO: (?) handle Host: header for DNS
    # FIXME: catches ip addresses as domain name.
    if 'source' in rec and rec['source'] == 'HOST':
        values = rec['value'].split(".")
        domains = [values.pop()]
        while values:
            domains.insert(0, values.pop() + "." + domains[0])
        return {'hostnames': [{'domains': domains,
                               'type': "?",
                               'name': domains[0]}]}


def _extract_passive_HTTP_SERVER_HEADER(rec):
    """Handle http server headers."""
    port = {
        'state_state': 'open',
        'state_reason': "passive",
        'port': rec['port'],
        'protocol': rec.get('protocol', 'tcp'),
        'service_name': 'http',
    }
    # TODO: handle other header values and merge them
    if rec.get('source') != 'SERVER':
        return {'ports': [port]}
    value = rec['value']
    script = {'id': 'http-server-header', 'output': value}
    port['scripts'] = [script]
    banner = (b"HTTP/1.1 200 OK\r\nServer: " + utils.nmap_decode_data(value) +
              b"\r\n\r\n")
    port.update(
        utils.match_nmap_svc_fp(output=banner,
                                proto=rec.get('protocol', 'tcp'),
                                probe="GetRequest")
    )
    return {'ports': [port]}


def _extract_passive_HTTP_CLIENT_HEADER(rec):
    """Handle http client headers."""
    # TODO: handle other header values
    if rec.get('source') != 'USER-AGENT':
        return {}
    return {'ports': [{
        'port': -1,
        'scripts': [{'id': 'http-user-agent',
                     'output': rec['value'],
                     'http-user-agent': [rec['value']]}],
    }]}


def _extract_passive_TCP_SERVER_BANNER(rec):
    """Handle banners from tcp servers."""
    value = rec['value']
    if rec['recontype'] == 'SSH_SERVER':
        value += "\r\n"
    port = {
        'state_state': 'open',
        'state_reason': "passive",
        'port': rec['port'],
        'protocol': rec.get('protocol', 'tcp'),
        'scripts': [{"id": "banner",
                     "output": value}],
    }
    port.update(rec.get('infos', {}))
    port.update(
        utils.match_nmap_svc_fp(output=utils.nmap_decode_data(value),
                                proto=rec.get('protocol', 'tcp'),
                                probe="NULL")
    )
    return {'ports': [port]}


_KEYS = {
    'ecdsa-sha2-nistp256': 'ECDSA',
}


def _extract_passive_SSH_SERVER_HOSTKEY(rec):
    """Handle SSH host keys."""
    # TODO: should (probably) be merged, sorted by date/time, keep one
    # entry per key type.
    #
    # (MAYBE) we should add a "lastseen" tag to every intel in view.
    value = utils.encode_b64(
        utils.nmap_decode_data(rec['value'])
    ).decode()
    fingerprint = rec['infos']['md5']
    key = {'type': rec['infos']['algo'],
           'key': value,
           'fingerprint': fingerprint}
    if 'bits' in rec['infos']:  # FIXME
        key['bits'] = rec['infos']['bits']
    fingerprint = utils.decode_hex(fingerprint)
    script = {
        'id': 'ssh-hostkey', 'ssh-hostkey': [key],
        'output': '\n  %s %s (%s)\n%s %s' % (
            key.get('bits', '-'),  # FIXME
            ':'.join('%02x' % (
                ord(i) if isinstance(i, (bytes, str)) else i
            ) for i in fingerprint),
            _KEYS.get(
                key['type'],
                (key['type'][4:] if key['type'][:4] == 'ssh-'
                 else key['type']).upper()
            ),
            key['type'],
            value
        ),
        'key': key
    }
    return {'ports': [{
        'state_state': 'open',
        'state_reason': "passive",
        'port': rec['port'],
        'protocol': rec.get('protocol', 'tcp'),
        'service_name': 'ssh',
        'scripts': [script],
    }]}


def _extract_passive_SSL_SERVER(rec):
    """Handle ssl server headers."""
    source = rec.get('source')
    if source == 'cert':
        return _extract_passive_SSL_SERVER_cert(rec)
    if source.startswith('ja3-'):
        return _extract_passive_SSL_SERVER_ja3(rec)
    return {}


def _extract_passive_SSL_SERVER_cert(rec):
    script = {"id": "ssl-cert"}
    port = {
        'state_state': 'open',
        'state_reason': "passive",
        'port': rec['port'],
        'protocol': rec.get('protocol', 'tcp'),
    }
    output, info = create_ssl_cert(rec['value'], b64encoded=False)
    if info:
        script['output'] = "\n".join(output)
        script['ssl-cert'] = info
        port['scripts'] = [script]
    return {'ports': [port]}


def _extract_passive_SSL_SERVER_ja3(rec):
    script = {"id": "ssl-ja3-server"}
    port = {
        'state_state': 'open',
        'state_reason': 'passive',
        'port': rec['port'],
        'protocol': rec.get('protocol', 'tcp'),
    }
    script['output'] = rec['value'] + ' - ' + rec['source'][4:]
    info = {
        'raw': rec['infos']['raw'],
        'sha256': rec['infos']['sha256'],
        'sha1': rec['infos']['sha1'],
        'md5': rec['value'],
        'client': {
            'raw': rec['infos']['client']['raw'],
            'sha256': rec['infos']['client']['sha256'],
            'sha1': rec['infos']['client']['sha1'],
            'md5': rec['source'][4:]
        }
    }
    script['ssl-ja3-server'] = [info]
    port['scripts'] = [script]
    return {'ports': [port]}


def _extract_passive_DNS_ANSWER(rec):
    """Handle dns server headers."""
    name = rec['value']
    domains = rec['infos']['domain']
    return {'hostnames': [{'domains': domains,
                           'type': rec['source'].split('-', 1)[0],
                           'name': name}]}


def _extract_passive_SSL_CLIENT(rec):
    """Handle SSL client ja3 extraction."""
    script = {"id": "ssl-ja3-client"}
    script['output'] = rec['value']
    script['ssl-ja3-client'] = [{
        'raw': rec['infos']['raw'],
        'sha256': rec['infos']['sha256'],
        'sha1': rec['infos']['sha1'],
        'md5': rec['value']
    }]

    port = {
        'port': -1,
        'scripts': [script]
    }

    return {'ports': [port]}


_EXTRACTORS = {
    # 'HTTP_CLIENT_HEADER_SERVER': _extract_passive_HTTP_CLIENT_HEADER_SERVER,
    'HTTP_CLIENT_HEADER': _extract_passive_HTTP_CLIENT_HEADER,
    'HTTP_SERVER_HEADER': _extract_passive_HTTP_SERVER_HEADER,
    'SSL_SERVER': _extract_passive_SSL_SERVER,
    'SSL_CLIENT': _extract_passive_SSL_CLIENT,
    # FIXME: see db/prostgres while hostnames are not merged, it is useless
    # to add DNS answers. It creates empty results.
    'DNS_ANSWER': _extract_passive_DNS_ANSWER,
    'SSH_SERVER': _extract_passive_TCP_SERVER_BANNER,
    'SSH_SERVER_HOSTKEY': _extract_passive_SSH_SERVER_HOSTKEY,
    'TCP_SERVER_BANNER': _extract_passive_TCP_SERVER_BANNER,
}


def passive_record_to_view(rec):
    """Return a passive entry in the View format.

    Note that this entry is likely to have no sense in itself. This
    function is intended to be used to format results for the merge
    function.

    """
    rec = dict(rec)
    if not rec.get('addr'):
        return
    outrec = {
        'addr': rec["addr"],
        'state_reason': 'passive',
        'schema_version': SCHEMA_VERSION,
    }
    # a DNS_ANSWER record is not enough to mark a host as up
    if rec['recontype'] != 'DNS_ANSWER':
        outrec['state'] = 'up'
    sensor = rec.get('sensor')
    if sensor:
        outrec['source'] = [sensor]
    try:
        outrec['starttime'] = datetime.fromtimestamp(rec["firstseen"])
        outrec['endtime'] = datetime.fromtimestamp(rec["lastseen"])
    except TypeError:
        outrec['starttime'] = rec['firstseen']
        outrec['endtime'] = rec['lastseen']
    function = _EXTRACTORS.get(rec['recontype'], lambda _: {})
    if isinstance(function, dict):
        function = function.get(rec['source'], lambda _: {})
    outrec.update(function(rec))
    openports = outrec['openports'] = {'count': 0}
    for port in outrec.get('ports', []):
        if port.get('state_state') != 'open':
            continue
        openports['count'] += 1
        protoopenports = openports.setdefault(port['protocol'],
                                              {'count': 0, 'ports': []})
        protoopenports['count'] += 1
        protoopenports['ports'].append(port['port'])
    if db.view.category:
        outrec['categories'] = [db.view.category]
    return outrec


def passive_to_view(flt):
    """Generates passive entries in the View format.

    Note that this entry is likely to have no sense in itself. This
    function is intended to be used to format results for the merge
    function.

    """
    for rec in db.passive.get(flt, sort=[("addr", 1)]):
        outrec = passive_record_to_view(rec)
        if outrec is not None:
            yield outrec


def from_passive(flt):
    """Iterator over passive results, by address."""
    records = passive_to_view(flt)
    cur_addr = None
    cur_rec = None
    for rec in records:
        if cur_addr is None:
            cur_addr = rec['addr']
            cur_rec = rec
        elif cur_addr != rec['addr']:
            # TODO: add_addr_info should be optional
            cur_rec['infos'] = {}
            for func in [db.data.country_byip,
                         db.data.as_byip,
                         db.data.location_byip]:
                cur_rec['infos'].update(func(cur_addr) or {})
            yield cur_rec
            cur_rec = rec
            cur_addr = rec['addr']
        else:
            cur_rec = db.view.merge_host_docs(cur_rec, rec)
    if cur_rec is not None:
        yield cur_rec


def nmap_record_to_view(rec):
    """Convert an nmap result in view.

    """
    if 'scanid' in rec:
        del rec['scanid']
    if 'source' in rec:
        if not rec['source']:
            rec['source'] = []
        elif not isinstance(rec['source'], list):
            rec['source'] = [rec['source']]
    rec['categories'] = rec.get('categories', [])
    if db.view.category:
        rec['categories'].append(db.view.category)
    return rec


def from_nmap(flt):
    """Return an Nmap entry in the View format."""
    cur_addr = None
    cur_rec = None
    result = None
    for rec in db.nmap.get(flt, sort=[("addr", 1)]):
        if 'addr' not in rec:
            continue
        rec = nmap_record_to_view(rec)
        if cur_addr is None:
            cur_addr = rec['addr']
            cur_rec = rec
            continue
        if cur_addr != rec['addr']:
            result = cur_rec
            cur_rec = rec
            cur_addr = rec['addr']
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
    next_addrs = [rec['addr'] for rec in next_recs]
    cur_rec = None
    cur_addr = min(next_addrs, key=utils.ip2int)
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
                next_addrs[i] = next_recs[i]['addr']
            i += 1
        if next_addrs and cur_addr not in next_addrs:
            yield cur_rec
            cur_rec = None
            cur_addr = min(next_addrs)
    if cur_rec is not None:
        yield cur_rec
