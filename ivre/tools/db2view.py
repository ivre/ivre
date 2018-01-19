# -*- coding: utf-8 -*-

"""Put selected results in views."""

from __future__ import print_function
from future.utils import viewitems, viewvalues
from datetime import datetime
import time
import os
import sys

from builtins import input
from past.builtins import basestring

from ivre import utils
from ivre.xmlnmap import SCHEMA_VERSION
from ivre.tools.viewcli import stub_print
from ivre.db import db

try:
    import argparse
    USING_ARGPARSE = True
except ImportError:
    import optparse
    USING_ARGPARSE = False

### Utitilities ###

def _stub_update(d, u):
    """Stub function to keep maximum information on update. ~='d.update(u)'"""
    if not isinstance(d, dict) or not isinstance(u, dict):
        raise TypeError
    for k, v in u.items():
        if isinstance(d.get(k), dict) and isinstance(v, dict):
            _stub_update(d[k], v)
            continue
        if isinstance(d.get(k), list) and isinstance(v, list):
            for e in v:
                if not e in d[k]:
                    d[k].append(e)
            continue
        d[k] = v

def _merge_passive(rec1, rec2):
    """Merging function for two passive scans."""
    new_rec = rec2.copy()
    new_rec['openports'] = {
        'count': 1,
        'tcp_count': 0,
        'tcp_ports': [],
        'udp_count': 0,
        'udp_ports': [],
    }
    for k, v in rec1.items():
        if isinstance(v, dict):
            # openports is updated on the fly.
            if k == 'openports':
                pass
            else:
                _stub_update(new_rec.setdefault(k, {}), v)
        elif isinstance(v, list):
            # Check for port duplication
            if k == 'ports':
                new_ports = {}
                for port2 in new_rec.get(k, []):
                    if not port2:
                        continue
                    _stub_update(
                        new_ports.setdefault(
                            port2.get('port', -1),
                            {}
                        ),
                        port2
                    )
                for port1 in rec1['ports']:
                    if not port1:
                        continue
                    _stub_update(
                        new_ports.setdefault(
                            port1.get('port', -1),
                            {}
                        ),
                        port1
                    )
                # FIXME: workaround for multiple script outputs.
                for _, port in viewitems(new_ports):
                    scriptlist = []
                    while port.setdefault('scripts', []):
                        sc1 = port['scripts'].pop()
                        for sc2 in port['scripts']:
                            if sc1['id'] == sc2['id']:
                                port['scripts'].remove(sc2)
                                sc1['output'] += ", %s" % sc2['output']
                        scriptlist.append(sc1)
                    port['scripts'] = scriptlist
                #
                new_ports = list(viewvalues(new_ports))
                for pts in new_ports:
                    if pts.get('port', -1) == -1:
                        continue
                    new_rec['openports']['count'] += 1
                    prot = pts.get('protocol', 'tcp')
                    new_rec['openports']['%s_count' % prot] += 1
                    new_rec['openports']['%s_ports' % prot]\
                        .append(pts['port'])
                new_rec[k] = new_ports
            # Check for hostname duplication
            elif k == 'hostnames':
                new_doms = []
                for dom2 in new_rec.get(k, []):
                    if not any(map(lambda x: x['name']==dom2['name'], v)):
                        new_doms.append(dom2)
                new_doms.extend(v)
                new_rec[k] = new_doms
            else:
                new_rec.setdefault(k, []).extend(v)
        else:
            if k == 'starttime':
                if not k in new_rec:
                    new_rec[k] = v
                else:
                    new_rec[k] = min(new_rec[k], v)
            elif k == 'endtime':
                if not k in new_rec:
                    new_rec[k] = v
                else:
                    new_rec[k] = max(new_rec[k], v)
            else:
                new_rec[k] = v
    return new_rec

### From passive database ###

def _extract_passive_HTTP_CLIENT_HEADER_SERVER(rec):
    """Handle http client header about server."""
    # FIXME: catches ip addresses as domain name.
    if 'source' in rec and rec['source'] == 'HOST':
        values = rec['value'].split(".")
        domains = [values.pop()]
        while values:
            domains.insert(0, values.pop()+"."+domains[0])
        return {'hostnames': [{'domains': domains,
                                'type': "?",
                                'name': domains[0]}]}


def _extract_passive_HTTP_SERVER_HEADER(rec):
    """Handle http server headers."""
    scripts = []
    if rec.get('source') == 'SERVER':
        scripts.append({'id': 'http-server-header',
                               'output': rec['value']})
    elif rec.get('source') == 'X-POWERED-BY':
        scripts.append({'id': 'x-powered', 'output': rec['value']})
    elif 'source' in rec:
        scripts.append({'id': rec['source'].lower(),
                               'output': rec['value']})
    port = {
        'scripts': scripts,
        'port': rec.get('port', -1),
    }
    for probe in ["GetRequest", "NULL"]:
        port.update(
            utils.match_nmap_svc_fp(output=rec['value'].encode(),
                                    proto=rec.get('protocol', 'tcp'),
                                    probe=probe,
            )
        )
    return {'ports': [port]}


def _extract_passive_TCP_SERVER_BANNER(rec):
    """Handle banners from tcp servers."""
    if not 'value' in rec:
        return {}
    port = {
        'scripts': [],
        'port': rec.get('port', -1),
    }
    port.update(
        utils.match_nmap_svc_fp(output=rec['value'].encode(),
                                proto=rec.get('protocol', 'tcp'),
                                probe="NULL",
        )
    )
    port.update(rec.get('infos', {}))
    return {'ports': [port]}


def _extract_passive_SSL_SERVER(rec):
    """Handle ssl server headers."""
    scripts = []
    if 'info' in rec:
        for i in rec['info']:
            if i == 'domain':
                continue
            scripts.append({'id': "ssl : %s" % i, 'output': rec['infos'][i]})
    if rec.get('source') == 'cert':
        scripts.append({'id': rec['source'].lower(),
                        'output': rec['value']})
        for k, v in viewitems(rec.get('moreinfo', {})):
            scripts.append({'id': k, 'output': v})
    elif 'source' in rec:
        scripts.append({'id': rec['source'].lower(),
                        'output': rec['value']})
    return {'ports': [{
                'scripts': scripts,
                'port': rec.get('port', -1),
           }]}


def _extract_passive_DNS_ANSWER(rec):
    """Handle dns server headers."""
    if 'source' in rec:
        thetype = rec['source'].split('-', 1)[0]
    else:
        thetype = "?"
    name = rec['value']
    domains = rec['moreinfo'].get('domain', []) 
    return {'hostnames': [{'domains': domains,
                            'type': thetype,
                            'name': name}]}

def _extract_passive_SSH_SERVER(rec):
    """Handle ssh server headers."""
    port = {
        'port': rec.get('port', -1),
    }
    update = utils.match_nmap_svc_fp(output=rec['value'].encode(),
                                proto='tcp',
                                probe="NULL",
    )
    port.update(
        {'scripts':
            [{'id': 'banner', 'output': rec['value']}]
        } if not update else update
    )
    return {'ports': [port]}

def _extract_passive_FTP_SERVER(rec):
    """Handle ftp server infos."""
    return _extract_passive_DEFAULT(rec)

def _extract_passive_POP_SERVER(rec):
    """Handle pop server infos."""
    return _extract_passive_DEFAULT(rec)

def _extract_passive_DEFAULT(rec):
    scripts = []
    if 'source' in rec:
        scripts.append({'id': rec['source'].lower(),
                        'output': rec['value']})
    return {'ports': [{
                'scripts': scripts,
                'port': rec.get('port', -1),
           }]}


_EXTRACTORS = {
    #'HTTP_CLIENT_HEADER_SERVER': _extract_passive_HTTP_CLIENT_HEADER_SERVER,
    'HTTP_SERVER_HEADER': _extract_passive_HTTP_SERVER_HEADER,
    'SSL_SERVER': _extract_passive_SSL_SERVER,
    # FIXME: see db/prostgres while hostnames are not merged, it is useless
    # to add DNS answers. It creates empty results.
    #'DNS_ANSWER': _extract_passive_DNS_ANSWER,
    'SSH_SERVER': _extract_passive_SSH_SERVER,
    'FTP_SERVER': _extract_passive_FTP_SERVER,
    'POP_SERVER': _extract_passive_POP_SERVER,
    'DHCP_SERVER': _extract_passive_DEFAULT,
    'TCP_SERVER_BANNER': _extract_passive_TCP_SERVER_BANNER,
}


def passive_to_view(flt):
    """Return a passive entry in the View format.
    Note that this entry is likely to have no sense in itself. This function
    is intended to be used to format results for the merge function."""
    cursor = db.passive.get(flt, sort=[("addr", 1)])
    for rec in cursor:
        rec = dict(rec)
        if not rec.get('addr') or not rec.get('port'):
            continue
        outrec = {
            'addr': rec["addr"],
            'state': "up",
            'state_reason': 'passive',
            'schema_version': SCHEMA_VERSION,
            'openports': {
                'count': 0,
                'tcp_count': 0,
                'tcp_ports': [],
                'udp_count': 0,
                'udp_ports': [],
            },
            'ports': [{
                'state_reason': "passive recon",
                'port': rec['port'],
                'state_state': 'open',
                'protocol': rec.get('protocol', 'tcp'),
            }],
        }
        outrec['openports']['count'] += 1
        if rec.get('protocol') == 'udp':
            outrec['openports']['udp_count'] += 1
            outrec['openports']['udp_ports'].append(rec['port'])
        else:
            outrec['openports']['tcp_count'] += 1
            outrec['openports']['tcp_ports'].append(rec['port'])
        try:
            outrec['starttime'] = datetime.fromtimestamp(int(rec["firstseen"]))
            outrec['endtime'] = datetime.fromtimestamp(int(rec["lastseen"]))
        except TypeError:
            outrec['starttime'] = rec['firstseen']
            outrec['endtime'] = rec['lastseen']
        if 'recontype' in rec:
            try:
                outrec = _merge_passive(
                    outrec,
                    _EXTRACTORS.get(rec['recontype'], lambda _: {})(rec)
                )
            except TypeError:
                utils.LOGGER.warning("TypeError raised for %s::%s." %
                                     (db.view.convert_ip(rec['addr']),
                                      rec['recontype']))
                continue
        yield outrec


def from_passive(flt):
    """Iterator over passive results, by address."""
    records = passive_to_view(flt)
    cur_addr = None
    result = None
    cur_rec = None
    for rec in records:
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
            cur_rec = _merge_passive(cur_rec, rec)
            continue
    if cur_rec is not None:
        yield cur_rec


### From Nmap database. ###

def from_nmap(flt):
    """Return an Nmap entry in the View format."""
    cursor = db.nmap.get(flt, sort=[("addr", 1)])
    for rec in cursor:
        if not 'addr' in rec:
            continue
        if 'scanid' in rec:
        # No reason to keep relation with scanfiles.
            del rec['scanid']
        yield rec


### To view database. ###

def main():
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(
            description='Create views from nmap and passive databases.')
    else:
        parser = optparse.OptionParser(
            description='Create views from nmap and passive databases.')
        parser.parse_args_orig = parser.parse_args
        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('ips', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option

    baseflt = db.view.flt_empty
    fltnmap = db.nmap.flt_empty
    fltpass = db.passive.flt_empty

    parser.add_argument('--category', metavar='CATEGORY',
                        help='Choose a different category than the default')
    parser.add_argument('--test', '-t', action='store_true',
                        help='Give results in standard output instead of '
                             'inserting them in database.')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='For test output, print out formated results.')

    if not USING_ARGPARSE:
        if 'nmap' in sys.argv:
            for args, kargs in db.nmap.argparser.args:
                parser.add_option(*args, **kargs)
        elif 'passive' in sys.argv:
            for args, kargs in db.passive.argparser.args:
                parser.add_option(*args, **kargs)
        else:
            print('ivre db2view: error: invalid subcommand {nmap, passive}.')
            exit(-1)
    else:
        subparsers = parser.add_subparsers(dest='view_source',
                                           help="Accepted values are "
                                                "'nmap' and 'passive'")

        nmapparser = subparsers.add_parser('nmap',
                                           parents=[db.nmap.argparser])
        passparser = subparsers.add_parser('passive',
                                           parents=[db.passive.argparser])
        passparser.add_argument('ips', nargs='*')

    args = parser.parse_args()

    if args.category:
        db.view.category = args.category
    if not args.view_source:
        args.view_source = 'all'
    if args.view_source == 'all':
        raise NotImplementedError
        fltnmap = db.nmap.parse_args(args)
        fltpass = db.passive.parse_args(args)
        def _from(flt_a, flt_p):
            a = from_nmap(flt_a)
            p = from_passive(flt_p)
            for e in a:
                yield e
            for e in p:
                yield e
    if args.view_source == 'nmap':
        _from = lambda x, _: from_nmap(x)
        fltnmap = db.nmap.parse_args(args, fltnmap)
    if args.view_source == 'passive':
        _from = lambda _, y: from_passive(y)
        fltpass = db.passive.parse_args(args, fltpass)
    if args.test:
        if args.verbose:
            def output(x):
                stub_print(x)
                print()
        else:
            def output(x):
                print(x)
    else:
        output = db.view.store_or_merge_host
    # Filter by ip for passive
    if args.view_source == 'passive' and args.ips:
        flt = db.passive.flt_empty
        for a in args.ips:
            if ':' in a:
                a = a.split(':', 1)
                if a[0].isdigit():
                    a[0] = int(a[0])
                if a[1].isdigit():
                    a[1] = int(a[1])
                flt = db.passive.flt_or(flt, db.passive.searchrange(a[0], a[1]))
            elif '-' in a:
                a = a.split('-', 1)
                if a[0].isdigit():
                    a[0] = int(a[0])
                if a[1].isdigit():
                    a[1] = int(a[1])
                flt = db.passive.flt_or(flt, db.passive.searchrange(a[0], a[1]))
            elif '/' in a:
                flt = db.passive.flt_or(flt, db.passive.searchnet(a))
            else:
                if a.isdigit():
                    a = db.passive.convert_ip(int(a))
                flt = db.passive.flt_or(flt, db.passive.searchhost(a))
        fltpass = db.passive.flt_and(fltpass, flt)
    # Output results
    itr = _from(fltnmap, fltpass)
    if not itr:
        return
    for it in itr:
        output(it)

