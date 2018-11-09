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


from __future__ import print_function
import json
import os
from xml.sax import saxutils
try:
    from collections import OrderedDict
except ImportError:
    # fallback to dict for Python 2.6
    OrderedDict = dict
import sys
try:
    reload(sys)
except NameError:
    pass
else:
    sys.setdefaultencoding('utf-8')


from future.utils import viewitems, viewvalues
from past.builtins import basestring


from ivre import utils, db, graphroute, config, xmlnmap


HONEYD_ACTION_FROM_NMAP_STATE = {
    'resets': 'reset',
    'no-responses': 'block',
}
HONEYD_DEFAULT_ACTION = 'block'
HONEYD_STD_SCRIPTS_BASE_PATH = '/usr/share/honeyd'
HONEYD_SSL_CMD = 'honeydssl --cert-subject %(subject)s -- %(command)s'


def _display_honeyd_preamble(out=sys.stdout):
    out.write("""create default
set default default tcp action block
set default default udp action block
set default default icmp action block

""")


def _getscript(port, sname):
    for s in port.get('scripts', []):
        if s['id'] == sname:
            return s
    return None


def _nmap_port2honeyd_action(port):
    if port['state_state'] == 'closed':
        return 'reset'
    elif port['state_state'] != 'open':
        return 'block'
    # if 'service_tunnel' in port and port['service_tunnel'] == 'ssl':
    #     sslrelay = True
    # else:
    #     sslrelay = False
    if 'service_name' in port:
        if port['service_name'] == 'tcpwrapped':
            return '"true"'
        elif port['service_name'] == 'ssh':
            s = _getscript(port, 'banner')
            if s is not None:
                banner = s['output']
            else:
                banner = 'SSH-%s-%s' % (
                    port.get('service_version', '2.0'),
                    '_'.join([k for k in
                              port.get('service_product', 'OpenSSH').split()
                              if k != 'SSH']),
                )
            return '''"%s %s"''' % (
                os.path.join(config.HONEYD_IVRE_SCRIPTS_PATH, 'sshd'),
                banner
            )
    return 'open'


def _display_honeyd_conf(host, honeyd_routes, honeyd_entries, out=sys.stdout):
    addr = utils.int2ip(host['addr'])
    hname = "host_%s" % addr.replace('.', '_')
    out.write("create %s\n" % hname)
    defaction = HONEYD_DEFAULT_ACTION
    if 'extraports' in host:
        extra = host['extraports']
        defaction = max(
            max(viewvalues(extra),
                key=lambda state: viewitems(state['total'])['reasons']),
            key=lambda reason: reason[1],
        )[0]
        defaction = HONEYD_ACTION_FROM_NMAP_STATE.get(defaction)
    out.write('set %s default tcp action %s\n' % (hname, defaction))
    for p in host.get('ports', []):
        try:
            out.write('add %s %s port %d %s\n' % (
                hname, p['protocol'], p['port'],
                _nmap_port2honeyd_action(p),
            ))
        except KeyError:
            # let's skip pseudo-port records that are only containers for host
            # scripts.
            pass
    if 'traces' in host and len(host['traces']) > 0:
        trace = max(host['traces'], key=lambda x: len(x['hops']))['hops']
        if trace:
            trace.sort(key=lambda x: x['ttl'])
            curhop = trace[0]
            honeyd_entries.add(curhop['ipaddr'])
            for t in trace[1:]:
                key = (curhop['ipaddr'], t['ipaddr'])
                latency = max(t['rtt'] - curhop['rtt'], 0)
                route = honeyd_routes.get(key)
                if route is None:
                    honeyd_routes[key] = {
                        'count': 1,
                        'high': latency,
                        'low': latency,
                        'mean': latency,
                        'targets': set([host['addr']])
                    }
                else:
                    route['targets'].add(host['addr'])
                    honeyd_routes[key] = {
                        'count': route['count'] + 1,
                        'high': max(route['high'], latency),
                        'low': min(route['low'], latency),
                        'mean': (route['mean'] * route['count'] +
                                 latency) / (route['count'] + 1),
                        'targets': route['targets'],
                    }
                curhop = t
    out.write('bind %s %s\n\n' % (addr, hname))
    return honeyd_routes, honeyd_entries


def _display_honeyd_epilogue(honeyd_routes, honeyd_entries, out=sys.stdout):
    for r in honeyd_entries:
        out.write('route entry %s\n' % utils.int2ip(r))
        out.write('route %s link %s/32\n' % (utils.int2ip(r),
                                             utils.int2ip(r)))
    out.write('\n')
    for r in honeyd_routes:
        out.write('route %s link %s/32\n' % (utils.int2ip(r[0]),
                                             utils.int2ip(r[1])))
        for t in honeyd_routes[r]['targets']:
            out.write('route %s add net %s/32 %s latency %dms\n' % (
                utils.int2ip(r[0]), utils.int2ip(t),
                utils.int2ip(r[1]),
                int(round(honeyd_routes[r]['mean'])),
            ))


def _display_xml_preamble(out=sys.stdout):
    out.write('<?xml version="1.0"?>\n'
              '<?xml-stylesheet '
              'href="file:///usr/local/bin/../share/nmap/nmap.xsl" '
              'type="text/xsl"?>\n')


def _display_xml_scan(scan, out=sys.stdout):
    if 'scaninfos' in scan and scan['scaninfos']:
        for k in scan['scaninfos'][0]:
            scan['scaninfo.%s' % k] = scan['scaninfos'][0][k]
        del scan['scaninfos']
    for k in ['version', 'start', 'startstr', 'args', 'scanner',
              'xmloutputversion', 'scaninfo.type', 'scaninfo.protocol',
              'scaninfo.numservices', 'scaninfo.services']:
        if k not in scan:
            scan[k] = ''
        elif isinstance(scan[k], basestring):
            scan[k] = scan[k].replace('"', '&quot;').replace('--', '-&#45;')
    out.write('<!DOCTYPE nmaprun PUBLIC '
              '"-//IDN nmap.org//DTD Nmap XML 1.04//EN" '
              '"https://svn.nmap.org/nmap/docs/nmap.dtd">\n'
              '<?xml-stylesheet '
              'href="file:///usr/local/bin/../share/nmap/nmap.xsl" '
              'type="text/xsl"?>\n'
              '<!-- Nmap %(version)s scan initiated %(startstr)s '
              'as: %(args)s -->\n'
              '<nmaprun scanner="%(scanner)s" args="%(args)s" '
              'start="%(start)s" startstr="%(startstr)s" '
              'version="%(version)s" '
              'xmloutputversion="%(xmloutputversion)s">\n'
              '<scaninfo type="%(scaninfo.type)s" '
              'protocol="%(scaninfo.protocol)s" '
              'numservices="%(scaninfo.numservices)s" '
              'services="%(scaninfo.services)s"/>\n' % scan)


def _display_xml_table_elem(doc, first=False, name=None, out=sys.stdout):
    if first:
        assert name is None
    name = '' if name is None else ' key=%s' % saxutils.quoteattr(name)
    if isinstance(doc, list):
        if not first:
            out.write('<table%s>\n' % name)
        for subdoc in doc:
            _display_xml_table_elem(subdoc, out=out)
        if not first:
            out.write('</table>\n')
    elif isinstance(doc, dict):
        if not first:
            out.write('<table%s>\n' % name)
        for key, subdoc in viewitems(doc):
            _display_xml_table_elem(subdoc, name=key, out=out)
        if not first:
            out.write('</table>\n')
    else:
        out.write('<elem%s>%s</elem>\n' % (name,
                                           saxutils.escape(
                                               str(doc),
                                               entities={'\n': '&#10;'},
                                           )))


def _display_xml_script(s, out=sys.stdout):
    out.write('<script id=%s' % saxutils.quoteattr(s['id']))
    if 'output' in s:
        out.write(' output=%s' % saxutils.quoteattr(s['output']))
    key = xmlnmap.ALIASES_TABLE_ELEMS.get(s['id'], s['id'])
    if key in s:
        out.write('>')
        _display_xml_table_elem(s[key], first=True, out=out)
        out.write('</script>')
    else:
        out.write('/>')


def _display_xml_host(h, out=sys.stdout):
    out.write('<host')
    for k in ["timedout", "timeoutcounter"]:
        if k in h:
            out.write(' %s=%s' % (k, saxutils.quoteattr(h[k])))
    for k in ["starttime", "endtime"]:
        if k in h:
            out.write(' %s=%s' % (k, saxutils.quoteattr(h[k].strftime('%s'))))
    out.write('>')
    if 'state' in h:
        out.write('<status state="%s"' % h['state'])
        for k in ["reason", "reason_ttl"]:
            kk = "state_%s" % k
            if kk in h:
                out.write(' %s="%s"' % (k, h[kk]))
        out.write('/>')
    out.write('\n')
    if 'addr' in h:
        out.write('<address addr="%s" addrtype="ipv4"/>\n' %
                  utils.force_int2ip(h['addr']))
    for t in h.get('addresses', []):
        for a in h['addresses'][t]:
            out.write('<address addr="%s" addrtype="%s"/>\n' % (a, t))
    if 'hostnames' in h:
        out.write('<hostnames>\n')
        for hostname in h['hostnames']:
            out.write('<hostname')
            for k in ['name', 'type']:
                if k in hostname:
                    out.write(' %s="%s"' % (k, hostname[k]))
            out.write('/>\n')
        out.write('</hostnames>\n')
    out.write('<ports>')
    for state, counts in viewitems(h.get('extraports', {})):
        out.write('<extraports state="%s" count="%d">\n' % (
            state, counts['total']
        ))
        for reason, count in viewitems(counts['reasons']):
            out.write('<extrareasons reason="%s" count="%d"/>\n' % (
                reason, count
            ))
        out.write('</extraports>\n')
    for p in h.get('ports', []):
        if p.get('port') == -1:
            h['scripts'] = p['scripts']
            continue
        out.write('<port')
        if 'protocol' in p:
            out.write(' protocol="%s"' % p['protocol'])
        if 'port' in p:
            out.write(' portid="%s"' % p['port'])
        out.write('><state')
        for k in ['state', 'reason', 'reason_ttl']:
            kk = 'state_%s' % k
            if kk in p:
                out.write(' %s=%s' % (k, saxutils.quoteattr(str(p[kk]))))
        out.write('/>')
        if 'service_name' in p:
            out.write('<service name="%s"' % p['service_name'])
            for k in ['servicefp', 'product', 'version', 'extrainfo',
                      'ostype', 'method', 'conf']:
                kk = "service_%s" % k
                if kk in p:
                    if isinstance(p[kk], basestring):
                        out.write(' %s=%s' % (
                            k, saxutils.quoteattr(p[kk])
                        ))
                    else:
                        out.write(' %s="%s"' % (k, p[kk]))
            # TODO: CPE
            out.write('></service>')
        for s in p.get('scripts', []):
            _display_xml_script(s, out=out)
        out.write('</port>\n')
    out.write('</ports>\n')
    if 'scripts' in h:
        out.write('<hostscript>')
        for s in h['scripts']:
            _display_xml_script(s, out=out)
        out.write('</hostscript>')
    for trace in h.get('traces', []):
        out.write('<trace')
        if 'port' in trace:
            out.write(' port=%s' % (saxutils.quoteattr(str(trace['port']))))
        if 'protocol' in trace:
            out.write(' proto=%s' % (saxutils.quoteattr(trace['protocol'])))
        out.write('>\n')
        for hop in sorted(trace.get('hops', []),
                          key=lambda hop: hop['ttl']):
            out.write('<hop')
            if 'ttl' in hop:
                out.write(' ttl=%s' % (
                    saxutils.quoteattr(str(hop['ttl']))
                ))
            if 'ipaddr' in hop:
                out.write(' ipaddr=%s' % (
                    saxutils.quoteattr(utils.int2ip(hop['ipaddr']))
                ))
            if 'rtt' in hop:
                out.write(' rtt=%s' % (
                    saxutils.quoteattr('%.2f' % hop['rtt']
                                       if isinstance(hop['rtt'], float) else
                                       hop['rtt'])
                ))
            if 'host' in hop:
                out.write(' host=%s' % (
                    saxutils.quoteattr(hop['host'])
                ))
            out.write('/>\n')
        out.write('</trace>\n')
    out.write('</host>\n')


def _display_xml_epilogue(out=sys.stdout):
    out.write('</nmaprun>\n')


def _displayhost_csv(fields, separator, nastr, dic, out=sys.stdout):
    out.write('\n'.join(separator.join(elt for elt in line)
                        for line in utils.doc2csv(dic, fields, nastr=nastr)))
    out.write('\n')


def displayfunction_honeyd(cur):
    _display_honeyd_preamble(sys.stdout)
    honeyd_routes = {}
    honeyd_entries = set()
    for h in cur:
        honeyd_routes, honeyd_entries = _display_honeyd_conf(
            h,
            honeyd_routes,
            honeyd_entries,
            sys.stdout
        )
    _display_honeyd_epilogue(honeyd_routes, honeyd_entries, sys.stdout)


def displayfunction_nmapxml(cur):
    _display_xml_preamble(out=sys.stdout)
    _display_xml_scan({}, out=sys.stdout)
    for h in cur:
        _display_xml_host(h, out=sys.stdout)
    _display_xml_epilogue(out=sys.stdout)


def displayfunction_explain(cur, db):
    sys.stdout.write(db.explain(cur, indent=4) + '\n')


def displayfunction_remove(cur, db):
    for h in cur:
        db.remove(h)


def displayfunction_graphroute(cur, arg, gr_include, gr_dont_reset):
    graph, entry_nodes = graphroute.buildgraph(
        cur,
        include_last_hop=gr_include == "last-hop",
        include_target=gr_include == "target",
    )
    if arg == "dot":
        if arg == "AS":
            def cluster(ipaddr):
                res = db.db.data.as_byip(ipaddr)
                if res is None:
                    return
                return (res['as_num'],
                        "%(as_num)d\n[%(as_name)s]" % res)
        elif arg == "Country":
            def cluster(ipaddr):
                res = db.db.data.country_byip(ipaddr)
                if res is None:
                    return
                return (res['country_code'],
                        "%(country_code)s - %(country_name)s" % res)
        else:
            cluster = None
        graphroute.writedotgraph(graph, sys.stdout,
                                 cluster=cluster)
    elif arg == "rtgraph3d":
        g = graphroute.display3dgraph(
            graph,
            reset_world=not gr_dont_reset
        )
        for n in entry_nodes:
            g.glow(utils.int2ip(n))


def displayfunction_csv(cur, arg, csv_sep, csv_na_str, add_infos):
    fields = {
        "ports": OrderedDict([
            ["addr", utils.int2ip],
            ["ports", OrderedDict([
                ["port", str],
                ["state_state", True]])]]),
        "hops": OrderedDict([
            ["addr", utils.int2ip],
            ["traces", OrderedDict([
                ["hops", OrderedDict([
                    ["ipaddr", utils.int2ip],
                    ["ttl", str],
                    ["rtt", lambda x: (csv_na_str if x == '--'
                                       else str(x))],
                ])]
            ])]
        ]),
        "rtt": OrderedDict([
            ["addr", utils.int2ip],
            ["traces", OrderedDict([
                ["hops", OrderedDict([
                    ["rtt", lambda x: (csv_na_str if x == '--'
                                       else str(x))],
                ])]
            ])]
        ]),
    }.get(arg)
    if fields is None:
        # active_parser.error("Invalid choice for --csv.")
        sys.stderr.write("Invalid choice for --csv.\n")
        return
    if add_infos:
        fields['infos'] = OrderedDict([
            ["country_code", True],
            ["city", True],
            ["as_num", str],
        ])
    sys.stdout.write(csv_sep.join(utils.fields2csv_head(fields)))
    sys.stdout.write('\n')
    for h in cur:
        _displayhost_csv(fields, csv_sep, csv_na_str, h, out=sys.stdout)


def displayfunction_json(cur, db, no_screenshots=False):
    if os.isatty(sys.stdout.fileno()):
        indent = 4
    else:
        indent = None
    for h in cur:
        for fld in ['_id', 'scanid']:
            try:
                del h[fld]
            except KeyError:
                pass
        for port in h.get('ports', []):
            if no_screenshots:
                for fname in ['screenshot', 'screendata']:
                    if fname in port:
                        del port[fname]
            elif 'screendata' in port:
                port['screendata'] = utils.encode_b64(
                    db.from_binary(port['screendata'])
                )
            for script in port.get('scripts', []):
                if 'masscan' in script and 'raw' in script['masscan']:
                    script['masscan']['raw'] = utils.encode_b64(
                        db.from_binary(
                            script['masscan']['raw']
                        )
                    )
        print(json.dumps(h, indent=indent,
                         default=db.serialize))


def display_short(db, flt, srt, lmt, skp):
    for val in db.distinct("addr", flt=flt, sort=srt, limit=lmt, skip=skp):
        sys.stdout.write(utils.force_int2ip(val) + '\n')


def display_distinct(db, arg, flt, srt, lmt, skp):
    for val in db.distinct(arg, flt=flt, sort=srt, limit=lmt, skip=skp):
        sys.stdout.write(str(val) + '\n')
