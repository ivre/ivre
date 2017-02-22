#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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

from ivre import utils, db, graphroute, config, xmlnmap, nmapout

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import os
from datetime import datetime
from xml.sax import saxutils
try:
    from collections import OrderedDict
except ImportError:
    # fallback to dict for Python 2.6
    OrderedDict = dict


HONEYD_ACTION_FROM_NMAP_STATE = {
    'resets': 'reset',
    'no-responses': 'block',
}
HONEYD_DEFAULT_ACTION = 'block'
HONEYD_STD_SCRIPTS_BASE_PATH = '/usr/share/honeyd'
HONEYD_SSL_CMD = 'honeydssl --cert-subject %(subject)s -- %(command)s'


def display_honeyd_preamble(out=sys.stdout):
    out.write("""create default
set default default tcp action block
set default default udp action block
set default default icmp action block

""")


def getscript(port, sname):
    for s in port.get('scripts', []):
        if s['id'] == sname:
            return s
    return None


def nmap_port2honeyd_action(port):
    if port['state_state'] == 'closed':
        return 'reset'
    elif port['state_state'] != 'open':
        return 'block'
    if 'service_tunnel' in port and port['service_tunnel'] == 'ssl':
        sslrelay = True
    else:
        sslrelay = False
    if 'service_name' in port:
        if port['service_name'] == 'tcpwrapped':
            return '"true"'
        elif port['service_name'] == 'ssh':
            s = getscript(port, 'banner')
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


def display_honeyd_conf(host, honeyd_routes, honeyd_entries, out=sys.stdout):
    addr = utils.int2ip(host['addr'])
    hname = "host_%s" % addr.replace('.', '_')
    out.write("create %s\n" % hname)
    defaction = HONEYD_DEFAULT_ACTION
    if 'extraports' in host:
        extra = host['extraports']
        defaction = max(
            max(extra.itervalues(),
                key=lambda state: state['total'])['reasons'].iteritems(),
            key=lambda reason: reason[1],
        )[0]
        defaction = HONEYD_ACTION_FROM_NMAP_STATE.get(defaction)
    out.write('set %s default tcp action %s\n' % (hname, defaction))
    for p in host.get('ports', []):
        try:
            out.write('add %s %s port %d %s\n' % (
                hname, p['protocol'], p['port'],
                nmap_port2honeyd_action(p),
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
                        'mean': (route['mean'] * route['count']
                                 + latency) / (route['count'] + 1),
                        'targets': route['targets'],
                    }
                curhop = t
    out.write('bind %s %s\n\n' % (addr, hname))
    return honeyd_routes, honeyd_entries


def display_honeyd_epilogue(honeyd_routes, honeyd_entries, out=sys.stdout):
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


def display_xml_preamble(out=sys.stdout):
    out.write('<?xml version="1.0"?>\n'
              '<?xml-stylesheet '
              'href="file:///usr/local/bin/../share/nmap/nmap.xsl" '
              'type="text/xsl"?>\n')


def display_xml_scan(scan, out=sys.stdout):
    if 'scaninfos' in scan and scan['scaninfos']:
        for k in scan['scaninfos'][0]:
            scan['scaninfo.%s' % k] = scan['scaninfos'][0][k]
        del scan['scaninfos']
    for k in ['version', 'start', 'startstr', 'args', 'scanner',
              'xmloutputversion', 'scaninfo.type', 'scaninfo.protocol',
              'scaninfo.numservices', 'scaninfo.services']:
        if k not in scan:
            scan[k] = ''
        elif isinstance(scan[k], (str, unicode)):
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


def display_xml_table_elem(doc, first=False, name=None, out=sys.stdout):
    if first:
        assert name is None
    name = '' if name is None else ' key=%s' % saxutils.quoteattr(name)
    if isinstance(doc, list):
        if not first:
            out.write('<table%s>\n' % name)
        for subdoc in doc:
            display_xml_table_elem(subdoc, out=out)
        if not first:
            out.write('</table>\n')
    elif isinstance(doc, dict):
        if not first:
            out.write('<table%s>\n' % name)
        for key, subdoc in doc.iteritems():
            display_xml_table_elem(subdoc, name=key, out=out)
        if not first:
            out.write('</table>\n')
    else:
        out.write('<elem%s>%s</elem>\n' % (name,
                                           saxutils.escape(
                                               str(doc),
                                               entities={'\n': '&#10;'},
                                           )))


def display_xml_script(s, out=sys.stdout):
    out.write('<script id=%s' % saxutils.quoteattr(s['id']))
    if 'output' in s:
        out.write(' output=%s' % saxutils.quoteattr(s['output']))
    key = xmlnmap.ALIASES_TABLE_ELEMS.get(s['id'], s['id'])
    if key in s:
        out.write('>')
        display_xml_table_elem(s[key], first=True, out=out)
        out.write('</script>')
    else:
        out.write('/>')


def display_xml_host(h, out=sys.stdout):
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
        try:
            out.write('<address addr="%s" addrtype="ipv4"/>\n' %
                      utils.int2ip(h['addr']))
        except:
            out.write('<address addr="%s" addrtype="ipv4"/>\n' % h['addr'])
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
    for state, counts in h.get('extraports', {}).iteritems():
        out.write('<extraports state="%s" count="%d">\n' % (
            state, counts['total']
        ))
        for reason, count in counts['reasons'].iteritems():
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
                    if type(p[kk]) in [str, unicode]:
                        out.write(' %s=%s' % (
                            k, saxutils.quoteattr(p[kk])
                        ))
                    else:
                        out.write(' %s="%s"' % (k, p[kk]))
            # TODO: CPE
            out.write('></service>')
        for s in p.get('scripts', []):
            display_xml_script(s, out=out)
        out.write('</port>\n')
    out.write('</ports>\n')
    if 'scripts' in h:
        out.write('<hostscript>')
        for s in h['scripts']:
            display_xml_script(s, out=out)
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
                                       if type(hop['rtt']) is float else
                                       hop['rtt'])
                ))
            if 'host' in hop:
                out.write(' host=%s' % (
                    saxutils.quoteattr(hop['host'])
                ))
            out.write('/>\n')
        out.write('</trace>\n')
    out.write('</host>\n')


def display_xml_epilogue(out=sys.stdout):
    out.write('</nmaprun>\n')


def displayhost_csv(fields, separator, nastr, dic, out=sys.stdout):
    out.write('\n'.join(separator.join(elt for elt in line)
                        for line in utils.doc2csv(dic, fields, nastr=nastr)))
    out.write('\n')

def main():
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='Access and query the active scans database.',
            parents=[db.db.nmap.argparser])
        USING_ARGPARSE = True
    except ImportError:
        import optparse
        parser = optparse.OptionParser(
            description='Access and query the active scans database.')
        for args, kargs in db.db.nmap.argparser.args:
            parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
        USING_ARGPARSE = False
    parser.add_argument('--init', '--purgedb', action='store_true',
                        help='Purge or create and initialize the database.')
    parser.add_argument('--ensure-indexes', action='store_true',
                        help='Create missing indexes (will lock the database).')
    parser.add_argument('--short', action='store_true',
                        help='Output only IP addresses, one per line.')
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON documents.')
    parser.add_argument('--no-screenshots', action='store_true',
                        help='When used with --json, do not output '
                        'screenshots data.')
    parser.add_argument('--honeyd', action='store_true',
                        help='Output results as a honeyd config file.')
    parser.add_argument('--nmap-xml', action='store_true',
                        help='Output results as a nmap XML output file.')
    parser.add_argument(
        '--graphroute',
        choices=["dot", "rtgraph3d"] if graphroute.HAVE_DBUS else ["dot"],
        help='Create a graph from traceroute results. '
        'dot: output result as Graphviz "dot" format to stdout.'
        '%s' % (" rtgraph3d: send results to rtgraph3d."
                if graphroute.HAVE_DBUS else "")
    )
    parser.add_argument('--graphroute-cluster', choices=['AS', 'Country'],
                        help='Cluster IP according to the specified criteria'
                        '(only for --graphroute dot)')
    if graphroute.HAVE_DBUS:
        parser.add_argument('--graphroute-dont-reset', action='store_true',
                            help='Do NOT reset graph (only for '
                            '--graphroute rtgraph3d)')
    parser.add_argument('--graphroute-include', choices=['last-hop', 'target'],
                        help='How far should graphroute go? Default if to '
                        'exclude the last hop and the target for each result.')
    parser.add_argument('--count', action='store_true',
                        help='Count matched results.')
    parser.add_argument('--explain', action='store_true',
                        help='MongoDB specific: .explain() the query.')
    parser.add_argument('--distinct', metavar='FIELD',
                        help='Output only unique FIELD part of the '
                        'results, one per line.')
    parser.add_argument('--top', metavar='FIELD / ~FIELD',
                        help='Output most common (least common: ~) values for '
                        'FIELD, by default 10, use --limit to change that, '
                        '--limit 0 means unlimited.')
    parser.add_argument('--delete', action='store_true',
                        help='DELETE the matched results instead of '
                        'displaying them.')
    parser.add_argument('--move-to-archives', action='store_true',
                        help='ARCHIVE the matched results instead of '
                        'displaying them (i.e., move the results to '
                        'the archive collections).')
    parser.add_argument('--move-from-archives', action='store_true',
                        help='UNARCHIVE the matched results instead of '
                        'displaying them (i.e., move the results from '
                        'the archive collections to the "fresh" results '
                        'collections).')
    parser.add_argument('--update-schema', action='store_true',
                        help='update (host) schema. Use with --version to '
                        'specify your current version and run twice, once '
                        'with --archive.')
    parser.add_argument('--csv', metavar='TYPE',
                        help='Output result as a CSV file',
                        choices=['ports', 'hops'])
    parser.add_argument('--csv-separator', metavar='SEPARATOR',
                        default=",",
                        help='Select separator for --csv output')
    parser.add_argument('--csv-add-infos', action='store_true',
                        help="Include country_code and as_number"
                        "fields to CSV file")
    parser.add_argument('--csv-na-str', default="NA",
                        help='String to use for "Not Applicable" value '
                        '(defaults to "NA")')
    if USING_ARGPARSE:
        parser.add_argument('--sort', metavar='FIELD / ~FIELD', nargs='+',
                            help='Sort results according to FIELD; use ~FIELD '
                            'to reverse sort order.')
    else:
        parser.add_argument('--sort', metavar='FIELD / ~FIELD',
                            help='Sort results according to FIELD; use ~FIELD '
                            'to reverse sort order.')
    parser.add_argument('--limit', type=int,
                        help='Ouput at most LIMIT results.')
    parser.add_argument('--skip', type=int,
                        help='Skip first SKIP results.')
    args = parser.parse_args()

    out = sys.stdout

    hostfilter = db.db.nmap.parse_args(args)
    sortkeys = []
    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will remove any scan result in your database. '
                'Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() != 'y':
                sys.exit(-1)
        db.db.nmap.init()
        sys.exit(0)
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will lock your database. '
                'Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() != 'y':
                sys.exit(-1)
        db.db.nmap.ensure_indexes()
        sys.exit(0)
    if args.top is not None:
        field, least = ((args.top[1:], True)
                        if args.top[:1] in '!-~' else
                        (args.top, False))
        topnbr = {0: None, None: 10}.get(args.limit, args.limit)
        for entry in db.db.nmap.topvalues(field, flt=hostfilter,
                                          topnbr=topnbr,
                                          archive=args.archives):
            if isinstance(entry['_id'], (list, tuple)):
                if entry['_id']:
                    entry['_id'] = ' / '.join(str(elt) for elt in entry['_id'])
                else:
                    entry['_id'] = "None"
            print "%(_id)s: %(count)d" % entry
        sys.exit(0)
    if args.sort is not None:
        sortkeys = [(field[1:], -1) if field.startswith('~') else (field, 1)
                    for field in args.sort]
    if args.short:
        for val in db.db.nmap.distinct("addr", flt=hostfilter, sort=sortkeys,
                                       limit=args.limit, skip=args.skip,
                                       archive=args.archives):
            try:
                out.write(utils.int2ip(val) + '\n')
            except:
                out.write(str(val) + '\n')
        sys.exit(0)
    elif args.distinct is not None:
        for val in db.db.nmap.distinct(args.distinct, flt=hostfilter,
                                       sort=sortkeys, limit=args.limit,
                                       skip=args.skip, archive=args.archives):
            out.write(str(val) + '\n')
        sys.exit(0)
    if args.json:
        import json

        def displayfunction(x):
            if os.isatty(sys.stdout.fileno()):
                indent = 4
            else:
                indent = None
            for h in x:
                for fld in ['_id', 'scanid']:
                    try:
                        del h[fld]
                    except KeyError:
                        pass
                for port in h.get('ports', []):
                    if args.no_screenshots:
                        for fname in ['screenshot', 'screendata']:
                            if fname in port:
                                del port[fname]
                    elif 'screendata' in port:
                        port['screendata'] = port['screendata'].encode(
                            'base64')
                    for script in port.get('scripts', []):
                        if 'masscan' in script and 'raw' in script['masscan']:
                            script['masscan']['raw'] = script['masscan'][
                                'raw'].encode('base64')
                print json.dumps(h, indent=indent,
                                 default=db.db.nmap.serialize)
    elif args.honeyd:
        def displayfunction(x):
            display_honeyd_preamble(out)
            honeyd_routes = {}
            honeyd_entries = set()
            for h in x:
                honeyd_routes, honeyd_entries = display_honeyd_conf(
                    h,
                    honeyd_routes,
                    honeyd_entries,
                    out
                )
            display_honeyd_epilogue(honeyd_routes, honeyd_entries, out)
    elif args.nmap_xml:
        def displayfunction(x):
            display_xml_preamble(out=out)
            if x.count() == 1 and not isinstance(x[0]['scanid'], list):
                scan = db.db.nmap.getscan(x[0]['scanid'], archive=args.archives)
                if 'scaninfos' in scan and scan['scaninfos']:
                    for k in scan['scaninfos'][0]:
                        scan['scaninfo.%s' % k] = scan['scaninfos'][0][k]
                    del scan['scaninfos']
            else:
                scan = {}
            display_xml_scan(scan, out=out)
            for h in x:
                display_xml_host(h, out=out)
            display_xml_epilogue(out=out)
    elif args.graphroute is not None:
        def displayfunction(cursor):
            graph, entry_nodes = graphroute.buildgraph(
                cursor,
                include_last_hop=args.graphroute_include == "last-hop",
                include_target=args.graphroute_include == "target",
            )
            if args.graphroute == "dot":
                if args.graphroute_cluster == "AS":
                    def cluster(ipaddr):
                        res = db.db.data.as_byip(ipaddr)
                        if res is None:
                            return
                        return (res['as_num'],
                                "%(as_num)d\n[%(as_name)s]" % res)
                elif args.graphroute_cluster == "Country":
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
            elif args.graphroute == "rtgraph3d":
                g = graphroute.display3dgraph(
                    graph,
                    reset_world=not args.graphroute_dont_reset
                )
                for n in entry_nodes:
                    g.glow(utils.int2ip(n))
    elif args.explain:
        def displayfunction(x):
            out.write(db.db.nmap.explain(x, indent=4) + '\n')
    elif args.delete:
        def displayfunction(x):
            for h in x:
                db.db.nmap.remove(h, archive=args.archives)
    elif args.move_to_archives:
        args.archives = False
        def displayfunction(x):
            for h in x:
                db.db.nmap.archive(h)
    elif args.move_from_archives:
        args.archives = True
        def displayfunction(x):
            for h in x:
                db.db.nmap.archive(h, unarchive=True)
    elif args.csv is not None:
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
                        ["rtt", lambda x: (args.csv_na_str if x == '--'
                                           else str(x))],
                    ])]
                ])]
            ]),
            "rtt": OrderedDict([
                ["addr", utils.int2ip],
                ["traces", OrderedDict([
                    ["hops", OrderedDict([
                        ["rtt", lambda x: (args.csv_na_str if x == '--'
                                           else str(x))],
                    ])]
                ])]
            ]),
        }.get(args.csv)
        if fields is None:
            parser.error("Invalid choice for --csv.")
        if args.csv_add_infos:
            fields['infos'] = OrderedDict([
                ["country_code", True],
                ["city", True],
                ["as_num", str],
            ])
        def displayfunction(x):
            out.write(args.csv_separator.join(utils.fields2csv_head(fields)))
            out.write('\n')
            for h in x:
                displayhost_csv(fields, args.csv_separator, args.csv_na_str,
                                h, out=out)
    else:
        def displayfunction(cursor):
            nmapout.displayhosts(cursor, out=out)

    if args.update_schema:
        db.db.nmap.migrate_schema(args.archives, args.version)
    elif args.count:
        out.write(
            str(db.db.nmap.count(hostfilter, archive=args.archives)) + '\n'
        )
    else:
        kargs = {"archive": args.archives}
        if args.limit is not None:
            kargs["limit"] = args.limit
        if args.skip is not None:
            kargs["skip"] = args.skip
        if sortkeys:
            kargs["sort"] = sortkeys
        cursor = db.db.nmap.get(hostfilter, **kargs)
        displayfunction(cursor)
        sys.exit(0)
