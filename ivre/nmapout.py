#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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

"""This sub-module contains function to convert & display Nmap scan
results as they are stored in the database (JSON).

"""

from ivre import utils

import sys
import os
import json

def displayhost(record, showscripts=True, showtraceroute=True, showos=True,
                out=sys.stdout):
    """Displays (on `out`, by default `sys.stdout`) the Nmap scan
    result contained in `record`.

    """
    try:
        h = "Host %s" % utils.int2ip(record['addr'])
    except:
        h = "Host %s" % record['addr']
    if record.get('hostnames'):
        h += " (%s)" % '/'.join(x['name'] for x in record['hostnames'])
    if 'source' in record:
        h += ' from %s' % record['source']
    if record.get('categories'):
        h += ' (%s)' % ', '.join(record['categories'])
    if 'state' in record:
        h += ' (%s' % record['state']
        if 'state_reason' in record:
            h += ': %s' % record['state_reason']
        h += ')\n'
    out.write(h)
    if 'infos' in record:
        infos = record['infos']
        if 'country_code' in infos or 'country_name' in infos:
            out.write("\t%s - %s" % (infos.get('country_code', '?'),
                                     infos.get('country_name', '?')))
            if 'city' in infos:
                out.write(' - %s' % infos['city'])
            out.write('\n')
        if 'as_num' in infos or 'as_name' in infos:
            out.write("\tAS%s - %s\n" % (infos.get('as_num', '?'),
                                         infos.get('as_name', '?')))
    if 'starttime' in record and 'endtime' in record:
        out.write("\tscan %s - %s\n" %
                 (record['starttime'], record['endtime']))
    if 'extraports' in record:
        d = record['extraports']
        for k in d:
            out.write("\t%d ports %s (%s)\n" %
                      (d[k][0], k, ', '.join(['%d %s' % (d[k][1][kk], kk)
                                              for kk in d[k][1].keys()])))
    if 'ports' in record:
        d = record['ports']
        d.sort(key=lambda x: (x.get('protocol'), x['port']))
        for k in d:
            if k.get('port') == 'host':
                record['scripts'] = k['scripts']
                continue
            reason = ""
            if 'state_reason' in k:
                reason = " (%s" % k['state_reason']
                for kk in filter(lambda x: x.startswith('state_reason_'),
                                 k.keys()):
                    reason += ", %s=%s" % (kk[13:], k[kk])
                reason += ')'
            srv = ""
            if 'service_name' in k:
                srv = "" + k['service_name']
                if 'service_method' in k:
                    srv += ' (%s)' % k['service_method']
                for kk in ['service_product', 'service_version',
                           'service_extrainfo', 'service_ostype',
                           'service_hostname']:
                    if kk in k:
                        srv += ' %s' % k[kk]
            out.write("\t%-10s%-8s%-22s%s\n" %
                      ('%s/%d' % (k.get('protocol'), k['port']),
                       k['state_state'], reason, srv))
            if showscripts and k.get('scripts'):
                for s in k['scripts']:
                    if 'output' not in s:
                        out.write('\t\t' + s['id'] + ':\n')
                    else:
                        o = filter(
                            lambda x: x, map(lambda x: x.strip(),
                                             s['output'].split('\n')))
                        if len(o) == 0:
                            out.write('\t\t' + s['id'] + ':\n')
                        elif len(o) == 1:
                            out.write('\t\t' + s['id'] + ': ' + o[0] + '\n')
                        elif len(o) > 1:
                            out.write('\t\t' + s['id'] + ': \n')
                            for oo in o:
                                out.write('\t\t\t' + oo + '\n')
    if showscripts and record.get('scripts'):
        out.write('\tHost scripts:\n')
        for s in record['scripts']:
            if 'output' not in s:
                out.write('\t\t' + s['id'] + ':\n')
            else:
                o = [x.strip() for x in s['output'].split('\n') if x]
                if len(o) == 0:
                    out.write('\t\t' + s['id'] + ':\n')
                elif len(o) == 1:
                    out.write('\t\t' + s['id'] + ': ' + o[0] + '\n')
                elif len(o) > 1:
                    out.write('\t\t' + s['id'] + ': \n')
                    for oo in o:
                        out.write('\t\t\t' + oo + '\n')
    if showtraceroute and record.get('traces'):
        for k in record['traces']:
            proto = k['protocol']
            if proto in ['tcp', 'udp']:
                proto += '/%d' % k['port']
            out.write('\tTraceroute (using %s)\n' % proto)
            hops = k['hops']
            hops.sort(key=lambda x: x['ttl'])
            for i in hops:
                try:
                    out.write('\t\t%3s %15s %7s\n' %
                              (i['ttl'], utils.int2ip(i['ipaddr']),
                               i['rtt']))
                except:
                    out.write('\t\t%3s %15s %7s\n' %
                              (i['ttl'], i['ipaddr'], i['rtt']))
    if showos and record.get('os', {}).get('osclass'):
        o = record['os']['osclass']
        maxacc = str(max([int(x['accuracy']) for x in o]))
        o = filter(lambda x: x['accuracy'] == maxacc, o)
        out.write('\tOS fingerprint\n')
        for oo in o:
            out.write(
                '\t\t%(osfamily)s / %(type)s / %(vendor)s / '
                'accuracy = %(accuracy)s\n' % oo)

def displayhosts(recordsgen, out=sys.stdout, **kargs):
    """Displays (on `out`, by default `sys.stdout`) the Nmap scan
    results generated by `recordsgen`.

    """
    for record in recordsgen:
        displayhost(record, out=out, **kargs)
        if os.isatty(out.fileno()):
            raw_input()
        else:
            out.write('\n')

def displayhosts_json(recordsgen, out=sys.stdout):
    """Displays (on `out`, by default `sys.stdout`) the Nmap scan
    result contained in `record` as JSON.

    """
    out.write(json.dumps(recordsgen, default=utils.serialize))
    out.write('\n')
