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

def _scriptoutput(record):
    out = []
    for script in record.get('scripts', []):
        if 'output' in script:
            scriptout = [line for line in
                         (line.strip() for line in
                          script['output'].split('\n')) if line]
            if len(scriptout) == 0:
                scriptout = ""
            elif len(scriptout) == 1:
                scriptout = " " + scriptout[0]
            else:
                scriptout = "\n\t\t\t%s" % "\n\t\t\t".join(scriptout)
        else:
            scriptout = ""
        out.append('\t\t%s:%s\n' % (script['id'], scriptout))
    return out

def displayhost(record, showscripts=True, showtraceroute=True, showos=True,
                out=sys.stdout):
    """Displays (on `out`, by default `sys.stdout`) the Nmap scan
    result contained in `record`.

    """
    try:
        line = "Host %s" % utils.int2ip(record['addr'])
    except:
        line = "Host %s" % record['addr']
    if record.get('hostnames'):
        line += " (%s)" % '/'.join(x['name'] for x in record['hostnames'])
    if 'source' in record:
        line += ' from %s' % record['source']
    if record.get('categories'):
        line += ' (%s)' % ', '.join(record['categories'])
    if 'state' in record:
        line += ' (%s' % record['state']
        if 'state_reason' in record:
            line += ': %s' % record['state_reason']
        line += ')\n'
    out.write(line)
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
    for state, counts in record.get('extraports', {}).iteritems():
        out.write("\t%d ports %s (%s)\n" %
                  (counts["total"], state,
                   ", ".join("%d %s" % (count, reason)
                             for reason, count in counts["reasons"].iteritems()
                             if reason != "total")))
    ports = record.get('ports', [])
    ports.sort(key=lambda x: (x.get('protocol'), x['port']))
    for port in ports:
        if port.get('port') == -1:
            record['scripts'] = port['scripts']
            continue
        if 'state_reason' in port:
            reason = " (%s)" % ', '.join(
                [port['state_reason']] +
                ["%s=%s" % (field[13:], value)
                 for field, value in port.iteritems()
                 if field.startswith('state_reason_')]
            )
        else:
            reason = ""
        if 'service_name' in port:
            srv = port['service_name']
            if 'service_method' in port:
                srv += ' (%s)' % port['service_method']
            for field in ['service_product', 'service_version',
                          'service_extrainfo', 'service_ostype',
                          'service_hostname']:
                if field in port:
                    srv += ' %s' % port[field]
        else:
            srv = ""
        out.write("\t%-10s%-8s%-22s%s\n" %
                  ('%s/%d' % (port.get('protocol'), port['port']),
                   port['state_state'], reason, srv))
        if showscripts:
            out.writelines(_scriptoutput(port))
    if showscripts:
        scripts = _scriptoutput(record)
        if scripts:
            out.write('\tHost scripts:\n')
            out.writelines(scripts)
    if showtraceroute and record.get('traces'):
        for trace in record['traces']:
            proto = trace['protocol']
            if proto in ['tcp', 'udp']:
                proto += '/%d' % trace['port']
            out.write('\tTraceroute (using %s)\n' % proto)
            hops = trace['hops']
            hops.sort(key=lambda hop: hop['ttl'])
            for hop in hops:
                try:
                    out.write('\t\t%3s %15s %7s\n' %
                              (hop['ttl'], utils.int2ip(hop['ipaddr']),
                               hop['rtt']))
                except:
                    out.write('\t\t%3s %15s %7s\n' %
                              (hop['ttl'], hop['ipaddr'], hop['rtt']))
    if showos and record.get('os', {}).get('osclass'):
        osclasses = record['os']['osclass']
        maxacc = str(max(int(x['accuracy']) for x in osclasses))
        osclasses = [osclass for osclass in osclasses
                     if osclass['accuracy'] == maxacc]
        out.write('\tOS fingerprint\n')
        for osclass in osclasses:
            out.write(
                '\t\t%(osfamily)s / %(type)s / %(vendor)s / '
                'accuracy = %(accuracy)s\n' % osclass)

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
