#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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

from ivre import db
import math
import matplotlib
import matplotlib.pyplot
# from mpl_toolkits.mplot3d import Axes3D
from mpl_toolkits.mplot3d import axes3d, Axes3D


def graphhost(ap):
    if 'ports' not in ap:
        return [], []
    hh, pp = [], []
    an = ap['addr']
    ap = ap['ports']
    for p in ap:
        pn = p['port']
        if p.get('state_state') == 'open':
            hh.append(an)
            pp.append(pn)
    return hh, pp


def getgraph(flt=db.db.nmap.flt_empty):
    h, p = [], []
    allhosts = db.db.nmap.get(flt)
    for ap in allhosts:
        hh, pp = graphhost(ap)
        h += hh
        p += pp
    return h, p


def graph3d(mainflt=db.db.nmap.flt_empty, alertflt=None):
    h, p = getgraph(flt=mainflt)
    fig = matplotlib.pyplot.figure()
    if matplotlib.__version__.startswith('0.99'):
        ax = Axes3D(fig)
    else:
        ax = fig.add_subplot(111, projection='3d')
    ax.plot([x / 65535 for x in h], [x % 65535 for x in h],
            [math.log(x, 10) for x in p], '.')
    if alertflt is not None:
        h, p = getgraph(flt=db.db.nmap.flt_and(mainflt, alertflt))
        if h:
            ax.plot([x / 65535 for x in h], [x % 65535 for x in h],
                    [math.log(x, 10) for x in p], '.', c='r')
    matplotlib.pyplot.show()


def graph2d(mainflt=db.db.nmap.flt_empty, alertflt=None):
    h, p = getgraph(flt=mainflt)
    fig = matplotlib.pyplot.figure()
    ax = fig.add_subplot(111)
    ax.semilogy(h, p, '.')
    if alertflt is not None:
        h, p = getgraph(flt=db.db.nmap.flt_and(mainflt, alertflt))
        if h:
            ax.semilogy(h, p, '.', c='r')
    matplotlib.pyplot.show()

def main():
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='Plot scan results.',
            parents=[db.db.nmap.argparser])
    except ImportError:
        import optparse
        parser = optparse.OptionParser(description='Plot scan results.')
        for args, kargs in db.db.nmap.argparser.args:
            parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
    parser.add_argument('--2d', '-2', action='store_const',
                        dest='graph',
                        const=graph2d,
                        default=graph3d)
    parser.add_argument('--3d', '-3', action='store_const',
                        dest='graph',
                        const=graph3d)
    parser.add_argument('--alert-445', action='store_const',
                        dest='alertflt',
                        const=db.db.nmap.searchxp445(),
                        default=db.db.nmap.searchhttpauth())
    parser.add_argument('--alert-nfs', action='store_const',
                        dest='alertflt',
                        const=db.db.nmap.searchnfs())
    args = parser.parse_args()
    args.graph(mainflt=db.db.nmap.parse_args(args),
               alertflt=args.alertflt)
