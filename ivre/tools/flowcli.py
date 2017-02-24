#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
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

from ivre.db import db
from ivre import utils

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import os

try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

DESCRIPTION = 'Access and query the flows database. See doc/FLOW.md for more ' \
              'information.'

def main():
    try:
        import argparse
        parser = argparse.ArgumentParser(description=DESCRIPTION)
        USING_ARGPARSE = True
    except ImportError:
        import optparse
        parser = optparse.OptionParser(description=DESCRIPTION)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
        USING_ARGPARSE = False
    parser.add_argument('--init', '--purgedb', action='store_true',
                        help='Purge or create and initialize the database.')
    parser.add_argument('--ensure-indexes', action='store_true',
                        help='Create missing indexes (will lock the database).')
    parser.add_argument('--node-filters', '-n', nargs="+",
                        help='Filter the results with a list of ivre specific '
                             'node textual filters (see WebUI doc in FLOW.md).')
    parser.add_argument('--flow-filters', '-f', nargs="+",
                        help='Filter the results with a list of ivre specific '
                             'flow textual filters (see WebUI doc in FLOW.md).')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Outputs the full json records of results.')
    parser.add_argument('--count', '-c', action='store_true',
                        help='Only return the count of the results.')
    parser.add_argument('--limit', '-l', type=int,
                        help='Ouput at most LIMIT results.')
    parser.add_argument('--skip', type=int, default=0,
                        help='Skip first SKIP results.')
    parser.add_argument('--orderby', '-o', 
                        help='Order of results ("src", "dst" or "flow")')
    parser.add_argument('--separator', '-s', help="Separator string.")
    parser.add_argument('--top', '-t', nargs="+",
                        help='Top flows for a given set of fields, e.g. '
                        '"--top src.addr dport".')
    parser.add_argument('--collect', '-C', nargs="+",
                        help='When using --top, also collect these properties.')
    parser.add_argument('--sum', '-S', nargs="+",
                        help='When using --top, sum on these properties to '
                        'order the result.')
    parser.add_argument('--mode', '-m',
                        help="Query special mode (flow_map, talk_map...)")
    parser.add_argument('--timeline', '-T', action="store_true",
                        help='Retrieves the timeline of each flow')
    parser.add_argument('--flow-daily', action="store_true",
                        help="Flow count per times of the day")
    parser.add_argument('--plot', action="store_true",
                        help="Plot data when possible (requires matplotlib).")
    parser.add_argument('--fields', nargs='+',
                        help="Display these fields for each entry.")
    args = parser.parse_args()

    out = sys.stdout

    if args.plot and plt is None:
        utils.LOGGING.critical("Matplotlib is required for --plot")
        sys.exit(-1)

    if args.init:
        if os.isatty(sys.stdin.fileno()):
            out.write(
                'This will remove any scan result in your database. '
                'Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() != 'y':
                sys.exit(-1)
        db.flow.init()
        sys.exit(0)

    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            out.write(
                'This will lock your database. '
                'Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() != 'y':
                sys.exit(-1)
        db.flow.ensure_indexes()
        sys.exit(0)

    filters = {"nodes": args.node_filters or [],
               "edges": args.flow_filters or []}

    query = db.flow.from_filters(filters, limit=args.limit, skip=args.skip,
                                 orderby=args.orderby, mode=args.mode,
                                 timeline=args.timeline)
    sep = args.separator or ' | '
    coma = ';' if args.separator else '; '
    coma2 = ',' if args.separator else ', '
    if args.count:
        count = db.flow.count(query)
        out.write('%(clients)d clients\n%(servers)d servers\n'
                  '%(flows)d flows\n' % count)

    elif args.top:
        top = db.flow.top(query, args.top, args.collect, args.sum)
        for rec in top:
            sys.stdout.write("%s%s%s%s%s\n" % (
                coma.join(map(str, rec["fields"])),
                sep,
                rec["count"],
                sep,
                coma.join(str(coma2.join(map(str, elt)))
                          for elt in rec["collected"])
                if rec["collected"] else ""
            ))

    elif args.flow_daily:
        cur_flow = None
        # FIXME? fully in-memory
        if args.plot:
            plot_data = {}
        for rec in db.flow.flow_daily(query):
            out.write(sep.join([rec["flow"],
                                rec["time_in_day"].strftime("%T.%f"),
                                str(rec["count"])]))
            out.write("\n")

            if args.plot:
                plot_data.setdefault(rec["flow"], [[], []])
                plot_data[rec["flow"]][0].append(rec["time_in_day"])
                plot_data[rec["flow"]][1].append(rec["count"])
        for flow, points in plot_data.iteritems():
            plt.plot(points[0], points[1], label=flow)
        plt.legend(loc='best')
        plt.show()

    else:
        fmt = '%%s%s%%s%s%%s' % (sep, sep)
        node_width = len('XXX.XXX.XXX.XXX')
        flow_width = len('tcp/XXXXX')
        for res in db.flow.to_iter(query):
            if args.json:
                out.write('%s\n' % res)
            else:
                elts = {}
                for elt in ["src", "flow", "dst"]:
                    elts[elt] = res[elt]['label']
                    if args.fields:
                        elts[elt] = "%s%s%s" % (
                            elts[elt],
                            coma,
                            coma.join(
                                str(res[elt]['data'].get(field, ""))
                                for field in args.fields
                            )
                        )
                src, flow, dst = elts["src"], elts["flow"], elts["dst"]
                node_width = max(node_width, len(src), len(dst))
                flow_width = max(flow_width, len(flow))
                if not args.separator:
                    fmt = ('%%-%ds%s%%-%ds%s%%-%ds' %
                           (node_width, sep, flow_width, sep, node_width))
                out.write(fmt % (src, flow, dst))
                if args.timeline:
                    out.write(sep)
                    out.write(coma.join(
                        map(str, sorted(res['flow']['data']['meta']['times'])))
                    )
                out.write('\n')
