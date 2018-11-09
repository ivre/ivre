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

"""Update the database from output of a p0f process"""


import signal
import functools
import subprocess
import os


import ivre.db
import ivre.utils
import ivre.passive


def terminate(signum, _):
    p0fprocess.terminate()


signal.signal(signal.SIGINT, terminate)
signal.signal(signal.SIGTERM, terminate)


def process_file(fname, sensor, bulk_db, bulk_local, mode):
    global p0fprocess
    if fname.lower().startswith('iface:'):
        fname = ['-i', fname[6:]]
    else:
        fname = ['-s', fname]
    if mode is None:
        mode = 'SYN'
    mode = ivre.passive.P0F_MODES[mode]
    recontype = 'P0F2-%s' % mode['name']
    p0fprocess = subprocess.Popen(
        ['p0f', '-q', '-l', '-S', '-ttt'] + fname +
        mode['options'] + [mode['filter']],
        stdout=subprocess.PIPE,
        preexec_fn=os.setpgrp,
    )
    if bulk_db:
        function = ivre.db.db.passive.insert_or_update_bulk
    elif bulk_local:
        function = ivre.db.db.passive.insert_or_update_local_bulk
    else:
        function = functools.partial(
            ivre.db.DBPassive.insert_or_update_bulk,
            ivre.db.db.passive,
        )
    function(
        ivre.passive.parse_p0f_line(
            line,
            include_port=(mode['name'] == 'SYN+ACK'),
            sensor=sensor,
            recontype=recontype,
        ) for line in p0fprocess.stdout
    )


def main():
    parser, use_argparse = ivre.utils.create_argparser(__doc__,
                                                       extraargs='filenames')
    parser.add_argument('--sensor', '-s', help='Sensor name')
    parser.add_argument('--mode', '-m', help='p0f mode',
                        choices=list(ivre.passive.P0F_MODES),
                        default="SYN")
    parser.add_argument('--bulk', action='store_true',
                        help='Use bulk inserts (this is the default)')
    parser.add_argument('--local-bulk', action='store_true',
                        help='Use local (memory) bulk inserts')
    parser.add_argument('--no-bulk', action='store_true',
                        help='Do not use bulk inserts')
    if use_argparse:
        parser.add_argument(
            'filenames', nargs="+", metavar='filename',
            help="PCAP file to read or iface:[interface name]",
        )
    args = parser.parse_args()
    for filename in args.filenames:
        process_file(filename, args.sensor,
                     (not (args.no_bulk or args.local_bulk)) or args.bulk,
                     args.local_bulk, args.mode)
