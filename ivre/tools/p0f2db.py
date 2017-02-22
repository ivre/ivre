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

"""Update the database from output of a p0f process"""

import ivre.db
import ivre.utils
import ivre.passive

import signal
import functools
import subprocess
import os
try:
    import argparse
    USING_ARGPARSE = True
except ImportError:
    import optparse
    USING_ARGPARSE = False


def terminate(signum, stack_frame):
    p0fprocess.terminate()

signal.signal(signal.SIGINT, terminate)
signal.signal(signal.SIGTERM, terminate)


def process_file(fname, sensor, bulk, mode):
    global p0fprocess
    if fname.lower().startswith('iface:'):
        fname = ['-i', fname[6:]]
    else:
        fname = ['-s', fname]
    if mode == None:
        mode = 'SYN'
    mode = ivre.passive.P0F_MODES[mode]
    recontype = 'P0F2-%s' % mode['name']
    p0fprocess = subprocess.Popen(
        ['p0f', '-q', '-l', '-S', '-ttt'] + fname
        + mode['options'] + [mode['filter']],
        stdout=subprocess.PIPE,
        preexec_fn=os.setpgrp,
    )
    if bulk:
        function = ivre.db.db.passive.insert_or_update_bulk
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
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(description=__doc__)
    else:
        parser = optparse.OptionParser(description=__doc__)
        parser.parse_args_orig = parser.parse_args

        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('filenames', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option
    parser.add_argument('--sensor', '-s', help='Sensor name')
    parser.add_argument('--mode', '-m', help='p0f mode',
                        choices=ivre.passive.P0F_MODES.keys(),
                        default="SYN")
    parser.add_argument('--bulk', action='store_true',
                        help='Use bulk inserts (this is the default)')
    parser.add_argument('--no-bulk', action='store_true',
                        help='Do not use bulk inserts')
    if USING_ARGPARSE:
        parser.add_argument(
            'filenames', nargs="+", metavar='filename',
            help="PCAP file to read or iface:[interface name]",
        )
    args = parser.parse_args()
    for filename in args.filenames:
        process_file(filename, args.sensor, (not args.no_bulk) or args.bulk,
                     args.mode)
