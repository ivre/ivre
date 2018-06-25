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

"""Update the database from output of the Bro script 'passiverecon'"""


import signal
import functools


import ivre.db
import ivre.utils
import ivre.passive
import ivre.parser.bro


signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)


def _get_ignore_rules(ignore_spec):
    """Executes the ignore_spec file and returns the ignore_rules
dictionary.

Python 2.6 bug: it has to be in a separate function than main()
because of the exec() call and the nested functions.

    """
    ignore_rules = {}
    if ignore_spec is not None:
        exec(compile(open(ignore_spec, "rb").read(), ignore_spec, 'exec'),
             ignore_rules)
    return ignore_rules


def rec_iter(bro_parser, sensor, ignore_rules):
    for line in bro_parser:
        line["timestamp"] = line.pop("ts")
        # skip PassiveRecon::
        line["recon_type"] = line["recon_type"][14:]
        yield ivre.passive.handle_rec(
            sensor,
            ignore_rules.get('IGNORENETS', {}),
            ignore_rules.get('NEVERIGNORE', {}),
            **line
        )


def main():
    import sys
    try:
        import argparse
        parser = argparse.ArgumentParser(description=__doc__)
    except ImportError:
        import optparse
        parser = optparse.OptionParser(description=__doc__)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
    parser.add_argument('--sensor', '-s', help='Sensor name')
    parser.add_argument('--ignore-spec', '-i',
                        help='Filename containing ignore rules')
    parser.add_argument('--bulk', action='store_true',
                        help='Use DB bulk inserts (this is the default)')
    parser.add_argument('--local-bulk', action='store_true',
                        help='Use local (memory) bulk inserts')
    parser.add_argument('--no-bulk', action='store_true',
                        help='Do not use bulk inserts')
    args = parser.parse_args()
    ignore_rules = _get_ignore_rules(args.ignore_spec)
    if (not (args.no_bulk or args.local_bulk)) or args.bulk:
        function = ivre.db.db.passive.insert_or_update_bulk
    elif args.local_bulk:
        function = ivre.db.db.passive.insert_or_update_local_bulk
    else:
        function = functools.partial(
            ivre.db.DBPassive.insert_or_update_bulk,
            ivre.db.db.passive,
        )
    # Python 2/3 compat: read stdin as binary in Python 3 with .buffer
    try:
        stdin = sys.stdin.buffer
    except AttributeError:
        stdin = sys.stdin
    bro_parser = ivre.parser.bro.BroFile(stdin)
    function(
        rec_iter(bro_parser, args.sensor, ignore_rules),
        getinfos=ivre.passive.getinfos
    )
