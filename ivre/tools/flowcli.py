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

from ivre.db import db

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import os

def main():
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='Access and query the flows database.',
        )
        USING_ARGPARSE = True
    except ImportError:
        import optparse
        parser = optparse.OptionParser(
            description='Access and query the flows database.')
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
        USING_ARGPARSE = False
    parser.add_argument('--init', '--purgedb', action='store_true',
                        help='Purge or create and initialize the database.')
    parser.add_argument('--ensure-indexes', action='store_true',
                        help='Create missing indexes (will lock the database).')
    parser.add_argument('--limit', type=int,
                        help='Ouput at most LIMIT results.')
    parser.add_argument('--skip', type=int,
                        help='Skip first SKIP results.')
    args = parser.parse_args()

    out = sys.stdout

    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will remove any scan result in your database. '
                'Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() != 'y':
                sys.exit(-1)
        db.flow.init()
        sys.exit(0)
    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will lock your database. '
                'Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() != 'y':
                sys.exit(-1)
        db.flow.ensure_indexes()
        sys.exit(0)
    query = db.flow.query(
        skip=args.skip, limit=args.limit,
    )
    query.ret = """
RETURN count(distinct src) as clients,
       count(distinct link) as flows,
       count(distinct dst) as servers
"""
    count = db.flow.db.run(query.query, query.params).next
    # Compat py2neo < 3
    try:
        count = count()
    except TypeError:
        pass
    count = dict(count)
    sys.stdout.write('%(clients)d clients\n%(servers)d servers\n'
                     '%(flows)d flows\n' % count)
