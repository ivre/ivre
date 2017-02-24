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

"""Manage scans run on remote agents."""

import ivre.target
import ivre.db
import ivre.utils
import ivre.config

import os
import sys
import time
import signal

def display_scan(scan, verbose=True):
    scan['target'] = ivre.db.db.agent.get_scan_target(scan['_id'])
    print "scan:"
    if verbose:
        print "  - id: %s" % scan['_id']
    print "  - categories:"
    for category in scan['target'].target.infos['categories']:
        print "    - %s" % category
    print "  - targets added: %d" % scan['target'].nextcount
    print "  - results fetched: %d" % scan['results']
    print "  - total targets to add: %d" % scan['target'].target.maxnbr
    print "  - available targets: %d" % scan['target'].target.targetscount
    if scan['target'].nextcount == scan['target'].target.maxnbr:
        print "    - all targets have been added"
    if scan['results'] == scan['target'].target.maxnbr:
        print "    - all results have been retrieved"
    if verbose:
        print "  - internal state: %r" % (scan['target'].getstate(),)
    print "  - agents:"
    for agent in scan['agents']:
        print "    - %s" % agent

def display_agent(agent, verbose=True):
    print "agent:"
    if verbose:
        print "  - id: %s" % agent['_id']
    print "  - source name: %s" % agent['source']
    if agent["host"] is None:
        print "  - local"
    else:
        print "  - remote host: %s" % agent["host"]
    print "  - remote path: %s" % agent["path"]["remote"]
    print "  - master: %s" % agent["master"]
    if verbose:
        print "  - local path: %s" % agent["path"]["local"]
        print "  - rsync command: %s" % ' '.join(agent["rsync"])
    print "  - current scan: %s" % agent["scan"]
    print "  - currently synced: %s" % agent["sync"]
    print "  - max waiting targets: %d" % agent["maxwaiting"]
    print "  - waiting targets: %d" % (
        ivre.db.db.agent.count_waiting_targets(agent['_id'])
    )
    print "  - current targets: %d" % (
        ivre.db.db.agent.count_current_targets(agent['_id'])
    )
    print "  - can receive: %d" % (
        ivre.db.db.agent.may_receive(agent['_id'])
    )

def display_master(master, verbose=True):
    print "master:"
    if verbose:
        print "  - id: %s" % master['_id']
    print "  - hostname %s" % master["hostname"]
    print "  - path %s" % master["path"]

WANT_DOWN = False

def main():
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description=__doc__,
            parents=[ivre.target.argparser])
    except ImportError:
        import optparse
        parser = optparse.OptionParser(
            description=__doc__)
        for args, kargs in ivre.target.argparser.args:
            parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
    parser.add_argument(
        '--assign-free-agents', action="store_true",
        help="Assign any agent available (only useful when specifying"
        " a target)."
    )
    parser.add_argument(
        '--max-waiting', metavar='COUNT', type=int, default=60,
        help='Maximum targets waiting (only affects --add-agent)'
    )
    parser.add_argument(
        '--source', metavar='NAME',
        help='Source name (only affects --add-agent)'
    )
    parser.add_argument('--add-agent', metavar='(HOST:)PATH', nargs='+')
    parser.add_argument('--del-agent', metavar='AGENT', nargs='+')
    parser.add_argument('--add-local-master', action="store_true")
    parser.add_argument('--master-path', metavar="PATH",
                        default=ivre.config.AGENT_MASTER_PATH,
                        help="Non-default path to use for master "
                        "(default is specified by the configuration "
                        "attribute `AGENT_MASTER_PATH`)")
    parser.add_argument('--list-agents', action="store_true")
    parser.add_argument('--list-scans', action="store_true")
    parser.add_argument('--list-masters', action="store_true")
    parser.add_argument('--assign', metavar="AGENT:SCAN")
    parser.add_argument('--unassign', metavar="AGENT")
    parser.add_argument('--init', action="store_true",
                        help='Purge or create and initialize the database.')
    parser.add_argument('--sleep', type=int, default=2,
                        help='Time to wait between each feed/sync '
                        'cycle (only usefull with --daemon).')
    parser.add_argument(
        '--daemon', action="store_true", help="""Run continuously
        feed/sync cycles. The "sync" part requires to be able to rsync
        to & from the agents non-interactively (without entering a
        password). Please note this will *not* daemonize the
        process.

        """)
    args = parser.parse_args()

    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will remove any agent and/or scan in your '
                'database and files. Process ? [y/N] ')
            ans = raw_input()
            if ans.lower() != 'y':
                sys.exit(-1)
        ivre.db.db.agent.init()
        ivre.utils.cleandir(args.master_path)
        for dirname in ["output", "onhold"]:
            ivre.utils.makedirs(
                os.path.join(args.master_path, dirname)
            )

    if args.add_local_master:
        ivre.utils.makedirs(args.master_path)
        ivre.db.db.agent.add_local_master(args.master_path)

    if args.add_agent is not None:
        masterid = ivre.db.db.agent.masterid_from_dir(args.master_path)
        for agent in args.add_agent:
            ivre.db.db.agent.add_agent_from_string(
                masterid, agent,
                maxwaiting=args.max_waiting,
                source=args.source,
            )

    if args.del_agent is not None:
        for agentid in args.del_agent:
            ivre.db.db.agent.del_agent(ivre.db.db.agent.str2id(agentid))

    if args.assign is not None:
        try:
            agentid, scanid = map(ivre.db.db.agent.str2id,
                                  args.assign.split(':', 1))
        except ValueError:
            parser.error("argument --assign: must give agentid:scanid")
        ivre.db.db.agent.assign_agent(agentid, scanid)

    if args.unassign is not None:
        ivre.db.db.agent.unassign_agent(ivre.db.db.agent.str2id(args.unassign))

    targets = ivre.target.target_from_args(args)
    if targets is not None:
        ivre.db.db.agent.add_scan(
            targets,
            assign_to_free_agents=bool(args.assign_free_agents)
        )

    if args.list_agents:
        for agent in (ivre.db.db.agent.get_agent(agentid)
                      for agentid in ivre.db.db.agent.get_agents()):
            display_agent(agent)

    if args.list_scans:
        for scan in (ivre.db.db.agent.get_scan(scanid)
                     for scanid in ivre.db.db.agent.get_scans()):
            display_scan(scan)

    if args.list_masters:
        for master in (ivre.db.db.agent.get_master(masterid)
                       for masterid in ivre.db.db.agent.get_masters()):
            display_master(master)

    if args.daemon:
        def terminate(signum, _):
            global WANT_DOWN
            print ('SHUTDOWN: got signal %d, will halt after current '
                   'task.' % signum)
            WANT_DOWN = True
        def terminate_now(signum, _):
            print 'SHUTDOWN: got signal %d, halting now.' % signum
            exit()
        signal.signal(signal.SIGINT, terminate)
        signal.signal(signal.SIGTERM, terminate)

        masterid = ivre.db.db.agent.masterid_from_dir(args.master_path)
        while not WANT_DOWN:
            ivre.db.db.agent.feed_all(masterid)
            ivre.db.db.agent.sync_all(masterid)
            signal.signal(signal.SIGINT, terminate_now)
            signal.signal(signal.SIGTERM, terminate_now)
            if not WANT_DOWN:
                time.sleep(args.sleep)
            signal.signal(signal.SIGINT, terminate)
            signal.signal(signal.SIGTERM, terminate)
