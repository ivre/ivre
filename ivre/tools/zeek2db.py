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

"""Update the flow database from Bro logs"""


import os
from ivre.parser.bro import BroFile
from ivre.db import db
from ivre import config, utils, flow


def _bro2flow(rec):
    """Prepares a document for db.flow.*add_flow()."""
    if "id_orig_h" in rec:
        rec["src"] = rec.pop("id_orig_h")
    if "id_resp_h" in rec:
        rec["dst"] = rec.pop("id_resp_h")
    if "ts" in rec:
        rec["start_time"] = rec["end_time"] = rec.pop("ts")
    if rec.get('proto', None) == 'icmp':
        # FIXME incorrect: source & dest flow?
        rec['type'], rec['code'] = rec.pop('id_orig_p'), rec.pop('id_resp_p')
    elif 'id_orig_p' in rec and 'id_resp_p' in rec:
        rec['sport'], rec['dport'] = rec.pop('id_orig_p'), rec.pop('id_resp_p')
    return rec


def http2flow(bulk, rec):
    rec['proto'] = 'tcp'
    db.flow.any2flow(bulk, 'http', rec)


def ssh2flow(bulk, rec):
    rec['proto'] = 'tcp'
    db.flow.any2flow(bulk, 'ssh', rec)


def _sip_paths_search_tcp(paths):
    """
    Fills the given proto_dict with transport protocol info found in path
    """
    for elt in paths:
        info = elt.split(' ')[0].split('/')
        if len(info) != 3:
            continue
        if info[2].lower() in ["tcp", "tls"]:
            return True
    return False


def sip2flow(bulk, rec):
    found_tcp = (_sip_paths_search_tcp(rec['response_path']) or
                 _sip_paths_search_tcp(rec['request_path']))
    rec["proto"] = "tcp" if found_tcp else "udp"
    db.flow.any2flow(bulk, 'sip', rec)


def snmp2flow(bulk, rec):
    rec['proto'] = 'udp'
    db.flow.any2flow(bulk, 'snmp', rec)


def ssl2flow(bulk, rec):
    rec['proto'] = 'tcp'  # FIXME Is it always true?
    db.flow.any2flow(bulk, 'ssl', rec)


def rdp2flow(bulk, rec):
    rec['proto'] = 'tcp'  # FIXME Is it always true?
    db.flow.any2flow(bulk, 'rdp', rec)


def dns2flow(bulk, rec):
    rec['answers'] = [elt.lower() for elt in
                      (rec['answers'] if rec['answers'] else [])]
    rec['query'] = rec['query'].lower() if rec['query'] else None
    db.flow.dns2flow(bulk, rec)


FUNCTIONS = {
    "conn": db.flow.conn2flow,
    "http": http2flow,
    "ssh": ssh2flow,
    "dns": dns2flow,
    "sip": sip2flow,
    "snmp": snmp2flow,
    "ssl": ssl2flow,
    "rdp": rdp2flow,
}


def any2flow(name):
    def inserter(bulk, rec):
        return db.flow.any2flow(bulk, name, rec)
    return inserter


def main():
    """Update the flow database from Bro logs"""
    parser, use_argparse = utils.create_argparser(__doc__,
                                                  extraargs="logfiles")
    if use_argparse:
        parser.add_argument("logfiles", nargs='*', metavar='FILE',
                            help="Bro log files")
    parser.add_argument("-v", "--verbose", help="verbose mode",
                        action="store_true")
    parser.add_argument("-C", "--no-cleanup",
                        help="avoid port cleanup heuristics",
                        action="store_true")
    args = parser.parse_args()

    if args.verbose:
        config.DEBUG = True

    for fname in args.logfiles:
        if not os.path.exists(fname):
            utils.LOGGER.error("File %r does not exist", fname)
            continue
        with BroFile(fname) as brof:
            bulk = db.flow.start_bulk_insert()
            utils.LOGGER.debug("Parsing %s\n\t%s", fname,
                               "Fields:\n%s\n" % "\n".join(
                                   "%s: %s" % (f, t)
                                   for f, t in brof.field_types
                               ))
            if brof.path in FUNCTIONS:
                func = FUNCTIONS[brof.path]
            elif brof.path in flow.META_DESC:
                func = any2flow(brof.path)
            else:
                utils.LOGGER.debug("Log format not (yet) supported for %r",
                                   fname)
                continue
            for line in brof:
                if not line:
                    continue
                func(bulk, _bro2flow(line))
            db.flow.bulk_commit(bulk)
            if brof.path == "conn" and not args.no_cleanup:
                db.flow.cleanup_flows()
