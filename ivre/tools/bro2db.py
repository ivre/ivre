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


FLOW_KEYS_TCP = {"dport": "{id_resp_p}", "proto": '"tcp"'}
FLOW_KEYS_UDP = {"dport": "{id_resp_p}", "proto": '"udp"'}
DEFAULT_FLOW_KEYS = FLOW_KEYS_TCP
DEFAULT_HOST_KEYS = {"addr": "{addr}"}
ALL_DESCS = {
    "dns": {
        "labels": ["DNS"],
        "flow_keys": {"dport": "{id_resp_p}", "proto": '{proto}'},
        "keys": {"query": None, "class": "{qclass_name}",
                 "type": "{qtype_name}", "rcode": "{rcode_name}",
                 "answers": None},
    },

    "http": {
        "labels": ["HTTP"],
        "keys": {"dport": "{id_resp_p}", "method": None,
                 "host": None, "user_agent": None,
                 "status_code": None, "status_msg": None,
                 "info_code": None, "info_msg": None,
                 "username": None, "password": None,
                 "proxied": None},
        "counters": ["request_body_len", "response_body_len"],
    },

    "known_devices__name": {
        "labels": ["Name"],
        "host_keys": {"addr": "{host}"},
        "keys": ["name"],
        "accumulators": {"source": ("{source}", 5)},
    },

    "known_devices__mac": {
        "labels": ["Mac"],
        "host_keys": {"addr": "{host}"},
        "keys": ["mac"],
        "accumulators": {"source": ("{source}", 5)},
    },

    "software": {
        "labels": ["Software"],
        "host_keys": {"addr": "{host}"},
        "keys": ["software_type", "name", "version_major", "version_minor",
                 "version_minor2", "version_minor3", "version_addl"],
        "accumulators": {"unparsed_version": ("{unparsed_version}", 5)},
        "kind": "host",
    },

    "ssl": {
        "labels": ["SSL"],
        "keys": {"dport": "{id_resp_p}", "version": None,
                 "cipher": None, "curve": None,
                 "server_name": None, "last_alert": None,
                 "next_protocol": None, "subject": None,
                 "issuer": None, "client_subject": None,
                 "client_issuer": None},
    },

    "ssh": {
        "labels": ["SSH"],
        "keys": {"dport": "{id_resp_p}", "version": None,
                 "auth_success": None, "client": None,
                 "server": None, "cipher_alg": None,
                 "mac_alg": None, "compression_alg": None,
                 "kex_alg": None, "host_key_alg": None,
                 "host_key": None},
    },

    "sip": {
        "labels": ["SIP"],
        "keys": {"dport": "{id_resp_p}", "method": None,
                 "uri": None, "request_from": None,
                 "request_to": None, "response_from": None,
                 "response_to": None, "reply_to": None,
                 "user_agent": None, "status_code": None,
                 "status_msg": None, "warning": None},
        "counters": ["request_body_len", "response_body_len"],
    },

    "snmp": {
        "labels": ["SNMP"],
        "keys": ["version", "community"],
        "flow_keys": FLOW_KEYS_UDP,
        "counters": {
            "get_requests": None,
            "get_bulk_requests": None,
            "get_responses": None,
            "set_requests": None,
        },
    },

    "modbus": {
        "labels": ["Modbus"],
        "keys": {"name": "{func}", "exception": None},
    },

    "rdp": {
        "labels": ["RDP"],
        "keys": ["cookie", "result", "security_protocol", "keyboard_layout",
                 "client_build", "client_name", "client_dig_product_id",
                 "cert_type", "cert_count", "cert_permanent",
                 "encryption_level", "encryption_method"],
    },
}


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


FUNCTIONS = {
    "conn": db.flow.conn2flow,
    "http": http2flow,
    "ssh": ssh2flow
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
