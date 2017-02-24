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

"""Update the flow database from Bro logs"""

import os
import re
import sys

from ivre.parser.bro import BroFile
from ivre.db import db
from ivre import config
from ivre import utils

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


def _bro2neo(rec):
    """Prepares a document for db.flow.*add_flow()."""
    if "id_orig_h" in rec:
        rec["src"] = rec.pop("id_orig_h")
    if "id_resp_h" in rec:
        rec["dst"] = rec.pop("id_resp_h")
    if "ts" in rec:
        rec["start_time"] = rec["end_time"] = rec.pop("ts")
    return rec


def any2neo(desc, kind=None):
    if kind is None:
        kind = desc.get("kind", "flow")

    def inserter(bulk, rec):
        keys = desc["keys"]
        link_type = desc.get("link", "INTEL")
        counters = desc.get("counters", [])
        accumulators = desc.get("accumulators", {})
        keys = utils.normalize_props(keys)
        counters = utils.normalize_props(counters)
        for props in (keys, counters, accumulators):
            for k, v in props.items():
                if v[0] == '{' and v[-1] == '}':
                    prop = v[1:-1]
                else:
                    prop = k
                if (prop not in rec or rec[prop] is None) and k in props:
                    del(props[k])
        if kind == "flow":
            flow_keys = desc.get("flow_keys", DEFAULT_FLOW_KEYS)
            bulk.append(
                db.flow.add_flow_metadata(
                    desc["labels"], link_type, keys, flow_keys,
                    counters=counters, accumulators=accumulators),
                rec
            )
        elif kind == "host":
            host_keys = desc.get("host_keys", DEFAULT_HOST_KEYS)
            bulk.append(
                db.flow.add_host_metadata(
                    desc["labels"], link_type, keys, host_keys=host_keys,
                    counters=counters, accumulators=accumulators),
                rec
            )
        else:
            raise ValueError("Unrecognized kind")
    return inserter


def conn2neo(bulk, rec):
    """Returns a statement inserting a CONN flow from a Bro log"""
    query_cache = conn2neo.query_cache
    linkattrs = ('proto',)
    accumulators = {}
    if rec['proto'] == 'icmp':
        # FIXME incorrect: source & dest flow?
        rec['type'], rec['code'] = rec.pop('id_orig_p'), rec.pop('id_resp_p')
        accumulators = {'codes': ('{code}', None)}
        linkattrs = linkattrs + ('type',)
    elif 'id_orig_p' in rec and 'id_resp_p' in rec:
        rec['sport'], rec['dport'] = rec.pop('id_orig_p'), rec.pop('id_resp_p')
        accumulators = {'sports': ('{sport}', 5)}
        linkattrs = linkattrs + ('dport',)

    counters = {
            "cspkts": "{orig_pkts}",
            "csbytes": "{orig_ip_bytes}",
            "scpkts": "{resp_pkts}",
            "scbytes": "{resp_ip_bytes}",
    }
    if linkattrs not in query_cache:
        query_cache[linkattrs] = db.flow.add_flow(
            ["Flow"], linkattrs, counters=counters,
            accumulators=accumulators)
    bulk.append(query_cache[linkattrs], rec)

conn2neo.query_cache = {}


# VERY simplistic IPv4/v6 re
IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|'
                   '^[a-f0-9:]*:[a-f0-9]{0,4}$')


def dns2neo(bulk, rec):
    # FIXME
    if db.flow.db_version[0] >= 3:
        rec["answers"] = ', '.join(rec.get("answers") or [])

    if (rec.get("query", "") or "").endswith(".in-addr.arpa"):
        # Reverse DNS
        # rec["names"] = rec["answers"]
        rec["addrs"] = ['.'.join(reversed(rec["query"].split(".")[:4]))]
    else:
        # Forward DNS
        # Name to resolve + aliases
        # rec["names"] =  [rec["query"]] + [addr for addr in rec["answers"]
        #                                   if not IP_RE.match(addr)]
        rec["addrs"] = [addr for addr in rec.get("answers", []) or []
                        if IP_RE.match(addr)]

    any2neo(ALL_DESCS["dns"])(bulk, rec)
    # TODO: loop in neo
    for addr in rec["addrs"]:
        tmp_rec = rec.copy()
        tmp_rec["addr"] = addr
        any2neo(ALL_DESCS["dns"], "host")(bulk, tmp_rec)

def knwon_devices2neo(bulk, rec):
    any2neo(ALL_DESCS["known_devices__name"], "host")(bulk, rec)
    any2neo(ALL_DESCS["known_devices__mac"], "host")(bulk, rec)

FUNCTIONS = {
    "conn": conn2neo,
    "dns": dns2neo,
    "known_devices": knwon_devices2neo,
}


def main():
    """Update the flow database from Bro logs"""
    try:
        import argparse
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('logfiles', nargs='*', metavar='FILE',
                            help='Bro log files')
    except ImportError:
        import optparse
        parser = optparse.OptionParser(description=__doc__)
        parser.parse_args_orig = parser.parse_args

        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('logfiles', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option

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
            elif brof.path in ALL_DESCS:
                func = any2neo(ALL_DESCS[brof.path])
            else:
                utils.LOGGER.debug("Log format not (yet) supported for %r",
                                   fname)
                continue
            for line in brof:
                if not line:
                    continue
                func(bulk, _bro2neo(line))
            bulk.commit()
            if brof.path == "conn" and not args.no_cleanup:
                db.flow.cleanup_flows()
