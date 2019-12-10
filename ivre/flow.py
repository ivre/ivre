#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2019 Pierre LALET <pierre.lalet@cea.fr>
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

"""
This module is part of IVRE.
Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains functions used for flow.
"""

import re

from ivre import utils, config

SCHEMA_VERSION = 1

FIELDS = {
    'src.addr': "Source IP Address",
    'dst.addr': "Destination IP Address",
    'proto': "Transport protocol",
    'dport': "Destination port (if relevant)",
    'sports': "Source ports (list) (if relevant)",
    'type': "ICMP type (if relevant)",
    'codes': "ICMP codes (list) (if relevant)",
    'count': "Number of occurrences of the flow",
    'csbytes': "Number of bytes sent by client (src) to server (dst)",
    'scbytes': "Number of bytes sent by server (dst) to client (src)",
    'cspkts': "Number of packets sent by client (src) to server (dst)",
    'scpkts': "Number of packets sent by server (dst) to client (src)",
    'firstseen': "First time the flow has been observed",
    'lastseen': "Last time the flow has been observed",
    'times': "Time periods during which the flow has been observed (list) "
             "(MongoDB backend only)",
    'times.duration': "Time period duration (MongoDB backend only)",
    'times.start': "Time period beginning (MongoDB backend only)",
}

HTTP_PASSIVE_RECONTYPES_SERVER = {
    'HTTP_CLIENT_HEADER_SERVER': {
        "HOST": "host"
    }
}

HTTP_PASSIVE_RECONTYPES_CLIENT = {
    'HTTP_CLIENT_HEADER': {
        "USER-AGENT": "user_agent"
    }
}

# This list contains the meta desc keys containing a list of values.
META_DESC_ARRAYS = ["dns.keys.answers"]

# This dictionary describes the handling of high level protocols during
# flow metadata insertion.
# The first level keys represent a Zeek protocol file
# The first level values are dictionaries, containing the following keys:
# - keys: represents fields that must be stored as unique
# - counters (optional): represents fields that must be stored as counters,
#       i.e. their values should be incremented.
# The final value can be a dictionary or a list.
# If the final value is a dictionary, then its keys are the
# internal names of the fields and its values are the name of corresponding
# fields of the parsed Zeek file. If the value is None, then the internal
# field name equals the parsed Zeek file field name.
# If its associated value is a list, each internal field name equals its
# corresponding parsed Zeek file field name.
META_DESC = {
    "dns": {
        "keys": {"query": None, "class": "{qclass_name}",
                 "type": "{qtype_name}", "rcode": "{rcode_name}",
                 "answers": None},
    },

    "http": {
        "keys": ["method", "host", "user_agent", "status_code", "status_msg",
                 "info_code", "info_msg", "username", "password", "proxied"],
        "counters": ["request_body_len", "response_body_len"],
    },

    "ssl": {
        "keys": ["version", "cipher", "curve", "server_name", "last_alert",
                 "next_protocol", "subject", "issuer", "client_subject",
                 "client_issuer"],
    },

    "ssh": {
        "keys": ["version", "auth_success", "client", "server", "cipher_alg",
                 "mac_alg", "compression_alg", "kex_alg", "host_key_alg",
                 "host_key"],
    },

    "sip": {
        "keys": ["method", "uri", "request_from", "request_to",
                 "response_from", "response_to", "reply_to", "user_agent",
                 "status_code", "status_msg", "warning"],
        "counters": ["request_body_len", "response_body_len"],
    },

    "snmp": {
        "keys": ["version", "community"],
        "counters": ["get_requests", "get_bulk_requests", "get_responses",
                     "set_requests"],
    },

    "modbus": {
        "keys": {"name": "{func}", "exception": None},
    },

    "rdp": {
        "keys": ["cookie", "result", "security_protocol", "keyboard_layout",
                 "client_build", "client_name", "client_dig_product_id",
                 "cert_type", "cert_count", "cert_permanent",
                 "encryption_level", "encryption_method"],
    },
}

# Stores available fields
# Populated by validate_field
_ALL_FIELDS = None


def validate_field(field):
    """
    Validates whether the given field is valid.
    If the field does not exist, it raises a ValueError exception.
    If the field is disabled, it logs a warning.
    Return value is unused.
    """
    if _ALL_FIELDS is None:
        _compute_available_fields()
    if field not in _ALL_FIELDS:
        raise ValueError("%s is not a valid field. Use --fields to get "
                         "the list of available fields." % field)
    if not _ALL_FIELDS[field]:
        utils.LOGGER.warning("%s might not work because you configured IVRE "
                             "to not store flows metadata.", field)


def _compute_available_fields():
    """
    Computes available fields from FIELDS and META_DESC and stores them in
    _ALL_FIELDS. It is a dictionary where keys are fields and values
    are booleans. The boolean represents whether the field is
    usable or not (useful for meta fields that can be disabled).
    """
    global _ALL_FIELDS
    _ALL_FIELDS = {}
    for field in FIELDS:
        _ALL_FIELDS[field] = True
    meta_enabled = config.FLOW_STORE_METADATA
    for meta in META_DESC:
        _ALL_FIELDS["meta.%s" % meta] = meta_enabled
        for name in META_DESC[meta]["keys"]:
            _ALL_FIELDS["meta.%s.%s" % (meta, name)] = meta_enabled
        for name in META_DESC[meta].get('counters', []):
            _ALL_FIELDS["meta.%s.%s" % (meta, name)] = meta_enabled


class Query(object):
    # The order matters because regex pipe is ungreedy
    operators_chars = [':', '==', '=~', '=', '!=', '<=', '<', '>=', '>']
    operators_re = re.compile('|'.join(re.escape(x) for x in operators_chars))
    identifier = re.compile('^[a-zA-Z][a-zA-Z0-9_]*$')
    or_re = re.compile('^OR|\\|\\|$')
    # Used to split filter in tokens (attributes, operators, values)
    # Example: '"test" test' is divided in 2 groups "test" and test
    splitter_re = re.compile('(?:[^\\s"]|"(?:\\\\.|[^"])*")+')
    clauses = []

    @classmethod
    def _split_filter_or(cls, flt):
        current = []
        for subflt in cls.splitter_re.finditer(flt):
            subflt = subflt.group()
            if cls.or_re.search(subflt):
                yield " ".join(current)
                current = []
            else:
                current.append(subflt)
        yield " ".join(current)

    def _add_clause_from_filter(self, flt):
        """
        Returns a clause object computed from the given filter
        flt format is
        "[!|-|~][ANY |ALL |ONE |NONE |LEN ]<attr>[operator <value>]"
        """
        clause = {'neg': False, 'array_mode': None, 'len_mode': False,
                  'attr': None, 'operator': None, 'value': None}
        if not flt:
            return None
        # Ignore labels (neo4j compatibility)
        if flt[0] == '#':
            return None
        if flt[0] in "-!~":
            clause['neg'] = True
            flt = flt[1:]
        array_modes = ['ANY', 'ALL', 'ONE', 'NONE']
        for array_mode in array_modes:
            if flt.startswith(array_mode + ' '):
                clause['array_mode'] = array_mode
                flt = flt[len(array_mode) + 1:]
                break
        if clause['array_mode'] is None and flt.startswith("LEN "):
            clause['len_mode'] = True
            flt = flt[4:]

        try:
            clause['operator'] = self.operators_re.search(flt).group()
        except AttributeError:
            clause['operator'] = None
            clause['attr'] = flt
        else:
            clause['attr'], value = [
                elt.strip() for elt in flt.split(clause['operator'], 1)]
            clause['value'] = utils.str2pyval(value)
        # Validate field
        # 'addr' is a shortcut for src.addr OR dst.addr
        if clause['attr'] != 'addr':
            validate_field(clause['attr'])
        return clause

    def add_clause_from_filter(self, flt, mode="node"):
        """
        Returns an array representing "AND" clauses, each
        clauses being an array of "OR" clauses
        so that 'c1 OR c2 AND c3' will be reprensented as
        [[c1,c2],[c3]]
        """
        clauses = []
        for subflt in self._split_filter_or(flt):
            if subflt:
                subclause = self._add_clause_from_filter(subflt)
                if subclause is not None:
                    clauses.append(subclause)
        return self.add_clause(clauses)

    def add_clause(self, clause):
        self.clauses.append(clause)

    def __init__(self):
        self.clauses = []

    def __str__(self):
        return str(self.clauses)
