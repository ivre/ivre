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
from ivre import utils

SCHEMA_VERSION = 1

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

META_DESC = {
    'http': {
        'method': None, 'host': None, 'user_agent': None, 'status_msg': None,
        'info_code': None, 'info_msg': None, 'request_body_len': None,
        'response_body_len': None
    },
    'dns': {
        'query': None, 'answers': None, 'class': 'qclass_name',
        'rcode': 'rcode_name', 'type': 'qtype_name'
    },
    'ssh': {
        'version': None, 'auth_success': None,
        'client': None, 'server': None, 'cipher_alg': None, 'mac_alg': None,
        'compression_alg': None, 'kex_alg': None, 'host_key_alg': None,
        'host_key': None
    },
    'sip': {
        'dport': None, 'method': None, "uri": None,
        "request_from": None, "request_to": None, "response_from": None,
        "response_to": None, "reply_to": None, "user_agent": None,
        "status_code": None, "status_msg": None, "warning": None
    },
    'modbus': {
        'name': 'func', 'exception': None
    },
    'snmp': {
        'version': None, 'community': None, 'get_requests': None,
        'get_bulk_requests': None, 'get_responses': None,
        'set_requests': None
    },
    'ssl': {
        'version': None, 'cipher': None, 'curve': None, 'server_name': None,
        'last_alert': None, 'next_protocol': None, 'subject': None,
        'issuer': None, 'client_subject': None, 'client_issuer': None
    },
    'rdp': {
        'cookie': None, 'result': None, 'security_protocol': None,
        'keyboard_layout': None, 'client_build': None, 'client_name': None,
        'client_dig_product_id': None, 'cert_type': None, 'cert_count': None,
        'cert_permanent': None, 'encryption_level': None,
        'encryption_method': None
    }
}


def ssh2passive_keys(rec, is_server):
    return [
        {
            'recontype': ('SSH_SERVER_ALGOS' if is_server
                          else 'SSH_CLIENT_ALGOS'),
            'entries': [
                {
                    'source': 'encryption_algorithms',
                    'value': rec.get('cipher_alg')
                },
                {'source': 'kex_algorithms', 'value': rec.get('kex_alg')},
                {'source': 'mac_algorithms', 'value': rec.get('mac_alg')},
                {
                    'source': 'compression_algorithms',
                    'value': rec.get('compression_alg')
                },
                {
                    'source': 'server_host_key_algorithms',
                    'value': rec.get('host_key_alg')
                }
            ]
        }
    ]


class Query(object):
    # The order matters because regex pipe is ungreedy
    operators_chars = [':', '==', '=~', '=', '!=', '<=', '<', '>=', '>']
    operators_re = re.compile('|'.join(re.escape(x) for x in operators_chars))
    identifier = re.compile('^[a-zA-Z][a-zA-Z0-9_]*$')
    or_re = re.compile('^OR|\\|\\|$')
    # matches '"test" test' in 2 groups "test" and test
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
