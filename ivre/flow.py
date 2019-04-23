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
