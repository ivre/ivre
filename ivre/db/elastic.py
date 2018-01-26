#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

"""This sub-module contains functions to interact with the Elasticsearch
database.

WARNING: Elasticsearch support is highly experimental, not tested and
not usable (for now). It is only included in case someone wants to
contribute!

"""

from __future__ import print_function
import struct


from elasticsearch import Elasticsearch


from ivre.db import DB, DBNmap
from ivre.utils import int2ip
from ivre.xmlnmap import Nmap2Elastic


class ElasticDB(DB):

    def __init__(self, hosts, **_):
        self.hosts = hosts
        self.indexes = {}

    @property
    def db(self):
        """The DB."""
        try:
            return self._db
        except AttributeError:
            self._db = Elasticsearch(self.hosts)
        return self._db

    def init(self):
        for idx in self.indexes:
            self.db.indices.delete(index=idx, ignore=[400, 404])
        self.create_indexes()

    def create_indexes(self):
        for idx, body in self.indexes.iteritems():
            print(self.db.indices.create(index=idx, ignore=400,
                                         body={"mappings": body}))


class ElasticDBNmap(ElasticDB, DBNmap):

    # FIXME
    flt_empty = None

    def __init__(self, host, **kargs):
        ElasticDB.__init__(self, host, **kargs)
        DBNmap.__init__(self)
        self.content_handler = Nmap2Elastic
        self.output_function = None
        self.indexes = {
            "ivre-nmap": {
                "scans": {
                    "_all": {"enabled": False},
                    "properties": {
                        "id": {"type": "binary"},
                        "scaninfos": {
                            "type": "nested",
                            "properties": {
                                "protocol": {"type": "keyword"},
                                "type": {"type": "keyword"},
                            },
                        },
                        "scanner": {"type": "keyword"},
                        "start": {"type": "keyword"},
                        "version": {"type": "keyword"},
                        "xmloutputversion": {"type": "keyword"},
                    },
                },
                "hosts": {
                    "_all": {"enabled": False},
                    "properties": {
                        "scanid": {"type": "binary"},
                        "schema_version": {"type": "byte"},

                        "addr": {"type": "ip"},
                        "categories": {"type": "keyword"},
                        "source": {"type": "keyword"},
                        "starttime": {"type": "date"},
                        "endtime": {"type": "date"},
                        "hostnames": {"type": "keyword"},

                        "infos.as_name": {"type": "keyword"},
                        "infos.as_num": {"type": "long"},
                        "infos.country_code": {"type": "keyword"},
                        "infos.country_name": {"type": "keyword"},
                        "infos.area_code": {"type": "integer"},
                        "infos.city": {"type": "keyword"},
                        "infos.loc": {"type": "geo_point"},
                        "infos.metro_code": {"type": "integer"},
                        "infos.postal_code": {"type": "keyword"},
                        "infos.region_code": {"type": "keyword"},

                        "openports": {
                            "type": "nested",
                            "properties": {
                                "count": {"type": "integer"},
                                "protocol": {"type": "keyword"},
                                "ports": {"type": "integer"},
                            }
                        },

                        "ports": {
                            "type": "nested",
                            "properties": {
                                "port": {"type": "long"},
                                "protocol": {"type": "keyword"},
                                "state_state": {"type": "keyword"},
                                "state_reason": {"type": "keyword"},
                                "state_reason_ttl": {"type": "short"},

                                "service_name": {"type": "keyword"},
                                "service_product": {"type": "keyword"},
                                "service_version": {"type": "keyword"},
                                "service_extrainfo": {"type": "keyword"},
                                "service_ostype": {"type": "keyword"},
                                "service_devicetype": {"type": "keyword"},
                                "service_hostname": {"type": "keyword"},
                                "service_tunnel": {"type": "keyword"},

                                "screendata": {"type": "binary"},
                                "screenshot": {"type": "keyword"},
                                "screenwords": {"type": "keyword"},

                                "scripts": {
                                    "type": "nested",
                                    "properties": {
                                        "id": {"type": "keyword"},
                                        "output": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                    },
                },
            },
        }

    def store_or_merge_host(self, host, gettoarchive, merge=False):
        # FIXME No merge or archive for now
        host = dict(host)
        if "openports" in host:
            openports = [{"protocol": "_all",
                          "count": host['openports']['count']}]
            openports.extend(dict(value, protocol=key)
                             for key, value in host['openports'].iteritems()
                             if isinstance(value, dict))
            host['openports'] = openports
        if 'loc' in host.get('infos', {}):
            host['infos'] = dict(host['infos'])
            if "coordinates" in host['infos']['loc']:
                host['infos']['loc'] = "%f,%f" % tuple(host['infos']['loc'][
                    'coordinates'
                ][::-1])
            else:
                del host['infos']['loc']
        try:
            host['addr'] = int2ip(host['addr'])
        except (struct.error, TypeError):
            pass
        try:
            host['addr'] = int2ip(host['addr'])
        except (struct.error, TypeError):
            pass
        host['scanid'] = host['scanid'].decode('hex').encode('base64')
        ret = self.db.index(index='ivre-nmap', doc_type='hosts', body=host)

    def store_scan_doc(self, scan):
        scan = dict(scan)
        id_ = scan.pop('_id').decode('hex').encode('base64')
        ret = self.db.index(index='ivre-nmap', id=id_, doc_type='scans',
                            body=scan)
        return id_
