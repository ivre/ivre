#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
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

"""This sub-module contains functions to interact with the ElasticSearch
databases.

"""

import json
import re
from urllib.parse import unquote


from elasticsearch import Elasticsearch, helpers
from elasticsearch_dsl import Q
from elasticsearch_dsl.query import Query


from ivre.active.data import ALIASES_TABLE_ELEMS
from ivre.db import DB, DBActive, DBView
from ivre import utils


PAGESIZE = 250


class ElasticDB(DB):

    nested_fields = []

    # filters
    flt_empty = Q()

    def __init__(self, url):
        super().__init__()
        self.username = ""
        self.password = ""
        self.hosts = None
        if "@" in url.netloc:
            username, hostname = url.netloc.split("@", 1)
            if ":" in username:
                self.username, self.password = (
                    unquote(val) for val in username.split(":", 1)
                )
            else:
                self.username = unquote(username)
            if hostname:
                self.hosts = [hostname]
        elif url.netloc:
            self.hosts = [url.netloc]
        index_prefix = url.path.lstrip("/")
        if index_prefix:
            self.index_prefix = index_prefix + "-"
        else:
            self.index_prefix = "ivre-"
        self.params = dict(
            x.split("=", 1) if "=" in x else (x, None)
            for x in url.query.split("&")
            if x
        )

    def init(self):
        """Initializes the mappings."""
        for idxnum, mapping in enumerate(self.mappings):
            idxname = self.indexes[idxnum]
            self.db_client.indices.delete(
                index=idxname,
                ignore=[400, 404],
            )
            self.db_client.indices.create(
                index=idxname,
                body={
                    "mappings": {
                        "properties": mapping,
                        # Since we do not need full text searches, use
                        # type "keyword" for strings (unless otherwise
                        # specified in mapping) instead of default
                        # (text + keyword)
                        "dynamic_templates": [
                            {
                                "strings": {
                                    "match_mapping_type": "string",
                                    # prevent RequestError exceptions when
                                    # one term's UTF-8 encoding is bigger
                                    # than the max length 32766
                                    "mapping": {
                                        "type": "keyword",
                                        "ignore_above": 32000,
                                    },
                                }
                            },
                        ],
                    }
                },
            )

    @property
    def db_client(self):
        """The DB connection."""
        try:
            return self._db_client
        except AttributeError:
            self._db_client = Elasticsearch(
                hosts=self.hosts, http_auth=(self.username, self.password)
            )
            return self._db_client

    @property
    def server_info(self):
        """Server information."""
        try:
            return self._server_info
        except AttributeError:
            self._server_info = self.db_client.info()
            return self._server_info

    @staticmethod
    def to_binary(data):
        return utils.encode_b64(data).decode()

    @staticmethod
    def from_binary(data):
        return utils.decode_b64(data.encode())

    @staticmethod
    def ip2internal(addr):
        return addr

    @staticmethod
    def internal2ip(addr):
        return addr

    @staticmethod
    def searchnonexistent():
        return Q("match", _id=0)

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).
        """
        return Q("match", addr=addr)

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        pass

    @staticmethod
    def _get_pattern(regexp):
        # The equivalent to a MongoDB or PostgreSQL search for regexp
        # /Test/ would be /.*Test.*/ in Elasticsearch, while /Test/ in
        # Elasticsearch is equivalent to /^Test$/ in MongoDB or
        # PostgreSQL.
        pattern, flags = utils.regexp2pattern(regexp)
        if flags & ~re.UNICODE:
            # is a flag, other than re.UNICODE, is set, issue a
            # warning as it will not be used
            utils.LOGGER.warning(
                "Elasticsearch does not support flags in regular "
                "expressions [%r with flags=%r]",
                pattern,
                flags,
            )
        return pattern

    @staticmethod
    def _flt_and(cond1, cond2):
        return cond1 & cond2

    @staticmethod
    def _flt_or(cond1, cond2):
        return cond1 | cond2

    @staticmethod
    def flt2str(flt):
        return json.dumps(flt.to_dict())


def _create_mappings(nested, all_mappings):
    res = {}
    for fld in nested:
        cur = res
        curkey = None
        for subkey in fld.split(".")[:-1]:
            if curkey is not None:
                subkey = "%s.%s" % (curkey, subkey)
            if cur.get(subkey, {}).get("type") == "nested":
                cur = cur[subkey].setdefault("properties", {})
                curkey = None
            else:
                curkey = subkey
        subkey = fld.rsplit(".", 1)[-1]
        if curkey is not None:
            subkey = "%s.%s" % (curkey, subkey)
        cur[subkey] = {
            "type": "nested",
            # This is needed to use the nested fields in
            # Kibana:
            "include_in_parent": True,
        }
    for fldtype, fldnames in all_mappings:
        for fld in fldnames:
            cur = res
            curkey = None
            for subkey in fld.split(".")[:-1]:
                if curkey is not None:
                    subkey = "%s.%s" % (curkey, subkey)
                if cur.get(subkey, {}).get("type") == "nested":
                    cur = cur[subkey].setdefault("properties", {})
                    curkey = None
                else:
                    curkey = subkey
            subkey = fld.rsplit(".", 1)[-1]
            if curkey is not None:
                subkey = "%s.%s" % (curkey, subkey)
            cur.setdefault(subkey, {})["type"] = fldtype
    return res


class ElasticDBActive(ElasticDB, DBActive):

    nested_fields = [
        "ports",
        "ports.scripts",
        "ports.scripts.http-app",
        "ports.scripts.http-headers",
        "ports.scripts.ssl-ja3-client",
        "ports.scripts.ssl-ja3-server",
    ]
    mappings = [
        _create_mappings(
            nested_fields,
            [
                ("nested", nested_fields),
                ("ip", DBActive.ipaddr_fields),
                ("date", DBActive.datetime_fields),
                ("geo_point", ["infos.coordinates"]),
            ],
        ),
    ]
    index_hosts = 0

    def store_or_merge_host(self, host):
        raise NotImplementedError

    def store_host(self, host):
        if "coordinates" in host.get("infos", {}):
            host["infos"]["coordinates"] = host["infos"]["coordinates"][::-1]
        self.db_client.index(index=self.indexes[0], body=host)

    def count(self, flt):
        return self.db_client.count(
            body={"query": flt.to_dict()},
            index=self.indexes[0],
            ignore_unavailable=True,
        )["count"]

    def _set_datetime_field(self, record, field, current=None):
        if current is None:
            current = []
        if "." not in field:
            if field in record:
                record[field] = utils.all2datetime(record[field])
            return
        nextfield, field = field.split(".", 1)
        if nextfield not in record:
            return
        current.append(nextfield)
        if ".".join(current) in self.list_fields:
            for subrecord in record[nextfield]:
                self._set_datetime_field(subrecord, field, current=current)
        else:
            self._set_datetime_field(record[nextfield], field, current=current)

    def get(self, spec, fields=None, **kargs):
        """Queries the active index."""
        query = {"query": spec.to_dict()}
        if fields is not None:
            query["_source"] = fields
        for rec in helpers.scan(
            self.db_client, query=query, index=self.indexes[0], ignore_unavailable=True
        ):
            host = dict(rec["_source"], _id=rec["_id"])
            if "coordinates" in host.get("infos", {}):
                host["infos"]["coordinates"] = host["infos"]["coordinates"][::-1]
            for field in self.datetime_fields:
                self._set_datetime_field(host, field)
            yield host

    def remove(self, host):
        """Removes the host from the active column. `host` must be the record as
        returned by .get().

        """
        self.db_client.delete(
            index=self.indexes[0],
            id=host["_id"],
        )

    def remove_many(self, flt):
        """Removes the host from the active column. `host` must be the record as
        returned by .get().

        """
        self.db_client.delete_by_query(
            index=self.indexes[0],
            body={"query": flt.to_dict()},
        )

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None):
        if flt is None:
            flt = self.flt_empty
        if field == "infos.coordinates":

            def fix_result(value):
                return tuple(float(v) for v in value.split(", "))

            base_query = {
                "script": {
                    "lang": "painless",
                    "source": "doc['infos.coordinates'].value",
                }
            }
            flt = self.flt_and(flt, self.searchhaslocation())
        else:
            base_query = {"field": field}
            if field in self.datetime_fields:

                def fix_result(value):
                    return utils.all2datetime(value / 1000.0)

            else:

                def fix_result(value):
                    return value

        # https://techoverflow.net/2019/03/17/how-to-query-distinct-field-values-in-elasticsearch/
        query = {"size": PAGESIZE, "sources": [{field: {"terms": base_query}}]}
        while True:
            result = self.db_client.search(
                body={"query": flt.to_dict(), "aggs": {"values": {"composite": query}}},
                index=self.indexes[0],
                ignore_unavailable=True,
                size=0,
            )
            for value in result["aggregations"]["values"]["buckets"]:
                yield fix_result(value["key"][field])
            if "after_key" not in result["aggregations"]["values"]:
                break
            query["after"] = result["aggregations"]["values"]["after_key"]

    def getlocations(self, flt):
        query = {
            "size": PAGESIZE,
            "sources": [
                {
                    "coords": {
                        "terms": {
                            "script": {
                                "lang": "painless",
                                "source": "doc['infos.coordinates'].value",
                            }
                        }
                    }
                }
            ],
        }
        flt = self.flt_and(flt & self.searchhaslocation())
        while True:
            result = self.db_client.search(
                body={"query": flt.to_dict(), "aggs": {"values": {"composite": query}}},
                index=self.indexes[0],
                ignore_unavailable=True,
                size=0,
            )
            for value in result["aggregations"]["values"]["buckets"]:
                yield {
                    "_id": tuple(float(v) for v in value["key"]["coords"].split(", ")),
                    "count": value["doc_count"],
                }
            if "after_key" not in result["aggregations"]["values"]:
                break
            query["after"] = result["aggregations"]["values"]["after_key"]

    def topvalues(self, field, flt=None, topnbr=10, sort=None, least=False):
        """
        This method uses an aggregation to produce top values for a given
        field or pseudo-field. Pseudo-fields are:
          - category[:regexp] / asnum / country / net[:mask]
          - port
          - port:open / :closed / :filtered / :<servicename>
          - portlist:open / :closed / :filtered
          - countports:open / :closed / :filtered
          - service / service:<portnbr>
          - product / product:<portnbr>
          - cpe / cpe.<part> / cpe:<cpe_spec> / cpe.<part>:<cpe_spec>
          - devicetype / devicetype:<portnbr>
          - script:<scriptid> / script:<port>:<scriptid>
            / script:host:<scriptid>
          - cert.* / smb.* / sshkey.* / ike.*
          - httphdr / httphdr.{name,value} / httphdr:<name>
          - httpapp / httpapp:<name>
          - modbus.* / s7.* / enip.*
          - mongo.dbs.*
          - vulns.*
          - screenwords
          - file.* / file.*:scriptid
          - hop
          - scanner.name / scanner.port:tcp / scanner.port:udp
        """
        baseterms = {"size": topnbr}
        if least:
            baseterms["order"] = {"_count": "asc"}
        outputproc = None
        nested = None
        if flt is None:
            flt = self.flt_empty
        if field == "category":
            field = {"field": "categories"}
        elif field.startswith("category:") or field.startswith("categories:"):
            subfield = utils.str2regexp(field.split(":", 1)[1])
            flt = self.flt_and(flt, self.searchcategory(subfield))
            if isinstance(subfield, utils.REGEXP_T):
                subfield = self._get_pattern(subfield)
            else:
                subfield = re.escape(subfield)
            field = {"field": "categories", "include": subfield}
        elif field == "asnum":
            flt = self.flt_and(flt, Q("exists", field="infos.as_num"))
            field = {"field": "infos.as_num"}
        elif field == "as":

            def outputproc(value):
                return tuple(
                    val if i else int(val) for i, val in enumerate(value.split(",", 1))
                )

            flt = self.flt_and(flt, Q("exists", field="infos.as_num"))
            field = {
                "script": {
                    "lang": "painless",
                    "source": "doc['infos.as_num'].value + ',' + "
                    "doc['infos.as_name'].value",
                }
            }
        elif field == "port" or field.startswith("port:"):

            def outputproc(value):
                return tuple(
                    int(val) if i else val for i, val in enumerate(value.rsplit("/", 1))
                )

            if field == "port":
                flt = self.flt_and(
                    flt,
                    Q("nested", path="ports", query=Q("exists", field="ports.port")),
                )
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "filter": {
                                "bool": {
                                    "must_not": [
                                        {"match": {"ports.port": -1}},
                                    ]
                                }
                            },
                            "aggs": {
                                "patterns": {
                                    "terms": dict(
                                        baseterms,
                                        script={
                                            "lang": "painless",
                                            "source": 'doc["ports.protocol"].value + "/" + '
                                            'doc["ports.port"].value',
                                        },
                                    ),
                                }
                            },
                        }
                    },
                }
            else:
                info = field[5:]
                if info in ["open", "filtered", "closed"]:
                    flt = self.flt_and(
                        flt,
                        Q(
                            "nested",
                            path="ports",
                            query=Q("match", ports__state_state=info),
                        ),
                    )
                    matchfield = "state_state"
                else:
                    flt = self.flt_and(
                        flt,
                        Q(
                            "nested",
                            path="ports",
                            query=Q("match", ports__service_name=info),
                        ),
                    )
                    matchfield = "service_name"
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "filter": {
                                "bool": {
                                    "must": [
                                        {"match": {"ports.%s" % matchfield: info}}
                                    ],
                                    "must_not": [{"match": {"ports.port": -1}}],
                                }
                            },
                            "aggs": {
                                "patterns": {
                                    "terms": dict(
                                        baseterms,
                                        script={
                                            "lang": "painless",
                                            "source": 'doc["ports.protocol"].value + "/" + '
                                            'doc["ports.port"].value',
                                        },
                                    ),
                                }
                            },
                        }
                    },
                }
        elif field == "service":

            def outputproc(value):
                return value or None

            flt = self.flt_and(flt, self.searchopenport())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"ports.state_state": "open"}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    field="ports.service_name",
                                    missing="",
                                ),
                            }
                        },
                    }
                },
            }
        elif field.startswith("service:"):
            port = int(field[8:])
            flt = self.flt_and(flt, self.searchport(port))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {"match": {"ports.state_state": "open"}},
                                    {"match": {"ports.port": port}},
                                ]
                            }
                        },
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    field="ports.service_name",
                                    missing="",
                                ),
                            }
                        },
                    }
                },
            }
        elif field == "product":

            def outputproc(value):
                return tuple(v or None for v in value.split("###", 1))

            flt = self.flt_and(flt, self.searchopenport())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"ports.state_state": "open"}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    script="""
String result = "";
if(doc['ports.service_name'].size() > 0) {
    result += doc['ports.service_name'].value;
}
result += "###";
if(doc['ports.service_product'].size() > 0) {
    result += doc['ports.service_product'].value;
}
return result;
""",
                                    missing="",
                                ),
                            }
                        },
                    }
                },
            }
        elif field.startswith("product:"):

            def outputproc(value):
                return tuple(v or None for v in value.split("###", 1))

            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                matchfield = "port"
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                matchfield = "service_name"
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {"match": {"ports.state_state": "open"}},
                                    {"match": {"ports.%s" % matchfield: info}},
                                ]
                            }
                        },
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    script="""
String result = "";
if(doc['ports.service_name'].size() > 0) {
    result += doc['ports.service_name'].value;
}
result += "###";
if(doc['ports.service_product'].size() > 0) {
    result += doc['ports.service_product'].value;
}
return result;
""",
                                ),
                            }
                        },
                    }
                },
            }
        elif field == "version":

            def outputproc(value):
                return tuple(v or None for v in value.split("###", 2))

            flt = self.flt_and(flt, self.searchopenport())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"ports.state_state": "open"}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    script="""
String result = "";
if(doc['ports.service_name'].size() > 0) {
    result += doc['ports.service_name'].value;
}
result += "###";
if(doc['ports.service_product'].size() > 0) {
    result += doc['ports.service_product'].value;
}
result += "###";
if(doc['ports.service_version'].size() > 0) {
    result += doc['ports.service_version'].value;
}
return result;
""",
                                    missing="",
                                ),
                            }
                        },
                    }
                },
            }
        elif field.startswith("version:"):

            def outputproc(value):
                return tuple(v or None for v in value.split("###", 2))

            info = field[8:]
            if info.isdigit():
                port = int(info)
                flt = self.flt_and(flt, self.searchport(port))
                matchflt = Q("match", ports__port=port)
            elif ":" in info:
                service, product = info.split(":", 1)
                flt = self.flt_and(
                    flt,
                    self.searchproduct(
                        product=product,
                        service=service,
                    ),
                )
                matchflt = Q("match", ports__service_name=service) & Q(
                    "match", ports__service_product=product
                )
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                matchflt = Q("match", ports__service_name=info)
            matchflt &= Q("match", ports__state_state="open")
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": matchflt.to_dict(),
                        "aggs": {
                            "patterns": {
                                "terms": dict(
                                    baseterms,
                                    script="""
String result = "";
if(doc['ports.service_name'].size() > 0) {
    result += doc['ports.service_name'].value;
}
result += "###";
if(doc['ports.service_product'].size() > 0) {
    result += doc['ports.service_product'].value;
}
result += "###";
if(doc['ports.service_version'].size() > 0) {
    result += doc['ports.service_version'].value;
}
return result;
""",
                                ),
                            }
                        },
                    }
                },
            }
        elif field == "httphdr":

            def outputproc(value):
                return tuple(value.split(":", 1))

            flt = self.flt_and(flt, self.searchhttphdr())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-headers"},
                                "aggs": {
                                    "patterns": {
                                        "terms": dict(
                                            baseterms,
                                            script={
                                                "lang": "painless",
                                                "source": "doc['ports.scripts.http-headers.name']."
                                                "value + ':' + doc['ports.scripts.http-"
                                                "headers.value'].value",
                                            },
                                        )
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field.startswith("httphdr."):
            flt = self.flt_and(flt, self.searchhttphdr())
            field = "ports.scripts.http-headers.%s" % field[8:]
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-headers"},
                                "aggs": {
                                    "patterns": {
                                        "terms": dict(baseterms, field=field),
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field.startswith("httphdr:"):
            subfield = field[8:].lower()
            flt = self.flt_and(flt, self.searchhttphdr(name=subfield))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-headers"},
                                "aggs": {
                                    "patterns": {
                                        "filter": {
                                            "match": {
                                                "ports.scripts.http-headers.name": subfield,
                                            }
                                        },
                                        "aggs": {
                                            "patterns": {
                                                "terms": dict(
                                                    baseterms,
                                                    field="ports.scripts.http-headers.value",
                                                ),
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field == "httpapp":

            def outputproc(value):
                return tuple(value.split(":", 1))

            flt = self.flt_and(flt, self.searchhttpapp())
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-app"},
                                "aggs": {
                                    "patterns": {
                                        "terms": dict(
                                            baseterms,
                                            script={
                                                "lang": "painless",
                                                "source": "doc['ports.scripts.http-app.application']"
                                                ".value + ':' + doc['ports.scripts.http-"
                                                "app.version'].value",
                                            },
                                        )
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field.startswith("httpapp:"):
            subfield = field[8:].lower()
            flt = self.flt_and(flt, self.searchhttpapp(name=subfield))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.http-app"},
                                "aggs": {
                                    "patterns": {
                                        "filter": {
                                            "match": {
                                                "ports.scripts.http-app.application": subfield,
                                            }
                                        },
                                        "aggs": {
                                            "patterns": {
                                                "terms": dict(
                                                    baseterms,
                                                    field="ports.scripts.http-app.version",
                                                ),
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field == "useragent" or field.startswith("useragent:"):
            if field == "useragent":
                flt = self.flt_and(flt, self.searchuseragent())
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "nested": {"path": "ports.scripts"},
                            "aggs": {
                                "patterns": {
                                    "terms": dict(
                                        baseterms,
                                        field="ports.scripts.http-user-agent",
                                    ),
                                }
                            },
                        }
                    },
                }
            else:
                subfield = utils.str2regexp(field[10:])
                flt = self.flt_and(flt, self.searchuseragent(useragent=subfield))
                if isinstance(subfield, utils.REGEXP_T):
                    subfield = self._get_pattern(subfield)
                else:
                    subfield = re.escape(subfield)
                nested = {
                    "nested": {"path": "ports"},
                    "aggs": {
                        "patterns": {
                            "nested": {"path": "ports.scripts"},
                            "aggs": {
                                "patterns": {
                                    "terms": dict(
                                        baseterms,
                                        field="ports.scripts.http-user-agent",
                                        include=subfield,
                                    ),
                                }
                            },
                        }
                    },
                }
        elif field == "ja3-client" or (
            field.startswith("ja3-client") and field[10] in ":."
        ):
            if ":" in field:
                field, value = field.split(":", 1)
                subkey, value = self._ja3keyvalue(utils.str2regexp(value))
                if isinstance(value, utils.REGEXP_T):
                    include_value = self._get_pattern(value)
                    filter_value = {
                        "regexp": {
                            "ports.scripts.ssl-ja3-client.%s" % subkey: include_value,
                        }
                    }
                else:
                    include_value = re.escape(value)
                    filter_value = {
                        "match": {
                            "ports.scripts.ssl-ja3-client.%s" % subkey: value,
                        }
                    }
            else:
                value = None
                subkey = None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            base = {
                "terms": dict(
                    baseterms,
                    field="ports.scripts.ssl-ja3-client.%s" % subfield,
                ),
            }
            if subkey is not None:
                if subkey != subfield:
                    base = {
                        "filter": filter_value,
                        "aggs": {"patterns": base},
                    }
                else:
                    base["terms"]["include"] = include_value
            flt = self.flt_and(flt, self.searchja3client(value_or_hash=value))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.ssl-ja3-client"},
                                "aggs": {"patterns": base},
                            }
                        },
                    }
                },
            }
        elif field == "ja3-server" or (
            field.startswith("ja3-server") and field[10] in ":."
        ):

            def outputproc(value):
                return tuple(value.split("/"))

            if ":" in field:
                field, values = field.split(":", 1)
                if ":" in values:
                    value1, value2 = values.split(":", 1)
                    if value1:
                        subkey1, value1 = self._ja3keyvalue(utils.str2regexp(value1))
                        if isinstance(value1, utils.REGEXP_T):
                            filter_value1 = {
                                "regexp": {
                                    "ports.scripts.ssl-ja3-server.%s"
                                    % subkey1: self._get_pattern(value1),
                                }
                            }
                        else:
                            filter_value1 = {
                                "match": {
                                    "ports.scripts.ssl-ja3-server.%s" % subkey1: value1,
                                }
                            }
                    else:
                        subkey1, value1 = None, None
                    if value2:
                        subkey2, value2 = self._ja3keyvalue(utils.str2regexp(value2))
                        if isinstance(value2, utils.REGEXP_T):
                            filter_value2 = {
                                "regexp": {
                                    "ports.scripts.ssl-ja3-server.client.%s"
                                    % subkey2: self._get_pattern(value2),
                                }
                            }
                        else:
                            filter_value2 = {
                                "match": {
                                    "ports.scripts.ssl-ja3-server.client.%s"
                                    % subkey2: value2,
                                }
                            }
                    else:
                        subkey2, value2 = None, None
                else:
                    subkey1, value1 = self._ja3keyvalue(utils.str2regexp(values))
                    if isinstance(value1, utils.REGEXP_T):
                        filter_value1 = {
                            "regexp": {
                                "ports.scripts.ssl-ja3-server.%s"
                                % subkey1: self._get_pattern(value1),
                            }
                        }
                    else:
                        filter_value1 = {
                            "match": {
                                "ports.scripts.ssl-ja3-server.%s" % subkey1: value1,
                            }
                        }
                    subkey2, value2 = None, None
            else:
                subkey1, value1 = None, None
                subkey2, value2 = None, None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            flt = self.flt_and(
                flt,
                self.searchja3server(
                    value_or_hash=value1,
                    client_value_or_hash=value2,
                ),
            )
            base = {
                "terms": dict(
                    baseterms,
                    script={
                        "lang": "painless",
                        "source": "doc['ports.scripts.ssl-ja3-server.%s'].value + '/' + "
                        "doc['ports.scripts.ssl-ja3-server.client.%s'].value"
                        % (subfield, subfield),
                    },
                ),
            }
            if value1 is not None:
                base = {
                    "filter": filter_value1,
                    "aggs": {"patterns": base},
                }
            if value2 is not None:
                base = {
                    "filter": filter_value2,
                    "aggs": {"patterns": base},
                }
            flt = self.flt_and(
                flt,
                self.searchja3server(
                    value_or_hash=value1,
                    client_value_or_hash=value2,
                ),
            )
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.ssl-ja3-server"},
                                "aggs": {"patterns": base},
                            }
                        },
                    }
                },
            }
        elif field.startswith("s7."):
            flt = self.flt_and(flt, self.searchscript(name="s7-info"))
            subfield = field[3:]
            field = {"field": "ports.scripts.s7-info." + subfield}
        elif field.startswith("scanner.port:"):
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = {"field": "ports.scripts.scanner.ports.%s.ports" % field[13:]}
        elif field == "scanner.name":
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = {"field": "ports.scripts.scanner.scanners.name"}
        else:
            field = {"field": field}
        body = {"query": flt.to_dict()}
        if nested is None:
            body["aggs"] = {"patterns": {"terms": dict(baseterms, **field)}}
        else:
            body["aggs"] = {"patterns": nested}
        utils.LOGGER.debug("DB: Elasticsearch aggregation: %r", body)
        result = self.db_client.search(
            body=body, index=self.indexes[0], ignore_unavailable=True, size=0
        )
        result = result["aggregations"]
        while "patterns" in result:
            result = result["patterns"]
        result = result["buckets"]
        if outputproc is None:
            for res in result:
                yield {"_id": res["key"], "count": res["doc_count"]}
        else:
            for res in result:
                yield {"_id": outputproc(res["key"]), "count": res["doc_count"]}

    @staticmethod
    def searchhaslocation(neg=False):
        res = Q("exists", field="infos.coordinates")
        if neg:
            return ~res
        return res

    @classmethod
    def searchcategory(cls, cat, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular category
        (records may have zero, one or more categories).
        """
        if isinstance(cat, list):
            res = Q("terms", categories=cat)
        elif isinstance(cat, utils.REGEXP_T):
            res = Q("regexp", categories=cls._get_pattern(cat))
        else:
            res = Q("match", categories=cat)
        if neg:
            return ~res
        return res

    @staticmethod
    def searchcountry(country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        country = utils.country_unalias(country)
        if isinstance(country, list):
            res = Q("terms", infos__country_code=country)
        else:
            res = Q("match", infos__country_code=country)
        if neg:
            return ~res
        return res

    @staticmethod
    def searchasnum(asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        if not isinstance(asnum, str) and hasattr(asnum, "__iter__"):
            res = Q("terms", infos__as_num=[int(val) for val in asnum])
        else:
            res = Q("match", infos__as_num=int(asnum))
        if neg:
            return ~res
        return res

    @classmethod
    def searchasname(cls, asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        if isinstance(asname, utils.REGEXP_T):
            res = Q("regexp", infos__as_name=cls._get_pattern(asname))
        else:
            res = Q("match", infos__as_name=asname)
        if neg:
            return ~res
        return res

    @staticmethod
    def searchopenport(neg=False):
        "Filters records with at least one open port."
        res = Q("nested", path="ports", query=Q("match", ports__state_state="open"))
        if neg:
            return ~res
        return res

    @staticmethod
    def searchport(port, protocol="tcp", state="open", neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        if port == "host":
            res = Q("nested", path="ports", query=Q("match", ports__port=-1))
        elif state == "open":
            res = Q("match", **{"openports.%s.ports" % protocol: port})
        else:
            res = Q(
                "nested",
                path="ports",
                query=(
                    Q("match", ports__port=port)
                    & Q("match", ports__protocol=protocol)
                    & Q("match", ports__state_state=state)
                ),
            )
        if neg:
            return ~res
        return res

    @classmethod
    def searchscript(cls, name=None, output=None, values=None, neg=False):
        """Search a particular content in the scripts results."""
        req = []
        if isinstance(name, list):
            req.append(Q("terms", **{"ports.scripts.id": name}))
        elif isinstance(name, utils.REGEXP_T):
            req.append(Q("regexp", **{"ports.scripts.id": cls._get_pattern(name)}))
        elif name is not None:
            req.append(Q("match", **{"ports.scripts.id": name}))
        if output is not None:
            if isinstance(output, utils.REGEXP_T):
                req.append(
                    Q("regexp", **{"ports.scripts.output": cls._get_pattern(output)})
                )
            else:
                req.append(Q("match", **{"ports.scripts.output": output}))
        if values:
            if isinstance(name, list):
                all_keys = set(ALIASES_TABLE_ELEMS.get(n, n) for n in name)
                if len(all_keys) != 1:
                    raise TypeError(
                        ".searchscript() needs similar `name` values when using a `values` arg"
                    )
                key = all_keys.pop()
            elif not isinstance(name, str):
                raise TypeError(
                    ".searchscript() needs a `name` arg when using a `values` arg"
                )
            else:
                key = ALIASES_TABLE_ELEMS.get(name, name)
            if isinstance(values, Query):
                req.append(values)
            elif isinstance(values, str):
                req.append(Q("match", **{"ports.scripts.%s" % key: values}))
            elif isinstance(values, utils.REGEXP_T):
                req.append(
                    Q(
                        "regexp",
                        **{"ports.scripts.%s" % key: cls._get_pattern(values)},
                    )
                )
            else:
                for field, value in values.items():
                    if isinstance(value, utils.REGEXP_T):
                        req.append(
                            Q(
                                "regexp",
                                **{
                                    "ports.scripts.%s.%s"
                                    % (key, field): cls._get_pattern(value)
                                },
                            )
                        )
                    else:
                        req.append(
                            Q(
                                "match",
                                **{"ports.scripts.%s.%s" % (key, field): value},
                            )
                        )
        if not req:
            res = Q(
                "nested",
                path="ports",
                query=Q(
                    "nested",
                    path="ports.scripts",
                    query=Q("exists", field="ports.scripts"),
                ),
            )
        else:
            query = cls.flt_and(*req)
            res = Q(
                "nested",
                path="ports",
                query=Q("nested", path="ports.scripts", query=query),
            )
        if neg:
            return ~res
        return res

    @staticmethod
    def searchservice(srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        if srv is False:
            res = ~Q("exists", field="ports.service_name")
        elif isinstance(srv, list):
            res = Q("terms", ports__service_name=srv)
        else:
            res = Q("match", ports__service_name=srv)
        if port is not None:
            res &= Q("match", ports__port=port)
        if protocol is not None:
            res &= Q("match", ports__protocol=protocol)
        return Q("nested", path="ports", query=res)

    @classmethod
    def searchproduct(
        cls, product=None, version=None, service=None, port=None, protocol=None
    ):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        res = []
        if product is not None:
            if product is False:
                res.append(~Q("exists", field="ports.service_product"))
            elif isinstance(product, list):
                res.append(Q("terms", ports__service_product=product))
            else:
                res.append(Q("match", ports__service_product=product))
        if version is not None:
            if version is False:
                res.append(~Q("exists", field="ports.service_version"))
            elif isinstance(version, list):
                res.append(Q("terms", ports__service_version=version))
            else:
                res.append(Q("match", ports__service_version=version))
        if service is not None:
            if service is False:
                res.append(~Q("exists", field="ports.service_name"))
            elif isinstance(service, list):
                res.append(Q("terms", ports__service_name=service))
            else:
                res.append(Q("match", ports__service_name=service))
        if port is not None:
            res.append(Q("match", ports__port=port))
        if protocol is not None:
            res.append(Q("match", ports__protocol=protocol))
        return Q("nested", path="ports", query=cls.flt_and(*res))


class ElasticDBView(ElasticDBActive, DBView):
    def __init__(self, url):
        super().__init__(url)
        self.indexes = [
            "%s%s" % (self.index_prefix, self.params.pop("indexname_hosts", "views"))
        ]

    def store_or_merge_host(self, host):
        if not self.merge_host(host):
            self.store_host(host)
