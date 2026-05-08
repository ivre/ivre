#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
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

from ivre import utils
from ivre.active.nmap import ALIASES_TABLE_ELEMS
from ivre.db import DB, DBActive, DBView
from ivre.plugins import load_plugins

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
        self.tls = url.scheme == "elastics"
        if "@" in url.netloc:
            username, hostname = url.netloc.split("@", 1)
            if ":" in username:
                self.username, self.password = (
                    unquote(val) for val in username.split(":", 1)
                )
            else:
                self.username = unquote(username)
            if hostname:
                self.hosts = [f"http{'s' if self.tls else ''}://{hostname}"]
        elif url.netloc:
            self.hosts = [f"http{'s' if self.tls else ''}://{url.netloc}"]
        index_prefix = url.path.lstrip("/")
        if index_prefix:
            self.index_prefix = f"{index_prefix}-"
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

    def flush(self):
        """Force-refresh every Elasticsearch index this backend
        owns so that just-written documents become searchable.

        Elasticsearch buffers writes for the cluster's
        ``refresh_interval`` (default 1s) before they are visible
        to ``_search``. Tests that read-back-after-write rely on
        this synchronous refresh to avoid race conditions; in
        production, the default refresh cadence is fine and the
        method is rarely used outside the test suite.
        """
        for idxname in self.indexes:
            self.db_client.indices.refresh(index=idxname)

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
            # if a flag, other than re.UNICODE, is set, issue a
            # warning as it will not be used
            utils.LOGGER.warning(
                "Elasticsearch does not support flags in regular "
                "expressions [%r with flags=%r]",
                pattern,
                flags,
            )
        return pattern

    @classmethod
    def _search_field(cls, field, value, neg=False):
        """Build the canonical Elasticsearch query for ``field``
        against ``value`` with optional negation. Mirrors the
        ``MongoDB._search_field`` helper on the Mongo side: a
        single dispatch over the four input shapes the IVRE web
        filter language can produce.

        - ``value`` is a regex (``utils.REGEXP_T``) → ``regexp``
          query (the pattern is rewritten via :meth:`_get_pattern`
          to match Elasticsearch's anchored-by-default semantics).
        - ``value`` is a list of length one → ``match`` query on
          the single element (collapses to the scalar shape so
          the wire output stays comparable to the legacy
          ``terms``-with-one-element form would).
        - ``value`` is a list of more elements → ``terms`` query.
        - ``value`` is a scalar → ``match`` query.

        ``neg=True`` wraps the result in ``~`` (a ``bool``
        ``must_not`` clause).
        """
        if isinstance(value, utils.REGEXP_T):
            res = Q("regexp", **{field: cls._get_pattern(value)})
        elif isinstance(value, list):
            if len(value) == 1:
                res = Q("match", **{field: value[0]})
            else:
                res = Q("terms", **{field: value})
        else:
            res = Q("match", **{field: value})
        if neg:
            return ~res
        return res

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
                subkey = f"{curkey}.{subkey}"
            if cur.get(subkey, {}).get("type") == "nested":
                cur = cur[subkey].setdefault("properties", {})
                curkey = None
            else:
                curkey = subkey
        subkey = fld.rsplit(".", 1)[-1]
        if curkey is not None:
            subkey = f"{curkey}.{subkey}"
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
                    subkey = f"{curkey}.{subkey}"
                if cur.get(subkey, {}).get("type") == "nested":
                    cur = cur[subkey].setdefault("properties", {})
                    curkey = None
                else:
                    curkey = subkey
            subkey = fld.rsplit(".", 1)[-1]
            if curkey is not None:
                subkey = f"{curkey}.{subkey}"
            cur.setdefault(subkey, {})["type"] = fldtype
    return res


class ElasticDBActive(ElasticDB, DBActive):
    nested_fields = [
        "ports",
        "ports.scripts",
        "ports.scripts.http-app",
        "ports.scripts.http-headers",
        "ports.scripts.ssl-cert",
        "ports.scripts.ssl-ja3-client",
        "ports.scripts.ssl-ja3-server",
        "ports.scripts.ssl-ja4-client",
        "tags",
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
        if field == "infos.coordinates" and hasattr(self, "searchhaslocation"):

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

    def topvalues(self, field, flt=None, topnbr=10, sort=None, least=False):
        """This method uses an aggregation to produce top values for a given
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
          - domains / domains[:level] / domains[:domain] / domains[:domain[:level]]
          - ja3-client[:filter][.type], ja3-server[:filter][:client][.type]
          - ja4-client[:filter][.type], jarm
          - hassh.type, hassh-client.type, hassh-server.type
          - tag.{value,type,info} / tag[:value]

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

            def outputproc(value):  # noqa: F811
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
                                    "must": [{"match": {f"ports.{matchfield}": info}}],
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
                                    {"match": {f"ports.{matchfield}": info}},
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
            field = f"ports.scripts.http-headers.{field[8:]}"
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
            subfield = field[8:]
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
                            f"ports.scripts.ssl-ja3-client.{subkey}": include_value,
                        }
                    }
                else:
                    include_value = re.escape(value)
                    filter_value = {
                        "match": {
                            f"ports.scripts.ssl-ja3-client.{subkey}": value,
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
                    field=f"ports.scripts.ssl-ja3-client.{subfield}",
                ),
            }
            if subkey is not None:
                if subkey != subfield:
                    base = {
                        # filter_value exists when subkey is not None
                        "filter": filter_value,  # pylint: disable=possibly-used-before-assignment
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
                                    f"ports.scripts.ssl-ja3-server.{subkey1}": self._get_pattern(
                                        value1
                                    ),
                                }
                            }
                        else:
                            filter_value1 = {
                                "match": {
                                    f"ports.scripts.ssl-ja3-server.{subkey1}": value1,
                                }
                            }
                    else:
                        subkey1, value1 = None, None
                    if value2:
                        subkey2, value2 = self._ja3keyvalue(utils.str2regexp(value2))
                        if isinstance(value2, utils.REGEXP_T):
                            filter_value2 = {
                                "regexp": {
                                    f"ports.scripts.ssl-ja3-server.client.{subkey2}": self._get_pattern(
                                        value2
                                    ),
                                }
                            }
                        else:
                            filter_value2 = {
                                "match": {
                                    f"ports.scripts.ssl-ja3-server.client.{subkey2}": value2,
                                }
                            }
                    else:
                        subkey2, value2 = None, None
                else:
                    subkey1, value1 = self._ja3keyvalue(utils.str2regexp(values))
                    if isinstance(value1, utils.REGEXP_T):
                        filter_value1 = {
                            "regexp": {
                                f"ports.scripts.ssl-ja3-server.{subkey1}": self._get_pattern(
                                    value1
                                ),
                            }
                        }
                    else:
                        filter_value1 = {
                            "match": {
                                f"ports.scripts.ssl-ja3-server.{subkey1}": value1,
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
                        "source": f"doc['ports.scripts.ssl-ja3-server.{subfield}'].value + '/' + doc['ports.scripts.ssl-ja3-server.client.{subfield}'].value",
                    },
                ),
            }
            if value1 is not None:
                base = {
                    # filter_value1 exists when value1 is not None
                    "filter": filter_value1,  # pylint: disable=used-before-assignment
                    "aggs": {"patterns": base},
                }
            if value2 is not None:
                base = {
                    # filter_value2 exists when value2 is not None
                    "filter": filter_value2,  # pylint: disable=used-before-assignment
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
        elif field == "ja4-client" or (
            field.startswith("ja4-client") and field[10] in ":."
        ):
            if ":" in field:
                field, value = field.split(":", 1)
                if isinstance(value, utils.REGEXP_T):
                    include_value = self._get_pattern(value)
                else:
                    include_value = re.escape(value)
            else:
                value = None
                include_value = None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "ja4"
            base = {
                "terms": dict(
                    baseterms,
                    field=f"ports.scripts.ssl-ja4-client.{subfield}",
                ),
            }
            if include_value is not None:
                base["terms"]["include"] = include_value
            flt = self.flt_and(flt, self.searchja4client(value=value))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "nested": {"path": "ports.scripts"},
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts.ssl-ja4-client"},
                                "aggs": {"patterns": base},
                            }
                        },
                    }
                },
            }
        elif field == "hassh" or (field.startswith("hassh") and field[5] in "-."):
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"
            aggs = {
                "patterns": {
                    "nested": {"path": "ports.scripts"},
                    "aggs": {
                        "patterns": {
                            "terms": dict(
                                baseterms,
                                field=f"ports.scripts.ssh2-enum-algos.hassh.{subfield}",
                            )
                        }
                    },
                }
            }
            if field == "hassh-server":
                flt = self.flt_and(flt, self.searchhassh(server=True))
                aggs = {
                    "patterns": {
                        "filter": {
                            "bool": {"must_not": [{"match": {"ports.port": -1}}]}
                        },
                        "aggs": aggs,
                    }
                }
            elif field == "hassh-client":
                flt = self.flt_and(flt, self.searchhassh(server=False))
                aggs = {
                    "patterns": {
                        "filter": {"match": {"ports.port": -1}},
                        "aggs": aggs,
                    }
                }
            elif field == "hassh":
                flt = self.flt_and(flt, self.searchhassh())
            else:
                raise ValueError(f"Unknown field {field}")
            nested = {"nested": {"path": "ports"}, "aggs": aggs}
        elif field.startswith("s7."):
            flt = self.flt_and(flt, self.searchscript(name="s7-info"))
            subfield = field[3:]
            field = {"field": f"ports.scripts.s7-info.{subfield}"}
        elif field.startswith("scanner.port:"):
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = {"field": f"ports.scripts.scanner.ports.{field[13:]}.ports"}
        elif field == "scanner.name":
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = {"field": "ports.scripts.scanner.scanners.name"}
        elif field == "jarm":
            flt = self.flt_and(flt, self.searchjarm())
            field = {"field": "ports.scripts.ssl-jarm"}
        elif field.startswith("jarm:"):
            port = int(field[5:])
            flt = self.flt_and(flt, self.searchjarm(), self.searchport(port))
            nested = {
                "nested": {"path": "ports"},
                "aggs": {
                    "patterns": {
                        "filter": {
                            "bool": {
                                "must": [
                                    {"match": {"ports.protocol": "tcp"}},
                                    {"match": {"ports.port": port}},
                                ]
                            }
                        },
                        "aggs": {
                            "patterns": {
                                "nested": {"path": "ports.scripts"},
                                "aggs": {
                                    "patterns": {
                                        "filter": {
                                            "match": {"ports.scripts.id": "ssl-jarm"}
                                        },
                                        "aggs": {
                                            "patterns": {
                                                "terms": dict(
                                                    baseterms,
                                                    field="ports.scripts.ssl-jarm",
                                                )
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        elif field == "tag" and hasattr(self, "searchtag"):
            flt = self.flt_and(flt, self.searchtag())

            def outputproc(value):
                return tuple(value.split(":", 1))

            nested = {
                "nested": {"path": "tags"},
                "aggs": {
                    "patterns": {
                        "terms": dict(
                            baseterms,
                            script={
                                "lang": "painless",
                                "source": "doc['tags.value'].value + ':' + doc['tags.info'].value",
                            },
                        )
                    }
                },
            }
        elif field.startswith("tag.") and hasattr(self, "searchtag"):
            flt = self.flt_and(flt, self.searchtag())
            field = {"field": f"tags.{field[4:]}"}
        elif field.startswith("tag:") and hasattr(self, "searchtag"):
            subfield = field[4:]
            flt = self.flt_and(flt, self.searchtag(tag={"value": subfield}))
            nested = {
                "nested": {"path": "tags"},
                "aggs": {
                    "patterns": {
                        "filter": {"match": {"tags.value": subfield}},
                        "aggs": {
                            "patterns": {
                                "terms": dict(baseterms, field="tags.info", missing="")
                            }
                        },
                    },
                },
            }
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
        return cls._search_field("categories", cat, neg=neg)

    @classmethod
    def searchsource(cls, src, neg=False):
        """Filter records by ``source`` (a free-form tag the
        scanner / ingestion pipeline assigns to each scan run).

        Mirrors :meth:`MongoDB.searchsource`: a ``match`` query
        against the ``source`` field, with the regex / list /
        scalar dispatch :meth:`_search_field` already provides.
        On the view backend ``source`` lands as an array of
        strings (one per merged scan); Elasticsearch's
        ``match`` against an array field returns a hit if any
        element matches, so the same predicate works for both
        Nmap and View shapes without a custom branch.
        """
        return cls._search_field("source", src, neg=neg)

    @classmethod
    def searchdomain(cls, name, neg=False):
        """Filter records by hostname domain (matches the
        domain at any level: ``foo.example.com`` matches
        ``example.com`` and ``com``).

        Mirrors :meth:`MongoDB.searchdomain`: a ``match`` query
        against the indexed ``hostnames.domains`` field (which
        ingestion populates with every suffix of every
        hostname).
        """
        return cls._search_field("hostnames.domains", name, neg=neg)

    @classmethod
    def searchhostname(cls, name=None, neg=False):
        """Filter records by hostname.

        With ``name=None`` the filter only checks for the
        existence (or absence, on ``neg=True``) of any hostname
        on the record.  With a ``name`` argument the predicate
        ANDs an indexed ``hostnames.domains`` lookup with the
        non-indexed ``hostnames.name`` match (so the hot path
        still goes through the index even though the exact
        ``hostnames.name`` field is not indexed).

        Mirrors :meth:`MongoDB.searchhostname`.
        """
        if name is None:
            # ``hostnames.domains`` is the indexed field; gate
            # on its existence rather than ``hostnames.name``
            # so a query without a specific hostname still
            # benefits from the index.
            res = Q("exists", field="hostnames.domains")
            if neg:
                return ~res
            return res
        if neg:
            return cls._search_field("hostnames.name", name, neg=True)
        # Positive match: combine the indexed domain lookup
        # (so the query goes through the index) with the
        # ``hostnames.name`` match.
        return cls.searchdomain(name) & cls._search_field("hostnames.name", name)

    # -- traces.hops -- mirroring :meth:`MongoDB.searchhop` /
    # ``searchhopname`` / ``searchhopdomain``.  ``traces.hops``
    # is *not* declared in :attr:`nested_fields`, so each
    # ``match`` flattens against the array directly: a query
    # combining ``ipaddr`` and ``ttl`` matches host records
    # where any single hop satisfies both predicates *or*
    # different hops satisfy them separately.  The latter is a
    # well-known limitation of non-nested array-of-objects on
    # Elasticsearch and is consistent with the rest of the
    # schema (e.g. ``hostnames.*``).
    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        """Filter records that have a traceroute hop with the
        supplied address (and optional TTL).

        Mirrors :meth:`MongoDB.searchhop`; ``traces.hops.ipaddr``
        is mapped as Elasticsearch's native ``ip`` type, so the
        match takes a printable IP string directly without the
        ``ip2internal`` split the Mongo helper applies.
        """
        res = Q("match", **{"traces.hops.ipaddr": hop})
        if ttl is not None:
            res &= Q("match", **{"traces.hops.ttl": ttl})
        if neg:
            return ~res
        return res

    @classmethod
    def searchhopdomain(cls, hop, neg=False):
        """Filter records by traceroute-hop domain.

        Mirrors :meth:`MongoDB.searchhopdomain`: a ``match``
        against the indexed ``traces.hops.domains`` field.
        """
        return cls._search_field("traces.hops.domains", hop, neg=neg)

    @classmethod
    def searchhopname(cls, hop, neg=False):
        """Filter records by traceroute-hop hostname.

        Mirrors :meth:`MongoDB.searchhopname`: positive matches
        AND the indexed ``traces.hops.domains`` lookup with the
        non-indexed ``traces.hops.host`` match (so the hot path
        still goes through the index even though
        ``traces.hops.host`` is not indexed); negative matches
        only exclude ``traces.hops.host`` so the indexed filter
        does not silently drop legitimate non-matches.
        """
        if neg:
            return cls._search_field("traces.hops.host", hop, neg=True)
        return cls.searchhopdomain(hop) & cls._search_field("traces.hops.host", hop)

    # -- per-port "fingerprint" filters --------------------
    @staticmethod
    def searchldapanon():
        """Filter records exposing an LDAP service that allows
        anonymous binds.

        Mirrors :meth:`MongoDB.searchldapanon`: a single
        ``match`` against ``ports.service_extrainfo`` -- the
        nmap LDAP probe records ``"Anonymous bind OK"`` in
        the service extra-info string when the bind succeeds
        without credentials.
        """
        return Q("match", ports__service_extrainfo="Anonymous bind OK")

    @staticmethod
    def searchvsftpdbackdoor():
        """Filter records exposing the vsftpd 2.3.4 backdoor
        (CVE-2011-2523).

        Mirrors :meth:`MongoDB.searchvsftpdbackdoor`: a nested
        match on the canonical product / version / state
        fingerprint Metasploit's ``ftp/vsftpd_234_backdoor``
        module checks.
        """
        return Q(
            "nested",
            path="ports",
            query=(
                Q("match", ports__protocol="tcp")
                & Q("match", ports__state_state="open")
                & Q("match", ports__service_product="vsftpd")
                & Q("match", ports__service_version="2.3.4")
            ),
        )

    @staticmethod
    def searchwebmin():
        """Filter records exposing a Webmin admin interface.

        Mirrors :meth:`MongoDB.searchwebmin`: nmap's HTTP
        service probe identifies Webmin via
        ``service_product == "MiniServ"`` while leaving
        ``service_extrainfo`` set to something *other* than
        ``"Webmin httpd"`` (which is the regular Apache /
        nginx hosting the admin UI).
        """
        return Q(
            "nested",
            path="ports",
            query=(
                Q("match", ports__service_name="http")
                & Q("match", ports__service_product="MiniServ")
                & ~Q("match", ports__service_extrainfo="Webmin httpd")
            ),
        )

    @classmethod
    def searchhttptitle(cls, title):
        """Filter records by HTTP / HTML page title.

        Mirrors :meth:`MongoDB.searchhttptitle`: delegates to
        :meth:`searchscript` with ``name=["http-title",
        "html-title"]`` so both the modern http-title and the
        legacy html-title NSE script outputs are matched.
        """
        return cls.searchscript(name=["http-title", "html-title"], output=title)

    # -- screenshot / screenwords -----------------------------
    @classmethod
    def searchscreenshot(
        cls,
        port=None,
        protocol="tcp",
        service=None,
        words=None,
        neg=False,
    ):
        """Filter records that have (or, with ``neg=True``,
        lack) a screenshot on at least one port.

        Mirrors :meth:`MongoDB.searchscreenshot`.  ``port`` /
        ``protocol`` / ``service`` constrain the matching
        port; ``words`` filters on the OCR word list.  The
        Mongo-shape semantics are preserved: ``neg=True`` with
        no port / service constraint means *no* port has a
        screenshot (the existence check inverts at the host
        level), whereas ``neg=True`` with a port / service
        constraint inverts the inner predicate so other ports
        on the same host can still keep their screenshots.

        The Elastic implementation routes everything through a
        ``Nested(ports, ...)`` query so the per-port filter is
        evaluated against a single port subdoc; ``ports`` is
        in :attr:`nested_fields`.
        """
        # ``words=None``, no port / service: existence check
        # at the host level (inverts at the EXISTS level on
        # ``neg=True``).
        if words is None and port is None and service is None:
            res = Q(
                "nested",
                path="ports",
                query=Q("exists", field="ports.screenshot"),
            )
            if neg:
                return ~res
            return res
        # ``words`` is set: a screenshot must always exist;
        # the negation flips at the per-port predicate
        # (``screenwords`` excludes the words rather than the
        # whole match).
        port_query = Q("exists", field="ports.screenshot")
        if port is not None:
            port_query &= Q("match", ports__port=port)
            port_query &= Q("match", ports__protocol=protocol)
        if service is not None:
            port_query &= Q("match", ports__service_name=service)
        if words is not None:
            words_q = cls._screenshot_words_predicate(words, neg=neg)
            port_query &= words_q
        elif neg:
            # ``words=None`` with a port / service constraint:
            # invert the per-port screenshot existence.
            port_query = ~Q("exists", field="ports.screenshot")
            if port is not None:
                port_query &= Q("match", ports__port=port)
                port_query &= Q("match", ports__protocol=protocol)
            if service is not None:
                port_query &= Q("match", ports__service_name=service)
        return Q("nested", path="ports", query=port_query)

    @classmethod
    def _screenshot_words_predicate(cls, words, neg=False):
        """Build the ``ports.screenwords`` predicate for
        :meth:`searchscreenshot`.  Matches the four input
        shapes Mongo's helper supports: ``bool`` (existence),
        ``list`` (every word must be present), regex (any
        element matches the pattern), or scalar string (any
        element equals the value).  ``neg=True`` flips the
        polarity at the predicate level (Mongo's ``$ne`` /
        ``$not``); ``words=False`` short-circuits to the
        no-word existence check regardless of ``neg``.
        """
        if isinstance(words, bool):
            res = Q("exists", field="ports.screenwords")
            if not words:
                return ~res
            return res
        if isinstance(words, list):
            lowered = [w.lower() for w in words]
            res = cls.flt_and(*(Q("match", ports__screenwords=w) for w in lowered))
            if neg:
                return ~res
            return res
        if isinstance(words, utils.REGEXP_T):
            pattern = re.compile(words.pattern.lower(), flags=words.flags)
            res = Q("regexp", **{"ports.screenwords": cls._get_pattern(pattern)})
            if neg:
                return ~res
            return res
        # scalar string -- lower-cased to match the
        # pre-stored shape.
        res = Q("match", ports__screenwords=words.lower())
        if neg:
            return ~res
        return res

    # -- searchsmbshares -- direct ``ports.scripts.smb-enum-shares``
    # query; ``ElasticDBActive.searchscript`` cannot translate
    # the nested ``$elemMatch`` / ``$or`` / ``$nin`` shape the
    # Mongo helper builds, so we go via a hand-rolled
    # ``Nested(ports, Nested(ports.scripts, Bool(...)))`` query.
    @classmethod
    def searchsmbshares(cls, access="", hidden=None):
        """Filter SMB shares with the given ``access`` (default:
        either read or write, accepted values 'r', 'w', 'rw').

        ``hidden=True`` selects hidden shares only,
        ``hidden=False`` non-hidden only, ``None`` (the default)
        accepts either.

        Mirrors :meth:`MongoDB.searchsmbshares`.  The Mongo
        helper builds a ``$elemMatch`` / ``$or`` / ``$nin``
        block under ``searchscript(values=...)``;
        :meth:`ElasticDBActive.searchscript` does not translate
        that shape, so the predicate is built directly here.
        """
        access_pattern = {
            "": re.compile("^(READ|WRITE)"),
            "r": re.compile("^READ(/|$)"),
            "w": re.compile("(^|/)WRITE$"),
            "rw": "READ/WRITE",
            "wr": "READ/WRITE",
        }[access.lower()]
        excluded_share_types = (
            "STYPE_IPC_HIDDEN",
            "Not a file share",
            "STYPE_IPC",
            "STYPE_PRINTQ",
        )

        def _access_match(field):
            if isinstance(access_pattern, utils.REGEXP_T):
                return Q(
                    "regexp",
                    **{field: cls._get_pattern(access_pattern)},
                )
            return Q("match", **{field: access_pattern})

        access_q = _access_match(
            "ports.scripts.smb-enum-shares.shares.Anonymous access"
        ) | _access_match("ports.scripts.smb-enum-shares.shares.Current user access")
        if hidden is None:
            type_q = ~Q(
                "terms",
                **{
                    "ports.scripts.smb-enum-shares.shares.Type": list(
                        excluded_share_types
                    )
                },
            )
        elif hidden:
            type_q = Q(
                "match",
                **{
                    "ports.scripts.smb-enum-shares.shares.Type": (
                        "STYPE_DISKTREE_HIDDEN"
                    )
                },
            )
        else:
            type_q = Q(
                "match",
                **{"ports.scripts.smb-enum-shares.shares.Type": "STYPE_DISKTREE"},
            )
        share_q = ~Q(
            "match",
            **{"ports.scripts.smb-enum-shares.shares.Share": "IPC$"},
        )
        return Q(
            "nested",
            path="ports",
            query=Q(
                "nested",
                path="ports.scripts",
                query=Q("match", **{"ports.scripts.id": "smb-enum-shares"})
                & access_q
                & type_q
                & share_q,
            ),
        )

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
            res = Q("match", **{f"openports.{protocol}.ports": port})
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
    def searchports(cls, ports, protocol="tcp", state="open", neg=False, any_=False):
        """Filter records that have all (or any, with
        ``any_=True``) of the listed ports in the given state.

        Mirrors :meth:`MongoDB.searchports`: defaults to
        AND-ing ``searchport(p)`` for every element (so every
        port must be open); ``any_=True`` returns the OR
        instead; ``neg=True`` AND-NOTs each match.

        ``any_`` and ``neg`` are mutually exclusive on Mongo;
        the same restriction applies here.
        """
        if any_ and neg:
            raise ValueError("searchports: cannot set both neg and any_")
        if any_:
            return cls.flt_or(
                *(cls.searchport(p, protocol=protocol, state=state) for p in ports)
            )
        return cls.flt_and(
            *(cls.searchport(p, protocol=protocol, state=state, neg=neg) for p in ports)
        )

    @classmethod
    def searchportsother(cls, ports, protocol="tcp", state="open"):
        """Filter records carrying at least one port (with the
        given ``state`` / ``protocol``) **other** than those
        listed.

        Mirrors :meth:`MongoDB.searchportsother`: a nested
        ``ports`` query with the same protocol / state
        constraints and ``ports.port NOT IN (...)``.  The
        Mongo helper uses ``$elemMatch + $nin`` on the openports
        map for ``state=open``; the Elastic implementation
        uses the same nested-ports path for both ``state=open``
        and other states so the predicate is uniform.
        """
        return Q(
            "nested",
            path="ports",
            query=(
                ~Q("terms", ports__port=ports)
                & Q("match", ports__protocol=protocol)
                & Q("match", ports__state_state=state)
            ),
        )

    @classmethod
    def searchcountopenports(cls, minn=None, maxn=None, neg=False):
        """Filter records whose ``openports.count`` falls in
        the ``[minn, maxn]`` range.

        Mirrors :meth:`MongoDB.searchcountopenports`: equal
        bounds collapse to a ``match`` (or ``must_not`` on
        ``neg=True``); a single bound emits ``range`` with
        ``gte`` / ``lte``; both bounds combine into a single
        ``range`` query (or, on ``neg=True``, an OR of the
        two individual range exclusions, mirroring Mongo's
        ``$or`` of ``$lt`` / ``$gt``).
        """
        if minn is None and maxn is None:
            raise AssertionError(
                "searchcountopenports: at least one of minn or maxn must be set"
            )
        if minn == maxn:
            res = Q("match", **{"openports.count": minn})
            if neg:
                return ~res
            return res
        if neg:
            # Mirror Mongo's ``$or`` of ``$lt`` / ``$gt``: the
            # row passes when ``count`` falls outside *either*
            # bound, so a host with very few open ports still
            # matches even if it has more than ``maxn``.
            clauses = []
            if minn is not None:
                clauses.append(Q("range", **{"openports.count": {"lt": minn}}))
            if maxn is not None:
                clauses.append(Q("range", **{"openports.count": {"gt": maxn}}))
            if len(clauses) == 1:
                return clauses[0]
            return cls.flt_or(*clauses)
        bounds: dict[str, int] = {}
        if minn is not None:
            bounds["gte"] = minn
        if maxn is not None:
            bounds["lte"] = maxn
        return Q("range", **{"openports.count": bounds})

    @classmethod
    def searchfile(cls, fname=None, scripts=None):
        """Filter records exposing a shared file by name (NSE
        ``ls`` module).

        Mirrors :meth:`MongoDB.searchfile`.  ``scripts``
        narrows the script-id space (string, list, or ``None``
        = any of the ``ls``-emitting scripts).
        """
        ls_path = "ports.scripts.ls.volumes.files.filename"
        if fname is None:
            file_q = Q("exists", field=ls_path)
        elif isinstance(fname, list):
            file_q = Q("terms", **{ls_path: fname})
        elif isinstance(fname, utils.REGEXP_T):
            file_q = Q("regexp", **{ls_path: cls._get_pattern(fname)})
        else:
            file_q = Q("match", **{ls_path: fname})
        if scripts is None:
            return Q(
                "nested",
                path="ports",
                query=Q("nested", path="ports.scripts", query=file_q),
            )
        if isinstance(scripts, str):
            scripts = [scripts]
        if len(scripts) == 1:
            id_q = Q("match", **{"ports.scripts.id": scripts[0]})
        else:
            id_q = Q("terms", **{"ports.scripts.id": scripts})
        return Q(
            "nested",
            path="ports",
            query=Q(
                "nested",
                path="ports.scripts",
                query=id_q & file_q,
            ),
        )

    @classmethod
    def searchvuln(cls, vulnid=None, state=None):
        """Filter records exposing a vulnerability matching
        ``vulnid`` and / or ``state``.

        Mirrors :meth:`MongoDB.searchvuln`: with neither
        argument the predicate matches any host with at least
        one ``ports.scripts.vulns.id`` field; with one or
        both, it constrains the matching field on the
        unwound vuln entry.
        """
        if state is None and vulnid is None:
            inner = Q("exists", field="ports.scripts.vulns.id")
        elif state is None:
            if isinstance(vulnid, utils.REGEXP_T):
                inner = Q(
                    "regexp",
                    **{"ports.scripts.vulns.id": cls._get_pattern(vulnid)},
                )
            else:
                inner = Q("match", **{"ports.scripts.vulns.id": vulnid})
        elif vulnid is None:
            inner = Q("match", **{"ports.scripts.vulns.state": state})
        else:
            inner = Q("match", **{"ports.scripts.vulns.id": vulnid}) & Q(
                "match", **{"ports.scripts.vulns.status": state}
            )
        return Q(
            "nested",
            path="ports",
            query=Q("nested", path="ports.scripts", query=inner),
        )

    @staticmethod
    def searchvulnintersil():
        """Filter records exposing the Intersil HTTPd password
        reset vulnerability (Boa HTTPd, MSF
        ``admin/http/intersil_pass_reset``).

        Mirrors :meth:`MongoDB.searchvulnintersil`: a nested
        ``ports`` match on the canonical product / version
        regex the MSF module checks.
        """
        return Q(
            "nested",
            path="ports",
            query=(
                Q("match", ports__protocol="tcp")
                & Q("match", ports__state_state="open")
                & Q("match", ports__service_product="Boa HTTPd")
                & Q(
                    "regexp",
                    ports__service_version=(
                        # Intersil firmware versions matching
                        # the MSF probe.
                        "0\\.9(3([^0-9]|).*"
                        "|4\\.([0-9]|0[0-9]|1[0-1])([^0-9]|).*)"
                    ),
                )
            ),
        )

    @classmethod
    def searchcpe(cls, cpe_type=None, vendor=None, product=None, version=None):
        """Filter records by CPE.  No argument matches any host
        with at least one CPE; otherwise the named fields are
        AND-ed against the same CPE entry (``cpes`` is a flat
        array of objects on the Elasticsearch schema -- not
        declared in :attr:`nested_fields` -- so a host with
        ``cpes = [{vendor: A, product: P}, {vendor: B, product:
        Q}]`` would match ``searchcpe(vendor="A", product="Q")``
        even though no single entry has both; this matches the
        existing schema's flat-array semantics for
        ``hostnames.*`` and the rest of the non-nested arrays).

        Mirrors :meth:`MongoDB.searchcpe`.
        """
        fields = [
            ("type", cpe_type),
            ("vendor", vendor),
            ("product", product),
            ("version", version),
        ]
        flt = [(name, value) for name, value in fields if value is not None]
        if not flt:
            return Q("exists", field="cpes")
        clauses = []
        for name, value in flt:
            if isinstance(value, utils.REGEXP_T):
                clauses.append(Q("regexp", **{f"cpes.{name}": cls._get_pattern(value)}))
            else:
                clauses.append(Q("match", **{f"cpes.{name}": value}))
        return cls.flt_and(*clauses)

    @classmethod
    def searchos(cls, txt):
        """Filter records by OS detection.  ``txt`` is matched
        against any of ``os.osclass.{vendor, osfamily, osgen,
        type}`` -- the same four sub-keys :meth:`MongoDB.searchos`
        ORs.
        """
        keys = ("vendor", "osfamily", "osgen", "type")
        if isinstance(txt, utils.REGEXP_T):
            pattern = cls._get_pattern(txt)
            return cls.flt_or(
                *(Q("regexp", **{f"os.osclass.{key}": pattern}) for key in keys)
            )
        return cls.flt_or(*(Q("match", **{f"os.osclass.{key}": txt}) for key in keys))

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
                req.append(Q("match", **{f"ports.scripts.{key}": values}))
            elif isinstance(values, utils.REGEXP_T):
                req.append(
                    Q(
                        "regexp",
                        **{f"ports.scripts.{key}": cls._get_pattern(values)},
                    )
                )
            else:
                for field, value in values.items():
                    if isinstance(value, utils.REGEXP_T):
                        req.append(
                            Q(
                                "regexp",
                                **{
                                    f"ports.scripts.{key}.{field}": cls._get_pattern(
                                        value
                                    )
                                },
                            )
                        )
                    else:
                        req.append(
                            Q(
                                "match",
                                **{f"ports.scripts.{key}.{field}": value},
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

    @classmethod
    def searchcert(
        cls,
        keytype=None,
        md5=None,
        sha1=None,
        sha256=None,
        subject=None,
        issuer=None,
        self_signed=None,
        pkmd5=None,
        pksha1=None,
        pksha256=None,
        cacert=False,
        neg=False,
    ):
        req = []
        if keytype is not None:
            req.append(Q("match", **{"ports.scripts.ssl-cert.pubkey.type": keytype}))
        for hashtype in ["md5", "sha1", "sha256"]:
            hashval = locals()[hashtype]
            if hashval is None:
                continue
            key = f"ports.scripts.ssl-cert.{hashtype}"
            if isinstance(hashval, utils.REGEXP_T):
                req.append(Q("regexp", **{key: cls._get_pattern(hashval).lower()}))
                continue
            if isinstance(hashval, list):
                req.append(Q("terms", **{key: [val.lower() for val in hashval]}))
                continue
            req.append(Q("match", **{key: hashval.lower()}))
        if subject is not None:
            if isinstance(subject, utils.REGEXP_T):
                req.append(
                    Q(
                        "regexp",
                        **{
                            "ports.scripts.ssl-cert.subject_text": cls._get_pattern(
                                subject
                            )
                        },
                    )
                )
            else:
                req.append(
                    Q("match", **{"ports.scripts.ssl-cert.subject_text": subject})
                )
        if issuer is not None:
            if isinstance(issuer, utils.REGEXP_T):
                req.append(
                    Q(
                        "regexp",
                        **{
                            "ports.scripts.ssl-cert.issuer_text": cls._get_pattern(
                                issuer
                            )
                        },
                    )
                )
            else:
                req.append(Q("match", **{"ports.scripts.ssl-cert.issuer_text": issuer}))
        if self_signed is not None:
            req.append(
                Q("match", **{"ports.scripts.ssl-cert.self_signed": self_signed})
            )
        for hashtype in ["md5", "sha1", "sha256"]:
            hashval = locals()[f"pk{hashtype}"]
            if hashval is None:
                continue
            key = f"ports.scripts.ssl-cert.pubkey.{hashtype}"
            if isinstance(hashval, utils.REGEXP_T):
                req.append(Q("regexp", **{key: cls._get_pattern(hashval).lower()}))
                continue
            if isinstance(hashval, list):
                req.append(Q("terms", **{key: [val.lower() for val in hashval]}))
                continue
            req.append(Q("match", **{key: hashval.lower()}))
        if req:
            res = Q(
                "nested",
                path="ports",
                query=Q(
                    "nested",
                    path="ports.scripts",
                    query=cls.flt_and(
                        Q(
                            "match",
                            **{
                                "ports.scripts.id": (
                                    "ssl-cacert" if cacert else "ssl-cert"
                                )
                            },
                        ),
                        Q(
                            "nested",
                            path="ports.scripts.ssl-cert",
                            query=cls.flt_and(*req),
                        ),
                    ),
                ),
            )
        else:
            res = Q(
                "nested",
                path="ports",
                query=Q(
                    "nested",
                    path="ports.scripts",
                    query=Q(
                        "match",
                        **{"ports.scripts.id": "ssl-cacert" if cacert else "ssl-cert"},
                    ),
                ),
            )
        if neg:
            return ~res
        return res

    @classmethod
    def searchtext(cls, text, neg=False):
        """Filter records that match the free-text ``text``
        across every text-bearing field declared in
        :attr:`DBActive.text_fields`.

        Mirrors the contract of :meth:`MongoDB.searchtext`
        (``{"$text": {"$search": text}}``) and
        :meth:`SQLDBActive.searchtext` (the ``OR``-of-``EXISTS``
        over text-bearing child tables): a single
        ``searchtext("foo")`` matches any host with ``foo``
        somewhere in its hostnames, tags, ports, scripts,
        traces, categories, or OS / CPE attributes.

        Composes one ``multi_match`` query per nesting level:

        * Fields under a path declared in :attr:`nested_fields`
          (``ports.*``, ``ports.scripts.*``, ``tags.*``) are
          wrapped in a ``nested`` query against the appropriate
          path so Elasticsearch evaluates the match against the
          inner document; a top-level ``multi_match`` against a
          nested-typed field silently returns nothing.
        * Remaining fields (``categories``, ``cpes.*``,
          ``hostnames.*``, ``os.*``, ``traces.hops.host``)
          fan out under a single root-level ``multi_match``.

        The per-group queries are OR-combined; ``neg=True``
        wraps the whole result in :class:`elasticsearch_dsl.query.Bool`'s
        ``~`` (i.e. ``must_not``).
        """
        # Group :attr:`text_fields` by their nested ancestor
        # (longest prefix match in :attr:`nested_fields`).
        nested_paths = sorted(cls.nested_fields, key=len, reverse=True)
        flat_fields: list[str] = []
        nested_groups: dict[str, list[str]] = {}
        for field in cls.text_fields:
            for path in nested_paths:
                if field == path or field.startswith(f"{path}."):
                    nested_groups.setdefault(path, []).append(field)
                    break
            else:
                flat_fields.append(field)

        queries: list[Q] = []
        if flat_fields:
            queries.append(Q("multi_match", query=text, fields=flat_fields))
        for path, fields in nested_groups.items():
            queries.append(
                Q(
                    "nested",
                    path=path,
                    query=Q("multi_match", query=text, fields=fields),
                )
            )

        if not queries:
            # No text fields declared on this backend: a
            # ``searchtext`` call is a guaranteed mismatch
            # (positive search) or a tautology (negation).
            return cls.flt_empty if neg else cls.searchnonexistent()

        result = queries[0]
        for query in queries[1:]:
            result = result | query
        if neg:
            return ~result
        return result

    @classmethod
    def searchhassh(cls, value_or_hash=None, server=None):
        if server is None:
            return cls._searchhassh(value_or_hash=value_or_hash)
        if value_or_hash is None:
            baseflt = Q(
                "nested",
                path="ports.scripts",
                query=Q("match", ports__scripts__id="ssh2-enum-algos"),
            )
        else:
            # this is not JA3, but we have the exact same logic & needs
            key, value = cls._ja3keyvalue(value_or_hash)
            if isinstance(value, utils.REGEXP_T):
                valflt = Q(
                    "regexp",
                    **{
                        f"ports.scripts.ssh2-enum-algos.hassh.{key}": cls._get_pattern(
                            value
                        )
                    },
                )
            else:
                valflt = Q(
                    "match", **{f"ports.scripts.ssh2-enum-algos.hassh.{key}": value}
                )
            baseflt = Q(
                "nested",
                path="ports.scripts",
                query=Q("match", ports__scripts__id="ssh2-enum-algos") & Q(valflt),
            )
        if server:
            portflt = ~Q("match", ports__port=-1)
        else:
            portflt = Q("match", ports__port=-1)
        return Q("nested", path="ports", query=portflt & baseflt)


class ElasticDBView(ElasticDBActive, DBView):
    def __init__(self, url):
        super().__init__(url)
        self.indexes = [
            f"{self.index_prefix}{self.params.pop('indexname_hosts', 'views')}"
        ]

    def store_or_merge_host(self, host):
        if not self.merge_host(host):
            self.store_host(host)

    @classmethod
    def searchtag(cls, tag=None, neg=False):
        """Filters (if `neg` == True, filters out) one particular tag (records
        may have zero, one or more tags).

        `tag` may be the value (as a str) or the tag (as a Tag, e.g.:
        `{"value": value, "info": info}`).

        """
        if not tag:
            res = Q("exists", field="tags.value")
            if neg:
                return ~res
            return res
        if not isinstance(tag, dict):
            tag = {"value": tag}
        all_res = []
        for key, value in tag.items():
            if isinstance(value, list) and len(value) == 1:
                value = value[0]
            if isinstance(value, list):
                res = Q("terms", **{f"tags.{key}": value})
            elif isinstance(value, utils.REGEXP_T):
                res = Q("regexp", **{f"tags.{key}": cls._get_pattern(value)})
            else:
                res = Q("match", **{f"tags.{key}": value})
            if neg:
                all_res.append(~res)
            else:
                all_res.append(res)
        if neg:
            return cls.flt_or(
                ~Q("exists", field="tags.value"),
                Q("nested", path="tags", query=cls.flt_or(*all_res)),
            )
        return Q("nested", path="tags", query=cls.flt_and(*all_res))

    @classmethod
    def searchcountry(cls, country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        return cls._search_field(
            "infos.country_code", utils.country_unalias(country), neg=neg
        )

    @classmethod
    def searchcity(cls, city, neg=False):
        """Filter records by GeoIP city.  Mirrors
        :meth:`MongoDB.searchcity` (a ``match`` on
        ``infos.city`` with the regex / list / scalar dispatch
        :meth:`_search_field` provides).
        """
        return cls._search_field("infos.city", city, neg=neg)

    @classmethod
    def searchasnum(cls, asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s). The legacy form coerced every
        element to ``int(...)`` blindly; preserve that here so
        ``"AS1234"``-prefixed strings still raise the same
        ``ValueError`` they did before \u2014 callers that want
        the prefix-stripping shape can pre-process via the
        ``MongoDB`` backend's ``_coerce_asnum`` mirror.
        """
        if not isinstance(asnum, str) and hasattr(asnum, "__iter__"):
            asnum = [int(val) for val in asnum]
        else:
            asnum = int(asnum)
        return cls._search_field("infos.as_num", asnum, neg=neg)

    @classmethod
    def searchasname(cls, asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        return cls._search_field("infos.as_name", asname, neg=neg)

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


load_plugins("ivre.plugins.db.elastic", globals())
