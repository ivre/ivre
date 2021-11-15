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

"""This sub-module contains functions to interact with the database
backends.

"""

from argparse import ArgumentParser
from collections import OrderedDict
from datetime import datetime, timedelta
from functools import reduce
from importlib import import_module
import json
import os
import pickle
import pipes
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
import uuid
import xml.sax


# tests: I don't want to depend on cluster for now
try:
    import cluster  # type: ignore

    USE_CLUSTER = True
except ImportError:
    USE_CLUSTER = False


from ivre import config, geoiputils, nmapout, passive, utils, xmlnmap, flow
from ivre.active.data import (
    ALIASES_TABLE_ELEMS,
    merge_host_docs,
    set_openports_attribute,
)
from ivre.zgrabout import ZGRAB_PARSERS


class DB:
    """The base database object. Must remain backend-independent and
    purpose-independent.

    For now, the only implemented backend is MongoDB, and there are
    three purposes: Nmap, Passive and Data.

    It is not mandatory for each backend to be ready to be used for
    each purpose (e.g., an SQL backend would probably fit for the
    Passive and Data purposes but not for the Nmap purpose). We need a
    subclass for each (backend, purpose) combination wanted.

    We have backend-independent, purpose-specific subclasses to factor
    some code, and purpose-independent, backend-specific subclasses
    for the same reason.

    The backend-specific purpose-specific classes inherit from both
    the relevant backend-independent, purpose-specific class and the
    relevant purpose-independent, backend-specific class.

    """

    globaldb = None
    ipaddr_fields = []
    datetime_fields = []
    list_fields = []

    def __init__(self):
        self.argparser = ArgumentParser(add_help=False)
        self.argparser.add_argument(
            "--country", metavar="CODE", help="show only results from this country"
        )
        self.argparser.add_argument(
            "--asnum",
            metavar="NUM[,NUM[...]]",
            help="show only results from this(those) AS(es)",
        )
        self.argparser.add_argument("--port", metavar="PORT")
        self.argparser.add_argument("--service", metavar="SVC[:PORT]")
        self.argparser.add_argument("--svchostname", metavar="HOSTNAME")
        self.argparser.add_argument("--product", metavar="[SVC:]PROD")
        self.argparser.add_argument(
            "--useragent", metavar="USER-AGENT", nargs="?", const=False
        )
        self.argparser.add_argument("--host", metavar="IP")
        self.argparser.add_argument("--range", metavar="IP", nargs=2)
        self.argparser.add_argument("--net", metavar="IP/MASK")
        self.argparser.add_argument("--ipv4", action="store_true")
        self.argparser.add_argument("--ipv6", action="store_true")
        self.argparser.add_argument(
            "ips",
            nargs="*",
            help="Display results for specified IP " "addresses or ranges.",
        )

    def parse_args(self, args, flt=None):
        if flt is None:
            flt = self.flt_empty
        if args.country is not None:
            flt = self.flt_and(flt, self.searchcountry(utils.str2list(args.country)))
        if args.asnum is not None:
            if args.asnum[:1] in "!-":
                flt = self.flt_and(
                    flt, self.searchasnum(utils.str2list(args.asnum[1:]), neg=True)
                )
            else:
                flt = self.flt_and(flt, self.searchasnum(utils.str2list(args.asnum)))
        if args.port is not None:
            port = args.port.replace("_", "/")
            if "/" in port:
                proto, port = port.split("/", 1)
            else:
                proto = "tcp"
            port = int(port)
            flt = self.flt_and(flt, self.searchport(port=port, protocol=proto))
        if args.service is not None:
            try:
                svc, port = args.service.split(":", 1)
            except ValueError:
                svc = args.service
                port = None
            else:
                port = int(port)
            flt = self.flt_and(
                flt,
                self.searchservice(utils.str2regexpnone(svc), port=port),
            )
        if args.product is not None:
            try:
                svc, prod = args.product.split(":", 1)
            except ValueError:
                svc = None
                prod = args.product
                port = None
            else:
                svc = utils.str2regexpnone(svc)
                if ":" in prod:
                    prod, port = prod.split(":", 1)
                    port = int(port)
                else:
                    port = None
            flt = self.flt_and(
                flt,
                self.searchproduct(
                    product=utils.str2regexpnone(prod),
                    service=svc,
                    port=port,
                ),
            )
        if args.svchostname is not None:
            flt = self.flt_and(
                flt, self.searchsvchostname(utils.str2regexp(args.svchostname))
            )
        if args.useragent is not None:
            if args.useragent is False:
                flt = self.flt_and(flt, self.searchuseragent())
            else:
                flt = self.flt_and(
                    flt,
                    self.searchuseragent(useragent=utils.str2regexp(args.useragent)),
                )
        if args.host is not None:
            flt = self.flt_and(flt, self.searchhost(args.host))
        if args.net is not None:
            flt = self.flt_and(flt, self.searchnet(args.net))
        if args.range is not None:
            flt = self.flt_and(flt, self.searchrange(*args.range))
        if args.ipv4:
            flt = self.flt_and(flt, self.searchipv4())
        if args.ipv6:
            flt = self.flt_and(flt, self.searchipv6())
        if args.ips:

            def _updtflt_(oflt, nflt):
                if not oflt:
                    return nflt
                return self.flt_or(oflt, nflt)

            loc_flt = None
            for a in args.ips:
                if "-" in a:
                    a = a.split("-", 1)
                    if a[0].isdigit():
                        a[0] = int(a[0])
                    if a[1].isdigit():
                        a[1] = int(a[1])
                    loc_flt = _updtflt_(loc_flt, self.searchrange(a[0], a[1]))
                elif "/" in a:
                    loc_flt = _updtflt_(loc_flt, self.searchnet(a))
                else:
                    if a.isdigit():
                        a = self.ip2internal(int(a))
                    loc_flt = _updtflt_(loc_flt, self.searchhost(a))
            flt = self.flt_and(flt, loc_flt)
        return flt

    @staticmethod
    def to_binary(data):
        return data

    @staticmethod
    def from_binary(data):
        return data

    # filters

    @classmethod
    def flt_and(cls, *args):
        """Returns a condition that is true iff all of the given
        conditions is true.

        """
        if args:
            return reduce(cls._flt_and, args)
        return cls.flt_empty

    @staticmethod
    def _flt_and(cond1, cond2):
        """Returns a condition that is true iff both `cond1` and
        `cond2` are true.

        This is typically implemented in the backend-specific
        subclass.

        """
        raise NotImplementedError

    @classmethod
    def flt_or(cls, *args):
        """Returns a condition that is true iff any of the given
        conditions is true.

        """
        if args:
            return reduce(cls._flt_or, args)
        return cls.flt_empty

    @staticmethod
    def _flt_or(cond1, cond2):
        """Returns a condition that is true iff either `cond1` or
        `cond2` is true.

        This is typically implemented in the backend-specific
        subclass.

        """
        raise NotImplementedError

    @staticmethod
    def ip2internal(addr):
        """Converts an IP address (given as either an integer or a string) to
        the internal value used by the backend.

        """
        raise NotImplementedError

    @staticmethod
    def internal2ip(addr):
        """Converts an IP address (given as the internal value used by the backend) to
        its classical form as a string.

        """
        raise NotImplementedError

    @staticmethod
    def features_addr_list(use_asnum, use_ipv6, use_single_int):
        """Returns a list of IP address features (for ML algorithms)

        If `use_asnum` is true, the first element is the AS number associated
        with the address (or 0 if no AS number has been found).

        If `use_single_int` is true, the next value is an integer representing
        the IP address (IPv4 addresses are converted to IPv6 using the
        standard ::ffff:A.B.C.D mapping when `use_ipv6` is true).

        If `use_single_int` is false, the next values are each byte of the IP
        address (4 bytes if `use_ipv6` is false, 16 otherwise, using the
        standard ::ffff:A.B.C.D mapping for IPv4 addresses).

        """
        result = ["asnum"] if use_asnum else []
        if use_single_int:
            return result + ["addr"]
        return result + ["addr_%d" % d for d in range(16 if use_ipv6 else 4)]

    def features_addr_get(self, addr, use_asnum, use_ipv6, use_single_int):
        """Returns a list of feature values (for ML algorithms) for an IP address.

        See .features_addr_list() for the number and meaning of the features.

        """
        if use_asnum:
            result = [self.globaldb.data.as_byip(addr).get("as_num", 0)]
        else:
            result = []
        if use_single_int:
            if use_ipv6:
                return result + [
                    utils.ip2int(addr if ":" in addr else ("::ffff:%s" % addr))
                ]
            return result + [utils.ip2int(addr)]
        addrbin = utils.ip2bin(addr)
        if use_ipv6:
            return result + list(addrbin)
        return result + list(addrbin)[-4:]

    def features_port_list(self, flt, yieldall, use_service, use_product, use_version):
        """Returns a list of ports features (for ML algorithms) as tuples of
        existing values.

        The first element of each tuple is the port number; if `use_service`
        is true, the next element is the service name; if `use_product` is
        true, the next element is the product name; if `use_version` is true,
        the next element is the string representing the version.

        If `yieldall` is true, when a specific feature exists (e.g., `(80,
        'http', 'Apache httpd')`), more generic features are also generated
        (e.g., `(80, 'http', None)`, `(80, None, None)`).

        `use_version` implies `use_product`, and `use_product` implies
        `use_service`.

        """
        if not yieldall:
            return list(
                tuple(val)
                for val in self._features_port_list(
                    flt, yieldall, use_service, use_product, use_version
                )
            )

        def _gen(val):
            val = list(val)
            yield tuple(val)
            for i in range(-1, -len(val), -1):
                val[i] = None
                yield tuple(val)

        return sorted(
            set(
                val
                for vals in self._features_port_list(
                    flt, yieldall, use_service, use_product, use_version
                )
                for val in _gen(vals)
            ),
            key=lambda val: [utils.key_sort_none(v) for v in val],
        )

    def _features_port_list(self, flt, yieldall, use_service, use_product, use_version):
        raise NotImplementedError()

    def features_port_get(
        self, features, flt, yieldall, use_service, use_product, use_version
    ):
        """Generates `(addr, port_features)` tuples where `addr` is a host IP
        address and `port_features` a list of values ports feature values (for ML
        algorithms) as lists of values.

        `features` is a list of features that may be generated, as provided by
        .features_port_list().

        """
        features = dict((f, i) for i, f in enumerate(features))
        return self._features_port_get(
            features, flt, yieldall, use_service, use_product, use_version
        )

    def _features_port_get(
        self, features, flt, yieldall, use_service, use_product, use_version
    ):
        raise NotImplementedError()

    def features(
        self,
        flt=None,
        use_asnum=True,
        use_ipv6=True,
        use_single_int=False,
        yieldall=True,
        use_service=True,
        use_product=False,
        use_version=False,
        subflts=None,
    ):
        """Returns a two-element tuple. The first element is a list on feature
        names, the second is a generator of lists of feature values. This is
        meant to be used with ML algorithms.

        `flt` is a base filter, (`.flt_empty` will be used by default).

        If `subflts` is provided, it must be a list of filters, or a list of
        (label, filter) tuples. A "category" field will be appended at the end
        of the feature values, which will be set to the index (or label) of
        the sub-filter used to generate the result.

        For example, to find differences between two networks, one could do:

            columns, data = dbase.features(subflts=[dbase.searchasnum(1234),
                                                    dbase.searchasnum(4321)])

        The last value of each result generated by data will be 0 for AS
        number 1234 and 1 for AS number 4321.

        One can add a label:

            columns, data = dbase.features(subflts=[
                ("AS1234", dbase.searchasnum(1234)),
                ("AS4321", dbase.searchasnum(4321)),
            ])

        The last value of each result generated by data will be either
        "AS1234" or "AS4321".

        To use this to create a pandas DataFrame, you can run:

            import pandas
            columns, data = dbase.features()
            df = pandas.DataFrame(data=data, columns=columns)

        """
        if flt is None:
            flt = self.flt_empty
        use_service = use_service or use_product or use_version
        use_product = use_product or use_version
        features_port = self.features_port_list(
            flt,
            yieldall,
            use_service,
            use_product,
            use_version,
        )
        headers = (
            self.features_addr_list(
                use_asnum,
                use_ipv6,
                use_single_int,
            )
            + features_port
        )
        if subflts:
            if isinstance(subflts[0], (list, tuple)) and len(subflts[0]) == 2:
                generator = subflts
            else:
                generator = enumerate(subflts)
            headers.append("category")
            return (
                headers,
                (
                    self.features_addr_get(
                        addr,
                        use_asnum,
                        use_ipv6,
                        use_single_int,
                    )
                    + features
                    + [label]
                    for label, subflt in generator
                    for addr, features in self.features_port_get(
                        features_port,
                        self.flt_and(flt, subflt),
                        yieldall,
                        use_service,
                        use_product,
                        use_version,
                    )
                ),
            )
        return (
            headers,
            (
                self.features_addr_get(addr, use_asnum, use_ipv6, use_single_int)
                + features
                for addr, features in self.features_port_get(
                    features_port,
                    flt,
                    yieldall,
                    use_service,
                    use_product,
                    use_version,
                )
            ),
        )

    @staticmethod
    def searchversion(version):
        """Filters documents based on their schema's version."""
        raise NotImplementedError

    @classmethod
    def searchnet(cls, net, neg=False):
        """Filters (if `neg` == True, filters out) one particular IP
        network (CIDR notation).

        """
        return cls.searchrange(*utils.net2range(net), neg=neg)

    @staticmethod
    def searchrange(start, stop, neg=False):
        """Filters (if `neg` == True, filters out) one particular IP
        range given its boundaries `start` and `stop`.

        """
        raise NotImplementedError

    @staticmethod
    def searchhost(addr, neg=False):
        raise NotImplementedError

    @classmethod
    def searchipv4(cls):
        return cls.searchnet("0.0.0.0/0")

    @classmethod
    def searchipv6(cls):
        return cls.searchnet("0.0.0.0/0", neg=True)

    @classmethod
    def searchval(cls, key, val):
        return cls.searchcmp(key, val, "=")

    def searchphpmyadmin(self):
        """Finds phpMyAdmin instances based on its cookies."""
        return self.searchcookie("phpMyAdmin")

    def searchcookie(self, name):
        """Finds specific cookie names.

        This is typically implemented in the backend-specific
        purpose-specific subclass.

        """
        raise NotImplementedError

    def searchwebfiles(self):
        """Finds shared files or directories that are typical of a web
        application.

        Being able to write web files often leads to arbitrary code
        execution.

        Being able to read directly web files (without a
        PHP/ASP/... interpreter) often leads to privilege escalation
        in the application and sometimes to arbitrary code
        execution by finding backdoors/shells/vulnerabilities.

        """
        return self.searchfile(
            fname=re.compile(
                "vhost|www|web\\.config|\\.htaccess|\\.([aj]sp|php|html?|js|css)", re.I
            )
        )

    def searchfile(self, fname=None, scripts=None):
        """Finds shared files or directories from a name or a
        pattern.

        """
        raise NotImplementedError

    def searchjavaua(self):
        """Finds Java User-Agent."""
        return self.searchuseragent(
            useragent=re.compile("(^| )(Java|javaws)/", flags=0),
        )

    @staticmethod
    def searchuseragent(useragent=None, neg=False):
        """Finds specified User-Agent(s)."""
        raise NotImplementedError

    def get(self, spec, **kargs):
        """Gets a cursor, which can be iterated to get results.

        The type of that cursor is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    @staticmethod
    def getid(record):
        """Gets a unique identifier for a specified `record`.

        The type of the identifier is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        return record["_id"]

    @classmethod
    def searchid(cls, oid, neg=False):
        """Gets a specific record given its unique identifier `idval`.

        Alias for .searchobjectid().

        """
        return cls.searchobjectid(oid, neg=neg)

    @classmethod
    def searchobjectid(cls, oid, neg=False):
        """Filters records by their ObjectID.  `oid` can be a single or many
        (as a list or any iterable) object ID(s), specified as strings
        or an `ObjectID`s.

        """
        raise NotImplementedError

    @classmethod
    def searchtorcert(cls):
        expr = re.compile("^commonName=www\\.[a-z2-7]{8,20}\\.(net|com)$", flags=0)
        return cls.searchcert(
            subject=expr,
            issuer=expr,
        )

    @classmethod
    def searchcertsubject(cls, expr, issuer=None):
        utils.LOGGER.info(
            "The API .searchcertsubject() is deprecated and will be removed. "
            "Use .searchcert() instead."
        )
        return cls.searchcert(subject=expr, issuer=issuer)

    @classmethod
    def searchcertissuer(cls, expr):
        utils.LOGGER.info(
            "The API .searchcertissuer() is deprecated and will be removed. "
            "Use .searchcert() instead."
        )
        return cls.searchcert(issuer=expr)

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
    ):
        """Look for a particular certificate"""
        raise NotImplementedError

    @staticmethod
    def _ja3keyvalue(value_or_hash):
        """Returns the key and the value to search for according
        to the nature of the given argument for ja3 filtering"""
        if isinstance(value_or_hash, utils.REGEXP_T):
            return ("raw", value_or_hash)
        if utils.HEX.search(value_or_hash):
            key = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value_or_hash), "raw")
        else:
            key = "raw"
        # If we have the raw value, we compute the MD5 hash because it
        # is indexed, so it will be faster to query.
        if key == "raw":
            return (
                "md5",
                utils.hashlib.new("md5", value_or_hash.encode()).hexdigest(),
            )
        return (key, value_or_hash.lower())

    @staticmethod
    def str2id(string):
        """Returns a unique identifier from `string`.

        The type of the identifier is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    if USE_CLUSTER:

        @staticmethod
        def hierarchical_clustering(values):
            """Returns a cluster"""
            return cluster.HierarchicalClustering(
                list(values),
                lambda x, y: abs(x["mean"] - y["mean"]),
            )

    @staticmethod
    def serialize(obj):
        return utils.serialize(obj)

    @staticmethod
    def cmp_schema_version(*_):
        return 0

    def display_top(self, arg, flt, lmt):
        field, least = (arg[1:], True) if arg[:1] in "!-~" else (arg, False)
        if lmt is None:
            lmt = 10
        elif lmt == 0:
            lmt = None
        for entry in self.topvalues(field, flt=flt, topnbr=lmt, least=least):
            if isinstance(entry["_id"], (list, tuple)):
                sep = " / " if isinstance(entry["_id"], tuple) else ", "
                if entry["_id"]:
                    if isinstance(entry["_id"][0], (list, tuple)):
                        entry["_id"] = sep.join(
                            "/".join(str(subelt) for subelt in elt) if elt else "None"
                            for elt in entry["_id"]
                        )
                    elif isinstance(entry["_id"][0], dict):
                        entry["_id"] = sep.join(
                            json.dumps(elt, default=utils.serialize)
                            for elt in entry["_id"]
                        )
                    else:
                        entry["_id"] = sep.join(str(elt) for elt in entry["_id"])
                else:
                    entry["_id"] = "None"
            elif isinstance(entry["_id"], dict):
                entry["_id"] = json.dumps(entry["_id"], default=utils.serialize)
            elif not entry["_id"]:
                entry["_id"] = "None"
            yield "%(_id)s: %(count)d\n" % entry


class DBActive(DB):

    ipaddr_fields = ["addr", "traces.hops.ipaddr", "ports.state_reason_ip"]
    datetime_fields = [
        "starttime",
        "endtime",
        "ports.scripts.ssl-cert.not_after",
        "ports.scripts.ssl-cert.not_before",
    ]
    list_fields = [
        "categories",
        "cpes",
        "openports.udp.ports",
        "openports.tcp.ports",
        "os.osclass",
        "os.osmatch",
        "ports",
        "ports.screenwords",
        "ports.scripts",
        "ports.scripts.dns-domains",
        "ports.scripts.dns-domains.parents",
        "ports.scripts.dns-zone-transfer",
        "ports.scripts.dns-zone-transfer.records",
        "ports.scripts.fcrdns",
        "ports.scripts.fcrdns.addresses",
        "ports.scripts.http-app",
        "ports.scripts.http-headers",
        "ports.scripts.http-nuclei",
        "ports.scripts.http-server-header",
        "ports.scripts.http-user-agent",
        "ports.scripts.ike-info.transforms",
        "ports.scripts.ike-info.vendor_ids",
        "ports.scripts.ls.volumes",
        "ports.scripts.ls.volumes.files",
        "ports.scripts.ms-sql-info",
        "ports.scripts.mongodb-databases.databases",
        "ports.scripts.mongodb-databases.databases.shards",
        "ports.scripts.rpcinfo",
        "ports.scripts.rpcinfo.version",
        "ports.scripts.scanner.http_uris",
        "ports.scripts.scanner.ports.tcp.ports",
        "ports.scripts.scanner.ports.udp.ports",
        "ports.scripts.scanner.probes",
        "ports.scripts.scanner.scanners",
        "ports.scripts.scanner.scanners.probes",
        "ports.scripts.smb-enum-shares.shares",
        "ports.scripts.ssh-hostkey",
        "ports.scripts.ssl-cert",
        "ports.scripts.ssl-ja3-client",
        "ports.scripts.ssl-ja3-server",
        "ports.scripts.vulns",
        "ports.scripts.vulns.check_results",
        "ports.scripts.vulns.description",
        "ports.scripts.vulns.extra_info",
        "ports.scripts.vulns.ids",
        "ports.scripts.vulns.refs",
        "traces",
        "traces.hops",
        "hostnames",
        "hostnames.domains",
    ]

    def __init__(self):
        super().__init__()
        self._schema_migrations = {
            "hosts": {
                None: (1, self.__migrate_schema_hosts_0_1),
                1: (2, self.__migrate_schema_hosts_1_2),
                2: (3, self.__migrate_schema_hosts_2_3),
                3: (4, self.__migrate_schema_hosts_3_4),
                4: (5, self.__migrate_schema_hosts_4_5),
                5: (6, self.__migrate_schema_hosts_5_6),
                6: (7, self.__migrate_schema_hosts_6_7),
                7: (8, self.__migrate_schema_hosts_7_8),
                8: (9, self.__migrate_schema_hosts_8_9),
                9: (10, self.__migrate_schema_hosts_9_10),
                10: (11, self.__migrate_schema_hosts_10_11),
                11: (12, self.__migrate_schema_hosts_11_12),
                12: (13, self.__migrate_schema_hosts_12_13),
                13: (14, self.__migrate_schema_hosts_13_14),
                14: (15, self.__migrate_schema_hosts_14_15),
                15: (16, self.__migrate_schema_hosts_15_16),
                16: (17, self.__migrate_schema_hosts_16_17),
                17: (18, self.__migrate_schema_hosts_17_18),
                18: (19, self.__migrate_schema_hosts_18_19),
            },
        }
        self.argparser.add_argument(
            "--category", metavar="CAT", help="show only results from this category"
        )
        self.argparser.add_argument(
            "--asname", metavar="NAME", help="show only results from this(those) AS(es)"
        )
        self.argparser.add_argument(
            "--source", metavar="SRC", help="show only results from this source"
        )
        self.argparser.add_argument("--version", metavar="VERSION", type=int)
        self.argparser.add_argument("--timeago", metavar="SECONDS", type=int)
        self.argparser.add_argument(
            "--id",
            metavar="ID",
            help="show only " "results with this(those) ID(s)",
            nargs="+",
        )
        self.argparser.add_argument(
            "--no-id",
            metavar="ID",
            help="show " "only results WITHOUT this(those) " "ID(s)",
            nargs="+",
        )
        self.argparser.add_argument("--hostname", metavar="NAME / ~NAME")
        self.argparser.add_argument("--domain", metavar="NAME / ~NAME")
        self.argparser.add_argument("--hop", metavar="IP")
        self.argparser.add_argument("--not-port", metavar="PORT")
        self.argparser.add_argument("--openport", action="store_true")
        self.argparser.add_argument("--no-openport", action="store_true")
        self.argparser.add_argument(
            "--countports",
            metavar="COUNT",
            help="show only results with a number of "
            "open ports within the provided range",
            nargs=2,
        )
        self.argparser.add_argument(
            "--no-countports",
            metavar="COUNT",
            help="show only results with a number of "
            "open ports NOT within the provided range",
            nargs=2,
        )
        self.argparser.add_argument("--script", metavar="ID[:OUTPUT]")
        self.argparser.add_argument("--no-script", metavar="ID[:OUTPUT]")
        self.argparser.add_argument("--os")
        self.argparser.add_argument("--anonftp", action="store_true")
        self.argparser.add_argument("--anonldap", action="store_true")
        self.argparser.add_argument("--authhttp", action="store_true")
        self.argparser.add_argument("--authbypassvnc", action="store_true")
        self.argparser.add_argument("--ypserv", "--nis", action="store_true")
        self.argparser.add_argument("--nfs", action="store_true")
        self.argparser.add_argument("--x11", action="store_true")
        self.argparser.add_argument("--xp445", action="store_true")
        self.argparser.add_argument("--httphdr")
        self.argparser.add_argument("--httpapp")
        self.argparser.add_argument("--owa", action="store_true")
        self.argparser.add_argument(
            "--vuln-boa", "--vuln-intersil", action="store_true"
        )
        self.argparser.add_argument("--torcert", action="store_true")
        self.argparser.add_argument("--sshkey", metavar="FINGERPRINT")

    @staticmethod
    def is_scan_present(_):
        return False

    def start_store_hosts(self):
        """Backend-specific subclasses may use this method to create some bulk
        insert structures.

        """

    def stop_store_hosts(self):
        """Backend-specific subclasses may use this method to commit bulk
        insert structures.

        """

    @staticmethod
    def getscreenshot(port):
        """Returns the content of a port's screenshot."""
        url = port.get("screenshot")
        if url is None:
            return None
        if url == "field":
            return port.get("screendata")
        return None

    def migrate_schema(self, version):
        """Implemented in backend-specific classes."""

    @classmethod
    def __migrate_schema_hosts_0_1(cls, doc):
        """Converts a record from version 0 (no "schema_version" key
        in the document) to version 1 (`doc["schema_version"] ==
        1`). Version 1 adds an "openports" nested document to ease
        open ports based researches.

        """
        assert "schema_version" not in doc
        assert "openports" not in doc
        doc["schema_version"] = 1
        openports = {"count": 0}
        for port in doc.get("ports", []):
            # populate openports
            if port.get("state_state") == "open":
                openports.setdefault(port["protocol"], {}).setdefault(
                    "ports", []
                ).append(port["port"])
            # create the screenwords attribute
            if "screenshot" in port and "screenwords" not in port:
                screenwords = utils.screenwords(cls.getscreenshot(port))
                if screenwords is not None:
                    port["screenwords"] = screenwords
        for proto in list(openports):
            if proto == "count":
                continue
            count = len(openports[proto]["ports"])
            openports[proto]["count"] = count
            openports["count"] += count
        doc["openports"] = openports

    @staticmethod
    def __migrate_schema_hosts_1_2(doc):
        """Converts a record from version 1 to version 2. Version 2
        discards service names when they have been found from
        nmap-services file.

        """
        assert doc["schema_version"] == 1
        doc["schema_version"] = 2
        for port in doc.get("ports", []):
            if port.get("service_method") == "table":
                for key in list(port):
                    if key.startswith("service_"):
                        del port[key]

    @staticmethod
    def __migrate_schema_hosts_2_3(doc):
        """Converts a record from version 2 to version 3. Version 3
        uses new Nmap structured data for scripts using the ls
        library.

        """
        assert doc["schema_version"] == 2
        doc["schema_version"] = 3
        migrate_scripts = set(["afp-ls", "nfs-ls", "smb-ls", "ftp-anon", "http-ls"])
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] in migrate_scripts:
                    if script["id"] in script:
                        script["ls"] = xmlnmap.change_ls(script.pop(script["id"]))
                    elif "ls" not in script:
                        data = xmlnmap.add_ls_data(script)
                        if data is not None:
                            script["ls"] = data
        for script in doc.get("scripts", []):
            if script["id"] in migrate_scripts:
                data = xmlnmap.add_ls_data(script)
                if data is not None:
                    script["ls"] = data

    @staticmethod
    def __migrate_schema_hosts_3_4(doc):
        """Converts a record from version 3 to version 4. Version 4
        creates a "fake" port entry to store host scripts.

        """
        assert doc["schema_version"] == 3
        doc["schema_version"] = 4
        if "scripts" in doc:
            doc.setdefault("ports", []).append(
                {
                    "port": "host",
                    "scripts": doc.pop("scripts"),
                }
            )

    @staticmethod
    def __migrate_schema_hosts_4_5(doc):
        """Converts a record from version 4 to version 5. Version 5
        uses the magic value -1 instead of "host" for "port" in the
        "fake" port entry used to store host scripts (see
        `migrate_schema_hosts_3_4()`). Moreover, it changes the
        structure of the values of "extraports" from [totalcount,
        {"state": count}] to {"total": totalcount, "state": count}.

        """
        assert doc["schema_version"] == 4
        doc["schema_version"] = 5
        for port in doc.get("ports", []):
            if port["port"] == "host":
                port["port"] = -1
        for state, (total, counts) in list(doc.get("extraports", {}).items()):
            doc["extraports"][state] = {"total": total, "reasons": counts}

    @staticmethod
    def __migrate_schema_hosts_5_6(doc):
        """Converts a record from version 5 to version 6. Version 6 uses Nmap
        structured data for scripts using the vulns NSE library.

        """
        assert doc["schema_version"] == 5
        doc["schema_version"] = 6
        migrate_scripts = set(
            script for script, alias in ALIASES_TABLE_ELEMS.items() if alias == "vulns"
        )
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] in migrate_scripts:
                    table = None
                    if script["id"] in script:
                        table = script.pop(script["id"])
                        script["vulns"] = table
                    elif "vulns" in script:
                        table = script["vulns"]
                    else:
                        continue
                    newtable = xmlnmap.change_vulns(table)
                    if newtable != table:
                        script["vulns"] = newtable

    @staticmethod
    def __migrate_schema_hosts_6_7(doc):
        """Converts a record from version 6 to version 7. Version 7 creates a
        structured output for mongodb-databases script.

        """
        assert doc["schema_version"] == 6
        doc["schema_version"] = 7
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "mongodb-databases":
                    if "mongodb-databases" not in script:
                        data = xmlnmap.add_mongodb_databases_data(script)
                        if data is not None:
                            script["mongodb-databases"] = data

    @staticmethod
    def __migrate_schema_hosts_7_8(doc):
        """Converts a record from version 7 to version 8. Version 8 fixes the
        structured output for scripts using the vulns NSE library.

        """
        assert doc["schema_version"] == 7
        doc["schema_version"] = 8
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if "vulns" in script:
                    if any(
                        elt in script["vulns"]
                        for elt in ["ids", "refs", "description", "state", "title"]
                    ):
                        script["vulns"] = [script["vulns"]]
                    else:
                        script["vulns"] = [
                            dict(tab, id=vulnid)
                            for vulnid, tab in script["vulns"].items()
                        ]

    @staticmethod
    def __migrate_schema_hosts_8_9(doc):
        """Converts a record from version 8 to version 9. Version 9 creates a
        structured output for http-headers script.

        """
        assert doc["schema_version"] == 8
        doc["schema_version"] = 9
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "http-headers":
                    if "http-headers" not in script:
                        data = xmlnmap.add_http_headers_data(script)
                        if data is not None:
                            script["http-headers"] = data

    @staticmethod
    def __migrate_schema_hosts_9_10(doc):
        """Converts a record from version 9 to version 10. Version 10 changes
        the field names of the structured output for s7-info script.

        """
        assert doc["schema_version"] == 9
        doc["schema_version"] = 10
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "s7-info":
                    if "s7-info" in script:
                        xmlnmap.change_s7_info_keys(script["s7-info"])

    @staticmethod
    def __migrate_schema_hosts_10_11(doc):
        """Converts a record from version 10 to version 11. Version 11 changes
        the way IP addresses are stored, the way coordinates are stored in
        JSON and the structured output of ssl-cert from Masscan results to
        make it more similar to Nmap.

        In version 10, IP addresses are stored as integers. In version 11,
        they are stored as canonical string representations.

        """
        assert doc["schema_version"] == 10
        doc["schema_version"] = 11
        try:
            doc["addr"] = utils.force_int2ip(doc["addr"])
        except KeyError:
            pass
        if "infos" in doc and "loc" in doc["infos"]:
            doc["infos"]["coordinates"] = doc["infos"].pop("loc")["coordinates"][::-1]
        for port in doc.get("ports", []):
            if "state_reason_ip" in port:
                try:
                    port["state_reason_ip"] = utils.force_int2ip(
                        port["state_reason_ip"]
                    )
                except ValueError:
                    pass
            for script in port.get("scripts", []):
                if script["id"] == "ssl-cert":
                    if "pem" in script["ssl-cert"]:
                        data = "".join(
                            script["ssl-cert"]["pem"].splitlines()[1:-1]
                        ).encode()
                        try:
                            (
                                script["output"],
                                script["ssl-cert"],
                            ) = xmlnmap.create_ssl_cert(data)
                        except Exception:
                            utils.LOGGER.warning(
                                "Cannot parse certificate %r", data, exc_info=True
                            )
                        else:
                            continue
                    try:
                        algo = script["ssl-cert"].pop("pubkeyalgo")
                    except KeyError:
                        pass
                    else:
                        script["pubkey"] = {
                            "type": utils.PUBKEY_TYPES.get(algo, algo),
                        }
        for trace in doc.get("traces", []):
            for hop in trace.get("hops", []):
                if "ipaddr" in hop:
                    try:
                        hop["ipaddr"] = utils.force_int2ip(hop["ipaddr"])
                    except ValueError:
                        pass
        return doc

    @staticmethod
    def __migrate_schema_hosts_11_12(doc):
        """Converts a record from version 11 to version 12. Version 12 changes
        the structured output for fcrdns and rpcinfo script.

        """
        assert doc["schema_version"] == 11
        doc["schema_version"] = 12
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "fcrdns":
                    if "fcrdns" in script:
                        script["fcrdns"] = xmlnmap.change_fcrdns_migrate(
                            script["fcrdns"]
                        )
                elif script["id"] == "rpcinfo":
                    if "rpcinfo" in script:
                        script["rpcinfo"] = xmlnmap.change_rpcinfo(script["rpcinfo"])
        return doc

    @staticmethod
    def __migrate_schema_hosts_12_13(doc):
        """Converts a record from version 12 to version 13. Version 13 changes
        the structured output for ms-sql-info and smb-enum-shares scripts.

        """
        assert doc["schema_version"] == 12
        doc["schema_version"] = 13
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ms-sql-info":
                    if "ms-sql-info" in script:
                        script["ms-sql-info"] = xmlnmap.change_ms_sql_info(
                            script["ms-sql-info"]
                        )
                elif script["id"] == "smb-enum-shares":
                    if "smb-enum-shares" in script:
                        script["smb-enum-shares"] = xmlnmap.change_smb_enum_shares(
                            script["smb-enum-shares"]
                        )
        return doc

    @staticmethod
    def __migrate_schema_hosts_13_14(doc):
        """Converts a record from version 13 to version 14. Version 14 changes
        the structured output for ssh-hostkey and ls scripts to prevent a same
        field from having different data types.

        """
        assert doc["schema_version"] == 13
        doc["schema_version"] = 14
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ssh-hostkey" and "ssh-hostkey" in script:
                    script["ssh-hostkey"] = xmlnmap.change_ssh_hostkey(
                        script["ssh-hostkey"]
                    )
                elif ALIASES_TABLE_ELEMS.get(script["id"]) == "ls" and "ls" in script:
                    script["ls"] = xmlnmap.change_ls_migrate(script["ls"])
        return doc

    @staticmethod
    def __migrate_schema_hosts_14_15(doc):
        """Converts a record from version 14 to version 15. Version 15 changes
        the structured output for httpègit script to move data to values
        instead of keys.

        """
        assert doc["schema_version"] == 14
        doc["schema_version"] = 15
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "http-git" and "http-git" in script:
                    script["http-git"] = xmlnmap.change_http_git(script["http-git"])
        return doc

    @staticmethod
    def __migrate_schema_hosts_15_16(doc):
        """Converts a record from version 15 to version 16. Version 16 uses a
        consistent structured output for Nmap http-server-header script (old
        versions reported `{"Server": "value"}`, while recent versions report
        `["value"]`).

        """
        assert doc["schema_version"] == 15
        doc["schema_version"] = 16
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "http-server-header":
                    if "http-server-header" in script:
                        data = script["http-server-header"]
                        if isinstance(data, dict):
                            if "Server" in data:
                                script["http-server-header"] = [data["Server"]]
                            else:
                                script["http-server-header"] = []
                    else:
                        script["http-server-header"] = [
                            line.split(":", 1)[1].lstrip()
                            for line in (
                                line.strip() for line in script["output"].splitlines()
                            )
                            if line.startswith("Server:")
                        ]

    @staticmethod
    def __migrate_schema_hosts_16_17(doc):
        """Converts a record from version 16 to version 17. Version 17 uses a
        list for ssl-cert output, since several certificates may exist on a
        single port.

        The parsing has been improved and more data gets stored, so while we
        do this, we use the opportunity to parse the certificate again.

        """
        assert doc["schema_version"] == 16
        doc["schema_version"] = 17
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ssl-cert" and "ssl-cert" in script:
                    data = script["ssl-cert"]
                    out = script["output"]
                    if "pem" in data:
                        rawdata = "".join(data["pem"].splitlines()[1:-1])
                        try:
                            out, data = xmlnmap.create_ssl_cert(rawdata.encode())
                        except Exception:
                            utils.LOGGER.warning(
                                "Cannot parse certificate data [%r]",
                                rawdata,
                                exc_info=True,
                            )
                            data = [data]
                    script["ssl-cert"] = data
                    script["output"] = out

    @staticmethod
    def __migrate_schema_hosts_17_18(doc):
        """Converts a record from version 17 to version 18. Version 18
        introduces HASSH (SSH fingerprint) in ssh2-enum-algos.

        """
        assert doc["schema_version"] == 17
        doc["schema_version"] = 18
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "ssh2-enum-algos" and "ssh2-enum-algos" in script:
                    (
                        script["output"],
                        script["ssh2-enum-algos"],
                    ) = xmlnmap.change_ssh2_enum_algos(
                        script["output"], script["ssh2-enum-algos"]
                    )
        return doc

    @staticmethod
    def __migrate_schema_hosts_18_19(doc):
        """Converts a record from version 18 to version 19. Version 19
        splits smb-os-discovery scripts into two, a ntlm-info one that contains all
        the information the original smb-os-discovery script got from NTLM, and a
        smb-os-discovery script with only the information regarding SMB

        """
        assert doc["schema_version"] == 18
        doc["schema_version"] = 19
        for port in doc.get("ports", []):
            for script in port.get("scripts", []):
                if script["id"] == "smb-os-discovery":
                    smb, ntlm = xmlnmap.split_smb_os_discovery(script)
                    script.update(smb)
                    if ntlm:
                        port["scripts"].append(ntlm)
                if script["id"].endswith("-ntlm-info"):
                    xmlnmap.post_ntlm_info(script, port, doc)
        return doc

    @staticmethod
    def json2dbrec(host):
        return host

    def store_scan_doc(self, scan):
        pass

    def update_scan_doc(self, scan_id, data):
        pass

    def remove(self, host):
        raise NotImplementedError

    def remove_many(self, flt):
        for rec in self.get(flt):
            self.remove(rec)

    def get_mean_open_ports(self, flt):
        """This method returns for a specific query `flt` a list of
        dictionary objects whose keys are `id` and `mean`; the value
        for `id` is a backend-dependant and uniquely identifies a
        record, and the value for `mean` is given by:

        (number of open ports) * sum(port number for each open port)

        """
        return [
            {
                "id": self.getid(host),
                "mean": reduce(
                    lambda x, y: x * y,
                    reduce(
                        lambda x, y: (x[0] + y[0], x[1] + y[1]),
                        (
                            (1, port["port"])
                            for port in host.get("ports", [])
                            if port["state_state"] == "open"
                        ),
                        (0, 0),
                    ),
                ),
            }
            for host in self.get(flt, fields=["ports"])
        ]
        # result = []
        # for host in self.get(flt, fields=["ports"]):
        #     count = 0
        #     ports = 1
        #     for port in host.get('ports', []):
        #         if port['state_state'] == 'open':
        #             count += 1
        #             ports += port['port']
        #     result.append((self.getid(host), count * ports))
        # return result

    def _features_port_get(
        self, features, flt, yieldall, use_service, use_product, use_version
    ):
        if use_version:

            def _extract(rec):
                for port in rec.get("ports", []):
                    if port["port"] == -1:
                        continue
                    yield (
                        port["port"],
                        port.get("service_name"),
                        port.get("service_product"),
                        port.get("service_version"),
                    )
                    if not yieldall:
                        continue
                    if port.get("service_version") is not None:
                        yield (
                            port["port"],
                            port.get("service_name"),
                            port.get("service_product"),
                            None,
                        )
                    else:
                        continue
                    if port.get("service_product") is not None:
                        yield (port["port"], port.get("service_name"), None, None)
                    else:
                        continue
                    if port.get("service_name") is not None:
                        yield (port["port"], None, None, None)

        elif use_product:

            def _extract(rec):
                for port in rec.get("ports", []):
                    if port["port"] == -1:
                        continue
                    yield (
                        port["port"],
                        port.get("service_name"),
                        port.get("service_product"),
                    )
                    if not yieldall:
                        continue
                    if port.get("service_product") is not None:
                        yield (port["port"], port.get("service_name"), None)
                    else:
                        continue
                    if port.get("service_name") is not None:
                        yield (port["port"], None, None)

        elif use_service:

            def _extract(rec):
                for port in rec.get("ports", []):
                    if port["port"] == -1:
                        continue
                    yield (port["port"], port.get("service_name"))
                    if not yieldall:
                        continue
                    if port.get("service_name") is not None:
                        yield (port["port"], None)

        else:

            def _extract(rec):
                for port in rec.get("ports", []):
                    if port["port"] == -1:
                        continue
                    yield (port["port"],)

        n_features = len(features)
        for rec in self.get(flt):
            currec = [0] * n_features
            for feat in _extract(rec):
                try:
                    currec[features[feat]] = 1
                except KeyError:
                    pass
            yield (rec["addr"], currec)

    def searchsshkey(
        self, fingerprint=None, key=None, keytype=None, bits=None, output=None
    ):
        """Search SSH host keys"""
        params = {"name": "ssh-hostkey"}
        if fingerprint is not None:
            if not isinstance(fingerprint, utils.REGEXP_T):
                fingerprint = fingerprint.replace(":", "").lower()
            params.setdefault("values", {})["fingerprint"] = fingerprint
        if key is not None:
            params.setdefault("values", {})["key"] = key
        if keytype is not None:
            params.setdefault("values", {})["type"] = "ssh-%s" % keytype
        if bits is not None:
            params.setdefault("values", {})["bits"] = bits
        if output is not None:
            params["output"] = output
        return self.searchscript(**params)

    def searchx11access(self):
        return self.searchscript(name="x11-access", output="X server access is granted")

    def searchbanner(self, banner):
        return self.searchscript(name="banner", output=banner)

    def searchvncauthbypass(self):
        return self.searchscript(name="realvnc-auth-bypass")

    def searchmssqlemptypwd(self):
        return self.searchscript(
            name="ms-sql-empty-password",
            output=re.compile("Login\\ Success", flags=0),
        )

    def searchmysqlemptypwd(self):
        return self.searchscript(
            name="mysql-empty-password",
            output=re.compile("account\\ has\\ empty\\ password", flags=0),
        )

    def searchcookie(self, name):
        return self.searchscript(
            name="http-headers",
            output=re.compile(
                "^ *Set-Cookie: %s=" % re.escape(name), flags=re.MULTILINE | re.I
            ),
        )

    def searchftpanon(self):
        return self.searchscript(
            name="ftp-anon",
            output=re.compile("^Anonymous\\ FTP\\ login\\ allowed", flags=0),
        )

    def searchhttpauth(self, newscript=True, oldscript=False):
        if newscript:
            if oldscript:
                return self.searchscript(
                    name=re.compile("^http-(default-accounts|auth)$"),
                    output=re.compile(
                        "credentials\\ found|" "HTTP\\ server\\ may\\ accept"
                    ),
                )
            return self.searchscript(
                name="http-default-accounts",
                output=re.compile("credentials\\ found"),
            )
        if oldscript:
            return self.searchscript(
                name="http-auth",
                output=re.compile("HTTP\\ server\\ may\\ accept"),
            )
        raise Exception('"newscript" and "oldscript" are both False')

    def searchowa(self):
        return self.searchscript(
            name=re.compile("^(http-(headers|auth-finder|title)|html-title)$"),
            output=re.compile("[ /](owa|exchweb)|X-OWA-Version|Outlook Web A", re.I),
        )

    def searchxp445(self):
        return self.flt_and(
            self.searchport(445),
            self.searchsmb(os="Windows 5.1"),
        )

    def searchypserv(self):
        return self.searchscript(name="rpcinfo", output=re.compile("ypserv", flags=0))

    def searchnfs(self):
        return self.searchscript(name="rpcinfo", output=re.compile("nfs", flags=0))

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
    ):
        values = {}
        if keytype is not None:
            values["pubkey.type"] = keytype
        if md5 is not None:
            values["md5"] = md5.lower()
        if sha1 is not None:
            values["sha1"] = sha1.lower()
        if sha256 is not None:
            values["sha256"] = sha256.lower()
        if subject is not None:
            values["subject_text"] = subject
        if issuer is not None:
            values["issuer_text"] = issuer
        if self_signed is not None:
            values["self_signed"] = self_signed
        if pkmd5 is not None:
            values["pubkey.md5"] = pkmd5.lower()
        if pksha1 is not None:
            values["pubkey.sha1"] = pksha1.lower()
        if pksha256 is not None:
            values["pubkey.sha256"] = pksha256.lower()
        return cls.searchscript(
            name="ssl-cacert" if cacert else "ssl-cert", values=values
        )

    @classmethod
    def searchhttphdr(cls, name=None, value=None):
        if name is None and value is None:
            return cls.searchscript(name="http-headers")
        if value is None:
            return cls.searchscript(name="http-headers", values={"name": name})
        if name is None:
            return cls.searchscript(name="http-headers", values={"value": value})
        return cls.searchscript(
            name="http-headers", values={"name": name, "value": value}
        )

    @classmethod
    def searchhttpapp(cls, name=None, version=None):
        if name is None and version is None:
            return cls.searchscript(name="http-app")
        if version is None:
            return cls.searchscript(name="http-app", values={"application": name})
        if name is None:
            return cls.searchscript(name="http-app", values={"version": version})
        return cls.searchscript(
            name="http-app", values={"application": name, "version": version}
        )

    @classmethod
    def searchdnssrv(cls, domain, sub=False):
        """Filter hosts that are authoritative for `domain` (or for any
        sub-domain of `domain`, when `sub` is set to True).

        """
        if sub:
            return cls.searchscript(name="dns-domains", values={"parents": domain})
        # `parents` field is indexed, `domain` is not
        return cls.searchscript(
            name="dns-domains", values={"parents": domain, "domain": domain}
        )

    def searchgeovision(self):
        return self.searchproduct(product=re.compile("^GeoVision", re.I))

    def searchwebcam(self):
        return self.searchdevicetype("webcam")

    @staticmethod
    def searchhost(addr, neg=False):
        raise NotImplementedError

    @staticmethod
    def searchsource(src, neg=False):
        raise NotImplementedError

    @staticmethod
    def searchscript(name=None, output=None, values=None, neg=False):
        raise NotImplementedError

    @staticmethod
    def searchport(port, protocol="tcp", state="open", neg=False):
        raise NotImplementedError

    @staticmethod
    def searchproduct(
        product=None, version=None, service=None, port=None, protocol=None
    ):
        raise NotImplementedError

    @staticmethod
    def searchdevicetype(devtype):
        raise NotImplementedError

    @classmethod
    def searchsmb(cls, **args):
        """Search particular results from smb-os-discovery host
        script. Example:

        .searchsmb(os="Windows 5.1", workgroup="WORKGROUP\\x00")

        """
        # key aliases
        if "dnsdomain" in args:
            args["domain_dns"] = args.pop("dnsdomain")
        if "forest" in args:
            args["forest_dns"] = args.pop("forest")
        for key in ["ntlm_os", "ntlm_version", "smb_version"]:
            if key in args:
                args[key.replace("_", "-")] = args.pop(key)
        return cls.searchscript(name="smb-os-discovery", values=args)

    @classmethod
    def searchntlm(cls, **args):
        """Search particular results from ntlm-info host script. Example:
        .searchntlm(Product_Version="10.0.17763")
        .searchntlm(protocol="http", Product_Version="10.0.17763")
        """
        return cls.searchscript(name="ntlm-info", values=args)

    @classmethod
    def searchuseragent(cls, useragent=None, neg=False):
        if useragent is None:
            return cls.searchscript(name="http-user-agent", neg=neg)
        return cls.searchscript(name="http-user-agent", values=useragent, neg=neg)

    def parse_args(self, args, flt=None):
        flt = super().parse_args(args, flt=flt)
        if args.category is not None:
            flt = self.flt_and(flt, self.searchcategory(utils.str2list(args.category)))
        if args.asname is not None:
            flt = self.flt_and(flt, self.searchasname(utils.str2regexp(args.asname)))
        if args.source is not None:
            flt = self.flt_and(flt, self.searchsource(args.source))
        if args.version is not None:
            flt = self.flt_and(flt, self.searchversion(args.version))
        if args.timeago is not None:
            flt = self.flt_and(flt, self.searchtimeago(args.timeago))
        if args.id is not None:
            flt = self.flt_and(flt, self.searchobjectid(args.id))
        if args.no_id is not None:
            flt = self.flt_and(flt, self.searchobjectid(args.no_id, neg=True))
        if args.hostname is not None:
            if args.hostname[:1] in "!~":
                flt = self.flt_and(
                    flt,
                    self.searchhostname(utils.str2regexp(args.hostname[1:]), neg=True),
                )
            else:
                flt = self.flt_and(
                    flt, self.searchhostname(utils.str2regexp(args.hostname))
                )
        if args.domain is not None:
            if args.domain[:1] in "!~":
                flt = self.flt_and(
                    flt, self.searchdomain(utils.str2regexp(args.domain[1:]), neg=True)
                )
            else:
                flt = self.flt_and(
                    flt, self.searchdomain(utils.str2regexp(args.domain))
                )
        if args.hop is not None:
            flt = self.flt_and(flt, self.searchhop(args.hop))
        if args.not_port is not None:
            not_port = args.not_port.replace("_", "/")
            if "/" in not_port:
                not_proto, not_port = not_port.split("/", 1)
            else:
                not_proto = "tcp"
            not_port = int(not_port)
            flt = self.flt_and(
                flt, self.searchport(port=not_port, protocol=not_proto, neg=True)
            )
        if args.openport:
            flt = self.flt_and(flt, self.searchopenport())
        if args.no_openport:
            flt = self.flt_and(flt, self.searchopenport(neg=True))
        if args.countports:
            minn, maxn = int(args.countports[0]), int(args.countports[1])
            flt = self.flt_and(flt, self.searchcountopenports(minn=minn, maxn=maxn))
        if args.no_countports:
            minn, maxn = int(args.no_countports[0]), int(args.no_countports[1])
            flt = self.flt_and(
                flt, self.searchcountopenports(minn=minn, maxn=maxn, neg=True)
            )
        if args.script is not None:
            if ":" in args.script:
                name, output = (
                    utils.str2regexp(string) for string in args.script.split(":", 1)
                )
            else:
                name, output = utils.str2regexp(args.script), None
            flt = self.flt_and(flt, self.searchscript(name=name, output=output))
        if args.no_script is not None:
            if ":" in args.no_script:
                name, output = (
                    utils.str2regexp(string) for string in args.no_script.split(":", 1)
                )
            else:
                name, output = utils.str2regexp(args.no_script), None
            flt = self.flt_and(
                flt, self.searchscript(name=name, output=output, neg=True)
            )
        if args.os is not None:
            flt = self.flt_and(flt, self.searchos(utils.str2regexp(args.os)))
        if args.anonftp:
            flt = self.flt_and(flt, self.searchftpanon())
        if args.anonldap:
            flt = self.flt_and(flt, self.searchldapanon())
        if args.authhttp:
            flt = self.flt_and(flt, self.searchhttpauth())
        if args.authbypassvnc:
            flt = self.flt_and(flt, self.searchvncauthbypass())
        if args.ypserv:
            flt = self.flt_and(flt, self.searchypserv())
        if args.nfs:
            flt = self.flt_and(flt, self.searchnfs())
        if args.x11:
            flt = self.flt_and(flt, self.searchx11access())
        if args.xp445:
            flt = self.flt_and(flt, self.searchxp445())
        if args.httphdr is not None:
            if not args.httphdr:
                flt = self.flt_and(flt, self.searchhttphdr())
            elif ":" in args.httphdr:
                name, value = args.httphdr.split(":", 1)
                name = utils.str2regexp(name.lower())
                value = utils.str2regexp(value)
                flt = self.flt_and(flt, self.searchhttphdr(name=name, value=value))
            else:
                flt = self.flt_and(
                    flt, self.searchhttphdr(name=utils.str2regexp(args.httphdr.lower()))
                )
        if args.httpapp is not None:
            if not args.httpapp:
                flt = self.flt_and(flt, self.searchhttpapp())
            elif ":" in args.httpapp:
                name, version = (
                    utils.str2regexp(v) for v in args.httpapp.split(":", 1)
                )
                flt = self.flt_and(
                    flt,
                    self.searchhttpapp(
                        name=name or None,
                        version=version or None,
                    ),
                )
            else:
                flt = self.flt_and(
                    flt, self.searchhttpapp(name=utils.str2regexp(args.httpapp))
                )
        if args.owa:
            flt = self.flt_and(flt, self.searchowa())
        if args.vuln_boa:
            flt = self.flt_and(flt, self.searchvulnintersil())
        if args.torcert:
            flt = self.flt_and(flt, self.searchtorcert())
        if args.sshkey is not None:
            flt = self.flt_and(
                flt, self.searchsshkey(fingerprint=utils.str2regexp(args.sshkey))
            )
        return flt

    @staticmethod
    def cmp_schema_version_host(_):
        return 0

    @staticmethod
    def cmp_schema_version_scan(_):
        return 0


class DBNmap(DBActive):

    content_handler = xmlnmap.Nmap2Txt

    def __init__(self, output_mode="json", output=sys.stdout):
        super().__init__()
        self.output_function = {
            "normal": nmapout.displayhosts,
        }.get(output_mode, nmapout.displayhosts_json)
        self.output = output

    def store_host(self, host):
        if self.output_function is not None:
            self.output_function(host, out=self.output)

    def store_scan(self, fname, **kargs):
        """This method opens a scan result, and calls the appropriate
        store_scan_* method to parse (and store) the scan result.

        """
        scanid = utils.hash_file(fname, hashtype="sha256")
        if self.is_scan_present(scanid):
            utils.LOGGER.debug("Scan already present in Database (%r).", fname)
            return False
        with utils.open_file(fname) as fdesc:
            fchar = fdesc.read(1)
            if fchar == b"{":
                firstline = fchar + fdesc.readline()[:-1]
        try:
            store_scan_function = {
                b"<": self.store_scan_xml,
            }[fchar]
        except KeyError:
            if fchar == b"{":
                try:
                    firstres = (firstline).decode()
                except UnicodeDecodeError:
                    raise ValueError("Unknown file type %s" % fname)
                try:
                    firstres = json.loads(firstres)
                except json.decoder.JSONDecodeError:
                    raise ValueError("Unknown file type %s" % fname)
                if "addr" in firstres:
                    store_scan_function = self.store_scan_json_ivre
                elif any(
                    mtch in firstres for mtch in ["matched", "matched-at"]
                ) and any(
                    tmpl in firstres
                    for tmpl in ["template", "templateID", "template-id"]
                ):
                    store_scan_function = self.store_scan_json_nuclei
                elif "ip" in firstres:
                    store_scan_function = self.store_scan_json_zgrab
                elif "name" in firstres:
                    if utils.is_valid_ip(firstres["name"]):
                        store_scan_function = self.store_scan_json_zdns_ptr
                    else:
                        store_scan_function = self.store_scan_json_zdns_a
                elif "altered_name" in firstres:
                    store_scan_function = self.store_scan_json_zdns_recursion
                else:
                    raise ValueError("Unknown file type %s" % fname)
            else:
                raise ValueError("Unknown file type %s" % fname)
        return store_scan_function(fname, filehash=scanid, **kargs)

    def store_scan_xml(self, fname, callback=None, **kargs):
        """This method parses an XML scan result, displays a JSON
        version of the result, and return True if everything went
        fine, False otherwise.

        In backend-specific subclasses, this method stores the result
        instead of displaying it, thanks to the `content_handler`
        attribute.

        The callback is a function called after each host insertion
        and takes this host as a parameter. This should be set to 'None'
        if no action has to be taken.

        """
        parser = xml.sax.make_parser()
        self.start_store_hosts()
        try:
            content_handler = self.content_handler(fname, self.globaldb, **kargs)
        except Exception:
            utils.LOGGER.warning("Exception (file %r)", fname, exc_info=True)
        else:
            content_handler.callback = callback
            parser.setContentHandler(content_handler)
            parser.setEntityResolver(xmlnmap.NoExtResolver())
            parser.setFeature(xml.sax.handler.feature_external_ges, 0)
            parser.setFeature(xml.sax.handler.feature_external_pes, 0)
            parser.parse(utils.open_file(fname))
            if self.output_function is not None:
                self.output_function(content_handler._db, out=self.output)
            self.stop_store_hosts()
            return True
        self.stop_store_hosts()
        return False

    def store_scan_json_ivre(
        self,
        fname,
        filehash=None,
        needports=False,
        needopenports=False,
        categories=None,
        source=None,
        add_addr_infos=True,
        force_info=False,
        callback=None,
        **_,
    ):
        """This method parses a JSON scan result as exported using
        `ivre scancli --json > file`, displays the parsing result, and
        return True if everything went fine, False otherwise.

        In backend-specific subclasses, this method stores the result
        instead of displaying it, thanks to the `store_host`
        method.

        The callback is a function called after each host insertion
        and takes this host as a parameter. This should be set to 'None'
        if no action has to be taken.

        """
        if categories is None:
            categories = []
        scan_doc_saved = False
        self.start_store_hosts()
        with utils.open_file(fname) as fdesc:
            for line in fdesc:
                host = self.json2dbrec(json.loads(line.decode()))
                if (needports and "ports" not in host) or (
                    needopenports and not host.get("openports", {}).get("count")
                ):
                    continue
                if "_id" in host:
                    del host["_id"]
                host["scanid"] = filehash
                if categories:
                    host["categories"] = categories
                if source is not None:
                    host["source"] = source
                if (
                    add_addr_infos
                    and self.globaldb is not None
                    and (force_info or "infos" not in host or not host["infos"])
                ):
                    host["infos"] = {}
                    for func in [
                        self.globaldb.data.country_byip,
                        self.globaldb.data.as_byip,
                        self.globaldb.data.location_byip,
                    ]:
                        host["infos"].update(func(host["addr"]) or {})
                # Update schema if/as needed.
                while host.get("schema_version") in self._schema_migrations["hosts"]:
                    oldvers = host.get("schema_version")
                    self._schema_migrations["hosts"][oldvers][1](host)
                    if oldvers == host.get("schema_version"):
                        utils.LOGGER.warning(
                            "[%r] could not migrate host from version " "%r [%r]",
                            self.__class__,
                            oldvers,
                            host,
                        )
                        break
                # We are about to insert data based on this file,
                # so we want to save the scan document
                if not scan_doc_saved:
                    self.store_scan_doc({"_id": filehash})
                    scan_doc_saved = True
                self.store_host(host)
                if callback is not None:
                    callback(host)
        self.stop_store_hosts()
        return True

    def store_scan_json_zgrab(
        self,
        fname,
        filehash=None,
        needports=False,
        needopenports=False,
        categories=None,
        source=None,
        add_addr_infos=True,
        force_info=False,
        callback=None,
        zgrab_port=None,
        **_,
    ):
        """This method parses a JSON scan result produced by zgrab, displays
        the parsing result, and return True if everything went fine,
        False otherwise.

        In backend-specific subclasses, this method stores the result
        instead of displaying it, thanks to the `store_host`
        method.

        The callback is a function called after each host insertion
        and takes this host as a parameter. This should be set to 'None'
        if no action has to be taken.

        """
        if categories is None:
            categories = []
        scan_doc_saved = False
        self.start_store_hosts()
        if zgrab_port is not None:
            zgrab_port = int(zgrab_port)
        with utils.open_file(fname) as fdesc:
            for line in fdesc:
                rec = json.loads(line.decode())
                try:
                    host = {
                        "addr": rec.pop("ip"),
                        "scanid": filehash,
                        "schema_version": xmlnmap.SCHEMA_VERSION,
                    }
                except KeyError:
                    # the last result (which contains a
                    # "success_count" field) holds the scan's data
                    if "success_count" in rec:
                        scan_doc = {"_id": filehash, "scanner": "zgrab"}
                        if "flags" in rec:
                            scan_doc["args"] = " ".join(
                                pipes.quote(elt) for elt in rec.pop("flags")
                            )
                        if "start_time" in rec:
                            # [:19]: remove timezone info
                            start = utils.all2datetime(rec.pop("start_time")[:19])
                            scan_doc["start"] = start.strftime("%s")
                            scan_doc["startstr"] = str(start)
                        if "end_time" in rec:
                            # [:19]: remove timezone info
                            end = utils.all2datetime(rec.pop("end_time")[:19])
                            scan_doc["end"] = end.strftime("%s")
                            scan_doc["endstr"] = str(end)
                        if "duration" in rec:
                            scan_doc["elapsed"] = str(rec.pop("duration"))
                        self.update_scan_doc(filehash, scan_doc)
                    else:
                        utils.LOGGER.warning('Record has no "ip" field %r', rec)
                    continue
                try:
                    # [:19]: remove timezone info
                    host["starttime"] = host["endtime"] = rec.pop("timestamp")[
                        :19
                    ].replace("T", " ")
                except KeyError:
                    pass
                if categories:
                    host["categories"] = categories
                if source is not None:
                    host["source"] = source
                for key, value in rec.pop("data", {}).items():
                    try:
                        timestamp = value.pop("timestamp")[:19].replace("T", " ")
                    except KeyError:
                        pass
                    else:
                        if "starttime" in host:
                            host["starttime"] = min(host["starttime"], timestamp)
                        else:
                            host["starttime"] = timestamp
                        if "endtime" in host:
                            host["endtime"] = max(host["endtime"], timestamp)
                        else:
                            host["endtime"] = timestamp
                    try:
                        parser = ZGRAB_PARSERS[key]
                    except KeyError:
                        utils.LOGGER.warning(
                            "Data type %r from zgrab not (yet) supported",
                            key,
                        )
                    else:
                        port = parser(value, host, port=zgrab_port)
                        if port:
                            host.setdefault("ports", []).append(port)
                if not host.get("ports"):
                    continue
                set_openports_attribute(host)
                if "cpes" in host:
                    host["cpes"] = list(host["cpes"].values())
                    for cpe in host["cpes"]:
                        cpe["origins"] = sorted(cpe["origins"])
                    if not host["cpes"]:
                        del host["cpes"]
                host = self.json2dbrec(host)
                if (needports and "ports" not in host) or (
                    needopenports
                    and not any(
                        port.get("state_state") == "open"
                        for port in host.get("ports", [])
                    )
                ):
                    continue
                if (
                    add_addr_infos
                    and self.globaldb is not None
                    and (force_info or "infos" not in host or not host["infos"])
                ):
                    host["infos"] = {}
                    for func in [
                        self.globaldb.data.country_byip,
                        self.globaldb.data.as_byip,
                        self.globaldb.data.location_byip,
                    ]:
                        host["infos"].update(func(host["addr"]) or {})
                # We are about to insert data based on this file,
                # so we want to save the scan document
                if not scan_doc_saved:
                    self.store_scan_doc({"_id": filehash, "scanner": "zgrab"})
                    scan_doc_saved = True
                self.store_host(host)
                if callback is not None:
                    callback(host)
        self.stop_store_hosts()
        return True

    def store_scan_json_zdns_ptr(
        self,
        fname,
        filehash=None,
        needports=False,
        needopenports=False,
        categories=None,
        source=None,
        add_addr_infos=True,
        force_info=False,
        callback=None,
        **_,
    ):
        """This method parses a JSON scan result produced by zdns to create
        hosts PTR entries, displays the parsing result, and return
        True if everything went fine, False otherwise.

        In backend-specific subclasses, this method stores the result
        instead of displaying it, thanks to the `store_host`
        method.

        The callback is a function called after each host insertion
        and takes this host as a parameter. This should be set to 'None'
        if no action has to be taken.

        """
        if categories is None:
            categories = []
        scan_doc_saved = False
        self.start_store_hosts()
        with utils.open_file(fname) as fdesc:
            for line in fdesc:
                rec = json.loads(line.decode())
                if rec.get("status") != "NOERROR":
                    continue
                try:
                    answers = rec["data"]["answers"]
                except KeyError:
                    continue
                hostnames = [
                    {
                        "name": name,
                        "type": "PTR",
                        "domains": list(utils.get_domains(name)),
                    }
                    for name in (
                        ans["answer"].rstrip(".")
                        for ans in answers
                        if (ans.get("class") == "IN" and ans.get("type") == "PTR")
                    )
                ]
                if not hostnames:
                    continue
                timestamp = rec.pop("timestamp")[:19].replace("T", " ")
                host = {
                    "addr": rec.pop("name"),
                    "scanid": filehash,
                    "schema_version": xmlnmap.SCHEMA_VERSION,
                    # [:19]: remove timezone info
                    "starttime": timestamp,
                    "endtime": timestamp,
                    "hostnames": hostnames,
                }
                if categories:
                    host["categories"] = categories
                if source is not None:
                    host["source"] = source
                host = self.json2dbrec(host)
                if (
                    add_addr_infos
                    and self.globaldb is not None
                    and (force_info or "infos" not in host or not host["infos"])
                ):
                    host["infos"] = {}
                    for func in [
                        self.globaldb.data.country_byip,
                        self.globaldb.data.as_byip,
                        self.globaldb.data.location_byip,
                    ]:
                        host["infos"].update(func(host["addr"]) or {})
                # We are about to insert data based on this file,
                # so we want to save the scan document
                if not scan_doc_saved:
                    self.store_scan_doc({"_id": filehash, "scanner": "zdns"})
                    scan_doc_saved = True
                self.store_host(host)
                if callback is not None:
                    callback(host)
        self.stop_store_hosts()
        return True

    def store_scan_json_zdns_a(
        self,
        fname,
        filehash=None,
        needports=False,
        needopenports=False,
        categories=None,
        source=None,
        add_addr_infos=True,
        force_info=False,
        callback=None,
        **_,
    ):
        """This method parses a JSON scan result produced by zdns to create
        hosts A / AAAA entries, displays the parsing result, and
        return True if everything went fine, False otherwise.

        In backend-specific subclasses, this method stores the result
        instead of displaying it, thanks to the `store_host`
        method.

        The callback is a function called after each host insertion
        and takes this host as a parameter. This should be set to 'None'
        if no action has to be taken.

        """
        if categories is None:
            categories = []
        scan_doc_saved = False
        self.start_store_hosts()
        with utils.open_file(fname) as fdesc:
            for line in fdesc:
                rec = json.loads(line.decode())
                if rec.get("status") != "NOERROR":
                    continue
                try:
                    answers = rec["data"]["answers"]
                except KeyError:
                    continue
                timestamp = rec.pop("timestamp")[:19].replace("T", " ")
                for ans in answers:
                    if ans.get("class") != "IN":
                        continue
                    if ans.get("type") not in {"A", "AAAA"}:
                        continue
                    host = {
                        "addr": ans["answer"],
                        "scanid": filehash,
                        "schema_version": xmlnmap.SCHEMA_VERSION,
                        # [:19]: remove timezone info
                        "starttime": timestamp,
                        "endtime": timestamp,
                        "hostnames": [
                            {
                                "name": ans["name"],
                                "type": ans["type"],
                                "domains": list(utils.get_domains(ans["name"])),
                            }
                        ],
                    }
                    if categories:
                        host["categories"] = categories
                    if source is not None:
                        host["source"] = source
                    host = self.json2dbrec(host)
                    if (
                        add_addr_infos
                        and self.globaldb is not None
                        and (force_info or "infos" not in host or not host["infos"])
                    ):
                        host["infos"] = {}
                        for func in [
                            self.globaldb.data.country_byip,
                            self.globaldb.data.as_byip,
                            self.globaldb.data.location_byip,
                        ]:
                            host["infos"].update(func(host["addr"]) or {})
                    # We are about to insert data based on this file,
                    # so we want to save the scan document
                    if not scan_doc_saved:
                        self.store_scan_doc({"_id": filehash, "scanner": "zdns"})
                        scan_doc_saved = True
                    self.store_host(host)
                    if callback is not None:
                        callback(host)
        self.stop_store_hosts()
        return True

    def store_scan_json_zdns_recursion(
        self,
        fname,
        filehash=None,
        needports=False,
        needopenports=False,
        categories=None,
        source=None,
        add_addr_infos=True,
        force_info=False,
        callback=None,
        masscan_probes=None,
        **_,
    ):
        """This method parses a JSON scan result produced by zdns for
        recursion test, displays the parsing result, and return True
        if everything went fine, False otherwise.

        In backend-specific subclasses, this method stores the result
        instead of displaying it, thanks to the `store_host`
        method.

        The callback is a function called after each host insertion
        and takes this host as a parameter. This should be set to 'None'
        if no action has to be taken.

        """
        if categories is None:
            categories = []
        answers = set()
        for probe in masscan_probes or []:
            if probe.startswith("ZDNS:"):
                answers.add(probe[5:])
        if not answers:
            utils.LOGGER.warning(
                "No ZDNS probe has been defined. Please use "
                '"--masscan-probes ZDNS:<query>:<type>:<expected result>" '
                '(example: "ZDNS:ivre.rocks:A:1.2.3.4")'
            )
        scan_doc_saved = False
        self.start_store_hosts()
        with utils.open_file(fname) as fdesc:
            for line in fdesc:
                rec = json.loads(line.decode())
                if rec.get("status") == "TIMEOUT":
                    continue
                try:
                    data = rec["data"]
                except KeyError:
                    utils.LOGGER.warning(
                        "Zdns record has no data entry [%r]",
                        rec,
                    )
                    continue
                try:
                    resolver = data["resolver"]
                except KeyError:
                    utils.LOGGER.warning(
                        "Zdns record has no resolver entry [%r]",
                        rec,
                    )
                    continue
                try:
                    addr, port = resolver.split(":", 1)
                    port = int(port)
                except Exception:
                    utils.LOGGER.warning(
                        "Zdns record has invalid resolver entry [%r]",
                        rec,
                        exc_info=True,
                    )
                    continue
                # Now we know for sure we have a DNS server here
                timestamp = rec.pop("timestamp")[:19].replace("T", " ")
                port = {
                    "protocol": data.get("protocol", "udp"),
                    "port": port,
                    "state_state": "open",
                    "state_reason": "response",
                    "service_name": "domain",
                    "service_method": "probed",
                }
                host = {
                    "addr": addr,
                    "scanid": filehash,
                    "schema_version": xmlnmap.SCHEMA_VERSION,
                    # [:19]: remove timezone info
                    "starttime": timestamp,
                    "endtime": timestamp,
                    "ports": [port],
                }
                if rec.get("status") == "NOERROR" and "answers" in data:
                    # the DNS server **did** answer our request
                    script = {
                        "id": "dns-recursion",
                        "output": "Recursion appears to be enabled",
                    }
                    if (
                        set(
                            "%(name)s:%(type)s:%(answer)s" % ans
                            for ans in data["answers"]
                        )
                        != answers
                    ):
                        script["output"] += "\nAnswer may be incorrect!\n%s" % (
                            "\n".join(
                                "%(name)s    %(type)s    %(answer)s" % ans
                                for ans in data["answers"]
                            )
                        )
                    port["scripts"] = [script]
                if categories:
                    host["categories"] = categories
                if source is not None:
                    host["source"] = source
                set_openports_attribute(host)
                host = self.json2dbrec(host)
                if (
                    add_addr_infos
                    and self.globaldb is not None
                    and (force_info or "infos" not in host or not host["infos"])
                ):
                    host["infos"] = {}
                    for func in [
                        self.globaldb.data.country_byip,
                        self.globaldb.data.as_byip,
                        self.globaldb.data.location_byip,
                    ]:
                        host["infos"].update(func(host["addr"]) or {})
                # We are about to insert data based on this file,
                # so we want to save the scan document
                if not scan_doc_saved:
                    self.store_scan_doc({"_id": filehash, "scanner": "zdns"})
                    scan_doc_saved = True
                self.store_host(host)
                if callback is not None:
                    callback(host)
        self.stop_store_hosts()
        return True

    def store_scan_json_nuclei(
        self,
        fname,
        filehash=None,
        needports=False,
        needopenports=False,
        categories=None,
        source=None,
        add_addr_infos=True,
        force_info=False,
        callback=None,
        **_,
    ):
        """This method parses a JSON scan result produced by nuclei, displays
        the parsing result, and return True if everything went fine,
        False otherwise.

        In backend-specific subclasses, this method stores the result
        instead of displaying it, thanks to the `store_host`
        method.

        The callback is a function called after each host insertion
        and takes this host as a parameter. This should be set to 'None'
        if no action has to be taken.

        """
        if categories is None:
            categories = []
        scan_doc_saved = False
        self.start_store_hosts()
        with utils.open_file(fname) as fdesc:
            for line in fdesc:
                try:
                    rec = json.loads(line.decode())
                except (UnicodeDecodeError, json.JSONDecodeError):
                    utils.LOGGER.warning("Cannot parse line %r", line, exc_info=True)
                    continue
                # new vs old format
                if "matched-at" in rec:
                    rec["matched"] = rec.pop("matched-at")
                if rec.get("type") == "http":
                    try:
                        url = rec.get("matched", rec["host"])
                    except KeyError:
                        utils.LOGGER.warning("No URL found [%r]", rec)
                        continue
                    is_ssl = False
                    try:
                        addr, port = utils.url2hostport(url)
                    except ValueError:
                        utils.LOGGER.warning("Invalid URL %r", url)
                        continue
                    else:
                        if url.startswith("https:"):
                            is_ssl = True
                elif rec.get("type") == "network":
                    try:
                        url = rec.get("matched", rec["host"])
                    except KeyError:
                        utils.LOGGER.warning("No URL found [%r]", rec)
                        continue
                    try:
                        addr, port = url.split(":", 1)
                    except ValueError:
                        utils.LOGGER.warning("Invalid URL [%r]", url)
                        continue
                    try:
                        port = int(port)
                    except ValueError:
                        utils.LOGGER.warning("Invalid URL [%r]", url)
                        continue
                else:
                    utils.LOGGER.warning(
                        "Data type %r from nuclei not (yet) supported",
                        rec.get("type"),
                    )
                    continue
                if "ip" in rec:
                    addr = rec["ip"]
                try:
                    utils.ip2int(addr)
                except (TypeError, socket.error, struct.error):
                    utils.LOGGER.warning("Hostnames in URL not supported [%r]", url)
                    continue
                # new vs old format
                if "info" in rec:
                    rec.update(rec.pop("info"))
                # new-new vs new vs old format...
                if "templateID" in rec:
                    rec["template"] = rec.pop("templateID")
                elif "template-id" in rec:
                    rec["template"] = rec.pop("template-id")
                name = rec["name"]
                if "matcher_name" in rec:
                    name += " (%s)" % rec["matcher_name"]
                script_id = "%s-nuclei" % (rec["type"])
                scripts = [
                    {
                        "id": script_id,
                        "output": "[%s] %s found at %s" % (rec["severity"], name, url),
                        script_id: [
                            {
                                "template": rec["template"],
                                "name": name,
                                "url": url,
                                "severity": rec["severity"],
                            },
                        ],
                    },
                ]
                if rec["template"] == "git-config":
                    repository = "%s:%d%s" % (addr, port, urlparse(url).path[:-6])
                    scripts.append(
                        {
                            "id": "http-git",
                            "output": "\n  %s\n    Git repository found!\n"
                            % repository,
                            "http-git": [
                                {
                                    "repository": repository,
                                    "files-found": [".git/config"],
                                },
                            ],
                        }
                    )
                port = {
                    "protocol": "tcp",
                    "port": port,
                    "service_name": "http",
                    "state_state": "open",
                    "scripts": scripts,
                }
                if is_ssl:
                    port["service_tunnel"] = "ssl"
                host = {
                    "addr": addr,
                    "scanid": filehash,
                    "schema_version": xmlnmap.SCHEMA_VERSION,
                    "ports": [port],
                }
                if "timestamp" in rec:
                    host["starttime"] = host["endtime"] = rec["timestamp"][:19].replace(
                        "T", " "
                    )
                if categories:
                    host["categories"] = categories
                if source is not None:
                    host["source"] = source
                host = self.json2dbrec(host)
                if (
                    add_addr_infos
                    and self.globaldb is not None
                    and (force_info or "infos" not in host or not host["infos"])
                ):
                    host["infos"] = {}
                    for func in [
                        self.globaldb.data.country_byip,
                        self.globaldb.data.as_byip,
                        self.globaldb.data.location_byip,
                    ]:
                        host["infos"].update(func(host["addr"]) or {})
                # We are about to insert data based on this file,
                # so we want to save the scan document
                if not scan_doc_saved:
                    self.store_scan_doc({"_id": filehash, "scanner": "nuclei"})
                    scan_doc_saved = True
                self.store_host(host)
                if callback is not None:
                    callback(host)
        self.stop_store_hosts()
        return True


class DBView(DBActive):
    def __init__(self):
        super().__init__()
        self.argparser.add_argument(
            "--ssl-ja3-server",
            metavar="JA3-SERVER[:JA3-CLIENT]",
            nargs="?",
            const=False,
            default=None,
        )
        self.argparser.add_argument(
            "--ssl-ja3-client",
            metavar="JA3-CLIENT",
            nargs="?",
            const=False,
            default=None,
        )

    def parse_args(self, args, flt=None):
        flt = super().parse_args(args, flt=flt)
        if args.ssl_ja3_client is not None:
            cli = args.ssl_ja3_client
            flt = self.flt_and(
                flt,
                self.searchja3client(
                    value_or_hash=(False if cli is False else utils.str2regexp(cli))
                ),
            )
        if args.ssl_ja3_server is not None:
            if args.ssl_ja3_server is False:
                # There are no additional arguments
                flt = self.flt_and(flt, self.searchja3server())
            else:
                split = [
                    utils.str2regexp(v) if v else None
                    for v in args.ssl_ja3_server.split(":", 1)
                ]
                if len(split) == 1:
                    # Only a JA3 server is given
                    flt = self.flt_and(
                        flt, self.searchja3server(value_or_hash=split[0])
                    )
                else:
                    # Both client and server JA3 are given
                    flt = self.flt_and(
                        flt,
                        self.searchja3server(
                            value_or_hash=split[0],
                            client_value_or_hash=split[1],
                        ),
                    )
        return flt

    @staticmethod
    def merge_host_docs(rec1, rec2):
        return merge_host_docs(rec1, rec2)

    def merge_host(self, host):
        """Attempt to merge `host` with an existing record.

        Return `True` if another record for the same address has been found,
        merged and the resulting document inserted in the database, `False`
        otherwise (in that case, it is the caller's responsibility to
        add `host` to the database if necessary).

        """
        try:
            flt = self.searchhost(host["addr"])
            rec = next(iter(self.get(flt)))
        except StopIteration:
            # "Merge" mode but no record for that host, let's add
            # the result normally
            return False
        self.store_host(self.merge_host_docs(rec, host))
        self.remove(rec)
        return True

    @classmethod
    def _searchja3(cls, value_or_hash, script_id, neg):
        if not value_or_hash:
            return cls.searchscript(name=script_id, neg=neg)
        key, value = cls._ja3keyvalue(value_or_hash)
        return cls.searchscript(name=script_id, values={key: value}, neg=neg)

    @classmethod
    def searchja3client(cls, value_or_hash=None, neg=False):
        return cls._searchja3(value_or_hash, "ssl-ja3-client", neg=neg)

    @classmethod
    def searchja3server(cls, value_or_hash=None, client_value_or_hash=None, neg=False):
        script_id = "ssl-ja3-server"
        if not client_value_or_hash:
            return cls._searchja3(value_or_hash, script_id, neg=neg)
        key_client, value_client = cls._ja3keyvalue(client_value_or_hash)
        values = {"client.%s" % (key_client): value_client}
        if value_or_hash:
            key_srv, value_srv = cls._ja3keyvalue(value_or_hash)
            values[key_srv] = value_srv
        return cls.searchscript(
            name=script_id,
            values=values,
            neg=neg,
        )


class _RecInfo:
    __slots__ = ["count", "firstseen", "infos", "lastseen"]

    def __init__(self, infos):
        self.count = 0
        self.firstseen = self.lastseen = None
        self.infos = infos

    @property
    def data(self):
        data = {"count": self.count}
        if self.infos:
            data["infos"] = self.infos
        return data

    def update_from_spec(self, spec):
        self.count += spec.get("count")
        firstseen = spec.get("firstseen")
        if firstseen is not None:
            if self.firstseen is None:
                self.firstseen = firstseen
            else:
                self.firstseen = min(self.firstseen, firstseen)
        lastseen = spec.get("lastseen")
        if lastseen is not None:
            if self.lastseen is None:
                self.lastseen = lastseen
            else:
                self.lastseen = min(self.lastseen, lastseen)

    def update(self, timestamp):
        self.count += 1
        if self.firstseen is None:
            self.firstseen = timestamp
        else:
            self.firstseen = min(self.firstseen, timestamp)
        if self.lastseen is None:
            self.lastseen = timestamp
        else:
            self.lastseen = max(self.lastseen, timestamp)


class DBPassive(DB):

    ipaddr_fields = ["addr"]
    datetime_fields = ["firstseen", "lastseen", "infos.not_after", "infos.not_before"]
    list_fields = ["infos.domain", "infos.domaintarget", "infos.san"]

    def __init__(self):
        super().__init__()
        self.argparser.add_argument("--sensor")
        self.argparser.add_argument("--torcert", action="store_true")
        self.argparser.add_argument("--dns")
        self.argparser.add_argument("--dnssub")
        self.argparser.add_argument("--cert")
        self.argparser.add_argument("--basicauth", action="store_true")
        self.argparser.add_argument("--auth", action="store_true")
        self.argparser.add_argument("--java", action="store_true")
        self.argparser.add_argument("--ftp", action="store_true")
        self.argparser.add_argument("--pop", action="store_true")
        self.argparser.add_argument("--timeago", type=int)
        self.argparser.add_argument("--timeagonew", type=int)
        self.argparser.add_argument(
            "--dnstype",
            metavar="DNS_TYPE",
            help="Display results for specified DNS type.",
        )
        self.argparser.add_argument(
            "--ssl-ja3-server",
            metavar="JA3-SERVER[:JA3-CLIENT]",
            nargs="?",
            const=False,
            default=None,
        )
        self.argparser.add_argument(
            "--ssl-ja3-client",
            metavar="JA3-CLIENT",
            nargs="?",
            const=False,
            default=None,
        )
        self.argparser_insert = ArgumentParser(add_help=False)
        self.argparser_insert.add_argument("--sensor", "-s", help="Sensor name")
        self.argparser_insert.add_argument(
            "--ignore-spec", "-i", help="Filename containing ignore rules"
        )
        self.argparser_insert.add_argument(
            "--bulk",
            action="store_true",
            help="Use DB bulk inserts (this is the default)",
        )
        self.argparser_insert.add_argument(
            "--local-bulk", action="store_true", help="Use local (memory) bulk inserts"
        )
        self.argparser_insert.add_argument(
            "--no-bulk", action="store_true", help="Do not use bulk inserts"
        )

    def parse_args(self, args, flt=None):
        flt = super().parse_args(args, flt=flt)
        if args.sensor is not None:
            flt = self.flt_and(flt, self.searchsensor(utils.str2list(args.sensor)))
        if args.torcert:
            flt = self.flt_and(flt, self.searchtorcert())
        if args.basicauth:
            flt = self.flt_and(flt, self.searchbasicauth())
        if args.auth:
            flt = self.flt_and(flt, self.searchhttpauth())
        if args.java:
            flt = self.flt_and(flt, self.searchjavaua())
        if args.ftp:
            flt = self.flt_and(flt, self.searchftpauth())
        if args.pop:
            flt = self.flt_and(flt, self.searchpopauth())
        if args.dns is not None:
            flt = self.flt_and(
                flt, self.searchdns(utils.str2regexp(args.dns), subdomains=False)
            )
        if args.dnssub is not None:
            flt = self.flt_and(
                flt, self.searchdns(utils.str2regexp(args.dnssub), subdomains=True)
            )
        if args.cert is not None:
            flt = self.flt_and(
                flt,
                self.searchcert(subject=utils.str2regexp(args.cert)),
            )
        if args.timeago is not None:
            flt = self.flt_and(
                flt,
                self.searchtimeago(args.timeago, new=False),
            )
        if args.timeagonew is not None:
            flt = self.flt_and(
                flt,
                self.searchtimeago(args.timeagonew, new=True),
            )
        if args.dnstype is not None:
            flt = self.flt_and(flt, self.searchdns(dnstype=args.dnstype))
        if args.ssl_ja3_client is not None:
            cli = args.ssl_ja3_client
            flt = self.flt_and(
                flt,
                self.searchja3client(
                    value_or_hash=(False if cli is False else utils.str2regexp(cli))
                ),
            )
        if args.ssl_ja3_server is not None:
            if args.ssl_ja3_server is False:
                # There are no additional arguments
                flt = self.flt_and(flt, self.searchja3server())
            else:
                split = [
                    utils.str2regexp(v) if v else None
                    for v in args.ssl_ja3_server.split(":", 1)
                ]
                if len(split) == 1:
                    # Only a JA3 server is given
                    flt = self.flt_and(
                        flt, self.searchja3server(value_or_hash=split[0])
                    )
                else:
                    # Both client and server JA3 are given
                    flt = self.flt_and(
                        flt,
                        self.searchja3server(
                            value_or_hash=split[0],
                            client_value_or_hash=split[1],
                        ),
                    )

        return flt

    def insert_or_update(
        self, timestamp, spec, getinfos=None, lastseen=None, replacecount=False
    ):
        raise NotImplementedError

    def insert_or_update_bulk(
        self, specs, getinfos=None, separated_timestamps=True, replacecount=False
    ):
        """Like `.insert_or_update()`, but `specs` parameter has to be an
        iterable of (timestamp, spec) values. This generic
        implementation does not use the bulk capacity of the
        underlying DB implementation but rather calls its
        `.insert_or_update()` method.

        """
        if separated_timestamps:
            for tstamp, spec in specs:
                self.insert_or_update(
                    tstamp, spec, getinfos=getinfos, replacecount=replacecount
                )
        else:
            for spec in specs:
                timestamp = spec.pop("firstseen", None)
                lastseen = spec.pop("lastseen", None)
                self.insert_or_update(
                    timestamp or lastseen,
                    spec,
                    getinfos=getinfos,
                    lastseen=lastseen or timestamp,
                    replacecount=replacecount,
                )

    def insert_or_update_local_bulk(
        self, specs, getinfos=None, separated_timestamps=True, replacecount=False
    ):
        """Like `.insert_or_update()`, but `specs` parameter has to be an
        iterable of (timestamp, spec) values. This generic
        implementation does not use the bulk capacity of the
        underlying DB implementation but uses a local cache and calls
        its `.insert_or_update()` method.

        """

        def _bulk_execute(records):
            utils.LOGGER.debug("DB:local bulk upsert: %d", len(records))
            for spec, metadata in records.items():
                self.insert_or_update(
                    metadata.firstseen,
                    dict(spec, **metadata.data),
                    getinfos=getinfos,
                    lastseen=metadata.lastseen,
                    replacecount=replacecount,
                )

        records = {}
        utils.LOGGER.debug(
            "DB: creating a local bulk upsert (%d records)", config.LOCAL_BATCH_SIZE
        )
        if separated_timestamps:
            for timestamp, spec in specs:
                if spec is None:
                    continue
                infos = spec.pop("infos", None)
                spec = tuple((key, spec[key]) for key in sorted(spec))
                records.setdefault(spec, _RecInfo(infos)).update(timestamp)
                if len(records) >= config.LOCAL_BATCH_SIZE:
                    _bulk_execute(records)
                    records = {}
        else:
            for spec in specs:
                if spec is None:
                    continue
                infos = spec.pop("infos", None)
                basespec = tuple(
                    (key, spec[key])
                    for key in sorted(spec)
                    if key not in ["count", "firstseen", "lastseen"]
                )
                records.setdefault(basespec, _RecInfo(infos)).update_from_spec(spec)
                if len(records) >= config.LOCAL_BATCH_SIZE:
                    _bulk_execute(records)
                    records = {}
        _bulk_execute(records)

    def _features_port_get(
        self, features, flt, yieldall, use_service, use_product, use_version
    ):
        curaddr = None
        currec = None
        if use_version:

            def _extract(rec):
                info = rec.get("infos", {})
                yield (
                    rec["port"],
                    info.get("service_name"),
                    info.get("service_product"),
                    info.get("service_version"),
                )
                if not yieldall:
                    return
                if info.get("service_version") is not None:
                    yield (
                        rec["port"],
                        info.get("service_name"),
                        info.get("service_product"),
                        None,
                    )
                if info.get("service_product") is not None:
                    yield (rec["port"], info.get("service_name"), None, None)
                if info.get("service_name") is not None:
                    yield (rec["port"], None, None, None)

        elif use_product:

            def _extract(rec):
                info = rec.get("infos", {})
                yield (
                    rec["port"],
                    info.get("service_name"),
                    info.get("service_product"),
                )
                if not yieldall:
                    return
                if info.get("service_product") is not None:
                    yield (rec["port"], info.get("service_name"), None)
                if info.get("service_name") is not None:
                    yield (rec["port"], None, None)

        elif use_service:

            def _extract(rec):
                info = rec.get("infos", {})
                yield (rec["port"], info.get("service_name"))
                if not yieldall:
                    return
                if info.get("service_name") is not None:
                    yield (rec["port"], None)

        else:

            def _extract(rec):
                yield (rec["port"],)

        n_features = len(features)
        for rec in self.get(
            self.flt_and(flt, self._search_field_exists("port")), sort=[("addr", 1)]
        ):
            # the addr aggregation could (should?) be done with an
            # aggregation framework pipeline
            if curaddr != rec["addr"]:
                if curaddr is not None:
                    yield (curaddr, currec)
                curaddr = rec["addr"]
                currec = [0] * n_features
            for feat in _extract(rec):
                # We could use += rec['count'] instead here
                currec[features[feat]] = 1
        if curaddr is not None:
            yield (curaddr, currec)

    def _search_field_exists(self, field):
        raise NotImplementedError

    def searchcountry(self, code, neg=False):
        return self.searchranges(geoiputils.get_ranges_by_country(code), neg=neg)

    def searchasnum(self, asnum, neg=False):
        return self.searchranges(geoiputils.get_ranges_by_asnum(asnum), neg=neg)

    @classmethod
    def searchranges(cls, ranges, neg=False):
        """Filters (if `neg` == True, filters out) some IP address ranges.

        `ranges` is an instance of ivre.geoiputils.IPRanges().

        """
        flt = []
        for start, stop in ranges.iter_ranges():
            flt.append(
                cls.searchrange(cls.ip2internal(start), cls.ip2internal(stop), neg=neg)
            )
        if flt:
            return (cls.flt_and if neg else cls.flt_or)(*flt)
        return cls.flt_empty if neg else cls.searchnonexistent()

    @staticmethod
    def searchdns(name=None, reverse=False, dnstype=None, subdomains=False):
        """Filters DNS records for domain `name` or type `dnstype`.
        `name` can be a string, a list or a regular expression.
        If `reverse` is set to True, filters reverse records.
        `dnstype` if specified, may be "A", "AAAA", "PTR".
        If `subdomains` is set to True, the filter will match any subdomains.
        """
        raise NotImplementedError

    def get(self, spec, **kargs):
        """Queries the active column with the provided filter "spec",
        and returns a generator."""
        raise NotImplementedError

    @staticmethod
    def _update_dns_blacklist(old_spec):
        """Create a new dns blacklist entry based on the value of
        the old dns entry"""
        dnsbl_val = old_spec["value"]
        return {
            "recontype": "DNS_BLACKLIST",
            "value": old_spec["addr"],
            "source": "%s-%s" % (dnsbl_val.split(".", 4)[4], old_spec["source"]),
            "addr": ".".join(dnsbl_val.split(".")[3::-1]),
            "count": old_spec["count"],
            "schema_version": passive.SCHEMA_VERSION,
        }

    def update_dns_blacklist(self):
        """Update the current database to detect blacklist domains.
        This function inserts a new element in the database, corresponding to the
        old element and delete the existing one."""

        flt = self.searchdns(list(config.DNS_BLACKLIST_DOMAINS), subdomains=True)
        base = self.get(flt)
        for old_spec in base:
            if any(
                old_spec["value"].endswith(dnsbl)
                for dnsbl in config.DNS_BLACKLIST_DOMAINS
            ):
                spec = self._update_dns_blacklist(old_spec)
                self.insert_or_update(
                    old_spec["firstseen"], spec, lastseen=old_spec["lastseen"]
                )
                self.remove(old_spec["_id"])

    @staticmethod
    def searchsensor(sensor, neg=False):
        raise NotImplementedError

    @classmethod
    def searchcategory(cls, cat, neg=False):
        """Filters (if `neg` == True, filters out) one particular category
        (records may have zero, one or more categories). We use the
        "sensor" field as a category equivalent for passive DB.

        """
        return cls.searchsensor(cat, neg=neg)


class DBData(DB):
    country_codes = None

    def infos_byip(self, addr):
        infos = {}
        addr_type = utils.get_addr_type(addr)
        if addr_type:
            infos["address_type"] = addr_type
        for infos_byip in [self.as_byip, self.country_byip, self.location_byip]:
            infos.update(infos_byip(addr) or {})
        if infos:
            return infos
        return None

    def as_byip(self, addr):
        raise NotImplementedError

    def location_byip(self, addr):
        raise NotImplementedError

    def country_byip(self, addr):
        raise NotImplementedError


class LockError(RuntimeError):
    """A runtime error used when a lock cannot be acquired or released."""


class DBAgent(DB):
    """Backend-independent code to handle agents-in-DB"""

    def add_agent(
        self, masterid, host, remotepath, rsync=None, source=None, maxwaiting=60
    ):
        """Prepares an agent and adds it to the DB using
        `self._add_agent()`

        """
        if rsync is None:
            rsync = ["rsync"]
        if not remotepath.endswith("/"):
            remotepath += "/"
        if source is None:
            source = remotepath if host is None else "%s:%s" % (host, remotepath)
        master = self.get_master(masterid)
        localpath = tempfile.mkdtemp(prefix="", dir=master["path"])
        for dirname in ["input"] + [
            os.path.join("remote", dname) for dname in ["input", "cur", "output"]
        ]:
            utils.makedirs(os.path.join(localpath, dirname))
        agent = {
            "host": host,
            "path": {
                "remote": remotepath,
                "local": localpath,
            },
            "source": source,
            "rsync": rsync,
            "maxwaiting": maxwaiting,
            "scan": None,
            "sync": True,
            "master": masterid,
        }
        return self._add_agent(agent)

    def stop_agent(self, agentid):
        agent = self.get_agent(agentid)
        if agent is None:
            raise IndexError("Agent not found [%r]" % agentid)
        if agent["scan"] is not None:
            self.unassign_agent(agent["_id"])

    def add_agent_from_string(self, masterid, string, source=None, maxwaiting=60):
        """Adds an agent from a description string of the form
        [tor:][hostname:]path.

        """
        string = string.split(":", 1)
        if string[0].lower() == "tor":
            string = string[1].split(":", 1)
            rsync = ["torify", "rsync"]
        else:
            rsync = None
        if len(string) == 1:
            return self.add_agent(
                masterid,
                None,
                string[0],
                rsync=rsync,
                source=source,
                maxwaiting=maxwaiting,
            )
        return self.add_agent(
            masterid,
            string[0],
            string[1],
            rsync=rsync,
            source=source,
            maxwaiting=maxwaiting,
        )

    def may_receive(self, agentid):
        """Returns the number of targets that can be added to an agent
        without exceeding its `maxwaiting` limit (the returned value
        cannot be negative).

        """
        agent = self.get_agent(agentid)
        return max(agent["maxwaiting"] - self.count_waiting_targets(agentid), 0)

    def count_waiting_targets(self, agentid):
        """Returns the number of waiting targets an agent has."""
        agent = self.get_agent(agentid)
        return sum(
            len(os.listdir(self.get_local_path(agent, path)))
            for path in ["input", os.path.join("remote", "input")]
        )

    def count_current_targets(self, agentid):
        """Returns the number of waiting targets an agent has."""
        agent = self.get_agent(agentid)
        return sum(
            1
            for fname in os.listdir(
                self.get_local_path(agent, os.path.join("remote", "cur"))
            )
            if fname.endswith(".xml")
        )

    @staticmethod
    def get_local_path(agent, dirname):
        if not dirname.endswith("/"):
            dirname += "/"
        return os.path.join(agent["path"]["local"], dirname)

    @staticmethod
    def get_remote_path(agent, dirname):
        if dirname and not dirname.endswith("/"):
            dirname += "/"
        return "%s%s" % (
            "" if agent["host"] is None else "%s:" % agent["host"],
            os.path.join(agent["path"]["remote"], dirname),
        )

    def sync_all(self, masterid):
        for agentid in self.get_agents_by_master(masterid):
            self.sync(agentid)

    def sync(self, agentid):
        agent = self.get_agent(agentid)
        master = self.get_master(agent["master"])
        subprocess.call(
            agent["rsync"]
            + [
                "-a",
                self.get_local_path(agent, "input"),
                self.get_local_path(agent, os.path.join("remote", "input")),
            ]
        )
        subprocess.call(
            agent["rsync"]
            + [
                "-a",
                "--remove-source-files",
                self.get_local_path(agent, "input"),
                self.get_remote_path(agent, "input"),
            ]
        )
        for dname in ["input", "cur"]:
            subprocess.call(
                agent["rsync"]
                + [
                    "-a",
                    "--delete",
                    self.get_remote_path(agent, dname),
                    self.get_local_path(agent, os.path.join("remote", dname)),
                ]
            )
        subprocess.call(
            agent["rsync"]
            + [
                "-a",
                "--remove-source-files",
                self.get_remote_path(agent, "output"),
                self.get_local_path(agent, os.path.join("remote", "output")),
            ]
        )
        outpath = self.get_local_path(agent, os.path.join("remote", "output"))
        for fname in os.listdir(outpath):
            scanid = fname.split("-", 1)[0]
            scan = self.get_scan(self.str2id(scanid))
            storedir = os.path.join(
                master["path"],
                "output",
                scanid,
                str(agentid),
            )
            utils.makedirs(storedir)
            with tempfile.NamedTemporaryFile(
                prefix="", suffix=".xml", dir=storedir, delete=False
            ) as fdesc:
                pass
            shutil.move(os.path.join(outpath, fname), fdesc.name)
            self.globaldb.nmap.store_scan(
                fdesc.name,
                categories=scan["target_info"]["categories"],
                source=agent["source"],
            )
            self.incr_scan_results(self.str2id(scanid))

    def feed_all(self, masterid):
        for scanid in self.get_scans():
            try:
                self.feed(masterid, scanid)
            except LockError:
                utils.LOGGER.error(
                    "Lock error - is another daemon process running?",
                    exc_info=True,
                )

    def feed(self, masterid, scanid):
        scan = self.lock_scan(scanid)
        # TODO: handle "onhold" targets
        target = self.get_scan_target(scanid)
        try:
            for agentid in scan["agents"]:
                if self.get_agent(agentid)["master"] == masterid:
                    for _ in range(self.may_receive(agentid)):
                        self.add_target(agentid, scanid, next(target))
        except StopIteration:
            # This scan is over, let's free its agents
            for agentid in scan["agents"]:
                self.unassign_agent(agentid)
        self.update_scan_target(scanid, target)
        self.unlock_scan(scan)

    def add_target(self, agentid, scanid, addr):
        agent = self.get_agent(agentid)
        try:
            addr = int(addr)
            addr = utils.int2ip(addr)
        except (ValueError, TypeError, struct.error):
            pass
        with tempfile.NamedTemporaryFile(
            prefix=str(scanid) + "-",
            dir=self.get_local_path(agent, "input"),
            delete=False,
            mode="w",
        ) as fdesc:
            fdesc.write("%s\n" % addr)
            return True
        return False

    def _add_agent(self, agent):
        """Adds an agent and returns its (backend-specific) unique
        identifier.

        This is implemented in the backend-specific class.

        """
        raise NotImplementedError

    def get_agent(self, agentid):
        """Gets an agent from its (backend-specific) unique
        identifier.

        This is implemented in the backend-specific class.

        """
        raise NotImplementedError

    def get_free_agents(self):
        raise NotImplementedError

    def get_agents_by_master(self, masterid):
        raise NotImplementedError

    def get_agents(self):
        raise NotImplementedError

    def del_agent(self, agentid, wait_results=True):
        """Removes an agent from its (backend-specific) unique
        identifier.
        """
        agent = self.get_agent(agentid)
        master = self.get_master(agent["master"])
        # stop adding targets
        self.unassign_agent(agentid, dont_reuse=True)
        # remove not-yet-sent targets
        path = self.get_local_path(agent, "input")
        dstdir = os.path.join(master["path"], "onhold")
        for fname in os.listdir(path):
            shutil.move(os.path.join(path, fname), dstdir)
        if wait_results:
            self.sync(agentid)

    def _del_agent(self, agentid):
        """Removes an agent's database entry from its
        (backend-specific) unique identifier.

        This is implemented in the backend-specific class.

        """
        raise NotImplementedError

    def add_scan(self, target, assign_to_free_agents=True):
        itertarget = iter(target)
        try:
            fdesc = itertarget.fdesc
        except AttributeError:
            pass
        else:
            if fdesc.closed:
                itertarget.fdesc = (False, 0)
            else:
                itertarget.fdesc = (True, fdesc.tell())
        scan = {
            "target": self.to_binary(pickle.dumps(itertarget)),
            "target_info": target.infos,
            "agents": [],
            "results": 0,
            "lock": None,
        }
        scanid = self._add_scan(scan)
        if assign_to_free_agents:
            for agentid in self.get_free_agents():
                self.assign_agent(agentid, scanid)

    def _add_scan(self, scan):
        raise NotImplementedError

    def get_scan_target(self, scanid):
        res = pickle.loads(self._get_scan_target(scanid))
        if hasattr(res, "fdesc"):
            opened, seekval = res.fdesc
            # pylint: disable=consider-using-with
            res.fdesc = open(res.target.filename)
            if opened:
                res.fdesc.seek(seekval)
            else:
                res.fdesc.close()
        return res

    def _get_scan_target(self, scanid):
        raise NotImplementedError

    def lock_scan(self, scanid):
        """Acquire lock for scanid. Returns the new scan object on success,
        and raises a LockError on failure.

        """
        lockid = uuid.uuid1()
        scan = self._lock_scan(scanid, None, lockid.bytes)
        if scan["lock"] is not None:
            scan["lock"] = uuid.UUID(bytes=scan["lock"])
        if scan["lock"] == lockid:
            return scan
        return None

    def unlock_scan(self, scan):
        """Release lock for scanid. Returns True on success, and raises a
        LockError on failure.

        """
        if scan.get("lock") is None:
            raise LockError(
                "Cannot release lock for %r: scan is not " "locked" % scan["_id"]
            )
        scan = self._lock_scan(scan["_id"], scan["lock"].bytes, None)
        return scan["lock"] is None

    def _lock_scan(self, scanid, oldlockid, newlockid):
        raise NotImplementedError

    def get_scan(self, scanid):
        raise NotImplementedError

    def get_scans(self):
        raise NotImplementedError

    def assign_agent(self, agentid, scanid, only_if_unassigned=False, force=False):
        raise NotImplementedError

    def unassign_agent(self, agentid, dont_reuse=False):
        raise NotImplementedError

    def update_scan_target(self, scanid, target):
        try:
            fdesc = target.fdesc
        except AttributeError:
            pass
        else:
            if fdesc.closed:
                target.fdesc = (False, 0)
            else:
                target.fdesc = (True, fdesc.tell())
        return self._update_scan_target(scanid, self.to_binary(pickle.dumps(target)))

    def _update_scan_target(self, scanid, target):
        raise NotImplementedError

    def incr_scan_results(self, scanid):
        raise NotImplementedError

    def add_local_master(self, path):
        masterid = self.add_master(socket.gethostname(), path)
        with open(os.path.join(path, "whoami"), "w") as fdesc:
            fdesc.write(str(masterid))
        return masterid

    def add_master(self, hostname, path):
        """Prepares a master and adds it to the DB using
        `self._add_master()`

        """
        master = {
            "hostname": hostname,
            "path": path,
        }
        return self._add_master(master)

    def _add_master(self, master):
        """Adds a master and returns its (backend-specific) unique
        identifier.

        This is implemented in the backend-specific class.

        """
        raise NotImplementedError

    def get_master(self, masterid):
        raise NotImplementedError

    def masterid_from_dir(self, path):
        with open(os.path.join(path, "whoami")) as fdesc:
            return self.str2id(fdesc.read())


class DBFlowMeta(type):
    """
    This metaclass aims to compute 'meta_desc' and 'list_fields' once for all
    instances of MongoDBFlow and TinyDBFlow.
    """

    def __new__(cls, name, bases, attrs):
        attrs["meta_desc"] = DBFlowMeta.compute_meta_desc()
        attrs["list_fields"] = DBFlowMeta.compute_list_fields(attrs["meta_desc"])
        return type.__new__(cls, name, bases, attrs)

    @staticmethod
    def compute_meta_desc():
        """
        Computes meta_desc from flow.META_DESC
        meta_desc is a "usable" version of flow.META_DESC. It is computed only
        once at class initialization.
        """
        meta_desc = {}
        for proto, configs in flow.META_DESC.items():
            meta_desc[proto] = {}
            for kind, values in configs.items():
                meta_desc[proto][kind] = utils.normalize_props(values)
        return meta_desc

    @staticmethod
    def compute_list_fields(meta_desc):
        """
        Computes list_fields from meta_desc.
        """
        list_fields = ["sports", "codes", "times"]
        for proto, kinds in meta_desc.items():
            for kind, values in kinds.items():
                if kind == "keys":
                    for name in values:
                        list_fields.append("meta.%s.%s" % (proto, name))
        return list_fields


class DBFlow(DB):
    """Backend-independent code to handle flows"""

    @classmethod
    def date_round(cls, date):
        if isinstance(date, datetime):
            ts = date.timestamp()
        else:
            ts = date
        ts = ts - (ts % config.FLOW_TIME_PRECISION)
        if isinstance(date, datetime):
            return datetime.fromtimestamp(ts)
        return ts

    @classmethod
    def from_filters(
        cls,
        filters,
        limit=None,
        skip=0,
        orderby="",
        mode=None,
        timeline=False,
        after=None,
        before=None,
        precision=None,
    ):
        """
        Returns a flow.Query object representing the given filters
        This should be inherited by backend specific classes
        """
        query = flow.Query()
        for flt_type in ["node", "edge"]:
            for flt in filters.get("%ss" % flt_type, []):
                query.add_clause_from_filter(flt, mode=flt_type)
        return query

    @classmethod
    def _get_timeslots(cls, start_time, end_time):
        """
        Returns an array of timeslots included between start_time and end_time
        """
        times = []
        first_timeslot = cls._get_timeslot(
            start_time, config.FLOW_TIME_PRECISION, config.FLOW_TIME_BASE
        )
        time = first_timeslot["start"]
        last_timeslot = cls._get_timeslot(
            end_time, config.FLOW_TIME_PRECISION, config.FLOW_TIME_BASE
        )
        end_time = last_timeslot["start"]
        while time <= end_time:
            d = OrderedDict()
            d["start"] = time
            d["duration"] = config.FLOW_TIME_PRECISION
            times.append(d)
            time += timedelta(seconds=config.FLOW_TIME_PRECISION)
        return times

    @staticmethod
    def _get_timeslot(time, precision, base):
        ts = time.timestamp()
        ts += utils.tz_offset(ts)
        new_ts = ts - (((ts % precision) - base) % precision)
        new_ts -= utils.tz_offset(new_ts)
        d = OrderedDict()
        d["start"] = datetime.fromtimestamp(new_ts)
        d["duration"] = precision
        return d

    def reduce_precision(
        self, new_precision, flt=None, before=None, after=None, current_precision=None
    ):
        """
        Changes precision of timeslots to <new_precision> of flows
        honoring:
            - the given filter <flt> if specified
            - that have been seen before <before> if specified
            - that have been seen after <after> if specified
            - timeslots changed must currently have <current_precision> if
                specified
        <base> represents the timestamp of the base point.
        If <current_precision> is specified:
            - <new_precision> must be a multiple of <current_precision>
            - <new_precision> must be greater than <current_precision>
        Timeslots that do not respect these rules will not be updated.
        """
        raise NotImplementedError("Only available with MongoDB backend.")

    def list_precisions(self):
        """
        Retrieves the list of timeslots precisions in the database.
        """
        raise NotImplementedError("Only available with MongoDB backend.")

    def count(self, flt):
        """
        Returns a dict {'client': nb_clients, 'servers': nb_servers',
        'flows': nb_flows} according to the given filter.
        """
        raise NotImplementedError

    def flow_daily(self, precision, flt, after=None, before=None):
        """
        Returns a generator within each element is a dict
        {
            flows: [("proto/dport", count), ...]
            time_in_day: time
        }
        """
        raise NotImplementedError

    @staticmethod
    def _flow2host(row, prefix):
        """
        Returns a dict which represents one of the two host of the given flow.
        prefix should be 'dst' or 'src' to get the source or the destination
        host.
        """
        res = {}
        if prefix == "src":
            res["addr"] = row.get("src_addr")
        elif prefix == "dst":
            res["addr"] = row.get("dst_addr")
        else:
            raise Exception("prefix must be 'dst' or 'src'")
        res["firstseen"] = row.get("firstseen")
        res["lastseen"] = row.get("lastseen")
        return res

    @staticmethod
    def _node2json(row):
        """
        Returns a dict representing a node in graph output.
        row must be the representation of an host, see _flow2host.
        """
        return {
            "id": row.get("addr"),
            "label": row.get("addr"),
            "labels": ["Host"],
            "x": random.random(),
            "y": random.random(),
            "data": row,
        }

    @staticmethod
    def _edge2json_default(
        row, timeline=False, after=None, before=None, precision=None
    ):
        """
        Returns a dict representing an edge in default graph output.
        row must be a flow entry.
        """
        label = (
            row.get("proto") + "/" + str(row.get("dport"))
            if row.get("proto") in ["tcp", "udp"]
            else row.get("proto") + "/" + str(row.get("type"))
        )
        res = {
            "id": str(row.get("_id")),
            "label": label,
            "labels": ["Flow"],
            "source": row.get("src_addr"),
            "target": row.get("dst_addr"),
            "data": {
                "cspkts": row.get("cspkts"),
                "csbytes": row.get("csbytes"),
                "count": row.get("count"),
                "scpkts": row.get("scpkts"),
                "scbytes": row.get("scbytes"),
                "proto": row.get("proto"),
                "firstseen": row.get("firstseen"),
                "lastseen": row.get("lastseen"),
                "__key__": str(row.get("_id")),
                "addr_src": row.get("src_addr"),
                "addr_dst": row.get("dst_addr"),
            },
        }

        # Fill timeline field if necessary
        if timeline and row.get("times"):
            # Remove timeslots that do not satisfy temporal filters
            res["data"]["meta"] = {
                "times": [
                    t
                    for t in row.get("times")
                    if (
                        (after is None or t.get("start") >= after)
                        and (before is None or t.get("start") < before)
                        and (precision is None or t.get("duration") == precision)
                    )
                ]
            }

        if row.get("proto") in ["tcp", "udp"]:
            res["data"]["sports"] = row.get("sports")
            res["data"]["dport"] = row.get("dport")
        elif row.get("proto") == "icmp":
            res["data"]["codes"] = row.get("codes")
            res["data"]["type"] = row.get("type")
        return res

    @staticmethod
    def _edge2json_flow_map(row):
        """
        Returns a dict representing an edge in flow map graph output.
        row must be a flow entry.
        """
        if row.get("proto") in ["udp", "tcp"]:
            flowkey = (row.get("proto"), row.get("dport"))
        else:
            flowkey = (row.get("proto"), None)
        res = {
            "id": str(row.get("_id")),
            "label": "MERGED_FLOWS",
            "labels": ["MERGED_FLOWS"],
            "source": row.get("src_addr"),
            "target": row.get("dst_addr"),
            "data": {"count": 1, "flows": [flowkey]},
        }
        return res

    @staticmethod
    def _edge2json_talk_map(row):
        """
        Returns a dict representing an edge in talk map graph output.
        row must be a flow entry.
        """
        res = {
            "id": str(row.get("_id")),
            "label": "TALK",
            "labels": ["TALK"],
            "source": row.get("src_addr"),
            "target": row.get("dst_addr"),
            "data": {"count": 1, "flows": ["TALK"]},
        }
        return res

    @classmethod
    def cursor2json_iter(
        cls, cursor, mode=None, timeline=False, after=None, before=None, precision=None
    ):
        """Takes a cursor on flows collection and for each entry yield a dict
        {src: src_node, dst: dst_node, flow: flow_edge}.

        """
        random.seed()
        for row in cursor:
            src_node = cls._node2json(cls._flow2host(row, "src"))
            dst_node = cls._node2json(cls._flow2host(row, "dst"))
            flow_node = []
            if mode == "flow_map":
                flow_node = cls._edge2json_flow_map(row)
            elif mode == "talk_map":
                flow_node = cls._edge2json_talk_map(row)
            else:
                flow_node = cls._edge2json_default(
                    row,
                    timeline=timeline,
                    after=after,
                    before=before,
                    precision=precision,
                )
            yield {"src": src_node, "dst": dst_node, "flow": flow_node}

    @classmethod
    def cursor2json_graph(
        cls, cursor, mode, timeline, after=None, before=None, precision=None
    ):
        """
        Returns a dict {"nodes": [], "edges": []} representing the output
        graph.
        Nodes are unique hosts. Edges are flows, formatted according to the
        given mode.
        """
        g = {"nodes": [], "edges": []}
        # Store unique hosts
        hosts = {}
        # Store tuples (source, dest) for flow and talk map modes.
        edges = {}
        for row in cls.cursor2json_iter(
            cursor,
            mode=mode,
            timeline=timeline,
            after=after,
            before=before,
            precision=precision,
        ):
            if mode in ["flow_map", "talk_map"]:
                flw = row["flow"]
                # If this edge already exists
                if (flw["source"], flw["target"]) in edges:
                    edge = edges[(flw["source"], flw["target"])]
                    if mode == "flow_map":
                        # In flow map mode, store flows data in each edge
                        flows = flw["data"]["flows"]
                        if flows[0] not in edge["data"]["flows"]:
                            edge["data"]["flows"].append(flows[0])
                            edge["data"]["count"] += 1
                else:
                    edges[(flw["source"], flw["target"])] = flw
            else:
                g["edges"].append(row["flow"])
            for host in (row["src"], row["dst"]):
                if host["id"] in hosts:
                    hosts[host["id"]]["data"]["firstseen"] = min(
                        hosts[host["id"]]["data"]["firstseen"],
                        host["data"]["firstseen"],
                    )
                    hosts[host["id"]]["data"]["lastseen"] = max(
                        hosts[host["id"]]["data"]["lastseen"], host["data"]["lastseen"]
                    )
                else:
                    hosts[host["id"]] = host
        g["nodes"] = list(hosts.values())
        if mode in ["flow_map", "talk_map"]:
            g["edges"] = list(edges.values())
        return g

    def to_graph(
        self,
        flt,
        limit=None,
        skip=None,
        orderby=None,
        mode=None,
        timeline=False,
        after=None,
        before=None,
    ):
        """Returns a dict {"nodes": [], "edges": []}."""
        return self.cursor2json_graph(
            self.get(flt, orderby=orderby, skip=skip, limit=limit),
            mode,
            timeline,
            after=after,
            before=before,
        )

    def to_iter(
        self,
        flt,
        limit=None,
        skip=None,
        orderby=None,
        mode=None,
        timeline=False,
        after=None,
        before=None,
        precision=None,
    ):
        """
        Returns an iterator which yields dict {"src": src, "dst": dst,
        "flow": flow}.
        """
        return self.cursor2json_iter(
            self.get(flt, orderby=orderby, skip=skip, limit=limit),
            mode=mode,
            timeline=timeline,
        )

    def host_details(self, node_id):
        """
        Returns details about an host with the given address
        Details means a dict : {
            in_flows: set() => incoming flows (proto, dport),
            out_flows: set() => outcoming flows (proto, dport),
            elt: {} => data about the host
            clients: set() => hosts which talked to this host
            servers: set() => hosts which this host talked to
        }
        """
        raise NotImplementedError

    def flow_details(self, flow_id):
        """
        Returns details about a flow with the given ObjectId.
        Details mean : {
            elt: {} => basic data about the flow,
            meta: [] => meta entries corresponding to the flow
        }
        """
        raise NotImplementedError

    def topvalues(
        self,
        flt,
        fields,
        collect_fields=None,
        sum_fields=None,
        limit=None,
        skip=None,
        least=False,
        topnbr=10,
    ):
        """
        Returns the top values honoring the given `query` for the given
        fields list `fields`, counting and sorting the aggregated records
        by `sum_fields` sum and storing the `collect_fields` fields of
        each original entry in aggregated records as a list.
        By default, the aggregated records are sorted by their number of
        occurrences.
        Return format:
            {
                fields: (field_1_value, field_2_value, ...),
                count: count,
                collected: [
                    (collect_1_value, collect_2_value, ...),
                    ...
                ]
            }
        Collected fields are unique.
        """
        raise NotImplementedError


class MetaDB:

    # Backend-specific purpose-specific sub-classes (e.g.,
    # MongoDBNmap) must be "registered" in this dict.
    #
    # The keys are the purposes ("nmap", "view", "passive", etc.), and
    # the values are dict objects which, in turn, associate a backend
    # name (as used as the scheme of the URLs in the configuration DB*
    # values, such as "mongodb", "http", "postgresql", etc.) to
    # tuples; the first element of those tuples is the sub-module name
    # ("mongo" for "ivre.db.mongo"), and the second is the class name.
    #
    # {"purpose": {"scheme": ("module_name", "ClassName"),
    #              [...]},
    #  [...]}
    db_types = {
        "nmap": {
            "http": ("http", "HttpDBNmap"),
            "mongodb": ("mongo", "MongoDBNmap"),
            "postgresql": ("sql.postgres", "PostgresDBNmap"),
            "tinydb": ("tiny", "TinyDBNmap"),
        },
        "passive": {
            "http": ("http", "HttpDBPassive"),
            "mongodb": ("mongo", "MongoDBPassive"),
            "postgresql": ("sql.postgres", "PostgresDBPassive"),
            "sqlite": ("sql.sqlite", "SqliteDBPassive"),
            "tinydb": ("tiny", "TinyDBPassive"),
        },
        "data": {
            "http": ("http", "HttpDBData"),
            "maxmind": ("maxmind", "MaxMindDBData"),
        },
        "agent": {
            "mongodb": ("mongo", "MongoDBAgent"),
            "tinydb": ("tiny", "TinyDBAgent"),
        },
        "flow": {
            "mongodb": ("mongo", "MongoDBFlow"),
            "postgresql": ("sql.postgres", "PostgresDBFlow"),
            "tinydb": ("tiny", "TinyDBFlow"),
        },
        "view": {
            "elastic": ("elastic", "ElasticDBView"),
            "http": ("http", "HttpDBView"),
            "mongodb": ("mongo", "MongoDBView"),
            "postgresql": ("sql.postgres", "PostgresDBView"),
            "tinydb": ("tiny", "TinyDBView"),
        },
    }

    def __init__(self, url=None, urls=None):
        self.url = url
        self.urls = urls or {}

    @property
    def nmap(self):
        try:
            # pylint: disable=access-member-before-definition
            return self._nmap
        except AttributeError:
            pass
        self._nmap = self.get_class("nmap")
        return self._nmap

    @property
    def passive(self):
        try:
            # pylint: disable=access-member-before-definition
            return self._passive
        except AttributeError:
            pass
        self._passive = self.get_class("passive")
        return self._passive

    @property
    def data(self):
        try:
            # pylint: disable=access-member-before-definition
            return self._data
        except AttributeError:
            pass
        self._data = self.get_class("data")
        return self._data

    @property
    def agent(self):
        try:
            # pylint: disable=access-member-before-definition
            return self._agent
        except AttributeError:
            pass
        self._agent = self.get_class("agent")
        return self._agent

    @property
    def flow(self):
        try:
            # pylint: disable=access-member-before-definition
            return self._flow
        except AttributeError:
            pass
        self._flow = self.get_class("flow")
        return self._flow

    @property
    def view(self):
        try:
            # pylint: disable=access-member-before-definition
            return self._view
        except AttributeError:
            pass
        self._view = self.get_class("view")
        return self._view

    def get_class(self, purpose):
        url = self.urls.get(purpose, self.url)
        if url is not None:
            url = urlparse(url)
            db_type = url.scheme
            if db_type == "https":
                db_type = "http"
            try:
                modulename, classname = self.db_types[purpose][db_type]
            except (KeyError, TypeError):
                utils.LOGGER.error(
                    "Cannot get database for %s from %s",
                    purpose,
                    url.geturl(),
                    exc_info=True,
                )
                return None
            try:
                module = import_module("ivre.db.%s" % modulename)
            except ImportError:
                utils.LOGGER.error(
                    "Cannot import ivre.db.%s for %s",
                    modulename,
                    url.geturl(),
                    exc_info=True,
                )
                return None
            result = getattr(module, classname)(url)
            result.globaldb = self
            return result
        return None


db = MetaDB(
    url=config.DB if hasattr(config, "DB") else None,
    urls=dict(
        [x[3:].lower(), getattr(config, x)] for x in dir(config) if x.startswith("DB_")
    ),
)
