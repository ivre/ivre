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

"""This sub-module contains functions to interact with the
database backends.
"""

try:
    from collections import OrderedDict
except ImportError:
    # fallback to dict for Python 2.6
    OrderedDict = dict
from datetime import datetime, timedelta
from functools import reduce
import json
import os
import pickle
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
import uuid
import xml.sax


from builtins import range
from future.utils import viewitems, viewvalues
# tests: I don't want to depend on cluster for now
try:
    import cluster
    USE_CLUSTER = True
except ImportError:
    USE_CLUSTER = False


from ivre import config, geoiputils, nmapout, utils, xmlnmap, flow


class DB(object):
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

    def __init__(self):
        self.argparser = utils.ArgparserParent()
        self.argparser.add_argument(
            '--country', metavar='CODE',
            help='show only results from this country'
        )
        self.argparser.add_argument(
            '--asnum', metavar='NUM[,NUM[...]]',
            help='show only results from this(those) AS(es)'
        )
        self.argparser.add_argument('--port', metavar='PORT')
        self.argparser.add_argument('--service', metavar='SVC')
        self.argparser.add_argument('--svchostname', metavar='HOSTNAME')
        self.argparser.add_argument('--useragent', metavar='USER-AGENT',
                                    nargs='?', const=False)

    def parse_args(self, args, flt=None):
        if flt is None:
            flt = self.flt_empty
        if args.country is not None:
            flt = self.flt_and(flt, self.searchcountry(
                utils.str2list(args.country)
            ))
        if args.asnum is not None:
            if args.asnum[:1] in '!-':
                flt = self.flt_and(flt, self.searchasnum(
                    utils.str2list(args.asnum[1:]), neg=True
                ))
            else:
                flt = self.flt_and(flt, self.searchasnum(
                    utils.str2list(args.asnum)
                ))
        if args.port is not None:
            port = args.port.replace('_', '/')
            if '/' in port:
                proto, port = port.split('/', 1)
            else:
                proto = 'tcp'
            port = int(port)
            flt = self.flt_and(
                flt,
                self.searchport(port=port, protocol=proto)
            )
        if args.service is not None:
            flt = self.flt_and(
                flt,
                self.searchservice(utils.str2regexp(args.service)),
            )
        if args.svchostname is not None:
            flt = self.flt_and(
                flt,
                self.searchsvchostname(utils.str2regexp(args.svchostname))
            )
        if args.useragent is not None:
            if args.useragent is False:
                flt = self.flt_and(flt, self.searchuseragent())
            else:
                flt = self.flt_and(
                    flt,
                    self.searchuseragent(
                        useragent=utils.str2regexp(args.useragent)
                    ),
                )
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
        return reduce(cls._flt_and, args)

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
        return reduce(cls._flt_or, args)

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
        result = ['asnum'] if use_asnum else []
        if use_single_int:
            return result + ['addr']
        return result + ['addr_%d' % d for d in range(16 if use_ipv6 else 4)]

    def features_addr_get(self, addr, use_asnum, use_ipv6, use_single_int):
        """Returns a list of feature values (for ML algorithms) for an IP address.

See .features_addr_list() for the number and meaning of the features.

        """
        if use_asnum:
            result = [self.globaldb.data.as_byip(addr).get('as_num', 0)]
        else:
            result = []
        if use_single_int:
            if use_ipv6:
                return result + [utils.ip2int(addr if ':' in addr
                                              else ('::ffff:%s' % addr))]
            return result + [utils.ip2int(addr)]
        addrbin = utils.ip2bin(addr)
        if use_ipv6:
            return result + [
                ord(addrbin[i:i + 1]) for i in range(len(addrbin))
            ]
        return result + [
            ord(addrbin[i:i + 1]) for i in range(len(addrbin))
        ][-4:]

    def features_port_list(self, flt, yieldall, use_service, use_product,
                           use_version):
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
            # when `yieldall` is false, the sort operation is done in
            # database, unless we are using MongoDB < 3.2
            try:
                supports_sort = self.mongodb_32_more
            except AttributeError:
                supports_sort = True
            if supports_sort:
                return list(
                    tuple(val) for val in
                    self._features_port_list(flt, yieldall, use_service,
                                             use_product, use_version)
                )
            return sorted(set(
                tuple(val) for val in
                self._features_port_list(flt, yieldall, use_service,
                                         use_product, use_version)
            ), key=lambda val: [utils.key_sort_none(v) for v in val])

        def _gen(val):
            yield tuple(val)
            for i in range(-1, -len(val), -1):
                val[i] = None
                yield tuple(val)
        return sorted(set(
            val
            for vals in self._features_port_list(flt, yieldall, use_service,
                                                 use_product, use_version)
            for val in _gen(vals)
        ), key=lambda val: [utils.key_sort_none(v) for v in val])

    def _features_port_list(self, flt, yieldall, use_service, use_product,
                            use_version):
        raise NotImplementedError()

    def features_port_get(self, features, flt, yieldall, use_service,
                          use_product, use_version):
        """Generates `(addr, port_features)` tuples where `addr` is a host IP
address and `port_features` a list of values ports feature values (for ML
algorithms) as lists of values.

`features` is a list of features that may be generated, as provided by
.features_port_list().

        """
        features = dict((f, i) for i, f in enumerate(features))
        return self._features_port_get(features, flt, yieldall, use_service,
                                       use_product, use_version)

    def _features_port_get(self, features, flt, yieldall, use_service,
                           use_product, use_version):
        raise NotImplementedError()

    def features(self, flt=None, use_asnum=True, use_ipv6=True,
                 use_single_int=False, yieldall=True, use_service=True,
                 use_product=False, use_version=False, subflts=None):
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
        headers = self.features_addr_list(
            use_asnum,
            use_ipv6,
            use_single_int,
        ) + features_port
        if subflts:
            if isinstance(subflts[0], (list, tuple)) and len(subflts[0]) == 2:
                generator = subflts
            else:
                generator = enumerate(subflts)
            headers.append('category')
            return (
                headers,
                (
                    self.features_addr_get(
                        addr,
                        use_asnum,
                        use_ipv6,
                        use_single_int,
                    ) + features + [label]
                    for label, subflt in generator
                    for addr, features in self.features_port_get(
                        features_port,
                        self.flt_and(flt, subflt),
                        yieldall,
                        use_service,
                        use_product,
                        use_version,
                    )
                )
            )
        return (
            headers,
            (
                self.features_addr_get(
                    addr,
                    use_asnum,
                    use_ipv6,
                    use_single_int
                ) + features
                for addr, features in self.features_port_get(
                    features_port,
                    flt,
                    yieldall,
                    use_service,
                    use_product,
                    use_version,
                )
            )
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

    @classmethod
    def searchipv4(cls):
        return cls.searchnet('0.0.0.0/0')

    @classmethod
    def searchipv6(cls):
        return cls.searchnet('0.0.0.0/0', neg=True)

    def searchphpmyadmin(self):
        """Finds phpMyAdmin instances based on its cookies."""
        return self.searchcookie('phpMyAdmin')

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
        return self.searchfile(fname=re.compile(
            'vhost|www|web\\.config|\\.htaccess|\\.([aj]sp|php|html?|js|css)',
            re.I))

    def searchfile(self, fname=None, scripts=None):
        """Finds shared files or directories from a name or a
        pattern.

        """
        raise NotImplementedError

    def searchjavaua(self):
        """Finds Java User-Agent."""
        return self.searchuseragent(
            useragent=re.compile('(^| )(Java|javaws)/', flags=0),
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
        return record['_id']

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

    @staticmethod
    def _ja3keyvalue(value_or_hash):
        """Returns the key and the value to search for according
        to the nature of the given argument for ja3 filtering"""
        if isinstance(value_or_hash, utils.REGEXP_T):
            return ('raw', value_or_hash)
        if utils.HEX.search(value_or_hash):
            key = {32: 'md5', 40: 'sha1',
                   64: 'sha256'}.get(len(value_or_hash), 'raw')
        else:
            key = 'raw'
        # If we have the raw value, we compute the MD5 hash because it
        # is indexed, so it will be faster to query.
        if key == 'raw':
            return (
                'md5',
                utils.hashlib.new('md5', value_or_hash.encode()).hexdigest(),
            )
        return (key, value_or_hash)

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
            """Returns a cluster
            """
            return cluster.HierarchicalClustering(
                [rec for rec in values],
                lambda x, y: abs(x['mean'] - y['mean'])
            )

    @staticmethod
    def serialize(obj):
        return utils.serialize(obj)

    @staticmethod
    def cmp_schema_version(*_):
        return 0


class DBActive(DB):
    def __init__(self):
        super(DBActive, self).__init__()
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
            },
        }
        self.argparser.add_argument(
            '--category', metavar='CAT',
            help='show only results from this category'
        )
        self.argparser.add_argument(
            '--asname', metavar='NAME',
            help='show only results from this(those) AS(es)'
        )
        self.argparser.add_argument('--source', metavar='SRC',
                                    help='show only results from this source')
        self.argparser.add_argument('--version', metavar="VERSION", type=int)
        self.argparser.add_argument('--timeago', metavar='SECONDS', type=int)
        if utils.USE_ARGPARSE:
            self.argparser.add_argument('--id', metavar='ID', help='show only '
                                        'results with this(those) ID(s)',
                                        nargs='+')
            self.argparser.add_argument('--no-id', metavar='ID', help='show '
                                        'only results WITHOUT this(those) '
                                        'ID(s)', nargs='+')
        else:
            self.argparser.add_argument('--id', metavar='ID', help='show only '
                                        'results with this ID')
            self.argparser.add_argument('--no-id', metavar='ID', help='show '
                                        'only results WITHOUT this ID')
        self.argparser.add_argument('--host', metavar='IP')
        self.argparser.add_argument('--hostname', metavar='NAME / ~NAME')
        self.argparser.add_argument('--domain', metavar='NAME / ~NAME')
        self.argparser.add_argument('--net', metavar='IP/MASK')
        self.argparser.add_argument('--range', metavar='IP', nargs=2)
        self.argparser.add_argument('--hop', metavar='IP')
        self.argparser.add_argument('--not-port', metavar='PORT')
        self.argparser.add_argument('--openport', action='store_true')
        self.argparser.add_argument('--no-openport', action='store_true')
        self.argparser.add_argument('--countports', metavar='COUNT',
                                    help='show only results with a number of '
                                    'open ports within the provided range',
                                    nargs=2)
        self.argparser.add_argument('--no-countports', metavar='COUNT',
                                    help='show only results with a number of '
                                    'open ports NOT within the provided range',
                                    nargs=2)
        self.argparser.add_argument('--script', metavar='ID[:OUTPUT]')
        self.argparser.add_argument('--no-script', metavar='ID[:OUTPUT]')
        self.argparser.add_argument('--os')
        self.argparser.add_argument('--anonftp', action='store_true')
        self.argparser.add_argument('--anonldap', action='store_true')
        self.argparser.add_argument('--authhttp', action='store_true')
        self.argparser.add_argument('--authbypassvnc', action='store_true')
        self.argparser.add_argument('--ypserv', '--nis', action='store_true')
        self.argparser.add_argument('--nfs', action='store_true')
        self.argparser.add_argument('--x11', action='store_true')
        self.argparser.add_argument('--xp445', action='store_true')
        self.argparser.add_argument('--httphdr')
        self.argparser.add_argument('--owa', action='store_true')
        self.argparser.add_argument('--vuln-boa', '--vuln-intersil',
                                    action='store_true')
        self.argparser.add_argument('--torcert', action='store_true')
        self.argparser.add_argument('--sshkey', metavar="FINGERPRINT")

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
        url = port.get('screenshot')
        if url is None:
            return None
        if url == "field":
            return port.get('screendata')
        return None

    def migrate_schema(self, version):
        """Implemented in backend-specific classes.

        """

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
            if port.get('state_state') == 'open':
                openports.setdefault(port["protocol"], {}).setdefault(
                    "ports", []).append(port["port"])
            # create the screenwords attribute
            if 'screenshot' in port and 'screenwords' not in port:
                screenwords = utils.screenwords(cls.getscreenshot(port))
                if screenwords is not None:
                    port['screenwords'] = screenwords
        for proto in list(openports):
            if proto == 'count':
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
                    if key.startswith('service_'):
                        del port[key]

    @staticmethod
    def __migrate_schema_hosts_2_3(doc):
        """Converts a record from version 2 to version 3. Version 3
        uses new Nmap structured data for scripts using the ls
        library.

        """
        assert doc["schema_version"] == 2
        doc["schema_version"] = 3
        migrate_scripts = set([
            "afp-ls", "nfs-ls", "smb-ls", "ftp-anon", "http-ls"
        ])
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] in migrate_scripts:
                    if script['id'] in script:
                        script["ls"] = xmlnmap.change_ls(
                            script.pop(script['id']))
                    elif "ls" not in script:
                        data = xmlnmap.add_ls_data(script)
                        if data is not None:
                            script['ls'] = data
        for script in doc.get('scripts', []):
            if script['id'] in migrate_scripts:
                data = xmlnmap.add_ls_data(script)
                if data is not None:
                    script['ls'] = data

    @staticmethod
    def __migrate_schema_hosts_3_4(doc):
        """Converts a record from version 3 to version 4. Version 4
        creates a "fake" port entry to store host scripts.

        """
        assert doc["schema_version"] == 3
        doc["schema_version"] = 4
        if 'scripts' in doc:
            doc.setdefault('ports', []).append({
                "port": "host",
                "scripts": doc.pop('scripts'),
            })

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
        for port in doc.get('ports', []):
            if port['port'] == 'host':
                port['port'] = -1
        for state, (total, counts) in list(viewitems(doc.get('extraports',
                                                             {}))):
            doc['extraports'][state] = {"total": total, "reasons": counts}

    @staticmethod
    def __migrate_schema_hosts_5_6(doc):
        """Converts a record from version 5 to version 6. Version 6 uses Nmap
        structured data for scripts using the vulns NSE library.

        """
        assert doc["schema_version"] == 5
        doc["schema_version"] = 6
        migrate_scripts = set(script for script, alias
                              in viewitems(xmlnmap.ALIASES_TABLE_ELEMS)
                              if alias == 'vulns')
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] in migrate_scripts:
                    table = None
                    if script['id'] in script:
                        table = script.pop(script['id'])
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
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] == "mongodb-databases":
                    if 'mongodb-databases' not in script:
                        data = xmlnmap.add_mongodb_databases_data(script)
                        if data is not None:
                            script['mongodb-databases'] = data

    @staticmethod
    def __migrate_schema_hosts_7_8(doc):
        """Converts a record from version 7 to version 8. Version 8 fixes the
        structured output for scripts using the vulns NSE library.

        """
        assert doc["schema_version"] == 7
        doc["schema_version"] = 8
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if 'vulns' in script:
                    if any(elt in script['vulns'] for elt in
                           ["ids", "refs", "description", "state", "title"]):
                        script['vulns'] = [script['vulns']]
                    else:
                        script['vulns'] = [dict(tab, id=vulnid)
                                           for vulnid, tab in
                                           viewitems(script['vulns'])]

    @staticmethod
    def __migrate_schema_hosts_8_9(doc):
        """Converts a record from version 8 to version 9. Version 9 creates a
        structured output for http-headers script.

        """
        assert doc["schema_version"] == 8
        doc["schema_version"] = 9
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] == "http-headers":
                    if 'http-headers' not in script:
                        data = xmlnmap.add_http_headers_data(script)
                        if data is not None:
                            script['http-headers'] = data

    @staticmethod
    def __migrate_schema_hosts_9_10(doc):
        """Converts a record from version 9 to version 10. Version 10 changes
the field names of the structured output for s7-info script.

        """
        assert doc["schema_version"] == 9
        doc["schema_version"] = 10
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] == "s7-info":
                    if 's7-info' in script:
                        xmlnmap.change_s7_info_keys(script['s7-info'])

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
            doc['addr'] = utils.force_int2ip(doc['addr'])
        except KeyError:
            pass
        if "infos" in doc and "loc" in doc["infos"]:
            doc["infos"]["coordinates"] = doc["infos"].pop(
                "loc"
            )["coordinates"][::-1]
        for port in doc.get('ports', []):
            if 'state_reason_ip' in port:
                try:
                    port['state_reason_ip'] = utils.force_int2ip(
                        port['state_reason_ip']
                    )
                except ValueError:
                    pass
            for script in port.get('scripts', []):
                if script['id'] == 'ssl-cert':
                    if 'pem' in script['ssl-cert']:
                        data = ''.join(
                            script['ssl-cert']['pem'].splitlines()[1:-1]
                        ).encode()
                        try:
                            newout, newinfo = xmlnmap.create_ssl_cert(data)
                        except Exception:
                            utils.LOGGER.warning('Cannot parse certificate %r',
                                                 data,
                                                 exc_info=True)
                        else:
                            script['output'] = '\n'.join(newout)
                            script['ssl-cert'] = newinfo
                            continue
                    try:
                        pubkeytype = {
                            'rsaEncryption': 'rsa',
                            'id-ecPublicKey': 'ec',
                            'id-dsa': 'dsa',
                            'dhpublicnumber': 'dh',
                        }[script['ssl-cert'].pop('pubkeyalgo')]
                    except KeyError:
                        pass
                    else:
                        script['pubkey'] = {'type': pubkeytype}
        for trace in doc.get('traces', []):
            for hop in trace.get('hops', []):
                if 'ipaddr' in hop:
                    try:
                        hop['ipaddr'] = utils.force_int2ip(hop['ipaddr'])
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
        for port in doc.get('ports', []):
            for script in port.get('scripts', []):
                if script['id'] == "fcrdns":
                    if "fcrdns" in script:
                        script["fcrdns"] = xmlnmap.change_fcrdns_migrate(
                            script["fcrdns"]
                        )
                elif script['id'] == "rpcinfo":
                    if "rpcinfo" in script:
                        script["rpcinfo"] = xmlnmap.change_rpcinfo(
                            script["rpcinfo"]
                        )
        return doc

    @staticmethod
    def json2dbrec(host):
        return host

    def store_scan_doc(self, scan):
        pass

    def remove(self, host):
        raise NotImplementedError

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
                        ((1, port['port'])
                         for port in host.get('ports', [])
                         if port['state_state'] == 'open'),
                        (0, 0)
                    )
                )
            } for host in self.get(flt, fields=["ports"])
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

    def searchsshkey(self, fingerprint=None, key=None,
                     keytype=None, bits=None, output=None):
        """Search SSH host keys """
        params = {"name": 'ssh-hostkey'}
        if fingerprint is not None:
            if not isinstance(fingerprint, utils.REGEXP_T):
                fingerprint = fingerprint.replace(":", "").lower()
            params.setdefault("values", {})['fingerprint'] = fingerprint
        if key is not None:
            params.setdefault("values", {})['key'] = key
        if keytype is not None:
            params.setdefault("values", {})['type'] = 'ssh-%s' % keytype
        if bits is not None:
            params.setdefault("values", {})['bits'] = bits
        if output is not None:
            params['output'] = output
        return self.searchscript(**params)

    def searchx11access(self):
        return self.searchscript(name='x11-access',
                                 output='X server access is granted')

    def searchbanner(self, banner):
        return self.searchscript(name='banner', output=banner)

    def searchvncauthbypass(self):
        return self.searchscript(name="realvnc-auth-bypass")

    def searchmssqlemptypwd(self):
        return self.searchscript(
            name='ms-sql-empty-password',
            output=re.compile('Login\\ Success', flags=0),
        )

    def searchmysqlemptypwd(self):
        return self.searchscript(
            name='mysql-empty-password',
            output=re.compile('account\\ has\\ empty\\ password', flags=0),
        )

    def searchcookie(self, name):
        return self.searchscript(
            name='http-headers',
            output=re.compile('^ *Set-Cookie: %s=' % re.escape(name),
                              flags=re.MULTILINE | re.I),
        )

    def searchftpanon(self):
        return self.searchscript(
            name='ftp-anon',
            output=re.compile('^Anonymous\\ FTP\\ login\\ allowed', flags=0),
        )

    def searchhttpauth(self, newscript=True, oldscript=False):
        if newscript:
            if oldscript:
                return self.searchscript(
                    name=re.compile('^http-(default-accounts|auth)$'),
                    output=re.compile('credentials\\ found|'
                                      'HTTP\\ server\\ may\\ accept'),
                )
            return self.searchscript(
                name='http-default-accounts',
                output=re.compile('credentials\\ found'),
            )
        if oldscript:
            return self.searchscript(
                name='http-auth',
                output=re.compile('HTTP\\ server\\ may\\ accept'),
            )
        raise Exception('"newscript" and "oldscript" are both False')

    def searchowa(self):
        return self.searchscript(
            name=re.compile('^(http-(headers|auth-finder|title)|html-title)$'),
            output=re.compile('[ /](owa|exchweb)|X-OWA-Version|Outlook Web A',
                              re.I)
        )

    def searchxp445(self):
        return self.flt_and(
            self.searchport(445),
            self.searchsmb(os="Windows 5.1"),
        )

    def searchypserv(self):
        return self.searchscript(name='rpcinfo',
                                 output=re.compile('ypserv', flags=0))

    def searchnfs(self):
        return self.searchscript(name='rpcinfo',
                                 output=re.compile('nfs', flags=0))

    def searchtorcert(self):
        expr = re.compile(
            '^commonName=www\\.[a-z2-7]{8,20}\\.(net|com)$',
            flags=0
        )
        return self.searchscript(
            name='ssl-cert',
            values={'subject_text': expr, 'issuer_text': expr},
        )

    @classmethod
    def searchhttphdr(cls, name=None, value=None):
        if name is None and value is None:
            return cls.searchscript(name="http-headers")
        if value is None:
            return cls.searchscript(name="http-headers", values={"name": name})
        if name is None:
            return cls.searchscript(name="http-headers",
                                    values={"value": value})
        return cls.searchscript(name="http-headers",
                                values={"name": name, "value": value})

    def searchgeovision(self):
        return self.searchproduct(re.compile('^GeoVision', re.I))

    def searchwebcam(self):
        return self.searchdevicetype('webcam')

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
    def searchport(port, protocol='tcp', state='open', neg=False):
        raise NotImplementedError

    @staticmethod
    def searchproduct(product, version=None, service=None, port=None,
                      protocol=None):
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
        if 'dnsdomain' in args:
            args['domain_dns'] = args.pop('dnsdomain')
        if 'forest' in args:
            args['forest_dns'] = args.pop('forest')
        return cls.searchscript(name='smb-os-discovery', values=args)

    @classmethod
    def searchuseragent(cls, useragent=None, neg=False):
        if useragent is None:
            return cls.searchscript(name="http-user-agent", neg=neg)
        return cls.searchscript(
            name="http-user-agent",
            values=useragent,
            neg=neg
        )

    def parse_args(self, args, flt=None):
        flt = super(DBActive, self).parse_args(args, flt=flt)
        if args.category is not None:
            flt = self.flt_and(flt, self.searchcategory(
                utils.str2list(args.category)))
        if args.asname is not None:
            flt = self.flt_and(flt, self.searchasname(
                utils.str2regexp(args.asname)))
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
        if args.host is not None:
            flt = self.flt_and(flt, self.searchhost(args.host))
        if args.hostname is not None:
            if args.hostname[:1] in '!~':
                flt = self.flt_and(
                    flt,
                    self.searchhostname(utils.str2regexp(args.hostname[1:]),
                                        neg=True)
                )
            else:
                flt = self.flt_and(
                    flt,
                    self.searchhostname(utils.str2regexp(args.hostname))
                )
        if args.domain is not None:
            if args.domain[:1] in '!~':
                flt = self.flt_and(
                    flt,
                    self.searchdomain(utils.str2regexp(args.domain[1:]),
                                      neg=True)
                )
            else:
                flt = self.flt_and(
                    flt,
                    self.searchdomain(utils.str2regexp(args.domain))
                )
        if args.net is not None:
            flt = self.flt_and(flt, self.searchnet(args.net))
        if args.range is not None:
            flt = self.flt_and(flt, self.searchrange(*args.range))
        if args.hop is not None:
            flt = self.flt_and(flt, self.searchhop(args.hop))
        if args.not_port is not None:
            not_port = args.not_port.replace('_', '/')
            if '/' in not_port:
                not_proto, not_port = not_port.split('/', 1)
            else:
                not_proto = 'tcp'
            not_port = int(not_port)
            flt = self.flt_and(
                flt,
                self.searchport(port=not_port, protocol=not_proto,
                                neg=True))
        if args.openport:
            flt = self.flt_and(flt, self.searchopenport())
        if args.no_openport:
            flt = self.flt_and(flt, self.searchopenport(neg=True))
        if args.countports:
            minn, maxn = int(args.countports[0]), int(args.countports[1])
            flt = self.flt_and(flt,
                               self.searchcountopenports(minn=minn,
                                                         maxn=maxn))
        if args.no_countports:
            minn, maxn = int(args.no_countports[0]), int(args.no_countports[1])
            flt = self.flt_and(flt,
                               self.searchcountopenports(minn=minn,
                                                         maxn=maxn,
                                                         neg=True))
        if args.script is not None:
            if ':' in args.script:
                name, output = (utils.str2regexp(string) for
                                string in args.script.split(':', 1))
            else:
                name, output = utils.str2regexp(args.script), None
            flt = self.flt_and(flt, self.searchscript(name=name,
                                                      output=output))
        if args.no_script is not None:
            if ':' in args.no_script:
                name, output = (utils.str2regexp(string) for
                                string in args.no_script.split(':', 1))
            else:
                name, output = utils.str2regexp(args.no_script), None
            flt = self.flt_and(flt, self.searchscript(name=name,
                                                      output=output,
                                                      neg=True))
        if args.os is not None:
            flt = self.flt_and(
                flt,
                self.searchos(utils.str2regexp(args.os))
            )
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
                name, value = args.httphdr.split(':', 1)
                name = utils.str2regexp(name.lower())
                value = utils.str2regexp(value)
                flt = self.flt_and(flt, self.searchhttphdr(name=name,
                                                           value=value))
            else:
                flt = self.flt_and(flt, self.searchhttphdr(
                    name=utils.str2regexp(args.httphdr.lower())
                ))
        if args.owa:
            flt = self.flt_and(flt, self.searchowa())
        if args.vuln_boa:
            flt = self.flt_and(flt, self.searchvulnintersil())
        if args.torcert:
            flt = self.flt_and(flt, self.searchtorcert())
        if args.sshkey is not None:
            flt = self.flt_and(flt, self.searchsshkey(
                fingerprint=utils.str2regexp(args.sshkey)))
        return flt

    @staticmethod
    def cmp_schema_version_host(_):
        return 0

    @staticmethod
    def cmp_schema_version_scan(_):
        return 0


class DBNmap(DBActive):

    def __init__(self, output_mode="json", output=sys.stdout):
        super(DBNmap, self).__init__()
        self.content_handler = xmlnmap.Nmap2Txt
        self.output_function = {
            "normal": nmapout.displayhosts,
        }.get(output_mode, nmapout.displayhosts_json)
        self.output = output

    def store_host(self, host):
        if self.output_function is not None:
            self.output_function([host], out=self.output)

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
        try:
            store_scan_function = {
                b'<': self.store_scan_xml,
                b'{': self.store_scan_json,
            }[fchar]
        except KeyError:
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
            content_handler = self.content_handler(fname, **kargs)
        except Exception:
            utils.LOGGER.warning('Exception (file %r)', fname, exc_info=True)
        else:
            content_handler.callback = callback
            parser.setContentHandler(content_handler)
            parser.setEntityResolver(xmlnmap.NoExtResolver())
            parser.parse(utils.open_file(fname))
            if self.output_function is not None:
                self.output_function(content_handler._db, out=self.output)
            self.stop_store_hosts()
            return True
        self.stop_store_hosts()
        return False

    def store_scan_json(self, fname, filehash=None,
                        needports=False, needopenports=False,
                        categories=None, source=None,
                        add_addr_infos=True, force_info=False,
                        callback=None, **_):
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
                for fname in ["_id"]:
                    if fname in host:
                        del host[fname]
                host["scanid"] = filehash
                if categories:
                    host["categories"] = categories
                if source is not None:
                    host["source"] = source
                if add_addr_infos and self.globaldb is not None and (
                        force_info or 'infos' not in host or not host['infos']
                ):
                    host['infos'] = {}
                    for func in [self.globaldb.data.country_byip,
                                 self.globaldb.data.as_byip,
                                 self.globaldb.data.location_byip]:
                        host['infos'].update(func(host['addr']) or {})
                if ((not needports or 'ports' in host) and
                    (not needopenports or
                     host.get('openports', {}).get('count'))):
                    # Update schema if/as needed.
                    while host.get(
                            "schema_version"
                    ) in self._schema_migrations["hosts"]:
                        oldvers = host.get("schema_version")
                        self._schema_migrations["hosts"][oldvers][1](host)
                        if oldvers == host.get("schema_version"):
                            utils.LOGGER.warning(
                                "[%r] could not migrate host from version "
                                "%r [%r]",
                                self.__class__, oldvers, host
                            )
                            break
                    # We are about to insert data based on this file,
                    # so we want to save the scan document
                    if not scan_doc_saved:
                        self.store_scan_doc({'_id': filehash})
                        scan_doc_saved = True
                    self.store_host(host)
                if callback is not None:
                    callback(host)
        self.stop_store_hosts()
        return True


class DBView(DBActive):

    def __init__(self):
        super(DBView, self).__init__()
        self.argparser.add_argument('--ssl-ja3-server',
                                    metavar='JA3-SERVER[:JA3-CLIENT]',
                                    nargs='?',
                                    const=False,
                                    default=None)
        self.argparser.add_argument('--ssl-ja3-client',
                                    metavar='JA3-CLIENT',
                                    nargs='?',
                                    const=False,
                                    default=None)

    def parse_args(self, args, flt=None):
        flt = super(DBView, self).parse_args(args, flt=flt)
        if args.ssl_ja3_client is not None:
            cli = args.ssl_ja3_client
            flt = self.flt_and(flt, self.searchja3client(
                value_or_hash=(
                    False if cli is False else utils.str2regexp(cli)
                )
            ))
        if args.ssl_ja3_server is not None:
            if args.ssl_ja3_server is False:
                # There are no additional arguments
                flt = self.flt_and(flt, self.searchja3server())
            else:
                split = [utils.str2regexp(v) if v else None
                         for v in args.ssl_ja3_server.split(':', 1)]
                if len(split) == 1:
                    # Only a JA3 server is given
                    flt = self.flt_and(flt, self.searchja3server(
                        value_or_hash=split[0]
                    ))
                else:
                    # Both client and server JA3 are given
                    flt = self.flt_and(flt, self.searchja3server(
                        value_or_hash=split[0],
                        client_value_or_hash=split[1],
                    ))
        return flt

    @staticmethod
    def merge_ja3_scripts(curscript, script, script_id):

        def is_server(script_id):
            return script_id == 'ssl-ja3-server'

        def ja3_equals(a, b, script_id):
            return (a['raw'] == b['raw'] and
                    (not is_server(script_id) or
                     a['client']['raw'] == b['client']['raw']))

        def ja3_output(ja3, script_id):
            output = ja3['md5']
            if is_server(script_id):
                output += ' - ' + ja3['client']['md5']
            return output
        return DBView._merge_scripts(curscript, script, script_id,
                                     ja3_equals, ja3_output)

    @staticmethod
    def merge_ua_scripts(curscript, script, script_id):

        def ua_equals(a, b, script_id):
            return a == b

        def ua_output(ua, script_id):
            return ua

        return DBView._merge_scripts(curscript, script, script_id,
                                     ua_equals, ua_output)

    @staticmethod
    def _merge_scripts(curscript, script, script_id,
                       script_equals, script_output):
        """Merge two scripts and return the result. Avoid duplicates.
        """
        to_merge_list = []
        for to_add in script[script_id]:
            to_merge = True
            for cur in curscript[script_id]:
                if script_equals(to_add, cur, script_id):
                    to_merge = False
                    break
            if to_merge:
                to_merge_list.append(to_add)
        curscript[script_id].extend(to_merge_list)
        # Compute output from curscript[script_id]
        output = ""
        for el in curscript[script_id]:
            output += script_output(el, script_id) + '\n'
        curscript['output'] = output
        return curscript

    @staticmethod
    def merge_scripts(curscript, script, script_id):
        if script_id.startswith('ssl-ja3-'):
            return DBView.merge_ja3_scripts(curscript, script, script_id)
        if script_id == 'http-user-agent':
            return DBView.merge_ua_scripts(curscript, script, script_id)
        return {}

    @staticmethod
    def merge_host_docs(rec1, rec2):
        """Merge two host records and return the result. Unmergeable /
        hard-to-merge fields are lost (e.g., extraports).

        """
        if rec1.get("schema_version") != rec2.get("schema_version"):
            raise ValueError("Cannot merge host documents. "
                             "Schema versions differ (%r != %r)" % (
                                 rec1.get("schema_version"),
                                 rec2.get("schema_version")))
        rec = {}
        if "schema_version" in rec1:
            rec["schema_version"] = rec1["schema_version"]
        # When we have different values, we will use the one from the
        # most recent scan, rec2
        if rec1.get("endtime") > rec2.get("endtime"):
            rec1, rec2 = rec2, rec1
        for fname, function in [("starttime", min), ("endtime", max)]:
            try:
                rec[fname] = function(record[fname] for record in [rec1, rec2]
                                      if fname in record)
            except ValueError:
                pass
        rec["state"] = "up" if rec1.get("state") == "up" else rec2.get("state")
        if rec["state"] is None:
            del rec["state"]
        rec["categories"] = list(
            set(rec1.get("categories", [])).union(
                rec2.get("categories", []))
        )
        for field in ["addr", "os"]:
            rec[field] = rec2[field] if rec2.get(field) else rec1.get(field)
            if not rec[field]:
                del rec[field]
        rec['source'] = list(set(rec1.get('source', []))
                             .union(set(rec2.get('source', []))))
        rec["traces"] = rec1.get("traces", []) + rec2.get("traces", [])
        rec["infos"] = {}
        for record in [rec1, rec2]:
            rec["infos"].update(record.get("infos", {}))
        # We want to make sure of (type, name) unicity
        hostnames = dict(((h['type'], h['name']), h.get('domains'))
                         for h in (rec1.get("hostnames", []) +
                                   rec2.get("hostnames", [])))
        rec["hostnames"] = [{"type": h[0], "name": h[1], "domains": d}
                            for h, d in viewitems(hostnames)]
        ports = dict(((port.get("protocol"), port["port"]), port.copy())
                     for port in rec2.get("ports", []))
        for port in rec1.get("ports", []):
            if (port.get('protocol'), port['port']) in ports:
                curport = ports[(port.get('protocol'), port['port'])]
                if 'scripts' in curport:
                    curport['scripts'] = curport['scripts'][:]
                else:
                    curport['scripts'] = []
                present_scripts = set(
                    script['id'] for script in curport['scripts']
                )
                for script in port.get("scripts", []):
                    if script['id'] not in present_scripts:
                        curport['scripts'].append(script)
                    elif (script['id'] in ['ssl-ja3-server',
                                           'ssl-ja3-client',
                                           'http-user-agent']):
                        # Merge scripts
                        curscript = next(x for x in curport['scripts']
                                         if x['id'] == script['id'])
                        DBView.merge_scripts(curscript, script, script['id'])
                if not curport['scripts']:
                    del curport['scripts']
                if 'service_name' in port:
                    if 'service_name' not in curport:
                        for key in port:
                            if key.startswith("service_"):
                                curport[key] = port[key]
                    elif port['service_name'] == curport['service_name']:
                        # if the "old" record has information missing
                        # from the "new" record and information from
                        # both records is consistent, let's keep the
                        # "old" data.
                        for key in port:
                            if (
                                    key.startswith("service_") and
                                    key not in curport
                            ):
                                curport[key] = port[key]
            else:
                ports[(port.get('protocol'), port['port'])] = port
        rec["ports"] = sorted(viewvalues(ports), key=lambda port: (
            port.get('protocol') or '~', port.get('port'),
        ))
        rec["openports"] = {}
        for record in [rec1, rec2]:
            for proto in record.get('openports', {}):
                if proto == 'count':
                    continue
                rec['openports'].setdefault(
                    proto, {}).setdefault(
                        'ports', set()).update(
                            record['openports'][proto]['ports'])
        if rec['openports']:
            for proto in list(rec['openports']):
                count = len(rec['openports'][proto]['ports'])
                rec['openports'][proto]['count'] = count
                rec['openports']['count'] = rec['openports'].get(
                    'count', 0) + count
                rec['openports'][proto]['ports'] = list(
                    rec['openports'][proto]['ports'])
        else:
            rec['openports']["count"] = 0
        for field in ["traces", "infos", "ports"]:
            if not rec[field]:
                del rec[field]
        return rec

    def merge_host(self, host):
        """Attempt to merge `host` with an existing record.

        Return `True` if another record for the same address has been found,
        merged and the resulting document inserted in the database, `False`
        otherwise (in that case, it is the caller's responsibility to
        add `host` to the database if necessary).

        """
        try:
            flt = self.searchhost(host['addr'])
            rec = next(self.get(flt))
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
        return cls._searchja3(value_or_hash, 'ssl-ja3-client', neg=neg)

    @classmethod
    def searchja3server(cls, value_or_hash=None, client_value_or_hash=None,
                        neg=False):
        script_id = 'ssl-ja3-server'
        if not client_value_or_hash:
            return cls._searchja3(value_or_hash, script_id, neg=neg)
        key_client, value_client = cls._ja3keyvalue(client_value_or_hash)
        values = {'client.%s' % (key_client): value_client}
        if value_or_hash:
            key_srv, value_srv = cls._ja3keyvalue(value_or_hash)
            values[key_srv] = value_srv
        return cls.searchscript(
            name=script_id,
            values=values,
            neg=neg,
        )


class _RecInfo(object):
    __slots__ = ["count", "firstseen", "infos", "lastseen"]

    def __init__(self, infos):
        self.count = 0
        self.firstseen = self.lastseen = None
        self.infos = infos

    @property
    def data(self):
        data = {'count': self.count}
        if self.infos:
            data['infos'] = self.infos
        return data

    def update_from_spec(self, spec):
        self.count += spec.get('count')
        firstseen = spec.get('firstseen')
        if firstseen is not None:
            if self.firstseen is None:
                self.firstseen = firstseen
            else:
                self.firstseen = min(self.firstseen, firstseen)
        lastseen = spec.get('lastseen')
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

    def __init__(self):
        super(DBPassive, self).__init__()
        self.argparser.add_argument('--sensor')
        self.argparser.add_argument('--torcert', action='store_true')
        self.argparser.add_argument('--dns')
        self.argparser.add_argument('--dnssub')
        self.argparser.add_argument('--cert')
        self.argparser.add_argument('--basicauth', action='store_true')
        self.argparser.add_argument('--auth', action='store_true')
        self.argparser.add_argument('--java', action='store_true')
        self.argparser.add_argument('--ftp', action='store_true')
        self.argparser.add_argument('--pop', action='store_true')
        self.argparser.add_argument('--timeago', type=int)
        self.argparser.add_argument('--timeagonew', type=int)
        self.argparser.add_argument(
            '--dnstype', metavar='DNS_TYPE',
            help='Display results for specified DNS type.',
        )

    def parse_args(self, args, flt=None):
        flt = super(DBPassive, self).parse_args(args, flt=flt)
        if args.sensor is not None:
            flt = self.flt_and(
                flt,
                self.searchsensor(args.sensor)
            )
        if args.torcert:
            flt = self.flt_and(flt, self.searchtorcert())
        if args.basicauth:
            flt = self.flt_and(flt, self.searchbasicauth())
        if args.auth:
            flt = self.flt_and(flt, self.searchhttpauth())
        if args.java:
            flt = self.flt_and(
                flt,
                self.searchjavaua()
            )
        if args.ftp:
            flt = self.flt_and(flt, self.searchftpauth())
        if args.pop:
            flt = self.flt_and(flt, self.searchpopauth())
        if args.dns is not None:
            flt = self.flt_and(
                flt,
                self.searchdns(utils.str2regexp(args.dns), subdomains=False)
            )
        if args.dnssub is not None:
            flt = self.flt_and(
                flt,
                self.searchdns(utils.str2regexp(args.dnssub), subdomains=True)
            )
        if args.cert is not None:
            flt = self.flt_and(
                flt,
                self.searchcertsubject(utils.str2regexp(args.cert)),
            )
        if args.timeago is not None:
            flt = self.flt_and(self.searchtimeago(args.timeago, new=False))
        if args.timeagonew is not None:
            flt = self.flt_and(self.searchtimeago(args.timeagonew, new=True))
        if args.dnstype is not None:
            flt = self.flt_and(flt, self.searchdns(dnstype=args.dnstype))
        return flt

    def insert_or_update(self, timestamp, spec, getinfos=None, lastseen=None):
        raise NotImplementedError

    def insert_or_update_bulk(self, specs, getinfos=None,
                              separated_timestamps=True):
        """Like `.insert_or_update()`, but `specs` parameter has to be an
        iterable of (timestamp, spec) values. This generic
        implementation does not use the bulk capacity of the
        underlying DB implementation but rather calls its
        `.insert_or_update()` method.

        """
        if separated_timestamps:
            for tstamp, spec in specs:
                self.insert_or_update(tstamp, spec, getinfos=getinfos)
        else:
            for spec in specs:
                timestamp = spec.pop("firstseen", None)
                lastseen = spec.pop("lastseen", None)
                self.insert_or_update(timestamp or lastseen, spec,
                                      getinfos=getinfos,
                                      lastseen=lastseen or timestamp)

    def insert_or_update_local_bulk(self, specs, getinfos=None,
                                    separated_timestamps=True):
        """Like `.insert_or_update()`, but `specs` parameter has to be an
        iterable of (timestamp, spec) values. This generic
        implementation does not use the bulk capacity of the
        underlying DB implementation but uses a local cache and calls
        its `.insert_or_update()` method.

        """
        def _bulk_execute(records):
            utils.LOGGER.debug("DB:local bulk upsert: %d", len(records))
            for spec, metadata in viewitems(records):
                self.insert_or_update(metadata.firstseen,
                                      dict(spec, **metadata.data),
                                      getinfos=getinfos,
                                      lastseen=metadata.lastseen)
        records = {}
        utils.LOGGER.debug("DB: creating a local bulk upsert (%d records)",
                           config.LOCAL_BATCH_SIZE)
        if separated_timestamps:
            for timestamp, spec in specs:
                if spec is None:
                    continue
                infos = spec.pop('infos', None)
                spec = tuple((key, spec[key]) for key in sorted(spec))
                records.setdefault(spec, _RecInfo(infos)).update(timestamp)
                if len(records) >= config.LOCAL_BATCH_SIZE:
                    _bulk_execute(records)
                    records = {}
        else:
            for spec in specs:
                if spec is None:
                    continue
                infos = spec.pop('infos', None)
                basespec = tuple(
                    (key, spec[key]) for key in sorted(spec)
                    if key not in ['count', 'firstseen', 'lastseen']
                )
                records.setdefault(basespec,
                                   _RecInfo(infos)).update_from_spec(spec)
                if len(records) >= config.LOCAL_BATCH_SIZE:
                    _bulk_execute(records)
                    records = {}
        _bulk_execute(records)

    def searchcountry(self, code, neg=False):
        return self.searchranges(
            geoiputils.get_ranges_by_country(code), neg=neg
        )

    def searchasnum(self, asnum, neg=False):
        return self.searchranges(
            geoiputils.get_ranges_by_asnum(asnum), neg=neg
        )

    @classmethod
    def searchranges(cls, ranges, neg=False):
        """Filters (if `neg` == True, filters out) some IP address ranges.

`ranges` is an instance of ivre.geoiputils.IPRanges().

        """
        flt = []
        for start, stop in ranges.iter_ranges():
            flt.append(cls.searchrange(cls.ip2internal(start),
                                       cls.ip2internal(stop), neg=neg))
        if flt:
            return (cls.flt_and if neg else cls.flt_or)(*flt)
        return cls.flt_empty if neg else cls.searchnonexistent()

    def searchtorcert(self):
        return self.searchcertsubject(
            re.compile('^commonName=www\\.[a-z2-7]{8,20}\\.(net|com)$',
                       flags=0),
            issuer=re.compile('^commonName=www\\.[a-z2-7]{8,20}\\.(net|com)$',
                              flags=0),
        )

    @staticmethod
    def searchcertsubject(expr, issuer=None):
        raise NotImplementedError

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
        spec = {}
        dnsbl_val = old_spec['value']
        spec['recontype'] = 'DNS_BLACKLIST'
        spec['value'] = old_spec['addr']
        spec['source'] = "%s-%s" % (dnsbl_val.split('.', 4)[4],
                                    old_spec['source'])
        spec['addr'] = '.'.join(dnsbl_val.split('.')[3::-1])
        spec['count'] = old_spec['count']
        return spec

    def update_dns_blacklist(self):
        """Update the current database to detect blacklist domains.
This function inserts a new element in the database, corresponding to the
old element and delete the existing one."""

        flt = self.searchdns(list(config.DNS_BLACKLIST_DOMAINS),
                             subdomains=True)
        base = self.get(flt)
        for old_spec in base:
            if any(old_spec['value'].endswith(dnsbl)
                   for dnsbl in config.DNS_BLACKLIST_DOMAINS):
                spec = self._update_dns_blacklist(old_spec)
                self.insert_or_update(old_spec['firstseen'], spec,
                                      lastseen=old_spec['lastseen'])
                self.remove(old_spec['_id'])


class DBData(DB):
    country_codes = None

    def infos_byip(self, addr):
        infos = {}
        for infos_byip in [self.as_byip,
                           self.country_byip,
                           self.location_byip]:
            infos.update(infos_byip(addr) or {})
        if infos:
            return infos
        return None

    def as_byip(self, addr):
        raise NotImplementedError

    def location_byip(self, addr):
        raise NotImplementedError


class LockError(RuntimeError):
    """A runtime error used when a lock cannot be acquired or released."""


class DBAgent(DB):
    """Backend-independent code to handle agents-in-DB"""

    def add_agent(self, masterid, host, remotepath,
                  rsync=None, source=None, maxwaiting=60):
        """Prepares an agent and adds it to the DB using
        `self._add_agent()`

        """
        if rsync is None:
            rsync = ["rsync"]
        if not remotepath.endswith('/'):
            remotepath += '/'
        if source is None:
            source = (remotepath if host is None
                      else "%s:%s" % (host, remotepath))
        master = self.get_master(masterid)
        localpath = tempfile.mkdtemp(prefix="", dir=master['path'])
        for dirname in ["input"] + [os.path.join("remote", dname)
                                    for dname in ["input", "cur", "output"]]:
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

    def add_agent_from_string(self, masterid, string,
                              source=None, maxwaiting=60):
        """Adds an agent from a description string of the form
        [tor:][hostname:]path.

        """
        string = string.split(':', 1)
        if string[0].lower() == 'tor':
            string = string[1].split(':', 1)
            rsync = ['torify', 'rsync']
        else:
            rsync = None
        if len(string) == 1:
            return self.add_agent(masterid, None, string[0],
                                  rsync=rsync,
                                  source=source,
                                  maxwaiting=maxwaiting)
        return self.add_agent(masterid, string[0], string[1],
                              rsync=rsync,
                              source=source,
                              maxwaiting=maxwaiting)

    def may_receive(self, agentid):
        """Returns the number of targets that can be added to an agent
        without exceeding its `maxwaiting` limit (the returned value
        cannot be negative).

        """
        agent = self.get_agent(agentid)
        return max(agent["maxwaiting"] - self.count_waiting_targets(agentid),
                   0)

    def count_waiting_targets(self, agentid):
        """Returns the number of waiting targets an agent has.

        """
        agent = self.get_agent(agentid)
        return sum(
            len(os.listdir(self.get_local_path(agent, path)))
            for path in ['input', os.path.join('remote', 'input')]
        )

    def count_current_targets(self, agentid):
        """Returns the number of waiting targets an agent has.

        """
        agent = self.get_agent(agentid)
        return sum(
            1 for fname in os.listdir(self.get_local_path(
                agent,
                os.path.join("remote", "cur")))
            if fname.endswith('.xml')
        )

    @staticmethod
    def get_local_path(agent, dirname):
        if not dirname.endswith('/'):
            dirname += '/'
        return os.path.join(agent["path"]["local"], dirname)

    @staticmethod
    def get_remote_path(agent, dirname):
        if dirname and not dirname.endswith('/'):
            dirname += '/'
        return "%s%s" % (
            '' if agent['host'] is None else "%s:" % agent['host'],
            os.path.join(agent["path"]["remote"], dirname)
        )

    def sync_all(self, masterid):
        for agentid in self.get_agents_by_master(masterid):
            self.sync(agentid)

    def sync(self, agentid):
        agent = self.get_agent(agentid)
        master = self.get_master(agent['master'])
        subprocess.call(agent['rsync'] + [
            '-a',
            self.get_local_path(agent, 'input'),
            self.get_local_path(agent, os.path.join('remote', 'input'))
        ])
        subprocess.call(agent['rsync'] + [
            '-a', '--remove-source-files',
            self.get_local_path(agent, 'input'),
            self.get_remote_path(agent, 'input')
        ])
        for dname in ['input', 'cur']:
            subprocess.call(agent['rsync'] + [
                '-a', '--delete',
                self.get_remote_path(agent, dname),
                self.get_local_path(agent, os.path.join('remote', dname))
            ])
        subprocess.call(agent['rsync'] + [
            '-a', '--remove-source-files',
            self.get_remote_path(agent, 'output'),
            self.get_local_path(agent, os.path.join('remote', 'output'))
        ])
        outpath = self.get_local_path(agent, os.path.join('remote', 'output'))
        for fname in os.listdir(outpath):
            scanid = fname.split('-', 1)[0]
            scan = self.get_scan(self.str2id(scanid))
            storedir = os.path.join(
                master["path"],
                "output",
                scanid,
                str(agentid),
            )
            utils.makedirs(storedir)
            fdesc = tempfile.NamedTemporaryFile(prefix="", suffix=".xml",
                                                dir=storedir, delete=False)
            shutil.move(
                os.path.join(outpath, fname),
                fdesc.name
            )
            self.globaldb.nmap.store_scan(
                fdesc.name,
                categories=scan['target_info']['categories'],
                source=agent['source'],
            )
            self.incr_scan_results(self.str2id(scanid))

    def feed_all(self, masterid):
        for scanid in self.get_scans():
            try:
                self.feed(masterid, scanid)
            except LockError:
                utils.LOGGER.error(
                    'Lock error - is another daemon process running?',
                    exc_info=True,
                )

    def feed(self, masterid, scanid):
        scan = self.lock_scan(scanid)
        # TODO: handle "onhold" targets
        target = self.get_scan_target(scanid)
        try:
            for agentid in scan['agents']:
                if self.get_agent(agentid)['master'] == masterid:
                    for _ in range(self.may_receive(agentid)):
                        self.add_target(agentid, scanid, next(target))
        except StopIteration:
            # This scan is over, let's free its agents
            for agentid in scan['agents']:
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
            prefix=str(scanid) + '-',
            dir=self.get_local_path(agent, "input"),
            delete=False,
        ) as fdesc:
            fdesc.write(("%s\n" % addr).encode())
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
        master = self.get_master(agent['master'])
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
            # We need to explicitly call self.to_binary() because with
            # MongoDB, Python 2.6 will store a unicode string that it
            # won't be able un pickle.loads() later
            "target": self.to_binary(pickle.dumps(itertarget)),
            "target_info": target.infos,
            "agents": [],
            "results": 0,
            "lock": None
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
        if scan['lock'] is not None:
            # This might be a bug in uuid module, Python 2 only
            #    File "/opt/python/2.6.9/lib/python2.6/uuid.py", line 145,
            #   in __init__
            #      int = long(('%02x'*16) % tuple(map(ord, bytes)), 16)
            # scan['lock'] = uuid.UUID(bytes=scan['lock'])
            scan['lock'] = uuid.UUID(
                hex=utils.encode_hex(scan['lock']).decode()
            )
        if scan['lock'] == lockid:
            return scan
        return None

    def unlock_scan(self, scan):
        """Release lock for scanid. Returns True on success, and raises a
LockError on failure.

        """
        if scan.get('lock') is None:
            raise LockError('Cannot release lock for %r: scan is not '
                            'locked' % scan['_id'])
        scan = self._lock_scan(scan['_id'], scan['lock'].bytes, None)
        return scan['lock'] is None

    def _lock_scan(self, scanid, oldlockid, newlockid):
        raise NotImplementedError

    def get_scan(self, scanid):
        raise NotImplementedError

    def get_scans(self):
        raise NotImplementedError

    def assign_agent(self, agentid, scanid,
                     only_if_unassigned=False,
                     force=False):
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
        # We need to explicitly call self.to_binary() because with
        # MongoDB, Python 2.6 will store a unicode string that it
        # won't be able un pickle.loads() later
        return self._update_scan_target(scanid,
                                        self.to_binary(pickle.dumps(target)))

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


class DBFlow(DB):
    """Backend-independent code to handle flows"""

    @classmethod
    def date_round(cls, date):
        if isinstance(date, datetime):
            ts = utils.datetime2timestamp(date)
        else:
            ts = date
        ts = ts - (ts % config.FLOW_TIME_PRECISION)
        if isinstance(date, datetime):
            return datetime.fromtimestamp(ts)
        return ts

    @classmethod
    def from_filters(cls, filters, limit=None, skip=0, orderby="", mode=None,
                     timeline=False):
        """
        Returns a flow.Query object representing the given filters
        Note: limit, skip, orderby, mode and timeline are IGNORED. They are
        present only for compatibility reasons with neo4j backend.
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
        time = cls.date_round(start_time)
        end_timeslot = cls.date_round(end_time)
        while time <= end_timeslot:
            d = OrderedDict()
            d['start'] = time
            d['duration'] = config.FLOW_TIME_PRECISION
            times.append(d)
            time += timedelta(seconds=config.FLOW_TIME_PRECISION)
        return times


class MetaDB(object):

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
        "nmap": {"http": ("http", "HttpDBNmap"),
                 "mongodb": ("mongo", "MongoDBNmap"),
                 "postgresql": ("sql.postgres", "PostgresDBNmap")},
        "passive": {"mongodb": ("mongo", "MongoDBPassive"),
                    "postgresql": ("sql.postgres", "PostgresDBPassive"),
                    "sqlite": ("sql.sqlite", "SqliteDBPassive")},
        "data": {"maxmind": ("maxmind", "MaxMindDBData")},
        "agent": {"mongodb": ("mongo", "MongoDBAgent")},
        "flow": {"neo4j": ("neo4j", "Neo4jDBFlow"),
                 "mongodb": ("mongo", "MongoDBFlow"),
                 "postgresql": ("sql.postgres", "PostgresDBFlow")},
        "view": {"http": ("http", "HttpDBView"),
                 "mongodb": ("mongo", "MongoDBView"),
                 "postgresql": ("sql.postgres", "PostgresDBView")},
    }

    def __init__(self, url=None, urls=None):
        self.url = url
        self.urls = urls

    @property
    def nmap(self):
        try:
            return self._nmap
        except AttributeError:
            pass
        self._nmap = self.get_class("nmap")
        return self._nmap

    @property
    def passive(self):
        try:
            return self._passive
        except AttributeError:
            pass
        self._passive = self.get_class("passive")
        return self._passive

    @property
    def data(self):
        try:
            return self._data
        except AttributeError:
            pass
        self._data = self.get_class("data")
        return self._data

    @property
    def agent(self):
        try:
            return self._agent
        except AttributeError:
            pass
        self._agent = self.get_class("agent")
        return self._agent

    @property
    def flow(self):
        try:
            return self._flow
        except AttributeError:
            pass
        self._flow = self.get_class("flow")
        return self._flow

    @property
    def view(self):
        try:
            return self._view
        except AttributeError:
            pass
        self._view = self.get_class("view")
        return self._view

    def get_class(self, purpose):
        url = self.urls.get(purpose, self.url)
        if url is not None:
            url = urlparse(url)
            try:
                modulename, classname = self.db_types[purpose][url.scheme]
            except (KeyError, TypeError):
                utils.LOGGER.error(
                    'Cannot get database for %s from %s',
                    purpose,
                    url.geturl(),
                    exc_info=True,
                )
                return None
            try:
                # we should use importlib.import_module, but it is an
                # external module in Python 2.6.
                module = __import__('ivre.db.%s' % modulename).db
            except ImportError:
                utils.LOGGER.error(
                    'Cannot import ivre.db.%s for %s',
                    modulename,
                    url.geturl(),
                    exc_info=True,
                )
                return None
            for submod in modulename.split('.'):
                module = getattr(module, submod)
            result = getattr(module, classname)(url)
            result.globaldb = self
            return result
        return None


db = MetaDB(
    url=config.DB if hasattr(config, "DB") else None,
    urls=dict([x[3:].lower(), getattr(config, x)]
              for x in dir(config) if x.startswith('DB_')))
