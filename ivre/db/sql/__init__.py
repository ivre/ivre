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

"""This module contains functions to interact with *ANY* SQL database.

"""


# Tests like "expr == None" should be used for BinaryExpression instances
# pylint: disable=singleton-comparison


import codecs
from collections import namedtuple
import csv
import datetime
import json
import re


from sqlalchemy import (
    Integer,
    and_,
    cast,
    column,
    create_engine,
    delete,
    desc,
    func,
    exists,
    join,
    not_,
    nullsfirst,
    or_,
    select,
    text,
    update,
    insert,
)
from sqlalchemy.dialects.postgresql import JSONB


from ivre.active.data import ALIASES_TABLE_ELEMS
from ivre.db import DB, DBActive, DBFlow, DBNmap, DBPassive, DBView
from ivre import config, utils, xmlnmap
from ivre.db.sql.tables import (
    N_Association_Scan_Category,
    N_Association_Scan_Hostname,
    N_Association_Scan_ScanFile,
    N_Category,
    N_Hop,
    N_Hostname,
    N_Port,
    N_Scan,
    N_ScanFile,
    N_Script,
    N_Trace,
    V_Association_Scan_Category,
    V_Association_Scan_Hostname,
    V_Category,
    V_Hop,
    V_Hostname,
    V_Port,
    V_Scan,
    V_Script,
    V_Trace,
    Flow,
    Passive,
    Point,
)


# Data


class CSVFile:
    """A file like object generating CSV lines suitable for use with
    PostgresDB.copy_from(). Reads (at most `limit`, when it's not None)
    lines from `fname`, skipping `skip` first lines.

    When .read() returns the empty string, the attribute `.more_to_read`
    is set to True when the `limit` has been reached, and to False when
    there is no more data to read from the input.

    """

    def __init__(self, fname, skip=0, limit=None):
        # pylint: disable=consider-using-with
        self.fdesc = codecs.open(fname, encoding="latin-1")
        for _ in range(skip):
            self.fdesc.readline()
        self.limit = limit
        if limit is not None:
            self.count = 0
        self.more_to_read = None
        self.inp = csv.reader(self.fdesc)

    @staticmethod
    def fixline(line):
        """Subclasses can override this method to generate the CSV line from
        the original line.

        """
        return line

    def read(self, size=None):
        if self.limit is not None:
            if self.count >= self.limit:
                self.more_to_read = True
                return ""
        try:
            line = None
            while line is None:
                line = self.fixline(next(self.inp))
            if self.limit is not None:
                self.count += 1
            return "%s\n" % "\t".join(line)
        except StopIteration:
            self.more_to_read = False
            return ""

    def readline(self):
        return self.read()

    def __exit__(self, *args):
        if self.fdesc is not None:
            self.fdesc.__exit__(*args)

    def __enter__(self):
        return self


# Nmap


class ScanCSVFile(CSVFile):
    def __init__(self, hostgen, ip2internal, table):
        self.ip2internal = ip2internal
        self.table = table
        self.inp = hostgen
        self.fdesc = None

    def fixline(self, line):
        for field in ["cpes", "extraports", "openports", "os", "traces"]:
            line.pop(field, None)
        line["addr"] = self.ip2internal(line["addr"])
        scanfileid = line.pop("scanid")
        if isinstance(scanfileid, str):
            scanfileid = [scanfileid]
        line["scanfileid"] = "{%s}" % ",".join('"\\x%s"' % fid for fid in scanfileid)
        line["time_start"] = line.pop("starttime")
        line["time_stop"] = line.pop("endtime")
        line["info"] = line.pop("infos", None)
        for field in ["categories"]:
            if field in line:
                line[field] = "{%s}" % json.dumps(line[field])[1:-1]
        for port in line.get("ports", []):
            for script in port.get("scripts", []):
                if "masscan" in script and "raw" in script["masscan"]:
                    script["masscan"]["raw"] = utils.encode_b64(
                        script["masscan"]["raw"]
                    )
                if "ssl-cert" in script:
                    for cert in script["ssl-cert"]:
                        for fld in ["not_before", "not_after"]:
                            if fld not in cert:
                                continue
                            if isinstance(cert[fld], datetime.datetime):
                                cert[fld] = cert[fld].timestamp()
                            elif isinstance(cert[fld], str):
                                cert[fld] = utils.all2datetime(cert[fld]).timestamp()
            if "screendata" in port:
                port["screendata"] = utils.encode_b64(port["screendata"])
        for field in ["hostnames", "ports", "info"]:
            if field in line:
                line[field] = json.dumps(line[field]).replace("\\", "\\\\")
        return [
            "\\N" if line.get(col.name) is None else str(line.get(col.name))
            for col in self.table.columns
        ]


# Passive
class PassiveCSVFile(CSVFile):
    info_fields = set(["distance", "signature", "version"])

    def __init__(
        self,
        siggen,
        ip2internal,
        table,
        limit=None,
        getinfos=None,
        separated_timestamps=True,
    ):
        self.ip2internal = ip2internal
        self.table = table
        self.inp = siggen
        self.fdesc = None
        self.limit = limit
        if limit is not None:
            self.count = 0
        self.getinfos = getinfos
        self.timestamps = separated_timestamps

    def fixline(self, line):
        if self.timestamps:
            timestamp, line = line
            line["firstseen"] = line["lastseen"] = utils.all2datetime(timestamp)
        else:
            line["firstseen"] = utils.all2datetime(line["firstseen"])
            line["lastseen"] = utils.all2datetime(line["lastseen"])
        if self.getinfos is not None:
            line.update(self.getinfos(line))
            try:
                line.update(line.pop("infos"))
            except KeyError:
                pass
        if "addr" in line:
            line["addr"] = self.ip2internal(line["addr"])
        else:
            line["addr"] = None
        line.setdefault("count", 1)
        line.setdefault("port", -1)
        for key in ["sensor", "value", "source", "targetval"]:
            line.setdefault(key, "")
        if line["recontype"] in {"SSL_SERVER", "SSL_CLIENT"} and line["source"] in {
            "cert",
            "cacert",
        }:
            for fld in ["not_before", "not_after"]:
                if fld not in line:
                    continue
                if isinstance(line[fld], datetime.datetime):
                    line[fld] = line[fld].timestamp()
                elif isinstance(line[fld], str):
                    line[fld] = utils.all2datetime(line[fld]).timestamp()
        for key, value in line.items():
            if key not in ["info", "moreinfo"] and isinstance(value, str):
                try:
                    value = value.encode("latin-1")
                except Exception:
                    pass
                line[key] = "".join(
                    chr(c) if 32 <= c <= 126 else "\\x%02x" % c for c in value
                ).replace("\\", "\\\\")
        line["info"] = (
            "%s"
            % json.dumps(
                dict(
                    (key, line.pop(key))
                    for key in list(line)
                    if key in self.info_fields
                ),
            ).replace("\\", "\\\\")
        )
        line["moreinfo"] = (
            "%s"
            % json.dumps(
                dict(
                    (key, line.pop(key))
                    for key in list(line)
                    if key not in self.table.columns
                ),
            ).replace("\\", "\\\\")
        )
        return [
            "\\N" if line.get(col.name) is None else str(line.get(col.name))
            for col in self.table.columns
        ]


class SQLDB(DB):

    table_layout = namedtuple("empty_layout", [])
    tables = table_layout()
    fields = {}
    no_limit = None

    def __init__(self, url):
        super().__init__()
        self.dburl = url.geturl()

    @property
    def db(self):
        """The DB connection."""
        try:
            return self._db
        except AttributeError:
            # echo on debug disabled for tests
            self._db = create_engine(self.dburl, echo=config.DEBUG_DB)
            return self._db

    @property
    def flt_empty(self):
        return self.base_filter()

    def drop(self):
        for table in reversed(self.tables):
            table.__table__.drop(bind=self.db, checkfirst=True)

    def create(self):
        for table in self.tables:
            table.__table__.create(bind=self.db, checkfirst=True)

    def init(self):
        self.drop()
        self.create()

    def explain(self, req, **_):
        """This method calls the SQL EXPLAIN statement to retrieve database
        statistics.
        """
        raise NotImplementedError()

    def _get(self, flt, limit=None, skip=None, sort=None, fields=None):
        raise NotImplementedError()

    @staticmethod
    def ip2internal(addr):
        # required for use with ivre.db.sql.tables.DefaultINET() (see
        # .bind_processor()). Backends using variants must implement
        # their own methods.
        if not addr:
            return b""
        return utils.ip2bin(addr)

    @staticmethod
    def internal2ip(addr):
        # required for use with ivre.db.sql.tables.DefaultINET() (see
        # .result_processor()). Backends using variants must implement
        # their own methods.
        if not addr:
            return None
        return utils.bin2ip(addr)

    @staticmethod
    def to_binary(data):
        return utils.encode_b64(data).decode()

    @staticmethod
    def from_binary(data):
        return utils.decode_b64(data.encode())

    @staticmethod
    def flt2str(flt):
        result = {}
        for queryname, queries in flt.all_queries.items():
            outqueries = []
            if not isinstance(queries, list):
                queries = [queries]
            for query in queries:
                if query is not None:
                    outqueries.append(str(query))
            if outqueries:
                result[queryname] = outqueries
        return json.dumps(result)

    def create_indexes(self):
        raise NotImplementedError()

    def ensure_indexes(self):
        raise NotImplementedError()

    @staticmethod
    def query(*args, **kargs):
        raise NotImplementedError()

    def run(self, query):
        raise NotImplementedError()

    @classmethod
    def from_dbdict(cls, d):
        raise NotImplementedError()

    @classmethod
    def from_dbprop(cls, prop, val):
        raise NotImplementedError()

    @classmethod
    def to_dbdict(cls, d):
        raise NotImplementedError()

    @classmethod
    def to_dbprop(cls, prop, val):
        raise NotImplementedError()

    # FIXME: move this method
    @classmethod
    def _date_round(cls, date):
        if isinstance(date, datetime.datetime):
            ts = date.timestamp()
        else:
            ts = date
        ts = ts - (ts % config.FLOW_TIME_PRECISION)
        if isinstance(date, datetime.datetime):
            return datetime.datetime.fromtimestamp(ts)
        return ts

    @staticmethod
    def fmt_results(fields, result):
        return dict(
            (fld, value) for fld, value in zip(fields, result) if value is not None
        )

    @classmethod
    def searchobjectid(cls, oid, neg=False):
        """Filters records by their ObjectID.  `oid` can be a single or many
        (as a list or any iterable) object ID(s), specified as strings
        or an `ObjectID`s.

        """
        if isinstance(oid, (int, str)):
            oid = [int(oid)]
        else:
            oid = [int(suboid) for suboid in oid]
        return cls._searchobjectid(oid, neg=neg)

    @staticmethod
    def _searchobjectid(oid, neg=False):
        raise NotImplementedError()

    @staticmethod
    def _distinct_req(field, flt):
        return flt.query(select([field.distinct()]).select_from(flt.select_from))

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None, **kargs):
        """This method produces a generator of distinct values for a given
        field.

        """
        if isinstance(field, str):
            n_dots = field.count(".")
            for i in range(n_dots + 1):
                subfields = field.rsplit(".", i)
                try:
                    fld = self.fields[subfields[0]]
                except KeyError:
                    continue
                for attr in subfields[1:]:
                    try:
                        fld = getattr(fld, attr)
                    except AttributeError:
                        continue
                field = fld
                break
            else:
                raise ValueError("Unknown field %r" % field)
        if flt is None:
            flt = self.flt_empty
        sort = [
            (self.fields[key] if isinstance(key, str) else key, way)
            for key, way in sort or []
        ]
        req = self._distinct_req(field, flt, **kargs)
        for key, way in sort:
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return (next(iter(res.values())) for res in self.db.execute(req))

    @staticmethod
    def _flt_and(cond1, cond2):
        return cond1 & cond2

    @staticmethod
    def _flt_or(cond1, cond2):
        return cond1 | cond2

    @staticmethod
    def _searchstring_re_inarray(idfield, field, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            if neg:
                # FIXME
                raise ValueError("Not implemented")
            operator = "~*" if (value.flags & re.IGNORECASE) else "~"
            value = value.pattern
            base1 = select(
                [idfield.label("id"), func.unnest(field).label("field")]
            ).cte("base1")
            base2 = (
                select([column("id", Integer)])
                .select_from(base1)
                .where(column("field").op(operator)(value))
            )
            return idfield.in_(base2)
        return not_(field.any(value)) if neg else field.any(value)

    @staticmethod
    def _searchstring_re(field, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            flt = field.op("~*" if (value.flags & re.IGNORECASE) else "~")(
                value.pattern
            )
            if neg:
                return not_(flt)
            return flt
        if neg:
            return field != value
        return field == value

    @staticmethod
    def _searchstring_list(field, value, neg=False, map_=None):
        if not isinstance(value, str) and hasattr(value, "__iter__"):
            if map_ is not None:
                value = [map_(elt) for elt in value]
            if neg:
                return field.notin_(value)
            return field.in_(value)
        if map_ is not None:
            value = map_(value)
        if neg:
            return field != value
        return field == value


class SQLDBFlow(SQLDB, DBFlow):
    table_layout = namedtuple("flow_layout", ["flow"])
    tables = table_layout(Flow)

    @staticmethod
    def query(*args, **kargs):
        raise NotImplementedError()

    def add_flow(
        self,
        labels,
        keys,
        counters=None,
        accumulators=None,
        srcnode=None,
        dstnode=None,
        time=True,
    ):
        raise NotImplementedError()

    @classmethod
    def add_host(cls, labels=None, keys=None, time=True):
        raise NotImplementedError()

    def add_flow_metadata(
        self,
        labels,
        linktype,
        keys,
        flow_keys,
        counters=None,
        accumulators=None,
        time=True,
        flow_labels=None,
    ):
        raise NotImplementedError()

    def add_host_metadata(
        self,
        labels,
        linktype,
        keys,
        host_keys=None,
        counters=None,
        accumulators=None,
        time=True,
    ):
        raise NotImplementedError()

    def host_details(self, node_id):
        raise NotImplementedError()

    def flow_details(self, flow_id):
        raise NotImplementedError()

    def from_filters(
        self, filters, limit=None, skip=0, orderby="", mode=None, timeline=False
    ):
        raise NotImplementedError()

    def to_graph(self, query):
        raise NotImplementedError()

    def to_iter(self, query):
        raise NotImplementedError()

    def count(self, flt):
        raise NotImplementedError()

    def flow_daily(self, query):
        raise NotImplementedError()

    def top(self, query, fields, collect=None, sumfields=None):
        """Returns an iterator of:
        {fields: <fields>, count: <number of occurrence or sum of sumfields>,
         collected: <collected fields>}.
        """
        raise NotImplementedError()

    def cleanup_flows(self):
        raise NotImplementedError()


class Filter:
    @staticmethod
    def fltand(flt1, flt2):
        return flt1 if flt2 is None else flt2 if flt1 is None else and_(flt1, flt2)

    @staticmethod
    def fltor(flt1, flt2):
        return flt1 if flt2 is None else flt2 if flt1 is None else or_(flt1, flt2)


class ActiveFilter(Filter):
    def __init__(
        self,
        main=None,
        hostname=None,
        category=None,
        port=None,
        script=None,
        tables=None,
        trace=None,
    ):
        self.main = main
        self.hostname = [] if hostname is None else hostname
        self.category = [] if category is None else category
        self.port = [] if port is None else port
        self.script = [] if script is None else script
        self.tables = tables  # default value is handled in the subclasses
        self.trace = [] if trace is None else trace

    @property
    def all_queries(self):
        return {
            "main": self.main,
            "hostname": self.hostname,
            "category": self.category,
            "port": [elt[1] if elt[0] else not_(elt[1]) for elt in self.port],
            "script": self.script,
            "tables": self.tables,
            "trace": self.trace,
        }

    def copy(self):
        return self.__class__(
            main=self.main,
            hostname=self.hostname[:],
            category=self.category[:],
            port=self.port[:],
            script=self.script[:],
            tables=self.tables,
            trace=self.trace[:],
        )

    def __and__(self, other):
        if self.tables != other.tables:
            print("self.tables = %s" % str(self.tables))
            print("other.tables = %s" % str(other.tables))
            raise ValueError("Cannot 'AND' two filters on separate tables")
        return self.__class__(
            main=self.fltand(self.main, other.main),
            hostname=self.hostname + other.hostname,
            category=self.category + other.category,
            port=self.port + other.port,
            script=self.script + other.script,
            tables=self.tables,
            trace=self.trace + other.trace,
        )

    def __or__(self, other):
        # FIXME: this has to be implemented
        if self.hostname and other.hostname:
            raise ValueError("Cannot 'OR' two filters on hostname")
        if self.category and other.category:
            raise ValueError("Cannot 'OR' two filters on category")
        if self.port and other.port:
            raise ValueError("Cannot 'OR' two filters on port")
        if self.script and other.script:
            raise ValueError("Cannot 'OR' two filters on script")
        if self.trace and other.trace:
            raise ValueError("Cannot 'OR' two filters on trace")
        if self.tables != other.tables:
            raise ValueError("Cannot 'OR' two filters on separate tables")
        return self.__class__(
            main=self.fltor(self.main, other.main),
            hostname=self.hostname + other.hostname,
            category=self.category + other.category,
            port=self.port + other.port,
            script=self.script + other.script,
            tables=self.tables,
            trace=self.trace + other.trace,
        )

    def select_from_base(self, base=None):
        if base in [None, self.tables.scan, self.tables.scan.__mapper__]:
            base = self.tables.scan
        else:
            base = join(self.tables.scan, base)
        return base

    @property
    def select_from(self):
        return self.select_from_base()

    def query(self, req):
        if self.main is not None:
            req = req.where(self.main)
        for incl, subflt in self.hostname:
            base = select([self.tables.hostname.scan]).where(subflt)
            if incl:
                req = req.where(self.tables.scan.id.in_(base))
            else:
                req = req.where(self.tables.scan.id.notin_(base))
        # See <http://stackoverflow.com/q/17112345/3223422> - "Using
        # INTERSECT with tables from a WITH clause"
        for subflt in self.category:
            req = req.where(
                exists(
                    select([1])
                    .select_from(
                        join(
                            self.tables.category, self.tables.association_scan_category
                        )
                    )
                    .where(subflt)
                    .where(
                        self.tables.association_scan_category.scan
                        == self.tables.scan.id
                    )
                )
            )
        for incl, subflt in self.port:
            if incl:
                req = req.where(
                    exists(
                        select([1])
                        .select_from(self.tables.port)
                        .where(subflt)
                        .where(self.tables.port.scan == self.tables.scan.id)
                    )
                )
            else:
                base = select([self.tables.port.scan]).where(subflt)
                req = req.where(self.tables.scan.id.notin_(base))
        for incl, subflt in self.script:
            subreq = select([1]).select_from(join(self.tables.script, self.tables.port))
            if isinstance(subflt, tuple):
                for selectfrom in subflt[1]:
                    subreq = subreq.select_from(selectfrom)
                subreq = subreq.where(subflt[0])
            else:
                subreq = subreq.where(subflt)
            subreq = subreq.where(self.tables.port.scan == self.tables.scan.id)
            if incl:
                req = req.where(exists(subreq))
            else:
                req = req.where(not_(exists(subreq)))
        for subflt in self.trace:
            req = req.where(
                exists(
                    select([1])
                    .select_from(join(self.tables.trace, self.tables.hop))
                    .where(subflt)
                    .where(self.tables.trace.scan == self.tables.scan.id)
                )
            )
        return req


class NmapFilter(ActiveFilter):
    def __init__(
        self,
        main=None,
        hostname=None,
        category=None,
        port=None,
        script=None,
        tables=None,
        trace=None,
    ):
        super().__init__(
            main=main,
            hostname=hostname,
            category=category,
            port=port,
            script=script,
            tables=SQLDBNmap.tables if tables is None else tables,
            trace=trace,
        )


class ViewFilter(ActiveFilter):
    def __init__(
        self,
        main=None,
        hostname=None,
        category=None,
        port=None,
        script=None,
        tables=None,
        trace=None,
    ):
        super().__init__(
            main=main,
            hostname=hostname,
            category=category,
            port=port,
            script=script,
            tables=SQLDBView.tables if tables is None else tables,
            trace=trace,
        )


class SQLDBActive(SQLDB, DBActive):
    _needunwind_script = set(
        [
            "http-headers",
            "http-user-agent",
            "ssh-hostkey",
            "ssl-cert",
            "ssl-ja3-client",
            "ssl-ja3-server",
        ]
    )

    @classmethod
    def needunwind_script(cls, key):
        key = key.split(".")
        for i in range(len(key)):
            subkey = ".".join(key[: i + 1])
            if subkey in cls._needunwind_script:
                yield subkey

    def __init__(self, url):
        super().__init__(url)
        self.output_function = None
        self.bulk = None

    def store_host(self, host):
        raise NotImplementedError()

    def store_or_merge_host(self, host):
        raise NotImplementedError()

    def migrate_schema(self, version):
        """Migrates the scan data."""
        failed = 0
        if (version or 0) < 9:
            failed += self._migrate_schema_8_9()
        if (version or 0) < 10:
            failed += self._migrate_schema_9_10()
        if (version or 0) < 11:
            failed += self._migrate_schema_10_11()
        if (version or 0) < 12:
            failed += self._migrate_schema_11_12()
        if (version or 0) < 13:
            failed += self._migrate_schema_12_13()
        if (version or 0) < 14:
            failed += self._migrate_schema_13_14()
        if (version or 0) < 15:
            failed += self._migrate_schema_14_15()
        if (version or 0) < 16:
            failed += self._migrate_schema_15_16()
        if (version or 0) < 18:
            failed += self._migrate_schema_17_18()
        if (version or 0) < 19:
            failed += self._migrate_schema_18_19()
        return failed

    def _migrate_schema_8_9(self):
        """Converts records from version 8 to version 9. Version 9 creates a
        structured output for http-headers script.

        """
        cond = self.tables.scan.schema_version == 8
        failed = set()
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name == "http-headers"))
        )
        for rec in self.db.execute(req):
            if "http-headers" not in rec.data:
                try:
                    data = xmlnmap.add_http_headers_data(
                        {"id": "http-headers", "output": rec.output}
                    )
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate host %r", rec.id, exc_info=True
                    )
                    failed.add(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == "http-headers",
                                )
                            )
                            .values(data={"http-headers": data})
                        )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=9))
        return len(failed)

    def _migrate_schema_9_10(self):
        """Converts a record from version 9 to version 10. Version 10 changes
        the field names of the structured output for s7-info script.

        """
        cond = self.tables.scan.schema_version == 9
        failed = set()
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name == "s7-info"))
        )
        for rec in self.db.execute(req):
            if "s7-info" in rec.data:
                try:
                    data = xmlnmap.change_s7_info_keys(rec.data["s7-info"])
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate host %r", rec.id, exc_info=True
                    )
                    failed.add(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == "s7-info",
                                )
                            )
                            .values(data={"s7-info": data})
                        )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=10))
        return len(failed)

    def _migrate_schema_10_11(self):
        """Converts a record from version 10 to version 11. Version 11 changes
        the way IP addresses are stored.

        """
        raise NotImplementedError

    def _migrate_schema_11_12(self):
        """Converts a record from version 11 to version 12. Version 12 changes
        the structured output for fcrdns and rpcinfo script.

        """
        cond = self.tables.scan.schema_version == 11
        failed = set()
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.name,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name.in_(["fcrdns", "rpcinfo"])))
        )
        for rec in self.db.execute(req):
            if rec.name in rec.data:
                migr_func = {
                    "fcrdns": xmlnmap.change_fcrdns_migrate,
                    "rpcinfo": xmlnmap.change_rpcinfo,
                }[rec.name]
                try:
                    data = migr_func(rec.data[rec.name])
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate host %r", rec.id, exc_info=True
                    )
                    failed.add(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == rec.name,
                                )
                            )
                            .values(data={rec.name: data})
                        )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=12))
        return len(failed)

    def _migrate_schema_12_13(self):
        """Converts a record from version 12 to version 13. Version 13 changes
        the structured output for ms-sql-info and smq-enum-shares scripts.

        """
        cond = self.tables.scan.schema_version == 12
        failed = set()
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.name,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(
                and_(
                    cond,
                    self.tables.script.name.in_(["ms-sql-info", "smb-enum-shares"]),
                )
            )
        )
        for rec in self.db.execute(req):
            print(repr(rec))
            if rec.name in rec.data:
                migr_func = {
                    "ms-sql-info": xmlnmap.change_ms_sql_info,
                    "smb-enum-shares": xmlnmap.change_smb_enum_shares,
                }[rec.name]
                try:
                    data = migr_func(rec.data[rec.name])
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate host %r", rec.id, exc_info=True
                    )
                    failed.add(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == rec.name,
                                )
                            )
                            .values(data={rec.name: data})
                        )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=13))
        return len(failed)

    def _migrate_schema_13_14(self):
        """Converts a record from version 13 to version 14. Version 14 changes
        the structured output for ssh-hostkey and ls scripts to prevent a same
        field from having different data types.

        """
        cond = self.tables.scan.schema_version == 13
        failed = set()
        scripts = [
            script_name
            for script_name, alias in ALIASES_TABLE_ELEMS.items()
            if alias == "ls"
        ]
        scripts.append("ssh-hostkey")
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.name,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name.in_(scripts)))
        )
        for rec in self.db.execute(req):
            if rec.name in rec.data:
                migr_func = (
                    xmlnmap.change_ssh_hostkey
                    if rec.name == "ssh-hostkey"
                    else xmlnmap.change_ls_migrate
                )
                try:
                    data = migr_func(rec.data[rec.name])
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate host %r", rec.id, exc_info=True
                    )
                    failed.add(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == rec.name,
                                )
                            )
                            .values(data={rec.name: data})
                        )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=14))
        return len(failed)

    def _migrate_schema_14_15(self):
        """Converts a record from version 14 to version 15. Version 15 changes
        the structured output for httpègit script to move data to values
        instead of keys.

        """
        cond = self.tables.scan.schema_version == 14
        failed = set()
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.name,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name == "http-git"))
        )
        for rec in self.db.execute(req):
            if rec.name in rec.data:
                try:
                    data = xmlnmap.change_http_git(rec.data[rec.name])
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate host %r", rec.id, exc_info=True
                    )
                    failed.add(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == rec.name,
                                )
                            )
                            .values(data={rec.name: data})
                        )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=15))
        return len(failed)

    def _migrate_schema_15_16(self):
        """Converts a record from version 15 to version 16. Version 16 uses a
        consistent structured output for Nmap http-server-header script (old
        versions reported `{"Server": "value"}`, while recent versions report
        `["value"]`).

        """
        cond = self.tables.scan.schema_version == 15
        failed = []
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name == "http-server-header"))
        )
        for rec in self.db.execute(req):
            updated = False
            if "http-server-header" in rec.data:
                data = rec.data["http-server-header"]
                if isinstance(data, dict):
                    updated = True
                    if "Server" in data:
                        data = [data["Server"]]
                    else:
                        data = []
            else:
                try:
                    data = [
                        line.split(":", 1)[1].lstrip()
                        for line in (line.strip() for line in rec.output.splitlines())
                        if line.startswith("Server:")
                    ]
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate host %r", rec.id, exc_info=True
                    )
                    failed.add(rec.id)
                else:
                    updated = True
            if updated:
                self.db.execute(
                    update(self.tables.script)
                    .where(
                        and_(
                            self.tables.script.port == rec.port,
                            self.tables.script.name == "http-server-header",
                        )
                    )
                    .values(data={"http-server-header": data})
                )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=16))
        return len(failed)

    def _migrate_schema_17_18(self):
        """Converts a record from version 17 to version 18. Version 18
        introduces HASSH (SSH fingerprint) in ssh2-enum-algos.

        """
        cond = self.tables.scan.schema_version == 17
        failed = set()
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.name,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name == "ssh2-enum-algos"))
        )
        for rec in self.db.execute(req):
            if rec.name in rec.data:
                try:
                    output, data = xmlnmap.change_ssh2_enum_algos(
                        rec.output,
                        rec.data[rec.name],
                    )
                except Exception:
                    utils.LOGGER.warning(
                        "Cannot migrate host %r", rec.id, exc_info=True
                    )
                    failed.add(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == rec.name,
                                )
                            )
                            .values(output=output, data={rec.name: data})
                        )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=18))
        return len(failed)

    def _migrate_schema_18_19(self):
        """Converts a record from version 18 to version 19. Version 19
        splits smb-os-discovery scripts into two, a ntlm-info one that contains all
        the information the original smb-os-discovery script got from NTLM, and a
        smb-os-discovery script with only the information regarding SMB

        """
        cond = self.tables.scan.schema_version == 18
        failed = set()
        req = (
            select(
                [
                    self.tables.scan.id,
                    self.tables.script.name,
                    self.tables.script.port,
                    self.tables.script.output,
                    self.tables.script.data,
                ]
            )
            .select_from(
                join(join(self.tables.scan, self.tables.port), self.tables.script)
            )
            .where(and_(cond, self.tables.script.name == "smb-os-discovery"))
        )
        for rec in self.db.execute(req):
            if rec.name == "smb-os-discovery":
                if rec.name in rec.data:
                    try:
                        smb, ntlm = xmlnmap.split_smb_os_discovery(rec.data)
                    except Exception:
                        utils.LOGGER.warning(
                            "Cannot migrate host %r", rec.id, exc_info=True
                        )
                        failed.add(rec.id)
                    else:
                        if "masscan" in smb:
                            data = {
                                "smb-os-discovery": smb["smb-os-discovery"],
                                "masscan": smb["masscan"],
                            }
                        else:
                            data = {"smb-os-discovery": smb["smb-os-discovery"]}
                        self.db.execute(
                            update(self.tables.script)
                            .where(
                                and_(
                                    self.tables.script.port == rec.port,
                                    self.tables.script.name == rec.name,
                                )
                            )
                            .values(output=smb["output"], data=data)
                        )
                        if ntlm:
                            self.db.execute(
                                insert(self.tables.script).values(
                                    port=rec.port,
                                    name=ntlm["id"],
                                    output=ntlm["output"],
                                    data={"ntlm-info": ntlm["ntlm-info"]},
                                )
                            )
                elif rec.name.endswith("-ntlm-info"):
                    script = {"id": rec.name, "output": rec.output, rec.name: rec.data}
                    xmlnmap.post_ntlm_info(script, {}, {})
                    self.db.execute(
                        update(self.tables.script)
                        .where(
                            and_(
                                self.tables.script.port == rec.port,
                                self.tables.script.name == rec.name,
                            )
                        )
                        .values(
                            name="ntlm-info",
                            output=script["output"],
                            data=script.get("ntlm-info", {}),
                        )
                    )
        if failed:
            cond = and_(cond, self.tables.scan.id.notin_(failed))
        self.db.execute(update(self.tables.scan).where(cond).values(schema_version=19))
        return len(failed)

    def count(self, flt, **_):
        return self.db.execute(
            flt.query(select([func.count()])).select_from(flt.select_from)
        ).fetchone()[0]

    @staticmethod
    def _distinct_req(field, flt):
        flt = flt.copy()
        return flt.query(
            select([field.distinct()]).select_from(flt.select_from_base(field.parent))
        )

    def _get_open_port_count(self, flt, limit=None, skip=None):
        req = flt.query(select([self.tables.scan.id]))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        base = req.cte("base")
        return (
            {"addr": rec[2], "starttime": rec[1], "openports": {"count": rec[0]}}
            for rec in self.db.execute(
                select(
                    [
                        func.count(self.tables.port.id),
                        self.tables.scan.time_start,
                        self.tables.scan.addr,
                    ]
                )
                .select_from(join(self.tables.port, self.tables.scan))
                .where(self.tables.port.state == "open")
                .group_by(self.tables.scan.addr, self.tables.scan.time_start)
                .where(self.tables.scan.id.in_(base))
            )
        )

    def get_open_port_count(self, flt, limit=None, skip=None):
        result = list(self._get_open_port_count(flt, limit=limit, skip=skip))
        return result, len(result)

    def getlocations(self, flt, limit=None, skip=None):
        req = flt.query(
            select(
                [
                    func.count(self.tables.scan.id),
                    self.tables.scan.info["coordinates"].astext,
                ]
            ).where(
                self.tables.scan.info.has_key("coordinates")  # noqa: W601
            ),
        )
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return (
            {"_id": Point().result_processor(None, None)(rec[1]), "count": rec[0]}
            for rec in self.db.execute(
                req.group_by(self.tables.scan.info["coordinates"].astext)
            )
        )

    def get_ips(self, flt, limit=None, skip=None):
        return tuple(
            action(flt, limit=limit, skip=skip) for action in [self.get, self.count]
        )

    def _get(self, flt, limit=None, skip=None, sort=None, fields=None):
        if fields is not None:
            utils.LOGGER.warning("Argument 'fields' provided but unused")
        req = flt.query(
            select(
                [
                    self.tables.scan.id,
                    self.tables.scan.addr,
                    self.tables.scan.source,
                    self.tables.scan.info,
                    self.tables.scan.time_start,
                    self.tables.scan.time_stop,
                    self.tables.scan.state,
                    self.tables.scan.state_reason,
                    self.tables.scan.state_reason_ttl,
                    self.tables.scan.schema_version,
                ]
            ).select_from(flt.select_from)
        )
        for key, way in sort or []:
            if isinstance(key, str) and key in self.fields:
                key = self.fields[key]
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return req

    def get(self, flt, limit=None, skip=None, sort=None, fields=None):
        req = self._get(flt, limit=limit, skip=skip, sort=sort, fields=fields)
        for scanrec in self.db.execute(req):
            rec = {}
            (
                rec["_id"],
                rec["addr"],
                rec["source"],
                rec["infos"],
                rec["starttime"],
                rec["endtime"],
                rec["state"],
                rec["state_reason"],
                rec["state_reason_ttl"],
                rec["schema_version"],
            ) = scanrec
            try:
                rec["addr"] = self.internal2ip(rec["addr"])
            except ValueError:
                pass
            if not rec["infos"]:
                del rec["infos"]
            categories = (
                select([self.tables.association_scan_category.category])
                .where(self.tables.association_scan_category.scan == rec["_id"])
                .cte("categories")
            )
            rec["categories"] = [
                cat[0]
                for cat in self.db.execute(
                    select([self.tables.category.name]).where(
                        self.tables.category.id == categories.c.category
                    )
                )
            ]
            for port in self.db.execute(
                select([self.tables.port]).where(self.tables.port.scan == rec["_id"])
            ):
                recp = {}
                (
                    portid,
                    _,
                    recp["port"],
                    recp["protocol"],
                    recp["state_state"],
                    recp["state_reason"],
                    recp["state_reason_ip"],
                    recp["state_reason_ttl"],
                    recp["service_name"],
                    recp["service_tunnel"],
                    recp["service_product"],
                    recp["service_version"],
                    recp["service_conf"],
                    recp["service_devicetype"],
                    recp["service_extrainfo"],
                    recp["service_hostname"],
                    recp["service_ostype"],
                    recp["service_servicefp"],
                ) = port
                try:
                    recp["state_reason_ip"] = self.internal2ip(recp["state_reason_ip"])
                except ValueError:
                    pass
                for fld, value in list(recp.items()):
                    if value is None:
                        del recp[fld]
                for script in self.db.execute(
                    select(
                        [
                            self.tables.script.name,
                            self.tables.script.output,
                            self.tables.script.data,
                        ]
                    ).where(self.tables.script.port == portid)
                ):
                    data = dict(
                        id=script.name,
                        output=script.output,
                        **(script.data if script.data else {}),
                    )
                    if "ssl-cert" in data:
                        for cert in data["ssl-cert"]:
                            for fld in ["not_before", "not_after"]:
                                try:
                                    cert[fld] = utils.all2datetime(cert[fld])
                                except KeyError:
                                    pass
                    recp.setdefault("scripts", []).append(data)
                rec.setdefault("ports", []).append(recp)
            for trace in self.db.execute(
                select([self.tables.trace]).where(self.tables.trace.scan == rec["_id"])
            ):
                curtrace = {}
                rec.setdefault("traces", []).append(curtrace)
                curtrace["port"] = trace["port"]
                curtrace["protocol"] = trace["protocol"]
                curtrace["hops"] = []
                for hop in self.db.execute(
                    select([self.tables.hop])
                    .where(self.tables.hop.trace == trace["id"])
                    .order_by(self.tables.hop.ttl)
                ):
                    values = dict(
                        (key, hop[key])
                        for key in ["ipaddr", "ttl", "rtt", "host", "domains"]
                    )
                    try:
                        values["ipaddr"] = self.internal2ip(values["ipaddr"])
                    except ValueError:
                        pass
                    curtrace["hops"].append(values)
            for hostname in self.db.execute(
                select([self.tables.hostname]).where(
                    self.tables.hostname.scan == rec["_id"]
                )
            ):
                rec.setdefault("hostnames", []).append(
                    dict((key, hostname[key]) for key in ["name", "type", "domains"])
                )
            yield rec

    def remove(self, host):
        """Removes the host scan result. `host` must be a record as yielded by
        .get().

        """
        self.db.execute(
            delete(self.tables.scan).where(self.tables.scan.id == host["_id"])
        )

    def remove_many(self, flt):
        """Removes the host scan result. `flt` must be a valid NmapFilter()
        instance.

        """
        base = flt.query(select([self.tables.scan.id])).cte("base")
        self.db.execute(delete(self.tables.scan).where(self.tables.scan.id.in_(base)))

    _topstructure = namedtuple(
        "topstructure", ["base", "fields", "where", "group_by", "extraselectfrom"]
    )
    _topstructure.__new__.__defaults__ = (None,) * len(_topstructure._fields)

    @classmethod
    def searchnonexistent(cls):
        return cls.base_filter(main=False)

    @classmethod
    def _searchobjectid(cls, oid, neg=False):
        if len(oid) == 1:
            return cls.base_filter(
                main=(cls.tables.scan.id != oid[0])
                if neg
                else (cls.tables.scan.id == oid[0])
            )
        return cls.base_filter(
            main=(cls.tables.scan.id.notin_(oid[0]))
            if neg
            else (cls.tables.scan.id.in_(oid[0]))
        )

    @classmethod
    def searchversion(cls, version):
        return cls.base_filter(main=cls.tables.scan.schema_version == version)

    @classmethod
    def searchcmp(cls, key, val, cmpop):
        if isinstance(key, str):
            key = cls.fields[key]
        return cls.base_filter(main=key.op(cmpop)(val))

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        if neg:
            return cls.base_filter(main=cls.tables.scan.addr != cls.ip2internal(addr))
        return cls.base_filter(main=cls.tables.scan.addr == cls.ip2internal(addr))

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        hosts = [cls.ip2internal(host) for host in hosts]
        if neg:
            return cls.base_filter(main=cls.tables.scan.addr.notin_(hosts))
        return cls.base_filter(main=cls.tables.scan.addr.in_(hosts))

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        start, stop = cls.ip2internal(start), cls.ip2internal(stop)
        if neg:
            return cls.base_filter(
                main=or_(cls.tables.scan.addr < start, cls.tables.scan.addr > stop)
            )
        return cls.base_filter(
            main=and_(cls.tables.scan.addr >= start, cls.tables.scan.addr <= stop)
        )

    @classmethod
    def searchdomain(cls, name, neg=False):
        return cls.base_filter(
            hostname=[
                (
                    not neg,
                    cls._searchstring_re_inarray(
                        cls.tables.hostname.id,
                        cls.tables.hostname.domains,
                        name,
                        neg=False,
                    ),
                ),
            ]
        )

    @classmethod
    def searchhostname(cls, name, neg=False):
        return cls.base_filter(
            hostname=[
                (
                    not neg,
                    cls._searchstring_re(cls.tables.hostname.name, name, neg=False),
                ),
            ]
        )

    @classmethod
    def searchcategory(cls, cat, neg=False):
        return cls.base_filter(
            category=[cls._searchstring_re(cls.tables.category.name, cat, neg=neg)]
        )

    @classmethod
    def searchcountry(cls, country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        country = utils.country_unalias(country)
        return cls.base_filter(
            main=cls._searchstring_list(
                cls.tables.scan.info["country_code"].astext, country, neg=neg
            )
        )

    @classmethod
    def searchcity(cls, city, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        city

        """
        return cls.base_filter(
            main=cls._searchstring_re(
                cls.tables.scan.info["city"].astext, city, neg=neg
            )
        )

    @classmethod
    def searchasnum(cls, asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        return cls.base_filter(
            main=cls._searchstring_list(
                cls.tables.scan.info["as_num"], asnum, neg=neg, map_=str
            )
        )

    @classmethod
    def searchasname(cls, asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        return cls.base_filter(
            main=cls._searchstring_rec(
                cls.tables.scan.info["as_name"].astext, asname, neg=neg
            )
        )

    @classmethod
    def searchport(cls, port, protocol="tcp", state="open", neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        if port == "host":
            return cls.base_filter(
                port=[
                    (
                        True,
                        (cls.tables.port.port >= 0)
                        if neg
                        else (cls.tables.port.port == -1),
                    ),
                ]
            )
        return cls.base_filter(
            port=[
                (
                    not neg,
                    and_(
                        cls.tables.port.port == port,
                        cls.tables.port.protocol == protocol,
                        cls.tables.port.state == state,
                    ),
                ),
            ]
        )

    @classmethod
    def searchportsother(cls, ports, protocol="tcp", state="open"):
        """Filters records with at least one port other than those
        listed in `ports` with state `state`.

        """
        return cls.base_filter(
            port=[
                (
                    True,
                    and_(
                        or_(
                            cls.tables.port.port.notin_(ports),
                            cls.tables.port.protocol != protocol,
                        ),
                        cls.tables.port.state == state,
                    ),
                )
            ]
        )

    @classmethod
    def searchports(cls, ports, protocol="tcp", state="open", neg=False, any_=False):
        if any_:
            if neg:
                raise ValueError("searchports: cannot set both neg and any_")
            return cls.base_filter(
                port=[
                    (
                        True,
                        and_(
                            cls.tables.port.port.in_(ports),
                            cls.tables.port.protocol == protocol,
                            cls.tables.port.state == state,
                        ),
                    ),
                ]
            )
        return cls.flt_and(
            *(
                cls.searchport(port, protocol=protocol, state=state, neg=neg)
                for port in ports
            )
        )

    @classmethod
    def searchcountopenports(cls, minn=None, maxn=None, neg=False):
        "Filters records with open port number between minn and maxn"
        assert minn is not None or maxn is not None
        req = select([column("scan", Integer)]).select_from(
            select([cls.tables.port.scan.label("scan"), func.count().label("count")])
            .where(cls.tables.port.state == "open")
            .group_by(cls.tables.port.scan)
            .alias("pcnt")
        )
        if minn == maxn:
            req = req.where(column("count") == minn)
        else:
            if minn is not None:
                req = req.where(column("count") >= minn)
            if maxn is not None:
                req = req.where(column("count") <= maxn)
        return cls.base_filter(
            main=cls.tables.scan.id.notin_(req) if neg else cls.tables.scan.id.in_(req)
        )

    @classmethod
    def searchopenport(cls, neg=False):
        "Filters records with at least one open port."
        return cls.base_filter(port=[(not neg, cls.tables.port.state == "open")])

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        if srv is False:
            req = cls.tables.port.service_name == None  # noqa: E711
        elif isinstance(srv, list):
            req = cls.tables.port.service_name.in_(srv)
        else:
            req = cls._searchstring_re(cls.tables.port.service_name, srv)
        if port is not None:
            req = and_(req, cls.tables.port.port == port)
        if protocol is not None:
            req = and_(req, cls.tables.port.protocol == protocol)
        return cls.base_filter(port=[(True, req)])

    @classmethod
    def searchproduct(
        cls, product=None, version=None, service=None, port=None, protocol=None
    ):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        req = True
        if product is not None:
            if product is False:
                req = and_(
                    req,
                    cls.tables.port.service_product == None,  # noqa: E711
                )
            elif isinstance(product, list):
                req = and_(
                    req,
                    cls.tables.port.service_product.in_(product),
                )
            else:
                req = and_(
                    req,
                    cls._searchstring_re(
                        cls.tables.port.service_product,
                        product,
                    ),
                )
        if version is not None:
            if version is False:
                req = and_(
                    req,
                    cls.tables.port.service_version == None,  # noqa: E711
                )
            elif isinstance(version, list):
                req = and_(
                    req,
                    cls.tables.port.service_version.in_(version),
                )
            else:
                req = and_(
                    req, cls._searchstring_re(cls.tables.port.service_version, version)
                )
        if service is not None:
            if service is False:
                req = and_(
                    req,
                    cls.tables.port.service_name == None,  # noqa: E711
                )
            elif isinstance(service, list):
                req = and_(
                    req,
                    cls.tables.port.service_name.in_(service),
                )
            else:
                req = and_(
                    req, cls._searchstring_re(cls.tables.port.service_name, service)
                )
        if port is not None:
            req = and_(req, cls.tables.port.port == port)
        if protocol is not None:
            req = and_(req, cls.tables.port.protocol == protocol)
        return cls.base_filter(port=[(True, req)])

    @classmethod
    def searchscript(cls, name=None, output=None, values=None, neg=False):
        """Search a particular content in the scripts results.

        If neg is True, filter out scan results which have at
        least one script matching the name/output/value
        """
        req = True
        if isinstance(name, list):
            req = and_(req, cls.tables.script.name.in_(name))
        elif name is not None:
            req = and_(
                req, cls._searchstring_re(cls.tables.script.name, name, neg=False)
            )
        if output is not None:
            req = and_(
                req, cls._searchstring_re(cls.tables.script.output, output, neg=False)
            )
        if values:
            if isinstance(name, list):
                all_keys = set(ALIASES_TABLE_ELEMS.get(n, n) for n in name)
                if len(all_keys) != 1:
                    raise TypeError(
                        ".searchscript() needs similar `name` values when using a `values` arg"
                    )
                basekey = all_keys.pop()
            elif not isinstance(name, str):
                raise TypeError(
                    ".searchscript() needs a `name` arg when using a `values` arg"
                )
            else:
                basekey = ALIASES_TABLE_ELEMS.get(name, name)
            if isinstance(values, (str, utils.REGEXP_T)):
                needunwind = sorted(set(cls.needunwind_script(basekey)))
            else:
                needunwind = sorted(
                    set(
                        unwind
                        for subkey in values
                        for unwind in cls.needunwind_script(
                            "%s.%s" % (basekey, subkey),
                        )
                    )
                )

            def _find_subkey(key):
                lastmatch = None
                if key is None:
                    key = []
                else:
                    key = key.split(".")
                for subkey in needunwind:
                    subkey = subkey.split(".")[1:]
                    if len(key) < len(subkey):
                        continue
                    if key == subkey:
                        return (".".join([basekey] + subkey), None)
                    if subkey == key[: len(subkey)]:
                        lastmatch = (
                            ".".join([basekey] + subkey),
                            ".".join(key[len(subkey) :]),
                        )
                return lastmatch

            def _to_json(key, value):
                key = key.split(".")
                result = value
                while key:
                    result = {key.pop(): result}
                return result

            if isinstance(values, (str, utils.REGEXP_T)):
                kv_generator = [(None, values)]
            else:
                kv_generator = values.items()

            for key, value in kv_generator:
                subkey = _find_subkey(key)
                if subkey is None:
                    if isinstance(value, utils.REGEXP_T):
                        base = cls.tables.script.data.op("->")(basekey)
                        key = key.split(".")
                        lastkey = key.pop()
                        for subkey in key:
                            base = base.op("->")(key)
                        base = base.op("->>")(lastkey)
                        req = and_(
                            req,
                            cls._searchstring_re(base, value, neg=False),
                        )
                    else:
                        req = and_(
                            req,
                            cls.tables.script.data.contains(
                                _to_json("%s.%s" % (basekey, key), value)
                            ),
                        )
                elif subkey[1] is None:
                    req = and_(
                        req,
                        cls._searchstring_re(
                            column(subkey[0].replace(".", "_").replace("-", "_")).op(
                                "->>"
                            )(0),
                            value,
                            neg=False,
                        ),
                    )
                elif "." in subkey[1]:
                    firstpart, tail = subkey[1].split(".", 1)
                    req = and_(
                        req,
                        column(subkey[0].replace(".", "_").replace("-", "_"))
                        .op("->")(firstpart)
                        .op("@>")(cast(_to_json(tail, value), JSONB)),
                    )
                else:
                    req = and_(
                        req,
                        cls._searchstring_re(
                            column(subkey[0].replace(".", "_").replace("-", "_")).op(
                                "->>"
                            )(subkey[1]),
                            value,
                            neg=False,
                        ),
                    )
            return cls.base_filter(
                script=[
                    (
                        not neg,
                        (
                            req,
                            [
                                func.jsonb_array_elements(
                                    cls.tables.script.data[subkey2]
                                ).alias(subkey2.replace(".", "_").replace("-", "_"))
                                for subkey2 in needunwind
                            ],
                        ),
                    )
                ]
            )
        return cls.base_filter(script=[(not neg, req)])

    @classmethod
    def searchsvchostname(cls, hostname):
        return cls.base_filter(
            port=[
                (True, cls._searchstring_re(cls.tables.port.service_hostname, hostname))
            ]
        )

    @classmethod
    def searchwebmin(cls):
        return cls.base_filter(
            port=[
                (
                    True,
                    and_(
                        cls.tables.port.service_name == "http",
                        cls.tables.port.service_product == "MiniServ",
                        cls.tables.port.service_extrainfo != "Webmin httpd",
                    ),
                )
            ]
        )

    @classmethod
    def searchx11(cls):
        return cls.base_filter(
            port=[
                (
                    True,
                    and_(
                        cls.tables.port.service_name == "X11",
                        cls.tables.port.service_extrainfo != "access denied",
                    ),
                )
            ]
        )

    def searchtimerange(self, start, stop, neg=False):
        start = utils.all2datetime(start)
        stop = utils.all2datetime(stop)
        if neg:
            return self.base_filter(
                main=(self.tables.scan.time_start < start)
                | (self.tables.scan.time_stop > stop)
            )
        return self.base_filter(
            main=(self.tables.scan.time_start >= start)
            & (self.tables.scan.time_stop <= stop)
        )

    @classmethod
    def searchfile(cls, fname=None, scripts=None):
        """Search shared files from a file name (either a string or a
        regexp), only from scripts using the "ls" NSE module.

        """
        if fname is None:
            req = cls.tables.script.data.op("@>")(
                '{"ls": {"volumes": [{"files": []}]}}'
            )
        else:
            if isinstance(fname, (utils.REGEXP_T, list)):
                base1 = (
                    select(
                        [
                            cls.tables.script.port,
                            func.jsonb_array_elements(
                                func.jsonb_array_elements(
                                    cls.tables.script.data["ls"]["volumes"]
                                ).op("->")("files")
                            )
                            .op("->>")("filename")
                            .label("filename"),
                        ]
                    )
                    .where(
                        cls.tables.script.data.op("@>")(
                            '{"ls": {"volumes": [{"files": []}]}}'
                        )
                    )
                    .cte("base1")
                )
                if isinstance(fname, list):
                    where_clause = column("filename").in_(fname)
                else:
                    where_clause = column("filename").op(
                        "~*" if (fname.flags & re.IGNORECASE) else "~"
                    )(fname.pattern)
                base2 = (
                    select([column("port", Integer)])
                    .select_from(base1)
                    .where(where_clause)
                )
                return cls.base_filter(port=[(True, cls.tables.port.id.in_(base2))])
            req = cls.tables.script.data.op("@>")(
                json.dumps({"ls": {"volumes": [{"files": [{"filename": fname}]}]}})
            )
        if scripts is None:
            return cls.base_filter(script=[(True, req)])
        if isinstance(scripts, str):
            scripts = [scripts]
        if len(scripts) == 1:
            return cls.base_filter(
                script=[(True, and_(cls.tables.script.name == scripts.pop(), req))]
            )
        return cls.base_filter(
            script=[(True, and_(cls.tables.script.name.in_(scripts), req))]
        )

    @classmethod
    def searchhttptitle(cls, title):
        return cls.base_filter(
            script=[
                (True, cls.tables.script.name.in_(["http-title", "html-title"])),
                (True, cls._searchstring_re(cls.tables.script.output, title)),
            ]
        )

    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        res = cls.tables.hop.ipaddr == cls.ip2internal(hop)
        if ttl is not None:
            res &= cls.tables.hop.ttl == ttl
        return cls.base_filter(trace=[not_(res) if neg else res])

    @classmethod
    def searchhopdomain(cls, hop, neg=False):
        return cls.base_filter(
            trace=[
                cls._searchstring_re_inarray(
                    cls.tables.hop.id, cls.tables.hop.domains, hop, neg=neg
                )
            ]
        )

    @classmethod
    def searchhopname(cls, hop, neg=False):
        return cls.base_filter(
            trace=[cls._searchstring_re(cls.tables.hop.host, hop, neg=neg)]
        )

    @classmethod
    def searchdevicetype(cls, devtype):
        return cls.base_filter(
            port=[
                (
                    True,
                    cls._searchstring_re(cls.tables.port.service_devicetype, devtype),
                )
            ]
        )

    @classmethod
    def searchnetdev(cls):
        return cls.base_filter(
            port=[
                (
                    True,
                    cls.tables.port.service_devicetype.in_(
                        [
                            "bridge",
                            "broadband router",
                            "firewall",
                            "hub",
                            "load balancer",
                            "proxy server",
                            "router",
                            "switch",
                            "WAP",
                        ]
                    ),
                )
            ]
        )

    @classmethod
    def searchphonedev(cls):
        return cls.base_filter(
            port=[
                (
                    True,
                    cls.tables.port.service_devicetype.in_(
                        [
                            "PBX",
                            "phone",
                            "telecom-misc",
                            "VoIP adapter",
                            "VoIP phone",
                        ]
                    ),
                )
            ]
        )

    @classmethod
    def searchldapanon(cls):
        return cls.base_filter(
            port=[
                (
                    True,
                    cls.tables.port.service_extrainfo == "Anonymous bind OK",
                )
            ]
        )

    @classmethod
    def searchvsftpdbackdoor(cls):
        return cls.base_filter(
            port=[
                (
                    True,
                    and_(
                        cls.tables.port.protocol == "tcp",
                        cls.tables.port.state == "open",
                        cls.tables.port.service_product == "vsftpd",
                        cls.tables.port.service_version == "2.3.4",
                    ),
                )
            ]
        )


class SQLDBNmap(SQLDBActive, DBNmap):
    table_layout = namedtuple(
        "nmap_layout",
        [
            "scanfile",
            "category",
            "scan",
            "hostname",
            "port",
            "script",
            "trace",
            "hop",
            "association_scan_hostname",
            "association_scan_category",
            "association_scan_scanfile",
        ],
    )
    tables = table_layout(
        N_ScanFile,
        N_Category,
        N_Scan,
        N_Hostname,
        N_Port,
        N_Script,
        N_Trace,
        N_Hop,
        N_Association_Scan_Hostname,
        N_Association_Scan_Category,
        N_Association_Scan_ScanFile,
    )
    fields = {
        "_id": N_Scan.id,
        "addr": N_Scan.addr,
        "source": N_Scan.source,
        "scanid": N_Association_Scan_ScanFile.scan_file,
        "starttime": N_Scan.time_start,
        "endtime": N_Scan.time_stop,
        "infos": N_Scan.info,
        "ports": N_Port,
        "state": N_Scan.state_reason_ttl,
        "state_reason": N_Scan.state_reason_ttl,
        "state_reason_ttl": N_Scan.state_reason_ttl,
        "schema_version": N_Scan.schema_version,
        "categories": N_Category.name,
        "hostnames.name": N_Hostname.name,
        "hostnames.domains": N_Hostname.domains,
    }

    base_filter = NmapFilter
    content_handler = xmlnmap.Nmap2DB

    def store_or_merge_host(self, host):
        self.store_host(host)

    def get(self, flt, limit=None, skip=None, sort=None, **kargs):
        for rec in super().get(flt, limit=limit, skip=skip, sort=sort, **kargs):
            rec["scanid"] = [
                scanfile[0]
                for scanfile in self.db.execute(
                    select([self.tables.association_scan_scanfile.scan_file]).where(
                        self.tables.association_scan_scanfile.scan == rec["_id"]
                    )
                )
            ]
            yield rec

    def _remove_unused_scan_files(self):
        """Removes unused scan files, useful when some scan results have been
        removed.

        """
        base = select([self.tables.association_scan_scanfile.scan_file]).cte("base")
        self.db.execute(
            delete(self.tables.scanfile).where(self.tables.scanfile.sha256.notin_(base))
        )

    def remove(self, host):
        """Removes the host scan result. `host` must be a record as yielded by
        .get().

        The scan files that are no longer linked to a scan are removed at the
        end of the call.

        """
        super().remove(host)
        self._remove_unused_scan_files()

    def remove_many(self, flt):
        """Removes the host scan result. `flt` must be a valid NmapFilter()
        instance.

        The scan files that are no longer linked to a scan are removed at the
        end of the call.

        """
        super().remove_many(flt)
        self._remove_unused_scan_files()

    @staticmethod
    def getscanids(host):
        return host["scanid"]

    def getscan(self, scanid):
        if isinstance(scanid, (str, bytes)) and len(scanid) == 64:
            scanid = utils.decode_hex(scanid)
        return self.db.execute(
            select([self.tables.scanfile]).where(self.tables.scanfile.sha256 == scanid)
        ).fetchone()

    def is_scan_present(self, scanid):
        return bool(
            self.db.execute(
                select([True])
                .where(self.tables.scanfile.sha256 == utils.decode_hex(scanid))
                .limit(1)
            ).fetchone()
        )

    @classmethod
    def searchsource(cls, src, neg=False):
        if isinstance(src, list):
            if neg:
                return cls.base_filter(main=(cls.tables.scan.source.notin_(src)))
            return cls.base_filter(main=(cls.tables.scan.source.in_(src)))
        return cls.base_filter(
            main=cls._searchstring_re(cls.tables.scan.source, src, neg=neg)
        )


class SQLDBView(SQLDBActive, DBView):
    table_layout = namedtuple(
        "view_layout",
        [
            "category",
            "scan",
            "hostname",
            "port",
            "script",
            "trace",
            "hop",
            "association_scan_hostname",
            "association_scan_category",
        ],
    )
    tables = table_layout(
        V_Category,
        V_Scan,
        V_Hostname,
        V_Port,
        V_Script,
        V_Trace,
        V_Hop,
        V_Association_Scan_Hostname,
        V_Association_Scan_Category,
    )
    fields = {
        "_id": V_Scan.id,
        "addr": V_Scan.addr,
        "source": V_Scan.source,
        "starttime": V_Scan.time_start,
        "endtime": V_Scan.time_stop,
        "infos": V_Scan.info,
        "ports": V_Port,
        "state": V_Scan.state_reason_ttl,
        "state_reason": V_Scan.state_reason_ttl,
        "state_reason_ttl": V_Scan.state_reason_ttl,
        "schema_version": V_Scan.schema_version,
        "categories": V_Category.name,
        "hostnames.name": V_Hostname.name,
        "hostnames.domains": V_Hostname.domains,
    }

    base_filter = ViewFilter

    def store_or_merge_host(self, host):
        # FIXME: may cause performance issues
        self.start_store_hosts()
        self.store_host(host)
        self.stop_store_hosts()

    @classmethod
    def searchsource(cls, src, neg=False):
        return cls.base_filter(
            main=cls._searchstring_re_inarray(
                cls.tables.scan.id, cls.tables.scan.source, src, neg=neg
            )
        )


class PassiveFilter(Filter):
    def __init__(self, main=None, tables=None):
        self.main = main
        self.tables = SQLDBPassive.tables if tables is None else tables

    @property
    def all_queries(self):
        return {
            "main": self.main,
            "tables": self.tables,
        }

    def __bool__(self):
        return self.main is not None

    def copy(self):
        return self.__class__(
            main=self.main,
            tables=self.tables,
        )

    def __and__(self, other):
        if self.tables != other.tables:
            raise ValueError("Cannot 'AND' two filters on separate tables")
        return self.__class__(
            main=self.fltand(self.main, other.main),
            tables=self.tables,
        )

    def __or__(self, other):
        if self.tables != other.tables:
            raise ValueError("Cannot 'OR' two filters on separate tables")
        return self.__class__(
            main=self.fltor(self.main, other.main),
            tables=self.tables,
        )

    @property
    def select_from(self):
        return self.tables.passive

    def query(self, req):
        if self.main is not None:
            req = req.where(self.main)
        return req


class SQLDBPassive(SQLDB, DBPassive):
    table_layout = namedtuple("passive_layout", ["passive"])
    tables = table_layout(Passive)
    fields = {
        "_id": Passive.id,
        "addr": Passive.addr,
        "sensor": Passive.sensor,
        "count": Passive.count,
        "firstseen": Passive.firstseen,
        "lastseen": Passive.lastseen,
        "distance": Passive.info.op("->>")("distance"),
        "signature": Passive.info.op("->>")("signature"),
        "version": Passive.info.op("->>")("version"),
        "infos": Passive.moreinfo,
        "infos.domain": Passive.moreinfo.op("->>")("domain"),
        "infos.issuer": Passive.moreinfo.op("->>")("issuer"),
        "infos.issuer_text": Passive.moreinfo.op("->>")("issuer_text"),
        "infos.md5": Passive.moreinfo.op("->>")("md5"),
        "infos.pubkey.type": (Passive.moreinfo.op("->")("pubkey").op("->>")("type")),
        "infos.san": Passive.moreinfo.op("->>")("san"),
        "infos.sha1": Passive.moreinfo.op("->>")("sha1"),
        "infos.sha256": Passive.moreinfo.op("->>")("sha256"),
        "infos.subject": Passive.moreinfo.op("->>")("subject"),
        "infos.subject_text": Passive.moreinfo.op("->>")("subject_text"),
        "infos.raw": Passive.moreinfo.op("->>")("raw"),
        "infos.domaintarget": Passive.moreinfo.op("->>")("domaintarget"),
        "infos.username": Passive.moreinfo.op("->>")("username"),
        "infos.password": Passive.moreinfo.op("->>")("password"),
        "infos.service_name": Passive.moreinfo.op("->>")("service_name"),
        "infos.service_ostype": Passive.moreinfo.op("->>")("service_ostype"),
        "infos.service_product": Passive.moreinfo.op("->>")("service_product"),
        "infos.service_version": Passive.moreinfo.op("->>")("service_version"),
        "infos.service_extrainfo": Passive.moreinfo.op("->>")("service_extrainfo"),
        "port": Passive.port,
        "recontype": Passive.recontype,
        "source": Passive.source,
        "targetval": Passive.targetval,
        "value": Passive.value,
        "schema_version": Passive.schema_version,
    }

    base_filter = PassiveFilter

    def count(self, flt):
        return self.db.execute(
            flt.query(select([func.count()]).select_from(flt.select_from))
        ).fetchone()[0]

    def remove(self, spec_or_id):
        if not isinstance(spec_or_id, Filter):
            spec_or_id = self.searchobjectid(spec_or_id)
        base = spec_or_id.query(
            select([self.tables.passive.id]).select_from(spec_or_id.select_from)
        ).cte("base")
        self.db.execute(
            delete(self.tables.passive).where(self.tables.passive.id.in_(base))
        )

    def _get(self, flt, limit=None, skip=None, sort=None, fields=None):
        if fields is not None:
            utils.LOGGER.warning("Argument 'fields' provided but unused")
        req = flt.query(
            select(
                [
                    self.tables.passive.id.label("_id"),
                    self.tables.passive.addr,
                    self.tables.passive.sensor,
                    self.tables.passive.count,
                    self.tables.passive.firstseen,
                    self.tables.passive.lastseen,
                    self.tables.passive.port,
                    self.tables.passive.recontype,
                    self.tables.passive.source,
                    self.tables.passive.targetval,
                    self.tables.passive.value,
                    self.tables.passive.info,
                    self.tables.passive.moreinfo,
                    self.tables.passive.schema_version,
                ]
            ).select_from(flt.select_from)
        )
        for key, way in sort or []:
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return req

    def get(self, flt, limit=None, skip=None, sort=None, fields=None):
        """Queries the passive database with the provided filter "flt", and
        returns a generator.

        """
        req = self._get(flt, limit=limit, skip=skip, sort=sort, fields=fields)
        for rec in self.db.execute(req):
            rec = dict((key, value) for key, value in rec.items() if value is not None)
            try:
                rec["addr"] = self.internal2ip(rec["addr"])
            except (KeyError, ValueError):
                pass
            rec["infos"] = dict(rec.pop("info"), **rec.pop("moreinfo"))
            if rec.get("recontype") in {"SSL_SERVER", "SSL_CLIENT"} and rec.get(
                "source"
            ) in {
                "cert",
                "cacert",
            }:
                rec["value"] = self.from_binary(rec["value"])
                for fld in ["not_before", "not_after"]:
                    try:
                        rec["infos"][fld] = utils.all2datetime(rec["infos"][fld])
                    except KeyError:
                        pass
            if rec.get("port") == -1:
                del rec["port"]
            yield rec

    def get_one(self, flt, skip=None):
        """Queries the passive database with the provided filter "flt", and
        returns the first result, or None if no result exists."""
        return next(self.get(flt, limit=1, skip=skip))

    def _insert_or_update(self, timestamp, values, lastseen=None, replacecount=False):
        raise NotImplementedError()

    def insert_or_update(
        self, timestamp, spec, getinfos=None, lastseen=None, replacecount=False
    ):
        if spec is None:
            return
        try:
            spec["addr"] = self.ip2internal(spec["addr"])
        except (KeyError, ValueError):
            pass
        if getinfos is not None:
            spec.update(getinfos(spec))
            try:
                spec.update(spec.pop("infos"))
            except KeyError:
                pass
        addr = spec.pop("addr", None)
        timestamp = utils.all2datetime(timestamp)
        if lastseen is not None:
            lastseen = utils.all2datetime(lastseen)
        if addr:
            addr = self.ip2internal(addr)
        if spec["recontype"] in {"SSL_SERVER", "SSL_CLIENT"} and spec["source"] in {
            "cert",
            "cacert",
        }:
            for fld in ["not_before", "not_after"]:
                if fld not in spec:
                    continue
                if isinstance(spec[fld], datetime.datetime):
                    spec[fld] = spec[fld].timestamp()
                elif isinstance(spec[fld], str):
                    spec[fld] = utils.all2datetime(spec[fld]).timestamp()
        otherfields = dict(
            (key, spec.pop(key, ""))
            for key in ["sensor", "source", "targetval", "recontype", "value"]
        )
        info = dict(
            (key, spec.pop(key))
            for key in ["distance", "signature", "version"]
            if key in spec
        )
        vals = {
            "addr": addr,
            # sensor: otherfields
            "count": spec.pop("count", 1),
            "firstseen": timestamp,
            "lastseen": lastseen or timestamp,
            "port": spec.pop("port", -1),
            # source, targetval, recontype, value: otherfields
            "info": info,
            "moreinfo": spec,
            "schema_version": spec.pop("schema_version", None),
        }
        vals.update(otherfields)
        self._insert_or_update(
            timestamp, vals, lastseen=lastseen, replacecount=replacecount
        )

    def topvalues(
        self,
        field,
        flt=None,
        topnbr=10,
        sort=None,
        limit=None,
        skip=None,
        least=False,
        distinct=True,
    ):
        """This method produces top values for a given field.

        If `distinct` is True (default), the top values are computed
        by distinct events. If it is False, they are computed based on
        the "count" field.

        """
        more_filter = None
        if flt is None:
            flt = PassiveFilter()
        if field == "domains":
            field = func.jsonb_array_elements(self.tables.passive.moreinfo["domain"])
        elif field.startswith("domains:"):
            level = int(field[8:]) - 1
            field = func.jsonb_array_elements_text(
                self.tables.passive.moreinfo["domain"]
            ).label("field")

            def more_filter(base):
                return (
                    func.length(base.field)
                    - func.length(func.replace(base.field, ".", ""))
                    == level
                )

        elif field == "net" or field.startswith("net:"):
            info = field[4:]
            info = int(info) if info else 24
            field = func.set_masklen(text("addr::cidr"), info)

            # another option would be:
            # def more_filter(base):
            #     return base.field.op('~')('^([^\\.]+\\.){%d}[^\\.]+$' %
            #                               level)
        if isinstance(field, str):
            field = self.fields[field]

        if field is not None and field == self.fields["addr"]:
            outputproc = self.internal2ip
        else:

            def outputproc(val):
                return val

        order = "count" if least else desc("count")
        if more_filter is None:
            req = flt.query(
                select(
                    [
                        (
                            func.count()
                            if distinct
                            else func.sum(self.tables.passive.count)
                        ).label("count"),
                        field,
                    ]
                )
                .select_from(flt.select_from)
                .group_by(field)
            )
        else:
            base1 = flt.query(
                select(
                    [
                        (
                            func.count()
                            if distinct
                            else func.sum(self.tables.passive.count)
                        ).label("count"),
                        field,
                    ]
                )
                .select_from(flt.select_from)
                .group_by(field)
            ).cte("base1")
            req = select([base1.c.count, base1.c.field]).where(more_filter(base1.c))
        return (
            {
                "count": result[0],
                "_id": outputproc(result[1:] if len(result) > 2 else result[1]),
            }
            for result in self.db.execute(req.order_by(order).limit(topnbr))
        )

    def _features_port_list(self, flt, yieldall, use_service, use_product, use_version):
        # This is in SQLDBPassive because it **should** work with
        # SQLite. However, because ACCESS_TXT does not work well with
        # the result processor, it does not. This is a similar problem
        # than .topvalues() with JSON fields.
        flt = self.flt_and(flt, self.searchport(-1, neg=True))
        if use_version:
            fields = [
                self.tables.passive.port,
                self.tables.passive.moreinfo.op("->>")("service_name"),
                self.tables.passive.moreinfo.op("->>")("service_product"),
                self.tables.passive.moreinfo.op("->>")("service_version"),
            ]
        elif use_product:
            fields = [
                self.tables.passive.port,
                self.tables.passive.moreinfo.op("->>")("service_name"),
                self.tables.passive.moreinfo.op("->>")("service_product"),
            ]
        elif use_service:
            fields = [
                self.tables.passive.port,
                self.tables.passive.moreinfo.op("->>")("service_name"),
            ]
        else:
            fields = [self.tables.passive.port]
        req = flt.query(select(fields).group_by(*fields))
        if not yieldall:
            req = req.order_by(*(nullsfirst(fld) for fld in fields))
            return self.db.execute(req)
        # results will be modified, we cannot keep a RowProxy
        # instance, so we convert the results to lists
        return (list(rec) for rec in self.db.execute(req))

    @classmethod
    def searchnonexistent(cls):
        return PassiveFilter(main=False)

    @classmethod
    def _searchobjectid(cls, oid, neg=False):
        if len(oid) == 1:
            return PassiveFilter(
                main=(cls.tables.passive.id != oid[0])
                if neg
                else (cls.tables.passive.id == oid[0])
            )
        return PassiveFilter(
            main=(cls.tables.passive.id.notin_(oid[0]))
            if neg
            else (cls.tables.passive.id.in_(oid[0]))
        )

    @classmethod
    def searchcmp(cls, key, val, cmpop):
        if isinstance(key, str):
            key = cls.fields[key]
        return PassiveFilter(main=key.op(cmpop)(val))

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        addr = cls.ip2internal(addr)
        return PassiveFilter(
            main=(cls.tables.passive.addr != addr)
            if neg
            else (cls.tables.passive.addr == addr),
        )

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        hosts = [cls.ip2internal(host) for host in hosts]
        return PassiveFilter(
            main=(
                cls.tables.passive.addr.notin_(hosts)
                if neg
                else cls.tables.passive.addr.in_(hosts)
            ),
        )

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        start, stop = cls.ip2internal(start), cls.ip2internal(stop)
        if neg:
            return PassiveFilter(
                main=or_(
                    cls.tables.passive.addr < start, cls.tables.passive.addr > stop
                )
            )
        return PassiveFilter(
            main=and_(cls.tables.passive.addr >= start, cls.tables.passive.addr <= stop)
        )

    @classmethod
    def searchranges(cls, ranges, neg=False):
        """Filters (if `neg` == True, filters out) some IP address ranges.

        `ranges` is an instance of ivre.geoiputils.IPRanges().

        """
        flt = []
        for start, stop in ranges.iter_ranges():
            start, stop = cls.ip2internal(start), cls.ip2internal(stop)
            flt.append(
                (or_ if neg else and_)(
                    cls.tables.passive.addr >= start, cls.tables.passive.addr <= stop
                )
            )
        if flt:
            return PassiveFilter(main=(and_ if neg else or_)(*flt))
        return cls.flt_empty if neg else cls.searchnonexistent()

    @classmethod
    def searchrecontype(cls, rectype, neg=False):
        if isinstance(rectype, list):
            if neg:
                return PassiveFilter(
                    main=(cls.tables.passive.recontype.notin_(rectype))
                )
            return PassiveFilter(main=(cls.tables.passive.recontype.in_(rectype)))
        return PassiveFilter(
            main=cls._searchstring_re(cls.tables.passive.recontype, rectype, neg=neg)
        )

    @classmethod
    def searchdns(cls, name=None, reverse=False, dnstype=None, subdomains=False):
        if name is not None:
            if isinstance(name, list):
                if len(name) == 1:
                    name = name[0]
                else:
                    return cls.flt_or(
                        *(
                            cls._searchdns(
                                name=domain,
                                reverse=reverse,
                                dnstype=dnstype,
                                subdomains=subdomains,
                            )
                            for domain in name
                        )
                    )
        return cls._searchdns(
            name=name, reverse=reverse, dnstype=dnstype, subdomains=subdomains
        )

    @classmethod
    def _searchdns(cls, name=None, reverse=False, dnstype=None, subdomains=False):
        cnd = cls.tables.passive.recontype == "DNS_ANSWER"
        if name is not None:
            cnd &= (
                (
                    cls.tables.passive.moreinfo[
                        "domaintarget" if reverse else "domain"
                    ].has_key(  # noqa: W601
                        name
                    )
                )
                if subdomains
                else cls._searchstring_re(
                    cls.tables.passive.targetval
                    if reverse
                    else cls.tables.passive.value,
                    name,
                )
            )
        if dnstype is not None:
            cnd &= cls.tables.passive.source.op("~")("^%s-" % dnstype.upper())
        return PassiveFilter(main=cnd)

    @classmethod
    def searchmac(cls, mac=None, neg=False):
        if mac is None:
            if neg:
                return PassiveFilter(main=cls.tables.passive.recontype != "MAC_ADDRESS")
            return PassiveFilter(main=cls.tables.passive.recontype == "MAC_ADDRESS")
        value = cls.tables.passive.value
        if isinstance(mac, utils.REGEXP_T):
            cnd = value.op("~*")(mac.pattern)
            if neg:
                cnd = not_(cnd)
        elif neg:
            cnd = value != mac
        else:
            cnd = value == mac
        return PassiveFilter(main=(cls.tables.passive.recontype == "MAC_ADDRESS") & cnd)

    @classmethod
    def searchuseragent(cls, useragent=None, neg=False):
        if neg:
            raise ValueError(
                "searchuseragent([...], neg=True) is not " "supported in passive DB."
            )
        if useragent is None:
            return PassiveFilter(
                main=(
                    (cls.tables.passive.recontype == "HTTP_CLIENT_HEADER")
                    & (cls.tables.passive.source == "USER-AGENT")
                )
            )
        return PassiveFilter(
            main=(
                (cls.tables.passive.recontype == "HTTP_CLIENT_HEADER")
                & (cls.tables.passive.source == "USER-AGENT")
                & (cls._searchstring_re(cls.tables.passive.value, useragent))
            )
        )

    @classmethod
    def searchftpauth(cls):
        return PassiveFilter(
            main=(
                (cls.tables.passive.recontype == "FTP_CLIENT")
                | (cls.tables.passive.recontype == "FTP_SERVER")
            )
        )

    @classmethod
    def searchpopauth(cls):
        return PassiveFilter(
            main=(
                (cls.tables.passive.recontype == "POP_CLIENT")
                | (cls.tables.passive.recontype == "POP_SERVER")
            )
        )

    @classmethod
    def searchbasicauth(cls):
        return PassiveFilter(
            main=(
                (
                    (cls.tables.passive.recontype == "HTTP_CLIENT_HEADER")
                    | (cls.tables.passive.recontype == "HTTP_CLIENT_HEADER_SERVER")
                )
                & (
                    (cls.tables.passive.source == "AUTHORIZATION")
                    | (cls.tables.passive.source == "PROXY-AUTHORIZATION")
                )
                & cls.tables.passive.value.op("~*")("^Basic")
            )
        )

    @classmethod
    def searchhttpauth(cls):
        return PassiveFilter(
            main=(
                (
                    (cls.tables.passive.recontype == "HTTP_CLIENT_HEADER")
                    | (cls.tables.passive.recontype == "HTTP_CLIENT_HEADER_SERVER")
                )
                & (
                    (cls.tables.passive.source == "AUTHORIZATION")
                    | (cls.tables.passive.source == "PROXY-AUTHORIZATION")
                )
            )
        )

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
        res = (cls.tables.passive.recontype == "SSL_SERVER") & (
            cls.tables.passive.source == ("cacert" if cacert else "cert")
        )
        if keytype is not None:
            res &= (
                cls.tables.passive.moreinfo.op("->")("pubkey").op("->>")("type")
                == keytype
            )
        if md5 is not None:
            res &= cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->>")("md5"),
                md5.lower(),
            )
        if sha1 is not None:
            res &= cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->>")("sha1"),
                sha1.lower(),
            )
        if sha256 is not None:
            res &= cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->>")("sha256"),
                sha256.lower(),
            )
        if subject is not None:
            res &= cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->>")("subject_text"),
                subject,
            )
        if issuer is not None:
            res &= cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->>")("issuer_text"),
                issuer,
            )
        if self_signed is not None:
            res &= cls.tables.passive.self_signed == self_signed
        if pkmd5 is not None:
            res &= cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->")("pubkey").op("->>")("md5"),
                pkmd5.lower(),
            )
        if pksha1 is not None:
            res &= cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->")("pubkey").op("->>")("sha1"),
                pksha1.lower(),
            )
        if pksha256 is not None:
            res &= cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->")("pubkey").op("->>")("sha256"),
                pksha256.lower(),
            )
        return PassiveFilter(main=res)

    @classmethod
    def _searchja3(cls, value_or_hash=None):
        if not value_or_hash:
            return True
        key, value = cls._ja3keyvalue(value_or_hash)
        try:
            return {
                "md5": cls.tables.passive.value,
                "sha1": cls.tables.passive.moreinfo.op("->>")("sha1"),
                "sha256": cls.tables.passive.moreinfo.op("->>")("sha256"),
            }[key] == value
        except KeyError:
            return cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->>")("raw"),
                value,
            )

    @classmethod
    def searchja3client(cls, value_or_hash=None):
        return PassiveFilter(
            main=(
                (cls.tables.passive.recontype == "SSL_CLIENT")
                & (cls.tables.passive.source == "ja3")
                & cls._searchja3(value_or_hash)
            )
        )

    @classmethod
    def searchja3server(cls, value_or_hash=None, client_value_or_hash=None):
        base = (cls.tables.passive.recontype == "SSL_SERVER") & cls._searchja3(
            value_or_hash
        )
        if not client_value_or_hash:
            return PassiveFilter(
                main=(base & cls.tables.passive.source.op("~")("^ja3-"))
            )
        key, value = cls._ja3keyvalue(client_value_or_hash)
        if key == "md5":
            return PassiveFilter(
                main=(base & (cls.tables.passive.source == "ja3-%s" % value))
            )
        base &= cls.tables.passive.source.op("~")("^ja3-")
        if key in ["sha1", "sha256"]:
            return PassiveFilter(
                main=(
                    base
                    & (
                        cls.tables.passive.moreinfo.op("->")("client").op("->>")(key)
                        == value
                    )
                )
            )
        return PassiveFilter(
            main=(
                base
                & cls._searchstring_re(
                    cls.tables.passive.moreinfo.op("->")("client").op("->>")("raw"),
                    value,
                )
            )
        )

    @classmethod
    def searchsshkey(cls, keytype=None):
        if keytype is None:
            return PassiveFilter(
                main=(
                    (cls.tables.passive.recontype == "SSH_SERVER_HOSTKEY")
                    & (cls.tables.passive.source == "SSHv2")
                )
            )
        return PassiveFilter(
            main=(
                (cls.tables.passive.recontype == "SSH_SERVER_HOSTKEY")
                & (cls.tables.passive.source == "SSHv2")
                & (cls.tables.passive.moreinfo.op("->>")("algo") == "ssh-" + keytype)
            )
        )

    @classmethod
    def searchtcpsrvbanner(cls, banner):
        return PassiveFilter(
            main=(
                (cls.tables.passive.recontype == "TCP_SERVER_BANNER")
                & (cls._searchstring_re(cls.tables.passive.value, banner))
            )
        )

    @classmethod
    def searchsensor(cls, sensor, neg=False):
        return PassiveFilter(
            main=(cls._searchstring_re(cls.tables.passive.sensor, sensor, neg=neg)),
        )

    @classmethod
    def searchport(cls, port, protocol="tcp", state="open", neg=False):
        """Filters (if `neg` == True, filters out) records on the specified
        protocol/port.

        """
        if protocol != "tcp":
            raise ValueError("Protocols other than TCP are not supported " "in passive")
        if state != "open":
            raise ValueError("Only open ports can be found in passive")
        return PassiveFilter(
            main=(cls.tables.passive.port != port)
            if neg
            else (cls.tables.passive.port == port)
        )

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search a port with a particular service."""
        if srv is False:
            flt = [~cls.tables.passive.moreinfo.op("?")("service_name")]
        elif isinstance(srv, list):
            flt = [cls.tables.passive.moreinfo.op("->>")("service_name").in_(srv)]
        else:
            flt = [
                cls._searchstring_re(
                    cls.tables.passive.moreinfo.op("->>")("service_name"), srv
                )
            ]
        if port is not None:
            flt.append(cls.tables.passive.port == port)
        if protocol is not None and protocol != "tcp":
            raise ValueError("Protocols other than TCP are not supported " "in passive")
        return PassiveFilter(main=and_(*flt))

    @classmethod
    def searchproduct(
        cls, product=None, version=None, service=None, port=None, protocol=None
    ):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        flt = []
        if product is not None:
            if product is False:
                flt.append(~cls.tables.passive.moreinfo.op("?")("service_product"))
            elif isinstance(product, list):
                flt.append(
                    cls.tables.passive.moreinfo.op("->>")("service_product").in_(
                        product
                    )
                )
            else:
                flt.append(
                    cls._searchstring_re(
                        cls.tables.passive.moreinfo.op("->>")("service_product"),
                        product,
                    )
                )
        if version is not None:
            if version is False:
                flt.append(~cls.tables.passive.moreinfo.op("?")("service_version"))
            elif isinstance(version, list):
                flt.append(
                    cls.tables.passive.moreinfo.op("->>")("service_version").in_(
                        version
                    )
                )
            else:
                flt.append(
                    cls._searchstring_re(
                        cls.tables.passive.moreinfo.op("->>")("service_version"),
                        version,
                    )
                )
        if service is not None:
            if service is False:
                flt.append(~cls.tables.passive.moreinfo.op("?")("service_name"))
            elif isinstance(service, list):
                flt.append(
                    cls.tables.passive.moreinfo.op("->>")("service_name").in_(service)
                )
            else:
                flt.append(
                    cls._searchstring_re(
                        cls.tables.passive.moreinfo.op("->>")("service_name"),
                        service,
                    )
                )
        if port is not None:
            flt.append(cls.tables.passive.port == port)
        if protocol is not None:
            if protocol != "tcp":
                raise ValueError(
                    "Protocols other than TCP are not supported " "in passive"
                )
        return PassiveFilter(main=and_(*flt))

    @classmethod
    def searchsvchostname(cls, hostname):
        return PassiveFilter(
            main=cls._searchstring_re(
                cls.tables.passive.moreinfo.op("->>")("service_hostname"),
                hostname,
            )
        )

    @classmethod
    def searchtimeago(cls, delta, neg=False, new=True):
        field = cls.tables.passive.firstseen if new else cls.tables.passive.lastseen
        if not isinstance(delta, datetime.timedelta):
            delta = datetime.timedelta(seconds=delta)
        now = datetime.datetime.now()
        timestamp = now - delta
        return PassiveFilter(main=(field < timestamp if neg else field >= timestamp))

    @classmethod
    def searchnewer(cls, timestamp, neg=False, new=True):
        field = cls.tables.passive.firstseen if new else cls.tables.passive.lastseen
        timestamp = utils.all2datetime(timestamp)
        return PassiveFilter(main=(field <= timestamp if neg else field > timestamp))
