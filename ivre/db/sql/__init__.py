#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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


import codecs
from collections import namedtuple
import csv
import datetime
from functools import reduce
import json
import re


from builtins import int, range
from future.utils import viewitems, viewvalues
from past.builtins import basestring
from sqlalchemy import create_engine, desc, func, column, delete, \
    exists, join, select, update, and_, not_, or_


from ivre.db import DB, DBFlow, DBNmap, DBPassive
from ivre import config, utils, xmlnmap
from ivre.db.sql.tables import Association_Scan_Category, \
    Association_Scan_Hostname, Association_Scan_ScanFile, Category, Flow, \
    Hop, Hostname, Passive, Point, Port, Scan, ScanFile, Script, Trace


# Data

class CSVFile(object):
    """A file like object generating CSV lines suitable for use with
PostgresDB.copy_from(). Reads (at most `limit`, when it's not None)
lines from `fname`, skipping `skip` first lines.

When .read() returns the empty string, the attribute `.more_to_read`
is set to True when the `limit` has been reached, and to False when
there is no more data to read from the input.

    """

    def __init__(self, fname, skip=0, limit=None):
        self.fdesc = codecs.open(fname, encoding='latin-1')
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
                return ''
        try:
            line = None
            while line is None:
                line = self.fixline(next(self.inp))
            if self.limit is not None:
                self.count += 1
            return '%s\n' % '\t'.join(line)
        except StopIteration:
            self.more_to_read = False
            return ''

    def readline(self):
        return self.read()

    def __exit__(self, *args):
        if self.fdesc is not None:
            self.fdesc.__exit__(*args)

    def __enter__(self):
        return self


# Nmap

class ScanCSVFile(CSVFile):

    def __init__(self, hostgen, convert_ip, table, merge):
        self.convert_ip = convert_ip
        self.table = table
        self.inp = hostgen
        self.merge = merge
        self.fdesc = None

    def fixline(self, line):
        for field in ["cpes", "extraports", "openports", "os", "traces"]:
            line.pop(field, None)
        line["addr"] = self.convert_ip(line['addr'])
        scanfileid = line.pop('scanid')
        if isinstance(scanfileid, basestring):
            scanfileid = [scanfileid]
        line["scanfileid"] = '{%s}' % ','.join('"\\x%s"' % fid
                                               for fid in scanfileid)
        line["time_start"] = line.pop('starttime')
        line["time_stop"] = line.pop('endtime')
        line["info"] = line.pop('infos', None)
        line["archive"] = 0
        line["merge"] = False
        for field in ["categories"]:
            if field in line:
                line[field] = "{%s}" % json.dumps(line[field])[1:-1]
        for port in line.get('ports', []):
            for script in port.get('scripts', []):
                if 'masscan' in script and 'raw' in script['masscan']:
                    script['masscan']['raw'] = utils.encode_b64(
                        script['masscan']['raw']
                    )
            if 'screendata' in port:
                port['screendata'] = utils.encode_b64(port['screendata'])
        for field in ["hostnames", "ports", "info"]:
            if field in line:
                line[field] = json.dumps(line[field]).replace('\\', '\\\\')
        return ["\\N" if line.get(col.name) is None else
                str(line.get(col.name))
                for col in self.table.columns]


# Passive
class PassiveCSVFile(CSVFile):
    info_fields = set(["distance", "signature", "version"])

    def __init__(self, siggen, convert_ip, table, limit=None, getinfos=None,
                 separated_timestamps=True):
        self.convert_ip = convert_ip
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
            if isinstance(timestamp, datetime.datetime):
                line["firstseen"] = line["lastseen"] = timestamp
            else:
                line["firstseen"] = line["lastseen"] = (
                    datetime.datetime.fromtimestamp(timestamp)
                )
        else:
            if not isinstance(line["firstseen"], datetime.datetime):
                line["firstseen"] = datetime.datetime.fromtimestamp(
                    line["firstseen"]
                )
            if not isinstance(line["lastseen"], datetime.datetime):
                line["lastseen"] = datetime.datetime.fromtimestamp(
                    line["lastseen"]
                )
        if self.getinfos is not None:
            additional_info = self.getinfos(line)
            try:
                line.update(additional_info['infos'])
            except KeyError:
                pass
            try:
                line.update(additional_info['fullinfos'])
            except KeyError:
                pass
        if "addr" in line:
            line["addr"] = self.convert_ip(line["addr"])
        else:
            line["addr"] = None
        line.setdefault("count", 1)
        line.setdefault("port", 0)
        for key in ["sensor", "value", "source", "targetval"]:
            line.setdefault(key, "")
        for key, value in viewitems(line):
            if key not in ["info", "moreinfo"] and \
               isinstance(value, basestring):
                try:
                    value = value.encode('latin-1')
                except Exception:
                    pass
                line[key] = "".join(
                    c.decode() if b' ' <= c <= b'~' else
                    ('\\x%02x' % ord(c))
                    for c in (value[i:i + 1] for i in range(len(value)))
                ).replace('\\', '\\\\')
        line["info"] = "%s" % json.dumps(
            dict((key, line.pop(key)) for key in list(line)
                 if key in self.info_fields),
        ).replace('\\', '\\\\')
        line["moreinfo"] = "%s" % json.dumps(
            dict((key, line.pop(key)) for key in list(line)
                 if key not in self.table.columns),
        ).replace('\\', '\\\\')
        return ["\\N" if line.get(col.name) is None else
                str(line.get(col.name))
                for col in self.table.columns]


class SQLDB(DB):
    tables = []
    fields = {}

    def __init__(self, url):
        self.dburl = url

    @property
    def db(self):
        """The DB connection."""
        try:
            return self._db
        except AttributeError:
            # echo on debug disabled for tests
            self._db = create_engine(self.dburl, echo=config.DEBUG_DB)
            return self._db

    def drop(self):
        for table in reversed(self.tables):
            table.__table__.drop(bind=self.db, checkfirst=True)

    def create(self):
        for table in self.tables:
            table.__table__.create(bind=self.db, checkfirst=True)

    def init(self):
        self.drop()
        self.create()

    @staticmethod
    def convert_ip(addr):
        return utils.force_int2ip(addr)

    @staticmethod
    def to_binary(data):
        return utils.encode_b64(data).decode()

    @staticmethod
    def from_binary(data):
        return utils.decode_b64(data.encode())

    def flt2str(self, flt):
        result = {}
        for queryname, queries in viewitems(flt.all_queries):
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
            ts = utils.datetime2timestamp(date)
        else:
            ts = date
        ts = ts - (ts % config.FLOW_TIME_PRECISION)
        if isinstance(date, datetime.datetime):
            return datetime.datetime.fromtimestamp(ts)
        else:
            return ts

    @staticmethod
    def fmt_results(fields, result):
        return dict((fld, value) for fld, value in zip(fields, result)
                    if value is not None)

    @classmethod
    def searchobjectid(cls, oid, neg=False):
        """Filters records by their ObjectID.  `oid` can be a single or many
        (as a list or any iterable) object ID(s), specified as strings
        or an `ObjectID`s.

        """
        if isinstance(oid, (int, basestring)):
            oid = [int(oid)]
        else:
            oid = [int(oid) for oid in oid]
        return cls._searchobjectid(oid, neg=neg)

    @staticmethod
    def _searchobjectid(oid, neg=False):
        raise NotImplementedError()

    @staticmethod
    def _distinct_req(field, flt):
        return flt.query(
            select([field.distinct()]).select_from(flt.select_from)
        )

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None,
                 **kargs):
        """This method produces a generator of distinct values for a given
field.

        """
        if isinstance(field, basestring):
            field = self.fields[field]
        if flt is None:
            flt = self.flt_empty
        sort = [
            (self.fields[key] if isinstance(key, basestring) else key, way)
            for key, way in sort or []
        ]
        req = self._distinct_req(field, flt, **kargs)
        for key, way in sort:
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return (next(iter(viewvalues(res))) for res in self.db.execute(req))

    @staticmethod
    def _flt_and(flt1, flt2):
        return flt1 & flt2

    @staticmethod
    def _flt_or(flt1, flt2):
        return flt1 | flt2

    @classmethod
    def flt_and(cls, *args):
        """Returns a condition that is true iff all of the given
        conditions is true.

        """
        return reduce(cls._flt_and, args)

    @classmethod
    def flt_or(cls, *args):
        """Returns a condition that is true iff any of the given
        conditions is true.

        """
        return reduce(cls._flt_or, args)

    @staticmethod
    def _searchstring_re_inarray(idfield, field, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            if neg:
                # FIXME
                raise ValueError("Not implemented")
            operator = '~*' if (value.flags & re.IGNORECASE) else '~'
            value = value.pattern
            base1 = select([idfield.label('id'),
                            func.unnest(field).label('field')]).cte('base1')
            base2 = select([column('id')])\
                .select_from(base1)\
                .where(column('field').op(operator)(value))\
                .cte('base2')
            return idfield.in_(base2)
        return not_(field.any(value)) if neg else field.any(value)

    @staticmethod
    def _searchstring_re(field, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            flt = field.op(
                '~*' if (value.flags & re.IGNORECASE) else '~'
            )(value.pattern)
            if neg:
                return not_(flt)
            return flt
        if neg:
            return field != value
        return field == value

    @staticmethod
    def _searchstring_list(field, value, neg=False, map_=None):
        if not isinstance(value, basestring) and hasattr(value, '__iter__'):
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
    tables = [Flow]

    def __init__(self, url):
        DBFlow.__init__(self)
        SQLDB.__init__(self, url)

    @staticmethod
    def query(*args, **kargs):
        raise NotImplementedError()

    def add_flow(self, labels, keys, counters=None, accumulators=None,
                 srcnode=None, dstnode=None, time=True):
        raise NotImplementedError()

    @classmethod
    def add_host(cls, labels=None, keys=None, time=True):
        raise NotImplementedError()

    def add_flow_metadata(self, labels, linktype, keys, flow_keys,
                          counters=None, accumulators=None, time=True,
                          flow_labels=["Flow"]):
        raise NotImplementedError()

    def add_host_metadata(self, labels, linktype, keys, host_keys=None,
                          counters=None, accumulators=None, time=True):
        raise NotImplementedError()

    def host_details(self, node_id):
        raise NotImplementedError()

    def flow_details(self, node_id):
        raise NotImplementedError()

    def from_filters(self, filters, limit=None, skip=0, orderby="", mode=None,
                     timeline=False):
        raise NotImplementedError()

    def to_graph(self, query):
        raise NotImplementedError()

    def to_iter(self, query):
        raise NotImplementedError()

    def count(self, query):
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


class Filter(object):

    @staticmethod
    def fltand(flt1, flt2):
        return (flt1 if flt2 is None else
                flt2 if flt1 is None else and_(flt1, flt2))

    @staticmethod
    def fltor(flt1, flt2):
        return (flt1 if flt2 is None else
                flt2 if flt1 is None else or_(flt1, flt2))


class NmapFilter(Filter):

    def __init__(self, main=None, hostname=None, category=None, port=None,
                 script=None, trace=None):
        self.main = main
        self.hostname = [] if hostname is None else hostname
        self.category = [] if category is None else category
        self.port = [] if port is None else port
        self.script = [] if script is None else script
        self.trace = [] if trace is None else trace

    @property
    def all_queries(self):
        return {
            "main": self.main,
            "hostname": self.hostname,
            "category": self.category,
            "port": [elt[1] if elt[0] else not_(elt[1]) for elt in self.port],
            "script": self.script,
            "trace": self.trace,
        }

    def copy(self):
        return self.__class__(
            main=self.main,
            hostname=self.hostname[:],
            category=self.category[:],
            port=self.port[:],
            script=self.script[:],
            trace=self.trace[:],
        )

    def __and__(self, other):
        return self.__class__(
            main=self.fltand(self.main, other.main),
            hostname=self.hostname + other.hostname,
            category=self.category + other.category,
            port=self.port + other.port,
            script=self.script + other.script,
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
        return self.__class__(
            main=self.fltor(self.main, other.main),
            hostname=self.hostname + other.hostname,
            category=self.category + other.category,
            port=self.port + other.port,
            script=self.script + other.script,
            trace=self.trace + other.trace,
        )

    def select_from_base(self, base=Scan):
        if base in [Scan, Scan.__mapper__]:
            base = Scan
        else:
            base = join(Scan, base)
        return base

    @property
    def select_from(self):
        return self.select_from_base()

    def query(self, req, archive=False):
        # TODO: improve performances
        #   - use a materialized view for `Scan` with `archive == 0`?
        if self.main is not None:
            req = req.where(self.main)
        if archive:
            req = req.where(Scan.archive > 0)
        else:
            req = req.where(Scan.archive == 0)
        for incl, subflt in self.hostname:
            base = select([Hostname.scan]).where(subflt).cte("base")
            if incl:
                req = req.where(Scan.id.in_(base))
            else:
                req = req.where(Scan.id.notin_(base))
        # See <http://stackoverflow.com/q/17112345/3223422> - "Using
        # INTERSECT with tables from a WITH clause"
        for subflt in self.category:
            req = req.where(exists(
                select([1])
                .select_from(join(Category, Association_Scan_Category))
                .where(subflt)
                .where(Association_Scan_Category.scan == Scan.id)
            ))
        for incl, subflt in self.port:
            if incl:
                req = req.where(exists(
                    select([1])
                    .select_from(Port)
                    .where(subflt)
                    .where(Port.scan == Scan.id)
                ))
            else:
                base = select([Port.scan]).where(subflt).cte("base")
                req = req.where(Scan.id.notin_(base))
        for subflt in self.script:
            subreq = select([1]).select_from(join(Script, Port))
            if isinstance(subflt, tuple):
                for selectfrom in subflt[1]:
                    subreq = subreq.select_from(selectfrom)
                subreq = subreq.where(subflt[0])
            else:
                subreq = subreq.where(subflt)
            subreq = subreq.where(Port.scan == Scan.id)
            req = req.where(exists(subreq))
        for subflt in self.trace:
            req = req.where(exists(
                select([1])
                .select_from(join(Trace, Hop))
                .where(subflt)
                .where(Trace.scan == Scan.id)
            ))
        return req


class SQLDBNmap(SQLDB, DBNmap):
    tables = [ScanFile, Category, Scan, Hostname, Port, Script, Trace, Hop,
              Association_Scan_Hostname, Association_Scan_Category,
              Association_Scan_ScanFile]
    fields = {
        "_id": Scan.id,
        "addr": Scan.addr,
        "source": Scan.source,
        "scanid": Association_Scan_ScanFile.scan_file,
        "starttime": Scan.time_start,
        "endtime": Scan.time_stop,
        "infos": Scan.info,
        "state": Scan.state_reason_ttl,
        "state_reason": Scan.state_reason_ttl,
        "state_reason_ttl": Scan.state_reason_ttl,
        "categories": Category.name,
        "hostnames.name": Hostname.name,
        "hostnames.domains": Hostname.domains,
    }
    _needunwind_script = set([
        "http-headers",
    ])

    @classmethod
    def needunwind_script(cls, key):
        key = key.split('.')
        for i in range(len(key)):
            subkey = '.'.join(key[:i])
            if subkey in cls._needunwind_script:
                yield subkey

    def __init__(self, url):
        SQLDB.__init__(self, url)
        DBNmap.__init__(self)
        self.content_handler = xmlnmap.Nmap2DB
        self.output_function = None
        self.flt_empty = NmapFilter()
        self.bulk = None

    def is_scan_present(self, scanid):
        return bool(
            self.db.execute(
                select([True])
                .where(
                    ScanFile.sha256 == utils.decode_hex(
                        scanid
                    )
                )
                .limit(1)
            ).fetchone()
        )

    def store_host(self, host, merge=False):
        raise NotImplementedError()

    def store_or_merge_host(self, host, gettoarchive, merge=False):
        self.store_host(host, merge=merge)

    def migrate_schema(self, archive, version):
        """Migrates the scan data. When `archive` is True, do nothing (when
`archive` is False, migrate both archived and non-archived records;
this is to remain compatible with MongoDB API without impacting the
performances).

        """
        failed = 0
        if (version or 0) < 9:
            failed += self.__migrate_schema_8_9()
        if (version or 0) < 10:
            failed += self.__migrate_schema_9_10()
        return failed

    def __migrate_schema_8_9(self):
        """Converts records from version 8 to version 9. Version 9 creates a
structured output for http-headers script.

        """
        failed = []
        req = (select([Scan.id, Script.port, Script.output, Script.data])
               .select_from(join(join(Scan, Port), Script))
               .where(and_(Scan.schema_version == 8,
                           Script.name == "http-headers")))
        for rec in self.db.execute(req):
            if 'http-headers' not in rec.data:
                try:
                    data = xmlnmap.add_http_headers_data({
                        'id': "http-headers",
                        'output': rec.output
                    })
                except Exception:
                    utils.LOGGER.warning("Cannot migrate host %r", rec.id,
                                         exc_info=True)
                    failed.append(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(Script)
                            .where(and_(Script.port == rec.port,
                                        Script.name == "http-headers"))
                            .values(data={"http-headers": data})
                        )
        self.db.execute(
            update(Scan)
            .where(and_(Scan.schema_version == 8, Scan.id.notin_(failed)))
            .values(schema_version=9)
        )
        return len(failed)

    def __migrate_schema_9_10(self):
        """Converts a record from version 8 to version 9. Version 10 changes
the field names of the structured output for s7-info script.

        """
        failed = []
        req = (select([Scan.id, Script.port, Script.output, Script.data])
               .select_from(join(join(Scan, Port), Script))
               .where(and_(Scan.schema_version == 9,
                           Script.name == "s7-info")))
        for rec in self.db.execute(req):
            if 's7-info' in rec.data:
                try:
                    data = xmlnmap.change_s7_info_keys(rec.data['s7-info'])
                except Exception:
                    utils.LOGGER.warning("Cannot migrate host %r", rec.id,
                                         exc_info=True)
                    failed.append(rec.id)
                else:
                    if data:
                        self.db.execute(
                            update(Script)
                            .where(and_(Script.port == rec.port,
                                        Script.name == "s7-info"))
                            .values(data={"s7-info": data})
                        )
        self.db.execute(
            update(Scan)
            .where(and_(Scan.schema_version == 9, Scan.id.notin_(failed)))
            .values(schema_version=10)
        )
        return len(failed)

    def count(self, flt, archive=False, **_):
        return self.db.execute(
            flt.query(select([func.count()]), archive=archive)
            .select_from(flt.select_from)
        ).fetchone()[0]

    @staticmethod
    def _distinct_req(field, flt, archive=False):
        flt = flt.copy()
        return flt.query(
            select([field.distinct()]).select_from(
                flt.select_from_base(field.parent)
            ),
            archive=archive
        )

    def get_open_port_count(self, flt, archive=False, limit=None, skip=None):
        req = flt.query(select([Scan.id]), archive=archive)
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        base = req.cte("base")
        return (
            {"addr": rec[2], "starttime": rec[1],
             "openports": {"count": rec[0]}}
            for rec in
            self.db.execute(
                select([func.count(Port.id), Scan.time_start, Scan.addr])
                .select_from(join(Port, Scan))
                .where(Port.state == "open")
                .group_by(Scan.addr, Scan.time_start)
                .where(Scan.id.in_(base))
            )
        )

    def getlocations(self, flt, archive=False, limit=None, skip=None):
        req = flt.query(
            select([func.count(Scan.id), Scan.info['coordinates'].astext])
            .where(Scan.info.has_key('coordinates')),
            # noqa: W601 (BinaryExpression)
            archive=archive,
        )
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        return ({'_id': Point().result_processor(None, None)(rec[1])[::-1],
                 'count': rec[0]}
                for rec in
                self.db.execute(req.group_by(Scan.info['coordinates'].astext)))

    def get(self, flt, archive=False, limit=None, skip=None, sort=None,
            **kargs):
        req = flt.query(select([Scan]).select_from(flt.select_from),
                        archive=archive)
        for key, way in sort or []:
            if isinstance(key, basestring) and key in self.fields:
                key = self.fields[key]
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        for scanrec in self.db.execute(req):
            rec = {}
            (rec["_id"], rec["addr"], rec["source"], rec["infos"],
             rec["starttime"], rec["endtime"], rec["state"],
             rec["state_reason"], rec["state_reason_ttl"],
             rec["archive"], rec["merge"], rec["schema_version"]) = scanrec
            if rec["infos"]:
                if 'coordinates' in rec['infos']:
                    rec['infos']['loc'] = {
                        'type': 'Point',
                        'coordinates': rec['infos'].pop('coordinates')[::-1],
                    }
            else:
                del rec["infos"]
            categories = (select([Association_Scan_Category.category])
                          .where(Association_Scan_Category.scan == rec["_id"])
                          .cte("categories"))
            rec["categories"] = [
                cat[0] for cat in
                self.db.execute(
                    select([Category.name])
                    .where(Category.id == categories.c.category)
                )
            ]
            rec["scanid"] = [
                scanfile[0] for scanfile in self.db.execute(
                    select([Association_Scan_ScanFile.scan_file])
                    .where(Association_Scan_ScanFile.scan == rec["_id"]))
            ]
            for port in self.db.execute(select([Port])
                                        .where(Port.scan == rec["_id"])):
                recp = {}
                (portid, _, recp["port"], recp["protocol"],
                 recp["state_state"], recp["state_reason"],
                 recp["state_reason_ip"], recp["state_reason_ttl"],
                 recp["service_name"], recp["service_tunnel"],
                 recp["service_product"], recp["service_version"],
                 recp["service_conf"], recp["service_devicetype"],
                 recp["service_extrainfo"], recp["service_hostname"],
                 recp["service_ostype"], recp["service_servicefp"]) = port
                for fld, value in list(viewitems(recp)):
                    if value is None:
                        del recp[fld]
                for script in self.db.execute(select([Script.name,
                                                      Script.output,
                                                      Script.data])
                                              .where(Script.port == portid)):
                    recp.setdefault('scripts', []).append(
                        dict(id=script.name,
                             output=script.output,
                             **(script.data if script.data else {}))
                    )
                rec.setdefault('ports', []).append(recp)
            for trace in self.db.execute(select([Trace])
                                         .where(Trace.scan == rec["_id"])):
                curtrace = {}
                rec.setdefault('traces', []).append(curtrace)
                curtrace['port'] = trace['port']
                curtrace['protocol'] = trace['protocol']
                curtrace['hops'] = []
                for hop in self.db.execute(select([Hop])
                                           .where(Hop.trace == trace['id'])
                                           .order_by(Hop.ttl)):
                    curtrace['hops'].append(dict(
                        (key, hop[key]) for key in ['ipaddr', 'ttl', 'rtt',
                                                    'host', 'domains']
                    ))
            for hostname in self.db.execute(
                    select([Hostname])
                    .where(Hostname.scan == rec["_id"])
            ):
                rec.setdefault('hostnames', []).append(dict(
                    (key, hostname[key]) for key in ['name', 'type', 'domains']
                ))
            yield rec

    def remove(self, host, archive=False):
        """Removes the host scan result. "host" must be a record as yielded by
        .get() or a valid NmapFilter() instance.

        The scan files that are no longer linked to a scan are removed
        at the end of the call.

        """
        if isinstance(host, dict):
            base = [host['_id']]
        else:
            base = host.query(select([Scan.id]), archive=archive).cte("base")
        self.db.execute(delete(Scan).where(Scan.id.in_(base)))
        # remove unused scan files
        base = select([Association_Scan_ScanFile.scan_file]).cte('base')
        self.db.execute(delete(ScanFile).where(ScanFile.sha256.notin_(base)))

    _topstructure = namedtuple("topstructure", ["base", "fields", "where",
                                                "group_by", "extraselectfrom"])
    _topstructure.__new__.__defaults__ = (None,) * len(_topstructure._fields)

    @staticmethod
    def getscanids(host):
        return host['scanid']

    def getscan(self, scanid, archive=False):
        if isinstance(scanid, basestring) and len(scanid) == 64:
            scanid = utils.decode_hex(scanid)
        return self.db.execute(select([ScanFile])
                               .where(ScanFile.sha256 == scanid)).fetchone()

    @staticmethod
    def searchnonexistent():
        return NmapFilter(main=False)

    @staticmethod
    def _searchobjectid(oid, neg=False):
        if len(oid) == 1:
            return NmapFilter(main=(Scan.id != oid[0]) if neg else
                              (Scan.id == oid[0]))
        return NmapFilter(main=(Scan.id.notin_(oid[0])) if neg else
                          (Scan.id.in_(oid[0])))

    @classmethod
    def searchcmp(cls, key, val, cmpop):
        if isinstance(key, basestring):
            key = cls.fields[key]
        return NmapFilter(main=key.op(cmpop)(val))

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        if neg:
            return NmapFilter(main=Scan.addr != cls.convert_ip(addr))
        return NmapFilter(main=Scan.addr == cls.convert_ip(addr))

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        hosts = [cls.convert_ip(host) for host in hosts]
        if neg:
            return NmapFilter(main=Scan.addr.notin_(hosts))
        return NmapFilter(main=Scan.addr.in_(hosts))

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        start, stop = cls.convert_ip(start), cls.convert_ip(stop)
        if neg:
            return NmapFilter(main=or_(Scan.addr < start, Scan.addr > stop))
        return NmapFilter(main=and_(Scan.addr >= start, Scan.addr <= stop))

    @classmethod
    def searchdomain(cls, name, neg=False):
        return NmapFilter(hostname=[
            (not neg, cls._searchstring_re_inarray(Hostname.id,
                                                   Hostname.domains, name,
                                                   neg=False)),
        ])

    @classmethod
    def searchhostname(cls, name, neg=False):
        return NmapFilter(hostname=[
            (not neg, cls._searchstring_re(Hostname.name, name, neg=False)),
        ])

    @classmethod
    def searchcategory(cls, cat, neg=False):
        return NmapFilter(category=[cls._searchstring_re(Category.name, cat,
                                                         neg=neg)])

    @classmethod
    def searchsource(cls, src, neg=False):
        return NmapFilter(main=cls._searchstring_re(Scan.source, src,
                                                    neg=neg))

    @classmethod
    def searchcountry(cls, country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        country = utils.country_unalias(country)
        return NmapFilter(
            main=cls._searchstring_list(Scan.info['country_code'].astext,
                                        country, neg=neg)
        )

    @classmethod
    def searchcity(cls, city, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        city

        """
        return NmapFilter(
            main=cls._searchstring_re(Scan.info['city'].astext,
                                      city, neg=neg)
        )

    @classmethod
    def searchasnum(cls, asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        return NmapFilter(
            main=cls._searchstring_list(Scan.info['as_num'], asnum,
                                        neg=neg, map_=str)
        )

    @classmethod
    def searchasname(cls, asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        return NmapFilter(
            main=cls._searchstring_re(Scan.info['as_name'].astext, asname,
                                      neg=neg)
        )

    @staticmethod
    def searchport(port, protocol='tcp', state='open', neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        if port == "host":
            return NmapFilter(port=[
                (True, (Port.port >= 0) if neg else (Port.port == -1)),
            ])
        return NmapFilter(port=[
            (not neg,
             and_(Port.port == port,
                  Port.protocol == protocol,
                  Port.state == state)),
        ])

    @staticmethod
    def searchportsother(ports, protocol='tcp', state='open'):
        """Filters records with at least one port other than those
        listed in `ports` with state `state`.

        """
        return NmapFilter(port=[(True,
                                 and_(or_(Port.port.notin_(ports),
                                          Port.protocol != protocol),
                                      Port.state == state))])

    @classmethod
    def searchports(cls, ports, protocol='tcp', state='open', neg=False):
        return cls.flt_and(*(cls.searchport(port, protocol=protocol,
                                            state=state, neg=neg)
                             for port in ports))

    @staticmethod
    def searchcountopenports(minn=None, maxn=None, neg=False):
        "Filters records with open port number between minn and maxn"
        assert minn is not None or maxn is not None
        req = (select([column("scan")])
               .select_from(select([Port.scan.label("scan"),
                                    func.count().label("count")])
                            .where(Port.state == "open")
                            .group_by(Port.scan).alias("pcnt")))
        if minn == maxn:
            req = req.where(column("count") == minn)
        else:
            if minn is not None:
                req = req.where(column("count") >= minn)
            if maxn is not None:
                req = req.where(column("count") <= maxn)
        return NmapFilter(main=Scan.id.notin_(req) if neg else
                          Scan.id.in_(req))

    @staticmethod
    def searchopenport(neg=False):
        "Filters records with at least one open port."
        return NmapFilter(port=[(not neg, Port.state == "open")])

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        req = cls._searchstring_re(Port.service_name, srv)
        if port is not None:
            req = and_(req, Port.port == port)
        if protocol is not None:
            req = and_(req, Port.protocol == protocol)
        return NmapFilter(port=[(True, req)])

    @classmethod
    def searchproduct(cls, product, version=None, service=None, port=None,
                      protocol=None):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        req = cls._searchstring_re(Port.service_product, product)
        if version is not None:
            req = and_(req, cls._searchstring_re(Port.service_version,
                                                 version))
        if service is not None:
            req = and_(req, cls._searchstring_re(Port.service_name, service))
        if port is not None:
            req = and_(req, Port.port == port)
        if protocol is not None:
            req = and_(req, Port.protocol == protocol)
        return NmapFilter(port=[(True, req)])

    @classmethod
    def searchscript(cls, name=None, output=None, values=None):
        """Search a particular content in the scripts results.

        """
        req = True
        if name is not None:
            req = and_(req, cls._searchstring_re(Script.name, name, neg=False))
        if output is not None:
            req = and_(req, cls._searchstring_re(Script.output, output,
                                                 neg=False))
        if values:
            if name is None:
                raise TypeError(".searchscript() needs a `name` arg "
                                "when using a `values` arg")
            basekey = xmlnmap.ALIASES_TABLE_ELEMS.get(name, name)
            needunwind = sorted(set(
                unwind
                for subkey in values
                for unwind in cls.needunwind_script("%s.%s" % (basekey,
                                                               subkey))
            ))

            def _find_subkey(key):
                lastmatch = None
                key = key.split('.')
                for subkey in needunwind:
                    subkey = subkey.split('.')[1:]
                    if len(key) < len(subkey):
                        continue
                    if key == subkey:
                        return (".".join([basekey] + subkey), None)
                    if subkey == key[:len(subkey)]:
                        lastmatch = (".".join([basekey] + subkey),
                                     ".".join(key[len(subkey):]))
                return lastmatch

            def _to_json(key, value):
                key = key.split('.')
                result = value
                while key:
                    result = {key.pop(): result}
                return result
            for key, value in viewitems(values):
                subkey = _find_subkey(key)
                if subkey is None:
                    # XXX TEST THIS
                    req = and_(
                        req,
                        Script.data.contains(_to_json("%s.%s" % (basekey, key),
                                                      value)),
                    )
                elif subkey[1] is None:
                    # XXX TEST THIS
                    req = and_(
                        req,
                        column(
                            subkey[0].replace(".", "_").replace('-', '_')
                        ) == value,
                    )
                elif '.' in subkey[1]:
                    # XXX TEST THIS
                    firstpart, tail = subkey.split('.', 1)
                    req = and_(
                        req,
                        column(subkey[0].replace(".", "_").replace('-', '_'))
                        .op('->')(firstpart).contains(_to_json(tail))
                    )
                else:
                    req = and_(
                        req,
                        cls._searchstring_re(
                            column(
                                subkey[0].replace(".", "_").replace('-', '_')
                            ).op('->>')(subkey[1]),
                            value, neg=False,
                        )
                    )
            return NmapFilter(script=[(
                req,
                [func.jsonb_array_elements(Script.data[subkey]).alias(
                    subkey.replace('.', '_').replace('-', '_')
                ) for subkey in needunwind],
            )])
        return NmapFilter(script=[req])

    @classmethod
    def searchcert(cls, keytype=None):
        if keytype is None:
            return cls.searchscript(name="ssl-cert")
        return cls.searchscript(name="ssl-cert",
                                values={'pubkey': {'type': keytype}})

    @classmethod
    def searchsshkey(cls, keytype=None):
        if keytype is not None:
            utils.LOGGER.warning(
                "Cannot use keytype with PostgreSQL backend. "
                "Filter will return more results than expected"
            )
        return cls.searchscript(name="ssh-hostkey")

    @classmethod
    def searchsvchostname(cls, hostname):
        return NmapFilter(port=[(
            True, cls._searchstring_re(Port.service_hostname, hostname)
        )])

    @staticmethod
    def searchwebmin():
        return NmapFilter(
            port=[(True, and_(Port.service_name == 'http',
                              Port.service_product == 'MiniServ',
                              Port.service_extrainfo != 'Webmin httpd'))]
        )

    @staticmethod
    def searchx11():
        return NmapFilter(
            port=[(True, and_(Port.service_name == 'X11',
                              Port.service_extrainfo != 'access denied'))]
        )

    def searchtimerange(self, start, stop, neg=False):
        if not isinstance(start, datetime.datetime):
            start = datetime.datetime.fromtimestamp(start)
        if not isinstance(stop, datetime.datetime):
            stop = datetime.datetime.fromtimestamp(stop)
        if neg:
            return NmapFilter(
                main=(Scan.time_start < start) | (Scan.time_stop > stop)
            )
        return NmapFilter(
            main=(Scan.time_start >= start) & (Scan.time_stop <= stop)
        )

    @classmethod
    def searchfile(cls, fname=None, scripts=None):
        """Search shared files from a file name (either a string or a
        regexp), only from scripts using the "ls" NSE module.

        """
        if fname is None:
            req = Script.data.op('@>')('{"ls": {"volumes": [{"files": []}]}}')
        else:
            if isinstance(fname, utils.REGEXP_T):
                base1 = select([
                    Script.port,
                    func.jsonb_array_elements(
                        func.jsonb_array_elements(
                            Script.data['ls']['volumes']
                        ).op('->')('files')
                    ).op('->>')('filename').label('filename')])\
                    .where(Script.data.op('@>')(
                        '{"ls": {"volumes": [{"files": []}]}}'
                    ))\
                    .cte('base1')
                base2 = (select([column('port')])
                         .select_from(base1)
                         .where(column('filename').op(
                             '~*' if (fname.flags & re.IGNORECASE) else '~'
                         )(fname.pattern))
                         .cte('base2'))
                return NmapFilter(port=[(True, Port.id.in_(base2))])
            else:
                req = Script.data.op('@>')(json.dumps(
                    {"ls": {"volumes": [{"files": [{"filename": fname}]}]}}
                ))
        if scripts is None:
            return NmapFilter(script=[req])
        if isinstance(scripts, basestring):
            scripts = [scripts]
        if len(scripts) == 1:
            return NmapFilter(script=[and_(Script.name == scripts.pop(), req)])
        return NmapFilter(script=[and_(Script.name.in_(scripts), req)])

    @classmethod
    def searchhttptitle(cls, title):
        return NmapFilter(script=[
            Script.name.in_(['http-title', 'html-title']),
            cls._searchstring_re(Script.output, title),
        ])

    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        res = Hop.ipaddr == cls.convert_ip(hop)
        if ttl is not None:
            res &= Hop.ttl == ttl
        return NmapFilter(trace=[not_(res) if neg else res])

    @classmethod
    def searchhopdomain(cls, hop, neg=False):
        return NmapFilter(trace=[cls._searchstring_re_inarray(
            Hop.id, Hop.domains, hop, neg=neg
        )])

    @classmethod
    def searchhopname(cls, hop, neg=False):
        return NmapFilter(trace=[cls._searchstring_re(Hop.host,
                                                      hop, neg=neg)])

    @classmethod
    def searchdevicetype(cls, devtype):
        return NmapFilter(port=[
            (True, cls._searchstring_re(Port.service_devicetype, devtype))
        ])

    @staticmethod
    def searchnetdev():
        return NmapFilter(port=[(
            True,
            Port.service_devicetype.in_([
                'bridge',
                'broadband router',
                'firewall',
                'hub',
                'load balancer',
                'proxy server',
                'router',
                'switch',
                'WAP',
            ])
        )])

    @staticmethod
    def searchphonedev():
        return NmapFilter(port=[(
            True,
            Port.service_devicetype.in_([
                'PBX',
                'phone',
                'telecom-misc',
                'VoIP adapter',
                'VoIP phone',
            ])
        )])

    @staticmethod
    def searchldapanon():
        return NmapFilter(port=[(
            True, Port.service_extrainfo == 'Anonymous bind OK',
        )])

    @staticmethod
    def searchvsftpdbackdoor():
        return NmapFilter(port=[(
            True,
            and_(Port.protocol == 'tcp',
                 Port.state == 'open',
                 Port.service_product == 'vsftpd',
                 Port.service_version == '2.3.4')
        )])


class PassiveFilter(Filter):

    def __init__(self, main=None):
        self.main = main

    @property
    def all_queries(self):
        return {
            "main": self.main,
        }

    def __nonzero__(self):
        return self.main is not None

    def copy(self):
        return self.__class__(
            main=self.main,
        )

    def __and__(self, other):
        return self.__class__(
            main=self.fltand(self.main, other.main),
        )

    def __or__(self, other):
        return self.__class__(
            main=self.fltor(self.main, other.main),
        )

    @property
    def select_from(self):
        return Passive

    def query(self, req):
        if self.main is not None:
            req = req.where(self.main)
        return req


class SQLDBPassive(SQLDB, DBPassive):
    tables = [Passive]
    fields = {
        "_id": Passive.id,
        "addr": Passive.addr,
        "sensor": Passive.sensor,
        "count": Passive.count,
        "firstseen": Passive.firstseen,
        "lastseen": Passive.lastseen,
        "distance": Passive.info.op('->>')('distance'),
        "signature": Passive.info.op('->>')('signature'),
        "version": Passive.info.op('->>')('version'),
        "infos": Passive.moreinfo,
        "infos.domain": Passive.moreinfo.op('->>')('domain'),
        "infos.issuer": Passive.moreinfo.op('->>')('issuer'),
        "infos.md5": Passive.moreinfo.op('->>')('md5'),
        "infos.pubkeyalgo": Passive.moreinfo.op('->>')('pubkeyalgo'),
        "infos.sha1": Passive.moreinfo.op('->>')('sha1'),
        "infos.sha256": Passive.moreinfo.op('->>')('sha256'),
        "infos.subject": Passive.moreinfo.op('->>')('subject'),
        "infos.domaintarget": Passive.moreinfo.op('->>')('domaintarget'),
        "infos.username": Passive.moreinfo.op('->>')('username'),
        "infos.password": Passive.moreinfo.op('->>')('password'),
        "infos.service_name": Passive.moreinfo.op('->>')('service_name'),
        "infos.service_ostype": Passive.moreinfo.op('->>')('service_ostype'),
        "infos.service_product": Passive.moreinfo.op('->>')('service_product'),
        "infos.service_version": Passive.moreinfo.op('->>')('service_version'),
        "infos.service_extrainfo": Passive.moreinfo.op('->>')(
            'service_extrainfo'
        ),
        "port": Passive.port,
        "recontype": Passive.recontype,
        "source": Passive.source,
        "targetval": Passive.targetval,
        "value": Passive.value,
    }

    def __init__(self, url):
        SQLDB.__init__(self, url)
        DBPassive.__init__(self)
        self.flt_empty = PassiveFilter()

    def count(self, flt):
        return self.db.execute(
            flt.query(
                select([func.count()]).select_from(flt.select_from)
            )
        ).fetchone()[0]

    def remove(self, flt):
        base = flt.query(
            select([Passive.id]).select_from(flt.select_from)
        ).cte("base")
        self.db.execute(delete(Passive).where(Passive.id.in_(base)))

    def get(self, flt, limit=None, skip=None, sort=None):
        """Queries the passive database with the provided filter "flt", and
returns a generator.

        """
        req = flt.query(
            select([
                Passive.addr, Passive.sensor, Passive.count, Passive.firstseen,
                Passive.lastseen, Passive.port, Passive.recontype,
                Passive.source, Passive.targetval, Passive.value,
                Passive.fullvalue, Passive.info, Passive.moreinfo
            ]).select_from(flt.select_from)
        )
        for key, way in sort or []:
            req = req.order_by(key if way >= 0 else desc(key))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        for rec in self.db.execute(req):
            rec = dict((key, value) for key, value in viewitems(rec)
                       if value is not None)
            rec["infos"] = dict(rec.pop("info"), **rec.pop("moreinfo"))
            yield rec

    def get_one(self, flt, skip=None):
        """Queries the passive database with the provided filter "flt", and
returns the first result, or None if no result exists."""
        return next(self.get(flt, limit=1, skip=skip))

    def _insert_or_update(self, timestamp, values, lastseen=None):
        raise NotImplementedError()

    def insert_or_update(self, timestamp, spec, getinfos=None, lastseen=None):
        if spec is None:
            return
        if getinfos is not None:
            additional_info = getinfos(spec)
            try:
                spec.update(additional_info['infos'])
            except KeyError:
                pass
            try:
                spec.update(additional_info['fullinfos'])
            except KeyError:
                pass
        addr = spec.pop("addr", None)
        timestamp = datetime.datetime.fromtimestamp(timestamp)
        if lastseen is not None:
            lastseen = datetime.datetime.fromtimestamp(lastseen)
        if addr:
            addr = self.convert_ip(addr)
        otherfields = dict(
            (key, spec.pop(key, ""))
            for key in ["sensor", "source", "targetval", "value"]
        )
        info = dict(
            (key, spec.pop(key))
            for key in ["distance", "signature", "version"]
            if key in spec
        )
        vals = {
            'addr': addr,
            # sensor: otherfields
            'count': spec.pop("count", 1),
            'firstseen': timestamp,
            'lastseen': lastseen or timestamp,
            'port': spec.pop("port", 0),
            'recontype': spec.pop("recontype"),
            # source, targetval, value: otherfields
            'fullvalue': spec.pop("fullvalue", None),
            'info': info,
            'moreinfo': spec,
        }
        vals.update(otherfields)
        self._insert_or_update(timestamp, vals, lastseen=lastseen)

    def insert_or_update_bulk(self, specs, getinfos=None,
                              separated_timestamps=True):
        """Like `.insert_or_update()`, but `specs` parameter has to be an
        iterable of `(timestamp, spec)` (if `separated_timestamps` is
        True) or `spec` (if it is False) values. This will perform
        PostgreSQL COPY FROM inserts with the major drawback that the
        `getinfos` parameter will be called (if it is not `None`) for
        each spec, even when the spec already exists in the database
        and the call was hence unnecessary.

        It's up to you to decide whether having bulk insert is worth
        it or if you want to go with the regular `.insert_or_update()`
        method.

        """
        if separated_timestamps:
            for ts, spec in specs:
                self.insert_or_update(ts, spec, getinfos=getinfos)
        else:
            for spec in specs:
                timestamp = spec.pop("firstseen", None)
                lastseen = spec.pop("lastseen", None)
                self.insert_or_update(timestamp or lastseen, spec,
                                      getinfos=getinfos, lastseen=lastseen)

    def migrate_from_db(self, db, flt=None, limit=None, skip=None, sort=None):
        if flt is None:
            flt = db.flt_empty
        self.insert_or_update_bulk(db.get(flt, limit=limit, skip=skip,
                                          sort=sort),
                                   separated_timestamps=False, getinfos=None)

    def migrate_from_mongodb_backup(self, backupfdesc):
        """This function uses a MongoDB backup file as a source to feed the
passive table."""
        def _backupgen(fdesc):
            for line in fdesc:
                try:
                    line = line.decode()
                except AttributeError:
                    pass
                try:
                    line = json.loads(line)
                except ValueError:
                    utils.LOGGER.warning("ignoring line [%r]", line)
                    continue
                try:
                    del line['_id']
                except KeyError:
                    pass
                line.update(line.pop('infos', {}))
                line.update(line.pop('fullinfos', {}))
                for key, value in viewitems(line):
                    if isinstance(value, dict) and len(value) == 1 \
                       and "$numberLong" in value:
                        line[key] = int(value['$numberLong'])
                yield line
        self.insert_or_update_bulk(_backupgen(backupfdesc), getinfos=None,
                                   separated_timestamps=False)

    def topvalues(self, field, flt=None, topnbr=10, sort=None,
                  limit=None, skip=None, least=False, distinct=True):
        """This method makes use of the aggregation framework to
        produce top values for a given field.

        If `distinct` is True (default), the top values are computed
        by distinct events. If it is False, they are computed based on
        the "count" field.

        """
        if isinstance(field, basestring):
            field = self.fields[field]
        outputproc = None
        if flt is None:
            flt = PassiveFilter()
        order = "count" if least else desc("count")
        req = flt.query(
            select([(func.count() if distinct else func.sum(Passive.count))
                    .label("count"), field])
            .select_from(flt.select_from)
            .group_by(field)
        )
        if outputproc is None:
            outputproc = lambda val: val
        return (
            {"count": result[0],
             "_id": outputproc(result[1:] if len(result) > 2 else result[1])}
            for result in self.db.execute(req.order_by(order).limit(topnbr))
        )

    @staticmethod
    def _searchobjectid(oid, neg=False):
        if len(oid) == 1:
            return PassiveFilter(main=(Passive.id != oid[0]) if neg else
                                 (Passive.id == oid[0]))
        return PassiveFilter(main=(Passive.id.notin_(oid[0])) if neg else
                             (Passive.id.in_(oid[0])))

    @classmethod
    def searchcmp(cls, key, val, cmpop):
        if isinstance(key, basestring):
            key = cls.fields[key]
        return PassiveFilter(main=key.op(cmpop)(val))

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        addr = cls.convert_ip(addr)
        return PassiveFilter(
            main=(Passive.addr != addr) if neg else (Passive.addr == addr),
        )

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        hosts = [cls.convert_ip(host) for host in hosts]
        return PassiveFilter(
            main=(Passive.addr.notin_(hosts) if neg else
                  Passive.addr.in_(hosts)),
        )

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        start, stop = cls.convert_ip(start), cls.convert_ip(stop)
        if neg:
            return PassiveFilter(main=or_(Passive.addr < start,
                                          Passive.addr > stop))
        return PassiveFilter(main=and_(Passive.addr >= start,
                                       Passive.addr <= stop))

    @staticmethod
    def searchrecontype(rectype):
        return PassiveFilter(main=(Passive.recontype == rectype))

    @classmethod
    def searchdns(cls, name, reverse=False, subdomains=False):
        return PassiveFilter(main=(
            (Passive.recontype == 'DNS_ANSWER') &
            (
                (Passive.moreinfo['domaintarget'
                                  if reverse else
                                  'domain'].has_key(name))
                # noqa: W601 (BinaryExpression)
                if subdomains else
                cls._searchstring_re(Passive.targetval
                                     if reverse else Passive.value, name)
            )
        ))

    @classmethod
    def searchuseragent(cls, useragent):
        return PassiveFilter(main=(
            (Passive.recontype == 'HTTP_CLIENT_HEADER') &
            (Passive.source == 'USER-AGENT') &
            (cls._searchstring_re(Passive.value, useragent))
        ))

    @staticmethod
    def searchftpauth():
        return PassiveFilter(main=(
            (Passive.recontype == 'FTP_CLIENT') |
            (Passive.recontype == 'FTP_SERVER')
        ))

    @staticmethod
    def searchpopauth():
        return PassiveFilter(main=(
            (Passive.recontype == 'POP_CLIENT') |
            (Passive.recontype == 'POP_SERVER')
        ))

    @staticmethod
    def searchbasicauth():
        return PassiveFilter(main=(
            ((Passive.recontype == 'HTTP_CLIENT_HEADER') |
             (Passive.recontype == 'HTTP_CLIENT_HEADER_SERVER')) &
            ((Passive.source == 'AUTHORIZATION') |
             (Passive.source == 'PROXY-AUTHORIZATION')) &
            Passive.value.op('~*')('^Basic')
        ))

    @staticmethod
    def searchhttpauth():
        return PassiveFilter(main=(
            ((Passive.recontype == 'HTTP_CLIENT_HEADER') |
             (Passive.recontype == 'HTTP_CLIENT_HEADER_SERVER')) &
            ((Passive.source == 'AUTHORIZATION') |
             (Passive.source == 'PROXY-AUTHORIZATION'))
        ))

    @staticmethod
    def searchcert(keytype=None):
        if keytype is None:
            return PassiveFilter(main=(
                (Passive.recontype == 'SSL_SERVER') &
                (Passive.source == 'cert')
            ))
        return PassiveFilter(main=(
            (Passive.recontype == 'SSL_SERVER') &
            (Passive.source == 'cert') &
            (Passive.moreinfo.op('->>')(
                'pubkeyalgo'
            ) == keytype + 'Encryption')
        ))

    @classmethod
    def searchcertsubject(cls, expr):
        return PassiveFilter(main=(
            (Passive.recontype == 'SSL_SERVER') &
            (Passive.source == 'cert') &
            (cls._searchstring_re(Passive.moreinfo.op('->>')('subject'), expr))
        ))

    @classmethod
    def searchcertissuer(cls, expr):
        return PassiveFilter(main=(
            (Passive.recontype == 'SSL_SERVER') &
            (Passive.source == 'cert') &
            (cls._searchstring_re(Passive.moreinfo.op('->>')('issuer'), expr))
        ))

    @classmethod
    def searchsshkey(cls, keytype=None):
        if keytype is None:
            return PassiveFilter(main=(
                (Passive.recontype == 'SSH_SERVER_HOSTKEY') &
                (Passive.source == 'SSHv2')
            ))
        return PassiveFilter(main=(
            (Passive.recontype == 'SSH_SERVER_HOSTKEY') &
            (Passive.source == 'SSHv2') &
            (Passive.moreinfo.op('->>')('algo') == 'ssh-' + keytype)
        ))

    @classmethod
    def searchtcpsrvbanner(cls, banner):
        return PassiveFilter(main=(
            (Passive.recontype == 'TCP_SERVER_BANNER') &
            (cls._searchstring_re(Passive.value, banner))
        ))

    @classmethod
    def searchsensor(cls, sensor, neg=False):
        return PassiveFilter(
            main=(cls._searchstring_re(Passive.sensor, sensor, neg=neg)),
        )

    @staticmethod
    def searchport(port, protocol='tcp', state='open', neg=False):
        """Filters (if `neg` == True, filters out) records on the specified
        protocol/port.

        """
        if protocol != 'tcp':
            raise ValueError("Protocols other than TCP are not supported "
                             "in passive")
        if state != 'open':
            raise ValueError("Only open ports can be found in passive")
        return PassiveFilter(main=(Passive.port != port)
                             if neg else (Passive.port == port))

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search a port with a particular service."""
        flt = [cls._searchstring_re(Passive.moreinfo.op('->>')('service_name'),
                                    srv)]
        if port is not None:
            flt.append(Passive.port == port)
        if protocol is not None and protocol != 'tcp':
            raise ValueError("Protocols other than TCP are not supported "
                             "in passive")
        return PassiveFilter(main=and_(*flt))

    @classmethod
    def searchproduct(cls, product, version=None, service=None, port=None,
                      protocol=None):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        flt = [
            cls._searchstring_re(Passive.moreinfo.op('->>')('service_product'),
                                 product)
        ]
        if version is not None:
            flt.append(
                cls._searchstring_re(
                    Passive.moreinfo.op('->>')('service_version'), version,
                )
            )
        if service is not None:
            flt.append(
                cls._searchstring_re(
                    Passive.moreinfo.op('->>')('service_name'), service,
                )
            )
        if port is not None:
            flt.append(Passive.port == port)
        if protocol is not None:
            if protocol != 'tcp':
                raise ValueError("Protocols other than TCP are not supported "
                                 "in passive")
        return PassiveFilter(main=and_(*flt))

    @classmethod
    def searchsvchostname(cls, hostname):
        return PassiveFilter(
            main=cls._searchstring_re(
                Passive.moreinfo.op('->>')(
                    'service_hostname'
                ),
                hostname,
            )
        )

    @staticmethod
    def searchtimeago(delta, neg=False, new=False):
        field = Passive.lastseen if new else Passive.firstseen
        if not isinstance(delta, datetime.timedelta):
            delta = datetime.timedelta(seconds=delta)
        now = datetime.datetime.now()
        timestamp = now - delta
        return PassiveFilter(main=(field < timestamp if neg else
                                   field >= timestamp))

    @staticmethod
    def searchnewer(timestamp, neg=False, new=False):
        field = Passive.lastseen if new else Passive.firstseen
        if not isinstance(timestamp, datetime.datetime):
            timestamp = datetime.datetime.fromtimestamp(timestamp)
        return PassiveFilter(main=(field <= timestamp if neg else
                                   field > timestamp))
