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

"""This sub-module contains functions to interact with TinyDB
databases.

"""


# Tests like "expr == None" should be used for QueryInstance instances
# pylint: disable=singleton-comparison


from collections import defaultdict, Counter
from copy import deepcopy
from datetime import datetime, time, timedelta
from functools import cmp_to_key
from itertools import product as cartesian_prod
import operator
import os
import re
import socket
import struct
from uuid import uuid1, UUID


from tinydb import TinyDB as TDB, Query
from tinydb.database import Document
from tinydb.operations import add, increment


from ivre.active.data import ALIASES_TABLE_ELEMS
from ivre.db import (
    DB,
    DBActive,
    DBAgent,
    DBNmap,
    DBPassive,
    DBView,
    DBFlow,
    DBFlowMeta,
    LockError,
)
from ivre import config
from ivre import flow
from ivre import utils
from ivre.xmlnmap import Nmap2DB


try:
    EMPTY_QUERY = Query().noop()
except TypeError:
    EMPTY_QUERY = Query()


class TinyDB(DB):

    """A DB using TinyDB backend"""

    flt_empty = EMPTY_QUERY
    no_limit = None

    def __init__(self, url):
        super().__init__()
        self.basepath = url.path
        utils.makedirs(self.basepath)

    @property
    def db(self):
        """The DB"""
        try:
            return self._db
        except AttributeError:
            self._db = TDB(os.path.join(self.basepath, "%s.json" % self.dbname))
            return self._db

    def invalidate_cache(self):
        try:
            self._db.close()
        except AttributeError:
            pass
        else:
            del self._db

    def init(self):
        try:
            self.db.drop_tables()
        except AttributeError:
            # TinyDB < 4
            self.db.purge_tables()

    def get(self, *args, **kargs):
        return list(self._get(*args, **kargs))

    def count(self, flt):
        return self.db.count(flt)

    def _db_get(self, flt, fields=None, sort=None, limit=None, skip=None):
        result = self.db.search(flt)
        if fields is not None:

            _fields = {}
            for fld in fields:
                try:
                    flds, lastfld = fld.rsplit(".", 1)
                except ValueError:
                    _fields[fld] = True
                else:
                    cur = _fields
                    for subfld in flds.split("."):
                        cur = cur.setdefault(subfld, {})
                    cur[lastfld] = True
            fields = _fields

            def _extractor(rec, wanted_fields, base=""):
                if isinstance(rec, Document):
                    res = Document({}, doc_id=rec.doc_id)
                else:
                    res = {}
                for fld, value in wanted_fields.items():
                    if fld not in rec:
                        continue
                    if value is True:
                        res[fld] = rec[fld]
                        continue
                    if base:
                        fullfld = "%s.%s" % (base, fld)
                    else:
                        fullfld = fld
                    if fullfld in self.list_fields:
                        res[fld] = [
                            _extractor(subrec, value, base=fullfld)
                            for subrec in rec[fld]
                        ]
                    else:
                        res[fld] = _extractor(rec[fld], value, base=fullfld)
                return res

        if not sort:
            if skip is not None:
                result = result[skip:]
            if limit is not None:
                result = result[:limit]
            if fields is not None:
                return [_extractor(rec, fields) for rec in result]
            return result

        def _cmp(v1, v2):
            for (k, o) in sort:
                f1 = v1
                f2 = v2
                for sk in k.split("."):
                    f1 = (f1 or {}).get(sk)
                    f2 = (f2 or {}).get(sk)
                if f1 == f2:
                    continue
                if f1 is None:
                    # None is lower than anything
                    return -o
                if f2 is None:
                    return o
                if f1 < f2:
                    return -o
                return o
            return 0

        result = sorted(result, key=cmp_to_key(_cmp))
        if skip is not None:
            result = result[skip:]
        if limit is not None:
            result = result[:limit]
        if fields is not None:
            return [_extractor(rec, fields) for rec in result]
        return result

    @staticmethod
    def _searchstring_re_inarray(query, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            res = query.test(lambda val: any(value.search(subval) for subval in val))
        else:
            res = query.any([value])
        if neg:
            return ~res
        return res

    @staticmethod
    def _searchstring_re(query, value, neg=False):
        if isinstance(value, utils.REGEXP_T):
            res = query.search(value.pattern, flags=value.flags)
            if neg:
                return ~res
            return res
        if neg:
            return query != value
        return query == value

    @classmethod
    def _generate_field_values(
        cls, record, field, base="", countfield=None, countval=None
    ):
        try:
            cur, field = field.split(".", 1)
        except ValueError:
            if field not in record:
                return
            if base:
                fullfield = "%s.%s" % (base, field)
            else:
                fullfield = field
            if fullfield in cls.list_fields or (
                # Hack: this field may or may not be a list (this
                # needs to be changed in a near future)
                fullfield == "scanid"
                and isinstance(record[field], list)
            ):
                for val in record[field]:
                    if countval is not None:
                        yield val, countval
                    elif countfield is not None:
                        yield val, record.get(countfield, 1)
                    else:
                        yield val
            elif countval is not None:
                yield record[field], countval
            elif countfield is not None:
                yield record[field], record.get(countfield, 1)
            else:
                yield record[field]
            return
        if cur not in record:
            return
        if countfield is not None:
            if countfield.startswith("%s." % cur):
                countfield = countfield.split(".", 1)[1]
            else:
                countval = record.get(countfield, 1)
                countfield = None
        record = record[cur]
        if base:
            base = "%s.%s" % (base, cur)
        else:
            base = cur
        if base in cls.list_fields:
            for subrec in record:
                for val in cls._generate_field_values(
                    subrec, field, base=base, countfield=countfield, countval=countval
                ):
                    yield val
        else:
            for val in cls._generate_field_values(
                record, field, base=base, countfield=countfield, countval=countval
            ):
                yield val

    def _search_field_exists(self, field, base="", baseq=None):
        if baseq is None:
            baseq = Query()
        if "." not in field:
            return getattr(baseq, field).exists()
        field, nextfields = field.split(".", 1)
        if base:
            fullfield = "%s.%s" % (base, field)
        else:
            fullfield = field
        if fullfield in self.list_fields:
            return getattr(baseq, field).any(
                self._search_field_exists(nextfields, base=fullfield)
            )
        return self._search_field_exists(
            nextfields, base=fullfield, baseq=getattr(baseq, field)
        )

    def distinct(self, field, flt=None, sort=None, limit=None, skip=None):
        if flt is None:
            flt = self.flt_empty
        flt &= self._search_field_exists(field)
        return list(
            set(
                val
                for rec in self._get(
                    flt, sort=sort, limit=limit, skip=skip, fields=[field]
                )
                for val in self._generate_field_values(rec, field)
            )
        )

    def remove(self, rec):
        """Removes the record from the active column. `rec` must be the record
        as returned by `.get()` or the record id.

        """
        if isinstance(rec, dict):
            rec = rec["_id"]
        self.db.remove(cond=Query()._id == rec)

    def remove_many(self, flt):
        """Removes the record from the active column. `flt` must be a valid
        filter.

        """
        self.db.remove(cond=flt)

    @staticmethod
    def str2id(string):
        return int(string)

    @staticmethod
    def to_binary(data):
        return utils.encode_b64(data).decode()

    @staticmethod
    def from_binary(data):
        return utils.decode_b64(data.encode())

    @staticmethod
    def ip2internal(addr):
        if isinstance(addr, int):
            return addr
        val1, val2 = struct.unpack("!QQ", utils.ip2bin(addr))
        return (val1 << 64) + val2

    @staticmethod
    def internal2ip(addr):
        return utils.bin2ip(struct.pack("!QQ", addr >> 64, addr & 0xFFFFFFFFFFFFFFFF))

    @staticmethod
    def flt2str(flt):
        return str(flt)

    @staticmethod
    def _flt_and(cond1, cond2):
        return cond1 & cond2

    @staticmethod
    def _flt_or(cond1, cond2):
        return cond1 | cond2

    @staticmethod
    def searchnonexistent():
        return Query()._id == 0

    @staticmethod
    def searchobjectid(oid, neg=False):
        """Filters records by their ObjectID.  `oid` can be a single or many
        (as a list or any iterable) object ID(s), specified as strings.

        """
        q = Query()
        if isinstance(oid, list):
            res = q._id.one_of(oid)
            if neg:
                return ~res
            return res
        if neg:
            return q._id != oid
        return q._id == oid

    @staticmethod
    def searchversion(version):
        """Filters documents based on their schema's version."""
        q = Query()
        if version is None:
            return q.schema_version.exists()
        return q.schema_version == version

    @classmethod
    def searchhost(cls, addr, neg=False):
        """Filters (if `neg` == True, filters out) one particular host
        (IP address).

        """
        q = Query()
        addr = cls.ip2internal(addr)
        if neg:
            return q.addr != addr
        return q.addr == addr

    @classmethod
    def searchhosts(cls, hosts, neg=False):
        res = Query().addr.one_of([cls.ip2internal(addr) for addr in hosts])
        if neg:
            return ~res
        return res

    @classmethod
    def searchrange(cls, start, stop, neg=False):
        start = cls.ip2internal(start)
        stop = cls.ip2internal(stop)
        q = Query()
        res = (q.addr >= start) & (q.addr <= stop)
        if neg:
            return ~res
        return res

    @staticmethod
    def searchval(key, val):
        return getattr(Query(), key) == val

    @staticmethod
    def searchcmp(key, val, cmpop):
        q = getattr(Query(), key)
        if cmpop == "<":
            return q < val
        if cmpop == "<=":
            return q <= val
        if cmpop == ">":
            return q > val
        if cmpop == ">=":
            return q >= val
        raise Exception(
            "Unknown operator %r (for key %r and val %r)"
            % (
                cmpop,
                key,
                val,
            )
        )


class TinyDBActive(TinyDB, DBActive):

    """An Active-specific DB using TinyDB backend

    This will be used by TinyDBNmap & TinyDBView

    """

    def _get(self, *args, **kargs):
        for host in self._db_get(*args, **kargs):
            host = deepcopy(host)
            try:
                host["addr"] = self.internal2ip(host["addr"])
            except (KeyError, socket.error):
                pass
            for port in host.get("ports", []):
                try:
                    port["state_reason_ip"] = self.internal2ip(port["state_reason_ip"])
                except (KeyError, socket.error):
                    pass
                for script in port.get("scripts", []):
                    for cert in script.get("ssl-cert", []):
                        for fld in ["not_before", "not_after"]:
                            try:
                                cert[fld] = utils.all2datetime(cert[fld])
                            except KeyError:
                                pass
            for trace in host.get("traces", []):
                for hop in trace.get("hops", []):
                    try:
                        hop["ipaddr"] = self.internal2ip(hop["ipaddr"])
                    except (KeyError, socket.error):
                        pass
            for fld in ["starttime", "endtime"]:
                try:
                    host[fld] = utils.all2datetime(host[fld])
                except KeyError:
                    pass
            yield host

    def store_host(self, host):
        # `host` may be an instance of Document, and have its own
        # doc_id: convert it to a dict instance instead.
        host = deepcopy(dict(host))
        try:
            host["scanid"] = [host["scanid"].decode()]
        except KeyError:
            pass
        try:
            host["addr"] = self.ip2internal(host["addr"])
        except (KeyError, ValueError):
            pass
        for port in host.get("ports", []):
            if "state_reason_ip" in port:
                try:
                    port["state_reason_ip"] = self.ip2internal(port["state_reason_ip"])
                except ValueError:
                    pass
            for script in port.get("scripts", []):
                for cert in script.get("ssl-cert", []):
                    for fld in ["not_before", "not_after"]:
                        if fld not in cert:
                            continue
                        if isinstance(cert[fld], datetime):
                            cert[fld] = cert[fld].timestamp()
                        elif isinstance(cert[fld], str):
                            cert[fld] = utils.all2datetime(cert[fld]).timestamp()
        for trace in host.get("traces", []):
            for hop in trace.get("hops", []):
                if "ipaddr" in hop:
                    try:
                        hop["ipaddr"] = self.ip2internal(hop["ipaddr"])
                    except ValueError:
                        pass
        for fld in ["starttime", "endtime"]:
            if fld not in host:
                continue
            if isinstance(host[fld], datetime):
                host[fld] = host[fld].timestamp()
            elif isinstance(host[fld], str):
                host[fld] = utils.all2datetime(host[fld]).timestamp()
        if "_id" not in host:
            _id = host["_id"] = str(uuid1())
        self.db.insert(host)
        utils.LOGGER.debug("HOST STORED: %r in %r", _id, self.dbname)
        return _id

    @staticmethod
    def getscanids(host):
        return host.get("scanid", [])

    @classmethod
    def searchdomain(cls, name, neg=False):
        q = Query()
        res = q.hostnames.any(cls._searchstring_re_inarray(q.domains, name))
        if neg:
            return ~res
        return res

    @classmethod
    def searchhostname(cls, name, neg=False):
        q = Query()
        res = q.hostnames.any(cls._searchstring_re(q.name, name))
        if neg:
            return ~res
        return res

    @classmethod
    def searchmac(cls, mac=None, neg=False):
        q_mac = Query().addresses.mac
        if mac is not None:
            if isinstance(mac, utils.REGEXP_T):
                mac = re.compile(mac.pattern, mac.flags | re.I)
            else:
                mac = mac.lower()
            return cls._searchstring_re(q_mac, mac, neg=neg)
        res = q_mac.exists()
        if neg:
            return ~res
        return res

    @classmethod
    def searchcategory(cls, cat, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular category
        (records may have zero, one or more categories).
        """
        return cls._searchstring_re_inarray(Query().categories, cat, neg=neg)

    @staticmethod
    def searchcountry(country, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        country, or a list of countries.

        """
        q = Query()
        country = utils.country_unalias(country)
        if isinstance(country, list):
            res = q.infos.country_code.one_of(country)
            if neg:
                return ~res
            return res
        if neg:
            return q.infos.country_code != country
        return q.infos.country_code == country

    @classmethod
    def searchcity(cls, city, neg=False):
        """
        Filters (if `neg` == True, filters out) one particular city.
        """
        return cls._searchstring_re(Query().infos.city, city, neg=neg)

    @staticmethod
    def searchhaslocation(neg=False):
        res = Query().infos.coordinates.exists()
        if neg:
            return ~res
        return res

    @staticmethod
    def searchasnum(asnum, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS number(s).

        """
        q = Query()
        if not isinstance(asnum, str) and hasattr(asnum, "__iter__"):
            res = q.infos.as_num.one_of([int(val) for val in asnum])
            if neg:
                return ~res
            return res
        asnum = int(asnum)
        if neg:
            return q.infos.as_num != asnum
        return q.infos.as_num == asnum

    @classmethod
    def searchasname(cls, asname, neg=False):
        """Filters (if `neg` == True, filters out) one or more
        particular AS.

        """
        return cls._searchstring_re(Query().infos.as_num, asname, neg=neg)

    @classmethod
    def searchsource(cls, src, neg=False):
        """Filters (if `neg` == True, filters out) one particular
        source.

        """
        q = Query()
        if isinstance(src, list):
            res = q.source.one_of(src)
            if neg:
                return ~res
            return res
        return cls._searchstring_re(q.source, src, neg=neg)

    @staticmethod
    def searchport(port, protocol="tcp", state="open", neg=False):
        """Filters (if `neg` == True, filters out) records with
        specified protocol/port at required state. Be aware that when
        a host has a lot of ports filtered or closed, it will not
        report all of them, but only a summary, and thus the filter
        might not work as expected. This filter will always work to
        find open ports.

        """
        q = Query()
        if port == "host":
            res = (q.port > 0) if neg else (q.port == -1)
        else:
            res = (q.port == port) & (q.protocol == protocol)
            if neg:
                return q.ports.any(res & (q.state_state != state)) | q.ports.all(~res)
            res &= q.state_state == state
        return q.ports.any(res)

    @staticmethod
    def searchportsother(ports, protocol="tcp", state="open"):
        """Filters records with at least one port other than those
        listed in `ports` with state `state`.

        """
        q = Query()
        return q.ports.any(
            q.protocol == protocol & q.state_state == state & ~q.port.one_of(ports)
        )

    @classmethod
    def searchports(cls, ports, protocol="tcp", state="open", neg=False, any_=False):
        res = [
            cls.searchport(port=port, protocol=protocol, state=state) for port in ports
        ]
        if any_:
            if neg:
                raise ValueError("searchports: cannot set both neg and any_")
            return cls.flt_or(*res)
        if neg:
            # pylint: disable=invalid-unary-operand-type
            return ~cls.flt_or(*res)
        return cls.flt_and(*res)

    @classmethod
    def searchcountopenports(cls, minn=None, maxn=None, neg=False):
        "Filters records with open port number between minn and maxn"
        assert minn is not None or maxn is not None
        res = []
        q = Query()
        if minn == maxn:
            if neg:
                return q.openports.count != minn
            return q.openports.count == minn
        if minn is not None:
            if neg:
                res.append(q.openports.count < minn)
            else:
                res.append(q.openports.count >= minn)
        if maxn is not None:
            if neg:
                res.append(q.openports.count > maxn)
            else:
                res.append(q.openports.count <= maxn)
        if neg:
            return cls.flt_or(*res)
        return cls.flt_and(*res)

    @staticmethod
    def searchopenport(neg=False):
        "Filters records with at least one open port."
        q = Query()
        res = q.ports.any(q.state_state == "open")
        if neg:
            return ~res
        return res

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search an open port with a particular service."""
        q = Query()
        if srv is False:
            flt = ~q.service_name.exists()
        elif isinstance(srv, list):
            flt = q.service_name.one_of(srv)
        else:
            flt = cls._searchstring_re(q.service_name, srv)
        if port is not None:
            flt &= q.port == port
        if protocol is not None:
            flt &= q.protocol == protocol
        return q.ports.any(flt)

    @classmethod
    def searchproduct(
        cls, product=None, version=None, service=None, port=None, protocol=None
    ):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        q = Query()
        res = []
        if product is not None:
            if product is False:
                res.append(~q.service_product.exists())
            elif isinstance(product, list):
                res.append(q.service_product.one_of(product))
            else:
                res.append(cls._searchstring_re(q.service_product, product))
        if version is not None:
            if version is False:
                res.append(~q.service_version.exists())
            elif isinstance(version, list):
                res.append(q.service_version.one_of(version))
            else:
                res.append(cls._searchstring_re(q.service_version, version))
        if service is not None:
            if service is False:
                res.append(~q.service_name.exists())
            elif isinstance(service, list):
                res.append(q.service_name.one_of(service))
            else:
                res.append(cls._searchstring_re(q.service_name, service))
        if port is not None:
            res.append(q.port == port)
        if protocol is not None:
            res.append(q.protocol == protocol)
        return q.ports.any(cls.flt_and(*res))

    @classmethod
    def searchscript(cls, name=None, output=None, values=None, neg=False):
        """Search a particular content in the scripts results."""
        q = Query()
        res = []
        if isinstance(name, list):
            res.append(q.id.one_of(name))
        elif name is not None:
            res.append(cls._searchstring_re(q.id, name))
        if output is not None:
            res.append(cls._searchstring_re(q.output, output))
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
            if isinstance(values, dict):
                for field, value in values.items():
                    if "ports.scripts.%s" % key in cls.list_fields:
                        base = q
                        for subfld in field.split("."):
                            base = getattr(base, subfld)
                        list_field = True
                    else:
                        base = getattr(q, key)
                        for subfld in field.split("."):
                            base = getattr(base, subfld)
                        list_field = False
                    if isinstance(value, utils.REGEXP_T):
                        if "ports.scripts.%s.%s" % (key, field) in cls.list_fields:
                            # pylint reports "Cell variable value
                            # defined in loop" - see
                            # https://stackoverflow.com/a/25314665
                            base = base.test(
                                lambda val, v=value: any(
                                    v.search(subval) for subval in val
                                )
                            )
                        else:
                            base = base.search(value.pattern, flags=value.flags)
                    elif "ports.scripts.%s.%s" % (key, field) in cls.list_fields:
                        base = base.any([value])
                    else:
                        base = base == value
                    if list_field:
                        res.append(getattr(q, key).any(base))
                    else:
                        res.append(base)
            elif "ports.scripts.%s" % key in cls.list_fields:
                res.append(cls._searchstring_re_inarray(getattr(q, key), values))
            else:
                res.append(cls._searchstring_re(getattr(q, key), values))
        if res:
            res = q.ports.any(q.scripts.any(cls.flt_and(*res)))
        else:
            res = q.ports.any(q.scripts.exists())
        if neg:
            # pylint: disable=invalid-unary-operand-type
            return ~res
        return res

    @classmethod
    def searchsvchostname(cls, hostname):
        q = Query()
        return q.ports.any(cls._searchstring_re(q.service_hostname, hostname))

    @staticmethod
    def searchwebmin():
        q = Query()
        return q.ports.any(
            (q.service_name == "http")
            & (q.service_product == "MiniServ")
            & (q.service_extrainfo != "Webmin httpd")
        )

    @staticmethod
    def searchx11():
        q = Query()
        return q.ports.any(
            (q.service_name == "X11") & (q.service_extrainfo != "access denied")
        )

    def searchfile(self, fname=None, scripts=None):
        """Search shared files from a file name (either a string or a
        regexp), only from scripts using the "ls" NSE module.

        """
        q = Query()
        if fname is None:
            fname = q.filename.exists()
        elif isinstance(fname, list):
            fname = q.filename.one_of(fname)
        else:
            fname = self._searchstring_re(q.filename, fname)
        if scripts is None:
            return q.ports.any(q.scripts.any(q.ls.volumes.any(q.files.any(fname))))
        if isinstance(scripts, str):
            scripts = [scripts]
        if len(scripts) == 1:
            return q.ports.any(
                q.scripts.any(
                    (q.id == scripts[0]) & q.ls.volumes.any(q.files.any(fname))
                )
            )
        return q.ports.any(
            q.scripts.any(q.id.one_of(scripts) & q.ls.volumes.any(q.files.any(fname)))
        )

    @classmethod
    def searchhttptitle(cls, title):
        q = Query()
        base = cls._searchstring_re(q.output, title)
        return q.ports.any(
            q.scripts.any(q.id.one_of(["http-title", "html-title"]) & base)
        )

    @staticmethod
    def searchos(txt):
        if isinstance(txt, utils.REGEXP_T):

            def _match(base):
                return base.search(txt.pattern, flags=txt.flags)

        else:

            def _match(base):
                return base == txt

        q = Query()
        return q.os.osclass.any(
            _match(q.vendor) | _match(q.osfamily) | _match(q.osclass) | _match(q.type)
        )

    @staticmethod
    def searchvsftpdbackdoor():
        q = Query()
        return q.ports.any(
            (q.protocol == "tcp")
            & (q.state_state == "open")
            & (q.service_product == "vsftpd")
            & (q.service_version == "2.3.4")
        )

    @staticmethod
    def searchvulnintersil():
        # See MSF modules/auxiliary/admin/http/intersil_pass_reset.rb
        q = Query()
        return q.ports.any(
            (q.protocol == "tcp")
            & (q.state_state == "open")
            & (q.service_product == "Boa HTTPd")
            & (
                q.service_version.search(
                    "^0\\.9(3([^0-9]|$)|" "4\\.([0-9]|0[0-9]|" "1[0-1])([^0-9]|$))"
                )
            )
        )

    @staticmethod
    def searchdevicetype(devtype):
        q = Query()
        if isinstance(devtype, utils.REGEXP_T):
            res = q.service_devicetype.search(devtype.pattern, flags=devtype.flags)
        elif isinstance(devtype, list):
            res = q.service_devicetype.one_of(devtype)
        else:
            res = q.service_devicetype == devtype
        return q.ports.any(res)

    def searchnetdev(self):
        return self.searchdevicetype(
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
        )

    def searchphonedev(self):
        return self.searchdevicetype(
            [
                "PBX",
                "phone",
                "telecom-misc",
                "VoIP adapter",
                "VoIP phone",
            ]
        )

    @staticmethod
    def searchldapanon():
        q = Query()
        return q.ports.any(q.service_extrainfo == "Anonymous bind OK")

    @classmethod
    def searchvuln(cls, vulnid=None, state=None):
        q = Query()
        res = []
        if state is not None:
            res.append(cls._searchstring_re(q.vulns.state, state))
        if vulnid is not None:
            res.append(cls._searchstring_re(q.vulns.id, vulnid))
        if res:
            res = cls.flt_and(*res)
        else:
            res = q.vulns.id.exists()
        return q.ports.any(q.scripts.any(res))

    @staticmethod
    def searchtimeago(delta, neg=False):
        if not isinstance(delta, timedelta):
            delta = timedelta(seconds=delta)
        tstamp = (datetime.now() - delta).timestamp()
        q = Query().endtime
        if neg:
            return q < tstamp
        return q >= tstamp

    @staticmethod
    def searchtimerange(start, stop, neg=False):
        if isinstance(start, datetime):
            start = start.timestamp()
        if isinstance(stop, datetime):
            stop = stop.timestamp()
        q = Query()
        if neg:
            return (q.endtime < start) | (q.starttime > stop)
        return (q.endtime >= start) & (q.starttime <= stop)

    @classmethod
    def searchhop(cls, hop, ttl=None, neg=False):
        try:
            hop = cls.ip2internal(hop)
        except ValueError:
            pass
        q = Query()
        res = [q.ipaddr == hop]
        if ttl is not None:
            res.append(q.ttl == ttl)
        res = q.traces.any(q.hops.any(cls.flt_and(*res)))
        if neg:
            return ~res
        return res

    @classmethod
    def searchhopdomain(cls, hop, neg=False):
        q = Query()
        res = q.traces.any(
            q.hops.any(
                cls._searchstring_re_inarray(
                    q.domains,
                    hop,
                )
            )
        )
        if neg:
            return ~res
        return res

    @classmethod
    def searchhopname(cls, hop, neg=False):
        q = Query()
        res = q.traces.any(q.hops.any(cls._searchstring_re(q.host, hop)))
        if neg:
            return ~res
        return res

    @classmethod
    def searchcpe(cls, cpe_type=None, vendor=None, product=None, version=None):
        """Look for a CPE by type (a, o or h), vendor, product or version (the
        part after the column following the product). No argument will just
        check for cpe existence.

        """
        q = Query()
        fields = [
            ("type", cpe_type),
            ("vendor", vendor),
            ("product", product),
            ("version", version),
        ]
        flt = [
            cls._searchstring_re(getattr(q, field), value)
            for field, value in fields
            if value is not None
        ]
        if not flt:
            return q.cpes.exists()
        return q.cpes.any(cls.flt_and(*flt))

    def topvalues(
        self,
        field,
        flt=None,
        topnbr=10,
        sort=None,
        limit=None,
        skip=None,
        least=False,
        aggrflt=None,
        specialproj=None,
        specialflt=None,
    ):
        """
        This method makes use of the aggregation framework to produce
        top values for a given field or pseudo-field. Pseudo-fields are:
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
        q = Query()
        if flt is None:
            flt = self.flt_empty

        def _outputproc(val):
            return val

        def _extractor(flt, field):
            for rec in self._get(
                flt, sort=sort, limit=limit, skip=skip, fields=[field]
            ):
                for val in self._generate_field_values(rec, field):
                    yield val

        def _newflt(field):
            return self._search_field_exists(field)

        if field == "category":
            field = "categories"
        elif field.startswith("category:") or field.startswith("categories:"):
            subflt = utils.str2regexp(field.split(":", 1)[1])
            field = "categories"
            if isinstance(subflt, utils.REGEXP_T):

                def _macth(value):
                    return subflt.search(value) is not None

            else:

                def _macth(value):
                    return value == subflt

            def _extractor(flt, field):  # noqa: F811
                for rec in self._get(
                    flt, sort=sort, limit=limit, skip=skip, fields=[field]
                ):
                    for cat in rec[field]:
                        if _macth(cat):
                            yield cat

            def _newflt(field):  # noqa: F811
                return self.searchcategory(subflt)

        elif field == "country":
            field = "infos.country_code"

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=[field, "infos.country_name"],
                ):
                    rec = rec["infos"]
                    yield (rec["country_code"], rec.get("country_name", "?"))

        elif field == "city":

            def _newflt(field):
                return self._search_field_exists(
                    "infos.country_code"
                ) & self._search_field_exists("infos.city")

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["infos.country_code", "infos.city"],
                ):
                    rec = rec["infos"]
                    yield (rec["country_code"], rec["city"])

        elif field == "asnum":
            field = "infos.as_num"
        elif field == "as":
            field = "infos.as_num"

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=[field, "infos.as_name"],
                ):
                    rec = rec["infos"]
                    yield (rec["as_num"], rec.get("as_name", "?"))

        elif field == "net" or field.startswith("net:"):
            maskval = int(field.split(":", 1)[1]) if ":" in field else 24
            mask = utils.int2mask(maskval)
            field = "addr"

            def _newflt(field):
                return self.searchipv4()

            def _extractor(flt, field):
                for rec in self._get(
                    flt, sort=sort, limit=limit, skip=skip, fields=[field]
                ):
                    yield "%s/%s" % (
                        utils.int2ip(utils.ip2int(rec["addr"]) & mask),
                        maskval,
                    )

        elif field == "port" or field.startswith("port:"):

            def _newflt(field):
                return q.ports.any(q.state_state.exists())

            if field == "port":
                matchfld = "ports.state_state"

                def _match(port):
                    return "state_state" in port

            else:
                info = field.split(":", 1)[1]
                if info in ["open", "filtered", "closed"]:
                    matchfld = "ports.state_state"

                    def _match(port):
                        return port.get("state_state") == info

                else:
                    matchfld = "ports.service_name"

                    def _match(port):
                        return port.get("service_name") == info

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.port", "ports.protocol", matchfld],
                ):
                    for port in rec["ports"]:
                        if _match(port):
                            yield (port.get("protocol", "?"), port["port"])

        elif field.startswith("portlist:"):
            fields = ["ports.port", "ports.protocol", "ports.state_state"]
            info = field.split(":", 1)[1]

            def _newflt(field):
                return q.ports.any(q.state_state.exists())

            def _extractor(flt, field):
                for rec in self._get(
                    flt, sort=sort, limit=limit, skip=skip, fields=fields
                ):
                    yield tuple(
                        sorted(
                            (port.get("protocol", "?"), port["port"])
                            for port in rec["ports"]
                            if port.get("state_state") == info
                        )
                    )

            def _outputproc(val):  # noqa: F811
                return list(val)

        elif field.startswith("countports:"):
            state = field.split(":", 1)[1]

            def _newflt(field):
                return q.ports.any(q.state_state.exists())

            def _extractor(flt, field):
                for rec in self._get(
                    flt, sort=sort, limit=limit, skip=skip, fields=["ports.state_state"]
                ):
                    yield sum(
                        1 for port in rec["ports"] if port.get("state_state") == state
                    )

        elif field == "service":

            def _newflt(field):
                return self.searchopenport()

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.state_state", "ports.service_name"],
                ):
                    for port in rec["ports"]:
                        if port.get("state_state") == "open":
                            yield port.get("service_name")

        elif field.startswith("service:"):
            portnum = int(field[8:])

            def _newflt(field):
                return self.searchport(portnum)

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.port", "ports.state_state", "ports.service_name"],
                ):
                    for port in rec["ports"]:
                        if (
                            port.get("port") == portnum
                            and port.get("state_state") == "open"
                        ):
                            yield port.get("service_name")

        elif field == "product":

            def _newflt(field):
                return self.searchopenport()

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=[
                        "ports.state_state",
                        "ports.service_name",
                        "ports.service_product",
                    ],
                ):
                    for port in rec["ports"]:
                        if port.get("state_state") == "open":
                            yield (
                                port.get("service_name"),
                                port.get("service_product"),
                            )

        elif field.startswith("product:"):
            service = field[8:]
            if service.isdigit():
                portnum = int(service)

                def _newflt(field):
                    return self.searchport(portnum)

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=[
                            "ports.port",
                            "ports.state_state",
                            "ports.service_name",
                            "ports.service_product",
                        ],
                    ):
                        for port in rec["ports"]:
                            if (
                                port.get("port") == portnum
                                and port.get("state_state") == "open"
                            ):
                                yield (
                                    port.get("service_name"),
                                    port.get("service_product"),
                                )

            else:

                def _newflt(field):
                    return self.searchservice(service)

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=[
                            "ports.state_state",
                            "ports.service_name",
                            "ports.service_product",
                        ],
                    ):
                        for port in rec["ports"]:
                            if (
                                port.get("state_state") == "open"
                                and port.get("service_name") == service
                            ):
                                yield (
                                    port.get("service_name"),
                                    port.get("service_product"),
                                )

        elif field == "version":

            def _newflt(field):
                return self.searchopenport()

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=[
                        "ports.state_state",
                        "ports.service_name",
                        "ports.service_product",
                        "ports.service_version",
                    ],
                ):
                    for port in rec["ports"]:
                        if port.get("state_state") == "open":
                            yield (
                                port.get("service_name"),
                                port.get("service_product"),
                                port.get("service_version"),
                            )

        elif field.startswith("version:"):
            service = field[8:]
            if service.isdigit():
                portnum = int(service)

                def _newflt(field):
                    return self.searchport(portnum)

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=[
                            "ports.port",
                            "ports.state_state",
                            "ports.service_name",
                            "ports.service_product",
                            "ports.service_version",
                        ],
                    ):
                        for port in rec["ports"]:
                            if (
                                port.get("port") == portnum
                                and port.get("state_state") == "open"
                            ):
                                yield (
                                    port.get("service_name"),
                                    port.get("service_product"),
                                    port.get("service_version"),
                                )

            elif ":" in service:
                service, product = service.split(":", 1)

                def _newflt(field):
                    return self.searchproduct(product=product, service=service)

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=[
                            "ports.state_state",
                            "ports.service_name",
                            "ports.service_product",
                            "ports.service_version",
                        ],
                    ):
                        for port in rec["ports"]:
                            if (
                                port.get("state_state") == "open"
                                and port.get("service_name") == service
                                and port.get("service_product") == product
                            ):
                                yield (
                                    port.get("service_name"),
                                    port.get("service_product"),
                                    port.get("service_version"),
                                )

            else:

                def _newflt(field):
                    return self.searchservice(service)

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=[
                            "ports.state_state",
                            "ports.service_name",
                            "ports.service_product",
                            "ports.service_version",
                        ],
                    ):
                        for port in rec["ports"]:
                            if (
                                port.get("state_state") == "open"
                                and port.get("service_name") == service
                            ):
                                yield (
                                    port.get("service_name"),
                                    port.get("service_product"),
                                    port.get("service_version"),
                                )

        elif field.startswith("cpe"):
            try:
                field, cpeflt = field.split(":", 1)
                cpeflt = cpeflt.split(":", 3)
            except ValueError:
                cpeflt = []
            try:
                field = field.split(".", 1)[1]
            except IndexError:
                field = "version"
            fields = ["type", "vendor", "product", "version"]
            if field not in fields:
                try:
                    field = fields[int(field) - 1]
                except (IndexError, ValueError):
                    field = "version"
            cpeflt = zip(fields, (utils.str2regexp(value) for value in cpeflt))

            def _newflt(field):
                return self.searchcpe(
                    **dict(
                        ("cpe_type" if key == "type" else key, value)
                        for key, value in cpeflt
                    )
                )

            def _extractor(flt, field):
                for rec in self._get(
                    flt, sort=sort, limit=limit, skip=skip, fields=["cpes"]
                ):
                    for cpe in rec["cpes"]:
                        good = True
                        for key, value in cpeflt:
                            if isinstance(value, utils.REGEXP_T):
                                if not value.search(cpe.get(key, "")):
                                    good = False
                                    break
                            elif cpe.get(key) != value:
                                good = False
                                break
                        if good:
                            res = []
                            for fld in fields:
                                res.append(cpe.get(fld))
                                if fld == field:
                                    break
                            yield tuple(res)

        elif field == "devicetype":
            field = "ports.service_devicetype"
        elif field.startswith("devicetype:"):
            portnum = int(field.split(":", 1)[1])

            def _newflt(field):
                return self.searchport(portnum)

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=[
                        "ports.port",
                        "ports.state_state",
                        "ports.service_devicetype",
                    ],
                ):
                    for port in rec["ports"]:
                        if (
                            port.get("port") == portnum
                            and port.get("state_state") == "open"
                        ):
                            yield port.get("service_devicetype")

        elif field.startswith("smb."):

            def _newflt(field):
                return self.searchscript(name="smb-os-discovery")

            field = "ports.scripts.smb-os-discovery." + field[4:]
        elif field.startswith("ntlm."):

            def _newflt(field):
                return self.searchscript(name="ntlm-info")

            arg = field[5:]
            arg = {
                "name": "Target_Name",
                "server": "NetBIOS_Computer_Name",
                "domain": "NetBIOS_Domain_Name",
                "workgroup": "Workgroup",
                "domain_dns": "DNS_Domain_Name",
                "forest": "DNS_Tree_Name",
                "fqdn": "DNS_Computer_Name",
                "os": "Product_Version",
                "version": "NTLM_Version",
            }.get(arg, arg)
            field = "ports.scripts.ntlm-info." + arg
        elif field.startswith("script:"):
            scriptid = field.split(":", 1)[1]
            if ":" in scriptid:
                portnum, scriptid = scriptid.split(":", 1)
                portnum = int(portnum)

                def _newflt(field):
                    return self.searchscript(name=scriptid) & self.searchport(portnum)

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=[
                            "ports.port",
                            "ports.scripts.id",
                            "ports.scripts.output",
                        ],
                    ):
                        for port in rec["ports"]:
                            if port.get("port") != portnum:
                                continue
                            for script in port.get("scripts", []):
                                if script["id"] == scriptid:
                                    yield script["output"]

            else:

                def _newflt(field):
                    return self.searchscript(name=scriptid)

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=["ports.scripts.id", "ports.scripts.output"],
                    ):
                        for port in rec["ports"]:
                            for script in port.get("scripts", []):
                                if script["id"] == scriptid:
                                    yield script["output"]

        elif field == "domains":
            field = "hostnames.domains"
        elif field.startswith("domains:"):
            level = int(field[8:]) - 1
            field = "hostnames.domains"

            def _extractor(flt, field):
                for rec in self._get(
                    flt, sort=sort, limit=limit, skip=skip, fields=["hostnames.domains"]
                ):
                    for host in rec["hostnames"]:
                        for dom in host.get("domains", []):
                            if dom.count(".") == level:
                                yield dom

        elif field.startswith("cert."):
            subfld = field[5:]
            field = "ports.scripts.ssl-cert." + subfld

            if subfld in ["issuer", "subject"]:

                def _extractor(flt, field):
                    for rec in self._get(
                        flt, sort=sort, limit=limit, skip=skip, fields=[field]
                    ):
                        for val in self._generate_field_values(rec, field):
                            yield tuple(sorted(val.items()))

                def _outputproc(val):
                    return dict(val)

        elif field == "useragent" or field.startswith("useragent:"):
            if field == "useragent":

                def _newflt(field):
                    return self.searchuseragent()

            else:
                subfield = utils.str2regexp(field[10:])

                def _newflt(field):
                    return self.searchuseragent(useragent=subfield)

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=["ports.scripts.http-user-agent"],
                    ):
                        for port in rec["ports"]:
                            for script in port.get("scripts", []):
                                for ua in script.get("http-user-agent", []):
                                    if isinstance(subfield, utils.REGEXP_T):
                                        if subfield.search(ua):
                                            yield ua
                                    else:
                                        if ua == subfield:
                                            yield ua

            field = "ports.scripts.http-user-agent"
        elif field == "ja3-client" or (
            field.startswith("ja3-client") and field[10] in ":."
        ):
            if ":" in field:
                field, value = field.split(":", 1)
                subkey, value = self._ja3keyvalue(utils.str2regexp(value))
                if isinstance(value, utils.REGEXP_T):

                    def _match(ja3cli):
                        return value.search(ja3cli.get(subkey, "")) is not None

                else:

                    def _match(ja3cli):
                        return value == ja3cli.get(subkey, "")

            else:
                value = None
                subkey = None

                def _match(ja3cli):
                    return True

            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"

            def _newflt(field):
                return self.searchja3client(value_or_hash=value)

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.ssl-ja3-client"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for ja3cli in script.get("ssl-ja3-client", []):
                                if isinstance(value, utils.REGEXP_T):
                                    if not value.search(ja3cli.get(subkey, "")):
                                        continue
                                elif value is not None:
                                    if value != ja3cli.get(subkey):
                                        continue
                                yield ja3cli.get(subfield)

        elif field == "ja3-server" or (
            field.startswith("ja3-server") and field[10] in ":."
        ):
            if ":" in field:
                field, values = field.split(":", 1)
                if ":" in values:
                    value1, value2 = values.split(":", 1)
                    if value1:
                        subkey1, value1 = self._ja3keyvalue(utils.str2regexp(value1))
                    else:
                        subkey1, value1 = None, None
                    if value2:
                        subkey2, value2 = self._ja3keyvalue(utils.str2regexp(value2))
                    else:
                        subkey2, value2 = None, None
                else:
                    subkey1, value1 = self._ja3keyvalue(utils.str2regexp(values))
                    subkey2, value2 = None, None
            else:
                subkey1, value1 = None, None
                subkey2, value2 = None, None
            if "." in field:
                field, subfield = field.split(".", 1)
            else:
                subfield = "md5"

            def _newflt(field):
                return self.searchja3server(
                    value_or_hash=value1,
                    client_value_or_hash=value2,
                )

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.ssl-ja3-server"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for ja3srv in script.get("ssl-ja3-server", []):
                                ja3cli = ja3srv.get("client", {})
                                if isinstance(value1, utils.REGEXP_T):
                                    if not value1.search(ja3srv.get(subkey1, "")):
                                        continue
                                elif value1 is not None:
                                    if value1 != ja3srv.get(subkey1):
                                        continue
                                if isinstance(value2, utils.REGEXP_T):
                                    if not value2.search(ja3cli.get(subkey2, "")):
                                        continue
                                elif value2 is not None:
                                    if value2 != ja3cli.get(subkey2):
                                        continue
                                yield (ja3srv.get(subfield), ja3cli.get(subfield))

        elif field == "sshkey.bits":

            def _newflt(field):
                return self.searchsshkey()

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.ssh-hostkey"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for hostk in script.get("ssh-hostkey", []):
                                yield (hostk.get("type"), hostk.get("bits"))

        elif field.startswith("sshkey."):

            def _newflt(field):
                return self.searchsshkey()

            field = "ports.scripts.ssh-hostkey." + field[7:]
        elif field == "ike.vendor_ids":

            def _newflt(field):
                return self.searchscript(name="ike-info")

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.ike-info.vendor_ids"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for vid in script.get("ike-info", {}).get("vendor_ids", []):
                                yield (vid.get("value"), vid.get("name"))

        elif field == "ike.transforms":

            def _newflt(field):
                return self.searchscript(name="ike-info")

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.ike-info.transforms"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for xfrm in script.get("ike-info", {}).get(
                                "transforms", []
                            ):
                                yield (
                                    xfrm.get("Authentication"),
                                    xfrm.get("Encryption"),
                                    xfrm.get("GroupDesc"),
                                    xfrm.get("Hash"),
                                    xfrm.get("LifeDuration"),
                                    xfrm.get("LifeType"),
                                )

        elif field == "ike.notification":
            field = "ports.scripts.ike-info.notification_type"
        elif field.startswith("ike."):
            field = "ports.scripts.ike-info." + field[4:]
        elif field == "httphdr":

            def _newflt(field):
                return self.searchhttphdr()

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.http-headers"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for hdr in script.get("http-headers", []):
                                yield (hdr.get("name"), hdr.get("value"))

        elif field.startswith("httphdr."):
            field = "ports.scripts.http-headers.%s" % field[8:]

            def _newflt(field):
                return self.searchhttphdr()

        elif field.startswith("httphdr:"):
            subfield = field[8:].lower()

            def _newflt(field):
                return self.searchhttphdr(name=subfield)

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.http-headers"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for hdr in script.get("http-headers", []):
                                if hdr.get("name", "").lower() == subfield:
                                    yield hdr.get("value")

        elif field == "httpapp":

            def _newflt(field):
                return self.searchhttpapp()

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.http-app"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for app in script.get("http-app", []):
                                yield (app.get("application"), app.get("version"))

        elif field.startswith("httpapp:"):
            subfield = field[8:]

            def _newflt(field):
                return self.searchhttpapp(name=subfield)

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.http-app"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            for app in script.get("http-headers", []):
                                if app.get("application", "") == subfield:
                                    yield app.get("version")

        elif field.startswith("modbus."):
            field = "ports.scripts.modbus-discover." + field[7:]
        elif field.startswith("s7."):
            field = "ports.scripts.s7-info." + field[3:]
        elif field.startswith("enip."):
            subfield = field[5:]
            subfield = {
                "vendor": "Vendor",
                "product": "Product Name",
                "serial": "Serial Number",
                "devtype": "Device Type",
                "prodcode": "Product Code",
                "rev": "Revision",
                "ip": "Device IP",
            }.get(subfield, subfield)
            field = "ports.scripts.enip-info." + subfield
        elif field.startswith("mongo.dbs."):
            field = "ports.scripts.mongodb-databases." + field[10:]
        elif field.startswith("vulns."):
            subfield = field[6:]
            if subfield == "id":
                field = "ports.scripts.vulns.id"
            else:
                field = "ports.scripts.vulns." + subfield

                def _extractor(flt, field):
                    for rec in self._get(
                        flt,
                        sort=sort,
                        limit=limit,
                        skip=skip,
                        fields=[field, "ports.scripts.vulns.id"],
                    ):
                        for port in rec["ports"]:
                            for script in port.get("scripts", []):
                                for vuln in script.get("vulns", []):
                                    yield (vuln.get("id"), vuln.get(subfield))

        elif field == "file" or (field.startswith("file") and field[4] in ".:"):
            if field.startswith("file:"):
                scripts = field[5:]
                if "." in scripts:
                    scripts, fieldname = scripts.split(".", 1)
                else:
                    fieldname = "filename"
                scripts = scripts.split(",")
            else:
                fieldname = field[5:] or "filename"
                scripts = None

            def _newflt(field):
                return self.searchfile(scripts=scripts)

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["ports.scripts.id", "ports.scripts.ls"],
                ):
                    for port in rec["ports"]:
                        for script in port.get("scripts", []):
                            if scripts is not None and script.get("id") not in scripts:
                                continue
                            for vol in script.get("ls", {}).get("volumes", []):
                                for fil in vol.get("files", []):
                                    yield fil.get(fieldname)

        elif field == "screenwords":
            field = "ports.screenwords"
        elif field == "hop":
            field = "traces.hops.ipaddr"
        elif field.startswith("hop") and field[3] in ":>":
            ttl = int(field[4:])
            if field[3] == ":":

                def _match(hop):
                    return hop.get("ttl", 0) == ttl

            else:

                def _match(hop):
                    return hop.get("ttl", 0) > ttl

            field = "traces.hops.ipaddr"

            def _extractor(flt, field):
                for rec in self._get(
                    flt,
                    sort=sort,
                    limit=limit,
                    skip=skip,
                    fields=["traces.hops.ipaddr", "traces.hops.ttl"],
                ):
                    for trace in rec["traces"]:
                        for hop in trace.get("hops", []):
                            if _match(hop):
                                yield hop["ipaddr"]

        elif field.startswith("scanner.port:"):
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = "ports.scripts.scanner.ports.%s.ports" % field[13:]
        elif field == "scanner.name":
            flt = self.flt_and(flt, self.searchscript(name="scanner"))
            field = "ports.scripts.scanner.scanners.name"
        return [
            {"_id": _outputproc(val), "count": count}
            for val, count in Counter(
                _extractor(flt & _newflt(field), field)
            ).most_common(topnbr)
        ]

    def _features_port_list(self, flt, yieldall, use_service, use_product, use_version):
        flt &= self._search_field_exists("ports.port")
        fields = ["ports.port"]
        if use_service:
            fields.append("ports.service_name")
            if use_product:
                fields.append("ports.service_product")
                if use_version:
                    fields.append("ports.service_version")

                    def _extract(port):
                        return (
                            port.get("port"),
                            port.get("service_name"),
                            port.get("service_product"),
                            port.get("service_version"),
                        )

                else:

                    def _extract(port):
                        return (
                            port.get("port"),
                            port.get("service_name"),
                            port.get("service_product"),
                        )

            else:

                def _extract(port):
                    return (port.get("port"), port.get("service_name"))

        else:

            def _extract(port):
                return (port.get("port"),)

        res = set()
        for rec in self._get(flt, fields=fields):
            for port in rec.get("ports", []):
                if port.get("port") == -1:
                    continue
                res.add(_extract(port))

        if yieldall:
            return res

        return sorted(res, key=lambda val: [utils.key_sort_none(v) for v in val])

    def getlocations(self, flt):
        res = defaultdict(int)
        for rec in self.get(flt):
            c = rec.get("infos", {}).get("coordinates", {})
            if not c:
                continue
            c = tuple(c)
            res[c] += 1
        for rec, count in res.items():
            yield {"_id": rec, "count": count}

    def get_ips_ports(self, flt, limit=None, skip=None):
        res = self.get(flt, limit=limit, skip=skip)
        count = sum(len(host.get("ports", [])) for host in res)
        return (
            (
                {
                    "addr": host["addr"],
                    "ports": [
                        {"state_state": port["state_state"], "port": port["port"]}
                        for port in host.get("ports", [])
                        if "state_state" in port
                    ],
                }
                for host in res
                if host.get("ports")
            ),
            count,
        )

    def get_ips(self, flt, limit=None, skip=None):
        res = self.get(flt, limit=limit, skip=skip)
        return (({"addr": host["addr"]} for host in res), len(res))

    def get_open_port_count(self, flt, limit=None, skip=None):
        res = self.get(flt, limit=limit, skip=skip)
        return (
            (
                {
                    "addr": host["addr"],
                    "starttime": host.get("starttime"),
                    "openports": {"count": host["openports"]["count"]},
                }
                for host in res
                if host.get("openports", {}).get("count") is not None
            ),
            len(res),
        )


class TinyDBNmap(TinyDBActive, DBNmap):

    """An Nmap-specific DB using TinyDB backend"""

    content_handler = Nmap2DB
    dbname = "nmap"
    dbname_scans = "nmap_scans"

    def __init__(self, url):
        super().__init__(url)
        self.output_function = None

    @property
    def db_scans(self):
        """The DB for scan files"""
        try:
            return self._db_scans
        except AttributeError:
            self._db_scans = TDB(
                os.path.join(self.basepath, "%s.json" % self.dbname_scans)
            )
            return self._db_scans

    def init(self):
        super().init()
        try:
            self.db_scans.drop_tables()
        except AttributeError:
            # TinyDB < 4
            self.db_scans.purge_tables()

    def remove(self, rec):
        """Removes the record from the active column. `rec` must be the record
        as returned by `.get()` or the record id.

        """
        q = Query()
        if isinstance(rec, dict):
            scanids = rec.get("scanid", [])
        else:
            try:
                scanids = self.get(q._id == rec)[0].get("scanid", [])
            except IndexError:
                scanids = []
        super().remove(rec)
        for scanid in scanids:
            if not self.db.get(q.scanid.any([scanid])):
                self.db_scans.remove(cond=Query()._id == scanid)

    def remove_many(self, flt):
        """Removes hosts from the active column, based on the filter `flt`.

        If the hosts removed had `scanid` attributes, and if some of them
        refer to scans that have no more host record after the deletion of the
        hosts, then the scan records are also removed.

        """
        scanids = list(self.distinct("scanid", flt=flt))
        super().remove_many(flt)
        for scanid in scanids:
            if not self.db.get(Query().scanid.any([scanid])):
                self.db_scans.remove(cond=Query()._id == scanid)

    def store_or_merge_host(self, host):
        self.store_host(host)

    def getscan(self, scanid):
        try:
            scanid = scanid.decode()
        except AttributeError:
            pass
        return self.db_scans.get(Query()._id == scanid)

    def is_scan_present(self, scanid):
        return self.getscan(scanid) is not None

    def store_scan_doc(self, scan):
        scan = deepcopy(scan)
        _id = scan["_id"] = scan["_id"].decode()
        if self.db_scans.get(Query()._id == _id) is not None:
            raise ValueError("Duplicate entry for id %r" % _id)
        self.db_scans.insert(scan)
        utils.LOGGER.debug("SCAN STORED: %r in %r", _id, self.dbname_scans)
        return _id

    def update_scan_doc(self, scan_id, data):
        self.db_scans.update(deepcopy(data), cond=Query()._id == scan_id.decode())


class TinyDBView(TinyDBActive, DBView):

    """A View-specific DB using TinyDB backend"""

    dbname = "view"

    def store_or_merge_host(self, host):
        if not self.merge_host(host):
            self.store_host(host)


def op_update(count, firstseen, lastseen):
    """A TinyDB operation to update a document with count, firstseen and
    lastseen values.

    """

    def transform(doc):
        doc["count"] = doc.get("count", 0) + count
        if firstseen is not None:
            doc["firstseen"] = min(doc.get("firstseen", firstseen), firstseen)
        if lastseen is not None:
            doc["lastseen"] = max(doc.get("lastseen", lastseen), lastseen)

    return transform


def op_update_replacecount(count, firstseen, lastseen):
    """A TinyDB operation to update a document with count, firstseen and
    lastseen values.

    """

    def transform(doc):
        doc["count"] = count
        if firstseen is not None:
            doc["firstseen"] = min(doc.get("firstseen", firstseen), firstseen)
        if lastseen is not None:
            doc["lastseen"] = max(doc.get("lastseen", lastseen), lastseen)

    return transform


class TinyDBPassive(TinyDB, DBPassive):

    """A Passive-specific DB using TinyDB backend"""

    dbname = "passive"

    @classmethod
    def rec2internal(cls, rec):
        """Given a record as presented to the user, fixes it before it can be
        inserted in the database.

        """
        rec = deepcopy(rec)
        try:
            rec["addr"] = cls.ip2internal(rec["addr"])
        except (KeyError, ValueError):
            pass
        for fld in ["firstseen", "lastseen"]:
            if fld not in rec:
                continue
            if isinstance(rec[fld], datetime):
                rec[fld] = rec[fld].timestamp()
            elif isinstance(rec[fld], str):
                rec[fld] = utils.all2datetime(rec[fld]).timestamp()
            if "_id" in rec:
                del rec["_id"]
        return rec

    @classmethod
    def internal2rec(cls, rec):
        """Given a record as stored in the database, fixes it before it can be
        returned to backend-agnostic functions.

        """
        rec = deepcopy(rec)
        try:
            rec["addr"] = cls.internal2ip(rec["addr"])
        except (KeyError, ValueError):
            pass
        for fld in ["firstseen", "lastseen"]:
            try:
                rec[fld] = utils.all2datetime(rec[fld])
            except KeyError:
                pass
        if rec.get("recontype") in {"SSL_SERVER", "SSL_CLIENT"} and rec.get(
            "source"
        ) in {
            "cert",
            "cacert",
        }:
            rec["value"] = cls.from_binary(rec["value"])
        if isinstance(rec, Document):
            rec["_id"] = rec.doc_id
        return rec

    def _get(self, *args, **kargs):
        for rec in self._db_get(*args, **kargs):
            if rec.get("recontype") in {"SSL_SERVER", "SSL_CLIENT"} and rec.get(
                "source"
            ) in {
                "cert",
                "cacert",
            }:
                for fld in ["not_before", "not_after"]:
                    try:
                        rec["infos"][fld] = utils.all2datetime(rec["infos"][fld])
                    except KeyError:
                        pass
            yield self.internal2rec(rec)

    def get_one(self, *args, **kargs):
        """Same function as get, except the first record matching "spec" (or
        None) is returned.

        """
        try:
            return self.get(*args, **kargs)[0]
        except IndexError:
            return None

    def insert(self, spec, getinfos=None):
        """Inserts the record "spec" into the passive column."""
        if getinfos is not None:
            spec.update(getinfos(spec))
        spec = self.rec2internal(spec)
        self.db.insert(spec)

    def insert_or_update(
        self, timestamp, spec, getinfos=None, lastseen=None, replacecount=False
    ):
        if spec is None:
            return
        q = Query()
        orig = deepcopy(spec)
        spec = self.rec2internal(spec)
        try:
            del spec["infos"]
        except KeyError:
            pass
        count = spec.pop("count", 1)
        spec_cond = self.flt_and(
            *(getattr(q, key) == value for key, value in spec.items())
        )
        if isinstance(timestamp, datetime):
            timestamp = timestamp.timestamp()
        elif isinstance(timestamp, str):
            timestamp = utils.all2datetime(timestamp).timestamp()
        if isinstance(lastseen, datetime):
            lastseen = lastseen.timestamp()
        elif isinstance(lastseen, str):
            lastseen = utils.all2datetime(lastseen).timestamp()
        current = self.get_one(spec_cond, fields=[])
        if current is not None:
            op = op_update_replacecount if replacecount else op_update
            self.db.update(
                op(count, timestamp, lastseen or timestamp), doc_ids=[current.doc_id]
            )
        else:
            doc = dict(
                spec, count=count, firstseen=timestamp, lastseen=lastseen or timestamp
            )
            if getinfos is not None:
                orig.update(getinfos(orig))
                try:
                    doc["infos"] = orig["infos"]
                except KeyError:
                    pass
                if doc["recontype"] in {"SSL_SERVER", "SSL_CLIENT"} and doc[
                    "source"
                ] in {
                    "cert",
                    "cacert",
                }:
                    for fld in ["not_before", "not_after"]:
                        if fld not in doc.get("infos", {}):
                            continue
                        info = doc["infos"]
                        if isinstance(info[fld], datetime):
                            info[fld] = info[fld].timestamp()
                        elif isinstance(info[fld], str):
                            info[fld] = utils.all2datetime(info[fld]).timestamp()
                # upsert() won't handle operations
            self.db.upsert(doc, spec_cond)

    def remove(self, spec_or_id):  # pylint: disable=arguments-renamed
        if isinstance(spec_or_id, int):
            self.db.remove(doc_ids=[spec_or_id])
        else:
            self.db.remove(cond=spec_or_id)

    def topvalues(
        self,
        field,
        flt=None,
        distinct=True,
        topnbr=10,
        sort=None,
        limit=None,
        skip=None,
        least=False,
        aggrflt=None,
        specialproj=None,
        specialflt=None,
    ):
        """This method makes use of the aggregation framework to
        produce top values for a given field.

        If `distinct` is True (default), the top values are computed
        by distinct events. If it is False, they are computed based on
        the "count" field.

        """
        if flt is None:
            flt = self.flt_empty
        if distinct:
            countfield = None
            fields = [field]
        else:
            countfield = "count"
            fields = [field, "count"]

        def _outputproc(val):
            return val

        def _extractor(flt, field):
            for rec in self._get(flt, sort=sort, limit=limit, skip=skip, fields=fields):
                for val in self._generate_field_values(
                    rec, field, countfield=countfield
                ):
                    yield val

        def _newflt(field):
            return self._search_field_exists(field)

        if field == "net" or field.startswith("net:"):
            maskval = int(field.split(":", 1)[1]) if ":" in field else 24
            mask = utils.int2mask(maskval)
            field = "addr"

            def _newflt(field):  # noqa: F811
                return self.searchipv4()

            def _extractor(flt, field):  # noqa: F811
                for rec in self._get(
                    flt, sort=sort, limit=limit, skip=skip, fields=fields
                ):
                    val = "%s/%s" % (
                        utils.int2ip(utils.ip2int(rec["addr"]) & mask),
                        maskval,
                    )
                    if distinct:
                        yield val
                    else:
                        yield (val, rec.get("count", 1))

        elif field == "domains":
            field = "infos.domain"
            if distinct:
                fields = [field]
            else:
                fields = [field, "count"]

            def _newflt(field):  # noqa: F811
                return self.searchdns()

        elif field.startswith("domains:"):
            level = int(field[8:]) - 1
            field = "infos.domain"

            def _newflt(field):  # noqa: F811
                return self.searchdns()

            def _extractor(flt, field):  # noqa: F811
                # We cannot use limit= or skip= here, since we are filtering
                # the results
                i = 0
                j = skip or 0
                fields = [field] if distinct else [field, "count"]
                for rec in self._get(flt, sort=sort, fields=fields):
                    for val in self._generate_field_values(rec, field):
                        if val.count(".") == level:
                            if j:
                                j -= 1
                                continue
                            i += 1
                            if distinct:
                                yield val
                            else:
                                yield (val, rec.get("count"))
                        if limit is not None and i >= limit:
                            break
                    if limit is not None and i >= limit:
                        break

        if distinct:
            return [
                {"_id": _outputproc(val), "count": count}
                for val, count in Counter(
                    _extractor(flt & _newflt(field), field)
                ).most_common(topnbr)
            ]
        res = Counter()
        for val, count in _extractor(flt & _newflt(field), field):
            res[val] += count
        return [
            {"_id": _outputproc(val), "count": count}
            for val, count in res.most_common(topnbr)
        ]

    def _features_port_list(self, flt, yieldall, use_service, use_product, use_version):
        flt &= self._search_field_exists("port")
        fields = ["port"]
        if use_service:
            fields.append("infos.service_name")
            if use_product:
                fields.append("infos.service_product")
                if use_version:
                    fields.append("infos.service_version")

                    def _extract(rec):
                        infos = rec.get("infos", {})
                        return (
                            rec.get("port"),
                            infos.get("service_name"),
                            infos.get("service_product"),
                            infos.get("service_version"),
                        )

                else:

                    def _extract(rec):
                        infos = rec.get("infos", {})
                        return (
                            rec.get("port"),
                            infos.get("service_name"),
                            infos.get("service_product"),
                        )

            else:

                def _extract(rec):
                    return (rec.get("port"), rec.get("infos", {}).get("service_name"))

        else:

            def _extract(rec):
                return (rec.get("port"),)

        res = set()
        for rec in self._get(flt, fields=fields):
            res.add(_extract(rec))

        if yieldall:
            return res

        return sorted(res, key=lambda val: [utils.key_sort_none(v) for v in val])

    @classmethod
    def searchrecontype(cls, rectype, neg=False):
        q = Query()
        if isinstance(rectype, list):
            res = q.recontype.one_of(rectype)
            if neg:
                return ~res
            return res
        return cls._searchstring_re(q.recontype, rectype, neg=neg)

    @classmethod
    def searchsensor(cls, sensor, neg=False):
        return cls._searchstring_re(Query().sensor, sensor, neg=neg)

    @staticmethod
    def searchport(port, protocol="tcp", state="open", neg=False):
        """Filters (if `neg` == True, filters out) records on the specified
        protocol/port.

        """
        if protocol != "tcp":
            raise ValueError("Protocols other than TCP are not supported " "in passive")
        if state != "open":
            raise ValueError("Only open ports can be found in passive")
        if neg:
            return Query().port != port
        return Query().port == port

    @classmethod
    def searchservice(cls, srv, port=None, protocol=None):
        """Search a port with a particular service."""
        q = Query()
        if srv is False:
            flt = ~q.infos.service_name.exists()
        elif isinstance(srv, list):
            flt = q.infos.service_name.one_of(srv)
        else:
            flt = cls._searchstring_re(q.infos.service_name, srv)
        if port is not None:
            flt &= q.port == port
        if protocol is not None and protocol != "tcp":
            raise ValueError("Protocols other than TCP are not supported " "in passive")
        return flt

    @classmethod
    def searchproduct(
        cls, product=None, version=None, service=None, port=None, protocol=None
    ):
        """Search a port with a particular `product`. It is (much)
        better to provide the `service` name and/or `port` number
        since those fields are indexed.

        """
        q = Query()
        res = []
        if product is not None:
            if product is False:
                res.append(~q.infos.service_product.exists())
            elif isinstance(product, list):
                res.append(q.infos.service_product.one_of(product))
            else:
                res.append(cls._searchstring_re(q.infos.service_product, product))
        if version is not None:
            if version is False:
                res.append(~q.infos.service_version.exists())
            elif isinstance(version, list):
                res.append(q.infos.service_version.one_of(version))
            else:
                res.append(cls._searchstring_re(q.infos.service_version, version))
        if service is not None:
            if service is False:
                res.append(~q.infos.service_name.exists())
            elif isinstance(service, list):
                res.append(q.infos.service_name.one_of(service))
            else:
                res.append(cls._searchstring_re(q.infos.service_name, service))
        if port is not None:
            res.append(q.port == port)
        if protocol is not None:
            if protocol != "tcp":
                raise ValueError(
                    "Protocols other than TCP are not supported " "in passive"
                )
        return cls.flt_and(*res)

    @classmethod
    def searchsvchostname(cls, hostname):
        return cls._searchstring_re(Query().infos.service_hostname, hostname)

    @classmethod
    def searchmac(cls, mac=None, neg=False):
        q = Query()
        res = q.recontype == "MAC_ADDRESS"
        if mac is not None:
            if isinstance(mac, utils.REGEXP_T):
                mac = re.compile(mac.pattern, mac.flags | re.I)
            else:
                mac = mac.lower()
            res &= cls._searchstring_re(q.value, mac, neg=neg)
        elif neg:
            return q.recontype != "MAC_ADDRESS"
        return res

    @classmethod
    def searchuseragent(cls, useragent=None, neg=False):
        if neg:
            raise ValueError(
                "searchuseragent([...], neg=True) is not " "supported in passive DB."
            )
        q = Query()
        res = (q.recontype == "HTTP_CLIENT_HEADER") & (q.source == "USER-AGENT")
        if useragent is None:
            return res
        return res & cls._searchstring_re(q.value, useragent)

    @classmethod
    def searchdns(cls, name=None, reverse=False, dnstype=None, subdomains=False):
        q = Query()
        res = q.recontype == "DNS_ANSWER"
        if name is not None:
            if subdomains:
                inarray = True
                if reverse:
                    req = q.infos.domaintarget
                else:
                    req = q.infos.domain
            else:
                inarray = False
                if reverse:
                    req = q.targetval
                else:
                    req = q.value
            if isinstance(name, list):
                if inarray:
                    res &= req.any(name)
                else:
                    res &= req.one_of(name)
            elif inarray:
                res &= cls._searchstring_re_inarray(req, name)
            else:
                res &= cls._searchstring_re(req, name)
        if dnstype is not None:
            res &= q.source.search("^%s-" % dnstype.upper())
        return res

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
        q = Query()
        res = (q.recontype == "SSL_SERVER") & (
            q.source == ("cacert" if cacert else "cert")
        )
        if keytype is not None:
            res &= q.infos.pubkey.type == keytype
        if md5 is not None:
            res &= cls._searchstring_re(q.infos.md5, md5.lower())
        if sha1 is not None:
            res &= cls._searchstring_re(q.infos.sha1, sha1.lower())
        if sha256 is not None:
            res &= cls._searchstring_re(q.infos.sha256, sha256.lower())
        if subject is not None:
            res &= cls._searchstring_re(q.infos.subject_text, subject)
        if issuer is not None:
            res &= cls._searchstring_re(q.infos.issuer_text, issuer)
        if self_signed is not None:
            res &= q.infos.self_signed == self_signed
        if pkmd5 is not None:
            res &= cls._searchstring_re(q.infos.pubkey.md5, pkmd5.lower())
        if pksha1 is not None:
            res &= cls._searchstring_re(q.infos.pubkey.sha1, pksha1.lower())
        if pksha256 is not None:
            res &= cls._searchstring_re(q.infos.pubkey.sha256, pksha256.lower())
        return res

    @classmethod
    def _searchja3(cls, query, value_or_hash):
        if not value_or_hash:
            return None
        key, value = cls._ja3keyvalue(value_or_hash)
        return cls._searchstring_re(
            query.value if key == "md5" else getattr(query.infos, key),
            value,
        )

    @classmethod
    def searchja3client(cls, value_or_hash=None):
        q = Query()
        base = (q.recontype == "SSL_CLIENT") & (q.source == "ja3")
        res = cls._searchja3(q, value_or_hash)
        if res is None:
            return base
        return base & res

    @classmethod
    def searchja3server(cls, value_or_hash=None, client_value_or_hash=None):
        q = Query()
        base = q.recontype == "SSL_SERVER"
        res = cls._searchja3(q, value_or_hash)
        if res is not None:
            base &= res
        if not client_value_or_hash:
            return base & q.source.search("^ja3-")
        key, value = cls._ja3keyvalue(client_value_or_hash)
        if key == "md5":
            return base & (q.source == ("ja3-%s" % value))
        return (
            base
            & q.source.search("^ja3-")
            & cls._searchstring_re(getattr(q.infos.client, key), client_value_or_hash)
        )

    @staticmethod
    def searchsshkey(keytype=None):
        q = Query()
        req = (q.recontype == "SSH_SERVER_HOSTKEY") & (q.source == "SSHv2")
        if keytype is None:
            return req
        return req & (q.infos.algo == "ssh-" + keytype)

    @staticmethod
    def searchbasicauth():
        q = Query()
        return (
            q.recontype.one_of(["HTTP_CLIENT_HEADER", "HTTP_CLIENT_HEADER_SERVER"])
            & q.source.one_of(["AUTHORIZATION", "PROXY-AUTHORIZATION"])
            & q.value.search("^Basic", flags=re.I)
        )

    @staticmethod
    def searchhttpauth():
        q = Query()
        return q.recontype.one_of(
            ["HTTP_CLIENT_HEADER", "HTTP_CLIENT_HEADER_SERVER"]
        ) & q.source.one_of(["AUTHORIZATION", "PROXY-AUTHORIZATION"])

    @staticmethod
    def searchftpauth():
        return Query().recontype.one_of(["FTP_CLIENT", "FTP_SERVER"])

    @staticmethod
    def searchpopauth():
        return Query().recontype.one_of(["POP_CLIENT", "POP_SERVER"])

    @classmethod
    def searchtcpsrvbanner(cls, banner):
        q = Query()
        return (q.recontype == "TCP_SERVER_BANNER") & cls._searchstring_re(
            q.value, banner
        )

    @staticmethod
    def searchtimeago(delta, neg=False, new=True):
        if not isinstance(delta, timedelta):
            delta = timedelta(seconds=delta)
        tstamp = (datetime.now() - delta).timestamp()
        req = getattr(Query(), "firstseen" if new else "lastseen")
        if neg:
            return req < tstamp
        return req >= tstamp

    @staticmethod
    def searchnewer(timestamp, neg=False, new=True):
        if isinstance(timestamp, datetime):
            timestamp = timestamp.timestamp()
        elif isinstance(timestamp, str):
            timestamp = utils.all2datetime(timestamp).timestamp()
        req = getattr(Query(), "firstseen" if new else "lastseen")
        if neg:
            return req <= timestamp
        return req > timestamp


class TinyDBAgent(TinyDB, DBAgent):

    """An Nmap-specific DB using TinyDB backend"""

    dbname = "agents"
    dbname_scans = "agents_scans"
    dbname_masters = "agents_masters"

    @property
    def db_scans(self):
        """The DB for scan files"""
        try:
            return self._db_scans
        except AttributeError:
            self._db_scans = TDB(
                os.path.join(self.basepath, "%s.json" % self.dbname_scans)
            )
            return self._db_scans

    @property
    def db_masters(self):
        """The DB for scan files"""
        try:
            return self._db_masters
        except AttributeError:
            self._db_masters = TDB(
                os.path.join(
                    self.basepath,
                    "%s.json" % self.dbname_masters,
                )
            )
            return self._db_masters

    def init(self):
        super().init()
        try:
            self.db_scans.drop_tables()
        except AttributeError:
            # TinyDB < 4
            self.db_scans.purge_tables()
            self.db_masters.purge_tables()
        else:
            self.db_masters.drop_tables()

    def _add_agent(self, agent):
        return self.db.insert(agent)

    def get_agent(self, agentid):
        res = self.db.get(doc_id=agentid)
        res["_id"] = res.doc_id
        return res

    def get_free_agents(self):
        return (x.doc_id for x in self.db.search(Query().scan == None))  # noqa: E711

    def get_agents_by_master(self, masterid):
        return (x.doc_id for x in self.db.search(Query().master == masterid))

    def get_agents(self):
        return (x.doc_id for x in self.db.search(self.flt_empty))

    def assign_agent(self, agentid, scanid, only_if_unassigned=False, force=False):
        q = Query()
        flt = []
        if only_if_unassigned:
            flt.append(q.scan == None)  # noqa: E711
        elif not force:
            flt.append(q.scan != False)  # noqa: E712
        if flt:
            flt = self.flt_and(*flt)
        else:
            flt = self.flt_empty
        self.db.update({"scan": scanid}, cond=flt, doc_ids=[agentid])
        agent = self.get_agent(agentid)
        if scanid is not None and scanid is not False and scanid == agent["scan"]:
            self.db_scans.update(
                add("agents", [agentid]),
                cond=~q.agents.any([agentid]),
                doc_ids=[scanid],
            )

    def unassign_agent(self, agentid, dont_reuse=False):
        agent = self.get_agent(agentid)
        scanid = agent.get("scan")
        if scanid is not None:

            def _pullagent(agentid):
                def _transform(doc):
                    doc["agents"].remove(agentid)

                return _transform

            self.db_scans.update(
                _pullagent(agentid),
                cond=Query().agents.any([agentid]),
                doc_ids=[scanid],
            )
        if dont_reuse:
            self.assign_agent(agentid, False, force=True)
        else:
            self.assign_agent(agentid, None, force=True)

    def _del_agent(self, agentid):
        return self.db.remove(doc_ids=[agentid])

    def _add_scan(self, scan):
        return self.db_scans.insert(scan)

    def get_scan(self, scanid):
        scan = self.db_scans.get(doc_id=scanid)
        scan["_id"] = scan.doc_id
        if scan.get("lock") is not None:
            scan["lock"] = UUID(bytes=self.from_binary(scan["lock"]))
        if "target_info" not in scan:
            target = self.get_scan_target(scanid)
            if target is not None:
                target_info = target.target.infos
                self.db_scans.update({"target_info": target_info}, doc_ids=[scanid])
                scan["target_info"] = target_info
        return scan

    def _get_scan_target(self, scanid):
        scan = self.db_scans.get(doc_id=scanid)
        return None if scan is None else self.from_binary(scan["target"])

    def _lock_scan(self, scanid, oldlockid, newlockid):
        """Change lock for scanid from oldlockid to newlockid. Returns the new
        scan object on success, and raises a LockError on failure.

        """
        if oldlockid is not None:
            oldlockid = self.to_binary(oldlockid)
        if newlockid is not None:
            newlockid = self.to_binary(newlockid)
        # TinyDB .update() will not use both cond= and doc_id=, so ...
        scan = self.db_scans.get(
            doc_id=scanid,
        )
        if (scan or {}).get("lock") != oldlockid:
            scan = None
        if scan is not None:
            # ... we need to do this instead
            self.db_scans.update(
                {"lock": newlockid, "pid": os.getpid()},
                # cond=q.lock == oldlockid,
                doc_ids=[scanid],
            )
            scan = self.db_scans.get(
                # TinyDB .get() will not use both cond= and doc_id=, so...
                # cond=q.lock == newlockid,
                doc_id=scanid,
            )
            # ... we need to do this instead
            if scan.get("lock") != newlockid:
                scan = None
        if scan is None:
            if oldlockid is None:
                raise LockError("Cannot acquire lock for %r" % scanid)
            if newlockid is None:
                raise LockError("Cannot release lock for %r" % scanid)
            raise LockError(
                "Cannot change lock for %r from "
                "%r to %r" % (scanid, oldlockid, newlockid)
            )
        if "target_info" not in scan:
            target = self.get_scan_target(scanid)
            if target is not None:
                target_info = target.target.infos
                self.db_scans.update({"target_info": target_info}, doc_ids=[scanid])
                scan["target_info"] = target_info
        if scan["lock"] is not None:
            scan["lock"] = self.from_binary(scan["lock"])
        scan["_id"] = scan.doc_id
        return scan

    def get_scans(self):
        return (x.doc_id for x in self.db_scans.search(self.flt_empty))

    def _update_scan_target(self, scanid, target):
        return self.db_scans.update({"target": target}, doc_ids=[scanid])

    def incr_scan_results(self, scanid):
        return self.db_scans.update(increment("results"), doc_ids=[scanid])

    def _add_master(self, master):
        return self.db_masters.insert(master)

    def get_master(self, masterid):
        return self.db_masters.get(doc_id=masterid)

    def get_masters(self):
        return (x.doc_id for x in self.db_masters.search(self.flt_empty))


# TinyDB update operations


def inc_op(key, value=1):
    subkeys = key.split(".")
    lastkey = subkeys.pop()

    def _transform(doc):
        for subkey in subkeys:
            doc = doc.setdefault(subkey, {})
        doc[lastkey] = doc.get(lastkey, 0) + value

    return _transform


def add_to_set_op(key, value):
    subkeys = key.split(".")
    lastkey = subkeys.pop()

    def _transform(doc):
        for subkey in subkeys:
            doc = doc.setdefault(subkey, {})
        doc = doc.setdefault(lastkey, [])
        if value not in doc:
            doc.append(value)

    return _transform


def min_op(key, value):
    if value is None:
        return lambda doc: None

    subkeys = key.split(".")
    lastkey = subkeys.pop()

    def _transform(doc):
        for subkey in subkeys:
            doc = doc.setdefault(subkey, {})
        doc[lastkey] = min(doc.get(lastkey, value), value)

    return _transform


def max_op(key, value):
    if value is None:
        return lambda doc: None

    subkeys = key.split(".")
    lastkey = subkeys.pop()

    def _transform(doc):
        for subkey in subkeys:
            doc = doc.setdefault(subkey, {})
        doc[lastkey] = max(doc.get(lastkey, value), value)

    return _transform


def combine_ops(*ops):
    def _transform(doc):
        for op in ops:
            op(doc)

    return _transform


class TinyDBFlow(TinyDB, DBFlow, metaclass=DBFlowMeta):

    """A Flow-specific DB using TinyDB backend"""

    dbname = "flows"

    datefields = [
        "firstseen",
        "lastseen",
        "times.start",
    ]

    # This represents the kinds of metadata that are defined in flow.META_DESC
    # Each kind is associated with an aggregation operator used for
    # insertion in db.
    meta_kinds = {
        "keys": add_to_set_op,
        "counters": inc_op,
    }

    operators = {
        ":": operator.eq,
        "=": operator.eq,
        "==": operator.eq,
        "!=": operator.ne,
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
        "=~": "regex",
    }

    @staticmethod
    def _get_flow_key(rec):
        """Returns a query that matches the flow"""
        q = Query()
        insertspec = {
            "src_addr": rec["src_addr"],
            "dst_addr": rec["dst_addr"],
            "proto": rec["proto"],
            "schema_version": flow.SCHEMA_VERSION,
        }
        res = (
            (q.src_addr == rec["src_addr"])
            & (q.dst_addr == rec["dst_addr"])
            & (q.proto == rec["proto"])
            & (q.schema_version == flow.SCHEMA_VERSION)
        )
        if rec["proto"] in ["udp", "tcp"]:
            insertspec["dport"] = rec["dport"]
            res &= q.dport == rec["dport"]
        elif rec["proto"] == "icmp":
            insertspec["type"] = rec["type"]
            res &= q.type == rec["type"]
        return res, insertspec

    @classmethod
    def _update_timeslots(cls, updatespec, insertspec, rec):
        """
        If configured, adds timeslots in `updatespec`.
        config.FLOW_TIME enables timeslots.
        if config.FLOW_TIME_FULL_RANGE is set, a flow is linked to every
        timeslots between its start_time and end_time.
        Otherwise, it is only linked to the timeslot corresponding to its
        start_time.
        """
        if config.FLOW_TIME:
            if config.FLOW_TIME_FULL_RANGE:
                generator = cls._get_timeslots(
                    rec["start_time"],
                    rec["end_time"],
                )
            else:
                generator = cls._get_timeslot(
                    rec["start_time"], config.FLOW_TIME_PRECISION, config.FLOW_TIME_BASE
                )
            for tslot in generator:
                tslot = dict(tslot)
                tslot["start"] = tslot["start"].timestamp()
                updatespec.append(add_to_set_op("times", tslot))
                lst = insertspec.setdefault("times", [])
                if tslot not in lst:
                    lst.append(tslot)

    def any2flow(self, bulk, name, rec):
        """Takes a parsed *.log line entry and upserts it (bulk is not used in
        this backend).  It is responsible for metadata processing (all
        but conn.log files).

        """
        # Convert addr
        rec["src_addr"] = self.ip2internal(rec["src"])
        rec["dst_addr"] = self.ip2internal(rec["dst"])
        # Insert in flows
        findspec, insertspec = self._get_flow_key(rec)
        updatespec = [
            min_op("firstseen", rec["start_time"].timestamp()),
            max_op("lastseen", rec["end_time"].timestamp()),
            inc_op("meta.%s.count" % name),
        ]
        insertspec.update(
            {
                "firstseen": rec["start_time"].timestamp(),
                "lastseen": rec["end_time"].timestamp(),
                "meta.%s.count" % name: 1,
            }
        )

        # metadata storage can be disabled.
        if config.FLOW_STORE_METADATA:
            for kind, op in self.meta_kinds.items():
                for key, value in self.meta_desc[name].get(kind, {}).items():
                    if not rec[value]:
                        continue
                    if "%s.%s.%s" % (name, kind, key) in flow.META_DESC_ARRAYS:
                        for val in rec[value]:
                            updatespec.append(op("meta.%s.%s" % (name, key), val))
                            if op is add_to_set_op:
                                lst = (
                                    insertspec.setdefault("meta", {})
                                    .setdefault(name, {})
                                    .setdefault(key, [])
                                )
                                if val not in lst:
                                    lst.append(val)
                            elif op is inc_op:
                                value = (
                                    insertspec.setdefault("meta", {})
                                    .setdefault(name, {})
                                    .get(key, 0)
                                )
                                insertspec["meta"][name][key] = value + val
                            else:
                                raise ValueError("Operation not supported [%r]" % op)
                    else:
                        updatespec.append(op("meta.%s.%s" % (name, key), rec[value]))
                        if op is add_to_set_op:
                            lst = (
                                insertspec.setdefault("meta", {})
                                .setdefault(name, {})
                                .setdefault(key, [])
                            )
                            if rec[value] not in lst:
                                lst.append(rec[value])
                        elif op is inc_op:
                            curval = (
                                insertspec.setdefault("meta", {})
                                .setdefault(name, {})
                                .get(key, 0)
                            )
                            insertspec["meta"][name][key] = curval + rec[value]
                        else:
                            raise ValueError("Operation not supported [%r]" % op)

        self._update_timeslots(updatespec, insertspec, rec)

        if self.db.get(findspec) is None:
            self.db.insert(insertspec)
        else:
            self.db.update(combine_ops(*updatespec), cond=findspec)

    @staticmethod
    def start_bulk_insert():
        """Bulks are not used with TinyDB."""
        return None

    @staticmethod
    def bulk_commit(bulk):
        """Bulks are not used with TinyDB."""
        assert bulk is None

    def conn2flow(self, bulk, rec):
        """Takes a parsed conn.log line entry and upserts it (bulk is not used
        in this backend).

        """
        rec["src_addr"] = self.ip2internal(rec["src"])
        rec["dst_addr"] = self.ip2internal(rec["dst"])
        findspec, insertspec = self._get_flow_key(rec)

        updatespec = [
            min_op("firstseen", rec["start_time"].timestamp()),
            max_op("lastseen", rec["end_time"].timestamp()),
            inc_op("cspkts", value=rec["orig_pkts"]),
            inc_op("scpkts", value=rec["resp_pkts"]),
            inc_op("csbytes", value=rec["orig_ip_bytes"]),
            inc_op("scbytes", value=rec["resp_ip_bytes"]),
            inc_op("count"),
        ]
        insertspec.update(
            {
                "firstseen": rec["start_time"].timestamp(),
                "lastseen": rec["end_time"].timestamp(),
                "cspkts": rec["orig_pkts"],
                "scpkts": rec["resp_pkts"],
                "csbytes": rec["orig_ip_bytes"],
                "scbytes": rec["resp_ip_bytes"],
                "count": 1,
            }
        )

        self._update_timeslots(updatespec, insertspec, rec)

        if rec["proto"] in ["udp", "tcp"]:
            updatespec.append(add_to_set_op("sports", rec["sport"]))
            insertspec["sports"] = [rec["sport"]]
        elif rec["proto"] == "icmp":
            updatespec.append(add_to_set_op("codes", rec["code"]))
            insertspec["codes"] = [rec["code"]]

        if self.db.get(findspec) is None:
            self.db.insert(insertspec)
        else:
            self.db.update(combine_ops(*updatespec), cond=findspec)

    def flow2flow(self, bulk, rec):
        """Takes an entry coming from Netflow or Argus and upserts it (bulk is
        not used in this backend)

        """
        rec["src_addr"] = self.ip2internal(rec["src"])
        rec["dst_addr"] = self.ip2internal(rec["dst"])
        findspec, insertspec = self._get_flow_key(rec)

        updatespec = [
            min_op("firstseen", rec["start_time"].timestamp()),
            max_op("lastseen", rec["end_time"].timestamp()),
            inc_op("cspkts", value=rec["cspkts"]),
            inc_op("scpkts", value=rec["scpkts"]),
            inc_op("csbytes", value=rec["csbytes"]),
            inc_op("scbytes", value=rec["scbytes"]),
            inc_op("count"),
        ]
        insertspec.update(
            {
                "firstseen": rec["start_time"].timestamp(),
                "lastseen": rec["end_time"].timestamp(),
                "cspkts": rec["cspkts"],
                "scpkts": rec["scpkts"],
                "csbytes": rec["csbytes"],
                "scbytes": rec["scbytes"],
                "count": 1,
            }
        )

        self._update_timeslots(updatespec, insertspec, rec)

        if rec["proto"] in ["udp", "tcp"]:
            updatespec.append(add_to_set_op("sports", rec["sport"]))
            lst = insertspec.setdefault("sports", [])
            if rec["sport"] not in lst:
                lst.append(rec["sport"])
        elif rec["proto"] == "icmp":
            updatespec.append(add_to_set_op("codes", rec["code"]))
            lst = insertspec.setdefault("codes", [])
            if rec["code"] not in lst:
                lst.append(rec["code"])

        if self.db.get(findspec) is None:
            self.db.insert(insertspec)
        else:
            self.db.update(combine_ops(*updatespec), cond=findspec)

    def _get(self, flt, orderby=None, **kargs):
        """
        Returns an iterator over flows honoring the given filter
        with the given options.
        """
        sort = kargs.get("sort")
        if orderby == "dst":
            sort = [("dst_addr", 1)]
        elif orderby == "src":
            sort = [("src_addr", 1)]
        elif orderby == "flow":
            sort = [("dport", 1), ("proto", 1)]
        if sort is not None:
            kargs["sort"] = sort
        elif orderby:
            raise ValueError("Unsupported orderby (should be 'src', 'dst' or 'flow')")
        for f in self._db_get(flt, **kargs):
            f = deepcopy(f)
            f["_id"] = f.doc_id
            try:
                f["src_addr"] = self.internal2ip(f["src_addr"])
                f["dst_addr"] = self.internal2ip(f["dst_addr"])
            except KeyError:
                pass
            yield f

    def count(self, flt):
        """
        Returns a dict {'client': nb_clients, 'servers': nb_servers',
        'flows': nb_flows} according to the given filter.
        """
        sources = set()
        destinations = set()
        flows = 0
        for flw in self.get(flt):
            sources.add(flw["src_addr"])
            destinations.add(flw["dst_addr"])
            flows += 1
        return {"clients": len(sources), "servers": len(destinations), "flows": flows}

    @staticmethod
    def should_switch_hosts(flw_id, flw):
        """
        Returns True if flow hosts should be switched, False otherwise.
        """
        if len(flw["dports"]) <= 5:
            return False

        # Try to avoid reversing scans
        if flw_id[2] == "tcp":
            ratio = 0
            divisor = 0
            if flw["cspkts"] > 0:
                ratio += flw["csbytes"] / float(flw["cspkts"])
                divisor += 1
            if flw["scpkts"] > 0:
                ratio += flw["scbytes"] / float(flw["scpkts"])
                divisor += 1

            avg = ratio / float(divisor)
            if avg < 50:
                # TCP segments were almost empty, which most of the time
                # corresponds to an active scan.
                return False

        return True

    def cleanup_flows(self):
        q = Query()
        res = {}
        flt = q.sports.test(lambda val: len(val) == 1) & (q.dport > 128)
        for flw in self.db.search(flt):
            rec = res.setdefault(
                (flw["src_addr"], flw["dst_addr"], flw["proto"], flw["sports"][0]), {}
            )
            rec.setdefault("_ids", set()).add(flw.doc_id)
            rec.setdefault("dports", set()).add(flw["dport"])
            for fld in ["cspkts", "scpkts", "csbytes", "scbytes", "count"]:
                rec[fld] = rec.get(fld, 0) + flw.get(fld, 0)
            for fld, op in [("firstseen", min), ("lastseen", max)]:
                if fld in rec:
                    value = rec[fld]
                    rec[fld] = op(flw.get(fld, value), value)
                elif fld in flw:
                    rec[fld] = flw[fld]
            lst_times = rec.setdefault("times", [])
            for tslot in flw["times"]:
                if tslot not in lst_times:
                    lst_times.append(tslot)
        counter = 0
        for flw_id, flw in res.items():
            if not self.should_switch_hosts(flw_id, flw):
                continue
            new_rec = {
                "src_addr": flw_id[1],
                "dst_addr": flw_id[0],
                "proto": flw_id[2],
                "dport": flw_id[3],
            }
            findspec, insertspec = self._get_flow_key(new_rec)
            updatespec = [
                min_op("firstseen", flw.get("firstseen")),
                max_op("lastseen", flw.get("lastseen")),
                inc_op("cspkts", value=flw["scpkts"]),
                inc_op("scpkts", value=flw["cspkts"]),
                inc_op("csbytes", value=flw["scbytes"]),
                inc_op("scbytes", value=flw["csbytes"]),
                inc_op("count", value=flw["count"]),
            ]
            insertspec.update(
                {
                    "firstseen": flw.get("firstseen"),
                    "lastseen": flw.get("lastseen"),
                    "cspkts": flw["scpkts"],
                    "scpkts": flw["cspkts"],
                    "csbytes": flw["scbytes"],
                    "scbytes": flw["csbytes"],
                    "count": flw["count"],
                }
            )
            for sport in flw["dports"]:
                updatespec.append(add_to_set_op("sports", sport))
            removespec = list(flw["_ids"])
            if config.FLOW_TIME:
                for tval in flw["times"]:
                    updatespec.append(add_to_set_op("times", tval))
            utils.LOGGER.debug(
                "Switch flow hosts: %s (%d) -- %s --> %s (%s)",
                self.internal2ip(flw_id[0]),
                flw_id[3],
                flw_id[2],
                self.internal2ip(flw_id[1]),
                ",".join(str(elt) for elt in flw["dports"]),
            )
            # upsert won't work with operations
            if self.db.get(findspec) is None:
                new_rec.update(insertspec)
                self.db.insert(new_rec)
            else:
                self.db.update(combine_ops(*updatespec), findspec)
            self.db.remove(doc_ids=removespec)
            counter += len(removespec)
        utils.LOGGER.debug("%d flows switched.", counter)

    @classmethod
    def _flt_from_clause_addr(cls, clause):
        """Returns a filter from the given clause which deals with addresses."""
        if clause["attr"] == "addr":
            res = cls.flt_or(
                *(
                    cls._flt_from_clause_addr(dict(clause, attr=subval, neg=False))
                    for subval in ["src_addr", "dst_addr"]
                )
            )
        else:
            if clause["operator"] == "regex":
                start, stop = (
                    cls.ip2internal(val) for val in utils.net2range(clause["value"])
                )
                res = cls._base_from_attr(
                    clause["attr"],
                    op=lambda val: (start <= val) & (val <= stop),
                    array_mode=clause["array_mode"],
                )
            else:
                res = cls._base_from_attr(
                    clause["attr"],
                    op=lambda val: clause["operator"](
                        val,
                        cls.ip2internal(clause["value"]),
                    ),
                    array_mode=clause["array_mode"],
                )
        if clause["neg"]:
            # pylint: disable=invalid-unary-operand-type
            return ~res
        return res

    @classmethod
    def _flt_from_clause_any(cls, clause):
        """Returns a filter from the given clause which does not deal with
        addresses.

        """
        if clause["len_mode"]:
            value = clause["value"]
            res = cls._base_from_attr(
                clause["attr"],
                op=lambda val: clause["operator"](val, value),
                array_mode=clause["array_mode"],
                len_mode=clause["len_mode"],
            )
        elif clause["operator"] == "regex":
            res = cls._base_from_attr(
                clause["attr"],
                op=lambda val: val.search(clause["value"]),
                array_mode=clause["array_mode"],
            )
        else:
            value = clause["value"]
            if clause["attr"] in cls.datefields:
                value = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").timestamp()
            res = cls._base_from_attr(
                clause["attr"],
                op=lambda val: clause["operator"](val, value),
                array_mode=clause["array_mode"],
            )
        if clause["neg"]:
            return ~res
        return res

    @classmethod
    def _get_array_attrs(cls, attr):
        base = []
        res = []
        cur = []
        subflts = attr.split(".")
        for subattr in subflts[:-1]:
            base.append(subattr)
            cur.append(subattr)
            curattr = ".".join(base)
            if curattr in cls.list_fields:
                res.append(cur)
                cur = []
        return res, cur + [subflts[-1]]

    @classmethod
    def _base_from_attr(cls, attr, op, array_mode=None, len_mode=False):
        array_fields, final_fields = cls._get_array_attrs(attr)
        final = Query()
        for subfld in final_fields:
            final = getattr(final, subfld)
        if op == "exists":
            final = final.exists()
        elif attr in cls.list_fields:
            if len_mode:
                final = final.test(lambda vals: op(len(vals)))
            elif array_mode is None or array_mode.lower() == "any":
                final = final.test(lambda vals: any(op(val) for val in vals))
            elif array_mode.lower() == "all":
                final = final.test(lambda vals: all(op(val) for val in vals))
            else:
                raise ValueError("Invalid array_mode %r" % array_mode)
            array_mode = None
        else:
            final = op(final)
        if not array_fields:
            return final
        res = []
        for array in array_fields:
            base = Query()
            for subfld in array:
                base = getattr(base, subfld)
            res.append(base)
        if array_mode is None or array_mode.lower() == "any":
            cur = res.pop().any(final)
        elif array_mode.lower() == "all":
            cur = res.pop().all(final)
        else:
            raise ValueError("Invalid array_mode %r" % array_mode)
        while res:
            cur = res.pop().any(cur)
        return cur

    @classmethod
    def _fix_operator(cls, op):
        try:
            return cls.operators[op]
        except KeyError:
            raise ValueError("Unknown operator %r" % op)

    @staticmethod
    def _fix_attr_name(attr):
        return {
            "src.addr": "src_addr",
            "dst.addr": "dst_addr",
        }.get(attr, attr)

    @classmethod
    def flt_from_clause(cls, clause):
        q = Query()
        clause["attr"] = cls._fix_attr_name(clause["attr"])
        if clause["operator"] is None:
            if clause["attr"] == "addr":
                res = q.src_addr.exists() | q.dst_addr.exists()
            else:
                res = cls._base_from_attr(
                    clause["attr"],
                    op="exists",
                    array_mode=clause["array_mode"],
                )
            if clause["neg"]:
                return ~res
            return res
        if clause["len_mode"]:
            clause["value"] = int(clause["value"])
        clause["operator"] = cls._fix_operator(clause["operator"])
        if clause["attr"] in ["addr", "src_addr", "dst_addr"]:
            return cls._flt_from_clause_addr(clause)
        return cls._flt_from_clause_any(clause)

    @classmethod
    def flt_from_query(cls, query):
        """
        Returns a MongoDB filter from the given query object.
        """
        res = []
        for and_clause in query.clauses:
            res_or = []
            for or_clause in and_clause:
                res_or.append(cls.flt_from_clause(or_clause))
            if res_or:
                res.append(cls.flt_or(*res_or))
        if res:
            return cls.flt_and(*res)
        return cls.flt_empty

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
        """Overloads from_filters method from TinyDB.

        It transforms a flow.Query object returned by
        super().from_filters into a TinyDB query and returns it.

        Note: limit, skip, orderby, mode, timeline are IGNORED. They
        are present only for compatibility reasons.
        """
        q = Query()
        query = super().from_filters(
            filters,
            limit=limit,
            skip=skip,
            orderby=orderby,
            mode=mode,
            timeline=timeline,
        )
        flt = cls.flt_from_query(query)
        times_filter = []
        if after:
            times_filter.append(q.start >= after)
        if before:
            times_filter.append(q.start < before)
        if precision:
            times_filter.append(q.duration == precision)
        if times_filter:
            flt &= q.times.any(cls.flt_and(*times_filter))
        return flt

    def flow_daily(self, precision, flt, after=None, before=None):
        """
        Returns a generator within each element is a dict
        {
            flows: [("proto/dport", count), ...]
            time_in_day: time
        }.
        """
        q = Query()
        timeflt = q.duration == precision
        if after:
            timeflt &= q.start >= after.timestamp()
        if before:
            timeflt &= q.start < before.timestamp()
        try:
            if flt == self.flt_empty:
                flt = q.times.any(timeflt)
            else:
                flt &= q.times.any(timeflt)
        except ValueError:
            # Hack for a bug in TinyDB: "ValueError: Query has no
            # path" can be raised when comparing empty queries
            if repr(flt) != "Query()":
                raise
            flt = q.times.any(timeflt)
        res = {}
        for flw in self.get(flt):
            for tslot in flw.get("times", []):
                if not timeflt(tslot):
                    continue
                dtm = utils.all2datetime(tslot["start"])
                res.setdefault((dtm.hour, dtm.minute, dtm.second), []).append(
                    {
                        "proto": flw.get("proto"),
                        "dport": flw.get("dport"),
                        "type": flw.get("type"),
                    }
                )
        for entry in sorted(res):
            fields = res[entry]
            flows = {}
            for field in fields:
                if field.get("proto") in ["tcp", "udp"]:
                    entry_name = "%(proto)s/%(dport)d" % field
                elif field.get("type") is not None:
                    entry_name = "%(proto)s/%(type)d" % field
                else:
                    entry_name = field["proto"]
                flows[entry_name] = flows.get(entry_name, 0) + 1
            yield {
                "flows": list(flows.items()),
                "time_in_day": time(hour=entry[0], minute=entry[1], second=entry[2]),
            }

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
                collected: (
                    (collect_1_value, collect_2_value, ...),
                    ...
                )
            }
        Collected fields are unique.
        """
        if flt is None:
            flt = self.flt_empty
        collect_fields = collect_fields or []
        sum_fields = sum_fields or []

        # Translation dictionary for special fields
        special_fields = {
            "src.addr": "src_addr",
            "dst.addr": "dst_addr",
            "sport": "sports",
        }
        fields = [special_fields.get(fld, fld) for fld in fields]
        collect_fields = [special_fields.get(fld, fld) for fld in collect_fields]
        sum_fields = [special_fields.get(fld, fld) for fld in sum_fields]
        all_fields = list(set(fields).union(collect_fields).union(sum_fields))

        for fields_list in (fields, collect_fields, sum_fields):
            for f in fields_list:
                if f not in ["src_addr", "dst_addr"]:
                    flow.validate_field(f)

        def _outputproc(val):
            return val

        def _extractor(flt):
            for rec in self._get(flt, limit=limit, skip=skip, fields=all_fields):
                # values = (
                #     self._generate_field_values(rec, field)
                #     for field in fields
                # )
                if sum_fields:
                    count = sum(
                        sum(self._generate_field_values(rec, field))
                        for field in sum_fields
                    )
                else:
                    count = 1

                def _get_one(generator):
                    try:
                        return next(generator)
                    except StopIteration:
                        return None

                collected = tuple(
                    tuple(set(self._generate_field_values(rec, field)))
                    if field in self.list_fields
                    else _get_one(self._generate_field_values(rec, field))
                    for field in collect_fields
                )
                for val in cartesian_prod(
                    *(self._generate_field_values(rec, field) for field in fields)
                ):
                    yield (val, count, collected)

        def _newflt(field):
            return self._search_field_exists(field)

        res = {}
        flt &= self.flt_and(*(_newflt(field) for field in all_fields))
        for key, count, collected in _extractor(flt):
            if key in res:
                curres = res[key]
                curres[0] += count
                curres[1].add(collected)
            else:
                res[key] = [count, set([collected])]
        result = sorted(
            (
                {
                    "fields": key,
                    "count": val[0],
                    "collected": tuple(tuple(col) for col in val[1]),
                }
                for key, val in res.items()
            ),
            key=lambda elt: elt["count"],
            reverse=True,
        )
        if topnbr is not None:
            return result[:topnbr]
        return result
