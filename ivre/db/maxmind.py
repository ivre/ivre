#! /usr/bin/env python

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

"""This sub-module contains functions to interact with the MaxMind
files.

"""


import codecs
from functools import reduce
import os
import struct


from builtins import object, range
from future.utils import viewitems


from ivre import config, utils
from ivre.db import DBData


class MaxMindFileIter(object):

    """Iterator for MaxMindFile"""

    def __init__(self, base):
        self.base = base
        self.current = []
        self.nextval = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.nextval is None:
            raise StopIteration()
        node_no = 0
        for i in range(96 if self.base.ip_version == 4 else 0, 128):
            try:
                flag = self.current[i]
            except IndexError:
                flag = self.nextval
                self.current.append(self.nextval)
                self.nextval = 0
            next_node_no = self.base.read_record(node_no, flag)
            if next_node_no == 0:
                raise Exception('Invalid file format')
            elif next_node_no >= self.base.node_count:
                pos = (next_node_no - self.base.node_count -
                       self.base.DATA_SECTION_SEPARATOR_SIZE)
                curvalinf = int(''.join(str(p) for p in self.current) +
                                '0' * (128 - len(self.current)), 2)
                curvalsup = int(''.join(str(p) for p in self.current) +
                                '1' * (128 - len(self.current)), 2)
                try:
                    while self.current.pop():
                        pass
                except IndexError:
                    self.nextval = None
                else:
                    self.current.append(1)
                return (curvalinf, curvalsup,
                        self.base.decode(pos, self.base.data_section_start)[1])
            node_no = next_node_no


class EmptyMaxMindFile(object):

    """Stub to replace MaxMind databases parsers. Used when a file is
missing to emit a warning message and return empty results.

    """

    def __init__(self, _):
        utils.LOGGER.warning("Cannot find Maxmind database files")

    def lookup(self, _):
        return {}


class MaxMindFile(object):

    """Parser for MaxMind databases.

    Code copied and adapted from
    https://github.com/yhirose/maxminddb/blob/master/lib/maxminddb.rb

    """

    METADATA_BEGIN_MARKER = b'\xab\xcd\xefMaxMind.com'
    DATA_SECTION_SEPARATOR_SIZE = 16
    SIZE_BASE_VALUES = [0, 29, 285, 65821]
    POINTER_BASE_VALUES = [0, 0, 2048, 526336]

    def __init__(self, path):
        self.path = path
        self._data = None
        pos = (self.data.rindex(self.METADATA_BEGIN_MARKER) +
               len(self.METADATA_BEGIN_MARKER))
        metadata = self.metadata = self.decode(pos, 0)[1]
        self.ip_version = metadata['ip_version']
        self.node_count = metadata['node_count']
        self.node_byte_size = metadata['record_size'] * 2 // 8
        self.search_tree_size = self.node_count * self.node_byte_size
        self.data_section_start = (self.search_tree_size +
                                   self.DATA_SECTION_SEPARATOR_SIZE)

    @property
    def data(self):
        if self._data is None:
            with open(self.path, 'rb') as fdesc:
                self._data = fdesc.read()
        return self._data

    def read_byte(self, pos):
        return ord(self.data[pos:pos + 1])

    def read_value(self, pos, size):
        return reduce(
            lambda x, y: (x << 8) + y,
            struct.unpack(
                '%dB' % size,
                self.data[pos:pos + size],
            ),
            0,
        )

    def decode(self, pos, base_pos):
        ctrl = ord(self.data[pos + base_pos:pos + base_pos + 1])
        pos += 1
        type_ = ctrl >> 5
        if type_ == 1:
            # pointer
            size = ((ctrl >> 3) & 0x3) + 1
            val1 = ctrl & 0x7
            val2 = self.read_value(pos + base_pos, size)
            pointer = ((val1 << (8 * size)) + val2 +
                       self.POINTER_BASE_VALUES[size])
            return pos + size, self.decode(pointer, base_pos)[1]
        if type_ == 0:
            # extended type
            type_ = 7 + self.read_byte(pos + base_pos)
            pos += 1
        size = ctrl & 0x1f
        if size >= 29:
            byte_size = size - 29 + 1
            val = self.read_value(pos + base_pos, byte_size)
            pos += byte_size
            size = val + self.SIZE_BASE_VALUES[byte_size]
        if type_ == 2:
            # utf8
            val = self.data[
                pos + base_pos:pos + base_pos + size
            ].decode('utf-8')
            pos += size
        elif type_ in [3, 15]:
            # double
            # float
            val = struct.unpack(
                {3: '>d', 15: '>f'}[type_],
                self.data[pos + base_pos:pos + base_pos + size],
            )[0]
            pos += size
        elif type_ == 4:
            # bytes
            val = self.data[pos + base_pos:pos + base_pos + size]
            pos += size
        elif type_ in [5, 6, 9, 10]:
            # unsigned 16-bit int
            # unsigned 32-bit int
            # unsigned 64-bit int
            # unsigned 128-bit int
            val = self.read_value(pos + base_pos, size)
            pos += size
        elif type_ == 7:
            # map
            val = {}
            for _ in range(size):
                pos, k = self.decode(pos, base_pos)
                pos, v = self.decode(pos, base_pos)
                val[k] = v
        elif type_ == 8:
            # signed 32-bit int
            v1 = struct.unpack(
                '>i', self.data[pos + base_pos:pos + base_pos + size]
            )[0]
            bits = size * 8
            val = (v1 & ~(1 << bits)) - (v1 & (1 << bits))
            pos += size
        elif type_ == 11:
            # array
            val = []
            for _ in range(size):
                pos, v = self.decode(pos, base_pos)
                val.append(v)
        elif type_ == 12:
            # data cache container
            raise Exception('TODO type == 12 (data cache container)')
        elif type_ == 13:
            # end marker
            val = None
        elif type_ == 14:
            # boolean
            val = bool(size)
        else:
            # unknown
            raise Exception('TODO type == %d (unknown)' % type_)
        return pos, val

    def read_record(self, node_no, flag):
        rec_byte_size = self.node_byte_size // 2
        pos = self.node_byte_size * node_no
        middle = (self.read_byte(pos + rec_byte_size)
                  if self.node_byte_size % 2 else 0)
        if flag == 0:  # left
            val = self.read_value(pos, rec_byte_size)
            val += ((middle & 0xf0) << 20) if middle else 0
        else:  # right
            val = self.read_value(pos + self.node_byte_size - rec_byte_size,
                                  rec_byte_size)
            val += ((middle & 0xf) << 24) if middle else 0
        return val

    def __repr__(self):
        return '<%s from %s>' % (self.__class__.__name__, self.path)

    def lookup(self, ip):
        node_no = 0
        addr = utils.force_ip2int(ip)
        for i in range(96 if self.ip_version == 4 else 0, 128):
            flag = (addr >> (127 - i)) & 1
            next_node_no = self.read_record(node_no, flag)
            if next_node_no == 0:
                raise Exception('Invalid file format')
            elif next_node_no >= self.node_count:
                pos = (next_node_no - self.node_count -
                       self.DATA_SECTION_SEPARATOR_SIZE)
                return self.decode(pos, self.data_section_start)[1]
            else:
                node_no = next_node_no
        raise Exception('Invalid file format')

    def __iter__(self):
        return MaxMindFileIter(self)

    @staticmethod
    def _get_fields(rec, fields):
        for field in fields:
            val = rec
            for subfield in field.split('->'):
                try:
                    val = val[subfield]
                except TypeError:
                    try:
                        subfield = int(subfield)
                    except ValueError:
                        val = None
                        break
                    try:
                        val = val[subfield]
                    except IndexError:
                        val = None
                        break
                except KeyError:
                    val = None
                    break
            yield val

    def _get_ranges(self, fields):
        gen = iter(self)
        start, stop, rec = next(gen)
        rec = tuple(self._get_fields(rec, fields))
        for n_start, n_stop, n_rec in gen:
            n_rec = tuple(self._get_fields(n_rec, fields))
            if n_start <= stop + 1 and n_rec == rec:
                stop = n_stop
            else:
                yield (start, stop) + rec
                start, stop, rec = n_start, n_stop, n_rec
        yield (start, stop) + rec

    def get_ranges(self, fields, cond=None):
        for rec in self._get_ranges(fields):
            if cond is None or cond(rec):
                yield rec


class MaxMindDBData(DBData):

    LANG = "en"

    AS_KEYS = {
        "autonomous_system_number": "as_num",
        "autonomous_system_organization": "as_name",
    }

    @property
    def db_asn(self):
        try:
            return self._db_asn
        except AttributeError:
            self._db_asn = EmptyMaxMindFile("ASN")
            return self._db_asn

    @property
    def db_city(self):
        try:
            return self._db_city
        except AttributeError:
            self._db_city = EmptyMaxMindFile("City")
            return self._db_city

    @property
    def db_country(self):
        try:
            return self._db_country
        except AttributeError:
            self._db_country = EmptyMaxMindFile("Country")
            return self._db_country

    def __init__(self, basepath):
        for fname in os.listdir(basepath):
            if fname.endswith('.mmdb'):
                subdb = MaxMindFile(os.path.join(basepath, fname))
                name = subdb.metadata['database_type'].lower()
                if name.startswith('geolite2-'):
                    name = name[9:]
                setattr(self, "_db_%s" % name, subdb)

    def as_byip(self, addr):
        return dict(
            (self.AS_KEYS.get(key, key), value)
            for key, value in viewitems(self.db_asn.lookup(addr))
        )

    def location_byip(self, addr):
        raw = self.db_city.lookup(addr)
        result = {}
        sub = raw.get('subdivisions')
        if sub:
            result['region_code'] = tuple(v.get('iso_code') for v in sub)
            result['region_name'] = tuple(v.get('names', {}).get(self.LANG)
                                          for v in sub)
        sub = raw.get('continent')
        if sub:
            value = sub.get('code')
            if value:
                result['continent_code'] = value
            value = sub.get('names', {}).get(self.LANG)
            if value:
                result['continent_name'] = value
        sub = raw.get('country')
        if sub:
            value = sub.get('iso_code')
            if value:
                result['country_code'] = value
            value = sub.get('names', {}).get(self.LANG)
            if value:
                result['country_name'] = value
        sub = raw.get('registered_country')
        if sub:
            value = sub.get('iso_code')
            if value:
                result['registered_country_code'] = value
            value = sub.get('names', {}).get(self.LANG)
            if value:
                result['registered_country_name'] = value
        value = raw.get('city', {}).get('names', {}).get(self.LANG)
        if value:
            result['city'] = value
        value = raw.get('postal', {}).get('code')
        if value:
            result['postal_code'] = value
        sub = raw.get('location')
        if sub:
            try:
                result['coordinates'] = (sub['latitude'], sub['longitude'])
            except KeyError:
                pass
            value = sub.get('accuracy_radius')
            result['coordinates_accuracy_radius'] = value
        if result:
            return result

    def country_byip(self, addr):
        result = {}
        raw = self.db_country.lookup(addr)
        sub = raw.get('country')
        if sub:
            value = sub.get('iso_code')
            if value:
                result['country_code'] = value
            value = sub.get('names', {}).get(self.LANG)
            if value:
                result['country_name'] = value
        return result

    def dump_as_ranges(self, fdesc):
        for data in self.db_asn.get_ranges(
                ["autonomous_system_number"],
                cond=lambda line: line[2] is not None,
        ):
            if data[0] > 0xffffffff:  # only IPv4
                break
            fdesc.write('%d,%d,%d\n' % data)

    def dump_country_ranges(self, fdesc):
        for data in self.db_country.get_ranges(
                ["country->iso_code"],
                cond=lambda line: line[2] is not None,
        ):
            if data[0] > 0xffffffff:  # only IPv4
                break
            fdesc.write('%d,%d,%s\n' % data)

    def dump_city_ranges(self, fdesc):
        for data in self.db_city.get_ranges(
                ["country->iso_code", "subdivisions->0->iso_code",
                 "city->names->%s" % config.GEOIP_LANG, "city->geoname_id"],
                cond=lambda line: (line[2] is not None and
                                   (line[3] is not None or
                                    line[4] is not None)),
        ):
            if data[0] > 0xffffffff:  # only IPv4
                break
            fdesc.write('%d,%d,%s,%s,%s,%s\n' % (
                data[:4] +
                (utils.encode_b64((data[4] or
                                   "").encode('utf-8')).decode('utf-8'),) +
                data[5:]
            ))

    def build_dumps(self, force=False):
        for attr, func in [
                ("db_asn", self.dump_as_ranges),
                ("db_country", self.dump_country_ranges),
                ("db_city", self.dump_city_ranges),
        ]:
            try:
                subdb = getattr(self, attr)
            except AttributeError:
                continue
            if not subdb.path.endswith('.mmdb'):
                continue
            csv_file = subdb.path[:-4] + 'dump-IPv4.csv'
            if not force:
                mmdb_mtime = os.path.getmtime(subdb.path)
                try:
                    csv_mtime = os.path.getmtime(csv_file)
                except OSError:
                    pass
                else:
                    if csv_mtime > mmdb_mtime:
                        utils.LOGGER.info('Skipping %r since %r is newer',
                                          os.path.basename(subdb.path),
                                          os.path.basename(csv_file))
                        continue
            utils.LOGGER.info('Dumping %r to %r', os.path.basename(subdb.path),
                              os.path.basename(csv_file))
            with codecs.open(csv_file, mode="w", encoding='utf-8') as fdesc:
                func(fdesc)
