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

"""
This module is part of IVRE.
Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains the classes and functions to handle
information about IP addresses (mostly from Maxmind GeoIP files).

"""


from __future__ import print_function
import codecs
import csv
import os.path
import sys
import tarfile
try:
    from urllib.request import build_opener
except ImportError:
    from urllib2 import build_opener
import zipfile


from builtins import range
from future.utils import viewitems, viewvalues


from ivre import utils, config


def bgp_raw_to_csv(fname, out):
    out = open(os.path.join(config.GEOIP_PATH, out), 'w')
    cur = None
    with open(os.path.join(config.GEOIP_PATH, fname), 'rb') as fdesc:
        for line in fdesc:
            start, stop = (utils.ip2int(elt) for elt in
                           utils.net2range(line[:-1].split(None, 1)[0]))
            if cur:
                if start >= cur[0] and stop <= cur[1]:
                    continue
                if start >= cur[0] and start <= cur[1]:
                    cur = (cur[0], stop)
                    continue
                if stop >= cur[0] and stop <= cur[1]:
                    cur = (start, cur[1])
                    continue
                if start <= cur[0] and stop >= cur[1]:
                    cur = (start, stop)
                    continue
                if start == cur[1] + 1:
                    cur = (cur[0], stop)
                    continue
                if stop == cur[0] + 1:
                    cur = (start, cur[1])
                    continue
                out.write('%d,%d\n' % cur)
            cur = (start, stop)
    if cur:
        out.write('%d,%d\n' % cur)


def unzip_all(fname, cond=None, clean=True):
    zdesc = zipfile.ZipFile(os.path.join(config.GEOIP_PATH, fname))
    for filedesc in zdesc.infolist():
        if cond and not cond(filedesc):
            continue
        with open(os.path.join(config.GEOIP_PATH,
                               os.path.basename(filedesc.filename)),
                  'wb') as wdesc:
            wdesc.write(zdesc.read(filedesc))
    zdesc.close()
    if clean:
        os.unlink(os.path.join(config.GEOIP_PATH, fname))


def gunzip(fname):
    if not fname.endswith('.gz'):
        raise Exception('filename should end with ".gz"')
    with utils.open_file(os.path.join(config.GEOIP_PATH, fname)) as inp:
        with open(os.path.join(config.GEOIP_PATH, fname[:-3]), "wb") as outp:
            outp.write(inp.read())


def untar_all(fname, cond=None, clean=True):
    tdesc = tarfile.TarFile(os.path.join(config.GEOIP_PATH, fname))
    for filedesc in tdesc:
        if cond and not cond(filedesc):
            continue
        with open(os.path.join(config.GEOIP_PATH,
                               os.path.basename(filedesc.name)),
                  'wb') as wdesc:
            wdesc.write(tdesc.extractfile(filedesc).read())
    tdesc.close()
    if clean:
        os.unlink(os.path.join(config.GEOIP_PATH, fname))


def rename(src, dst):
    os.rename(os.path.join(config.GEOIP_PATH, src),
              os.path.join(config.GEOIP_PATH, dst))


PARSERS = [
    (unzip_all, ['GeoLite2-City-CSV.zip'],
     {"cond": lambda fdesc: fdesc.filename.endswith('.csv')}),
    (unzip_all, ['GeoLite2-Country-CSV.zip'],
     {"cond": lambda fdesc: fdesc.filename.endswith('.csv')}),
    (unzip_all, ['GeoLite2-ASN-CSV.zip'],
     {"cond": lambda fdesc: fdesc.filename.endswith('.csv')}),
    (gunzip, ['GeoLite2-City.tar.gz'], {}),
    (untar_all, ['GeoLite2-City.tar'],
     {"cond": lambda fdesc: fdesc.name.endswith('.mmdb')}),
    (gunzip, ['GeoLite2-Country.tar.gz'], {}),
    (untar_all, ['GeoLite2-Country.tar'],
     {"cond": lambda fdesc: fdesc.name.endswith('.mmdb')}),
    (gunzip, ['GeoLite2-ASN.tar.gz'], {}),
    (untar_all, ['GeoLite2-ASN.tar'],
     {"cond": lambda fdesc: fdesc.name.endswith('.mmdb')}),
    (bgp_raw_to_csv, ['BGP.raw', 'BGP.csv'], {}),
]


def download_all(verbose=False):
    utils.makedirs(config.GEOIP_PATH)
    opener = build_opener()
    opener.addheaders = [('User-agent', 'IVRE/1.0 +https://ivre.rocks/')]
    for fname, url in viewitems(config.IPDATA_URLS):
        outfile = os.path.join(config.GEOIP_PATH, fname)
        if verbose:
            sys.stdout.write("Downloading %s to %s: " % (url, outfile))
            sys.stdout.flush()
        with open(outfile, 'wb') as wdesc:
            udesc = opener.open(url)
            wdesc.write(udesc.read())
            if verbose:
                sys.stdout.write("done.\n")
    if verbose:
        sys.stdout.write("Unpacking: ")
        sys.stdout.flush()
    for func, args, kargs in PARSERS:
        func(*args, **kargs)
    if verbose:
        sys.stdout.write("done.\n")


def locids_by_country(country_code):
    fdesc = csv.DictReader(codecs.open(os.path.join(
        config.GEOIP_PATH,
        'GeoLite2-Country-Locations-%s.csv' % config.GEOIP_LANG,
    ), encoding='utf-8'))
    for line in fdesc:
        if line['country_iso_code'] == country_code:
            yield int(line['geoname_id'])


def locids_by_city(country_code, city_name):
    fdesc = csv.DictReader(codecs.open(os.path.join(
        config.GEOIP_PATH,
        'GeoLite2-City-Locations-%s.csv' % config.GEOIP_LANG,
    ), encoding='utf-8'))
    city_name = utils.encode_b64((city_name or
                                  "").encode('utf-8')).decode('utf-8')
    for line in fdesc:
        if (line['country_iso_code'], line['city_name']) == \
           (country_code, city_name):
            yield int(line['geoname_id'])


def locids_by_region(country_code, reg_code):
    fdesc = csv.DictReader(codecs.open(os.path.join(
        config.GEOIP_PATH,
        'GeoLite2-City-Locations-%s.csv' % config.GEOIP_LANG,
    ), encoding='utf-8'))
    for line in fdesc:
        if (line['country_iso_code'], line['subdivision_1_iso_code']) == \
           (country_code, reg_code):
            yield int(line['geoname_id'])


class IPRanges(object):

    def __init__(self, ranges=None):
        """ranges must be given in the "correct" order *and* not
        overlap.

        """
        self.ranges = {}
        self.length = 0
        if ranges is not None:
            for rnge in ranges:
                self.append(*rnge)

    def append(self, start, stop):
        length = stop - start + 1
        self.ranges[self.length] = (start, length)
        self.length += int(length)  # in case it's a long

    def iter_ranges(self):
        for start, length in sorted(viewvalues(self.ranges)):
            yield utils.int2ip(start), utils.int2ip(start + length - 1)

    def __len__(self):
        return self.length

    def __getitem__(self, item):
        rangeindex = max(k for k in self.ranges if k <= item)
        item -= rangeindex
        rnge = self.ranges[rangeindex]
        if item < rnge[1]:
            return rnge[0] + item
        raise IndexError("index out of range")


def _get_by_data(datafile, condition):
    fdesc = open(os.path.join(config.GEOIP_PATH, datafile))
    for line in fdesc:
        line = line[:-1].split(',')
        if condition(line):
            yield int(line[0]), int(line[1])


def get_ranges_by_data(datafile, condition):
    rnge = IPRanges()
    for start, stop in _get_by_data(datafile, condition):
        rnge.append(start, stop)
    return rnge


def get_ranges_by_country(code):
    return get_ranges_by_data(
        "GeoLite2-Country.dump-IPv4.csv",
        lambda line: line[2] == code,
    )


def get_ranges_by_location(locid):
    return get_ranges_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[5] == str(locid)
    )


def get_ranges_by_city(country_code, city):
    return get_ranges_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[2] == country_code and
        line[4] == utils.encode_b64(
            (city or "").encode('utf-8')
        ).decode('utf-8'),
    )


def get_ranges_by_region(country_code, reg_code):
    return get_ranges_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[2] == country_code and line[3] == reg_code,
    )


def get_ranges_by_asnum(asnum):
    return get_ranges_by_data(
        "GeoLite2-ASN.dump-IPv4.csv",
        lambda line: line[2] == str(asnum),
    )


def get_routable_ranges():
    return get_ranges_by_data('BGP.csv', lambda _: True)


def get_ips_by_data(datafile, condition, skip=0, maxnbr=None):
    res = []
    for start, stop in _get_by_data(datafile, condition):
        curaddrs = [utils.int2ip(addr) for addr in range(start, stop + 1)]
        if skip > 0:
            skip -= len(curaddrs)
            if skip <= 0:
                curaddrs = curaddrs[skip:]
            else:
                curaddrs = []
        if maxnbr is not None:
            maxnbr -= len(curaddrs)
            if maxnbr < 0:
                return res + curaddrs[:maxnbr]
            elif maxnbr == 0:
                return res + curaddrs
        res += curaddrs
    return res


def get_ips_by_country(code, **kargs):
    return get_ips_by_data(
        "GeoLite2-Country.dump-IPv4.csv",
        lambda line: line[2] == code,
        **kargs
    )


def get_ips_by_location(locid, **kargs):
    return get_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[5] == str(locid),
        **kargs
    )


def get_ips_by_city(country_code, city, **kargs):
    return get_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[2] == country_code and
        line[4] == utils.encode_b64(
            (city or "").encode('utf-8')
        ).decode('utf-8'),
        **kargs
    )


def get_ips_by_region(country_code, reg_code, **kargs):
    return get_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[2] == country_code and line[3] == reg_code,
        **kargs
    )


def get_ips_by_asnum(asnum, **kargs):
    return get_ips_by_data(
        "GeoLite2-ASN.dump-IPv4.csv",
        lambda line: line[2] == str(asnum),
        **kargs
    )


def get_routable_ips(**kargs):
    return get_ips_by_data(
        'BGP.csv', lambda _: True, **kargs
    )


def count_ips_by_data(datafile, condition):
    res = 0
    for start, stop in _get_by_data(datafile, condition):
        res += stop - start + 1
    return res


def count_ips_by_country(code):
    return count_ips_by_data(
        "GeoLite2-Country.dump-IPv4.csv",
        lambda line: line[2] == code,
    )


def count_ips_by_location(locid):
    return count_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[5] == str(locid),
    )


def count_ips_by_city(country_code, city):
    return count_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[2] == country_code and
        line[4] == utils.encode_b64(
            (city or "").encode('utf-8')
        ).decode('utf-8'),
    )


def count_ips_by_region(country_code, reg_code):
    return count_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[2] == country_code and line[3] == reg_code,
    )


def count_ips_by_asnum(asnum):
    return count_ips_by_data(
        "GeoLite2-ASN.dump-IPv4.csv",
        lambda line: line[2] == str(asnum),
    )


def count_routable_ips():
    return count_ips_by_data(
        'BGP.csv',
        lambda _: True,
    )


def list_ips_by_data(datafile, condition,
                     listall=True, listcidrs=False,
                     skip=0, maxnbr=None, multiple=False):
    if ((not listall) or listcidrs) and ((skip != 0) or (maxnbr is not None)):
        utils.LOGGER.warning('Skip and maxnbr parameters have no effect '
                             'when listall == False or listcidrs == True.')
    if listcidrs:
        listall = False
    for start, stop in _get_by_data(datafile, condition):
        if listall:
            curaddrs = [utils.int2ip(addr) for addr in
                        range(start, stop + 1)]
            if skip > 0:
                skip -= len(curaddrs)
                if skip <= 0:
                    curaddrs = curaddrs[skip:]
                else:
                    curaddrs = []
            if maxnbr is not None:
                maxnbr -= len(curaddrs)
                if maxnbr < 0:
                    curaddrs = curaddrs[:maxnbr]
            for addr in curaddrs:
                print(addr)
            if maxnbr is not None and maxnbr <= 0:
                return
        elif listcidrs:
            for net in utils.range2nets((start, stop)):
                print(net)
        else:
            print("%s - %s" % (utils.int2ip(start),
                               utils.int2ip(stop)))


def list_ips_by_country(code, **kargs):
    return list_ips_by_data(
        "GeoLite2-Country.dump-IPv4.csv",
        lambda line: line[2] == code,
        **kargs
    )


def list_ips_by_location(locid, **kargs):
    return list_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[5] == str(locid),
        **kargs
    )


def list_ips_by_city(country_code, city, **kargs):
    return list_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[2] == country_code and
        line[4] == utils.encode_b64(
            (city or "").encode('utf-8')
        ).decode('utf-8'),
        **kargs
    )


def list_ips_by_region(country_code, reg_code, **kargs):
    return list_ips_by_data(
        'GeoLite2-City.dump-IPv4.csv',
        lambda line: line[2] == country_code and line[3] == reg_code,
        **kargs
    )


def list_ips_by_asnum(asnum, **kargs):
    return list_ips_by_data(
        "GeoLite2-ASN.dump-IPv4.csv",
        lambda line: line[2] == str(asnum),
        **kargs
    )


def list_routable_ips(**kargs):
    return list_ips_by_data(
        'BGP.csv', lambda _: True, **kargs
    )
