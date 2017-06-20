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

"""
This module is part of IVRE.
Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains the classes and functions to handle
information about IP addresses (mostly from Maxmind GeoIP files).

"""


from __future__ import print_function
import functools
import os.path
import sys
try:
    from urllib.request import build_opener
except ImportError:
    from urllib2 import build_opener
import zipfile
import zlib


from builtins import range
from future.utils import viewitems


from ivre import utils, config


def bgp_raw_to_csv(fname, out):
    out = open(os.path.join(config.GEOIP_PATH, out), 'wb')
    cur = []
    with open(os.path.join(config.GEOIP_PATH, fname), 'rb') as fdesc:
        for line in fdesc:
            start, stop = (utils.ip2int(elt) for elt in
                           utils.net2range(line[:-1].split()[0]))
            if cur:
                if start >= cur[0] and stop <= cur[1]:
                    continue
                if start >= cur[0] and start <= cur[1]:
                    cur = [cur[0], stop]
                    continue
                if stop >= cur[0] and stop <= cur[1]:
                    cur = [start, cur[1]]
                    continue
                if start <= cur[0] and stop >= cur[1]:
                    cur = [start, stop]
                    continue
                if start == cur[1] + 1:
                    cur = [cur[0], stop]
                    continue
                if stop == cur[0] + 1:
                    cur = [start, cur[1]]
                    continue
                out.write(('"%s","%s","%d","%d"\n' % (
                    utils.int2ip(cur[0]), utils.int2ip(cur[1]), cur[0], cur[1],
                )).encode())
            cur = [start, stop]
    if cur:
        out.write(('"%s","%s","%d","%d"\n' % (
            utils.int2ip(cur[0]), utils.int2ip(cur[1]), cur[0], cur[1],
        )).encode())


def unzip_all(fname):
    zdesc = zipfile.ZipFile(os.path.join(config.GEOIP_PATH, fname))
    for filedesc in zdesc.infolist():
        if filedesc.filename.endswith('/'):
            continue
        with open(os.path.join(config.GEOIP_PATH,
                               os.path.basename(filedesc.filename)),
                  'wb') as wdesc:
            wdesc.write(zdesc.read(filedesc))


def rename(src, dst):
    os.rename(os.path.join(config.GEOIP_PATH, src),
              os.path.join(config.GEOIP_PATH, dst))

PARSERS = [
    (unzip_all, ['GeoIPCountryCSV.zip'], {}),
    (unzip_all, ['GeoIPCityCSV.zip'], {}),
    (unzip_all, ['GeoIPASNumCSV.zip'], {}),
    (rename, ['GeoIPCountryWhois.csv', 'GeoIPCountry.csv'], {}),
    (rename, ['GeoLiteCity-Blocks.csv', 'GeoIPCity-Blocks.csv'], {}),
    (rename, ['GeoLiteCity-Location.csv', 'GeoIPCity-Location.csv'], {}),
    (rename, ['GeoIPASNum2.csv', 'GeoIPASNum.csv'], {}),
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
        if url.endswith('.gz'):
            decode = zlib.decompress
        else:
            decode = lambda x: x
        with open(outfile, 'wb') as wdesc:
            udesc = opener.open(url)
            wdesc.write(decode(udesc.read()))
            if verbose:
                sys.stdout.write("done.\n")
    if verbose:
        sys.stdout.write("Unpacking: ")
        sys.stdout.flush()
    for func, args, kargs in PARSERS:
        func(*args, **kargs)
    if verbose:
        sys.stdout.write("done.\n")


def locids_by_city(country_code, city_name):
    with open(os.path.join(config.GEOIP_PATH,
                           'GeoIPCity-Location.csv'), 'rb') as fdesc:
        for _ in range(2):
            fdesc.readline()
        for line in fdesc:
            locid, country, _, city, _ = line[:-1].split(b',', 4)
            country = country.strip(b'"')
            city = city.strip(b'"')
            if (country, city) == (country_code, city_name):
                yield int(locid)


def locids_by_region(country_code, region_code):
    with open(os.path.join(config.GEOIP_PATH,
                           'GeoIPCity-Location.csv', 'rb')) as fdesc:
        for _ in range(2):
            fdesc.readline()
        for line in fdesc:
            locid, country, region, _ = line[:-1].split(b',', 3)
            country = country.strip(b'"')
            region = region.strip(b'"')
            if (country, region) == (country_code, region_code):
                yield int(locid)


def parseline_country(line):
    line = line.strip(b'\n"').split(b'","')
    try:
        return int(line[2]), int(line[3]), line[4].decode()
    except Exception:
        utils.LOGGER.warning('Exception while reading line %r', line,
                             exc_info=True)
        raise


def parseline_location(line):
    line = line.strip(b'\n"').split(b'","')
    try:
        return int(line[0]), int(line[1]), int(line[2])
    except Exception:
        if line[0].startswith(b'Copyright '):
            return None, None, None
        elif line[0].startswith(b'startIpNum,'):
            return None, None, None
        else:
            utils.LOGGER.warning('Exception while reading line %r', line,
                                 exc_info=True)
            raise


def parseline_asnum(line, withcomment=False):
    line = line.strip(b'\n').split(b',', 2)
    try:
        if line[2][:1] == b'"' and line[2][-1:] == b'"':
            asnum, ascomment = line[2][1:-1].split(b' ', 1)
        else:
            asnum = line[2]
            ascomment = None
        if asnum.startswith(b'AS'):
            asnum = int(asnum[2:])
        else:
            raise Exception('asnum %r should start with AS' % asnum)
    except Exception:
        utils.LOGGER.warning('Exception while reading line %r', line,
                             exc_info=True)
        raise
    if withcomment:
        return int(line[0]), int(line[1]), asnum, ascomment
    return int(line[0]), int(line[1]), asnum


def parseline_routable(line):
    line = line.strip(b'\n"').split(b'","')
    try:
        return int(line[2]), int(line[3]), True
    except Exception:
        utils.LOGGER.warning('Exception while reading line %r', line,
                             exc_info=True)
        raise


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

    def __len__(self):
        return self.length

    def __getitem__(self, item):
        rangeindex = max(k for k in self.ranges if k <= item)
        item -= rangeindex
        rnge = self.ranges[rangeindex]
        if item < rnge[1]:
            return rnge[0] + item
        raise IndexError("index out of range")


def get_ranges_by_data(datafile, parseline, data, multiple=False):
    rnge = IPRanges()
    with open(datafile) as fdesc:
        for line in fdesc:
            start, stop, curdata = parseline(line)
            if (multiple and curdata in data) or curdata == data:
                rnge.append(start, stop)
    return rnge

get_ranges_by_country = functools.partial(
    get_ranges_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPCountry.csv'),
    parseline_country,
)

get_ranges_by_location = functools.partial(
    get_ranges_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPCity-Blocks.csv'),
    parseline_location,
    multiple=True,
)

def get_ranges_by_city(country_code, city):
    return get_ranges_by_location(set(locids_by_city(country_code, city)))

def get_ranges_by_region(country_code, region_code):
    return get_ranges_by_location(set(locids_by_region(country_code,
                                                       region_code)))

get_ranges_by_asnum = functools.partial(
    get_ranges_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPASNum.csv'),
    parseline_asnum,
)

get_routable_ranges = functools.partial(
    get_ranges_by_data,
    os.path.join(config.GEOIP_PATH, 'BGP.csv'),
    parseline_routable,
    True,
)


def get_ips_by_data(datafile, parseline, data, skip=0, maxnbr=None,
                    multiple=False):
    res = []
    with open(datafile, 'rb') as fdesc:
        for line in fdesc:
            start, stop, curdata = parseline(line)
            if (multiple and curdata in data) or curdata == data:
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

get_ips_by_country = functools.partial(
    get_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPCountry.csv'),
    parseline_country,
)

get_ips_by_location = functools.partial(
    get_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPCity-Blocks.csv'),
    parseline_location,
    multiple=True,
)

def get_ips_by_city(country_code, city, **kargs):
    return get_ips_by_location(set(locids_by_city(country_code, city)),
                               **kargs)

def get_ips_by_region(country_code, region_code, **kargs):
    return get_ips_by_location(set(locids_by_region(country_code,
                                                    region_code)),
                               **kargs)

get_ips_by_asnum = functools.partial(
    get_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPASNum.csv'),
    parseline_asnum,
)

get_routable_ips = functools.partial(
    get_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'BGP.csv'),
    parseline_routable,
    True,
)


def count_ips_by_data(datafile, parseline, data, multiple=False):
    res = 0
    with open(datafile, 'rb') as fdesc:
        for line in fdesc:
            start, stop, curdata = parseline(line)
            if (multiple and curdata in data) or curdata == data:
                res += stop - start + 1
    return res

count_ips_by_country = functools.partial(
    count_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPCountry.csv'),
    parseline_country,
)

count_ips_by_location = functools.partial(
    count_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPCity-Blocks.csv'),
    parseline_location,
    multiple=True,
)

def count_ips_by_city(country_code, city):
    return count_ips_by_location(set(locids_by_city(country_code, city)))

def count_ips_by_region(country_code, region_code):
    return count_ips_by_location(set(locids_by_region(country_code,
                                                      region_code)))

count_ips_by_asnum = functools.partial(
    count_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPASNum.csv'),
    parseline_asnum,
)

count_routable_ips = functools.partial(
    count_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'BGP.csv'),
    parseline_routable,
    True,
)


def list_ips_by_data(datafile, parseline, data,
                     listall=True, listcidrs=False,
                     skip=0, maxnbr=None, multiple=False):
    if ((not listall) or listcidrs) and ((skip != 0) or (maxnbr is not None)):
        utils.LOGGER.warning('Skip and maxnbr parameters have no effect '
                             'when listall == False or listcidrs == True.')
    if listcidrs:
        listall = False
    with open(datafile, 'rb') as fdesc:
        for line in fdesc:
            start, stop, curdata = parseline(line)
            if (multiple and curdata in data) or curdata == data:
                if listall:
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
                            curaddrs = curaddrs[:maxnbr]
                    for addr in curaddrs:
                        print(addr)
                    if maxnbr is not None and maxnbr <= 0:
                        return
                elif listcidrs:
                    for net in utils.range2nets((start, stop)):
                        print(net)
                else:
                    print("%s - %s" % (utils.int2ip(start), utils.int2ip(stop)))


list_ips_by_country = functools.partial(
    list_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPCountry.csv'),
    parseline_country,
)

list_ips_by_location = functools.partial(
    list_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPCity-Blocks.csv'),
    parseline_location,
    multiple=True,
)

def list_ips_by_city(country_code, city, **kargs):
    return list_ips_by_location(set(locids_by_city(country_code, city)),
                                **kargs)

def list_ips_by_region(country_code, region_code, **kargs):
    return list_ips_by_location(set(locids_by_region(country_code,
                                                     region_code)),
                                **kargs)

list_ips_by_asnum = functools.partial(
    list_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'GeoIPASNum.csv'),
    parseline_asnum,
)

list_routable_ips = functools.partial(
    list_ips_by_data,
    os.path.join(config.GEOIP_PATH, 'BGP.csv'),
    parseline_routable,
    True,
)
