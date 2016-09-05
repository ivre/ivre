#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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
This sub-module contains objects and functions to manipulate target
lists.
"""

from ivre import utils, geoiputils, mathutils, config

import random
import tempfile
import subprocess
import os
import shlex
import re


class Target(object):
    """This is the base class for a Target object, which is,
    basically, a set of IP selected according specific criteria
    (selection is implemented in the subclasses) that we will be able
    to enumerate in a random order (most of the time, see `TargetFile`
    class below when this is not possible).

    """

    def __init__(self, targets, rand=True, maxnbr=None, state=None):
        self.targets = targets
        self.rand = rand
        self.targetscount = len(targets)
        if maxnbr is None:
            self.maxnbr = self.targetscount
        else:
            self.maxnbr = maxnbr
        self.state = state

    def __len__(self):
        return self.maxnbr

    def __iter__(self):
        return IterTarget(self, rand=self.rand, state=self.state)


class IterTarget(object):
    """The iterator object returned by `Target.__iter__()`"""

    def __iter__(self):
        return self

    def __init__(self, target, rand=True, state=None):
        # see https://fr.wikipedia.org/wiki/Générateur_congruentiel_linéaire
        self.target = target
        self.nextcount = 0
        self.lcg_m = target.targetscount
        if state is not None:
            self.previous = state[0]
            self.lcg_c = state[1]
            self.lcg_a = state[2]
            self.nextcount = state[3]
        elif rand and target.targetscount > 1:
            # X_{-1}
            self.previous = random.randint(0, self.lcg_m - 1)
            # GCD(c, m) == 1
            self.lcg_c = random.randint(1, self.lcg_m - 1)
            while mathutils.gcd(self.lcg_c, self.lcg_m) != 1:
                self.lcg_c = random.randint(1, self.lcg_m - 1)
            # a - 1 is divisible by all prime factors of m
            mfactors = reduce(lambda x, y: x * y,
                              set(mathutils.factors(self.lcg_m)))
            # a - 1 is a multiple of 4 if m is a multiple of 4.
            if self.lcg_m % 4 == 0:
                mfactors *= 2
            self.lcg_a = mfactors + 1
        else:
            self.previous = self.lcg_m - 1
            self.lcg_a = 1
            self.lcg_c = 1

    def getstate(self):
        return (self.previous, self.lcg_c, self.lcg_a, self.nextcount)

    def next(self):
        if self.nextcount >= self.target.maxnbr:
            raise StopIteration
        self.nextcount += 1
        self.previous = (self.lcg_a * self.previous + self.lcg_c) % self.lcg_m
        return self.target.targets[self.previous]


class TargetTest(Target):
    """This class can be used to get addresses within the
    127.0.0.0/8 network range.

    """

    def __init__(self, count=10, categories=None, rand=True, maxnbr=None,
                 state=None):
        Target.__init__(
            self,
            geoiputils.IPRanges(ranges=[(2130706433, 2130706432 + count)]),
            rand=rand, maxnbr=maxnbr, state=state
        )
        if categories is None:
            categories = ['TEST']
        self.infos = {'categories': categories}


class TargetCountry(Target):
    """This class can be used to get IP addresses from a country,
    according to the data from Maxmind GeoIP.

    """

    def __init__(self, country, categories=None, rand=True, maxnbr=None,
                 state=None):
        Target.__init__(self,
                        geoiputils.get_ranges_by_country(country),
                        rand=rand, maxnbr=maxnbr, state=state)
        if categories is None:
            categories = ['COUNTRY-%s' % country]
        self.infos = {'categories': categories}


class TargetRegion(Target):
    """This class can be used to get IP addresses from a region,
    according to the data from Maxmind GeoIP.

    """

    def __init__(self, country, region, categories=None, rand=True,
                 maxnbr=None, state=None):
        Target.__init__(self,
                        geoiputils.get_ranges_by_region(country, region),
                        rand=rand, maxnbr=maxnbr, state=state)
        if categories is None:
            categories = ['REGION-%s-%s' % (country, region)]
        self.infos = {'categories': categories}


class TargetCity(Target):
    """This class can be used to get IP addresses from a specified
    city, according to the data from Maxmind GeoIP.

    """

    def __init__(self, city, categories=None, rand=True, maxnbr=None,
                 state=None):
        Target.__init__(self,
                        geoiputils.get_ranges_by_city(city),
                        rand=rand, maxnbr=maxnbr, state=state)
        if categories is None:
            categories = ['CITY-%s' % city]
        self.infos = {'categories': categories}


class TargetAS(Target):
    """This class can be used to get IP addresses from a specic AS,
    according to the data from Maxmind GeoIP.

    """

    def __init__(self, asnum, categories=None, rand=True, maxnbr=None,
                 state=None):
        if type(asnum) is str and asnum.upper().startswith('AS'):
            asnum = int(asnum[2:])
        else:
            asnum = int(asnum)
        Target.__init__(
            self,
            geoiputils.get_ranges_by_asnum(asnum),
            rand=rand, maxnbr=maxnbr, state=state
        )
        if categories is None:
            categories = ['AS-%d' % asnum]
        self.infos = {'categories': categories}


class TargetRoutable(Target):
    """This class can be used to get all the routable IP addresses,
    according to the APNIC database.

    """

    def __init__(self, categories=None, rand=True, maxnbr=None, state=None):
        Target.__init__(
            self,
            geoiputils.get_routable_ranges(),
            rand=rand, maxnbr=maxnbr, state=state
        )
        if categories is None:
            categories = ['ROUTABLE']
        self.infos = {'categories': categories}


class TargetRange(Target):
    """This class can be used to get the IP addresses within a
    specific range.

    """

    def __init__(self, start, stop, categories=None, rand=True, maxnbr=None,
                 state=None):
        Target.__init__(
            self,
            geoiputils.IPRanges(ranges=[(utils.ip2int(start),
                                         utils.ip2int(stop))]),
            rand=rand, maxnbr=maxnbr, state=state
        )
        if categories is None:
            categories = ['RANGE-%s-%s' % (start, stop)]
        self.infos = {'categories': categories}


class TargetNetwork(TargetRange):
    """This class can be used to get the IP addresses of a specific
    nework.

    """

    def __init__(self, net, **kargs):
        if 'categories' not in kargs or kargs['categories'] is None:
            kargs['categories'] = ['NET-' + net.replace('/', '_')]
        TargetRange.__init__(self, *utils.net2range(net), **kargs)


class TargetFile(Target):
    """This is a specific `Target`-like object (see `Target`), with
    neither the knowledge of the size of the IP addresses set, nor the
    ability to get the nth element without getting the (n-1) elements
    before it.

    Because of this, we cannot iterate the IP addresses in a random
    order.

    """

    def __getaddr__(self, line):
        try:
            return utils.ip2int(line.split('#', 1)[0].strip())
        except utils.socket.error:
            pass

    def __init__(self, filename, categories=None, maxnbr=None):
        self.filename = filename
        if categories is None:
            categories = ['FILE-%s' % filename.replace('/', '_')]
        self.infos = {'categories': categories}
        with open(filename) as fdesc:
            i = 0
            for line in fdesc:
                try:
                    self.__getaddr__(line)
                    i += 1
                except utils.socket.error:
                    pass
            self.targetscount = i
        if maxnbr is None:
            self.maxnbr = self.targetscount
        else:
            self.maxnbr = maxnbr

    def __iter__(self):
        return IterTargetFile(self, open(self.filename))

    def close(self):
        pass


class IterTargetFile(object):
    """The iterator object returned by `TargetFile.__iter__()`"""

    def __iter__(self):
        return self

    def __init__(self, target, fdesc):
        self.target = target
        self.nextcount = 0
        self.fdesc = fdesc

    def __readline__(self):
        line = self.fdesc.readline()
        if line == '':
            self.fdesc.close()
            self.target.close()
            raise StopIteration
        return self.target.__getaddr__(line)

    def next(self):
        while True:
            addr = self.__readline__()
            if addr is not None:
                self.nextcount += 1
                return addr


class TargetZMapPreScan(TargetFile):
    """This class can be used to get the IP addresses that answered to
    a specific ZMap probe. This can be used to have a first pre-scan
    before the full Nmap scan.

    """

    def __init__(self, target, zmap='zmap', port=80, zmap_opts=None):
        self.srctarget = target
        self.infos = target.infos
        if zmap_opts is None:
            zmap_opts = []
        zmap_opts += ['-p', str(port)]
        self.infos['zmap_pre_scan'] = zmap_opts[:]
        zmap_opts = [zmap] + zmap_opts + ['-o', '-']
        self.tmpfile = tempfile.NamedTemporaryFile(delete=False)
        for start, count in target.targets.ranges.itervalues():
            for net in utils.range2nets((start, start + count - 1)):
                self.tmpfile.write("%s\n" % net)
        self.tmpfile.close()
        zmap_opts += ['-w', self.tmpfile.name]
        self.proc = subprocess.Popen(zmap_opts, stdout=subprocess.PIPE)
        self.targetsfd = self.proc.stdout

    def __iter__(self):
        return IterTargetFile(self, self.targetsfd)

    def close(self):
        os.unlink(self.tmpfile.name)


class TargetNmapPreScan(TargetZMapPreScan):
    """This class can be used to get the IP addresses that answered to
    a specific Nmap probe. This can be used to have a first pre-scan
    before the full Nmap scan.

    """

    match_addr = re.compile('^Host: ([^ ]+) \\(.*\\)\tStatus: Up$')

    def __getaddr__(self, line):
        addr = self.match_addr.match(line)
        if addr is not None:
            try:
                return utils.ip2int(addr.groups()[0])
            except utils.socket.error:
                pass

    def __init__(self, target, nmap='nmap', ports=None, nmap_opts=None):
        self.srctarget = target
        self.infos = target.infos
        if ports is None:
            ports = [80, 443]
        ports = ','.join(str(p) for p in ports)
        if nmap_opts is None:
            nmap_opts = []
        nmap_opts += ['-n', '-PS%s' % ports, '-sS', '--open', '-p', ports]
        self.infos['nmap_pre_scan'] = nmap_opts[:]
        # TODO: use -iL and feed target randomly when needed, w/o
        # using a temporary file
        self.tmpfile = tempfile.NamedTemporaryFile(delete=False)
        nmap_opts = [nmap, '-iL', self.tmpfile.name, '-oG', '-'] + nmap_opts
        for start, count in target.targets.ranges.itervalues():
            for net in utils.range2nets((start, start + count - 1)):
                self.tmpfile.write("%s\n" % net)
        self.tmpfile.close()
        self.proc = subprocess.Popen(nmap_opts, stdout=subprocess.PIPE)
        self.targetsfd = self.proc.stdout


try:
    import argparse
    argparser = argparse.ArgumentParser(add_help=False)
except ImportError:
    argparser = utils.FakeArgparserParent()

argparser.add_argument('--categories', metavar='CAT', nargs='+',
                       help='tag scan results with these categories')
argparser.add_argument('--country', '-c', metavar='CODE',
                       help='select a country')
argparser.add_argument('--region', nargs=2,
                       metavar=('COUNTRY_CODE', 'REGION_CODE'),
                       help='select a region')
argparser.add_argument('--asnum', '-a', metavar='AS', type=int,
                       help='select an autonomous system')
argparser.add_argument('--range', '-r', nargs=2, metavar=('START', 'STOP'),
                       help='select an address range')
argparser.add_argument('--network', '-n', metavar='NET/MASK',
                       help='select a network')
argparser.add_argument('--routable', action="store_true")
argparser.add_argument('--file', '-f', metavar='FILENAME',
                       help='read targets from a file')
argparser.add_argument('--test', '-t', metavar='COUNT', type=int,
                       help='select COUNT addresses on local loop')
argparser.add_argument('--zmap-prescan-port', type=int)
argparser.add_argument('--zmap-prescan-opts')
argparser.add_argument('--nmap-prescan-ports', type=int, nargs="+")
argparser.add_argument('--nmap-prescan-opts')
argparser.add_argument('--limit', '-l', type=int,
                       help='number of addresses to output')
argparser.add_argument('--state', type=int, nargs=4,
                       help='internal LCG state')


def target_from_args(args):
    if args.country is not None:
        target = TargetCountry(args.country,
                               categories=args.categories,
                               maxnbr=args.limit,
                               state=args.state)
    elif args.region is not None:
        target = TargetRegion(args.region[0], args.region[1],
                               categories=args.categories,
                               maxnbr=args.limit,
                               state=args.state)
    elif args.asnum is not None:
        target = TargetAS(args.asnum,
                          categories=args.categories,
                          maxnbr=args.limit,
                          state=args.state)
    elif args.range is not None:
        target = TargetRange(args.range[0], args.range[1],
                             categories=args.categories,
                             maxnbr=args.limit,
                             state=args.state)
    elif args.network is not None:
        target = TargetNetwork(args.network,
                               categories=args.categories,
                               maxnbr=args.limit,
                               state=args.state)
    elif args.routable:
        target = TargetRoutable(categories=args.categories,
                                maxnbr=args.limit,
                                state=args.state)
    elif args.file is not None:
        target = TargetFile(args.file,
                            categories=args.categories)
    elif args.test is not None:
        target = TargetTest(args.test,
                            categories=args.categories,
                            maxnbr=args.limit,
                            state=args.state)
    else:
        return None
    if args.zmap_prescan_port is not None:
        if args.zmap_prescan_opts is None:
            zmap_prescan_opts = []
        else:
            zmap_prescan_opts = shlex.split(args.zmap_prescan_opts)
        if '-b' not in zmap_prescan_opts:
            zmap_prescan_opts += ['-b', os.devnull]
        return TargetZMapPreScan(
            target,
            port=args.zmap_prescan_port,
            zmap_opts=zmap_prescan_opts,
        )
    if args.nmap_prescan_ports is not None:
        if args.nmap_prescan_opts is None:
            nmap_prescan_opts = []
        else:
            nmap_prescan_opts = shlex.split(args.nmap_prescan_opts)
        return TargetNmapPreScan(
            target,
            ports=args.nmap_prescan_ports,
            nmap_opts=nmap_prescan_opts
        )
    return target
