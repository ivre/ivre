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

"""This sub-module contains objects and functions to manipulate target
lists.

"""


from argparse import ArgumentParser
from functools import reduce
from math import gcd
from operator import add, mul
import os
import random
import re
import shlex
import subprocess
import tempfile


from ivre import utils, geoiputils, mathutils


class Target:
    """This is the base class for a Target object, which is,
    basically, a set of IP selected according specific criteria
    (selection is implemented in the subclasses) that we will be able
    to enumerate in a random order (most of the time, see `TargetFile`
    class below when this is not possible).

    """

    def __init__(
        self, targets, rand=True, maxnbr=None, state=None, name=None, categories=None
    ):
        self.targets = targets
        self.rand = rand
        # len() result needs to be lower than sys.maxsize
        self.targetscount = targets.__len__()
        if maxnbr is None:
            self.maxnbr = self.targetscount
        else:
            self.maxnbr = maxnbr
        self.state = state
        self.name = name or (
            "%d address%s from %d range%s"
            % (
                self.maxnbr,
                "es" if self.maxnbr > 1 else "",
                len(targets),
                "s" if len(targets) > 1 else "",
            )
        )
        if categories is None:
            self.categories = [self.name]
        else:
            self.categories = categories
        self.infos = {"categories": self.categories}

    def __len__(self):
        return self.maxnbr

    def __iter__(self):
        return IterTarget(self, rand=self.rand, state=self.state)

    def __repr__(self):
        return "<Target %s>" % self.name

    def union(self, *others):
        others = tuple(o for o in others if o)
        if self.maxnbr < self.targetscount or any(
            o.maxnbr < o.targetscount for o in others
        ):
            raise ValueError("Cannot union when maxnbr is set")
        if self.state or any(o.state for o in others):
            raise ValueError("Cannot union when state is set")
        return Target(
            self.targets.union(*(o.targets for o in others)),
            rand=self.rand or any(o.rand for o in others),
            name=" + ".join([self.name] + [o.name for o in others]),
        )

    def __add__(self, other):
        return self.union(other)


class IterTarget:
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
            while gcd(self.lcg_c, self.lcg_m) != 1:
                self.lcg_c = random.randint(1, self.lcg_m - 1)
            # a - 1 is divisible by all prime factors of m
            mfactors = reduce(mul, set(mathutils.factors(self.lcg_m)))
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

    def __next__(self):
        if self.nextcount >= self.target.maxnbr:
            raise StopIteration
        self.nextcount += 1
        self.previous = (self.lcg_a * self.previous + self.lcg_c) % self.lcg_m
        return self.target.targets[self.previous]


class TargetTest(Target):
    """This class can be used to get addresses within the
    127.0.0.0/8 network range.

    """

    def __init__(self, count=10, categories=None, rand=True, maxnbr=None, state=None):
        if count < 0:
            raise ValueError("count must be greater than or equal to 0")
        if count > 16777216:
            raise ValueError("count must be lower than or equal to 16777216")
        super().__init__(
            geoiputils.IPRanges(ranges=[(2130706433, 2130706432 + count)]),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name="TEST-%d" % count,
            categories=categories,
        )


class TargetRegisteredCountry(Target):
    """This class can be used to get IP addresses from a country, based on
    the "registered_country" fields from Maxmind GeoIP.

    """

    def __init__(self, country, categories=None, rand=True, maxnbr=None, state=None):
        super().__init__(
            geoiputils.get_ranges_by_registered_country(country),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name="REGISTERED_COUNTRY-%s" % country,
            categories=categories,
        )


class TargetCountry(Target):
    """This class can be used to get IP addresses from a country,
    according to the data from Maxmind GeoIP.

    """

    def __init__(self, country, categories=None, rand=True, maxnbr=None, state=None):
        super().__init__(
            geoiputils.get_ranges_by_country(country),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name="COUNTRY-%s" % country,
            categories=categories,
        )


class TargetRegion(Target):
    """This class can be used to get IP addresses from a region,
    according to the data from Maxmind GeoIP.

    """

    def __init__(
        self, country, region, categories=None, rand=True, maxnbr=None, state=None
    ):
        super().__init__(
            geoiputils.get_ranges_by_region(country, region),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name="REGION-%s-%s" % (country, region),
            categories=categories,
        )


class TargetCity(Target):
    """This class can be used to get IP addresses from a specified
    city, according to the data from Maxmind GeoIP.

    """

    def __init__(
        self, country_code, city, categories=None, rand=True, maxnbr=None, state=None
    ):
        super().__init__(
            geoiputils.get_ranges_by_city(country_code, city),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name="CITY-%s-%s" % (country_code, city),
            categories=categories,
        )


class TargetAS(Target):
    """This class can be used to get IP addresses from a specific AS,
    according to the data from Maxmind GeoIP.

    """

    def __init__(self, asnum, categories=None, rand=True, maxnbr=None, state=None):
        if isinstance(asnum, str) and asnum.upper().startswith("AS"):
            asnum = int(asnum[2:])
        else:
            asnum = int(asnum)
        super().__init__(
            geoiputils.get_ranges_by_asnum(asnum),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name="AS-%d" % asnum,
            categories=categories,
        )


class TargetRoutable(Target):
    """This class can be used to get all the routable IP addresses,
    according to the APNIC database.

    """

    def __init__(self, categories=None, rand=True, maxnbr=None, state=None):
        super().__init__(
            geoiputils.get_routable_ranges(),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name="ROUTABLE",
            categories=categories,
        )


class TargetRange(Target):
    """This class can be used to get the IP addresses within a
    specific range.

    """

    def __init__(
        self,
        start,
        stop,
        categories=None,
        rand=True,
        maxnbr=None,
        state=None,
        name=None,
    ):
        super().__init__(
            geoiputils.IPRanges(ranges=[(utils.ip2int(start), utils.ip2int(stop))]),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name=name or "RANGE-%s-%s" % (start, stop),
            categories=categories,
        )


class TargetNetwork(TargetRange):
    """This class can be used to get the IP addresses of a specific
    network.

    """

    def __init__(self, net, categories=None, rand=True, maxnbr=None, state=None):
        super().__init__(
            *utils.net2range(net),
            rand=rand,
            maxnbr=maxnbr,
            state=state,
            name="NET-%s" % net.replace("/", "-"),
            categories=categories,
        )


class TargetFile(Target):
    """This is a specific `Target`-like object (see `Target`), with
    neither the knowledge of the size of the IP addresses set, nor the
    ability to get the nth element without getting the (n-1) elements
    before it.

    Because of this, we cannot iterate the IP addresses in a random
    order or .union().

    """

    @staticmethod
    def _getaddr(line):
        try:
            return utils.ip2int(line.split("#", 1)[0].strip())
        except utils.socket.error:
            return None

    def __init__(self, filename, categories=None, maxnbr=None, state=None):
        self.filename = filename
        self.name = "FILE-%s" % filename
        if categories is None:
            categories = [self.name]
        self.infos = {"categories": categories}
        with open(filename) as fdesc:
            self.targetscount = sum(
                1 for line in fdesc if self._getaddr(line) is not None
            )
        if maxnbr is None:
            self.maxnbr = self.targetscount
        else:
            self.maxnbr = maxnbr
        self.state = state

    def __iter__(self):
        return IterTargetFile(
            self,
            open(self.filename),
            state=self.state,
        )

    def close(self):
        pass


class IterTargetFile:
    """The iterator object returned by `TargetFile.__iter__()`"""

    def __iter__(self):
        return self

    def __init__(self, target, fdesc, state=None):
        self.target = target
        self.nextcount = 0
        self.fdesc = fdesc
        if state is not None:
            opened, seekval = state[:2]
            if opened:
                self.fdesc.seek(seekval)
            else:
                self.fdesc.closed()

    def getstate(self):
        opened = not self.fdesc.closed
        return (int(opened), self.fdesc.tell() if opened else 0, 0, 0)

    def __readline__(self):
        line = self.fdesc.readline()
        if line == "":
            self.fdesc.close()
            self.target.close()
            raise StopIteration
        return self.target._getaddr(line)

    def __next__(self):
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

    def __init__(self, target, zmap="zmap", port=80, zmap_opts=None):
        self.srctarget = target
        self.infos = target.infos
        if zmap_opts is None:
            zmap_opts = []
        zmap_opts += ["-p", str(port)]
        self.infos["zmap_pre_scan"] = zmap_opts[:]
        zmap_opts = [zmap] + zmap_opts + ["-o", "-"]
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as self.tmpfile:
            for start, count in target.targets.ranges.values():
                for net in utils.range2nets((start, start + count - 1)):
                    self.tmpfile.write("%s\n" % net)
        zmap_opts += ["-w", self.tmpfile.name]
        # pylint: disable=consider-using-with
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

    match_addr = re.compile("^Host: ([^ ]+) \\(.*\\)\tStatus: Up$")

    @classmethod
    def _getaddr(cls, line):
        addr = cls.match_addr.match(line)
        if addr is not None:
            try:
                return utils.ip2int(addr.groups()[0])
            except utils.socket.error:
                pass
        return None

    def __init__(self, target, nmap="nmap", ports=None, nmap_opts=None):
        self.srctarget = target
        self.infos = target.infos
        if ports is None:
            ports = [80, 443]
        ports = ",".join(str(p) for p in ports)
        if nmap_opts is None:
            nmap_opts = []
        nmap_opts += ["-n", "-PS%s" % ports, "-sS", "--open", "-p", ports]
        self.infos["nmap_pre_scan"] = nmap_opts[:]
        # TODO: use -iL and feed target randomly when needed, w/o
        # using a temporary file
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as self.tmpfile:
            nmap_opts = [nmap, "-iL", self.tmpfile.name, "-oG", "-"] + nmap_opts
            for start, count in target.targets.ranges.values():
                for net in utils.range2nets((start, start + count - 1)):
                    self.tmpfile.write("%s\n" % net)
        # pylint: disable=consider-using-with
        self.proc = subprocess.Popen(nmap_opts, stdout=subprocess.PIPE)
        self.targetsfd = self.proc.stdout


ARGPARSER = ArgumentParser(add_help=False)
ARGPARSER.add_argument(
    "--categories",
    metavar="CAT",
    nargs="+",
    help="tag scan results with these categories",
)
ARGPARSER.add_argument(
    "--country", "-c", metavar="CODE[,CODE[,...]]", help="select a country"
)
ARGPARSER.add_argument(
    "--registered-country",
    metavar="CODE[,CODE[,...]]",
    help="select a registered country",
)
ARGPARSER.add_argument(
    "--city", nargs=2, metavar=("COUNTRY_CODE", "CITY"), help="select a region"
)
ARGPARSER.add_argument(
    "--region", nargs=2, metavar=("COUNTRY_CODE", "REGION_CODE"), help="select a region"
)
ARGPARSER.add_argument(
    "--asnum", "-a", metavar="AS[,AS[,...]]", help="select an autonomous system"
)
ARGPARSER.add_argument(
    "--range", "-r", nargs=2, metavar=("START", "STOP"), help="select an address range"
)
ARGPARSER.add_argument("--network", "-n", metavar="NET/MASK", help="select a network")
ARGPARSER.add_argument("--routable", action="store_true")
ARGPARSER.add_argument(
    "--file", "-f", metavar="FILENAME", help="read targets from a file"
)
ARGPARSER.add_argument(
    "--test",
    "-t",
    metavar="COUNT",
    type=int,
    help="select COUNT addresses on local loop",
)
ARGPARSER.add_argument("--zmap-prescan-port", type=int)
ARGPARSER.add_argument("--zmap-prescan-opts")
ARGPARSER.add_argument("--nmap-prescan-ports", type=int, nargs="+")
ARGPARSER.add_argument("--nmap-prescan-opts")
ARGPARSER.add_argument("--limit", "-l", type=int, help="number of addresses to output")
ARGPARSER.add_argument("--state", type=int, nargs=4, help="internal LCG state")


def target_from_args(args):
    if args.country is not None:
        countries = set()
        for country in args.country.split(","):
            ccodes = utils.country_unalias(country)
            if isinstance(ccodes, list):
                countries.update(ccodes)
            else:
                countries.add(ccodes)
        target = reduce(
            add,
            (
                TargetCountry(
                    country,
                    categories=args.categories,
                    maxnbr=args.limit,
                    state=args.state,
                )
                for country in countries
            ),
        )
    elif args.registered_country is not None:
        countries = set()
        for country in args.registered_country.split(","):
            ccodes = utils.country_unalias(country)
            if isinstance(ccodes, list):
                countries.update(ccodes)
            else:
                countries.add(ccodes)
        target = reduce(
            add,
            (
                TargetRegisteredCountry(
                    country,
                    categories=args.categories,
                    maxnbr=args.limit,
                    state=args.state,
                )
                for country in countries
            ),
        )
    elif args.city is not None:
        target = TargetCity(
            args.city[0],
            args.city[1],
            categories=args.categories,
            maxnbr=args.limit,
            state=args.state,
        )
    elif args.region is not None:
        target = TargetRegion(
            args.region[0],
            args.region[1],
            categories=args.categories,
            maxnbr=args.limit,
            state=args.state,
        )
    elif args.asnum is not None:
        target = reduce(
            add,
            (
                TargetAS(
                    asnum,
                    categories=args.categories,
                    maxnbr=args.limit,
                    state=args.state,
                )
                for asnum in args.asnum.split(",")
            ),
        )
    elif args.range is not None:
        target = TargetRange(
            args.range[0],
            args.range[1],
            categories=args.categories,
            maxnbr=args.limit,
            state=args.state,
        )
    elif args.network is not None:
        target = TargetNetwork(
            args.network,
            categories=args.categories,
            maxnbr=args.limit,
            state=args.state,
        )
    elif args.routable:
        target = TargetRoutable(
            categories=args.categories, maxnbr=args.limit, state=args.state
        )
    elif args.file is not None:
        target = TargetFile(args.file, categories=args.categories, state=args.state)
    elif args.test is not None:
        target = TargetTest(
            args.test, categories=args.categories, maxnbr=args.limit, state=args.state
        )
    else:
        return None
    if args.zmap_prescan_port is not None:
        if args.zmap_prescan_opts is None:
            zmap_prescan_opts = []
        else:
            zmap_prescan_opts = shlex.split(args.zmap_prescan_opts)
        if "-b" not in zmap_prescan_opts:
            zmap_prescan_opts += ["-b", os.devnull]
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
            target, ports=args.nmap_prescan_ports, nmap_opts=nmap_prescan_opts
        )
    return target
