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

"""This sub-module contains the classes and functions to handle
information about IP addresses (mostly from Maxmind GeoIP files).

"""


import codecs
import csv
import os.path
import sys
import tarfile
from typing import Any, Callable, Dict, Generator, Iterable, List, Optional, Tuple
from urllib.request import build_opener
import zipfile


from ivre import VERSION, utils, config


def bgp_raw_to_csv(fname: str, outname: str) -> None:
    cur = None
    assert config.GEOIP_PATH is not None
    with open(os.path.join(config.GEOIP_PATH, fname), "rb") as fdesc, open(
        os.path.join(config.GEOIP_PATH, outname), "w"
    ) as out:
        for line in fdesc:
            start, stop = (
                utils.ip2int(elt)
                for elt in utils.net2range(line[:-1].split(None, 1)[0])
            )
            if cur:
                if start >= cur[0] and stop <= cur[1]:
                    continue
                if cur[0] <= start <= cur[1]:
                    cur = (cur[0], stop)
                    continue
                if cur[0] <= stop <= cur[1]:
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
                out.write("%d,%d\n" % cur)
            cur = (start, stop)
        if cur:
            out.write("%d,%d\n" % cur)


def unzip_all(
    fname: str,
    cond: Optional[Callable[[zipfile.ZipInfo], bool]] = None,
    clean: bool = True,
) -> None:
    assert config.GEOIP_PATH is not None
    with zipfile.ZipFile(os.path.join(config.GEOIP_PATH, fname)) as zdesc:
        for filedesc in zdesc.infolist():
            if cond and not cond(filedesc):
                continue
            with open(
                os.path.join(config.GEOIP_PATH, os.path.basename(filedesc.filename)),
                "wb",
            ) as wdesc:
                wdesc.write(zdesc.read(filedesc))
    if clean:
        os.unlink(os.path.join(config.GEOIP_PATH, fname))


def gunzip(fname: str, clean: bool = True) -> None:
    if not fname.endswith(".gz"):
        raise Exception('filename should end with ".gz"')
    assert config.GEOIP_PATH is not None
    with utils.open_file(os.path.join(config.GEOIP_PATH, fname)) as inp:
        with open(os.path.join(config.GEOIP_PATH, fname[:-3]), "wb") as outp:
            outp.write(inp.read())
    if clean:
        os.unlink(os.path.join(config.GEOIP_PATH, fname))


def untar_all(
    fname: str,
    cond: Optional[Callable[[tarfile.TarInfo], bool]] = None,
    clean: bool = True,
) -> None:
    assert config.GEOIP_PATH is not None
    with tarfile.TarFile(os.path.join(config.GEOIP_PATH, fname)) as tdesc:
        for filedesc in tdesc:
            if cond and not cond(filedesc):
                continue
            with open(
                os.path.join(config.GEOIP_PATH, os.path.basename(filedesc.name)), "wb"
            ) as wdesc:
                rdesc = tdesc.extractfile(filedesc)
                if rdesc is None:
                    continue
                wdesc.write(rdesc.read())
    if clean:
        os.unlink(os.path.join(config.GEOIP_PATH, fname))


def rename(src: str, dst: str) -> None:
    assert config.GEOIP_PATH is not None
    os.rename(
        os.path.join(config.GEOIP_PATH, src), os.path.join(config.GEOIP_PATH, dst)
    )


PARSERS: List[Tuple[Callable, List[str], Dict[str, Any]]] = [
    (
        unzip_all,
        ["GeoLite2-City-CSV.zip"],
        {"cond": lambda fdesc: fdesc.filename.endswith(".csv")},
    ),
    (
        unzip_all,
        ["GeoLite2-Country-CSV.zip"],
        {"cond": lambda fdesc: fdesc.filename.endswith(".csv")},
    ),
    (
        unzip_all,
        ["GeoLite2-ASN-CSV.zip"],
        {"cond": lambda fdesc: fdesc.filename.endswith(".csv")},
    ),
    (gunzip, ["GeoLite2-City.tar.gz"], {}),
    (
        untar_all,
        ["GeoLite2-City.tar"],
        {"cond": lambda fdesc: fdesc.name.endswith(".mmdb")},
    ),
    (gunzip, ["GeoLite2-Country.tar.gz"], {}),
    (
        untar_all,
        ["GeoLite2-Country.tar"],
        {"cond": lambda fdesc: fdesc.name.endswith(".mmdb")},
    ),
    (gunzip, ["GeoLite2-ASN.tar.gz"], {}),
    (
        untar_all,
        ["GeoLite2-ASN.tar"],
        {"cond": lambda fdesc: fdesc.name.endswith(".mmdb")},
    ),
    (gunzip, ["GeoLite2-dumps.tar.gz"], {}),
    (
        untar_all,
        ["GeoLite2-dumps.tar"],
        {"cond": lambda fdesc: fdesc.name.endswith(".csv")},
    ),
    (bgp_raw_to_csv, ["BGP.raw", "BGP.csv"], {}),
]


def download_all(verbose: bool = False) -> None:
    assert config.GEOIP_PATH is not None
    utils.makedirs(config.GEOIP_PATH)
    opener = build_opener()
    opener.addheaders = [("User-agent", "IVRE/%s +https://ivre.rocks/" % VERSION)]
    for fname, url in config.IPDATA_URLS.items():
        if url is None:
            if not fname.startswith("GeoLite2-"):
                continue
            if fname.startswith("GeoLite2-dumps."):
                continue
            basename, ext = fname.split(".", 1)
            url = (
                "https://download.maxmind.com/app/geoip_download?"
                "edition_id=%s&suffix=%s&license_key=%s"
                % (
                    basename,
                    ext,
                    config.MAXMIND_LICENSE_KEY,
                )
            )
        outfile = os.path.join(config.GEOIP_PATH, fname)
        if verbose:
            sys.stdout.write("Downloading %s to %s: " % (url, outfile))
            sys.stdout.flush()
        with open(outfile, "wb") as wdesc:
            udesc = opener.open(url)
            wdesc.write(udesc.read())
            if verbose:
                sys.stdout.write("done.\n")
    if verbose:
        sys.stdout.write("Unpacking: ")
        sys.stdout.flush()
    for func, args, kargs in PARSERS:
        try:
            func(*args, **kargs)
        except Exception:
            utils.LOGGER.warning(
                "A parser failed: %s(%s, %s)",
                func.__name__,
                ", ".join(args),
                ", ".join("%s=%r" % k_v for k_v in kargs.items()),
                exc_info=True,
            )
    if verbose:
        sys.stdout.write("done.\n")


def locids_by_country(country_code: str) -> Generator[int, None, None]:
    assert config.GEOIP_PATH is not None
    with codecs.open(
        os.path.join(
            config.GEOIP_PATH,
            "GeoLite2-Country-Locations-%s.csv" % config.GEOIP_LANG,
        ),
        encoding="utf-8",
    ) as fdesc:
        csvfd = csv.DictReader(fdesc)
        for line in csvfd:
            if line["country_iso_code"] == country_code:
                yield int(line["geoname_id"])


def locids_by_city(country_code: str, city_name: str) -> Generator[int, None, None]:
    assert config.GEOIP_PATH is not None
    with codecs.open(
        os.path.join(
            config.GEOIP_PATH,
            "GeoLite2-City-Locations-%s.csv" % config.GEOIP_LANG,
        ),
        encoding="utf-8",
    ) as fdesc:
        csvfd = csv.DictReader(fdesc)
        city_name = utils.encode_b64((city_name or "").encode("utf-8")).decode("utf-8")
        for line in csvfd:
            if (line["country_iso_code"], line["city_name"]) == (
                country_code,
                city_name,
            ):
                yield int(line["geoname_id"])


def locids_by_region(country_code: str, reg_code: str) -> Generator[int, None, None]:
    assert config.GEOIP_PATH is not None
    with codecs.open(
        os.path.join(
            config.GEOIP_PATH,
            "GeoLite2-City-Locations-%s.csv" % config.GEOIP_LANG,
        ),
        encoding="utf-8",
    ) as fdesc:
        csvfd = csv.DictReader(fdesc)
        for line in csvfd:
            if (line["country_iso_code"], line["subdivision_1_iso_code"]) == (
                country_code,
                reg_code,
            ):
                yield int(line["geoname_id"])


class IPRanges:
    def __init__(self, ranges: Optional[Iterable[Tuple[int, int]]] = None) -> None:
        """ranges must be given in the "correct" order *and* not
        overlap.

        """
        self.ranges: Dict[int, Tuple[int, int]] = {}
        self.length = 0
        if ranges is not None:
            for rnge in ranges:
                self.append(*rnge)

    def append(self, start: int, stop: int) -> None:
        length = stop - start + 1
        self.ranges[self.length] = (start, length)
        self.length += int(length)  # in case it's a long

    def union(self, *others: "IPRanges") -> "IPRanges":
        res = IPRanges()
        gens = [self.iter_int_ranges()] + [o.iter_int_ranges() for o in others]
        curs = []
        # We cannot use a `for itr in itrs` loop here because itrs is
        # modified in the loop.
        i = 0
        while i < len(gens):
            try:
                curs.append(list(next(gens[i])))
            except StopIteration:
                # We need to remove the corresponding generator from
                # gens, which happens to be the n-th where n is the
                # current length of next_recs.
                del gens[len(curs)]  # Do not increment i here
            else:
                i += 1
        while curs:
            cur_range = min(curs, key=lambda k: k[0])
            while True:
                # We cannot use a `for i in range(len(itrs))` loop because
                # itrs is modified in the loop.
                i = 0
                cur_range_modified = False
                while i < len(gens):
                    needs_continue = False
                    while curs[i][1] < cur_range[1]:
                        try:
                            curs[i] = list(next(gens[i]))
                        except StopIteration:
                            del gens[i]
                            del curs[i]
                            needs_continue = True
                            break  # Do not increment i
                        i += 1
                    if needs_continue:
                        continue
                    if curs[i][0] <= cur_range[1] + 1:
                        cur_range[1] = curs[i][1]
                        cur_range_modified = True
                        try:
                            curs[i] = list(next(gens[i]))
                        except StopIteration:
                            del gens[i]
                            del curs[i]
                            continue  # Do not increment i
                    i += 1
                if not cur_range_modified:
                    break
            res.append(*cur_range)
        return res

    def iter_int_ranges(self) -> Generator[Tuple[int, int], None, None]:
        for start, length in sorted(self.ranges.values()):
            yield start, start + length - 1

    def iter_ranges(self) -> Generator[Tuple[str, str], None, None]:
        for start, length in sorted(self.ranges.values()):
            yield utils.int2ip(start), utils.int2ip(start + length - 1)

    def iter_nets(self) -> Generator[str, None, None]:
        for start, length in sorted(self.ranges.values()):
            for net in utils.range2nets(
                (utils.int2ip(start), utils.int2ip(start + length - 1))
            ):
                yield net

    def iter_addrs(self) -> Generator[str, None, None]:
        for start, length in sorted(self.ranges.values()):
            for val in range(start, start + length):
                yield utils.int2ip(val)

    def __len__(self) -> int:
        return self.length

    def __getitem__(self, item: int) -> int:
        rangeindex = max(k for k in self.ranges if k <= item)
        item -= rangeindex
        rnge = self.ranges[rangeindex]
        if item < rnge[1]:
            return rnge[0] + item
        raise IndexError("index out of range")


ConditionCallback = Callable[[List[str]], bool]


def _get_by_data(
    datafile: str, condition: ConditionCallback
) -> Generator[Tuple[int, int], None, None]:
    assert config.GEOIP_PATH is not None
    with open(os.path.join(config.GEOIP_PATH, datafile)) as fdesc:
        for line in fdesc:
            line_parsed = line[:-1].split(",")
            if condition(line_parsed):
                yield int(line_parsed[0]), int(line_parsed[1])


def get_ranges_by_data(datafile: str, condition: ConditionCallback) -> IPRanges:
    rnge = IPRanges()
    for start, stop in _get_by_data(datafile, condition):
        rnge.append(start, stop)
    return rnge


def get_ranges_by_country(code: str) -> IPRanges:
    return get_ranges_by_data(
        "GeoLite2-Country.dump-IPv4.csv",
        lambda line: line[2] == code,
    )


def get_ranges_by_registered_country(code: str) -> IPRanges:
    return get_ranges_by_data(
        "GeoLite2-RegisteredCountry.dump-IPv4.csv",
        lambda line: line[2] == code,
    )


def get_ranges_by_location(locid: int) -> IPRanges:
    return get_ranges_by_data(
        "GeoLite2-City.dump-IPv4.csv", lambda line: line[5] == str(locid)
    )


def get_ranges_by_city(country_code: str, city: str) -> IPRanges:
    return get_ranges_by_data(
        "GeoLite2-City.dump-IPv4.csv",
        lambda line: line[2] == country_code
        and line[4] == utils.encode_b64((city or "").encode("utf-8")).decode("utf-8"),
    )


def get_ranges_by_region(country_code: str, reg_code: str) -> IPRanges:
    return get_ranges_by_data(
        "GeoLite2-City.dump-IPv4.csv",
        lambda line: line[2] == country_code and line[3] == reg_code,
    )


def get_ranges_by_asnum(asnum: int) -> IPRanges:
    return get_ranges_by_data(
        "GeoLite2-ASN.dump-IPv4.csv",
        lambda line: line[2] == str(asnum),
    )


def get_routable_ranges() -> IPRanges:
    return get_ranges_by_data("BGP.csv", lambda _: True)
