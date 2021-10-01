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


"""This sub-module contains functions that might be useful to any other
sub-module or script.

"""


import ast
import argparse
from bisect import bisect_left
import base64
import bz2
import datetime
import functools
import gzip
import hashlib
from io import BytesIO
import logging
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
from types import TracebackType
from typing import (
    Any,
    AnyStr,
    BinaryIO,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Match,
    Optional,
    Pattern,
    Set,
    Tuple,
    Type,
    Union,
    cast,
)
from urllib.parse import urlparse


try:
    from OpenSSL import crypto as osslc  # type: ignore
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    USE_PYOPENSSL = False
else:
    USE_PYOPENSSL = True
try:
    import PIL.Image  # type: ignore
    import PIL.ImageChops  # type: ignore
except ImportError:
    USE_PIL = False
else:
    USE_PIL = True


from ivre import config
from ivre.types import NmapProbe, NmapProbeRec, NmapServiceMatch, Record


# (1)
# http://docs.mongodb.org/manual/core/indexes/#index-behaviors-and-limitations
# (2) http://docs.mongodb.org/manual/reference/limits/#limit-index-size
# (1) says that "Index keys can be no larger than 1024 bytes. This
# includes the field value or values, the field name or names, and the
# namespace." On the other hand, (2) says that "Indexed items can be
# no larger than 1024 bytes. This value is the indexed content
# (i.e. the field value, or compound field value.)". From what we've
# seen, it seems that (1) is right.
MAXVALLEN = 1000


LOGGER = logging.getLogger("ivre")
REGEXP_T = type(re.compile(""))
HEX = re.compile("^[a-f0-9]+$", re.IGNORECASE)
STRPTIME_SUPPORTS_TZ = sys.version_info >= (3, 7)


# IP address regexp, based on
# https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8

# _IPV4SEG = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
# _IPV4ADDR = r'(?:(?:%s\.){3,3}%s)' % (_IPV4SEG, _IPV4SEG)
# _IPV6SEG = r'(?:(?:[0-9a-fA-F]){1,4})'
# _IPV6GROUPS = (
#     r'(?:%s:){7,7}%s' % (_IPV6SEG, _IPV6SEG),
#     r'(?:%s:){1,7}:' % (_IPV6SEG, ),
#     r'(?:%s:){1,6}:%s' % (_IPV6SEG, _IPV6SEG),
#     r'(?:%s:){1,5}(?::%s){1,2}' % (_IPV6SEG, _IPV6SEG),
#     r'(?:%s:){1,4}(?::%s){1,3}' % (_IPV6SEG, _IPV6SEG),
#     r'(?:%s:){1,3}(?::%s){1,4}' % (_IPV6SEG, _IPV6SEG),
#     r'(?:%s:){1,2}(?::%s){1,5}' % (_IPV6SEG, _IPV6SEG),
#     r'%s:(?:(?::%s){1,6})' % (_IPV6SEG, _IPV6SEG),
#     r':(?:(?::%s){1,7}|:)' % (_IPV6SEG, ),
#     r'fe80:(?::%s){0,4}%%[0-9a-zA-Z]{1,}' % (_IPV6SEG, ),
#     r'::(?:ffff(?::0{1,4}){0,1}:){0,1}%s' % (_IPV4ADDR, ),
#     r'(?:%s:){1,4}:%s' % (_IPV6SEG, _IPV4ADDR),
# )
# _IPV6ADDR = '|'.join(
#     # Reverse rows for greedy match
#     '(?:%s)' % g for g in _IPV6GROUPS[::-1]
# )
# _IPADDR = '^(%s|%s)$' % (_IPV4ADDR, _IPV6ADDR)
# _NETMASK = r'(?:12[0-8]|1[0-1][0-9]|0?[0-9]{1,2})'
# _NETADDR = '^(%s|%s)/(%s|%s)$' % (_IPV4ADDR, _IPV6ADDR, _NETMASK, _IPV4ADDR)
IPADDR = re.compile(
    "^((?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|("
    "?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,4}:("
    "?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2"
    "[0-4]|1{0,1}[0-9]){0,1}[0-9])))|(?:::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:"
    "(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]"
    "|1{0,1}[0-9]){0,1}[0-9])))|(?:fe80:(?::(?:(?:[0-9a-fA-F]){1,4})){0,4}%[0-"
    "9a-zA-Z]{1,})|(?::(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,7}|:))|(?:(?:(?:[0-9"
    "a-fA-F]){1,4}):(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,6}))|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,2}(?::(?:(?:[0-9a-fA-F]){1,4})){1,5})|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,3}(?::(?:(?:[0-9a-fA-F]){1,4})){1,4})|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,4}(?::(?:(?:[0-9a-fA-F]){1,4})){1,3})|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,5}(?::(?:(?:[0-9a-fA-F]){1,4})){1,2})|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,6}:(?:(?:[0-9a-fA-F]){1,4}))|(?:(?:(?:(?:[0-9a-fA-F]){1,"
    "4}):){1,7}:)|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){7,7}(?:(?:[0-9a-fA-F]){1,4}"
    ")))$",
    re.I,
)
NETADDR = re.compile(
    "^((?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|("
    "?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,4}:("
    "?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2"
    "[0-4]|1{0,1}[0-9]){0,1}[0-9])))|(?:::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:"
    "(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]"
    "|1{0,1}[0-9]){0,1}[0-9])))|(?:fe80:(?::(?:(?:[0-9a-fA-F]){1,4})){0,4}%[0-"
    "9a-zA-Z]{1,})|(?::(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,7}|:))|(?:(?:(?:[0-9"
    "a-fA-F]){1,4}):(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,6}))|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,2}(?::(?:(?:[0-9a-fA-F]){1,4})){1,5})|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,3}(?::(?:(?:[0-9a-fA-F]){1,4})){1,4})|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,4}(?::(?:(?:[0-9a-fA-F]){1,4})){1,3})|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,5}(?::(?:(?:[0-9a-fA-F]){1,4})){1,2})|(?:(?:(?:(?:[0-9a-"
    "fA-F]){1,4}):){1,6}:(?:(?:[0-9a-fA-F]){1,4}))|(?:(?:(?:(?:[0-9a-fA-F]){1,"
    "4}):){1,7}:)|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){7,7}(?:(?:[0-9a-fA-F]){1,4}"
    ")))/((?:12[0-8]|1[0-1][0-9]|0?[0-9]{1,2})|(?:(?:(?:25[0-5]|(?:2[0-4]|1{0,"
    "1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    ")$",
    re.I,
)
IPV4ADDR = re.compile(
    "^(?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?"
    ":2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$",
    re.I,
)
MACADDR = re.compile("^(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}", re.I)

NMAP_FINGERPRINT_IVRE_KEY = {
    "d": "service_devicetype",
    "h": "service_hostname",
    "i": "service_extrainfo",
    "o": "service_ostype",
    "p": "service_product",
    "v": "service_version",
    "cpe": "cpe",
}

logging.basicConfig()


def is_valid_ip(ipstr: AnyStr) -> bool:
    """Return True iff `ipstr` is a valid IP address."""
    if isinstance(ipstr, bytes):
        data = ipstr.decode()
    else:
        data = ipstr
    try:
        socket.inet_aton(data)
    except socket.error:
        pass
    else:
        return True
    try:
        socket.inet_pton(socket.AF_INET6, data)
    except socket.error:
        return False
    return True


def ip2int(ipstr: AnyStr) -> int:
    """Converts the classical decimal, dot-separated, string
    representation of an IPv4 address, or the hexadecimal,
    colon-separated, string representation of an IPv6 address, to an
    integer.

    """
    if isinstance(ipstr, bytes):
        data = ipstr.decode()
    else:
        data = ipstr
    try:
        return cast(int, struct.unpack("!I", socket.inet_aton(data))[0])
    except socket.error:
        val1: int
        val2: int
        val1, val2 = struct.unpack(
            "!QQ",
            socket.inet_pton(socket.AF_INET6, data),
        )
        return (val1 << 64) + val2


def force_ip2int(ipstr: Union[AnyStr, int]) -> int:
    """Same as ip2int(), but works when ipstr is already an int"""
    if isinstance(ipstr, (str, bytes)):
        return ip2int(ipstr)
    return ipstr


def int2ip(ipint: int) -> str:
    """Converts the integer representation of an IP address to its
    classical decimal, dot-separated (for IPv4) or hexadecimal,
    colon-separated (for IPv6) string representation.

    """
    try:
        return socket.inet_ntoa(struct.pack("!I", ipint))
    except struct.error:
        return socket.inet_ntop(
            socket.AF_INET6,
            struct.pack("!QQ", ipint >> 64, ipint & 0xFFFFFFFFFFFFFFFF),
        )


def int2ip6(ipint: int) -> str:
    """Converts the integer representation of an IPv6 address to its
    classical decimal, hexadecimal, colon-separated string
    representation.

    """
    return socket.inet_ntop(
        socket.AF_INET6,
        struct.pack("!QQ", ipint >> 64, ipint & 0xFFFFFFFFFFFFFFFF),
    )


def force_int2ip(ipint: Union[int, str]) -> str:
    """Same as int2ip(), but works when ipint is already a atring"""
    if isinstance(ipint, int):
        return int2ip(ipint)
    return ipint


def ip2bin(ipval: Union[AnyStr, int]) -> bytes:
    """Attempts to convert any IP address representation (both IPv4 and
    IPv6) to a 16-bytes binary blob.

    IPv4 addresses are converted to IPv6 using the standard ::ffff:A.B.C.D
    mapping.

    """
    if isinstance(ipval, int):
        return struct.pack("!QQ", ipval >> 64, ipval & 0xFFFFFFFFFFFFFFFF)
    if isinstance(ipval, bytes):
        # Possibly already a binary representation
        if len(ipval) == 16:
            return ipval
        if len(ipval) == 4:
            return b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + ipval
        try:
            data = ipval.decode()
        except UnicodeDecodeError:
            raise ValueError("Invalid IP address %r" % ipval)
    else:
        data = ipval
    try:
        return b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + socket.inet_aton(
            data
        )
    except socket.error:
        pass
    try:
        return socket.inet_pton(socket.AF_INET6, data)
    except socket.error:
        raise ValueError("Invalid IP address %r" % ipval)


def bin2ip(ipval: Union[AnyStr, int]) -> str:
    """Converts a 16-bytes binary blob to an IPv4 or IPv6 standard
    representation. See ip2bin().

    """
    if isinstance(ipval, str):
        try:
            socket.inet_aton(ipval)
            return ipval
        except socket.error:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, ipval)
            return ipval
        except socket.error:
            raise ValueError("Invalid IP address %r" % ipval)
    if isinstance(ipval, int):
        return int2ip(ipval)
    if ipval[:12] == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff":
        return socket.inet_ntoa(ipval[12:])
    return socket.inet_ntop(socket.AF_INET6, ipval)


def int2mask(mask: int) -> int:
    """Converts the number of bits set to 1 in a mask (the 24 in
    10.0.0.0/24) to the 32-bit integer corresponding to the IP address
    of the mask (ip2int("255.255.255.0") for 24)

    From scapy:utils.py:itom(x).

    """
    return (0xFFFFFFFF00000000 >> mask) & 0xFFFFFFFF


def int2mask6(mask: int) -> int:
    """Converts the number of bits set to 1 in a mask (the 48 in
    2001:db8:1234::/48) to the 128-bit integer corresponding to the IP address
    of the mask (ip2int("ffff:ffff:ffff::") for 48)

    """
    return (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000 >> mask
    ) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


def net2range(network: AnyStr) -> Tuple[str, str]:
    """Converts a network to a (start, stop) tuple."""
    if isinstance(network, bytes):
        data = network.decode()
    else:
        data = network
    addr, mask = data.split("/")
    ipv6 = ":" in addr
    addr_int = ip2int(addr)
    if (not ipv6 and "." in mask) or (ipv6 and ":" in mask):
        mask_int = ip2int(mask)
    elif ipv6:
        mask_int = int2mask6(int(mask))
    else:
        mask_int = int2mask(int(mask))
    start = addr_int & mask_int
    if ipv6:
        return int2ip6(start), int2ip6(
            start + 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF - mask_int
        )
    return int2ip(start), int2ip(start + 0xFFFFFFFF - mask_int)


def range2nets(rng: Tuple[Union[AnyStr, int], Union[AnyStr, int]]) -> List[str]:
    """Converts a (start, stop) tuple to a list of networks."""
    start, stop = (force_ip2int(addr) for addr in rng)
    if stop < start:
        raise ValueError()
    res = []
    cur = start
    maskint = 32
    mask = int2mask(maskint)
    while True:
        while cur & mask == cur and cur | (~mask & 0xFFFFFFFF) <= stop:
            maskint -= 1
            if maskint < 0:
                break
            mask = int2mask(maskint)
        res.append("%s/%d" % (int2ip(cur), maskint + 1))
        mask = int2mask(maskint + 1)
        if stop & mask == cur:
            return res
        cur = (cur | (~mask & 0xFFFFFFFF)) + 1
        maskint = 32
        mask = int2mask(maskint)


def get_domains(name: str) -> Generator[str, None, None]:
    """Generates the upper domains from a domain name."""
    data = name.split(".")
    return (".".join(data[i:]) for i in range(len(data)))


def _espace_slash(string: str) -> str:
    """This function transforms '\\/' in '/' but leaves '\\\\/' unchanged. This
    is useful to parse regexp from Javascript style (/regexp/).

    """
    escaping = False
    new_string = ""
    for char in string:
        if not escaping and char == "\\":
            escaping = True
        elif escaping and char != "/":
            new_string += "\\" + char
            escaping = False
        else:
            new_string += char
            escaping = False
    return new_string


def _escape_first_slash(string: str) -> str:
    """This function removes the first '\\' if the string starts with '\\/'."""
    if string.startswith("\\/"):
        string = string[1:]
    return string


def str2regexp(string: str) -> Union[str, Pattern[str]]:
    """This function takes a string and returns either this string or
    a python regexp object, when the string is using the syntax
    /regexp[/flags].
    """
    if not string.startswith("/"):
        return _escape_first_slash(string)
    string = string[1:]
    try:
        string, flags_str = string.rsplit("/", 1)
    except ValueError:
        flags = 0
    else:
        flags = sum(getattr(re, f.upper()) for f in flags_str)
    # Enable slash-escape even if it is not necessary
    return re.compile(_espace_slash(string), flags)


def str2regexpnone(value: str) -> Union[str, Pattern[str], bool]:
    """Just like str2regexp, but handle special '-' value, which means
    False.

    """
    if value == "-":
        return False
    return str2regexp(value)


def regexp2pattern(
    string: Union[Union[str, bytes], Pattern]
) -> Tuple[Union[str, bytes], int]:
    """This function takes a regexp or a string and returns a pattern and
    some flags, suitable for use with re.compile(), combined with
    another pattern before. Useful, for example, if you want to create
    a regexp like '^ *Set-Cookie: *[name]=[value]' where name and
    value are regexp.

    """
    if isinstance(string, REGEXP_T):
        flags = string.flags
        data = string.pattern
        patterns = ("^", "$", ".*") if isinstance(data, str) else (b"^", b"$", b".*")
        if data.startswith(patterns[0]):
            data = data[1:]
        # elif data.startswith('('):
        #     raise ValueError("Regexp starting with a group are not "
        #                      "(yet) supported")
        else:
            data = patterns[2] + data
        if data.endswith(patterns[1]):
            data = data[:-1]
        # elif data.endswith(')'):
        #     raise ValueError("Regexp ending with a group are not "
        #                      "(yet) supported")
        else:
            data += patterns[2]
        return data, flags
    if isinstance(string, bytes):
        return re.escape(string), 0
    if isinstance(string, str):
        return re.escape(string), re.UNICODE
    raise TypeError()


def str2list(string: AnyStr) -> Union[AnyStr, List[AnyStr]]:
    """This function takes a string and returns either this string or
    a list of the coma-or-pipe separated elements from the string.

    """
    patterns = (",", "|") if isinstance(string, str) else (b",", b"|")
    if patterns[0] in string or patterns[1] in string:
        return string.replace(patterns[1], patterns[0]).split(patterns[0])
    return string


_PYVALS = {
    "true": True,
    "false": False,
    "null": None,
    "none": None,
}


def str2pyval(string: str) -> Any:
    """This function takes a string and returns a Python object"""
    try:
        return ast.literal_eval(string)
    except (ValueError, SyntaxError):
        # "special" values, fallback as simple string
        return _PYVALS.get(string, string)


def ports2nmapspec(portlist: Iterable[int]) -> str:
    """This function takes an iterable and returns a string
    suitable for use as argument for Nmap's -p option.

    """
    # unique and sorted (http://stackoverflow.com/a/13605607/3223422)
    portlist = sorted(set(portlist))
    result: List[str] = []
    current: Tuple[Optional[int], Optional[int]] = (None, None)
    for port in portlist:
        if port - 1 == current[1]:
            current = (current[0], port)
        else:
            if current[0] is not None:
                result.append(
                    str(current[0]) if current[0] == current[1] else "%d-%d" % current  # type: ignore
                )
            current = (port, port)
    if current[0] is not None:
        result.append(
            str(current[0]) if current[0] == current[1] else "%d-%d" % current  # type: ignore
        )
    return ",".join(result)


def nmapspec2ports(string: str) -> Set[int]:
    """This function takes a string suitable for use as argument for
    Nmap's -p option and returns the corresponding set of ports.

    """
    result: Set[int] = set()
    for ports in string.split(","):
        if "-" in ports:
            port1, port2 = (int(port) for port in ports.split("-", 1))
            result = result.union(range(port1, port2 + 1))
        else:
            result.add(int(ports))
    return result


def all2datetime(arg: Union[int, float, str, datetime.datetime]) -> datetime.datetime:
    """Return a datetime object from an int (timestamp) or an iso
    formatted string '%Y-%m-%d %H:%M:%S'.

    """
    if isinstance(arg, datetime.datetime):
        return arg
    if isinstance(arg, str):
        for fmt in [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]:
            try:
                return datetime.datetime.strptime(arg, fmt)
            except ValueError:
                pass
        raise ValueError("time data %r does not match standard formats" % arg)
    if isinstance(arg, (int, float)):
        return datetime.datetime.fromtimestamp(arg)
    raise TypeError("%s is of unknown type." % repr(arg))


def makedirs(dirname: AnyStr) -> None:
    """Makes directories like mkdir -p, raising no exception when
    dirname already exists.

    """
    try:
        os.makedirs(dirname)
    except FileExistsError:
        pass


def cleandir(dirname: AnyStr) -> None:
    """Removes a complete tree, like rm -rf on a directory, raising no
    exception when dirname does not exist.

    """
    try:
        shutil.rmtree(dirname)
    except FileNotFoundError:
        pass


def isfinal(elt: Any) -> bool:
    """Decides whether or not elt is a final element (i.e., an element
    that does not contain other elements)

    """
    return isinstance(elt, (str, int, float, datetime.datetime, REGEXP_T))


def diff(doc1: Dict[str, Any], doc2: Dict[str, Any]) -> Dict[str, Any]:
    """NOT WORKING YET - WORK IN PROGRESS - Returns fields that differ
    between two scans.

    """
    keys1 = set(doc1)
    keys2 = set(doc2)
    res: Dict[str, Any] = {}
    for key in keys1.symmetric_difference(keys2):
        res[key] = True
    for key in keys1.intersection(keys2):
        if isfinal(doc1[key]) or isfinal(doc2[key]):
            if doc1[key] != doc2[key]:
                res[key] = True
                continue
            continue
        if key in ["categories"]:
            set1 = set(doc1[key])
            set2 = set(doc2[key])
            res[key] = list(set1.symmetric_difference(set2))
            if not res[key]:
                del res[key]
            continue
        if key == "extraports":
            res[key] = {}
            for state in set(doc1[key]).union(doc2[key]):
                if doc1[key].get(state) != doc2[key].get(state):
                    res[key][state] = True
            if not res[key]:
                del res[key]
            continue
        if key in ["ports"]:
            res[key] = {}
            kkeys1 = set(t["port"] for t in doc1["ports"])
            kkeys2 = set(t["port"] for t in doc2["ports"])
            for kkey in kkeys1.symmetric_difference(kkeys2):
                res[key][kkey] = True
            for kkey in kkeys1.intersection(kkeys2):
                pass
    return res


def fields2csv_head(fields: Dict[str, Any], prefix: str = "") -> List[str]:
    """Given an (ordered) dictionary `fields`, returns a list of the
    fields. NB: recursive function, hence the `prefix` parameter.

    """
    line = []
    for field, subfields in fields.items():
        if subfields is True or callable(subfields):
            line.append(prefix + field)
        elif isinstance(subfields, dict):
            line += fields2csv_head(subfields, prefix=prefix + field + ".")
    return line


def doc2csv(doc: Record, fields: Dict[str, Any], nastr: str = "NA") -> List[list]:
    """Given a document and an (ordered) dictionary `fields`, returns
    a list of CSV lines. NB: recursive function.

    """
    lines: List[list] = [[]]
    for field, subfields in fields.items():
        if subfields is True:
            value = doc.get(field)
            if isinstance(value, list):
                lines = [
                    line + [nastr if valelt is None else valelt]
                    for line in lines
                    for valelt in value
                ]
            else:
                lines = [line + [nastr if value is None else value] for line in lines]
        elif callable(subfields):
            value = doc.get(field)
            if isinstance(value, list):
                lines = [
                    line + [nastr if valelt is None else subfields(valelt)]
                    for line in lines
                    for valelt in value
                ]
            else:
                lines = [
                    line + [nastr if value is None else subfields(value)]
                    for line in lines
                ]
        elif isinstance(subfields, dict):
            subdoc = doc.get(field)
            if isinstance(subdoc, list):
                lines = [
                    line + newline
                    for line in lines
                    for subdocelt in subdoc
                    for newline in doc2csv(subdocelt, subfields, nastr=nastr)
                ]
            elif subdoc is None:
                lines = [
                    line + newline
                    for line in lines
                    for newline in doc2csv({}, subfields, nastr=nastr)
                ]
            else:
                lines = [
                    line + newline
                    for line in lines
                    for newline in doc2csv(subdoc, subfields, nastr=nastr)
                ]
    return lines


class FileOpener(BinaryIO):
    """A file-like object, working with gzip or bzip2 compressed files.

    Uses subprocess.Popen() to call zcat or bzcat by default (much
    faster), fallbacks to gzip.open or bz2.BZ2File.

    """

    FILE_OPENERS_MAGIC: Dict[bytes, Callable] = {
        b"\x1f\x8b": gzip.open,
        b"BZ": bz2.BZ2File,
    }

    def __init__(self, fname: Union[str, BinaryIO]) -> None:
        if not isinstance(fname, str):
            self.fdesc = fname
            self.needsclose = False
            return
        self.needsclose = True
        with open(fname, "rb") as fdesc:
            magic = fdesc.read(2)
        try:
            py_opener = self.FILE_OPENERS_MAGIC[magic]
        except KeyError:
            # Not a compressed file
            # pylint: disable=consider-using-with
            self.fdesc = open(fname, "rb")
            return
        self.fdesc = py_opener(fname)

    def read(self, *args) -> bytes:  # type: ignore
        return self.fdesc.read(*args)

    def readline(self, limit: int = -1) -> bytes:
        return self.fdesc.readline(limit)

    def fileno(self) -> int:
        return self.fdesc.fileno()

    def close(self) -> None:
        # since .close() is explicitly called, we close self.fdesc
        # even when self.close is False.
        self.fdesc.close()

    def __enter__(self) -> "FileOpener":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        if self.needsclose:
            self.fdesc.close()

    def __iter__(self) -> "FileOpener":
        return self

    def __next__(self) -> bytes:
        return next(self.fdesc)

    # The following methods ensure we have a BinaryIO compatible type

    @property
    def closed(self) -> bool:
        return self.fdesc.closed

    @property
    def mode(self) -> str:
        return self.fdesc.mode

    @property
    def name(self) -> str:
        return self.fdesc.name

    def flush(self) -> None:
        self.fdesc.flush()

    def isatty(self) -> bool:
        return self.fdesc.isatty()

    def readable(self) -> bool:
        return self.fdesc.readable()

    def readlines(self, hint: int = -1) -> List[bytes]:
        return self.fdesc.readlines(hint)

    def seekable(self) -> bool:
        return self.fdesc.seekable()

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.fdesc.seek(offset, whence=whence)

    def tell(self) -> int:
        return self.fdesc.tell()

    def truncate(self, size: Optional[int] = None) -> int:
        return self.fdesc.truncate(size=size)

    def writable(self) -> bool:
        return self.fdesc.writable()

    def write(self, s: bytes) -> int:
        return self.fdesc.write(s)

    def writelines(self, lines: Iterable[bytes]) -> None:
        self.fdesc.writelines(lines)


def open_file(fname: str) -> FileOpener:
    return FileOpener(fname)


def hash_file(fname: str, hashtype: str = "sha1") -> bytes:
    """Compute a hash of data from a given file"""
    with open_file(fname) as fdesc:
        result = hashlib.new(hashtype)
        for data in iter(lambda: fdesc.read(1048576), b""):
            result.update(data)
        return result.hexdigest().encode()


def serialize(obj: Any) -> str:
    """Return a JSON-compatible representation for `obj`"""
    if isinstance(obj, REGEXP_T):
        return "/%s/%s" % (
            obj.pattern,
            "".join(x.lower() for x in "ILMSXU" if getattr(re, x) & obj.flags),
        )
    if isinstance(obj, datetime.datetime):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.decode()
    raise TypeError("Don't know what to do with %r (%r)" % (obj, type(obj)))


class LogFilter(logging.Filter):
    """A logging filter that prevents duplicate warnings and only reports
    messages with level lower than INFO when config.DEBUG (or
    config.DEBUG_DB) is True.

    """

    MAX_WARNINGS_STORED = 100

    def __init__(self) -> None:
        super().__init__()
        self.warnings: Set[str] = set()

    def filter(self, record: logging.LogRecord) -> bool:
        """Decides whether we should log a record"""
        if record.levelno < logging.INFO:
            if record.msg.startswith("DB:"):
                return config.DEBUG_DB
            return config.DEBUG
        if record.levelno != logging.WARNING:
            return True
        if record.msg in self.warnings:
            return False
        if len(self.warnings) > self.MAX_WARNINGS_STORED:
            self.warnings = set()
        self.warnings.add(record.msg)
        return True


LOGGER.addFilter(LogFilter())
LOGGER.setLevel(1 if config.DEBUG or config.DEBUG_DB else 20)


CLI_ARGPARSER = argparse.ArgumentParser(add_help=False)
# DB
CLI_ARGPARSER.add_argument(
    "--init",
    "--purgedb",
    action="store_true",
    help="Purge or create and initialize the database.",
)
CLI_ARGPARSER.add_argument(
    "--ensure-indexes",
    action="store_true",
    help="Create missing indexes (will lock the " "database).",
)
CLI_ARGPARSER.add_argument(
    "--update-schema",
    action="store_true",
    help="update (host) schema. Use with --version to " "specify your current version",
)
# Actions / display modes
CLI_ARGPARSER.add_argument(
    "--delete",
    action="store_true",
    help="DELETE the matched results instead of " "displaying them.",
)
CLI_ARGPARSER.add_argument(
    "--short", action="store_true", help="Output only IP addresses, one per line."
)
CLI_ARGPARSER.add_argument(
    "--count", action="store_true", help="Count matched results."
)
CLI_ARGPARSER.add_argument(
    "--explain", action="store_true", help="MongoDB specific: .explain() the query."
)
CLI_ARGPARSER.add_argument(
    "--distinct",
    metavar="FIELD",
    help="Output only unique FIELD part of the " "results, one per line.",
)
CLI_ARGPARSER.add_argument(
    "--json", action="store_true", help="Output results as JSON documents."
)
CLI_ARGPARSER.add_argument(
    "--http-urls",
    action="store_true",
    help="Output results as HTTP URLs, one per line.",
)
CLI_ARGPARSER.add_argument(
    "--sort",
    metavar="FIELD / ~FIELD",
    nargs="+",
    help="Sort results according to FIELD; use " "~FIELD to reverse sort order.",
)
CLI_ARGPARSER.add_argument("--limit", type=int, help="Output at most LIMIT results.")
CLI_ARGPARSER.add_argument("--skip", type=int, help="Skip first SKIP results.")


# Country aliases:
#   - UK: GB
#   - EU: 27 EU member states, + EU itself, for historical reasons
COUNTRY_ALIASES: Dict[str, Union[str, List[str]]] = {
    "UK": "GB",
    "EU": [
        "AT",
        "BE",
        "BG",
        "HR",
        "CY",
        "CZ",
        "DK",
        "EE",
        "FI",
        "FR",
        "DE",
        "GR",
        "HU",
        "IE",
        "IT",
        "LV",
        "LT",
        "LU",
        "MT",
        "NL",
        "PL",
        "PT",
        "RO",
        "SK",
        "SI",
        "ES",
        "SE",
        "EU",
    ],
}


def country_unalias(country: Union[str, Iterable[str]]) -> Union[str, List[str]]:
    """Takes either a country code (or an iterator of country codes)
    and returns either a country code or a list of country codes.

    Current aliases are:

      - "UK": alias for "GB".

      - "EU": alias for a list containing the list of the country
        codes of the European Union member states. It also includes
        "EU" itself, because that was a valid "country" code in
        previous Maxmind GeoIP databases.

    """
    if isinstance(country, str):
        return COUNTRY_ALIASES.get(country, country)
    if hasattr(country, "__iter__"):
        empty: List[str] = []
        return functools.reduce(
            lambda x, y: x + (y if isinstance(y, list) else [y]),
            (country_unalias(country_elt) for country_elt in country),
            empty,
        )
    raise TypeError("country should be a string or an iterable of strings")


_WORDS = re.compile(b"\\w+")


def screenwords(imgdata: bytes) -> Optional[List[str]]:
    """Takes an image and returns a list of the words seen by the OCR"""
    if config.TESSERACT_CMD is not None:
        # pylint: disable=consider-using-with
        proc = subprocess.Popen(
            [config.TESSERACT_CMD, "stdin", "stdout"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        assert proc.stdin is not None
        assert proc.stdout is not None
        proc.stdin.write(imgdata)
        proc.stdin.close()
        words = set()
        result = []
        size = MAXVALLEN
        for line in proc.stdout:
            if size == 0:
                break
            for word_match in _WORDS.finditer(line):
                word_bytes = word_match.group()
                try:
                    word = word_bytes.decode().lower()
                except UnicodeDecodeError:
                    continue
                if word in words:
                    continue
                if len(word) <= size:
                    words.add(word)
                    result.append(word)
                    size -= len(word)
                else:
                    # When we meet the first word that would make
                    # result too big, we stop immediately. This
                    # choice has been made to limit the time spent
                    # here.
                    size = 0
                    break
        if result:
            return result
    return None


if USE_PIL:

    def _img_size(bbox: Tuple[int, int, int, int]) -> int:
        """Returns the size of a given `bbox`"""
        return (bbox[2] - bbox[0]) * (bbox[3] - bbox[1])

    def _trim_image(
        img: PIL.Image, tolerance: int
    ) -> Optional[Tuple[int, int, int, int]]:
        """Returns the tiniest `bbox` to trim `img`"""
        result = None
        for pixel in [
            (0, 0),
            (img.size[0] - 1, 0),
            (0, img.size[1] - 1),
            (img.size[0] - 1, img.size[1] - 1),
        ]:
            if (
                result is not None
                and result[0] < pixel[0] < result[2] - 1
                and result[1] < pixel[1] < result[3] - 1
            ):
                # This pixel is already removed by current result
                continue
            bkg = PIL.Image.new(img.mode, img.size, img.getpixel(pixel))
            diffbkg = PIL.ImageChops.difference(img, bkg)
            if tolerance:
                diffbkg = PIL.ImageChops.add(diffbkg, diffbkg, 2.0, -tolerance)
            bbox = diffbkg.getbbox()
            if not bbox:
                # Image no longer exists after trim
                return None
            if result is None:
                result = bbox
            elif _img_size(bbox) < _img_size(result):
                result = bbox
        return result

    def trim_image(
        imgdata: bytes, tolerance: int = 1, minborder: int = 10
    ) -> Union[bytes, bool]:
        """Trims the image, `tolerance` is an integer from 0 (not
        tolerant, trims region with the exact same color) to 255
        (too tolerant, will trim the whole image).

        """
        img = PIL.Image.open(BytesIO(imgdata))
        bbox = _trim_image(img, tolerance)
        if bbox:
            newbbox = (
                max(bbox[0] - minborder, 0),
                max(bbox[1] - minborder, 0),
                img.size[0] - max(img.size[0] - bbox[2] - minborder, 0),
                img.size[1] - max(img.size[1] - bbox[3] - minborder, 0),
            )
            if newbbox != (0, 0, img.size[0], img.size[1]):
                out = BytesIO()
                img.crop(newbbox).save(out, format="jpeg")
                out.seek(0)
                return out.read()
            # Image does not need to be modified
            return True
        # Image no longer exists after trim
        return False


else:

    def trim_image(
        imgdata: bytes, tolerance: int = 1, minborder: int = 10
    ) -> Union[bytes, bool]:
        """Stub function used when PIL cannot be found"""
        LOGGER.warning("Python PIL not found, screenshots will not be trimmed")
        return imgdata


_PORTS: Dict[str, Dict[int, float]] = {}
_PORTS_POPULATED = False


def _set_ports() -> None:
    """Populate _PORTS global dict, based on nmap-services when available
    (and found), with a fallback to /etc/services.

        This function is called on module load.

    """
    global _PORTS, _PORTS_POPULATED
    try:
        # pylint: disable=consider-using-with
        assert config.NMAP_SHARE_PATH is not None
        fdesc = open(os.path.join(config.NMAP_SHARE_PATH, "nmap-services"))
    except (IOError, AttributeError, AssertionError):
        try:
            with open("/etc/services") as fdesc:
                for line in fdesc:
                    try:
                        _, port_s = line.split("#", 1)[0].split(None, 2)
                        port_s, proto = port_s.split("/", 1)
                        port = int(port_s)
                    except ValueError:
                        continue
                    _PORTS.setdefault(proto, {})[port] = 0.5
        except IOError:
            pass
    else:
        for line in fdesc:
            try:
                _, port_s, freq_s = line.split("#", 1)[0].split(None, 3)
                port_s, proto = port_s.split("/", 1)
                port = int(port_s)
                freq = float(freq_s)
            except ValueError:
                continue
            _PORTS.setdefault(proto, {})[port] = freq
        fdesc.close()
    for proto, entry in config.KNOWN_PORTS.items():
        for port, proba in entry.items():
            _PORTS.setdefault(proto, {})[port] = proba
    _PORTS_POPULATED = True


def guess_srv_port(port1: int, port2: int, proto: str = "tcp") -> int:
    """Returns 1 when port1 is probably the server port, -1 when that's
    port2, and 0 when we cannot tell.

    """
    if not _PORTS_POPULATED:
        _set_ports()
    ports = _PORTS.get(proto, {})
    val1, val2 = ports.get(port1, 0), ports.get(port2, 0)
    cmpval = (val1 > val2) - (val1 < val2)
    if cmpval == 0:
        return (port2 > port1) - (port2 < port1)
    return cmpval


_NMAP_PROBES: Dict[
    str,
    Dict[str, NmapProbeRec],
] = {}
_NMAP_PROBES_POPULATED = False
_NMAP_CUR_PROBE: Optional[NmapProbe] = None
_NMAP_CUR_FALLBACK: Optional[List[str]] = None


def _read_nmap_probes() -> None:
    global _NMAP_CUR_PROBE, _NMAP_CUR_FALLBACK, _NMAP_PROBES_POPULATED
    _NMAP_CUR_PROBE = None
    _NMAP_CUR_FALLBACK = None

    def parse_line(line: bytes) -> None:
        global _NMAP_PROBES, _NMAP_CUR_PROBE, _NMAP_CUR_FALLBACK
        if line.startswith(b"match "):
            line = line[6:]
            soft = False
        elif line.startswith(b"softmatch "):
            line = line[10:]
            soft = True
        elif line.startswith(b"fallback "):
            assert _NMAP_CUR_FALLBACK is not None
            _NMAP_CUR_FALLBACK.append(line[9:].decode())
            return
        elif line.startswith(b"Probe "):
            _NMAP_CUR_PROBE = []
            _NMAP_CUR_FALLBACK = []
            proto, name, probe = line[6:].split(b" ", 2)
            if not (len(probe) >= 3 and probe[:2] == b"q|" and probe[-1:] == b"|"):
                LOGGER.warning("Invalid nmap probe %r", probe)
            else:
                probe = nmap_decode_data(probe[2:-1].decode(), arbitrary_escapes=True)
            assert _NMAP_CUR_PROBE is not None
            assert _NMAP_CUR_FALLBACK is not None
            _NMAP_PROBES.setdefault(proto.lower().decode(), {})[name.decode()] = {
                "probe": probe,
                "fp": _NMAP_CUR_PROBE,
                "fallbacks": _NMAP_CUR_FALLBACK,
            }
            return
        else:
            return
        service, data = line.split(b" ", 1)
        info: Dict[str, Any] = {"soft": soft}
        while data:
            if data.startswith(b"cpe:"):
                key = "cpe"
                data = data[4:]
            else:
                key = data[0:1].decode()
                data = data[1:]
            sep = data[0:1]
            data = data[1:]
            index = data.index(sep)
            value = data[:index]
            value_out: Union[Pattern[bytes], str]
            data = data[index + 1 :]
            flag = b""
            if data:
                if b" " in data:
                    flag, data = data.split(b" ", 1)
                else:
                    flag, data = data, b""
            if key == "m":
                if value.endswith(b"\\r\\n"):
                    value = value[:-4] + b"(?:\\r\\n|$)"
                elif value.endswith(b"\\\\n"):
                    value = value[:3] + b"(?:\\\\n|$)"
                elif value.endswith(b"\\n"):
                    value = value[:-2] + b"(?:\\n|$)"
                value_out = re.compile(
                    value,
                    flags=sum(
                        getattr(re, f) if hasattr(re, f) else 0
                        for f in flag.decode().upper()
                    ),
                )
                flag = b""
            else:
                try:
                    value_out = value.decode("utf-8")
                except UnicodeDecodeError:
                    value_out = repr(value)
            if key == "cpe":
                info.setdefault(key, []).append(value_out)
            else:
                info[key] = (value_out, flag)
            data = data.lstrip(b" ")
        assert _NMAP_CUR_PROBE is not None
        _NMAP_CUR_PROBE.append((service.decode(), info))

    try:
        assert config.NMAP_SHARE_PATH is not None
        with open(
            os.path.join(config.NMAP_SHARE_PATH, "nmap-service-probes"), "rb"
        ) as fdesc:
            for fline in fdesc:
                parse_line(fline[:-1])
    except (AttributeError, AssertionError, TypeError, IOError):
        LOGGER.warning("Cannot read Nmap service fingerprint file.", exc_info=True)
    del _NMAP_CUR_PROBE, _NMAP_CUR_FALLBACK
    _NMAP_PROBES_POPULATED = True


def get_nmap_svc_fp(proto: str = "tcp", probe: str = "NULL") -> NmapProbeRec:
    global _NMAP_PROBES, _NMAP_PROBES_POPULATED
    if not _NMAP_PROBES_POPULATED:
        _read_nmap_probes()
    return _NMAP_PROBES[proto][probe]


def get_nmap_probes(proto: str) -> Dict[bytes, str]:
    if not _NMAP_PROBES_POPULATED:
        _read_nmap_probes()
    return {value["probe"]: name for name, value in _NMAP_PROBES[proto].items()}


def match_nmap_svc_fp(
    output: bytes, proto: str = "tcp", probe: str = "NULL", soft: bool = False
) -> NmapServiceMatch:
    """Take output from a given probe and return the closest nmap
    fingerprint."""
    softmatch: NmapServiceMatch = {}
    result: NmapServiceMatch = {}
    try:
        probe_data = get_nmap_svc_fp(
            proto=proto,
            probe=probe,
        )
        fingerprints = probe_data["fp"]
    except KeyError:
        pass
    else:
        fallbacks = probe_data.get("fallbacks")
        for service, fingerprint in fingerprints:
            match = fingerprint["m"][0].search(output)
            if match is not None:
                if probe == "NULL" and service == "landesk-rc":
                    # This Nmap fingerprint sucks: it is just a size
                    # check with a simple rule to exclude values
                    # starting with HTTP, RTSP or SIP. This gives too
                    # many false positive matches. According to a
                    # comment, the values are supposed to be
                    # random. Let's at least make sure it contains
                    # enough different chars.
                    if len(set(output)) < 100:
                        continue
                doc = softmatch if fingerprint["soft"] else result
                if service.startswith("ssl/"):
                    doc["service_name"] = service[4:]
                    doc["service_tunnel"] = "ssl"
                else:
                    doc["service_name"] = service
                for elt, key in NMAP_FINGERPRINT_IVRE_KEY.items():
                    if elt in fingerprint:
                        if elt == "cpe":
                            data_cpe = [
                                "cpe:/%s" % nmap_svc_fp_format_data(value, match)
                                for value in fingerprint[elt]
                            ]
                            if data_cpe:
                                assert key == "cpe"
                                doc["cpe"] = data_cpe
                        else:
                            data = nmap_svc_fp_format_data(fingerprint[elt][0], match)
                            if data:
                                # key is in
                                # NMAP_FINGERPRINT_IVRE_KEY.values()
                                # and is not "cpe"
                                doc[key] = data  # type: ignore
                if not fingerprint["soft"]:
                    return result
        if fallbacks:
            for fallback in fallbacks:
                # Hack: in Nmap fingerprint file, nothing specifies
                # the protocol of the fallback probe. However, the
                # same probe may exist with different
                # protocols. Usually, the fallback probes use the same
                # protocol than the original probe; the only
                # exceptions so far are DNSStatusRequestTCP (fallback
                # DNSStatusRequest) and DNSVersionBindReqTCP (fallback
                # DNSVersionBindReq)
                if proto == "tcp" and fallback + "TCP" == probe:
                    fallback_result = match_nmap_svc_fp(
                        output, proto="udp", probe=fallback, soft=soft
                    )
                else:
                    fallback_result = match_nmap_svc_fp(
                        output, proto=proto, probe=fallback, soft=soft
                    )
                if fallback_result.get("soft"):
                    softmatch = fallback_result
                else:
                    return fallback_result
    if softmatch and soft:
        softmatch["soft"] = True
    return softmatch


_NMAP_PAYLOADS = {}
_NMAP_PAYLOADS_POPULATED = False


def _read_nmap_payloads() -> None:
    global _NMAP_PAYLOADS_POPULATED

    def _parse_line(line: str) -> Generator[str, None, None]:
        status = 0
        for c in line:
            if status == 0:
                if c in {"#", "\r", "\n"}:
                    return
                yield c
                if c == '"':
                    status = 1
            elif status == 1:
                if c in {"\r", "\n"}:
                    LOGGER.warning("Unexpected EOL while reading line %r", line)
                    return
                yield c
                if c == '"':
                    status = 0

    try:
        cur_probe = None
        cur_line = []
        assert config.NMAP_SHARE_PATH is not None
        with open(os.path.join(config.NMAP_SHARE_PATH, "nmap-payloads"), "r") as fdesc:
            for line in fdesc:
                line = "".join(_parse_line(line.strip()))
                if not line.strip():
                    continue
                if line.startswith("source "):
                    continue
                if line.startswith("udp "):
                    line_l = line.strip().split(" ", 2)[1:]
                    if cur_probe is not None:
                        _NMAP_PAYLOADS[nmap_decode_data("".join(cur_line))] = cur_probe
                    cur_probe = line_l.pop(0)
                    if line_l:
                        line = line_l[0]
                        if len(line) > 3 and line[0] == line[-1] == '"':
                            line = line[1:-1]
                        cur_line = [line]
                    else:
                        cur_line = []
                elif line.startswith('"'):
                    if len(line.strip()) > 1 and line[-1] == '"':
                        line = line[1:-1]
                    cur_line.append(line)
        if cur_probe is not None:
            _NMAP_PAYLOADS[nmap_decode_data("".join(cur_line))] = cur_probe
    except (AttributeError, AssertionError, TypeError, IOError):
        LOGGER.warning("Cannot read Nmap service fingerprint file.", exc_info=True)
    _NMAP_PAYLOADS_POPULATED = True


def get_nmap_udp_payloads() -> Dict[bytes, str]:
    if not _NMAP_PAYLOADS_POPULATED:
        _read_nmap_payloads()
    return _NMAP_PAYLOADS


_IKESCAN_VENDOR_IDS: List[Tuple[bytes, Pattern[bytes]]]
_IKESCAN_VENDOR_IDS_POPULATED = False


def _read_ikescan_vendor_ids() -> None:
    global _IKESCAN_VENDOR_IDS, _IKESCAN_VENDOR_IDS_POPULATED
    try:
        assert config.DATA_PATH is not None
        with open(os.path.join(config.DATA_PATH, "ike-vendor-ids"), "rb") as fdesc:
            sep = re.compile(b"\\t+")
            _IKESCAN_VENDOR_IDS = [
                (
                    line[0],
                    re.compile(line[1].replace(b"[[:xdigit:]]", b"[0-9a-f]"), re.I),
                )
                for line in (
                    sep.split(line, 1)
                    for line in (line.strip().split(b"#", 1)[0] for line in fdesc)
                    if line
                )
            ]
    except (AttributeError, AssertionError, IOError):
        LOGGER.warning("Cannot read ike-scan vendor IDs file.", exc_info=True)
    _IKESCAN_VENDOR_IDS_POPULATED = True


def get_ikescan_vendor_ids() -> List[Tuple[bytes, Pattern[bytes]]]:
    global _IKESCAN_VENDOR_IDS, _IKESCAN_VENDOR_IDS_POPULATED
    if not _IKESCAN_VENDOR_IDS_POPULATED:
        _read_ikescan_vendor_ids()
    return _IKESCAN_VENDOR_IDS


def find_ike_vendor_id(vendorid: bytes) -> Optional[bytes]:
    vid = encode_hex(vendorid)
    for name, sig in get_ikescan_vendor_ids():
        if sig.search(vid):
            return name
    return None


_WIRESHARK_MANUF_DB_LAST_ADDR: List[int] = []
_WIRESHARK_MANUF_DB_VALUES: List[Optional[Tuple[str, Optional[str]]]] = []
_WIRESHARK_MANUF_DB_POPULATED = False


def _mac2int(value: str) -> int:
    """Converts a MAC address to an integer"""
    return sum(
        v << (40 - 8 * i) for i, v in enumerate(int(v, 16) for v in value.split(":"))
    )


def _int2macmask(mask: int) -> int:
    """Converts the number of bits set to 1 in a mask to the 48-bit
    integer usable as a mask.

    """
    return (0xFFFFFFFFFFFF000000000000 >> mask) & 0xFFFFFFFFFFFF


def _read_wireshark_manuf_db() -> None:
    global _WIRESHARK_MANUF_DB_LAST_ADDR, _WIRESHARK_MANUF_DB_VALUES, _WIRESHARK_MANUF_DB_POPULATED

    if config.WIRESHARK_SHARE_PATH is None:
        return

    def parse_line(line: str) -> None:
        line = line.split("#", 1)[0]
        if not line:
            return
        line = line.strip()
        if not line:
            return
        comment: Optional[str]
        try:
            addr, manuf, comment = line.split("\t", 2)
        except ValueError:
            try:
                addr, manuf = line.split("\t", 1)
            except ValueError:
                LOGGER.warning(
                    "Cannot parse a line from Wireshark " "manufacturer database [%r].",
                    line,
                    exc_info=True,
                )
                return
            comment = None
        if "/" in addr:
            addr, mask_s = addr.split("/")
            mask = int(mask_s)
        else:
            mask = (addr.count(":") + 1) * 8
        addr += ":00" * (5 - addr.count(":"))
        try:
            addr_int = _mac2int(addr)
        except ValueError:
            LOGGER.warning(
                "Cannot parse a line from Wireshark " "manufacturer database [%r].",
                line,
            )
            return
        if (
            _WIRESHARK_MANUF_DB_LAST_ADDR
            and _WIRESHARK_MANUF_DB_LAST_ADDR[-1] != addr_int - 1
        ):
            _WIRESHARK_MANUF_DB_LAST_ADDR.append(addr_int - 1)
            _WIRESHARK_MANUF_DB_VALUES.append(None)
        elif _WIRESHARK_MANUF_DB_VALUES and _WIRESHARK_MANUF_DB_VALUES[-1] == (
            manuf,
            comment,
        ):
            _WIRESHARK_MANUF_DB_LAST_ADDR.pop()
            _WIRESHARK_MANUF_DB_VALUES.pop()
        _WIRESHARK_MANUF_DB_LAST_ADDR.append(
            (addr_int & _int2macmask(mask)) + 2 ** (48 - mask) - 1
        )
        _WIRESHARK_MANUF_DB_VALUES.append((manuf, comment))

    try:
        with open(os.path.join(config.WIRESHARK_SHARE_PATH, "manuf"), "r") as fdesc:
            for line in fdesc:
                parse_line(line[:-1])
    except (AttributeError, TypeError, IOError):
        LOGGER.warning("Cannot read Wireshark manufacturer database.", exc_info=True)
    _WIRESHARK_MANUF_DB_POPULATED = True


def get_wireshark_manuf_db() -> Tuple[
    List[int], List[Optional[Tuple[str, Optional[str]]]]
]:
    global _WIRESHARK_MANUF_DB_LAST_ADDR, _WIRESHARK_MANUF_DB_VALUES, _WIRESHARK_MANUF_DB_POPULATED
    if not _WIRESHARK_MANUF_DB_POPULATED:
        _read_wireshark_manuf_db()
    return _WIRESHARK_MANUF_DB_LAST_ADDR, _WIRESHARK_MANUF_DB_VALUES


def mac2manuf(mac: str) -> Optional[Tuple[str, Optional[str]]]:
    last_addr, values = get_wireshark_manuf_db()
    try:
        return values[bisect_left(last_addr, _mac2int(mac))]
    except IndexError:
        # empty lists, a warning must have been issued on db load
        return None


# Nmap (and Zeek) encoding & decoding


_REPRS = {13: "\\r", 10: "\\n", 9: "\\t", 92: "\\\\"}
_RAWS = {"r": b"\r", "n": b"\n", "t": b"\t", "\\": b"\\", "0": b"\x00", '"': b'"'}


def nmap_encode_data(data: bytes) -> str:
    """Encode binary data (bytes) to a string (str) as Nmap would encode it."""
    return "".join(
        _REPRS[d] if d in _REPRS else chr(d) if 32 <= d <= 126 else "\\x%02x" % d
        for d in data
    )


def zeek_encode_data(data: bytes) -> str:
    """Encode binary data (bytes) to a string (str) as Zeek would encode it."""
    return "".join(
        "\\\\"
        if d == b"\\"
        else d.decode()
        if b" " <= d <= b"~"
        else "\\x%02x" % ord(d)
        for d in (data[i : i + 1] for i in range(len(data)))
    )


def _nmap_decode_data(
    data: str, arbitrary_escapes: bool = False
) -> Generator[bytes, None, None]:
    status = 0
    first_byte = -1
    for char in data:
        if status == 0:
            # not in an escape sequence
            if char == "\\":
                status = 1
                continue
            yield char.encode()
            continue
        if status == 1:
            # after a backslash
            if char in _RAWS:
                yield _RAWS[char]
                status = 0
                continue
            if char == "x":
                status = 2
                continue
            if arbitrary_escapes:
                LOGGER.debug("nmap_decode_data: unnecessary escape %r", "\\" + char)
            else:
                LOGGER.warning("nmap_decode_data: cannot decode %r", "\\" + char)
                yield b"\\"
            yield char.encode()
            status = 0
            continue
        if status == 2:
            # after \x
            try:
                first_byte = int(char, 16)
            except ValueError:
                LOGGER.warning("nmap_decode_data: cannot decode %r", "\\x" + char)
                yield b"\\x"
                yield char.encode()
                status = 0
                continue
            status = 3
            continue
        if status == 3:
            # after \x?
            try:
                value = bytes([first_byte * 16 + int(char, 16)])
            except ValueError:
                LOGGER.warning(
                    "nmap_decode_data: cannot decode %r", "\\x%x%s" % (first_byte, char)
                )
                yield ("\\x%x%s" % (first_byte, char)).encode()
                status = 0
                continue
            yield value
            first_byte = -1
            status = 0
            continue
    if status:
        LOGGER.warning("nmap_decode_data: invalid escape sequence at end of string")


def nmap_decode_data(data: str, arbitrary_escapes: bool = False) -> bytes:
    return b"".join(_nmap_decode_data(data, arbitrary_escapes=arbitrary_escapes))


def _nmap_command_match_subst(match_num: int) -> Pattern[str]:
    return re.compile('\\$SUBST\\(%d,"([^"]*)","([^"]*)"\\)' % match_num)


def _nmap_command_match_i(match_num: int) -> Pattern[str]:
    return re.compile('\\$I\\(%d,"([<>])"\\)' % match_num)


def nmap_svc_fp_format_data(data: str, match: Match) -> Optional[str]:
    for i, value in enumerate(match.groups()):
        if value is None:
            if (
                "$%d" % (i + 1) in data
                or "$P(%d)" % (i + 1) in data
                or "$I(%d," % (i + 1) in data
                or "$SUBST(%d," % (i + 1) in data
            ):
                return None
            continue
        data = data.replace("$%d" % (i + 1), nmap_encode_data(value))
        data = data.replace("$P(%d)" % (i + 1), nmap_encode_data(only_printable(value)))
        # pylint: disable=cell-var-from-loop
        data = _nmap_command_match_subst(i + 1).sub(
            # we know m.groups() is a Tuple[str, str]
            lambda m: nmap_encode_data(value).replace(*m.groups()),  # type: ignore
            data,
        )
        if len(value) == 2:
            # $I(x,"<") or $I(x,">") may exist
            data = _nmap_command_match_i(i + 1).sub(
                lambda m: str(struct.unpack("%sH" % m.groups()[0], value)[0]),
                data,
            )
    return data


def normalize_props(props: Union[list, dict]) -> dict:
    """Returns a normalized property list/dict so that (roughly):
    - a list [k] gives {k: str(k)}
    - a dict {k: v} gives {k: str(k) if v is None else str(v)}
    """
    if not isinstance(props, dict):
        props = dict.fromkeys(props)
    for key, value in props.items():
        if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
            props[key] = value[1:-1]
    props = {
        key: str(key) if value is None else str(value) for key, value in props.items()
    }
    return props


def tz_offset(timestamp: Optional[Union[int, float]] = None) -> int:
    """
    Returns the offset between UTC and local time at "timestamp".
    """
    if timestamp is None:
        timestamp = time.time()
    utc_offset = datetime.datetime.fromtimestamp(
        timestamp
    ) - datetime.datetime.utcfromtimestamp(timestamp)
    return int(utc_offset.total_seconds())


def datetime2utcdatetime(dtm: datetime.datetime) -> datetime.datetime:
    """
    Returns the given datetime in UTC. dtm is expected to be in local
    timezone.
    """
    offset = tz_offset(timestamp=dtm.timestamp())
    delta = datetime.timedelta(seconds=offset)
    return dtm - delta


_UNITS = [""]
_UNITS.extend("kMGTPEZY")


def num2readable(value: Union[int, float]) -> str:
    idx = int(math.log(value, 1000))
    try:
        unit = _UNITS[idx]
    except IndexError:
        unit = "Y"
        idx = 1000 ** 8
    else:
        idx = 1000 ** idx
    if isinstance(value, float):
        return "%.3f%s" % (value / float(idx), unit)
    return "%d%s" % (value / float(idx), unit)


def decode_hex(value: AnyStr) -> bytes:
    if isinstance(value, str):
        return bytes.fromhex(value)
    return bytes.fromhex(value.decode())


def encode_hex(value: bytes) -> bytes:
    return value.hex().encode()


def decode_b64(value: bytes) -> bytes:
    return base64.decodebytes(value)


def encode_b64(value: bytes) -> bytes:
    return base64.encodebytes(value).replace(b"\n", b"")


def printable(string: AnyStr) -> AnyStr:
    if isinstance(string, bytes):
        return bytes(c if 32 <= c <= 126 else 46 for c in string)
    return "".join(c if " " <= c <= "~" else "." for c in string)


def only_printable(string: AnyStr) -> AnyStr:
    if isinstance(string, bytes):
        return bytes(c for c in string if 32 <= c <= 126)
    return "".join(c for c in string if " " <= c <= "~")


def _parse_ssh_key(data: bytes) -> Generator[bytes, None, None]:
    """Generates SSH key elements"""
    while data:
        length = struct.unpack(">I", data[:4])[0]
        yield data[4 : 4 + length]
        data = data[4 + length :]


def parse_ssh_key(data: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        hashtype: hashlib.new(hashtype, data).hexdigest()
        for hashtype in ["md5", "sha1", "sha256"]
    }
    parsed = _parse_ssh_key(data)
    try:
        keytype = info["algo"] = next(parsed).decode()
    except Exception:
        LOGGER.warning("Cannot parse SSH host key from data %r", data)
        return info
    if keytype == "ssh-rsa":
        try:
            info["exponent"], info["modulus"] = (
                int(encode_hex(elt), 16) for elt in parsed
            )
        except Exception:
            LOGGER.info(
                "Cannot parse SSH RSA host key from data %r", data, exc_info=True
            )
        else:
            info["bits"] = int(math.ceil(math.log(info["modulus"], 2)))
            # convert integer to strings to prevent overflow errors
            # (e.g., "MongoDB can only handle up to 8-byte ints")
            for val in ["exponent", "modulus"]:
                info[val] = str(info[val])
    elif keytype == "ssh-dss":
        info["bits"] = int(math.ceil(math.log(int(encode_hex(next(parsed)), 16), 2)))
    elif keytype == "ecdsa-sha2-nistp256":
        info["bits"] = 256
    elif keytype == "ssh-ed25519":
        info["bits"] = len(next(parsed)) * 8
    else:
        LOGGER.debug("Cannot get key size for type %r (data %r)", keytype, data)
    return info


# https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
# Consulted february 2019
_ADDR_TYPES = [
    "Unspecified",
    "Loopback",
    "Reserved",
    "Current-Net",
    None,
    "Private",
    None,
    "CGN",
    None,
    "Loopback",
    None,
    "Link-Local",
    None,
    "Private",
    None,
    "Reserved",
    None,
    "Documentation",
    None,
    "IPv6-to-IPv4",
    None,
    "Private",
    None,
    "Benchmark",
    None,
    "Documentation",
    None,
    "Documentation",
    None,
    "Multicast",
    "Reserved",
    "Broadcast",
    "Reserved",
    "Well-known prefix",
    "Reserved",
    # RFC 6666 Remote Triggered Black Hole
    "Discard (RTBH)",
    "Reserved",
    None,
    "Protocol assignments",
    None,
    "Documentation",
    None,
    "6to4",
    None,
    "Reserved",
    "Unique Local Unicast",
    "Reserved",
    "Link Local Unicast",
    "Reserved",
    "Multicast",
]

_ADDR_TYPES_LAST_IP = [
    ip2int("::"),
    ip2int("::1"),
    ip2int("::fffe:ffff:ffff"),
    ip2int("::ffff:0.255.255.255"),
    ip2int("::ffff:9.255.255.255"),
    ip2int("::ffff:10.255.255.255"),
    ip2int("::ffff:100.63.255.255"),
    ip2int("::ffff:100.127.255.255"),
    ip2int("::ffff:126.255.255.255"),
    ip2int("::ffff:127.255.255.255"),
    ip2int("::ffff:169.253.255.255"),
    ip2int("::ffff:169.254.255.255"),
    ip2int("::ffff:172.15.255.255"),
    ip2int("::ffff:172.31.255.255"),
    ip2int("::ffff:191.255.255.255"),
    ip2int("::ffff:192.0.0.255"),
    ip2int("::ffff:192.0.1.255"),
    ip2int("::ffff:192.0.2.255"),
    ip2int("::ffff:192.88.98.255"),
    ip2int("::ffff:192.88.99.255"),
    ip2int("::ffff:192.167.255.255"),
    ip2int("::ffff:192.168.255.255"),
    ip2int("::ffff:198.17.255.255"),
    ip2int("::ffff:198.19.255.255"),
    ip2int("::ffff:198.51.99.255"),
    ip2int("::ffff:198.51.100.255"),
    ip2int("::ffff:203.0.112.255"),
    ip2int("::ffff:203.0.113.255"),
    ip2int("::ffff:223.255.255.255"),
    ip2int("::ffff:239.255.255.255"),
    ip2int("::ffff:255.255.255.254"),
    ip2int("::ffff:255.255.255.255"),
    ip2int("64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("64:ff9b::ffff:ffff"),
    ip2int("ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("100::ffff:ffff:ffff:ffff"),
    ip2int("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ip2int("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
]


def get_addr_type(addr: str) -> Optional[str]:
    """Returns the type (Private, Loopback, etc.) of an IPv4 address, or
    None if it is a "normal", usable address.

    """

    if ":" not in addr:
        addr = "::ffff:" + addr
    try:
        data = ip2int(addr)
    except (TypeError, socket.error):
        return None
    return _ADDR_TYPES[bisect_left(_ADDR_TYPES_LAST_IP, data)]


_CERTINFOS = [
    re.compile(
        b"\n *"
        b"Issuer: (?P<issuer>.*)"
        b"\n(?:.*\n)* *"
        b"Not Before *: (?P<not_before>.*)"
        b"\n(?:.*\n)* *"
        b"Not After *: (?P<not_after>.*)"
        b"\n(?:.*\n)* *"
        b"Subject: (?P<subject>.*)"
        b"\n(?:.*\n)* *"
        b"Public Key Algorithm: (?P<type>rsaEncryption)"
        b"\n *"
        b"(?:RSA )?Public-Key: \\((?P<bits>[0-9]+) bit\\)"
        b"\n *"
        b"Modulus: *\n(?P<modulus>[\\ 0-9a-f:\n]+)"
        b"\n *"
        b"Exponent: (?P<exponent>[0-9]+) .*"
        b"(?:\n|$)"
    ),
    re.compile(
        b"\n *"
        b"Issuer: (?P<issuer>.*)"
        b"\n(?:.*\n)* *"
        b"Not Before *: (?P<not_before>.*)"
        b"\n(?:.*\n)* *"
        b"Not After *: (?P<not_after>.*)"
        b"\n(?:.*\n)* *"
        b"Subject: (?P<subject>.*)"
        b"\n(?:.*\n)* *"
        b"Public Key Algorithm: (?P<type>.*)"
        b"(?:\n|$)"
    ),
]

_CERTINFOS_EXT_SAN = re.compile(
    b"\n *"
    b"X509v3 Subject Alternative Name: *(?:critical *)?\n *(?P<san>.*)"
    b"(?:\n|$)"
)

_CERTINFOS_EXT_BC = re.compile(
    b"\n *" b"X509v3 Basic Constraints: *(?:critical *)?\n *(?P<bc>.*)" b"(?:\n|$)"
)

_CERTKEYS = {
    "C": "countryName",
    "CN": "commonName",
    "DC": "domainComponent",
    "L": "localityName",
    "O": "organizationName",
    "OU": "organizationalUnitName",
    "ST": "stateOrProvinceName",
    "SN": "surname",
}

_CERTALGOS = {
    6: "rsaEncryption",
    408: "id-ecPublicKey",
    116: "id-dsa",
    28: "dhpublicnumber",
}

_CERTKEYTYPES = {
    6: "rsa",
    408: "ec",
    116: "dsa",
    28: "dh",
}

PUBKEY_TYPES = {
    "rsaEncryption": "rsa",
    "id-ecPublicKey": "ec",
    "id-dsa": "dsa",
    "dhpublicnumber": "dh",
}

PUBKEY_REV_TYPES = dict((val, key) for key, val in PUBKEY_TYPES.items())


def _parse_cert_subject(subject: str) -> Generator[Tuple[str, str], None, None]:
    status = 0
    curkey = []
    curvalue = []
    for char in subject:
        if status == -1:
            # reading space before the key
            if char == " ":
                continue
            curkey.append(char)
            status += 1
        elif status == 0:
            # reading key
            if char == " ":
                status += 1
                continue
            if char == "=":
                status += 2
                continue
            curkey.append(char)
        elif status == 1:
            # reading '='
            if char != "=":
                return
            status += 1
        elif status == 2:
            # reading space after '='
            if char == " ":
                continue
            # reading beginning of value
            if char == '"':
                status += 2
                continue
            curvalue.append(char)
            status += 1
        elif status == 3:
            # reading value without quotes
            if char == ",":
                yield "".join(curkey), "".join(curvalue)
                curkey = []
                curvalue = []
                status = -1
                continue
            curvalue.append(char)
        elif status == 4:
            # reading value with quotes
            if char == '"':
                status -= 1
                continue
            if char == "\\":
                status += 1
                continue
            curvalue.append(char)
        elif status == 5:
            curvalue.append(char)
            status -= 1
    yield "".join(curkey), "".join(curvalue)


def _parse_subject(subject: osslc.X509Name) -> Tuple[str, Dict[str, str]]:
    """Parses an X509Name object (from pyOpenSSL module) and returns a
    text and a dict suitable for use by get_cert_info().

    """
    components = []
    for k, v in subject.get_components():
        k = printable(k).decode()
        v = printable(v).decode()
        k = _CERTKEYS.get(k, k)
        components.append((k, v))
    return "/".join("%s=%s" % kv for kv in components), dict(components)


if STRPTIME_SUPPORTS_TZ:

    def _parse_datetime(value: bytes) -> Optional[datetime.datetime]:
        try:
            return datetime.datetime.strptime(value.decode(), "%Y%m%d%H%M%S%z")
        except ValueError:
            return datetime.datetime.strptime(value.decode()[:14], "%Y%m%d%H%M%S")
        except Exception:
            LOGGER.warning("Cannot parse datetime value %r", value, exc_info=True)
            return None


else:

    def _parse_datetime(value: bytes) -> Optional[datetime.datetime]:
        try:
            return datetime.datetime.strptime(value.decode()[:14], "%Y%m%d%H%M%S")
        except Exception:
            LOGGER.warning("Cannot parse datetime value %r", value, exc_info=True)
            return None


if USE_PYOPENSSL:

    def get_cert_info(cert: bytes) -> Dict[str, Any]:
        """Extract info from a certificate (hash values, issuer, subject,
            algorithm) in an handy-to-index-and-query form.

        This version relies on the pyOpenSSL module.

        """
        result: Dict[str, Any] = {
            hashtype: hashlib.new(hashtype, cert).hexdigest()
            for hashtype in ["md5", "sha1", "sha256"]
        }
        data = osslc.load_certificate(osslc.FILETYPE_ASN1, cert)
        result["subject_text"], result["subject"] = _parse_subject(data.get_subject())
        result["issuer_text"], result["issuer"] = _parse_subject(data.get_issuer())
        for i in range(data.get_extension_count()):
            ext = data.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                try:
                    # XXX str() / encoding
                    result["san"] = [x.strip() for x in str(ext).split(", ")]
                except Exception:
                    LOGGER.warning(
                        "Cannot decode subjectAltName %r for %r",
                        ext,
                        result["subject_text"],
                        exc_info=True,
                    )
                break
        result["self_signed"] = result["issuer_text"] == result["subject_text"]
        not_before = _parse_datetime(data.get_notBefore())
        not_after = _parse_datetime(data.get_notAfter())
        if not_before is not None:
            result["not_before"] = not_before
            if not_after is not None:
                result["not_after"] = not_after
                lifetime = not_after - not_before
                result["lifetime"] = int(lifetime.total_seconds())
        elif not_after is not None:
            result["not_after"] = not_after
        result["pubkey"] = {}
        pubkey = data.get_pubkey()
        pubkeytype = pubkey.type()
        result["pubkey"]["type"] = _CERTKEYTYPES.get(pubkeytype, pubkeytype)
        result["pubkey"]["bits"] = pubkey.bits()
        if pubkeytype == 6:
            # RSA
            numbers = pubkey.to_cryptography_key().public_numbers()
            result["pubkey"]["exponent"] = numbers.e
            result["pubkey"]["modulus"] = str(numbers.n)
        pubkey = pubkey.to_cryptography_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
        for hashtype in ["md5", "sha1", "sha256"]:
            result["pubkey"][hashtype] = hashlib.new(hashtype, pubkey).hexdigest()
        result["pubkey"]["raw"] = encode_b64(pubkey).decode()
        return result


else:

    def get_cert_info(cert: bytes) -> Dict[str, Any]:
        """Extract info from a certificate (hash values, issuer, subject,
            algorithm) in an handy-to-index-and-query form.

        This version parses the output of "openssl x509 -text" command line,
        and is a fallback when pyOpenSSL cannot be imported.

        """
        result: Dict[str, Any] = {
            hashtype: hashlib.new(hashtype, cert).hexdigest()
            for hashtype in ["md5", "sha1", "sha256"]
        }
        with subprocess.Popen(
            [
                config.OPENSSL_CMD,
                "x509",
                "-noout",
                "-text",
                "-inform",
                "DER",
                "-pubkey",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        ) as proc:
            assert proc.stdin is not None
            assert proc.stdout is not None
            proc.stdin.write(cert)
            proc.stdin.close()
            data, pubkey = proc.stdout.read().split(b"-----BEGIN PUBLIC KEY-----")
        for expr in _CERTINFOS:
            match = expr.search(data)
            if match is not None:
                break
        else:
            LOGGER.info(
                "Cannot parse certificate %r - " "no matching expression in %r",
                cert,
                data,
            )
            return result
        for field, fdata in match.groupdict().items():
            try:
                fdata_str = fdata.decode()
                if field in ["issuer", "subject"]:
                    flddata = [
                        (_CERTKEYS.get(key, key), value)
                        for key, value in _parse_cert_subject(fdata_str)
                    ]
                    # replace '.' by '_' in keys to produce valid JSON
                    result[field] = dict(
                        (key.replace(".", "_"), value) for key, value in flddata
                    )
                    result["%s_text" % field] = "/".join(
                        "%s=%s" % item for item in flddata
                    )
                elif field in ["bits", "exponent"]:
                    result[field] = int(fdata_str)
                elif field == "modulus":
                    result[field] = str(
                        int(
                            fdata_str.replace(" ", "")
                            .replace(":", "")
                            .replace("\n", ""),
                            16,
                        )
                    )
                elif field in ["not_before", "not_after"]:
                    if STRPTIME_SUPPORTS_TZ:
                        try:
                            result[field] = datetime.datetime.strptime(
                                fdata_str,
                                "%b %d %H:%M:%S %Y %Z",
                            )
                        except ValueError:
                            result[field] = datetime.datetime.strptime(
                                fdata_str[:-4],
                                "%b %d %H:%M:%S %Y",
                            )
                    else:
                        result[field] = datetime.datetime.strptime(
                            fdata_str[:-4],
                            "%b %d %H:%M:%S %Y",
                        )
                else:
                    result[field] = fdata_str
            except Exception:
                LOGGER.info(
                    "Error when parsing certificate %r with field %r (value %r)",
                    cert,
                    field,
                    fdata,
                    exc_info=True,
                )
        result["self_signed"] = result["issuer_text"] == result["subject_text"]
        if "not_before" in result and "not_after" in result:
            lifetime = result["not_after"] - result["not_before"]
            result["lifetime"] = int(lifetime.total_seconds())
        san = _CERTINFOS_EXT_SAN.search(data)
        if san is not None:
            try:
                result["san"] = san.groups()[0].decode().split(", ")
            except Exception:
                LOGGER.info(
                    "Cannot parse subjectAltName in certificate %r", cert, exc_info=True
                )
        result["pubkey"] = {}
        for fld in ["modulus", "exponent", "bits"]:
            if fld in result:
                result["pubkey"][fld] = result.pop(fld)
        if "type" in result:
            pubkeytype = result.pop("type")
            result["pubkey"]["type"] = PUBKEY_TYPES.get(pubkeytype, pubkeytype)
        pubkey = decode_b64(b"".join(pubkey.splitlines()[1:-1]))
        for hashtype in ["md5", "sha1", "sha256"]:
            result["pubkey"][hashtype] = hashlib.new(hashtype, pubkey).hexdigest()
        result["pubkey"]["raw"] = encode_b64(pubkey)
        return result


# https://stackoverflow.com/a/26348624
@functools.total_ordering
class MinValue:
    def __le__(self, other: Any) -> bool:
        return True

    def __eq__(self, other: Any) -> bool:
        return self is other


MIN_VALUE = MinValue()


def key_sort_none(value: Optional[Any]) -> Any:
    """This function can be used as `key=` argument for sorted() and
    .sort(), in order to sort values that can be of a certain type (e.g.,
    str), or None, so that None is always lower.

    We just need to replace None with MIN_VALUE, which is an object that
    happily compares with anything, and is lower than anything.

    """
    if value is None:
        return MIN_VALUE
    return value


def ptr2addr(ptr: str) -> Optional[str]:
    """
    Returns the IP address (v4 or v6) represented by the given PTR,
    None if the string does not seem to be a PTR
    """
    if ptr.endswith(".in-addr.arpa"):
        return ".".join(reversed(ptr.split(".")[:4]))
    if ptr.endswith(".ip6.arpa"):
        return int2ip6(int(ptr[:-9].replace(".", "")[::-1], 16))
    return None


def is_ptr(ptr: str) -> bool:
    """
    Check whether the given string is a PTR
    """
    return ptr.endswith(".in-addr.arpa") or ptr.endswith(".ip6.arpa")


def deep_sort_dict_list(elt: dict) -> None:
    """
    Deep sort the list values inside a dictionary.
    elt must be a dictionary
    Notice: It does not sort nested lists.
    """
    for value in elt.values():
        if isinstance(value, list):
            value.sort()
        elif isinstance(value, dict):
            deep_sort_dict_list(value)


_SCHEMES_PORTS = {"ftp": 21, "http": 80, "https": 443}


def url2hostport(url: str) -> Tuple[str, int]:
    url_p = urlparse(url)
    host = url_p.netloc
    if host.startswith("["):
        try:
            mark = host.index("]")
        except ValueError as exc:
            raise ValueError("Bad netloc in URL") from exc
        port = host[mark + 1 :]
        host = host[1:mark]
        if not port:
            try:
                return host, _SCHEMES_PORTS[url_p.scheme]
            except KeyError as exc:
                raise ValueError("Bad scheme in URL") from exc
        if not port.startswith(":"):
            raise ValueError("Bad netloc in URL")
        try:
            return host, int(port[1:])
        except ValueError as exc:
            raise ValueError("Bad netloc in URL") from exc
    if ":" in host:
        host, port = host.split(":", 1)
        try:
            return host, int(port)
        except ValueError as exc:
            raise ValueError("Bad netloc in URL") from exc
    try:
        return host, _SCHEMES_PORTS[url_p.scheme]
    except KeyError as exc:
        raise ValueError("Bad scheme in URL") from exc
