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
This sub-module contains functions that might be usefull to any other
sub-module or script.
"""

import ast
import bz2
from cStringIO import StringIO
import datetime
import errno
import gzip
import hashlib
import logging
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import traceback
try:
    import PIL.Image
    import PIL.ImageChops
    USE_PIL = True
except ImportError:
    USE_PIL = False


from ivre import config

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
REGEXP_T = type(re.compile(''))


logging.basicConfig()


def ip2int(ipstr):
    """Converts the classical decimal, dot-separated, string
    representation of an IP address to an integer, suitable for
    database storage.

    """
    return struct.unpack('!I', socket.inet_aton(ipstr))[0]


def int2ip(ipint):
    """Converts the integer representation of an IP address to its
    classical decimal, dot-separated, string representation.

    """
    return socket.inet_ntoa(struct.pack('!I', ipint))


def int2mask(mask):
    """Converts the number of bits set to 1 in a mask (the 24 in
    10.0.0.0/24) to the integer corresponding to the IP address of the
    mask (ip2int("255.255.255.0") for 24)

    From scapy:utils.py:itom(x).

    """
    return (0xffffffff00000000L >> mask) & 0xffffffffL


def net2range(network):
    """Converts a network to a (start, stop) tuple."""
    addr, mask = network.split('/')
    addr = ip2int(addr)
    if '.' in mask:
        mask = ip2int(mask)
    else:
        mask = int2mask(int(mask))
    start = addr & mask
    stop = int2ip(start + 0xffffffff - mask)
    start = int2ip(start)
    return start, stop


def range2nets(rng):
    """Converts a (start, stop) tuple to a list of networks."""
    start, stop = rng
    if isinstance(start, basestring):
        start = ip2int(start)
    if isinstance(stop, basestring):
        stop = ip2int(stop)
    if stop < start:
        raise ValueError()
    res = []
    cur = start
    maskint = 32
    mask = int2mask(maskint)
    while True:
        while cur & mask == cur and cur | (~mask & 0xffffffff) <= stop:
            maskint -= 1
            mask = int2mask(maskint)
        res.append('%s/%d' % (int2ip(cur), maskint + 1))
        mask = int2mask(maskint + 1)
        if stop & mask == cur:
            return res
        cur = (cur | (~mask & 0xffffffff)) + 1
        maskint = 32
        mask = int2mask(maskint)


def get_domains(name):
    """Generates the upper domains from a domain name."""
    name = name.split('.')
    return ('.'.join(name[i:]) for i in xrange(len(name)))


def str2regexp(string):
    """This function takes a string and returns either this string or
    a python regexp object, when the string is using the syntax
    /regexp[/flags].

    """
    if string.startswith('/'):
        string = string.split('/', 2)[1:]
        if len(string) == 1:
            string.append('')
        string = re.compile(
            string[0],
            sum(getattr(re, f.upper()) for f in string[1])
        )
    return string


def regexp2pattern(string):
    """This function takes a regexp or a string and returns a pattern
    and some flags, suitable for use with re.compile(), combined with
    another pattern before. Usefull, for example, if you want to
    create a regexp like '^ *Set-Cookie: *[name]=[value]' where name
    and value are regexp.

    """
    if isinstance(string, REGEXP_T):
        flags = string.flags
        string = string.pattern
        if string.startswith('^'):
            string = string[1:]
        # elif string.startswith('('):
        #     raise ValueError("Regexp starting with a group are not "
        #                      "(yet) supported")
        else:
            string = ".*" + string
        if string.endswith('$'):
            string = string[:-1]
        # elif string.endswith(')'):
        #     raise ValueError("Regexp ending with a group are not "
        #                      "(yet) supported")
        else:
            string += ".*"
        return string, flags
    else:
        return re.escape(string), 0


def str2list(string):
    """This function takes a string and returns either this string or
    a list of the coma-or-pipe separated elements from the string.

    """
    if ',' in string or '|' in string:
        return string.replace('|', ',').split(',')
    return string


_PYVALS = {
    "true": True,
    "false": False,
    "null": None,
    "none": None,
}


def str2pyval(string):
    """This function takes a string and returns a Python object"""
    try:
        return ast.literal_eval(string)
    except (ValueError, SyntaxError):
        # "special" values, fallback as simple string
        return _PYVALS.get(string, string)


def ports2nmapspec(portlist):
    """This function takes an iterable and returns a string
    suitable for use as argument for Nmap's -p option.

    """
    # unique and sorted (http://stackoverflow.com/a/13605607/3223422)
    portlist = sorted(set(portlist))
    result = []
    current = (None, None)
    for port in portlist:
        if port - 1 == current[1]:
            current = (current[0], port)
        else:
            if current[0] is not None:
                result.append(str(current[0])
                              if current[0] == current[1]
                              else "%d-%d" % current)
            current = (port, port)
    if current[0] is not None:
        result.append(str(current[0])
                      if current[0] == current[1]
                      else "%d-%d" % current)
    return ",".join(result)


def nmapspec2ports(string):
    """This function takes a string suitable for use as argument for
    Nmap's -p option and returns the corresponding set of ports.

    """
    result = set()
    for ports in string.split(','):
        if '-' in ports:
            ports = map(int, ports.split('-', 1))
            result = result.union(xrange(ports[0], ports[1] + 1))
        else:
            result.add(int(ports))
    return result


def makedirs(dirname):
    """Makes directories like mkdir -p, raising no exception when
    dirname already exists.

    """
    try:
        os.makedirs(dirname)
    except OSError as exception:
        if not (exception.errno == errno.EEXIST and os.path.isdir(dirname)):
            raise


def cleandir(dirname):
    """Removes a complete tree, like rm -rf on a directory, raising no
    exception when dirname does not exist.

    """
    try:
        shutil.rmtree(dirname)
    except OSError as exception:
        if exception.errno != errno.ENOENT:
            raise


def isfinal(elt):
    """Decides whether or not elt is a final element (i.e., an element
    that does not contain other elements)

    """
    return isinstance(elt, (basestring, int, long, float,
                            datetime.datetime, REGEXP_T))


def diff(doc1, doc2):
    """NOT WORKING YET - WORK IN PROGRESS - Returns fields that differ
    between two scans.

    """
    keys1 = set(doc1)
    keys2 = set(doc2)
    res = {}
    for key in keys1.symmetric_difference(keys2):
        res[key] = True
    for key in keys1.intersection(keys2):
        if isfinal(doc1[key]) or isfinal(doc2[key]):
            if doc1[key] != doc2[key]:
                res[key] = True
                continue
            continue
        if key in ['categories']:
            set1 = set(doc1[key])
            set2 = set(doc2[key])
            res[key] = [s for s in set1.symmetric_difference(set2)]
            if not res[key]:
                del res[key]
            continue
        if key == 'extraports':
            res[key] = {}
            for state in set(doc1[key]).union(doc2[key]):
                if doc1[key].get(state) != doc2[key].get(state):
                    res[key][state] = True
            if not res[key]:
                del res[key]
            continue
        if key in ['ports']:
            res[key] = {}
            kkeys1 = set(t['port'] for t in doc1['ports'])
            kkeys2 = set(t['port'] for t in doc2['ports'])
            for kkey in kkeys1.symmetric_difference(kkeys2):
                res[key][kkey] = True
            for kkey in kkeys1.intersection(kkeys2):
                pass
                # print kkey
    return res


def fields2csv_head(fields, prefix=''):
    """Given an (ordered) dictionnary `fields`, returns a list of the
    fields. NB: recursive function, hence the `prefix` parameter.

    """
    line = []
    for field, subfields in fields.iteritems():
        if subfields is True or callable(subfields):
            line.append(prefix + field)
        elif isinstance(subfields, dict):
            line += fields2csv_head(subfields,
                                    prefix=prefix + field + '.')
    return line


def doc2csv(doc, fields, nastr="NA"):
    """Given a document and an (ordered) dictionnary `fields`, returns
    a list of CSV lines. NB: recursive function.

    """
    lines = [[]]
    for field, subfields in fields.iteritems():
        if subfields is True:
            value = doc.get(field)
            if isinstance(value, list):
                lines = [line + [nastr if valelt is None else valelt]
                         for line in lines for valelt in value]
            else:
                lines = [line + [nastr if value is None else value]
                         for line in lines]
        elif callable(subfields):
            value = doc.get(field)
            if isinstance(value, list):
                lines = [line + [nastr if valelt is None
                                 else subfields(valelt)]
                         for line in lines for valelt in value]
            else:
                lines = [line + [nastr if value is None else subfields(value)]
                         for line in lines]
        elif isinstance(subfields, dict):
            subdoc = doc.get(field)
            if isinstance(subdoc, list):
                lines = [line + newline
                         for line in lines
                         for subdocelt in subdoc
                         for newline in doc2csv(subdocelt,
                                                subfields,
                                                nastr=nastr)]
            elif subdoc is None:
                lines = [line + newline
                         for line in lines
                         for newline in doc2csv({},
                                                subfields,
                                                nastr=nastr)]
            else:
                lines = [line + newline
                         for line in lines
                         for newline in doc2csv(subdoc,
                                                subfields,
                                                nastr=nastr)]
    return lines


class FileOpener(object):
    """A file-like object, working with gzip or bzip2 compressed files.

    Uses subprocess.Popen() to call zcat or bzcat by default (much
    faster), fallbacks to gzip.open or bz2.BZ2File.

    """
    FILE_OPENERS_MAGIC = {
        "\x1f\x8b": (config.GZ_CMD, gzip.open),
        "BZ": (config.BZ2_CMD, bz2.BZ2File),
    }

    def __init__(self, fname):
        self.proc = None
        if not isinstance(fname, basestring):
            self.fdesc = fname
            self.needsclose = False
            return
        self.needsclose = True
        with open(fname) as fdesc:
            magic = fdesc.read(2)
        try:
            cmd_opener, py_opener = self.FILE_OPENERS_MAGIC[magic]
        except KeyError:
            # Not a compressed file
            self.fdesc = open(fname)
            return
        try:
            # By default we try to use zcat / bzcat, since they seem to be
            # (a lot) faster
            self.proc = subprocess.Popen([cmd_opener, fname],
                                         stdout=subprocess.PIPE,
                                         stderr=open(os.devnull, 'w'))
            self.fdesc = self.proc.stdout
            return
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise
        # Fallback to the appropriate python opener
        self.fdesc = py_opener(fname)

    def read(self, *args):
        return self.fdesc.read(*args)

    def fileno(self):
        return self.fdesc.fileno()

    def close(self):
        # since .close() is explicitly called, we close self.fdesc
        # even when self.close is False.
        self.fdesc.close()
        if self.proc is not None:
            self.proc.wait()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.needsclose:
            self.fdesc.close()
        if self.proc is not None:
            self.proc.wait()

    def __iter__(self):
        return self

    def next(self):
        return self.fdesc.next()


def open_file(fname):
    return FileOpener(fname)


_HASH_COMMANDS = {
    'md5': config.MD5_CMD,
    'sha1': config.SHA1_CMD,
    'sha256': config.SHA256_CMD,
}


def hash_file(fname, hashtype="sha1"):
    """Compute a hash of data from a given file"""
    with open_file(fname) as fdesc:
        if hashtype in _HASH_COMMANDS:
            try:
                # By default we try to use {md5,sha1,sha256}sum
                # command, since they seem to be (a lot) faster
                return subprocess.Popen(
                    [_HASH_COMMANDS[hashtype]], stdin=fdesc,
                    stdout=subprocess.PIPE, stderr=open(os.devnull, 'w')
                ).communicate()[0].split()[0]
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
        result = hashlib.new(hashtype)
        for data in iter(lambda: fdesc.read(1048576), ""):
            result.update(data)
        return result.hexdigest()


def serialize(obj):
    """Return a JSON-compatible representation for `obj`"""
    if isinstance(obj, REGEXP_T):
        return '/%s/%s' % (
            obj.pattern,
            ''.join(x.lower() for x in 'ILMSXU'
                    if getattr(re, x) & obj.flags),
        )
    if isinstance(obj, datetime.datetime):
        return str(obj)
    raise TypeError("Don't know what to do with %r (%r)" % (obj, type(obj)))


class LogFilter(logging.Filter):
    """A logging filter that prevents dupplicate warnings and only reports
messages with level lower than INFO when config.DEBUG (or
config.DEBUG_DB) is True.

    """
    MAX_WARNINGS_STORED = 100
    def __init__(self):
        # Python 2.6: logging.Filter is an old-style class, super()
        # cannot be used.
        # super(LogFilter, self).__init__()
        logging.Filter.__init__(self)
        self.warnings = set()
    def filter(self, record):
        """Decides whether we should log a record"""
        if record.levelno < logging.INFO:
            if record.msg.startswith('DB:'):
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


class FakeArgparserParent(object):
    """This is a stub to implement a parent-like behavior when
    optparse has to be used.

    """

    def __init__(self):
        self.args = []

    def add_argument(self, *args, **kargs):
        """Stores parent's arguments for latter (manual)
        processing.

        """
        self.args.append((args, kargs))


# Country aliases:
#   - UK: GB
#   - EU*: EU + 28 EU member states
COUNTRY_ALIASES = {
    "UK": "GB",
    "EU*": [
        "EU", "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI",
        "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT",
        "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB",
    ],
}


def country_unalias(country):
    """Takes either a country code (or an iterator of country codes)
    and returns either a country code or a list of country codes.

    Current aliases are:

      - "UK": alias for "GB".

      - "EU*": alias for a list containing "EU" (which is a code used
        in Maxming GeoIP database) plus the list of the country codes
        of the European Union member states.

    """
    if isinstance(country, basestring):
        return COUNTRY_ALIASES.get(country, country)
    if hasattr(country, '__iter__'):
        return reduce(
            lambda x, y: x + (y if isinstance(y, list) else [y]),
            (country_unalias(country_elt) for country_elt in country),
            [],
        )
    return country


def screenwords(imgdata):
    """Takes an image and returns a list of the words seen by the OCR"""
    if config.TESSERACT_CMD is not None:
        proc = subprocess.Popen([config.TESSERACT_CMD, "stdin", "stdout"],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        proc.stdin.write(imgdata)
        proc.stdin.close()
        words = set()
        result = []
        size = MAXVALLEN
        for line in proc.stdout:
            if size == 0:
                break
            for word in line.split():
                if word not in words:
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

if USE_PIL:
    def _img_size(bbox):
        """Returns the size of a given `bbox`"""
        return (bbox[2] - bbox[0]) * (bbox[3] - bbox[1])

    def _trim_image(img, tolerance):
        """Returns the tiniest `bbox` to trim `img`"""
        result = None
        for pixel in [(0, 0), (img.size[0] - 1, 0), (0, img.size[1] - 1),
                      (img.size[0] - 1, img.size[1] - 1)]:
            if result is not None and result[0] < pixel[0] < result[2] - 1 \
               and result[1] < pixel[1] < result[3] - 1:
                # This pixel is already removed by current result
                continue
            bkg = PIL.Image.new(img.mode, img.size, img.getpixel(pixel))
            diffbkg = PIL.ImageChops.difference(img, bkg)
            if tolerance:
                diffbkg = PIL.ImageChops.add(diffbkg, diffbkg, 2.0, -tolerance)
            bbox = diffbkg.getbbox()
            if not bbox:
                # Image no longer exists after trim
                return
            if result is None:
                result = bbox
            elif _img_size(bbox) < _img_size(result):
                result = bbox
        return result

    def trim_image(imgdata, tolerance=1, minborder=10):
        """Trims the image, `tolerance` is an integer from 0 (not
        tolerant, trims region with the exact same color) to 255
        (too tolerant, will trim the whole image).

        """
        img = PIL.Image.open(StringIO(imgdata))
        bbox = _trim_image(img, tolerance)
        if bbox:
            newbbox = (max(bbox[0] - minborder, 0),
                       max(bbox[1] - minborder, 0),
                       img.size[0] - max(img.size[0] - bbox[2] - minborder, 0),
                       img.size[1] - max(img.size[1] - bbox[3] - minborder, 0))
            if newbbox != (0, 0, img.size[0], img.size[1]):
                out = StringIO()
                img.crop(newbbox).save(out, format='jpeg')
                out.seek(0)
                return out.read()
            # Image does not need to be modified
            return True
        # Image no longer exists after trim
        return False
else:
    def trim_image(imgdata, _tolerance=1, _minborder=10):
        """Stub function used when PIL cannot be found"""
        LOGGER.warning('Python PIL not found, screenshots will not be trimmed')
        return imgdata


_PORTS = {}
_PORTS_POPULATED = False


def _set_ports():
    """Populate _PORTS global dict, based on nmap-services when available
(and found), with a fallback to /etc/services.

    This function is called on module load.

    """
    global _PORTS, _PORTS_POPULATED
    try:
        fdesc = open(os.path.join(config.NMAP_SHARE_PATH, 'nmap-services'))
    except (IOError, AttributeError):
        try:
            with open('/etc/services') as fdesc:
                for line in fdesc:
                    try:
                        _, port = line.split('#', 1)[0].split(None, 2)
                        port, proto = port.split('/', 1)
                        port = int(port)
                    except ValueError:
                        continue
                    _PORTS.setdefault(proto, {})[port] = 0.5
        except IOError:
            pass
    else:
        for line in fdesc:
            try:
                _, port, freq = line.split('#', 1)[0].split(None, 3)
                port, proto = port.split('/', 1)
                port = int(port)
                freq = float(freq)
            except ValueError:
                continue
            _PORTS.setdefault(proto, {})[port] = freq
        fdesc.close()
    for proto, entry in config.KNOWN_PORTS.iteritems():
        for port, proba in entry.iteritems():
            _PORTS.setdefault(proto, {})[port] = proba
    _PORTS_POPULATED = True


def guess_srv_port(port1, port2, proto="tcp"):
    """Returns 1 when port1 is probably the server port, -1 when that's
    port2, and 0 when we cannot tell.

    """
    if not _PORTS_POPULATED:
        _set_ports()
    ports = _PORTS.get(proto, {})
    cmpval = cmp(ports.get(port1, 0), ports.get(port2, 0))
    if cmpval == 0:
        return cmp(port2, port1)
    return cmpval


_NMAP_PROBES = {}
_NMAP_PROBES_POPULATED = False
_NMAP_CUR_PROBE = None


def _read_nmap_probes():
    global _NMAP_CUR_PROBE, _NMAP_PROBES_POPULATED
    _NMAP_CUR_PROBE = None
    def parse_line(line):
        global _NMAP_PROBES, _NMAP_CUR_PROBE
        if line.startswith('match '):
            line = line[6:]
            soft = False
        elif line.startswith('softmatch '):
            line = line[10:]
            soft = True
        elif line.startswith('Probe '):
            _NMAP_CUR_PROBE = []
            proto, name, probe = line[6:].split(' ', 2)
            _NMAP_PROBES.setdefault(proto.lower(), {})[name] = {
                "probe": probe, "fp": _NMAP_CUR_PROBE
            }
            return
        else:
            return
        service, data = line.split(' ', 1)
        info = {"soft": soft}
        while data:
            if data.startswith('cpe:'):
                key = 'cpe'
                data = data[4:]
            else:
                key = data[0]
                data = data[1:]
            sep = data[0]
            data = data[1:]
            index = data.index(sep)
            value = data[:index]
            data = data[index + 1:]
            flag = ''
            if data:
                if ' ' in data:
                    flag, data = data.split(' ', 1)
                else:
                    flag, data = data, ''
            if key == 'm':
                if value.endswith('\\r\\n'):
                    value = value[:-4] + '(?:\\r\\n|$)'
                elif value.endswith('\\\\n'):
                    value = value[:3] + '(?:\\\\n|$)'
                elif value.endswith('\\n'):
                    value = value[:-2] + '(?:\\n|$)'
                value = re.compile(
                    value,
                    flags=sum(getattr(re, f) if hasattr(re, f) else 0
                              for f in flag.upper()),
                )
                flag = ''
            info[key] = (value, flag)
        _NMAP_CUR_PROBE.append((service, info))
    try:
        with open(os.path.join(config.NMAP_SHARE_PATH, 'nmap-service-probes')) as fdesc:
            for line in fdesc:
                parse_line(line[:-1])
    except (AttributeError, IOError):
        LOGGER.warning('Cannot read Nmap service fingerprint file.',
                       exc_info=True)
    del _NMAP_CUR_PROBE
    _NMAP_PROBES_POPULATED = True


def get_nmap_svc_fp(proto="tcp", probe="NULL"):
    global _NMAP_PROBES, _NMAP_PROBES_POPULATED
    if not _NMAP_PROBES_POPULATED:
        _read_nmap_probes()
    return _NMAP_PROBES[proto][probe]


_IKESCAN_VENDOR_IDS = {}
_IKESCAN_VENDOR_IDS_POPULATED = False


def _read_ikescan_vendor_ids():
    global _IKESCAN_VENDOR_IDS, _IKESCAN_VENDOR_IDS_POPULATED
    try:
        with open(os.path.join(config.DATA_PATH, 'ike-vendor-ids')) as fdesc:
            sep = re.compile('\\t+')
            _IKESCAN_VENDOR_IDS = [
                (line[0], re.compile(line[1].replace('[[:xdigit:]]',
                                                     '[0-9a-f]'), re.I))
                for line in (
                    sep.split(line, 1)
                    for line in (line.strip().split('#', 1)[0]
                                 for line in fdesc)
                    if line
                )
            ]
    except (AttributeError, IOError) as exc:
        LOGGER.warning('Cannot read ike-scan vendor IDs file.', exc_info=True)
    _IKESCAN_VENDOR_IDS_POPULATED = True


def get_ikescan_vendor_ids():
    global _IKESCAN_VENDOR_IDS, _IKESCAN_VENDOR_IDS_POPULATED
    if not _IKESCAN_VENDOR_IDS_POPULATED:
        _read_ikescan_vendor_ids()
    return _IKESCAN_VENDOR_IDS


def find_ike_vendor_id(vendorid):
    vid = vendorid.encode('hex')
    for name, sig in get_ikescan_vendor_ids():
        if sig.search(vid):
            return name


def nmap_encode_data(data):
    return "".join(
        (d if " " <= d <= "~" else (repr(d)[1:-1] if d in '\r\n\t'
                                    else ('\\x%02x' % ord(d))))
        for d in data
    )


def nmap_svc_fp_format_data(data, match):
    for i, value in enumerate(match.groups()):
        if value is None:
            if '$%d' % (i + 1) in data:
                return
            continue
        data = data.replace('$%d' % (i + 1), nmap_encode_data(value))
    return data


def normalize_props(props):
    """Returns a normalized property list/dict so that (roughly):
        - a list gives {k: "{k}"}
        - a dict gives {k: v if v is not None else "{%s}" % v}
    """
    if not isinstance(props, dict):
        props = dict.fromkeys(props)
    props = dict(
        (key, (value if isinstance(value, basestring) else
               ("{%s}" % key) if value is None else
               str(value))) for key, value in props.iteritems()
    )
    return props


def datetime2timestamp(dtetme):
    return float(dtetme.strftime("%s.%f"))


_UNITS = ['']
_UNITS.extend('kMGTPEZY')


def num2readable(value):
    idx = int(math.log(value, 1000))
    try:
        unit = _UNITS[idx]
    except IndexError:
        unit = 'Y'
        idx = 1000 ** 8
    else:
        idx = 1000 ** idx
    if isinstance(value, float):
        return '%.3f%s' % (value / idx, unit)
    return '%d%s' % (value / idx, unit)
