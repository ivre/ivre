#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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
Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains functions that might be usefull to any other
sub-module or script.
"""

import struct
import socket
import datetime
import re
import hashlib
import subprocess
import os
import errno
import stat

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

REGEXP_T = type(re.compile(''))

def guess_prefix(directory=None):
    """Attempts to find the base directory where IVRE components are
    installed.

    """
    def check_candidate(path, directory=None):
        candidate = os.path.join(path, 'share', 'ivre')
        if directory is not None:
            candidate = os.path.join(candidate, directory)
        try:
            if stat.S_ISDIR(os.stat(candidate).st_mode):
                return candidate
        except OSError:
            pass    
    if __file__.startswith('/'):
        path = '/'
        # absolute path
        for elt in __file__.split('/')[1:]:
            if elt in ['lib', 'lib32', 'lib64']:
                candidate = check_candidate(path, directory=directory)
                if candidate is not None:
                    return candidate
            path = os.path.join(path, elt)
    for path in ['/usr', '/usr/local', '/opt', '/opt/ivre']:
        candidate = check_candidate(path, directory=directory)
        if candidate is not None:
            return candidate

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
    if type(start) is str:
        start = ip2int(start)
    if type(stop) is str:
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


def getdomains(name):
    """Generates the upper domains from a domain name."""
    name = name.split('.')
    return ('.'.join(name[i:]) for i in xrange(len(name)))


def _passive_getinfos_http_client_authorization(spec):
    """Extract (for now) the usernames and passwords from Basic
    authorization headers
    """
    infos = {}
    fullinfos = {}
    data = spec.get('fullvalue', spec['value']).split(None, 1)
    if data[0].strip().lower() == 'basic' and data[1:]:
        try:
            infos['username'], infos['password'] = ''.join(
                data[1].strip()).decode('base64').decode('latin-1').split(':', 1)
            for field in ['username', 'password']:
                if len(infos[field]) > MAXVALLEN:
                    fullinfos[field] = infos[field]
                    infos[field] = infos[field][:MAXVALLEN]
        except Exception:
            pass
    res = {}
    if infos:
        res['infos'] = infos
    if fullinfos:
        res['fullinfos'] = fullinfos
    return res


def _passive_getinfos_dns(spec):
    """Extract domain names in an handy-to-index-and-query form."""
    infos = {}
    fullinfos = {}
    fields = {'domain': 'value', 'domaintarget': 'targetval'}
    for field in fields:
        try:
            if fields[field] not in spec:
                continue
            infos[field] = []
            fullinfos[field] = []
            for domain in getdomains(spec.get('full' + fields[field],
                                              spec[fields[field]])):
                infos[field].append(domain[:MAXVALLEN])
                if len(domain) > MAXVALLEN:
                    fullinfos[field].append(domain)
            if not infos[field]:
                del infos[field]
            if not fullinfos[field]:
                del fullinfos[field]
        except Exception:
            pass
    res = {}
    if infos:
        res['infos'] = infos
    if fullinfos:
        res['fullinfos'] = fullinfos
    return res

_CERTINFOS = re.compile(
    '\n *'
    'Issuer: (?P<issuer>.*)'
    '\n(?:.*\n)* *'
    'Subject: (?P<subject>.*)'
    '\n(?:.*\n)* *'
    'Public Key Algorithm: (?P<pubkeyalgo>.*)'
    '(?:\n|$)'
)


def _passive_getinfos_cert(spec):
    """Extract info from a certificate (hash values, issuer, subject,
    algorithm) in an handy-to-index-and-query form.

    """
    infos = {}
    fullinfos = {}
    try:
        cert = spec.get('fullvalue', spec['value']).decode('base64')
    except Exception:
        return {}
    for hashtype in ['md5', 'sha1']:
        infos['%shash' % hashtype] = hashlib.new(hashtype, cert).hexdigest()
    proc = subprocess.Popen(['openssl', 'x509', '-noout', '-text',
                             '-inform', 'DER'], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    proc.stdin.write(cert)
    proc.stdin.close()
    try:
        newinfos = _CERTINFOS.search(proc.stdout.read()).groupdict()
        newfullinfos = {}
        for field in newinfos:
            if len(newinfos[field]) > MAXVALLEN:
                newfullinfos[field] = newinfos[field]
                newinfos[field] = newinfos[field][:MAXVALLEN]
        infos.update(newinfos)
        fullinfos.update(newfullinfos)
    except Exception:
        pass
    res = {}
    if infos:
        res['infos'] = infos
    if fullinfos:
        res['fullinfos'] = fullinfos
    return res

_PASSIVE_GETINFOS_FUNCTIONS = {
    'HTTP_CLIENT_HEADER':
    {'AUTHORIZATION': _passive_getinfos_http_client_authorization,
     'PROXY-AUTHORIZATION': _passive_getinfos_http_client_authorization},
    'HTTP_CLIENT_HEADER_SERVER':
    {'AUTHORIZATION': _passive_getinfos_http_client_authorization,
     'PROXY-AUTHORIZATION': _passive_getinfos_http_client_authorization},
    'DNS_ANSWER': _passive_getinfos_dns,
    'SSL_SERVER': _passive_getinfos_cert,
}


def passive_getinfos(spec):
    """This functions takes a document from a passive sensor, and
    prepares its 'infos' and 'fullinfos' fields (which are not added
    but returned).

    """
    function = _PASSIVE_GETINFOS_FUNCTIONS.get(spec.get('recontype'))
    if type(function) is dict:
        function = function.get(spec.get('source'))
    if function is None:
        return {}
    if hasattr(function, '__call__'):
        return function(spec)


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
    if type(string) is REGEXP_T:
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


def makedirs(dirname):
    """Makes directories like mkdir -p, raising no exception when
    dirname already exists.

    """
    try:
        os.makedirs(dirname)
    except OSError as exception:
        if not (exception.errno == errno.EEXIST and os.path.isdir(dirname)):
            raise exception


def isfinal(elt):
    """Decides whether or not elt is a final element (i.e., an element
    that does not contain other elements)

    """
    return type(elt) in [str, int, float, unicode, datetime.datetime]


def diff(doc1, doc2):
    """NOT WORKING YET - WORK IN PROGRESS - Returns fields that differ
    between two scans.

    """
    keys1 = set(doc1.keys())
    keys2 = set(doc2.keys())
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
        if key in ['extraports']:
            res[key] = {}
            kkeys1 = set(doc1[key].keys())
            kkeys2 = set(doc2[key].keys())
            for kkey in kkeys1.symmetric_difference(kkeys2):
                res[key][kkey] = True
            for kkey in kkeys1.intersection(kkeys2):
                if doc1[key][kkey] != doc2[key][kkey]:
                    res[key][kkey] = True
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
