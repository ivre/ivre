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
Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>

This module implement tools to look for (public) keys in the database.

"""

from ivre.db import db
from ivre.utils import int2ip

from collections import namedtuple
import re
import subprocess
import struct
from Crypto.PublicKey import RSA

Key = namedtuple("key", ["ip", "port", "service", "type", "size",
                         "key", "md5"])

class DBKey(object):
    """Base class for a key lookup tool"""

    def __init__(self, dbc, baseflt=None):
        self.dbc = dbc
        self.baseflt = self.dbc.flt_empty if baseflt is None else baseflt

    @property
    def cond(self):
        return self.dbc.flt_and(self.baseflt, self.fltkey)

    def __iter__(self):
        return (key
                for record in self.dbc.get(self.cond)
                for key in self.getkeys(record))


class NmapKey(DBKey):
    """Base class for a key lookup tool specialized for the active
    (Nmap) DB.

    """

    def __init__(self, baseflt=None):
        DBKey.__init__(self, db.nmap, baseflt=baseflt)

    def getscripts(self, host):
        for port in host.get('ports', []):
            try:
                script = (s for s in port.get('scripts', [])
                          if s['id'] == self.scriptid).next()
            except StopIteration:
                continue
            yield {"port": port["port"], "script": script}


class PassiveKey(DBKey):
    """Base class for a key lookup tool specialized for the passive
    (Bro) DB.

    """
    def __init__(self, baseflt=None):
        DBKey.__init__(self, db.passive, baseflt=baseflt)

    def getkeys(self, record):
        certtext = self._pem2key(record['fullvalue']
                                 if 'fullvalue' in record
                                 else record['value'])
        if certtext is None:
            return
        yield Key(int2ip(record['addr']), record["port"], "ssl",
                  certtext['type'], int(certtext['len']),
                  RSA.construct((
                      long(self.modulus_badchars.sub(
                          "", certtext['modulus']), 16),
                      long(certtext['exponent']))),
                  record['infos']['md5hash'].decode('hex'))


class SSLKey(object):
    """Base class for a key lookup tool specialized for the Keys from
    SSL certificates.

    """

    def __init__(self):
        self.pem_borders = re.compile('^-*(BEGIN|END) CERTIFICATE-*$', re.M)
        self.modulus_badchars = re.compile('[ :\n]+')

    def read_pem(self, pem):
        pem = self.pem_borders.sub("", pem).replace('\n', '').decode('base64')
        proc = subprocess.Popen(['openssl', 'x509', '-noout', '-text',
                                 '-inform', 'DER'], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        proc.stdin.write(pem)
        proc.stdin.close()
        return proc.stdout.read()

    def _pem2key(self, pem):
        pem = self.read_pem(pem)
        certtext = self.keyincert.search(pem)
        return None if certtext is None else certtext.groupdict()


class SSLNmapKey(NmapKey, SSLKey):
    """Base class for the keys from SSL certificates within the active
    (Nmap) DB.

    """

    def __init__(self, baseflt=None):
        NmapKey.__init__(self, baseflt=baseflt)
        SSLKey.__init__(self)
        self.scriptid = "ssl-cert"

    @property
    def fltkey(self):
        return self.dbc.searchscript(
            name=self.scriptid,
            values={'pem': re.compile('^-* *BEGIN CERTIFICATE'),
                    'pubkey.type': self.keytype},
        )

    def getkeys(self, host):
        for script in self.getscripts(host):
            yield Key(int2ip(host['addr']), script["port"], "ssl",
                      script["script"][self.scriptid]['pubkey']['type'],
                      script["script"][self.scriptid]['pubkey']['bits'],
                      self.pem2key(script["script"][self.scriptid]['pem']),
                      script["script"][self.scriptid]['md5'].decode('hex'))


class SSLPassiveKey(PassiveKey, SSLKey):
    """Base class for the keys from SSL certificates within the passive
    (Bro) DB.

    """

    def __init__(self, baseflt=None):
        PassiveKey.__init__(self, baseflt=baseflt)
        SSLKey.__init__(self)

    @property
    def fltkey(self):
        return {'source': 'cert',
                'recontype': 'SSL_SERVER',
                'infos.pubkeyalgo': '%sEncryption' % self.keytype}


class SSHNmapKey(NmapKey):
    """Base class for the SSH keys within the active (Nmap) DB."""

    def __init__(self, baseflt=None):
        NmapKey.__init__(self, baseflt=baseflt)
        self.scriptid = "ssh-hostkey"

    @property
    def fltkey(self):
        return self.dbc.searchscript(
            name=self.scriptid,
            values={'key': re.compile('^[a-zA-Z0-9/+]+={0,2}$'),
                    'type': 'ssh-%s' % self.keytype},
        )

    def getkeys(self, host):
        for script in self.getscripts(host):
            for key in script['script'][self.scriptid]:
                if key['type'][4:] == self.keytype:
                    data = key['key'].decode('base64')
                    # Handle bug (in Nmap?) where data gets encoded
                    # twice.
                    if data[0] != '\x00':
                        data = data.decode('base64')
                    yield Key(
                        int2ip(host['addr']), script["port"], "ssh",
                        key['type'][4:],
                        int(key['bits']),
                        self.data2key(data),
                        key['fingerprint'].decode('hex'))

    @staticmethod
    def _data2key(data):
        while data:
            length = struct.unpack('>I', data[:4])[0]
            yield data[4:4 + length]
            data = data[4 + length:]


class RSAKey(object):
    """Base class for the RSA Keys.

    """

    def __init__(self):
        self.keyincert = re.compile('\n *Issuer: (?P<issuer>.*)'
                                    '\n(?:.*\n)* *Subject: (?P<subject>.*)'
                                    '\n(?:.*\n)* *Public Key Algorithm:'
                                    ' (?P<type>.*)Encryption'
                                    '\n *Public-Key: \\((?P<len>[0-9]+) bit\\)'
                                    '\n *Modulus:\n(?P<modulus>[\\ 0-9a-f:\n]+)'
                                    '\n\\ *Exponent: (?P<exponent>[0-9]+) ')
        self.keytype = 'rsa'

    def _pem2key(self, pem):
        raise NotImplementedError

    def pem2key(self, pem):
        certtext = self._pem2key(pem)
        return None if certtext is None else RSA.construct((
            long(self.modulus_badchars.sub("", certtext['modulus']), 16),
            long(certtext['exponent']),
        ))

    def _data2key(self, data):
        raise NotImplementedError

    def data2key(self, data):
        data = self._data2key(data)
        _, exp, mod = (data.next(),
                       long(data.next().encode('hex'), 16),
                       long(data.next().encode('hex'), 16))
        return RSA.construct((mod, exp))


class SSLRsaNmapKey(SSLNmapKey, RSAKey):
    """Tool for the RSA Keys from SSL certificates within the active
    (Nmap) DB.

    """

    def __init__(self, baseflt=None):
        SSLNmapKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)


class SSHRsaNmapKey(SSHNmapKey, RSAKey):
    """Tool for the RSA Keys from SSH services within the active
    (Nmap) DB.

    """

    def __init__(self, baseflt=None):
        SSHNmapKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)


class SSLRsaPassiveKey(SSLPassiveKey, RSAKey):
    """Tool for the RSA Keys from SSL certificates within the passive
    (Bro) DB.

    """

    def __init__(self, baseflt=None):
        SSLPassiveKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)

