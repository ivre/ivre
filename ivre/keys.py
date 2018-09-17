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

This module implement tools to look for (public) keys in the database.

"""


from collections import namedtuple
import re
import subprocess


from Crypto.PublicKey import RSA
from past.builtins import long


from ivre.db import db
from ivre import config, utils


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
                script = next(s for s in port.get('scripts', [])
                              if s['id'] == self.scriptid)
            except StopIteration:
                continue
            yield {"port": port["port"], "script": script}


class PassiveKey(DBKey):
    """Base class for a key lookup tool specialized for the passive
    (Bro) DB.

    """
    def __init__(self, baseflt=None):
        DBKey.__init__(self, db.passive, baseflt=baseflt)


class SSLKey(object):
    """Base class for a key lookup tool specialized for the Keys from
    SSL certificates.

    """

    pem_borders = re.compile(b'^-*(BEGIN|END) CERTIFICATE-*$', re.M)
    modulus_badchars = re.compile(b'[ :\n]+')

    @property
    def fltkey(self):
        return self.dbc.searchcert(keytype=self.keytype)

    @classmethod
    def read_pem(cls, pem):
        try:
            pem = pem.encode()
        except AttributeError:
            pass
        pem = utils.decode_b64(cls.pem_borders.sub(b"", pem))
        proc = subprocess.Popen([config.OPENSSL_CMD, 'x509', '-noout', '-text',
                                 '-inform', 'DER'], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        proc.stdin.write(pem)
        proc.stdin.close()
        return proc.stdout.read()

    @classmethod
    def _pem2key(cls, pem):
        pem = cls.read_pem(pem)
        certtext = cls.keyincert.search(pem)
        return None if certtext is None else certtext.groupdict()

    def read_der(self, der):
        proc = subprocess.Popen([config.OPENSSL_CMD, 'x509', '-noout', '-text',
                                 '-inform', 'DER'], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        proc.stdin.write(der)
        proc.stdin.close()
        return proc.stdout.read()

    def _der2key(self, der):
        der = self.read_der(der)
        certtext = self.keyincert.search(der)
        return None if certtext is None else certtext.groupdict()


class SSLNmapKey(NmapKey, SSLKey):
    """Base class for the keys from SSL certificates within the active
    (Nmap) DB.

    """

    scriptid = "ssl-cert"

    def __init__(self, baseflt=None):
        NmapKey.__init__(self, baseflt=baseflt)
        SSLKey.__init__(self)

    def getkeys(self, host):
        for script in self.getscripts(host):
            yield Key(host['addr'], script["port"], "ssl",
                      script["script"][self.scriptid]['pubkey']['type'],
                      script["script"][self.scriptid]['pubkey']['bits'],
                      self.pem2key(script["script"][self.scriptid]['pem']),
                      utils.decode_hex(script["script"][self.scriptid]['md5']))


class SSLPassiveKey(PassiveKey, SSLKey):
    """Base class for the keys from SSL certificates within the passive
    (Bro) DB.

    """

    def __init__(self, baseflt=None):
        PassiveKey.__init__(self, baseflt=baseflt)
        SSLKey.__init__(self)

    def getkeys(self, record):
        certtext = self._der2key(record['value'])
        if certtext is None:
            return

        yield Key(record['addr'], record["port"], "ssl", certtext['type'],
                  int(certtext['len']),
                  RSA.construct((
                      long(self.modulus_badchars.sub(
                          b"", certtext['modulus']), 16),
                      long(certtext['exponent']))),
                  utils.decode_hex(record['infos']['md5']))


class SSHKey(object):
    """Base class for a key lookup tool specialized for the Keys from
    SSH hosts.

    """

    @property
    def fltkey(self):
        return self.dbc.searchsshkey(keytype=self.keytype)


class SSHNmapKey(NmapKey, SSHKey):
    """Base class for the SSH keys within the active (Nmap) DB."""

    scriptid = "ssh-hostkey"

    def __init__(self, baseflt=None):
        NmapKey.__init__(self, baseflt=baseflt)
        SSHKey.__init__(self)

    def getkeys(self, host):
        for script in self.getscripts(host):
            for key in script['script'][self.scriptid]:
                if key['type'][4:] == self.keytype:
                    data = utils.decode_b64(key['key'].encode())
                    # Handle bug (in Nmap?) where data gets encoded
                    # twice.
                    if data[:1] != b'\x00':
                        data = utils.decode_b64(data)
                    yield Key(
                        host['addr'], script["port"], "ssh", key['type'][4:],
                        int(float(key['bits'])),  # for some reason,
                                                  # Nmap sometimes
                                                  # outputs 1024.0
                        self.data2key(data),
                        utils.decode_hex(key['fingerprint']),
                    )


class SSHPassiveKey(PassiveKey, SSHKey):
    """Base class for the keys from SSH certificates within the passive
    (Bro) DB.

    """

    def __init__(self, baseflt=None):
        PassiveKey.__init__(self, baseflt=baseflt)
        SSHKey.__init__(self)

    def getkeys(self, record):
        yield Key(record['addr'], record["port"], "ssh",
                  record['infos']['algo'][4:], record['infos']['bits'],
                  RSA.construct((long(record['infos']['modulus']),
                                 long(record['infos']['exponent']))),
                  utils.decode_hex(record['infos']['md5']))


class RSAKey(object):
    """Base class for the RSA Keys.

    """

    keyincert = re.compile(
        b'\n *Issuer: (?P<issuer>.*)'
        b'\n(?:.*\n)* *Subject: (?P<subject>.*)'
        b'\n(?:.*\n)* *Public Key Algorithm:'
        b' (?P<type>.*)Encryption'
        b'\n *(?:.*)Public-Key: \\((?P<len>[0-9]+) bit\\)'
        b'\n *Modulus:\n(?P<modulus>[\\ 0-9a-f:\n]+)'
        b'\n\\ *Exponent: (?P<exponent>[0-9]+) '
    )
    keytype = 'rsa'

    @classmethod
    def _pem2key(cls, pem):
        raise NotImplementedError

    @classmethod
    def pem2key(cls, pem):
        certtext = cls._pem2key(pem)
        return None if certtext is None else RSA.construct((
            long(cls.modulus_badchars.sub(b"", certtext['modulus']), 16),
            long(certtext['exponent']),
        ))

    @staticmethod
    def data2key(data):
        data = utils._parse_ssh_key(data)
        _, exp, mod = (next(data),  # noqa: F841 (_)
                       long(utils.encode_hex(next(data)), 16),
                       long(utils.encode_hex(next(data)), 16))
        return RSA.construct((mod, exp))


class SSLRsaNmapKey(SSLNmapKey, RSAKey):
    """Tool for the RSA Keys from SSL certificates within the active
    (Nmap) DB.

    """

    def __init__(self, baseflt=None):
        SSLNmapKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)

    def getkeys(self, host):
        for script in self.getscripts(host):
            key = script["script"][self.scriptid]['pubkey']
            yield Key(host['addr'], script["port"], "ssl", key['type'],
                      key['bits'],
                      RSA.construct((long(key['modulus']),
                                     long(key['exponent']),)),
                      utils.decode_hex(script["script"][self.scriptid]['md5']))


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


class SSHRsaPassiveKey(SSHPassiveKey, RSAKey):
    """Tool for the RSA Keys from SSH services within the active
    (Nmap) DB.

    """

    def __init__(self, baseflt=None):
        SSHPassiveKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)
