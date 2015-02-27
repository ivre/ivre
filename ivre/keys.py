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

This module implement tools to look for (public) keys in the database.
"""

from ivre.db import db

import re
import struct
import subprocess
from Crypto.Hash import MD5


class Key(object):
    scriptid = None
    regexp_key = None
    regexp_hash = None

    def __init__(self, cond=None):
        if cond is None:
            self.cond = {}
        else:
            self.cond = cond

    def cond_key(self):
        return db.nmap.flt_and(
            self.cond,
            db.nmap.searchscript(name=self.scriptid,
                                 output=self.regexp_key))

    def cond_hash(self):
        return db.nmap.flt_and(
            self.cond,
            db.nmap.searchscript(name=self.scriptid,
                                 output=self.regexp_hash))

    def extract_key(self, i):
        return i

    @staticmethod
    def filter(_):
        return True

    @staticmethod
    def count(cond):
        return db.nmap.get(cond).count()

    def count_keys(self):
        return self.count(self.cond_key())

    def count_hashes(self):
        return self.count(self.cond_hash())

    def get(self, cond, regexp):
        cur = db.nmap.get(cond, timeout=False)
        for host in cur:
            for port in host['ports']:
                if not 'scripts' in port:
                    continue
                for script in port['scripts']:
                    if script['id'] == self.scriptid:
                        for i in regexp.finditer(script['output']):
                            i = i.groupdict()
                            i['host'] = host['addr']
                            i['port'] = port['port']
                            if self.filter(i):
                                i = self.extract_key(i)
                                yield i

    def get_keys(self):
        return self.get(self.cond_key(), self.regexp_key)

    def get_hashes(self):
        return self.get(self.cond_hash(), self.regexp_hash)


class PassiveSSLKey(Key):
    def __init__(self, cond=None):
        Key.__init__(self, cond=cond)
        self.cond_hash = self.cond_key

    def cond_key(self):
        return db.passive.flt_and(
            self.cond,
            db.passive.searchcert())

    @staticmethod
    def count(cond):
        return db.passive.get(cond).count()

    def count_keys(self):
        return self.count(self.cond_key())

    def count_hashes(self):
        return self.count(self.cond_hash())

    def get(self, cond):
        cur = db.passive.get(cond, timeout=False)
        for record in cur:
            i = {
                'host': record['addr'],
                'port': record['port'],
            }
            if 'fullvalue' in record:
                i['cert'] = record['fullvalue']
            else:
                i['cert'] = record['value']
            # here we cannot test .filter() before .extract_key()...
            i = self.extract_key(i)
            if self.filter(i):
                yield i

    def get_keys(self):
        return self.get(self.cond_key())

    def get_hashes(self):
        return self.get(self.cond_hash())


class SSHKey(Key):
    keytype = None
    scriptid = 'ssh-hostkey'

    def filter(self, i):
        if self.keytype is None:
            return True
        else:
            return 'type' in i and i['type'] == 'ssh-%s' % self.keytype

    def get_cond(self, condtype):
        if self.keytype is None:
            return db.nmap.flt_and(
                self.cond,
                db.nmap.searchscript(name=self.scriptid),
                {'ports.scripts.ssh-hostkey.%s' % condtype: {'$exists': True}},
            )
        return db.nmap.flt_and(
            self.cond,
            db.nmap.searchscript(name=self.scriptid),
            {'ports.scripts.ssh-hostkey': {'$elemMatch': {
                condtype: {'$exists': True},
                'type': 'ssh-%s' % self.keytype,
            }}},
        )

    def cond_key(self):
        return self.get_cond("key")

    def cond_hash(self):
        return self.get_cond("fingerprint")

    def get(self, cond):
        cur = db.nmap.get(cond, timeout=False)
        for host in cur:
            for port in host['ports']:
                for script in port.get('scripts', []):
                    if script['id'] == self.scriptid:
                        for i in script.get(self.scriptid, []):
                            i['host'] = host['addr']
                            i['port'] = port['port']
                            if self.filter(i):
                                i = self.extract_key(i)
                                yield i

    def extract_key(self, i):
        if i.get('type', '').startswith('ssh-'):
            i['type'] = i['type'][4:]
        if i.get('bits', '').isdigit():
            i['len'] = int(i.pop('bits'))
        if 'fingerprint' in i:
            i['hash'] = i.pop('fingerprint').decode('hex')
        return i

    def get_keys(self):
        return self.get(self.cond_key())

    def get_hashes(self):
        return self.get(self.cond_hash())

    @staticmethod
    def extract_key_data(data):
        while data:
            length = struct.unpack('>I', data[:4])[0]
            yield data[4:4 + length]
            data = data[4 + length:]


class SSHRSAKey(SSHKey):
    keytype = 'rsa'

    def extract_key(self, i):
        i = SSHKey.extract_key(self, i)
        if 'key' in i:
            _, exponent, modulus = self.extract_key_data(
                i['key'].decode('base64').decode('base64'))
            i['modulus'] = int(modulus.encode('hex'), 16)
            i['exponent'] = int(exponent.encode('hex'), 16)
            del i['key']
        return i


class SSLKey(Key):
    regexp_key = re.compile('\nPublic Key type: (?P<type>[^\n]*)'
                            '\nPublic Key bits: (?P<len>[0-9]+)\n.*'
                            '\nMD5: +(?P<hash>(?:[0-9a-f]{4} ){7}[0-9a-f]{4})'
                            '\n.*\n-----BEGIN CERTIFICATE-----'
                            '(?P<cert>[A-Za-z0-9/+=\n]+)'
                            '-----END CERTIFICATE-----\n', re.S)
    regexp_hash = re.compile('\nPublic Key type: (?P<type>[^\n]*)'
                             '\nPublic Key bits: (?P<len>[0-9]+)\n.*'
                             '\nMD5: +(?P<hash>(?:[0-9a-f]{4} ){7}[0-9a-f]{4})'
                             '\n', re.S)
    scriptid = 'ssl-cert'

    def extract_key(self, i):
        if 'hash' in i:
            i['hash'] = i['hash'].replace(' ', '').decode('hex')
        elif 'cert' in i:
            i['hash'] = MD5.new(
                i['cert'].replace('\n', '').decode('base64')
            ).hexdigest()
        return i


class SSLRSAKey(SSLKey):
    regexp_keyincert = re.compile('\n *Issuer: (?P<issuer>.*)'
                                  '\n(?:.*\n)* *Subject: (?P<subject>.*)'
                                  '\n(?:.*\n)* *Public Key Algorithm:'
                                  ' (?P<type>.*)Encryption'
                                  '\n *Public-Key: \\((?P<len>[0-9]+) bit\\)'
                                  '\n *Modulus:\n(?P<modulus>[\\ 0-9a-f:\n]+)'
                                  '\n\\ *Exponent: (?P<exponent>[0-9]+) ')

    @staticmethod
    def filter(i):
        return 'type' in i and i['type'] == 'rsa'

    def extract_key(self, i):
        i = SSLKey.extract_key(self, i)
        if 'cert' in i:
            proc = subprocess.Popen(['openssl', 'x509', '-noout', '-text',
                                     '-inform', 'DER'], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
            proc.stdin.write(i['cert'].replace('\n', '').decode('base64'))
            proc.stdin.close()
            certtext = proc.stdout.read()
            try:
                i.update(self.regexp_keyincert.search(certtext).groupdict())
            except AttributeError:
                pass
            else:
                i['modulus'] = int(re.sub('[ :\n]', '', i['modulus']), 16)
                i['exponent'] = int(i['exponent'])
            if 'len' in i and type(i['len']) is str:
                i['len'] = int(i['len'])
            del i['cert']
        return i


class PassiveSSLRSAKey(PassiveSSLKey, SSLRSAKey):

    def cond_key(self):
        return db.passive.flt_and(
            db.passive.flt_and(self.cond,
                               db.passive.searchcert()),
            db.passive.searchval('infos.pubkeyalgo', 'rsaEncryption'))

    def extract_key(self, i):
        if 'value' in i:
            i['cert'] = i['value']
            del i['value']
        return SSLRSAKey.extract_key(self, i)
