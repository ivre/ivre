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

"""This module implement tools to look for (public) keys in the
database.

"""


from collections import namedtuple
import re
import subprocess
from typing import AnyStr, Dict, Generator, Optional, Pattern, Union


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers


from ivre.db import db
from ivre import config
from ivre.types import DBPassive, DBNmap, DBView, Filter, Record
from ivre.types.active import NmapScript
from ivre import utils

DB = Union[DBPassive, DBNmap, DBView]

Key = namedtuple("Key", ["ip", "port", "service", "type", "size", "key", "md5"])

MODULUS_BADCHARS = re.compile(b"[ :\n]+")


def _rsa_construct(exp: int, mod: int) -> RSAPublicNumbers:
    return RSAPublicNumbers(exp, mod).public_key(default_backend())


class DBKey:
    """Base class for a key lookup tool"""

    fltkey: Filter

    def __init__(self, dbc: DB, baseflt: Optional[Filter] = None) -> None:
        self.dbc = dbc
        self.baseflt = self.dbc.flt_empty if baseflt is None else baseflt

    def getkeys(self, record: Record) -> Generator[Key, None, None]:
        raise NotImplementedError

    @property
    def cond(self) -> Filter:
        return self.dbc.flt_and(self.baseflt, self.fltkey)

    def __iter__(self) -> Generator[Key, None, None]:
        return (
            key for record in self.dbc.get(self.cond) for key in self.getkeys(record)
        )


class NmapKey(DBKey):
    """Base class for a key lookup tool specialized for the active
    (Nmap) DB.

    """

    scriptid: Optional[str] = None

    def __init__(self, baseflt: Optional[Filter] = None) -> None:
        DBKey.__init__(self, db.nmap, baseflt=baseflt)

    def getscripts(
        self, host: Record
    ) -> Generator[Dict[str, Union[str, NmapScript]], None, None]:
        for port in host.get("ports", []):
            try:
                script = next(
                    s for s in port.get("scripts", []) if s["id"] == self.scriptid
                )
            except StopIteration:
                continue
            yield {"port": port["port"], "script": script}


class PassiveKey(DBKey):
    """Base class for a key lookup tool specialized for the passive DB."""

    def __init__(self, baseflt: Optional[Filter] = None) -> None:
        DBKey.__init__(self, db.passive, baseflt=baseflt)


class SSLKey:
    """Base class for a key lookup tool specialized for the Keys from
    SSL certificates.

    """

    pem_borders = re.compile(b"^-*(BEGIN|END) CERTIFICATE-*$", re.M)
    keytype: str
    keyincert: Pattern[bytes]
    dbc: DB

    @property
    def fltkey(self) -> Filter:
        return self.dbc.searchcert(keytype=self.keytype)

    @classmethod
    def read_pem(cls, pem: AnyStr) -> bytes:
        if isinstance(pem, str):
            raw_cert = pem.encode()
        else:
            raw_cert = pem
        raw_cert = utils.decode_b64(cls.pem_borders.sub(b"", raw_cert))
        with subprocess.Popen(
            [config.OPENSSL_CMD, "x509", "-noout", "-text", "-inform", "DER"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        ) as proc:
            assert proc.stdin is not None
            assert proc.stdout is not None
            proc.stdin.write(raw_cert)
            proc.stdin.close()
            return proc.stdout.read()

    @classmethod
    def _pem2key(cls, pem: AnyStr) -> Optional[Dict[str, bytes]]:
        assert cls.keyincert is not None
        pem_parsed = cls.read_pem(pem)
        certtext = cls.keyincert.search(pem_parsed)
        return None if certtext is None else certtext.groupdict()

    @staticmethod
    def read_der(der: bytes) -> bytes:
        with subprocess.Popen(
            [config.OPENSSL_CMD, "x509", "-noout", "-text", "-inform", "DER"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        ) as proc:
            assert proc.stdin is not None
            assert proc.stdout is not None
            proc.stdin.write(der)
            proc.stdin.close()
            return proc.stdout.read()

    def _der2key(self, der: bytes) -> Optional[Dict[str, bytes]]:
        assert self.keyincert is not None
        der = self.read_der(der)
        certtext = self.keyincert.search(der)
        return None if certtext is None else certtext.groupdict()


class SSLNmapKey(NmapKey, SSLKey):
    """Base class for the keys from SSL certificates within the active
    (Nmap) DB.

    """

    scriptid = "ssl-cert"

    def __init__(self, baseflt: Optional[Filter] = None) -> None:
        NmapKey.__init__(self, baseflt=baseflt)
        SSLKey.__init__(self)

    @classmethod
    def pem2key(cls, pem: bytes) -> Optional[RSAPublicNumbers]:
        raise NotImplementedError

    def getkeys(self, record: Record) -> Generator[Key, None, None]:
        for script in self.getscripts(record):
            assert isinstance(script["script"], dict)  # NmapRecord
            yield Key(
                record["addr"],
                script["port"],
                "ssl",
                script["script"][self.scriptid]["pubkey"]["type"],
                script["script"][self.scriptid]["pubkey"]["bits"],
                self.pem2key(script["script"][self.scriptid]["pem"]),
                utils.decode_hex(script["script"][self.scriptid]["md5"]),
            )


class SSLPassiveKey(PassiveKey, SSLKey):
    """Base class for the keys from SSL certificates within the passive
    DB.

    """

    def __init__(self, baseflt: Optional[Filter] = None) -> None:
        PassiveKey.__init__(self, baseflt=baseflt)
        SSLKey.__init__(self)

    def getkeys(self, record: Filter) -> Generator[Key, None, None]:
        certtext = self._der2key(record["value"])
        if certtext is None:
            return

        yield Key(
            record["addr"],
            record["port"],
            "ssl",
            certtext["type"],
            int(certtext["len"]),
            _rsa_construct(
                int(certtext["exponent"]),
                int(MODULUS_BADCHARS.sub(b"", certtext["modulus"]), 16),
            ),
            utils.decode_hex(record["infos"]["md5"]),
        )


class SSHKey:
    """Base class for a key lookup tool specialized for the Keys from
    SSH hosts.

    """

    keytype: str
    dbc: DB

    @property
    def fltkey(self) -> Filter:
        return self.dbc.searchsshkey(keytype=self.keytype)


class SSHNmapKey(NmapKey, SSHKey):
    """Base class for the SSH keys within the active (Nmap) DB."""

    scriptid = "ssh-hostkey"

    @staticmethod
    def data2key(data: bytes) -> RSAPublicNumbers:
        raise NotImplementedError

    def __init__(self, baseflt: Filter = None) -> None:
        NmapKey.__init__(self, baseflt=baseflt)
        SSHKey.__init__(self)

    def getkeys(self, record: Record) -> Generator[Key, None, None]:
        for script in self.getscripts(record):
            assert isinstance(script["script"], dict)
            for key in script["script"][self.scriptid]:
                if key["type"][4:] == self.keytype:
                    data = utils.decode_b64(key["key"].encode())
                    # Handle bug (in Nmap?) where data gets encoded
                    # twice.
                    if data[:1] != b"\x00":
                        data = utils.decode_b64(data)
                    yield Key(
                        record["addr"],
                        script["port"],
                        "ssh",
                        key["type"][4:],
                        int(float(key["bits"])),  # for some reason,
                        # Nmap sometimes
                        # outputs 1024.0
                        self.data2key(data),
                        utils.decode_hex(key["fingerprint"]),
                    )


class SSHPassiveKey(PassiveKey, SSHKey):
    """Base class for the keys from SSH certificates within the passive
    DB.

    """

    def __init__(self, baseflt: Filter = None) -> None:
        PassiveKey.__init__(self, baseflt=baseflt)
        SSHKey.__init__(self)

    @staticmethod
    def getkeys(record: Record) -> Generator[Key, None, None]:
        yield Key(
            record["addr"],
            record["port"],
            "ssh",
            record["infos"]["algo"][4:],
            record["infos"]["bits"],
            _rsa_construct(
                int(record["infos"]["exponent"]), int(record["infos"]["modulus"])
            ),
            utils.decode_hex(record["infos"]["md5"]),
        )


class RSAKey:
    """Base class for the RSA Keys."""

    keyincert = re.compile(
        b"\n *Issuer: (?P<issuer>.*)"
        b"\n(?:.*\n)* *Subject: (?P<subject>.*)"
        b"\n(?:.*\n)* *Public Key Algorithm:"
        b" (?P<type>.*)Encryption"
        b"\n *(?:.*)Public-Key: \\((?P<len>[0-9]+) bit\\)"
        b"\n *Modulus:\n(?P<modulus>[\\ 0-9a-f:\n]+)"
        b"\n\\ *Exponent: (?P<exponent>[0-9]+) "
    )
    keytype = "rsa"

    @classmethod
    def _pem2key(cls, pem: AnyStr) -> Optional[Dict[str, bytes]]:
        raise NotImplementedError

    @classmethod
    def pem2key(cls, pem: bytes) -> Optional[RSAPublicNumbers]:
        certtext = cls._pem2key(pem)
        return (
            None
            if certtext is None
            else _rsa_construct(
                int(certtext["exponent"]),
                int(MODULUS_BADCHARS.sub(b"", certtext["modulus"]), 16),
            )
        )

    @staticmethod
    def data2key(data: bytes) -> RSAPublicNumbers:
        data_parsed = utils._parse_ssh_key(data)
        _, exp, mod = (
            next(data_parsed),  # noqa: F841 (_)
            int(utils.encode_hex(next(data_parsed)), 16),
            int(utils.encode_hex(next(data_parsed)), 16),
        )
        return _rsa_construct(exp, mod)


class SSLRsaNmapKey(RSAKey, SSLNmapKey):
    """Tool for the RSA Keys from SSL certificates within the active
    (Nmap) DB.

    """

    def __init__(self, baseflt: Optional[Filter] = None) -> None:
        SSLNmapKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)

    def getkeys(self, record: Record) -> Generator[Key, None, None]:
        for script in self.getscripts(record):
            assert isinstance(script["script"], dict)
            for cert in script["script"].get(self.scriptid, []):
                key = cert["pubkey"]
                yield Key(
                    record["addr"],
                    script["port"],
                    "ssl",
                    key["type"],
                    key["bits"],
                    _rsa_construct(int(key["exponent"]), int(key["modulus"])),
                    utils.decode_hex(cert["md5"]),
                )


class SSHRsaNmapKey(RSAKey, SSHNmapKey):
    """Tool for the RSA Keys from SSH services within the active
    (Nmap) DB.

    """

    def __init__(self, baseflt: Optional[Filter] = None) -> None:
        SSHNmapKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)


class SSLRsaPassiveKey(RSAKey, SSLPassiveKey):
    """Tool for the RSA Keys from SSL certificates within the passive DB."""

    def __init__(self, baseflt: Optional[Filter] = None) -> None:
        SSLPassiveKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)


class SSHRsaPassiveKey(RSAKey, SSHPassiveKey):
    """Tool for the RSA Keys from SSH services within the active
    (Nmap) DB.

    """

    def __init__(self, baseflt: Optional[Filter] = None) -> None:
        SSHPassiveKey.__init__(self, baseflt=baseflt)
        RSAKey.__init__(self)
