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

"""This sub-module contains functions to interact with SQLite
databases.

"""


# Tests like "expr == None" should be used for BinaryExpression instances
# pylint: disable=singleton-comparison


from sqlalchemy import Index, and_, func, insert, update
from sqlalchemy.exc import IntegrityError

from ivre import utils, config
from ivre.db.sql import SQLDB, SQLDBPassive


class SqliteDB(SQLDB):
    def __init__(self, url):
        super().__init__(url)
        # url.geturl() removes two necessary '/' from url
        self.dburl = "%s://%s" % (url.scheme, url.path)

    def explain(self, req, **_):
        raise Exception("Explain is not yet implemented for sqlite.")


class SqliteDBPassive(SqliteDB, SQLDBPassive):
    def __init__(self, url):
        super().__init__(url)
        Index(
            "ix_passive_record",
            self.tables.passive.addr,
            self.tables.passive.sensor,
            self.tables.passive.recontype,
            self.tables.passive.port,
            self.tables.passive.source,
            self.tables.passive.value,
            self.tables.passive.targetval,
            self.tables.passive.info,
            unique=True,
            sqlite_where=self.tables.passive.addr != None,  # noqa: E711
        )
        Index(
            "ix_passive_record_noaddr",
            self.tables.passive.sensor,
            self.tables.passive.recontype,
            self.tables.passive.port,
            self.tables.passive.source,
            self.tables.passive.value,
            self.tables.passive.targetval,
            self.tables.passive.info,
            unique=True,
            sqlite_where=self.tables.passive.addr == None,  # noqa: E711
        )

    def _insert_or_update(self, timestamp, values, lastseen=None, replacecount=False):
        stmt = insert(self.tables.passive).values(
            dict(values, addr=utils.force_int2ip(values["addr"]))
        )
        try:
            self.db.execute(stmt)
        except IntegrityError:
            whereclause = and_(
                self.tables.passive.addr == values["addr"],
                self.tables.passive.sensor == values["sensor"],
                self.tables.passive.recontype == values["recontype"],
                self.tables.passive.source == values["source"],
                self.tables.passive.value == values["value"],
                self.tables.passive.targetval == values["targetval"],
                self.tables.passive.info == values["info"],
                self.tables.passive.port == values["port"],
            )
            upsert = {
                "firstseen": func.least(
                    self.tables.passive.firstseen,
                    timestamp,
                ),
                "lastseen": func.greatest(
                    self.tables.passive.lastseen,
                    lastseen or timestamp,
                ),
                "count": (
                    values["count"]
                    if replacecount
                    else self.tables.passive.count + values["count"]
                ),
            }
            updt = update(self.tables.passive).where(whereclause).values(upsert)
            self.db.execute(updt)

    def update_dns_blacklist(self):
        """A specific implementation is required for SQLite because
        it is not possible to read and write the database at the same time."""

        flt = self.searchdns(list(config.DNS_BLACKLIST_DOMAINS), subdomains=True)
        base = self.get(flt)
        specs = []
        for old_spec in base:
            if any(
                old_spec["value"].endswith(dnsbl)
                for dnsbl in config.DNS_BLACKLIST_DOMAINS
            ):
                spec = self._update_dns_blacklist(old_spec)
                specs.append(
                    [spec, old_spec["firstseen"], old_spec["lastseen"], old_spec["_id"]]
                )
        for elmt in specs:
            self.insert_or_update(elmt[1], elmt[0], lastseen=elmt[2])
            self.remove(elmt[3])
