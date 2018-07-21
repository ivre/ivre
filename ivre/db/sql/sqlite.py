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

"""This sub-module contains functions to interact with SQLite
databases.

"""


from sqlalchemy import func, insert, update, and_
from sqlalchemy.exc import IntegrityError

from ivre import utils
from ivre.db.sql import SQLDB, SQLDBPassive


class SqliteDB(SQLDB):

    def __init__(self, url):
        SQLDB.__init__(self, url)

    @classmethod
    def convert_ip(cls, addr):
        return utils.force_ip2int(addr)


class SqliteDBPassive(SqliteDB, SQLDBPassive):

    def __init__(self, url):
        SqliteDB.__init__(self, url)
        SQLDBPassive.__init__(self, url)

    def _insert_or_update(self, timestamp, vals, lastseen=None):
        stmt = insert(self.tables.passive)\
            .values(dict(vals, addr=utils.force_int2ip(vals['addr'])))
        try:
            self.db.execute(stmt)
        except IntegrityError:
            whereclause = and_(
                self.tables.passive.addr == vals['addr'],
                self.tables.passive.sensor == vals['sensor'],
                self.tables.passive.recontype == vals['recontype'],
                self.tables.passive.source == vals['source'],
                self.tables.passive.value == vals['value'],
                self.tables.passive.targetval == vals['targetval'],
                self.tables.passive.info == vals['info'],
                self.tables.passive.port == vals['port']
            )
            upsert = {
                'firstseen': func.least(
                    self.tables.passive.firstseen,
                    timestamp,
                ),
                'lastseen': func.greatest(
                    self.tables.passive.lastseen,
                    lastseen or timestamp,
                ),
                'count': self.tables.passive.count + vals['count'],
            }
            updt = update(
                self.tables.passive
            ).where(whereclause).values(upsert)
            self.db.execute(updt)
