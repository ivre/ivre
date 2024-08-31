#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2022 Pierre LALET <pierre@droids-corp.org>
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

"""This sub-module contains functions to interact with the Amazon
DocumentDB databases.

"""


from ivre.db.mongo import (
    MongoDBActive,
    MongoDBAgent,
    MongoDBFlow,
    MongoDBNmap,
    MongoDBPassive,
    MongoDBView,
)


class DocumentDBNmap(MongoDBNmap):
    is_documentdb = True


class DocumentDBView(MongoDBView):
    is_documentdb = True
    # DocumentDB has no support for text indexes
    indexes = MongoDBActive.indexes
    schema_migrations_indexes = MongoDBActive.schema_migrations_indexes


class DocumentDBPassive(MongoDBPassive):
    is_documentdb = True


class DocumentDBAgent(MongoDBAgent):
    pass


class DocumentDBFlow(MongoDBFlow):
    pass
