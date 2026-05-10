#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
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

"""IVRE backend for AWS DocumentDB.

DocumentDB speaks the MongoDB wire protocol but its query
engine is a re-implementation that lacks a small set of
operators IVRE relies on elsewhere; the four classes in this
module subclass the regular ``MongoDB*`` backends and set
``is_documentdb = True`` so the matching workarounds in
``ivre.db.mongo`` activate.

Selected by a ``DB = "documentdb://...`` URL in
``ivre.conf``; the connection-string options are otherwise
identical to the ``mongodb://`` scheme.

Supported / unsupported surface
-------------------------------

* **Supported (everything else).** Every IVRE query path that
  is not explicitly listed below works the same way it does on
  upstream MongoDB. That includes regex matches (``$regex``),
  conjunction / disjunction / negation
  (``$and`` / ``$or`` / ``$nor``, ``$ne`` / ``$nin`` /
  ``$not``), ``$elemMatch``, the aggregation pipeline used by
  ``topvalues`` (with the ``$floor`` workaround applied
  automatically — see below), and the geospatial operators
  used by the world-map widget.

* **Not supported: full-text search.** DocumentDB has neither
  a text-index facility nor a ``$text`` operator, so
  ``MongoDBView.searchtext`` (the backend behind
  ``ivre view --search`` and the ``/cgi/view?q=text:...``
  filter) cannot run. ``DocumentDBView`` therefore inherits
  ``MongoDBActive.indexes`` (which contain no text index)
  rather than ``MongoDBView.indexes`` (which does), and the
  test suite skips the corresponding assertions when the
  ``IVRE_BACKEND_FLAVOR=documentdb`` environment variable is
  set. Callers that need free-text search on DocumentDB
  deployments should pre-filter via the structured fields
  exposed by the regular search helpers (host, port,
  service, product, hostname, domain, ...).

* **Worked around: missing aggregation operators.** The
  ``$floor`` aggregation operator is not available on
  DocumentDB; ``MongoDBActive.topvalues`` and
  ``MongoDBPassive.topvalues`` substitute a
  ``$subtract / $divide / $mod`` equivalent when
  ``self.is_documentdb`` is true.

* **Worked around: cursor-timeout semantics.** DocumentDB
  does not honour ``no_cursor_timeout=True`` on long-running
  cursors the way MongoDB does; the schema-migration cursor
  in ``ivre.db.mongo.MongoDB`` flips the flag based on
  ``is_documentdb``.

CI coverage
-----------

The ``documentdb.yml`` workflow exercises every code path
gated on ``is_documentdb`` by running the regular test suite
with ``DB_*`` configured to ``documentdb://...`` URLs against
**MongoDB 5.0** — the API level AWS DocumentDB currently
claims compatibility with. Pinning to 5.0 (rather than the
newest 7.0/8.0 used by the upstream ``mongodb`` workflow)
catches accidental use of post-5.0 operators that would fail
on a real DocumentDB instance even though they work on
upstream MongoDB. Beyond that, the workflow catches
regressions in the IVRE-side workarounds (a deleted
``is_documentdb`` branch, a typo in the substituted
expression, a missing ``is_documentdb`` flag on a new
subclass).

It does **not** prove that an operator IVRE assumes to be
available on AWS DocumentDB actually is — vanilla MongoDB 5.0
still implements a superset of AWS DocumentDB's surface (every
operator AWS chose to leave out of their reimplementation is
still present here). Closing that gap fully would require a
real AWS DocumentDB cluster in CI, which is **not currently
planned** (no free tier, no sponsor); see E4.11 in the
roadmap. A separate workflow targeting Microsoft's
open-source DocumentDB project (a PostgreSQL-based MongoDB-
compatible engine that powers Azure Cosmos DB's MongoDB API,
unrelated to AWS DocumentDB despite the name collision) is
tracked alongside as another supported deployment target for
operators running IVRE on cloud-native infrastructure.
"""

from ivre.db.mongo import (
    MongoDBActive,
    MongoDBFlow,
    MongoDBNmap,
    MongoDBPassive,
    MongoDBRir,
    MongoDBView,
)


class DocumentDBNmap(MongoDBNmap):
    is_documentdb = True


class DocumentDBView(MongoDBView):
    is_documentdb = True
    # DocumentDB has no support for text indexes (no ``"text"``
    # index type, no ``$text`` operator). Inherit the
    # ``MongoDBActive`` index list, which omits the text index
    # the ``MongoDBView`` set adds.
    indexes = MongoDBActive.indexes
    schema_migrations_indexes = MongoDBActive.schema_migrations_indexes


class DocumentDBPassive(MongoDBPassive):
    is_documentdb = True


class DocumentDBFlow(MongoDBFlow):
    is_documentdb = True


class DocumentDBRir(MongoDBRir):
    is_documentdb = True
    # Drop the trailing ``"text"`` index entry from
    # :data:`MongoDBRir.indexes` (the GIN-equivalent index over
    # ``netname`` / ``descr`` / ``remarks`` / ``notify`` /
    # ``org``); DocumentDB rejects text indexes wholesale.
    # Every other index (range lookup, ``aut-num``, country,
    # source, schema version, size) is a regular B-tree and
    # works unchanged.  ``searchXXX`` helpers on
    # :class:`MongoDBRir` do not call ``$text`` so the
    # text-index removal is the only adjustment needed for
    # parity.
    indexes = [MongoDBRir.indexes[0][:-1]]
