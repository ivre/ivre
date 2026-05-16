#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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


"""Administer the per-entity notes purpose: initialise collections /
indexes, ensure indexes after a schema bump, count records.

The notes purpose stores entity-keyed markdown annotations (per host,
per domain, per ASN, ...) -- see :class:`ivre.db.DBNotes`.  Lifecycle
is independent of the data purposes: ``view --init``, ``nmap --init``,
``passive --init`` never touch notes.  Use this command to wipe or
maintain the notes-side collections explicitly.
"""

import argparse
import os
import sys

from ivre.db import db


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Administer the per-entity notes database.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help=(
            "Drop the notes and note_revisions collections and "
            "recreate their indexes.  Destroys every recorded "
            "annotation."
        ),
    )
    parser.add_argument(
        "--ensure-indexes",
        action="store_true",
        help=(
            "Create any missing indexes on the notes collections "
            "without dropping data.  Idempotent."
        ),
    )
    parser.add_argument(
        "--count",
        action="store_true",
        help="Print the number of notes (optionally narrowed by --entity-type).",
    )
    parser.add_argument(
        "--entity-type",
        metavar="TYPE",
        help=(
            "Restrict --count to one entity type (e.g. ``host``).  "
            "When omitted, --count returns the total across every type."
        ),
    )
    args = parser.parse_args()

    # Bail out early when no notes backend is wired so we
    # surface a friendly message instead of an
    # ``AttributeError: 'NoneType'...`` from the first
    # ``db.notes.<method>()`` call below.  ``MetaDB.notes``
    # returns ``None`` when ``DBNotes.backends`` has no entry
    # for the configured URL's scheme -- at v1 only
    # ``mongodb://`` is registered (see
    # :class:`ivre.db.DBNotes`).  Mirrors the
    # ``db.auth is None`` check in :mod:`ivre.tools.authcli`.
    if db.notes is None:
        sys.exit(
            "Error: Notes backend not available. The notes purpose "
            "is implemented on MongoDB only at v1; set DB_NOTES (or "
            "DB) to a mongodb:// URL to enable it."
        )

    if args.init:
        # Mirror :func:`ivre.tools.scancli.main`'s confirmation
        # prompt so an interactive operator does not wipe the
        # collection by mistake.  Non-interactive callers (CI,
        # scripts) pipe ``/dev/null`` to stdin to skip the prompt.
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                "This will remove every note in your database. Process ? [y/N] "
            )
            ans = input()
            if ans.lower() != "y":
                sys.exit(-1)
        db.notes.init()
        sys.exit(0)

    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write("This will lock your database. Process ? [y/N] ")
            ans = input()
            if ans.lower() != "y":
                sys.exit(-1)
        db.notes.ensure_indexes()
        sys.exit(0)

    if args.count:
        print(db.notes.count_notes(entity_type=args.entity_type))
        sys.exit(0)

    parser.print_help()
