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
indexes, ensure indexes after a schema bump, count records,
migrate pre-existing Dokuwiki notes into the DB.

The notes purpose stores entity-keyed markdown annotations (per host,
per domain, per ASN, ...) -- see :class:`ivre.db.DBNotes`.  Lifecycle
is independent of the data purposes: ``view --init``, ``nmap --init``,
``passive --init`` never touch notes.  Use this command to wipe or
maintain the notes-side collections explicitly.
"""

import argparse
import os
import re
import sys

from ivre import utils
from ivre.db import NoteAlreadyExists, NoteBodyTooLarge, db

# Dokuwiki page filenames are ``<page-name>.txt`` under the
# wiki's ``data/pages/`` tree.  The legacy IVRE integration
# (``ivre.web.utils.get_notepad_pages_localdokuwiki``) only
# matched IPv4 pages -- the dotted-decimal filename happens to
# be valid Dokuwiki page-name syntax.  The migration mirrors
# that scope: IPv4 pages only, importing each as a ``host``
# entity-keyed note.  IPv6 pages would have a different
# filename shape (colons are not valid Dokuwiki page-name
# characters) and were never surfaced by the legacy
# integration.
_DOKUWIKI_IPV4_PAGE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\.txt$")


def _import_from_dokuwiki(pagesdir: str) -> int:
    """Walk ``pagesdir`` for Dokuwiki ``<IPv4>.txt`` pages and
    import each as a ``host``-keyed note via
    :meth:`DBNotes.set_note` with ``expected_revision=0`` so a
    re-run of the import is idempotent (already-imported
    addresses skip cleanly via :class:`NoteAlreadyExists`).

    Returns the process exit code:

    * ``0`` on a clean import (any mix of imported / skipped
      pages, ``errors == 0``);
    * ``1`` if the directory does not exist, no
      ``<IPv4>.txt`` pages existed at all, or one or more
      pages failed (so scripted migrations / CI can detect
      partial failures).

    Blank / whitespace-only pages are counted as skipped
    (Dokuwiki leaves them behind after a page delete; they do
    not represent operator-authored content but they are also
    not an error worth flagging).
    """
    if not os.path.isdir(pagesdir):
        utils.LOGGER.error("Dokuwiki pages directory not found: %s", pagesdir)
        return 1
    imported = 0
    skipped = 0
    errors = 0
    # ``os.listdir`` can raise ``OSError`` between the
    # ``isdir`` check above and this call (TOCTOU on the
    # directory itself, permission denied on the contents,
    # transient I/O error on a network mount).  The CLI's
    # contract is to *report* failures via the counters /
    # exit code, not to crash with a stack trace -- so
    # surface a clear log line and return the same non-zero
    # exit code we already use for the missing-directory
    # path.
    try:
        entries = sorted(os.listdir(pagesdir))
    except OSError as exc:
        utils.LOGGER.error(
            "Cannot list Dokuwiki pages directory %s: %s",
            pagesdir,
            exc,
        )
        return 1
    for entry in entries:
        match = _DOKUWIKI_IPV4_PAGE.match(entry)
        if not match:
            continue
        addr = match.group(1)
        path = os.path.join(pagesdir, entry)
        try:
            with open(path, encoding="utf-8") as fdesc:
                body = fdesc.read()
        except OSError as exc:
            utils.LOGGER.warning("Cannot read Dokuwiki page %s: %s", path, exc)
            errors += 1
            continue
        except UnicodeDecodeError as exc:
            # Corrupted page or non-UTF-8 content (legacy
            # Dokuwiki installs sometimes carry Latin-1
            # pages).  Count as an error rather than crashing
            # the whole migration: the operator can re-encode
            # the offending file and re-run.  ``set_note``
            # would reject the bytes anyway -- the storage
            # layer requires valid UTF-8 markdown.
            utils.LOGGER.warning(
                "Cannot decode Dokuwiki page %s as UTF-8: %s",
                path,
                exc,
            )
            errors += 1
            continue
        # Skip empty / whitespace-only pages -- they are
        # placeholders Dokuwiki leaves behind after a page
        # delete and do not represent operator-authored
        # content.  Migrating them as empty notes would just
        # add noise to the new DB.  Count them as ``skipped``
        # so a directory of only-blank pages does not fall
        # through to the "no pages matched" error path
        # (blanks did match, we intentionally chose to skip
        # them).
        if not body.strip():
            skipped += 1
            continue
        try:
            db.notes.set_note(
                "host",
                addr,
                body,
                "dokuwiki-import",
                expected_revision=0,
            )
        except NoteAlreadyExists:
            # Re-run safety: a previous invocation already
            # migrated this page.  Operators get an idempotent
            # CLI without having to track what's been imported.
            skipped += 1
            continue
        except NoteBodyTooLarge as exc:
            utils.LOGGER.warning(
                "Dokuwiki page %s exceeds the body cap "
                "(WEB_HOST_NOTES_MAX_BYTES); skipping: %s",
                path,
                exc,
            )
            errors += 1
            continue
        except ValueError as exc:
            # Most likely a canonicalisation failure on an
            # exotic page name that slipped past the regex (or
            # a deliberately weird IP value).  Skip and report.
            utils.LOGGER.warning("Skipping Dokuwiki page %s: %s", path, exc)
            errors += 1
            continue
        imported += 1
    if not imported and not skipped and not errors:
        utils.LOGGER.error(
            "No Dokuwiki pages matched ``<IPv4>.txt`` under %s",
            pagesdir,
        )
        return 1
    # ``skipped`` lumps "already present" (idempotent re-run
    # path) and "blank placeholder" pages; both are intentional
    # non-imports rather than failures.  Use a neutral label so
    # the counter stays accurate without splitting the bucket
    # into two operator-visible knobs.
    print(
        f"Dokuwiki import: {imported} imported, " f"{skipped} skipped, {errors} errors"
    )
    # Non-zero exit on partial failures so scripted
    # migrations / CI can detect them.  The counters were
    # printed above so the operator still sees what succeeded
    # before the process exits.
    return 1 if errors else 0


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
    parser.add_argument(
        "--import-from-dokuwiki",
        metavar="PAGESDIR",
        nargs="?",
        const="/var/lib/dokuwiki/data/pages",
        help=(
            "Migrate the legacy Dokuwiki-backed notes into the "
            "DBNotes purpose.  Walks ``PAGESDIR`` (defaults to "
            "``/var/lib/dokuwiki/data/pages``) for "
            "``<IPv4>.txt`` pages and imports each as a "
            "``host``-keyed note authored by ``dokuwiki-import``.  "
            "Idempotent: re-running skips pages already imported "
            "via the storage layer's create-only mode."
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

    if args.import_from_dokuwiki is not None:
        sys.exit(_import_from_dokuwiki(args.import_from_dokuwiki))

    parser.print_help()
