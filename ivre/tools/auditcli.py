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


"""Administer the audit-log purpose: query / count / get / purge.

Operator-side counterpart to the :class:`ivre.db.DBAudit` storage
layer and the producer-side hook in :mod:`ivre.web.audit_hook`.
Unlike the web routes and MCP tools (which are per-user / admin
gated), this CLI runs locally against the configured backend with
operator privilege -- the assumption being that anyone with shell
access to the IVRE host can already inspect the raw audit
collection.

Subcommands:

* ``--query``  -- list events matching ``--event-type`` /
  ``--user-email`` / ``--since`` / ``--until``; supports
  ``--limit`` and ``--skip`` for pagination.
* ``--count``  -- count events matching the same filter.
* ``--get EVENT_ID`` -- fetch one event by id (any UUID textual
  form :class:`uuid.UUID` accepts).
* ``--purge-older-than DURATION`` -- delete every event whose
  ``created_at`` is older than the given cutoff (e.g. ``30d``,
  ``180d``, ``2y``).
* ``--init`` / ``--ensure-indexes`` -- collection / index
  lifecycle, mirroring :mod:`ivre.tools.notes`.

Output is JSON: a single event for ``--get``, a JSON array for
``--query``, a bare integer for ``--count`` and
``--purge-older-than``.
"""

import argparse
import datetime
import json
import os
import re
import sys

from ivre import utils
from ivre.db import db

# Duration shorthand for ``--purge-older-than`` and ``--since`` /
# ``--until``: ``Ns`` / ``Nm`` / ``Nh`` / ``Nd`` / ``Ny``.  Mirrors
# the ``timeago:`` syntax already supported by the web query
# parser (``ivre/web/utils.py:643-657``); aligned so an operator
# who knows one knows the other.
_DURATION_UNITS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "y": 31_557_600,
}

_DURATION_RE = re.compile(r"^(\d+)([smhdy])$")


def _parse_duration(raw: str) -> datetime.timedelta:
    """Translate ``"30d"`` / ``"180d"`` / ``"2y"`` (or a bare
    integer count of seconds) into a :class:`timedelta`.

    Raises :class:`SystemExit` (via :func:`sys.exit`) on a
    malformed value, so an operator typo surfaces as a clean
    CLI error rather than a stack trace.
    """
    match = _DURATION_RE.match(raw)
    if match is None:
        try:
            return datetime.timedelta(seconds=int(raw))
        except (TypeError, ValueError):
            sys.exit(
                f"Error: invalid duration {raw!r} "
                "(expected ``Ns`` / ``Nm`` / ``Nh`` / ``Nd`` / ``Ny`` "
                "or a bare integer count of seconds)"
            )
    return datetime.timedelta(
        seconds=int(match.group(1)) * _DURATION_UNITS[match.group(2)]
    )


def _parse_datetime(raw: str | None) -> datetime.datetime | None:
    """Translate ``--since`` / ``--until`` arguments.

    Accepted forms:

    * ``None`` / empty -- returns ``None`` (no bound).
    * ``"30d"`` / ``"2h"`` / ... -- duration shorthand;
      interpreted as "this many seconds ago" relative to
      :func:`datetime.datetime.now` in UTC.
    * Unix timestamp (``"1716595200"``).
    * ISO 8601 (``"2026-05-25T00:00:00Z"``, ``"2026-05-25"``).

    Naive ISO strings are interpreted as UTC.
    """
    if not raw:
        return None
    match = _DURATION_RE.match(raw)
    if match is not None:
        delta = _parse_duration(raw)
        return datetime.datetime.now(tz=datetime.timezone.utc) - delta
    try:
        return datetime.datetime.fromtimestamp(float(raw), tz=datetime.timezone.utc)
    except (TypeError, ValueError):
        # Not numeric -- fall through to the ISO branch.  Range
        # errors (``OverflowError`` / ``OSError``) mean it *was*
        # numeric but the platform can't represent it; surface
        # those as a clean CLI error rather than falling into
        # the ISO parser (which would also fail, with a less
        # useful message).
        pass
    except (OverflowError, OSError) as exc:
        sys.exit(f"Error: invalid datetime {raw!r}: {exc}")
    try:
        parsed = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        sys.exit(f"Error: invalid datetime {raw!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--init",
        action="store_true",
        help=(
            "Drop the audit_events collection and recreate its "
            "indexes.  Destroys every recorded event."
        ),
    )
    action.add_argument(
        "--ensure-indexes",
        action="store_true",
        help=(
            "Create any missing indexes on the audit collection "
            "without dropping data.  Idempotent."
        ),
    )
    action.add_argument(
        "--query",
        action="store_true",
        help="List events matching the filter (default action).",
    )
    action.add_argument(
        "--count",
        action="store_true",
        help="Print the count of events matching the filter.",
    )
    action.add_argument(
        "--get",
        metavar="EVENT_ID",
        help=(
            "Fetch one event by id (any UUID textual form). "
            "Prints the JSON event, or ``null`` when no event "
            "matches."
        ),
    )
    action.add_argument(
        "--purge-older-than",
        metavar="DURATION",
        help=(
            "Delete every event older than the given cutoff "
            "(e.g. ``30d``, ``180d``, ``2y``, or a bare integer "
            "count of seconds).  Prints the number of rows "
            "deleted."
        ),
    )
    parser.add_argument(
        "--event-type",
        choices=("upload", "admin_action", "oversize_query"),
        help="Narrow --query / --count to one event type.",
    )
    parser.add_argument(
        "--user-email",
        help="Narrow --query / --count to one user's events.",
    )
    parser.add_argument(
        "--since",
        metavar="WHEN",
        help=(
            "Lower bound on ``created_at`` (inclusive).  "
            "Accepts ``Nd`` / ``Nh`` shorthand, a Unix "
            "timestamp, or an ISO 8601 datetime."
        ),
    )
    parser.add_argument(
        "--until",
        metavar="WHEN",
        help="Upper bound on ``created_at`` (exclusive); same format as --since.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Cap on --query output (default: 100).",
    )
    parser.add_argument(
        "--skip",
        type=int,
        default=0,
        help="Pagination offset for --query (default: 0).",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=None,
        help="Pretty-print JSON output with this indent width.",
    )
    args = parser.parse_args()

    if db.audit is None:
        sys.exit(
            "Error: Audit backend not available. Set DB_AUDIT (or "
            "DB) to a backend with audit support (MongoDB, "
            "PostgreSQL, or DuckDB) to enable it."
        )

    if args.init:
        # Confirmation prompt matches ``ivre notes --init`` /
        # ``ivre scancli --init``: an interactive operator gets
        # a guard rail, scripted callers can pipe ``/dev/null``
        # to stdin.
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                "This will remove every audit event in your database. "
                "Process ? [y/N] "
            )
            if input().lower() != "y":
                sys.exit(-1)
        db.audit.init()
        sys.exit(0)

    if args.ensure_indexes:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write("This will lock your database. Process ? [y/N] ")
            if input().lower() != "y":
                sys.exit(-1)
        db.audit.ensure_indexes()
        sys.exit(0)

    if args.purge_older_than is not None:
        delta = _parse_duration(args.purge_older_than)
        cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - delta
        deleted = db.audit.purge_older_than(cutoff)
        print(deleted)
        sys.exit(0)

    if args.get is not None:
        # ``_normalize_event_id`` raises ``ValueError`` on a
        # malformed UUID textual form; surface that as a clean
        # CLI error rather than a stack trace.  Mirrors how the
        # ``--purge-older-than`` / ``--since`` / ``--until``
        # parsers handle bad operator input.
        try:
            events = db.audit.query(event_id=args.get, limit=1)
        except ValueError as exc:
            sys.exit(f"Error: {exc}")
        if not events:
            print("null")
        else:
            print(json.dumps(events[0], default=utils.serialize, indent=args.indent))
        sys.exit(0)

    filters: dict[str, object] = {
        "event_type": args.event_type,
        "user_email": args.user_email,
        "since": _parse_datetime(args.since),
        "until": _parse_datetime(args.until),
    }

    if args.count:
        print(db.audit.count(**filters))
        sys.exit(0)

    # Default action: --query (also reached when the operator
    # passes no action flag at all).
    events = db.audit.query(limit=args.limit, skip=args.skip, **filters)
    print(json.dumps(events, default=utils.serialize, indent=args.indent))
