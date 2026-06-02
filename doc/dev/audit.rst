Audit log
#########

IVRE keeps an **append-only audit log** of the security-relevant
actions performed through its web layer: data uploads, admin
actions, and queries large enough to be truncated. It is a
security control first and a debugging aid second -- the storage
layer is *fail-loud*, so an event that cannot be written aborts
the request rather than silently dropping the record.

The audit purpose (``db.audit``, :class:`ivre.db.DBAudit`) is
independent from the data purposes (``nmap`` / ``view`` /
``passive`` / ``flow``): it can point at a different,
write-restricted backend, and a deployment that does not opt into
it simply has ``db.audit is None`` with no events recorded.

Configuration
=============

The backend is selected by the ``DB_AUDIT`` option in
``ivre.conf``. When left unset it defaults to the value of
``DB``, so operators get a working ``db.audit`` out of the box::

    # Same store as everything else (the default): leave
    # DB_AUDIT unset and it follows DB.

    # Or send the audit stream to a dedicated, write-restricted
    # store (typical for compliance setups):
    DB_AUDIT = "postgresql://ivre:ivre@db.example/ivre_audit"

The audit purpose is supported on MongoDB, PostgreSQL and DuckDB.
Provision (or re-provision) its collection / table and indexes
with::

    $ ivre auditcli --init            # drop + recreate (destroys events)
    $ ivre auditcli --ensure-indexes  # create missing indexes, keep data

``--ensure-indexes`` is idempotent and never drops rows; run it
after upgrading IVRE on an existing deployment.

Event types
===========

Three categories are recorded (the closed set in
:attr:`ivre.db.DBAudit.EVENT_TYPES`):

``upload``
    A successful write against ``POST /cgi/scans``,
    ``POST /cgi/view``, ``POST /cgi/flows`` or
    ``POST /cgi/flows/cleanup`` -- data ingested through the web
    API, plus the flows-cleanup maintenance write.

``admin_action``
    A mutating request under ``/cgi/auth/admin/*`` (creating or
    updating a user, revoking another user's API key, ...).

``oversize_query``
    A record-listing request whose underlying result count
    exceeded ``WEB_MAXRESULTS``. The event is recorded before the
    truncated response is streamed, so the trail captures queries
    that saw only part of the matching set.

Each event carries the actor (user e-mail, API-key hash and
remote address, any of which may be empty for anonymous traffic),
the targeted resource (route and method), an outcome (typically
the HTTP status), a free-form ``details`` object whose shape
depends on the event type, and a UTC ``created_at`` timestamp.

Events are produced automatically by the per-route hook in
:mod:`ivre.web.audit_hook`; application code does not call the
storage layer directly.

Reading the log
===============

Command line
------------

``ivre auditcli`` is the operator-side reader. It runs locally
against the configured backend with full privilege -- the
assumption being that shell access to the IVRE host already
grants access to the raw collection -- so it applies **no**
per-user gating, unlike the web API below.

Actions (mutually exclusive; ``--query`` is the default):

``--query``
    List matching events as a JSON array, newest first.
    ``--limit`` (default 100) and ``--skip`` paginate.

``--count``
    Print the number of matching events.

``--get EVENT_ID``
    Fetch a single event by id (any textual UUID form), or
    ``null`` when none matches.

``--purge-older-than DURATION``
    Delete every event older than the cutoff and print the number
    removed (see :ref:`dev/audit:Retention`).

``--init`` / ``--ensure-indexes``
    Collection / index lifecycle (see
    :ref:`dev/audit:Configuration`).

Filters (apply to ``--query`` and ``--count``):

``--event-type {upload,admin_action,oversize_query}``
    Narrow to one category.

``--user-email EMAIL``
    Narrow to one user's events.

``--since WHEN`` / ``--until WHEN``
    Bound ``created_at``. ``WHEN`` accepts duration shorthand
    relative to now (``30d``, ``2h``, ``90m``, ...), a Unix
    timestamp, or an ISO-8601 datetime (naive values are read as
    UTC). ``--since`` is inclusive, ``--until`` exclusive.

The duration shorthand matches the ``timeago:`` syntax of the web
query parser, so the same expression works on both sides.

Examples::

    # Everything alice did in the last week:
    $ ivre auditcli --user-email alice@example.org --since 7d

    # How many oversize queries in the last 30 days:
    $ ivre auditcli --count --event-type oversize_query --since 30d

    # One event, pretty-printed:
    $ ivre auditcli --get 3f1e8c1a... --indent 2

Web API
-------

The same events are exposed read-only under ``/cgi/audit/*``.
These routes are **admin-or-self** gated: an authenticated user
reads their own trail, an admin reads everyone's, and an
anonymous caller gets ``401``. A non-admin who asks for another
user's events with ``user_email=`` gets ``403``. When no audit
backend is configured the routes return ``501``.

The full request / response reference (query parameters, status
codes, response shapes) is generated from the route docstrings on
the :ref:`dev/web-api:Web API` page; see the *List audit events*,
*Count audit events* and *Read a single audit event* endpoints.
Authentication uses the standard web-layer session / API-key flow
(see :ref:`usage/web-auth:Web Authentication`).

No MCP surface
==============

The audit log is deliberately **not** exposed through the
``ivre mcp-server``. It is a security control, and giving an
LLM-driven agent a read path into the log would broaden the
attack surface of the log itself (and risk leaking one user's
actions to another through a tool the gate does not cover).
Programmatic consumers use ``ivre auditcli`` or the
``/cgi/audit/*`` routes, both of which apply the appropriate
trust boundary.

Retention
=========

Retention is **operator-driven**. IVRE ships **no** automatic
expiry: there is no TTL index and no ``WEB_AUDIT_TTL_SECONDS`` (or
equivalent) configuration knob. An audit log that silently sheds
its oldest entries is a poor security control -- the deletion
policy should be an explicit, auditable operator decision, not a
hidden default.

The single retention verb is::

    $ ivre auditcli --purge-older-than 180d

which deletes every event whose ``created_at`` is older than the
cutoff and prints the number removed. ``DURATION`` accepts the
same shorthand as ``--since`` (``180d``, ``2y``, or a bare
integer count of seconds).

Operators who want periodic pruning schedule this command
themselves -- for example a daily ``cron`` entry or a ``systemd``
timer::

    # /etc/cron.d/ivre-audit-retention
    17 3 * * *  ivre  ivre auditcli --purge-older-than 365d

Pointing ``DB_AUDIT`` at a dedicated, write-restricted store (for
example a PostgreSQL instance with append-only controls) composes
with this: the application only ever appends and runs the explicit
purge, while the database enforces the WORM-style guarantees a
compliance regime may require.
