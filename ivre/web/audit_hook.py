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


"""Producer-side glue for the :mod:`ivre.db.DBAudit` purpose.

The storage layer (committed in PR #1885) defines what an audit
event *is* and how it is persisted; this module is the per-route
hook that actually populates the log from live HTTP traffic.

The event categories are wired here (matching
:attr:`ivre.db.DBAudit.EVENT_TYPES`):

* ``upload`` -- the :func:`audit_event` decorator stamps an event
  on every successful write against ``POST /scans``,
  ``POST /view``, ``POST /flows`` and ``POST /flows/cleanup``.
* ``admin_action`` -- the same decorator wraps every mutating
  route under ``/cgi/auth/admin/*``.
* ``oversize_query`` -- :func:`record_oversize_query` is called
  at the top of every record-listing route once the filter has
  been built; when the underlying ``count()`` exceeds
  ``config.WEB_MAXRESULTS`` (and the operator has set that knob)
  an audit event is recorded before the truncated response is
  streamed.
* ``auth`` -- :func:`record_auth` records interactive login
  successes and failures (OAuth and magic-link). The
  :func:`audit_auth` decorator on the login routes captures the
  failure paths; the success event is recorded by the auth funnel
  itself (it alone knows the authenticated e-mail). Only the
  method, provider, e-mail, remote address and outcome are
  stored -- never a credential (OAuth code / token, magic-link
  token).

Failure model: fail-loud on storage failure (the audit log is a
security control, an unrecorded event is worse than a failed
request -- see :class:`ivre.db.AuditWriteError`).  However, when
no audit backend is configured (``db.audit is None``, e.g. on a
read-only HTTP backend or an Elastic-only deployment) the hook
silently skips: an operator who has not opted into auditing
should not get HTTP 500s on every write.
"""

import hashlib
from functools import wraps
from typing import Any, Callable

from bottle import HTTPResponse, request, response

from ivre import config, utils
from ivre.db import db
from ivre.web.base import extract_api_key

# Request-environ key set by the auth routes once they have recorded
# their own ``auth`` event (success, or an in-funnel failure that
# knows the e-mail), so :func:`audit_auth` does not record a second,
# e-mail-less event for the same request.
_AUTH_RECORDED_ENVIRON_KEY = "ivre.audit.auth_recorded"

# Cap on the stored ``auth`` failure ``reason``. Failure reasons are
# derived from abort messages, one of which (``OAuth error: <error>``)
# folds in a provider-/query-supplied string: bound it so a long or
# junk value cannot bloat the audit store.
_REASON_MAX_LEN = 200


def _capture_actor() -> dict[str, Any]:
    """Build the ``actor`` sub-dict for the current Bottle request.

    Three fields, all nullable (see
    :class:`ivre.db.sql.tables.AuditEvent` for the storage shape):

    * ``user_email`` -- resolved via :func:`ivre.web.utils.get_user`,
      imported lazily inside the function body to avoid an
      import-time cycle (``web.utils`` itself imports from
      ``web.base``, which this module also depends on, so a
      module-level ``from ivre.web import utils`` here would
      reorder the import graph on first load).  ``None`` for
      anonymous / unauthenticated callers.
    * ``api_key_hash`` -- SHA-256 hex of the raw API key when one
      was presented (same digest the auth backend stores in
      ``auth_api_key.key_hash``); ``None`` for cookie /
      ``REMOTE_USER`` traffic.  Storing the hash rather than the
      raw key avoids putting credential material in the audit
      trail while still allowing forensic correlation against
      the auth backend's key registry.
    * ``remote_addr`` -- ``request.remote_addr`` verbatim; no
      normalisation (the rate-limit ledger groups IPv6 by /48
      for evasion resistance, but the audit log records the
      caller's actual peer address for forensics).
    """
    # Local import to avoid the import-time cycle between
    # ``ivre.web.utils`` and ``ivre.web.base`` -- ``utils`` is
    # importable from a Bottle request context but pulling it at
    # module load would order this module before ``utils`` has
    # finished defining ``get_user``.
    from ivre.web import utils as webutils  # pylint: disable=import-outside-toplevel

    api_key = extract_api_key()
    api_key_hash = (
        hashlib.sha256(api_key.encode()).hexdigest() if api_key is not None else None
    )
    return {
        "user_email": webutils.get_user(),
        "api_key_hash": api_key_hash,
        "remote_addr": request.remote_addr,
    }


def _capture_resource() -> dict[str, Any]:
    """Build the ``resource`` sub-dict for the current request.

    ``route`` is the Bottle route template (``/scans``,
    ``/auth/admin/users/<email:path>``) -- the path *template*,
    not the request URI, so per-call URL parameters do not bloat
    the audit log's cardinality (every ``DELETE
    /auth/admin/api-keys/<key_hash>`` aggregates under a single
    bucket regardless of the per-call hash).  ``method`` is the
    HTTP verb in upper case.  Both are forensically useful and
    bounded in size, so they live in the indexable
    ``resource.*`` sub-document rather than the free-form
    ``details`` dict.
    """
    route_rule = None
    route = request.route
    if route is not None:
        route_rule = getattr(route, "rule", None)
    return {
        "route": route_rule,
        "method": request.method,
    }


def _response_status_code() -> int | None:
    """Return the current Bottle response's numeric status code.

    Bottle stores ``response.status`` as either ``"200 OK"``
    (string) or just the integer; the property
    ``response.status_code`` normalises this to an ``int``.  The
    code is captured *after* the wrapped handler has returned
    but *before* Bottle has finished serialising the response,
    so it reflects whatever the handler set via
    ``response.status = ...`` (defaults to 200 when the handler
    returns normally).
    """
    try:
        code = response.status_code
    except AttributeError:
        return None
    if isinstance(code, int):
        return code
    try:
        return int(str(code).split(" ", 1)[0])
    except (TypeError, ValueError):
        return None


def _record(event_type: str, *, details: dict[str, Any], outcome: int | None) -> None:
    """Persist one audit event, swallowing the no-backend case.

    The :class:`ivre.db.AuditWriteError` raised by the storage
    layer on a real backend failure is *not* caught here: per
    the ABC's fail-loud contract, an unrecorded audit event must
    propagate to the Bottle error handler (HTTP 500) rather than
    be silently lost.  The only swallowed condition is
    ``db.audit is None`` (no audit backend configured), where
    the operator has explicitly opted out and the route must
    still serve traffic.
    """
    if db.audit is None:
        return
    db.audit.record(
        event_type,
        actor=_capture_actor(),
        resource=_capture_resource(),
        details=details,
        outcome=outcome,
    )


def audit_event(
    event_type: str,
    *,
    capture_details: (
        Callable[[tuple[Any, ...], dict[str, Any], Any], dict[str, Any]] | None
    ) = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: record an audit event after the wrapped Bottle
    handler returns.

    ``event_type`` must be a member of
    :attr:`ivre.db.DBAudit.EVENT_TYPES` (the storage layer
    validates this at insert time; we do not pre-check here so a
    typo surfaces uniformly across every persisted event rather
    than at decoration time only for the first invocation).

    ``capture_details`` is an optional callable that receives
    three positional arguments -- ``(args, kwargs, result)``
    where ``args`` / ``kwargs`` are the wrapped handler's call
    arguments (Bottle URL-bound parameters arrive there) and
    ``result`` is its return value -- and returns a JSON-
    serializable dict.  Use it to enrich the audit event with
    route-specific payload (e.g. the ``count`` returned by an
    upload, or the ``source`` / ``categories`` read off
    ``request.forms``).  Must return a ``dict`` (the storage
    layer rejects anything else with :class:`ValueError`);
    returning ``{}`` is fine.  Callbacks that do not need a
    particular argument should take it as ``_args`` /
    ``_kwargs`` / ``_result`` and ignore it.

    The decorator stacks *inside* :func:`ivre.web.base.check_referer`
    / :func:`check_upload_ok` / :func:`quota_gated` (the existing
    write-route guards): we only want to record events for
    requests that passed the gates, otherwise the audit log
    fills with rejected-attempt noise that belongs in the
    request log instead.  Concretely::

        @application.post("/<subdb:re:scans|view>")
        @check_referer
        @check_upload_ok
        @quota_gated
        @audit_event("upload", capture_details=...)
        def post_nmap(subdb): ...

    A handler exception is *not* caught -- the audit event only
    fires on the success path.  Failed writes are visible
    through Bottle's error handler / access log; recording an
    "upload that did not happen" would be misleading.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def _newfunc(*args: Any, **kwargs: Any) -> Any:
            result = func(*args, **kwargs)
            try:
                details: Any = (
                    capture_details(args, kwargs, result)
                    if capture_details is not None
                    else {}
                )
            except Exception:
                # A buggy ``capture_details`` callable must not
                # take down the request; log loudly and record
                # the event with an empty ``details`` so the
                # event itself is not lost.  The reverse
                # ("propagate the bug") would let a typo in a
                # one-line lambda break every audited write
                # route.
                utils.LOGGER.error(
                    "audit capture_details callable raised on %s",
                    event_type,
                    exc_info=True,
                )
                details = {}
            if not isinstance(details, dict):
                # Same fail-soft rationale as the ``except`` above:
                # a callback that returns the wrong shape (e.g. a
                # string or ``None``) would otherwise trip the
                # ABC's ``_validate_details`` check inside
                # ``db.audit.record`` and ``AuditWriteError`` /
                # ``ValueError`` would bubble up to the caller --
                # contradicting the "callback bugs must not break
                # the wrapped route" guarantee.  Bad payloads
                # that *are* dicts but contain non-JSON values
                # still surface loudly through the ABC; that is
                # a real bug worth not silencing.
                utils.LOGGER.error(
                    "audit capture_details returned non-dict on %s: %r",
                    event_type,
                    type(details).__name__,
                )
                details = {}
            _record(event_type, details=details, outcome=_response_status_code())
            return result

        return _newfunc

    return decorator


def record_auth(
    *,
    success: bool,
    method: str,
    provider: str | None = None,
    email: str | None = None,
    reason: str | bytes | None = None,
    outcome: int | None = None,
) -> None:
    """Record an ``auth`` audit event for an interactive login attempt.

    ``method`` is the authentication method (``"oauth"`` /
    ``"magic_link"``); ``provider`` names the OAuth provider
    (``"google"`` / ``"github"`` / ...) and is ``None`` for the
    magic-link flow.  ``email`` is the address that authenticated (on
    success) or was targeted (on failure, when the route knows it).
    ``reason`` is a short failure cause; ``bytes`` are decoded and the
    value is truncated to :data:`_REASON_MAX_LEN` so an adversary-
    influenced abort message (e.g. the OAuth ``error`` parameter)
    cannot bloat the store. Non-text values are dropped.

    **No credential material is ever recorded** -- only the method,
    provider, e-mail, the caller's remote address (via the actor
    sub-doc) and the outcome.  In particular OAuth ``code`` /
    ``access_token`` values and magic-link tokens never reach the log.

    The actor is built explicitly here rather than via
    :func:`_capture_actor`: at the point an auth event fires the
    session is not yet established (so ``get_user`` would resolve to
    ``None`` on success), and the relevant identity is the ``email``
    being authenticated, not a presented API key.

    Fail-loud on a real storage failure (like every other event);
    no-op when no audit backend is configured.  Marks the request so
    :func:`audit_auth` will not also record an event for it.
    """
    request.environ[_AUTH_RECORDED_ENVIRON_KEY] = True
    if db.audit is None:
        return
    details: dict[str, Any] = {
        "result": "success" if success else "failure",
        "method": method,
    }
    if provider is not None:
        details["provider"] = provider
    if isinstance(reason, bytes):
        reason = reason.decode("utf-8", "replace")
    if isinstance(reason, str) and reason:
        details["reason"] = reason[:_REASON_MAX_LEN]
    db.audit.record(
        "auth",
        actor={
            "user_email": email,
            "api_key_hash": None,
            "remote_addr": request.remote_addr,
        },
        resource=_capture_resource(),
        details=details,
        outcome=outcome,
    )


def audit_auth(method: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator for the interactive-login routes: record a *failed*
    ``auth`` event whenever the wrapped handler aborts (HTTP >= 400).

    The *success* event is recorded inside
    :func:`ivre.web.auth._handle_authenticated_user` -- it alone knows
    the authenticated e-mail -- which signals success by raising
    Bottle's ``redirect`` (HTTP 3xx); this decorator lets that through
    unrecorded.  Bottle's ``abort`` and ``redirect`` both raise
    :class:`bottle.HTTPResponse`, so a single ``except`` separates the
    two by status code.

    Failures that the funnel already recorded with the e-mail (e.g. a
    pending-approval rejection) set ``_AUTH_RECORDED_ENVIRON_KEY`` and
    are skipped here, so each login attempt yields exactly one event.
    The OAuth provider, when the route has one, is read from the
    ``provider`` keyword argument; the e-mail is unknown for the
    pre-funnel failures this branch handles (invalid OAuth state,
    missing code, expired magic link, ...), which is expected.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def _newfunc(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except HTTPResponse as resp:
                status = resp.status_code
                if (
                    isinstance(status, int)
                    and status >= 400
                    and not request.environ.get(_AUTH_RECORDED_ENVIRON_KEY)
                ):
                    # ``record_auth`` normalises the abort body into a
                    # bounded ``reason`` (decode bytes, truncate, drop
                    # non-text).
                    record_auth(
                        success=False,
                        method=method,
                        provider=kwargs.get("provider"),
                        reason=resp.body,
                        outcome=status,
                    )
                raise

        return _newfunc

    return decorator


def record_oversize_query(
    dbase: Any,
    flt: Any,
    *,
    route: str,
) -> None:
    """Record an ``oversize_query`` audit event when the
    underlying result count exceeds :data:`config.WEB_MAXRESULTS`.

    The route handler is expected to call this once it has
    built the filter (``flt``) for its data-plane read but
    before streaming the (potentially truncated) response::

        flt_params = get_base(subdb)
        audit_hook.record_oversize_query(
            subdb, flt_params.flt, route="/scans"
        )

    No-op when:

    * ``WEB_MAXRESULTS`` is ``None`` -- no threshold has been
      configured, so the truncation behaviour is "stream
      whatever ``WEB_LIMIT`` asked for"; there is nothing to
      flag.
    * ``db.audit`` is ``None`` -- no audit backend configured.

    Otherwise we issue one ``count()`` round-trip against the
    backend; on overflow the audit event records the exact
    count, the threshold, the normalised filter (for forensic
    reproducibility) and the route template.  ``outcome=200``
    is recorded because the read itself still succeeds -- it is
    the operator's truncated-response policy that the event
    flags, not a request failure.

    The cost is one extra ``count()`` per audited read.  This
    is acceptable on compliance-grade deployments that have
    opted into the threshold via ``WEB_MAXRESULTS``; deployments
    that leave the knob at its default (``None``) pay nothing.
    """
    if config.WEB_MAXRESULTS is None or db.audit is None:
        return
    threshold = config.WEB_MAXRESULTS
    try:
        count = dbase.count(flt)
    except Exception:
        # An audit-side count failure must not affect the
        # served read.  Log loudly so the operator can fix the
        # underlying backend issue, then skip the event -- the
        # alternative (propagating to the route) would degrade
        # the data-plane availability for a security-control
        # bookkeeping operation.
        utils.LOGGER.warning(
            "audit oversize_query count failed on route %s",
            route,
            exc_info=True,
        )
        return
    if count <= threshold:
        return
    try:
        flt_repr = dbase.flt2str(flt)
    except Exception:
        # Same fail-soft rationale as the ``count`` branch
        # above: a malformed / un-serialisable filter must not
        # break the read.  The event is still useful without
        # the filter -- ``route``, ``result_count`` and
        # ``threshold`` carry the bulk of the forensic value.
        flt_repr = "<unrepresentable>"
    # ``outcome=200`` hardcoded: an oversize event is recorded
    # for a *successful* read (the response is still served,
    # just truncated to ``WEB_MAXRESULTS``).  ``response.status_code``
    # would carry whatever the request shaped to so far, which
    # in a test or middleware-heavy environment may be stale
    # from a previous request; the semantic answer here is
    # always 200.
    _record(
        "oversize_query",
        details={
            "result_count": int(count),
            "threshold": int(threshold),
            "filter": flt_repr,
            "route": route,
        },
        outcome=200,
    )
