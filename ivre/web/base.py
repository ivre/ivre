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


"""Bottle application instance and shared utilities for the IVRE web
interface.

This module exists to break the cyclic import between ``app`` and
``auth``: both need the ``application`` and ``check_referer`` objects,
so they live here where neither module is imported.
"""

import hashlib
import json
from functools import wraps

from bottle import Bottle, abort, request, response

from ivre import config, utils
from ivre.db import db

application = Bottle()


@application.hook("after_request")
def add_security_headers():
    response.set_header("X-Frame-Options", "DENY")
    response.set_header("Content-Security-Policy", "frame-ancestors 'none'")
    response.set_header("X-Content-Type-Options", "nosniff")


def _parse_bearer(auth_header: str) -> str | None:
    """Return the token from an ``Authorization: Bearer <token>``
    header value, or ``None`` if the value is not a well-formed
    bearer credential.

    Accepts any whitespace separator between scheme and token
    (a single space, a tab, multiple-whitespace runs, ...) so
    callers do not have to know the exact byte the client used.
    Returns ``None`` on every malformed shape:

    * missing / empty header value;
    * any scheme other than ``bearer`` (case-insensitive);
    * scheme present but no token (``"Bearer "``, ``"Bearer\\t"``,
      whitespace-only header, ...).

    Used by :func:`extract_api_key` to surface the token to the
    auth layer, and by :func:`check_referer` to gate the CSRF
    bypass on a positive parse. Sharing the parser is what
    keeps the two functions from disagreeing on what counts as
    "this looks like an API request" (a previous version of
    ``check_referer`` did the parse inline and raised
    ``IndexError`` on whitespace-only ``Authorization`` values).
    """
    parts = auth_header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1]:
        return parts[1]
    return None


def extract_api_key() -> str | None:
    """Return the raw API key string from the current Bottle
    request, or ``None`` if no API-key header is present.

    Recognises ``X-API-Key`` (preferred) and ``Authorization:
    Bearer <key>`` (case-insensitive scheme match, any
    whitespace separator). The header extraction is
    intentionally separate from validation: it is cheap and
    side-effect-free, so upstream gates (e.g.
    :func:`quota_gated`) can call it on every request without
    touching the DB. Lives in this module so consumers in both
    :mod:`ivre.web.base` and :mod:`ivre.web.utils` can reach it
    without re-introducing the cycle ``base`` -> ``utils`` ->
    ``base`` that the module docstring describes.
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key
    return _parse_bearer(request.headers.get("Authorization", ""))


def check_referer(func):
    """Wrapper for route functions to implement a basic anti-CSRF check
    based on the Referer: header.

        It will abort (status code 400) if the referer is invalid.

    """

    if config.WEB_ALLOWED_REFERERS is False:
        return func

    def _die(referer):
        utils.LOGGER.critical("Invalid Referer header [%r]", referer)
        response.set_header("Content-Type", "application/json")
        response.status = "400 Bad Request"
        return json.dumps(
            {
                "error": "Invalid Referer header. Check your configuration.",
            }
        )

    @wraps(func)
    def _newfunc(*args, **kargs):
        # An ``X-API-Key`` or ``Authorization: Bearer <token>``
        # header is recognised as a programmatic-client signal
        # and bypasses the Referer check: browsers do not
        # auto-attach these headers, so a CSRF attacker cannot
        # forge them. Delegating to ``extract_api_key`` keeps
        # the bypass predicate aligned with what the auth /
        # quota layers actually accept downstream (so a
        # well-formed header here also reaches ``get_user`` /
        # ``quota_gated``, and a malformed one neither bypasses
        # CSRF nor is treated as auth material). When auth is
        # enabled the key is validated for real later in the
        # request (``get_user`` / ``quota_gated``).
        if extract_api_key() is not None:
            return func(*args, **kargs)

        referer = request.headers.get("Referer")
        if not referer:
            return _die(referer)
        if config.WEB_ALLOWED_REFERERS is None:
            base_url = f"{'/'.join(request.url.split('/', 3)[:3])}/"
            if referer.startswith(base_url):
                return func(*args, **kargs)
        elif (
            # pylint: disable=unsupported-membership-test
            referer
            in config.WEB_ALLOWED_REFERERS
        ):
            return func(*args, **kargs)
        return _die(referer)

    return _newfunc


def quota_gated(func):
    """Per-API-key sliding-window quota gate for data-plane
    routes.

    The decorator is a no-op for requests that do *not* carry an
    ``X-API-Key`` or ``Authorization: Bearer ...`` header
    (session-cookie / ``REMOTE_USER`` traffic is unaffected), and
    a no-op when ``config.WEB_AUTH_ENABLED`` is ``False`` or the
    auth backend is not configured. For requests that *do* carry
    an API key:

    * the key is validated via ``db.auth.validate_api_key``;
      invalid / expired / disabled keys get ``HTTP 401``;
    * the validated user record is cached on
      ``request.environ['ivre.api_key_user']`` so a later
      :func:`ivre.web.utils.get_user` call inside the same
      request does not hit the DB twice;
    * when ``config.WEB_API_KEY_RATE_MAX`` is set, the key is
      gated through ``db.auth.is_rate_limited`` /
      ``record_rate_limit`` with key
      ``f"api:{sha256(key).hexdigest()}"``,
      ``max_attempts=WEB_API_KEY_RATE_MAX``, and
      ``window=WEB_API_KEY_RATE_WINDOW``;
    * over-quota requests get ``HTTP 429`` and are *not* counted
      (the window is extended only by allowed requests, matching
      the magic-link rate-limit pattern at
      ``ivre/web/auth.py:357-385``).

    The gate is intentionally scoped to programmatic clients:
    interactive SPA traffic uses the session cookie path, which
    is gated by ``WEB_AUTH_ENABLED`` and the auth backend's own
    session lifetime instead.
    """

    @wraps(func)
    def _newfunc(*args, **kargs):
        # Cheap deployment-shape checks first: on the most
        # common deployment (``WEB_AUTH_ENABLED = False``,
        # the default) the gate must short-circuit before
        # parsing any request header. ``extract_api_key`` is
        # cheap and side-effect-free today, but reading two
        # headers per request on 17 data-plane routes adds up
        # -- and keeping the gate's parser dependency-free
        # also defends against a future ``extract_api_key``
        # rewrite that grows side effects (logging,
        # validation, ...).
        if not config.WEB_AUTH_ENABLED:
            return func(*args, **kargs)
        if db.auth is None:
            return func(*args, **kargs)
        api_key = extract_api_key()
        if api_key is None:
            return func(*args, **kargs)
        user = db.auth.validate_api_key(api_key)
        # Mirror :func:`ivre.web.utils.get_user`'s cache fast-
        # path requirements: a user record without ``is_active``
        # *or* without ``email`` is unusable downstream
        # (``get_user`` returns the email, every consumer
        # branches on the active flag). Treat the gap as
        # "invalid key" rather than caching a half-formed dict
        # that ``get_user`` would silently bypass -- otherwise
        # the cache-then-skip path would double-stamp
        # ``last_used`` on the auth backend.
        if (
            not isinstance(user, dict)
            or not user.get("is_active")
            or not user.get("email")
        ):
            abort(401, "Invalid or expired API key")
        # Cache the validated user so ``get_user`` reuses it
        # instead of running a second ``validate_api_key`` (which
        # would re-stamp ``last_used`` for the same request).
        # Only cache the two fields ``get_user`` actually reads
        # (``email`` and ``is_active``): the backend's full user
        # record may carry display name, group memberships,
        # last-login timestamp, etc., none of which the cache
        # reader needs, and keeping them on ``request.environ``
        # would needlessly widen the surface a logging
        # middleware or error-traceback dump might surface.
        request.environ["ivre.api_key_user"] = {
            "email": user["email"],
            "is_active": user["is_active"],
        }
        max_attempts = config.WEB_API_KEY_RATE_MAX
        if not isinstance(max_attempts, int) or max_attempts <= 0:
            return func(*args, **kargs)
        window = config.WEB_API_KEY_RATE_WINDOW
        if not isinstance(window, int) or window <= 0:
            return func(*args, **kargs)
        # Hash the raw key with the same algorithm
        # ``create_api_key`` / ``validate_api_key`` use so the
        # rate-limit ledger never stores credential material in
        # plaintext.
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        limit_key = f"api:{key_hash}"
        if db.auth.is_rate_limited(limit_key, max_attempts, window):
            # Log the SHA-256 prefix rather than ``api_key[:12]``
            # (which would put 7 base64url chars of the raw
            # 256-bit secret in syslog). The hash prefix
            # identifies the offending key for operators without
            # leaking credential material; the full SHA-256 lives
            # in the rate-limit ledger and can be cross-referenced
            # there if needed.
            utils.LOGGER.info(
                "API key quota exceeded (key_hash=%s, max=%d, window=%ds)",
                key_hash[:16],
                max_attempts,
                window,
            )
            abort(
                429,
                f"API key quota exceeded "
                f"({max_attempts} requests per {window} seconds)",
            )
        db.auth.record_rate_limit(limit_key)
        return func(*args, **kargs)

    return _newfunc


def check_upload_ok(func):
    """Wrapper for write-side route functions that gates the
    handler on the ``WEB_UPLOAD_OK`` knob.

    Setting ``WEB_UPLOAD_OK = False`` (the default in
    ``ivre/config.py``) makes the decorated handler return 403
    *Forbidden* before the body is consumed.  ``WEB_UPLOAD_OK``
    was historically only surfaced to the JS client through
    ``/config`` so the AngularJS UI could hide its upload
    widgets, leaving every ``POST`` route open to any
    referrer-conformant client.  This decorator turns the flag
    into a real server-side gate.

    The flag is read on every call (rather than once at
    decoration time) so an operator can flip the value in
    ``ivre.conf`` without restarting the WSGI worker.
    """

    @wraps(func)
    def _newfunc(*args, **kargs):
        if not config.WEB_UPLOAD_OK:
            utils.LOGGER.critical(
                "Upload attempt while WEB_UPLOAD_OK is disabled",
            )
            response.set_header("Content-Type", "application/json")
            response.status = "403 Forbidden"
            return json.dumps(
                {
                    "error": (
                        "Uploads are disabled. Set WEB_UPLOAD_OK = True in "
                        "ivre.conf to enable write endpoints."
                    ),
                }
            )
        return func(*args, **kargs)

    return _newfunc
