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

"""Authentication helpers for the IVRE MCP HTTP transport.

The MCP server speaks two authentication shapes against the same
underlying user store (:class:`ivre.db.DBAuth`):

* **API-key bearer (existing).** ``Authorization: Bearer <ivre_key>``
  with an opaque random token created via the Web UI
  (``POST /auth/api-keys``).  Validated by
  :func:`ivre.db.DBAuth.validate_api_key`.

* **OAuth 2.1 + PKCE consent flow (new).** MCP clients (Claude
  Desktop, Cursor, Claude Code, …) discover IVRE via the
  ``/.well-known/oauth-authorization-server`` document, optionally
  register themselves via RFC 7591 dynamic client registration, and
  walk an end-user consent flow before receiving an opaque
  IVRE-issued access token (and a refresh token).  Implemented by
  :class:`IvreOAuthProvider`, which fulfils the SDK's
  :class:`OAuthAuthorizationServerProvider` Protocol.

Both shapes round-trip through the SDK's
:class:`mcp.server.auth.middleware.bearer_auth.BearerAuthBackend`,
which calls :meth:`OAuthAuthorizationServerProvider.load_access_token`
when an ``auth_server_provider`` is wired (this is the case when
:data:`ivre.config.MCP_OAUTH_AS_ENABLED` is true).  The provider's
``load_access_token`` accepts either an OAuth access token or an
IVRE API key, so the two shapes coexist transparently.

The ``AccessToken`` model carries the authenticated user's email in
the ``client_id`` field and the user's groups in the ``scopes``
list; downstream MCP tools retrieve the email with
:func:`current_user_email` and the groups with
:func:`current_user_groups`.

This module requires the optional ``mcp`` package (``ivre[mcp]``);
it is only imported from call sites that have already verified the
package is available (see ``_MCP_IMPORT_ERROR`` in
:mod:`ivre.tools.mcp_server`).
"""

from __future__ import annotations

import datetime
import hashlib
import secrets
from typing import Any
from urllib.parse import urlencode

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    TokenVerifier,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl

from ivre import config, utils
from ivre.db import db


def _now_utc() -> datetime.datetime:
    """Single source of UTC ``now`` for token / code timestamps."""
    return datetime.datetime.now(tz=datetime.timezone.utc)


def _hash_token(token: str) -> str:
    """SHA-256 hex digest used as the storage key for tokens / refresh
    tokens.  The raw token is never persisted -- only the digest --
    mirroring the API-key store's posture.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def _build_access_token(user: dict[str, Any], token: str) -> AccessToken:
    """Build the :class:`AccessToken` carried through the SDK's
    ``auth_context`` middleware.  ``client_id`` carries the user's
    email and ``scopes`` mirror :data:`ivre.db.DBAuth` user groups
    (telemetry, not authorisation -- per-scope enforcement is a
    follow-up).
    """
    return AccessToken(
        token=token,
        client_id=user["email"],
        scopes=list(user.get("groups", []) or []),
    )


class IvreTokenVerifier(TokenVerifier):
    """Verify MCP bearer tokens against the IVRE API-key store.

    Used when only the Resource-Server half of the OAuth model is
    wired (:data:`ivre.config.MCP_OAUTH_AS_ENABLED` is false): the
    MCP HTTP transport accepts ``Authorization: Bearer <ivre_key>``
    and validates the opaque API key against
    :func:`DBAuth.validate_api_key`.  When the Authorization-Server
    flow is enabled, :class:`IvreOAuthProvider` takes over and
    accepts both shapes via :meth:`load_access_token`.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        if db.auth is None:
            utils.LOGGER.warning(
                "MCP HTTP: authentication backend not configured",
            )
            return None
        try:
            user = db.auth.validate_api_key(token)
        except Exception:  # pragma: no cover - defensive
            utils.LOGGER.error("MCP HTTP: API key validation failed", exc_info=True)
            return None
        if user is None or not user.get("is_active"):
            return None
        return _build_access_token(user, token)


class IvreOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """OAuth 2.1 Authorization Server backed by :class:`DBAuth`.

    Delivers the eight Protocol methods the MCP SDK calls to drive
    the ``/authorize`` -> consent -> ``/token`` flow:

    * :meth:`get_client` / :meth:`register_client` -- RFC 7591
      dynamic client registration, gated on
      :data:`config.MCP_OAUTH_DCR_ENABLED`.
    * :meth:`authorize` -- persists a one-shot
      :class:`AuthorizationRequest` keyed by a fresh opaque
      ``request_id`` and returns the consent-page URL the SDK
      redirects the user-agent to.  The consent page lives in the
      Bottle Web app (``/cgi/auth/oauth/consent``); it reuses the
      existing session cookie / login flow so an unauthenticated
      user is bounced through the regular IVRE login first.
    * :meth:`load_authorization_code` /
      :meth:`exchange_authorization_code` -- one-shot code
      consumption per RFC 6749 §4.1.2 (the
      :meth:`DBAuth.consume_authorization_code` call atomically
      loads-and-deletes).
    * :meth:`load_refresh_token` / :meth:`exchange_refresh_token`
      -- both rotate the access *and* refresh tokens (the old
      refresh token is revoked before the new pair is minted),
      following the SDK's "SHOULD rotate" recommendation.
    * :meth:`load_access_token` -- accepts both an
      IVRE-issued OAuth access token *and* an existing API key
      (transparent coexistence).
    * :meth:`revoke_token` -- single-token revocation; the cascade
      to the matching refresh / access pair is left to operator
      tooling (the SDK does not surface enough metadata to find
      the sibling token).
    """

    def __init__(self, public_base_url: str) -> None:
        """``public_base_url`` is the externally-reachable scheme +
        host + (optional) base path of the Bottle web app.  The
        ``/cgi/auth/oauth/consent`` URL is appended at
        :meth:`authorize` time; the AS issuer URL advertised in the
        OAuth metadata document is the same base.  Trailing slash
        is stripped on assignment so the join below is unambiguous.
        """
        self.public_base_url = public_base_url.rstrip("/")

    # ----- Client management (RFC 7591) ------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if db.auth is None:
            return None
        record = db.auth.get_oauth_client(client_id)
        if record is None:
            return None
        record.pop("_id", None)
        record.pop("created_at", None)
        return OAuthClientInformationFull.model_validate(record)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not config.MCP_OAUTH_DCR_ENABLED:
            # The SDK's ``RegistrationHandler`` translates
            # ``NotImplementedError`` into the canonical
            # ``registration_disabled`` error response.
            raise NotImplementedError("Dynamic client registration is disabled")
        if db.auth is None:
            raise NotImplementedError("Authentication backend not configured")
        payload = client_info.model_dump(mode="json", exclude_none=True)
        db.auth.create_oauth_client(payload)

    # ----- /authorize ------------------------------------------------

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        if db.auth is None:
            raise AuthorizeError(
                error="server_error",
                error_description="Authentication backend not configured",
            )
        # Persist the authorize request so the consent page (and the
        # post-consent code-mint step) can recover the exact PKCE
        # challenge / redirect URI / scope set without trusting the
        # user-agent to round-trip them.  A one-shot ``request_id``
        # is the only piece of state the browser carries.
        request_id = secrets.token_urlsafe(32)
        now = _now_utc()
        ttl = max(int(config.MCP_OAUTH_REQUEST_TTL), 30)
        payload = {
            "client_id": client.client_id,
            "scopes": list(params.scopes or []),
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "state": params.state,
            "resource": params.resource,
            "expires_at": now + datetime.timedelta(seconds=ttl),
        }
        db.auth.create_authorization_request(request_id, payload)
        return f"{self.public_base_url}/cgi/auth/oauth/consent?{urlencode({'request_id': request_id})}"

    # ----- /token ----------------------------------------------------

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        # The SDK calls ``load_authorization_code`` *before*
        # ``exchange_authorization_code`` to validate the PKCE
        # verifier.  This step must be a non-mutating peek so
        # ``exchange`` is the single atomic claim per RFC 6749
        # §4.1.2 -- a consume-then-reinsert dance would briefly
        # remove the record from the store and let two parallel
        # loads each "see" the code, widening the
        # information-disclosure window if the code leaks.
        if db.auth is None:
            return None
        record = db.auth.get_authorization_code(authorization_code)
        if record is None or record.get("client_id") != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=list(record.get("scopes", [])),
            expires_at=record["expires_at"].timestamp(),
            client_id=record["client_id"],
            code_challenge=record["code_challenge"],
            redirect_uri=AnyUrl(record["redirect_uri"]),
            redirect_uri_provided_explicitly=record["redirect_uri_provided_explicitly"],
            resource=record.get("resource"),
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        if db.auth is None:
            raise TokenError(error="server_error")
        record = db.auth.consume_authorization_code(authorization_code.code)
        if record is None or record.get("client_id") != client.client_id:
            raise TokenError(error="invalid_grant")
        user_email = record.get("user_email")
        if not user_email:
            raise TokenError(
                error="invalid_grant",
                error_description="Authorization code has no associated user",
            )
        return self._issue_token_pair(
            client.client_id,
            user_email,
            list(record.get("scopes", [])),
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        if db.auth is None:
            return None
        record = db.auth.validate_oauth_token(refresh_token)
        if record is None or record.get("kind") != "refresh":
            return None
        if record.get("client_id") != client.client_id:
            return None
        expires_at = record.get("expires_at")
        return RefreshToken(
            token=refresh_token,
            client_id=record["client_id"],
            scopes=list(record.get("scopes", [])),
            expires_at=int(expires_at.timestamp()) if expires_at else None,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        if db.auth is None:
            raise TokenError(error="server_error")
        # Down-scoping is allowed (RFC 6749 §6) but widening is not.
        if scopes and not set(scopes).issubset(refresh_token.scopes):
            raise TokenError(error="invalid_scope")
        effective_scopes = scopes or refresh_token.scopes
        # Recover the user email from the stored record before
        # revoking it: the ``RefreshToken`` shape the SDK exposes
        # does not carry the user binding, so we have to look up
        # the underlying record while it is still valid.
        stored = db.auth.validate_oauth_token(refresh_token.token)
        user_email = (stored or {}).get("user_email")
        if not user_email:
            raise TokenError(
                error="invalid_grant",
                error_description="Refresh token is no longer valid",
            )
        # Rotate: revoke the consumed refresh token *and* the
        # access token that was minted alongside it before
        # issuing the new pair.  RFC 6749 §10.4 and the OAuth 2.1
        # draft both recommend invalidating the previously issued
        # access token when its paired refresh token is rotated,
        # to bound replay if the pair has been leaked (the access
        # token's own TTL would otherwise keep it valid for up to
        # ``MCP_OAUTH_ACCESS_TOKEN_TTL`` after the refresh side
        # has been rotated).  The sibling is found via the
        # ``refresh_token_hash`` field stamped on every access
        # record at mint time by :meth:`_issue_token_pair`.
        refresh_hash = _hash_token(refresh_token.token)
        db.auth.revoke_oauth_token(refresh_hash)
        db.auth.revoke_oauth_tokens_by_refresh(refresh_hash)
        return self._issue_token_pair(
            client.client_id, user_email, list(effective_scopes)
        )

    # ----- Token verification (RS side) ------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Validate a bearer token presented on an MCP tool call.

        Accepts two shapes transparently:

        * IVRE-issued OAuth access tokens (``ivre_oat_<rand>``
          prefix), looked up in the ``auth_oauth_token`` store.
        * Pre-existing IVRE API keys (``ivre_<rand>`` prefix),
          looked up in the legacy ``auth_api_key`` store.

        The two prefixes never collide so a simple
        ``startswith`` dispatch is enough; if a key has no
        recognised prefix we fall through to the API-key path
        (backwards compat with keys generated before the prefix
        convention).
        """
        if db.auth is None:
            return None
        # OAuth path first -- this is the only path that issues
        # access tokens with the ``ivre_oat_`` prefix.
        record = db.auth.validate_oauth_token(token)
        if record is not None and record.get("kind") == "access":
            user = db.auth.get_user_by_email(record["user_email"])
            if user is None or not user.get("is_active"):
                return None
            return _build_access_token(user, token)
        # Fallback: legacy IVRE API key.
        try:
            user = db.auth.validate_api_key(token)
        except Exception:  # pragma: no cover - defensive
            utils.LOGGER.error("MCP HTTP: API key validation failed", exc_info=True)
            return None
        if user is None or not user.get("is_active"):
            return None
        return _build_access_token(user, token)

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        if db.auth is None:
            return
        db.auth.revoke_oauth_token(_hash_token(token.token))

    # ----- Internal helpers ------------------------------------------

    def _issue_token_pair(
        self,
        client_id: str,
        user_email: str,
        scopes: list[str],
    ) -> OAuthToken:
        """Mint a fresh access + refresh token pair and persist
        their hashes.  Called from both the authorization-code
        exchange and the refresh-token rotation paths.
        """
        assert db.auth is not None  # the callers guard this
        now = _now_utc()
        access_ttl = max(int(config.MCP_OAUTH_ACCESS_TOKEN_TTL), 60)
        access_token = f"ivre_oat_{secrets.token_urlsafe(32)}"
        refresh_token = f"ivre_ort_{secrets.token_urlsafe(32)}"
        access_expires = now + datetime.timedelta(seconds=access_ttl)
        # Refresh-token TTL is configurable; ``None`` means
        # never-expiring (until revoked), which the validator
        # tolerates via the ``expires_at IS NULL`` clause.
        refresh_ttl = config.MCP_OAUTH_REFRESH_TOKEN_TTL
        refresh_expires = (
            now + datetime.timedelta(seconds=int(refresh_ttl))
            if refresh_ttl is not None
            else None
        )
        # Stamp the refresh-token hash on the access record so
        # :meth:`exchange_refresh_token` can cascade-revoke the
        # sibling access token when the refresh side rotates
        # (RFC 6749 §10.4 -- the previously issued access token
        # must not survive its paired refresh token).  Only the
        # one-way reference is stored: rotation always starts
        # from the refresh side, never the reverse.
        refresh_token_hash = _hash_token(refresh_token)
        common = {
            "client_id": client_id,
            "user_email": user_email,
            "scopes": list(scopes),
            "revoked_at": None,
            "issued_at": now,
        }
        db.auth.create_oauth_token(
            _hash_token(access_token),
            {
                **common,
                "kind": "access",
                "expires_at": access_expires,
                "refresh_token_hash": refresh_token_hash,
            },
        )
        db.auth.create_oauth_token(
            refresh_token_hash,
            {**common, "kind": "refresh", "expires_at": refresh_expires},
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=int((access_expires - now).total_seconds()),
            refresh_token=refresh_token,
            scope=" ".join(scopes) if scopes else None,
        )


def current_user_email() -> str | None:
    """Return the authenticated user email from the current MCP call.

    Returns ``None`` outside of an MCP HTTP request context or when
    the caller is anonymous.
    """
    access_token = get_access_token()
    if access_token is None:
        return None
    # client_id is set to the user email by IvreTokenVerifier /
    # IvreOAuthProvider; for anonymous / other providers we return
    # whatever value is there so that ``WEB_INIT_QUERIES`` keyed on
    # a non-email string still works.
    return access_token.client_id or None


def current_user_groups() -> list[str]:
    """Return the authenticated user groups, or an empty list."""
    access_token = get_access_token()
    if access_token is None:
        return []
    return list(access_token.scopes or [])


def issue_authorization_code(
    request_id: str,
    user_email: str,
) -> tuple[str, dict[str, Any]] | None:
    """Mint a one-shot authorization code from a pending consent
    request.

    Called by the Bottle consent route (``POST /auth/oauth/consent``)
    after the user clicks "Allow".  Atomically consumes the pending
    :class:`AuthorizationRequest` and persists the issued code with
    the consenting user's email and an :data:`MCP_OAUTH_CODE_TTL`
    expiry.

    Returns ``(code, payload)`` where ``code`` is the raw
    authorization code to embed in the redirect to the OAuth
    client and ``payload`` is the consumed authorization-request
    record (with ``redirect_uri`` / ``state`` / ``scopes`` /
    ``code_challenge`` / ``resource`` / ``client_id`` fields the
    caller needs to build the redirect URL).  Returning the
    payload here lets the caller skip a redundant peek before the
    consume -- one DB round-trip instead of two, no race window
    between peek and consume.

    Returns ``None`` when the request has already been consumed
    or expired.
    """
    if db.auth is None:
        return None
    payload = db.auth.consume_authorization_request(request_id)
    if payload is None:
        return None
    code = secrets.token_urlsafe(32)
    now = _now_utc()
    ttl = max(int(config.MCP_OAUTH_CODE_TTL), 30)
    record = {
        "client_id": payload["client_id"],
        "scopes": list(payload.get("scopes", [])),
        "redirect_uri": payload["redirect_uri"],
        "redirect_uri_provided_explicitly": payload.get(
            "redirect_uri_provided_explicitly", True
        ),
        "code_challenge": payload["code_challenge"],
        "resource": payload.get("resource"),
        "state": payload.get("state"),
        "user_email": user_email,
        "expires_at": now + datetime.timedelta(seconds=ttl),
    }
    db.auth.create_authorization_code(code, record)
    return code, payload


def peek_authorization_request(request_id: str) -> dict[str, Any] | None:
    """Return the stored authorization-request payload *without*
    consuming it.  Used by the consent ``GET`` to render the
    "App X wants Y" page before the user makes a choice.

    Backed by the non-mutating :meth:`DBAuth.get_authorization_request`
    primitive: the consent flow's atomic claim happens at submit
    time via :func:`issue_authorization_code` (which calls
    :meth:`DBAuth.consume_authorization_request`).  Keeping the
    peek non-mutating avoids the race window where a parallel
    submit / peek could see different states of the same request.
    """
    if db.auth is None:
        return None
    payload: dict[str, Any] | None = db.auth.get_authorization_request(request_id)
    return payload


__all__ = [
    "AccessToken",
    "IvreOAuthProvider",
    "IvreTokenVerifier",
    "current_user_email",
    "current_user_groups",
    "issue_authorization_code",
    "peek_authorization_request",
]
