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

"""Authentication routes for the IVRE web interface."""

from __future__ import annotations

import hmac
import html
import ipaddress
import json
import secrets
import smtplib
from email.mime.text import MIMEText
from urllib.parse import urlencode, urlparse, urlsplit, urlunparse

from bottle import abort, redirect, request, response

from ivre import config, utils
from ivre.db import db
from ivre.web import utils as webutils
from ivre.web.base import application, check_referer
from ivre.web.oauth import (
    exchange_code,
    get_authorize_url,
    get_enabled_providers,
    get_user_email,
)

# Optional dependency: the OAuth consent routes below import the
# MCP-side helpers (``issue_authorization_code`` /
# ``peek_authorization_request``).  Those helpers transitively
# import the ``mcp`` package, which is an optional extra
# (``ivre[mcp]``).  Mirror the try-import pattern already used in
# :mod:`ivre.tools.mcp_server`: leave the names as ``None`` when
# the dep is missing; the route handlers abort cleanly in that
# case.  Re-import at request time would also work but keeps the
# import graph noisier.
try:
    from ivre.tools.mcp_server.auth import (
        issue_authorization_code as _mcp_issue_authorization_code,
    )
    from ivre.tools.mcp_server.auth import (
        peek_authorization_request as _mcp_peek_authorization_request,
    )
except ImportError:  # pragma: no cover - exercised via the mcp-less smoke test
    _mcp_issue_authorization_code = None  # type: ignore[assignment]
    _mcp_peek_authorization_request = None  # type: ignore[assignment]

if not config.WEB_SECRET or not isinstance(config.WEB_SECRET, str):
    raise ValueError(
        "WEB_SECRET must be set to a random string when "
        "WEB_AUTH_ENABLED is True (e.g. `openssl rand -base64 42`)"
    )


def _get_base_url() -> str:
    """Return the base URL for OAuth callbacks, including the WSGI mount point.

    For example, if the request URL is http://host/cgi/auth/login/github,
    the script_name is /cgi, and this returns http://host/cgi.
    """
    if config.WEB_AUTH_BASE_URL:
        return config.WEB_AUTH_BASE_URL.rstrip("/")
    origin = "/".join(request.url.split("/", 3)[:3])
    script_name = request.environ.get("SCRIPT_NAME", "")
    return f"{origin}{script_name}"


def _make_state() -> str:
    """Generate an HMAC-signed OAuth state parameter."""
    nonce = secrets.token_urlsafe(32)
    sig = hmac.new(config.WEB_SECRET.encode(), nonce.encode(), "sha256").hexdigest()
    return f"{nonce}.{sig}"


def _verify_state(state: str) -> bool:
    """Verify an HMAC-signed OAuth state parameter."""
    parts = state.split(".", 1)
    if len(parts) != 2:
        return False
    nonce, sig = parts
    expected = hmac.new(
        config.WEB_SECRET.encode(), nonce.encode(), "sha256"
    ).hexdigest()
    return hmac.compare_digest(sig, expected)


# Hard upper bound on a ``next=`` value carried through the login
# chain.  Browsers tolerate URLs into the multi-kilobyte range and
# our signed-cookie carrier has its own ~4 KB envelope budget, so
# the cap mostly defends against runaway / pathological input
# rather than a hard browser limit.
_NEXT_URL_MAX_LENGTH = 2048


def _validate_next_url(value: str | None) -> str | None:
    """Return ``value`` if it is a safe same-origin relative path,
    else ``None``.

    Rejects everything that could be turned into an open-redirect
    after a successful sign-in:

    * absolute URLs (``http://…``, ``https://…``, ``javascript:…``)
      -- ``urlsplit(value).scheme`` non-empty.
    * protocol-relative URLs (``//host/path``) -- starts with two
      forward slashes.
    * backslash variants browsers may normalise back to ``//``
      (``/\\evil``).  Other backslash-prefixed inputs (e.g.
      ``\\evil``, no leading slash) are caught by the prior
      "must start with ``/``" check below.
    * CR / LF / NUL injection that could break header parsing on
      the way out (``redirect()`` builds a ``Location:`` header).
    * inputs longer than :data:`_NEXT_URL_MAX_LENGTH` characters.
    * anything that does not start with a single forward slash
      (the caller decided ``next=`` is a path; bare strings, ``?
      foo``, ``#frag``-only inputs are rejected so the
      same-origin guarantee is unambiguous).

    Callers default to ``"/"`` when the helper returns ``None``.
    """
    if not value or not isinstance(value, str):
        return None
    if len(value) > _NEXT_URL_MAX_LENGTH:
        return None
    if any(ch in value for ch in ("\r", "\n", "\x00")):
        return None
    if not value.startswith("/"):
        return None
    # Reject protocol-relative + backslash variants browsers may
    # normalise back to ``//``.  ``\\`` early-rejection covers
    # ``/\\evil.com``; the ``//`` prefix check covers the plain
    # protocol-relative form.
    if value.startswith("//") or value.startswith("/\\"):
        return None
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return None
    return value


def _check_registration(email: str) -> bool:
    """Check if a new user with this email is allowed to register."""
    policy = config.WEB_AUTH_REGISTRATION
    if policy == "open":
        return True
    if policy == "closed":
        return False
    if policy.startswith("domain:"):
        allowed_domains = policy[7:].split(",")
        if "@" in email:
            domain = email.split("@", 1)[1].lower()
            return domain in (d.strip().lower() for d in allowed_domains)
    return False


def _set_session_cookie(token: str) -> None:
    """Set the session cookie."""
    response.set_cookie(
        "_ivre_session",
        token,
        secret=config.WEB_SECRET,
        httponly=True,
        path="/",
        max_age=config.WEB_AUTH_SESSION_LIFETIME,
        samesite="lax",
        secure=request.url.startswith("https"),
    )


def _handle_authenticated_user(
    email: str,
    display_name: str | None = None,
    next_url: str | None = None,
) -> str:
    """Handle a successfully authenticated user: create/check user record,
    create session, return the post-login redirect URL.

    ``next_url`` is the operator-supplied return path threaded
    through the login chain.  We re-validate it at the boundary
    (defence-in-depth: callers may pass either pre-validated or
    raw values), then fall back to ``"/"`` when it is missing or
    rejected.

    Aborts on user-state errors (pending approval, missing
    backend).
    """
    if db.auth is None:
        abort(500, "Authentication backend not configured")
    user = db.auth.get_user_by_email(email)
    if user is None:
        is_active = _check_registration(email)
        db.auth.create_user(
            email,
            display_name=display_name,
            is_active=is_active,
        )
        user = db.auth.get_user_by_email(email)
        if not is_active:
            abort(403, "Account created but pending admin approval")
    if not user.get("is_active"):
        abort(403, "Account is pending admin approval")
    # Update display name if we have a better one
    if display_name and user.get("display_name") == user["email"]:
        db.auth.update_user(email, display_name=display_name)
    token = db.auth.create_session(email)
    _set_session_cookie(token)
    return _validate_next_url(next_url) or "/"


# --- OAuth routes ---


@application.get("/auth/login/<provider>")
@check_referer
def login_provider(provider: str) -> None:
    if provider not in get_enabled_providers():
        abort(404, "Provider not available")
    state = _make_state()
    response.set_cookie(
        "_ivre_oauth_state",
        state,
        secret=config.WEB_SECRET,
        httponly=True,
        path="/",
        max_age=300,
        samesite="lax",
        secure=request.url.startswith("https"),
    )
    # Stash a validated ``next=`` path in a separate signed cookie
    # so the callback can land the user back on the page they
    # started from (e.g. the OAuth consent screen mounted at
    # ``/cgi/auth/oauth/consent``).  The cookie has the same
    # 5 min TTL as the OAuth state cookie -- a user who takes
    # longer than that on the upstream IdP loses both equally.
    next_url = _validate_next_url(request.params.get("next"))
    if next_url is not None:
        response.set_cookie(
            "_ivre_login_next",
            next_url,
            secret=config.WEB_SECRET,
            httponly=True,
            path="/",
            max_age=300,
            samesite="lax",
            secure=request.url.startswith("https"),
        )
    base_url = _get_base_url()
    redirect_uri = f"{base_url}/auth/callback/{provider}"
    redirect(get_authorize_url(provider, state, redirect_uri))


@application.get("/auth/callback/<provider>")
def callback_provider(provider: str) -> None:
    if provider not in get_enabled_providers():
        abort(404, "Provider not available")
    # Verify state
    state = request.params.get("state", "")
    cookie_state = request.get_cookie("_ivre_oauth_state", secret=config.WEB_SECRET)
    if not cookie_state or not _verify_state(state) or state != cookie_state:
        abort(400, "Invalid OAuth state")
    # Clear the state cookie
    response.delete_cookie("_ivre_oauth_state", path="/")
    # Recover and clear the stashed ``next=``.  Bottle's signed-cookie
    # helper returns ``None`` on a tampered / missing cookie; the
    # validator below catches anything that slipped through (the
    # validation step here is intentional defence-in-depth -- the
    # cookie is signed with ``WEB_SECRET`` so a forgery is already
    # rejected, but re-validating keeps the open-redirect surface
    # uniformly bounded).
    raw_next = request.get_cookie("_ivre_login_next", secret=config.WEB_SECRET)
    next_url = _validate_next_url(raw_next if isinstance(raw_next, str) else None)
    response.delete_cookie("_ivre_login_next", path="/")
    # Check for errors from provider
    error = request.params.get("error")
    if error:
        abort(400, f"OAuth error: {error}")
    # Exchange code for tokens
    code = request.params.get("code")
    if not code:
        abort(400, "Missing authorization code")
    base_url = _get_base_url()
    redirect_uri = f"{base_url}/auth/callback/{provider}"
    try:
        tokens = exchange_code(provider, code, redirect_uri)
    except Exception:
        utils.LOGGER.error("OAuth token exchange failed", exc_info=True)
        abort(500, "Authentication failed")
    if "error" in tokens or "access_token" not in tokens:
        utils.LOGGER.error("OAuth token exchange returned error: %r", tokens)
        abort(500, "Authentication failed")
    email, display_name = get_user_email(provider, tokens)
    if not email:
        abort(400, "Could not retrieve email from provider")
    redir = _handle_authenticated_user(email, display_name, next_url=next_url)
    redirect(redir)


# --- Magic link routes ---


def _normalize_ip_for_rate_limit(addr: str) -> str:
    """Normalize an IP address for rate limiting.

    IPv6 addresses are grouped by /48 (the minimum end-site allocation
    per RIR policy) to prevent evasion by rotating addresses within a
    larger allocation.
    """
    try:
        ip = ipaddress.ip_address(addr)
        if isinstance(ip, ipaddress.IPv6Address):
            net = ipaddress.IPv6Network(f"{ip}/48", strict=False)
            return f"{net.network_address}/48"
    except ValueError:
        pass
    return addr


@application.post("/auth/magic-link")
@check_referer
def send_magic_link() -> str:
    if not config.WEB_AUTH_MAGIC_LINK_ENABLED:
        abort(404, "Magic link authentication is not enabled")
    next_url: str | None = None
    try:
        data = json.loads(request.body.read())
        email = data.get("email", "").strip().lower()
        # The frontend may carry a ``next=<safe-path>`` so the
        # verify endpoint can land the user back on the page that
        # triggered the magic-link request.  The validator drops
        # anything that is not a same-origin relative path.
        raw_next = data.get("next")
        if isinstance(raw_next, str):
            next_url = _validate_next_url(raw_next)
    except (json.JSONDecodeError, AttributeError):
        email = request.forms.get("email", "").strip().lower()
        raw_next = request.forms.get("next")
        if isinstance(raw_next, str):
            next_url = _validate_next_url(raw_next)
    if not email or "@" not in email:
        abort(400, "Invalid email address")
    # Always return success to prevent email enumeration
    response.content_type = "application/json"
    try:
        window = config.WEB_AUTH_MAGIC_LINK_LIFETIME
        email_key = f"magic:email:{email}"
        ip_key = f"magic:ip:{_normalize_ip_for_rate_limit(request.remote_addr)}"
        if db.auth is not None and (
            db.auth.is_rate_limited(
                email_key,
                config.WEB_AUTH_MAGIC_LINK_RATE_PER_EMAIL,
                window,
            )
            or db.auth.is_rate_limited(
                ip_key,
                config.WEB_AUTH_MAGIC_LINK_RATE_PER_IP,
                window,
            )
        ):
            utils.LOGGER.warning(
                "Magic link rate limit hit for %s / %s",
                email,
                request.remote_addr,
            )
        else:
            if db.auth is not None:
                db.auth.record_rate_limit(email_key)
                db.auth.record_rate_limit(ip_key)
            _send_magic_link_email(email, next_url=next_url)
    except Exception:
        utils.LOGGER.error("Failed to send magic link email", exc_info=True)
    return json.dumps({"status": "ok", "message": "Check your email"})


@application.get("/auth/magic-link/verify")
def verify_magic_link() -> None:
    if not config.WEB_AUTH_MAGIC_LINK_ENABLED:
        abort(404, "Magic link authentication is not enabled")
    token = request.params.get("token", "")
    if db.auth is None:
        abort(500, "Authentication backend not configured")
    email = db.auth.consume_magic_link_token(token)
    if email is None:
        abort(400, "Invalid or expired magic link")
    # Re-validate the ``next=`` carried in the link.  The magic
    # link itself travels via email so we must assume it can be
    # tampered with in transit; the validator drops any payload
    # that is not a same-origin relative path.
    next_url = _validate_next_url(request.params.get("next"))
    redir = _handle_authenticated_user(email, next_url=next_url)
    redirect(redir)


def _send_magic_link_email(email: str, next_url: str | None = None) -> None:
    """Send a magic link email.

    ``next_url`` is the optional post-login redirect path.  It is
    expected to already be validated by :func:`_validate_next_url`;
    callers passing raw user input should validate first.
    """
    base_url = _get_base_url()
    token = db.auth.create_magic_link_token(email, config.WEB_AUTH_MAGIC_LINK_LIFETIME)
    link = f"{base_url}/auth/magic-link/verify?token={token}"
    if next_url:
        link = f"{link}&{urlencode({'next': next_url})}"
    msg = MIMEText(
        f"Click this link to log in to IVRE:\n\n{link}\n\n"
        f"This link expires in {config.WEB_AUTH_MAGIC_LINK_LIFETIME // 60} minutes.\n"
        "If you did not request this, you can safely ignore this email."
    )
    msg["Subject"] = "IVRE Login Link"
    msg["From"] = config.WEB_AUTH_SMTP_FROM
    msg["To"] = email
    if config.WEB_AUTH_SMTP_USE_TLS:
        smtp = smtplib.SMTP(config.WEB_AUTH_SMTP_HOST, config.WEB_AUTH_SMTP_PORT)
        smtp.starttls()
    else:
        smtp = smtplib.SMTP(config.WEB_AUTH_SMTP_HOST, config.WEB_AUTH_SMTP_PORT)
    if config.WEB_AUTH_SMTP_USER:
        smtp.login(config.WEB_AUTH_SMTP_USER, config.WEB_AUTH_SMTP_PASSWORD)
    smtp.sendmail(config.WEB_AUTH_SMTP_FROM, [email], msg.as_string())
    smtp.quit()
    utils.LOGGER.info("Magic link sent to %s", email)


# --- Session routes ---


@application.get("/auth/me")
@check_referer
def auth_me() -> str:
    response.content_type = "application/json"
    user = webutils.get_user()
    if user is None:
        return json.dumps({"authenticated": False})
    result = {"authenticated": True, "email": user}
    if db.auth is not None:
        user_doc = db.auth.get_user_by_email(user)
        if user_doc:
            result["display_name"] = user_doc.get("display_name", user)
            result["is_admin"] = user_doc.get("is_admin", False)
            result["groups"] = user_doc.get("groups", [])
    return json.dumps(result)


@application.get("/auth/check")
def auth_check() -> str:
    """Lightweight auth check for nginx auth_request.

    Returns 200 with X-Auth-User header if authenticated, 401 otherwise.
    """
    user = webutils.get_user()
    if user is None:
        abort(401, "")
    response.set_header("X-Auth-User", user)
    return ""


@application.post("/auth/logout")
@check_referer
def auth_logout() -> str:
    session_token = request.get_cookie("_ivre_session", secret=config.WEB_SECRET)
    if session_token and db.auth is not None:
        db.auth.delete_session(session_token)
    response.delete_cookie("_ivre_session", path="/")
    response.content_type = "application/json"
    return json.dumps({"status": "ok"})


# --- API key routes ---


@application.get("/auth/api-keys")
@check_referer
def list_api_keys() -> str:
    user = webutils.get_user()
    if user is None:
        abort(401, "Authentication required")
    response.content_type = "application/json"
    keys = db.auth.list_api_keys(user)
    for key in keys:
        key.pop("_id", None)
        if "created_at" in key:
            key["created_at"] = key["created_at"].isoformat()
        if "last_used" in key and key["last_used"]:
            key["last_used"] = key["last_used"].isoformat()
        if "expires_at" in key and key["expires_at"]:
            key["expires_at"] = key["expires_at"].isoformat()
    return json.dumps(keys)


@application.post("/auth/api-keys")
@check_referer
def create_api_key() -> str:
    user = webutils.get_user()
    if user is None:
        abort(401, "Authentication required")
    try:
        data = json.loads(request.body.read())
    except (json.JSONDecodeError, AttributeError):
        abort(400, "Invalid request body")
    name = data.get("name", "").strip()
    if not name:
        abort(400, "API key name is required")
    key = db.auth.create_api_key(user, name)
    response.content_type = "application/json"
    return json.dumps({"key": key, "name": name})


@application.delete("/auth/api-keys/<key_hash>")
@check_referer
def delete_api_key(key_hash: str) -> str:
    user = webutils.get_user()
    if user is None:
        abort(401, "Authentication required")
    deleted = db.auth.delete_api_key(key_hash, user_email=user)
    if not deleted:
        abort(404, "API key not found")
    response.content_type = "application/json"
    return json.dumps({"status": "ok"})


# --- Admin routes ---


def _ensure_admin() -> None:
    """Abort the request with 401/403 unless the caller is an
    authenticated admin. Centralises the gate shared by every
    ``/auth/admin/*`` route."""
    user = webutils.get_user()
    if user is None:
        abort(401, "Authentication required")
    if db.auth is None:
        abort(500, "Authentication backend not configured")
    user_doc = db.auth.get_user_by_email(user)
    if not user_doc or not user_doc.get("is_admin"):
        abort(403, "Admin access required")


@application.get("/auth/admin/users")
@check_referer
def admin_list_users() -> str:
    _ensure_admin()
    users = db.auth.list_users()
    for u in users:
        u.pop("_id", None)
        if "created_at" in u:
            u["created_at"] = u["created_at"].isoformat()
        if "last_login" in u and u["last_login"]:
            u["last_login"] = u["last_login"].isoformat()
    response.content_type = "application/json"
    return json.dumps(users)


@application.get("/auth/admin/api-keys")
@check_referer
def admin_list_api_keys() -> str:
    """Admin audit view: list every API key across every user.
    The full secret is never stored, so the response carries the
    same fields as the owner-scoped ``GET /auth/api-keys`` plus
    the ``user_email`` of each key's owner (already in the
    underlying record)."""
    _ensure_admin()
    keys = db.auth.list_api_keys()
    for key in keys:
        key.pop("_id", None)
        if "created_at" in key:
            key["created_at"] = key["created_at"].isoformat()
        if "last_used" in key and key["last_used"]:
            key["last_used"] = key["last_used"].isoformat()
        if "expires_at" in key and key["expires_at"]:
            key["expires_at"] = key["expires_at"].isoformat()
    response.content_type = "application/json"
    return json.dumps(keys)


@application.delete("/auth/admin/api-keys/<key_hash>")
@check_referer
def admin_delete_api_key(key_hash: str) -> str:
    """Admin revocation path: delete any user's key by hash. The
    owner-scoped ``DELETE /auth/api-keys/<key_hash>`` path stays
    available for users to revoke their own keys without admin
    privileges."""
    _ensure_admin()
    deleted = db.auth.delete_api_key(key_hash)
    if not deleted:
        abort(404, "API key not found")
    response.content_type = "application/json"
    return json.dumps({"status": "ok"})


@application.put("/auth/admin/users/<email:path>")
@check_referer
def admin_update_user(email: str) -> str:
    _ensure_admin()
    try:
        data = json.loads(request.body.read())
    except (json.JSONDecodeError, AttributeError):
        abort(400, "Invalid request body")
    allowed_fields = {"is_active", "is_admin", "groups", "display_name"}
    updates = {k: v for k, v in data.items() if k in allowed_fields}
    if not updates:
        abort(400, "No valid fields to update")
    target = db.auth.get_user_by_email(email)
    if target is None:
        # Admin can create users via PUT (upsert)
        db.auth.create_user(
            email,
            display_name=updates.get("display_name"),
            is_admin=updates.get("is_admin", False),
            is_active=updates.get("is_active", True),
            groups=updates.get("groups"),
        )
    else:
        db.auth.update_user(email, **updates)
    response.content_type = "application/json"
    return json.dumps({"status": "ok"})


# --- Auth config route ---


@application.get("/auth/config")
@check_referer
def auth_config() -> str:
    """Return authentication configuration for the frontend."""
    response.content_type = "application/json"
    providers = get_enabled_providers()
    provider_labels = {}
    if "oidc" in providers:
        provider_labels["oidc"] = config.WEB_AUTH_OIDC_LABEL
    result = {
        "enabled": True,
        "providers": providers,
        "magic_link": config.WEB_AUTH_MAGIC_LINK_ENABLED,
    }
    if provider_labels:
        result["provider_labels"] = provider_labels
    return json.dumps(result)


# --- OAuth consent routes (MCP Authorization Server) ---
#
# The MCP server's ``IvreOAuthProvider.authorize()`` redirects the
# user-agent here with an opaque ``request_id`` after parsing the
# OAuth ``/authorize`` request.  This module owns the consent UX:
#
# * ``GET  /auth/oauth/consent?request_id=...`` -- render an HTML
#   consent page showing the requesting client name + scope list;
#   redirects to the login flow when the user is not authenticated
#   (after login the user lands back on the same URL).
#
# * ``POST /auth/oauth/consent`` -- handle the ``allow`` / ``deny``
#   button click; on allow, mint an authorization code via
#   :func:`ivre.tools.mcp_server.auth.issue_authorization_code` and
#   redirect to the OAuth client's ``redirect_uri`` with ``code`` /
#   ``state``; on deny, redirect with
#   ``error=access_denied`` per RFC 6749 §4.1.2.1.


def _html_escape(value: object) -> str:
    """Minimal HTML escape for embedding untrusted strings in the
    consent page; the page is hand-written (no server-side
    templating) so the escaping is explicit at every
    interpolation site.
    """
    return html.escape(str(value), quote=True)


def _oauth_client_redirect(
    redirect_uri: str,
    state: str | None,
    **extra: str,
) -> None:
    """Bounce the user-agent back to the OAuth client's
    ``redirect_uri`` with the standard ``code`` / ``state`` /
    ``error`` query parameters (per RFC 6749 §4.1.2 and
    §4.1.2.1).  ``state`` is passed through verbatim so the
    client can correlate its request.
    """
    params: list[tuple[str, str]] = []
    if state is not None:
        params.append(("state", state))
    params.extend((k, v) for k, v in extra.items() if v is not None)
    parsed = urlparse(redirect_uri)
    existing = parsed.query
    query = urlencode(params)
    if existing:
        query = f"{existing}&{query}"
    redirect(urlunparse(parsed._replace(query=query)))


def _render_consent_page(
    request_id: str,
    client_name: str,
    scopes: list[str],
    user_email: str,
) -> str:
    """Render the consent HTML.

    Hand-written (no Jinja / no templating) so the surface stays
    minimal and the CSP-friendly profile (no inline JS, only inline
    CSS hashes) is easy to lock down.  Every interpolation site
    runs through :func:`_html_escape`.
    """
    response.content_type = "text/html; charset=utf-8"
    scope_items = (
        "".join(f"<li>{_html_escape(s)}</li>" for s in scopes)
        if scopes
        else "<li><em>(no scopes requested)</em></li>"
    )
    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8">'
        "<title>IVRE -- Authorise application</title>"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<style>"
        "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
        "max-width:30rem;margin:3rem auto;padding:0 1rem;color:#222}"
        "h1{font-size:1.4rem;margin-bottom:1rem}"
        ".client{font-weight:600}"
        "ul{padding-left:1.5rem}"
        ".user{color:#666;font-size:.9rem;margin:1rem 0}"
        ".actions{margin-top:1.5rem;display:flex;gap:.5rem}"
        "button{padding:.6rem 1.2rem;font-size:1rem;border-radius:.4rem;"
        "border:1px solid #888;background:#fff;cursor:pointer}"
        "button.allow{background:#2d6cdf;color:#fff;border-color:#2d6cdf}"
        "</style>"
        "</head><body>"
        f'<h1><span class="client">{_html_escape(client_name)}</span> '
        "would like to access your IVRE data</h1>"
        "<p>This application is asking permission to act on your "
        "behalf with the following scopes:</p>"
        f"<ul>{scope_items}</ul>"
        f'<p class="user">Signed in as <strong>'
        f"{_html_escape(user_email)}</strong>.</p>"
        '<form method="post" action="/cgi/auth/oauth/consent">'
        f'<input type="hidden" name="request_id" '
        f'value="{_html_escape(request_id)}">'
        '<div class="actions">'
        '<button type="submit" name="action" value="deny">Deny</button>'
        '<button type="submit" name="action" value="allow" '
        'class="allow">Allow</button>'
        "</div>"
        "</form>"
        "</body></html>"
    )


@application.get("/auth/oauth/consent")
@check_referer
def oauth_consent_page() -> str:
    """Render the OAuth consent screen for an in-flight
    authorization request driven by the MCP server's
    :class:`IvreOAuthProvider`.

    Reuses the existing session cookie / login flow: if the user
    is not logged in we redirect to ``/login?next=...`` so the
    return path lands back here after authentication.
    """
    if not config.MCP_OAUTH_AS_ENABLED or _mcp_peek_authorization_request is None:
        abort(404, "OAuth Authorization Server is disabled")
    if db.auth is None:
        abort(500, "Authentication backend not configured")
    request_id = request.query.get("request_id", "").strip()
    if not request_id:
        abort(400, "missing request_id")
    user_email = webutils.get_user()
    if user_email is None:
        # Bounce through the login page; the frontend interprets
        # ``?next=`` to redirect back after a successful login.
        target = f"/cgi/auth/oauth/consent?{urlencode({'request_id': request_id})}"
        redirect(f"/login?{urlencode({'next': target})}")
    payload = _mcp_peek_authorization_request(request_id)
    if payload is None:
        abort(400, "authorization request not found or expired")
    client_record = db.auth.get_oauth_client(payload["client_id"])
    client_name = (client_record or {}).get("client_name") or payload["client_id"]
    scopes = list(payload.get("scopes") or [])
    return _render_consent_page(
        request_id=request_id,
        client_name=client_name,
        scopes=scopes,
        user_email=user_email,
    )


@application.post("/auth/oauth/consent")
@check_referer
def oauth_consent_submit() -> None:
    """Handle the user's ``Allow`` / ``Deny`` decision and bounce
    the user-agent back to the OAuth client's ``redirect_uri``.

    On ``Allow``: mints a fresh authorization code and redirects
    with ``code=<value>&state=<request-state>``.  On ``Deny`` (or
    any non-``allow`` action): redirects with
    ``error=access_denied`` per RFC 6749 §4.1.2.1.
    """
    if not config.MCP_OAUTH_AS_ENABLED or _mcp_issue_authorization_code is None:
        abort(404, "OAuth Authorization Server is disabled")
    if db.auth is None:
        abort(500, "Authentication backend not configured")
    user_email = webutils.get_user()
    if user_email is None:
        abort(401, "Authentication required")
    request_id = (request.forms.get("request_id") or "").strip()
    action = (request.forms.get("action") or "").strip().lower()
    if not request_id:
        abort(400, "missing request_id")
    if action == "allow":
        # ``issue_authorization_code`` atomically consumes the
        # pending request and returns both the minted code *and*
        # the consumed payload, so we can build the redirect
        # without a separate peek round-trip.
        result = _mcp_issue_authorization_code(request_id, user_email)
        if result is None:
            abort(400, "authorization request not found or expired")
        code, pending = result
        _oauth_client_redirect(
            pending["redirect_uri"],
            pending.get("state"),
            code=code,
        )
        return
    # ``deny`` (or anything else): consume the pending request so
    # the user cannot revisit the consent page after declining;
    # use the consumed payload directly to build the
    # ``error=access_denied`` redirect (single DB round-trip, no
    # race window between peek and consume).
    pending = db.auth.consume_authorization_request(request_id)
    if pending is None:
        abort(400, "authorization request not found or expired")
    _oauth_client_redirect(
        pending["redirect_uri"],
        pending.get("state"),
        error="access_denied",
        error_description="The user denied the authorization request.",
    )
