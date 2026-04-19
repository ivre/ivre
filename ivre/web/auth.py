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
import ipaddress
import json
import secrets
import smtplib
from email.mime.text import MIMEText

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


def _handle_authenticated_user(email: str, display_name: str | None = None) -> str:
    """Handle a successfully authenticated user: create/check user record,
    create session, redirect to app.

    Returns the redirect URL, or aborts on error.
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
    return "/"


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
    redir = _handle_authenticated_user(email, display_name)
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
    try:
        data = json.loads(request.body.read())
        email = data.get("email", "").strip().lower()
    except (json.JSONDecodeError, AttributeError):
        email = request.forms.get("email", "").strip().lower()
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
            _send_magic_link_email(email)
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
    redir = _handle_authenticated_user(email)
    redirect(redir)


def _send_magic_link_email(email: str) -> None:
    """Send a magic link email."""
    base_url = _get_base_url()
    token = db.auth.create_magic_link_token(email, config.WEB_AUTH_MAGIC_LINK_LIFETIME)
    link = f"{base_url}/auth/magic-link/verify?token={token}"
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


@application.get("/auth/admin/users")
@check_referer
def admin_list_users() -> str:
    user = webutils.get_user()
    if user is None:
        abort(401, "Authentication required")
    if db.auth is None:
        abort(500, "Authentication backend not configured")
    user_doc = db.auth.get_user_by_email(user)
    if not user_doc or not user_doc.get("is_admin"):
        abort(403, "Admin access required")
    users = db.auth.list_users()
    for u in users:
        u.pop("_id", None)
        if "created_at" in u:
            u["created_at"] = u["created_at"].isoformat()
        if "last_login" in u and u["last_login"]:
            u["last_login"] = u["last_login"].isoformat()
    response.content_type = "application/json"
    return json.dumps(users)


@application.put("/auth/admin/users/<email:path>")
@check_referer
def admin_update_user(email: str) -> str:
    user = webutils.get_user()
    if user is None:
        abort(401, "Authentication required")
    if db.auth is None:
        abort(500, "Authentication backend not configured")
    user_doc = db.auth.get_user_by_email(user)
    if not user_doc or not user_doc.get("is_admin"):
        abort(403, "Admin access required")
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
