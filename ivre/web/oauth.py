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

"""OAuth2 provider implementations using stdlib only."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

from ivre import VERSION, config, utils

USER_AGENT = f"IVRE/{VERSION} +https://ivre.rocks/"

PROVIDERS: dict[str, dict[str, Any]] = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scopes": "openid email profile",
        "client_id_config": "WEB_AUTH_GOOGLE_CLIENT_ID",
        "client_secret_config": "WEB_AUTH_GOOGLE_CLIENT_SECRET",
    },
    "microsoft": {
        "authorize_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scopes": "openid email profile User.Read",
        "client_id_config": "WEB_AUTH_MICROSOFT_CLIENT_ID",
        "client_secret_config": "WEB_AUTH_MICROSOFT_CLIENT_SECRET",
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "emails_url": "https://api.github.com/user/emails",
        "scopes": "user:email",
        "client_id_config": "WEB_AUTH_GITHUB_CLIENT_ID",
        "client_secret_config": "WEB_AUTH_GITHUB_CLIENT_SECRET",
    },
}


def _discover_oidc() -> dict[str, str] | None:
    """Fetch OIDC Discovery document and extract endpoints.

    Returns a dict with authorize_url, token_url, userinfo_url or None
    on failure.
    """
    if not config.WEB_AUTH_OIDC_DISCOVERY_URL:
        return None
    try:
        req = urllib.request.Request(
            config.WEB_AUTH_OIDC_DISCOVERY_URL,
            headers={"User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            doc = json.loads(resp.read())
        return {
            "authorize_url": doc["authorization_endpoint"],
            "token_url": doc["token_endpoint"],
            "userinfo_url": doc["userinfo_endpoint"],
        }
    except Exception:
        utils.LOGGER.warning(
            "OIDC Discovery failed for %s",
            config.WEB_AUTH_OIDC_DISCOVERY_URL,
            exc_info=True,
        )
        return None


_oidc_discovered: dict[str, str] | None = None
_oidc_discovered_done = False


def _get_oidc_endpoints() -> dict[str, str] | None:
    """Return OIDC endpoints, using discovery (cached) or manual config."""
    global _oidc_discovered, _oidc_discovered_done  # noqa: PLW0603
    if not _oidc_discovered_done:
        _oidc_discovered = _discover_oidc()
        _oidc_discovered_done = True
    if _oidc_discovered:
        return _oidc_discovered
    # Fall back to manually configured URLs
    if config.WEB_AUTH_OIDC_AUTHORIZE_URL and config.WEB_AUTH_OIDC_TOKEN_URL:
        return {
            "authorize_url": config.WEB_AUTH_OIDC_AUTHORIZE_URL,
            "token_url": config.WEB_AUTH_OIDC_TOKEN_URL,
            "userinfo_url": config.WEB_AUTH_OIDC_USERINFO_URL or "",
        }
    return None


if config.WEB_AUTH_OIDC_CLIENT_ID:
    PROVIDERS["oidc"] = {
        "scopes": config.WEB_AUTH_OIDC_SCOPES,
        "client_id_config": "WEB_AUTH_OIDC_CLIENT_ID",
        "client_secret_config": "WEB_AUTH_OIDC_CLIENT_SECRET",
    }


def get_enabled_providers() -> list[str]:
    """Return list of provider names that have client_id configured."""
    enabled = []
    for name, prov in PROVIDERS.items():
        client_id = getattr(config, prov["client_id_config"], None)
        if client_id:
            enabled.append(name)
    return enabled


def _get_provider_url(provider: str, prov: dict[str, Any], key: str) -> str:
    """Return a provider URL, resolving OIDC endpoints dynamically."""
    if provider == "oidc":
        endpoints = _get_oidc_endpoints()
        if endpoints is None:
            raise ValueError("OIDC endpoints not configured")
        return endpoints[key]
    url = prov[key]
    if provider == "microsoft":
        url = url.format(tenant=config.WEB_AUTH_MICROSOFT_TENANT)
    return url


def get_authorize_url(provider: str, state: str, redirect_uri: str) -> str:
    """Build the OAuth2 authorization URL for a provider."""
    prov = PROVIDERS[provider]
    client_id = getattr(config, prov["client_id_config"])
    authorize_url = _get_provider_url(provider, prov, "authorize_url")
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": prov["scopes"],
        "state": state,
    }
    return f"{authorize_url}?{urllib.parse.urlencode(params)}"


def exchange_code(provider: str, code: str, redirect_uri: str) -> dict[str, Any]:
    """Exchange an authorization code for tokens."""
    prov = PROVIDERS[provider]
    client_id = getattr(config, prov["client_id_config"])
    client_secret = getattr(config, prov["client_secret_config"])
    token_url = _get_provider_url(provider, prov, "token_url")
    data = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
    ).encode()
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    req = urllib.request.Request(token_url, data=data, headers=headers)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def get_user_email(
    provider: str, tokens: dict[str, Any]
) -> tuple[str | None, str | None]:
    """Extract user email and display name from OAuth tokens.

    Returns (email, display_name) tuple.
    """
    prov = PROVIDERS[provider]
    access_token = tokens.get("access_token")

    # Always use the userinfo endpoint rather than decoding the ID
    # token JWT. The ID token would need signature verification
    # (via the provider's JWKS) to be trustworthy; the userinfo
    # endpoint is authoritative and verified by the TLS connection.
    userinfo_url = _get_provider_url(provider, prov, "userinfo_url")
    if not userinfo_url:
        return None, None
    headers = {
        "Authorization": f"Bearer {access_token}",
        "User-Agent": USER_AGENT,
    }
    req = urllib.request.Request(userinfo_url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        userinfo = json.loads(resp.read())

    if provider == "github":
        email = userinfo.get("email")
        name = userinfo.get("name") or userinfo.get("login")
        if not email:
            # GitHub may not return email in profile; fetch from emails API
            email = _github_get_primary_email(access_token)
        return email, name

    if provider == "microsoft":
        return userinfo.get("mail") or userinfo.get("userPrincipalName"), userinfo.get(
            "displayName"
        )

    # Google and other OIDC
    return userinfo.get("email"), userinfo.get("name")


def _github_get_primary_email(access_token: str) -> str | None:
    """Fetch the primary verified email from GitHub's emails API."""
    headers = {"Authorization": f"Bearer {access_token}", "User-Agent": USER_AGENT}
    req = urllib.request.Request(PROVIDERS["github"]["emails_url"], headers=headers)
    with urllib.request.urlopen(req) as resp:
        emails = json.loads(resp.read())
    for entry in emails:
        if entry.get("primary") and entry.get("verified"):
            return entry["email"]
    # Fall back to any verified email
    for entry in emails:
        if entry.get("verified"):
            return entry["email"]
    return None
