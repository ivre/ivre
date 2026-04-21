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

The MCP server uses a :class:`TokenVerifier` that bridges
``Authorization: Bearer <token>`` (as sent by MCP clients such as
Claude Desktop or Claude Code over HTTP) to the IVRE API-key
infrastructure already used by the Web UI
(:func:`ivre.db.DBAuth.validate_api_key`).

The ``AccessToken`` returned by :meth:`IvreTokenVerifier.verify_token`
stores the authenticated user's email in the ``client_id`` field and
the user's groups in the ``scopes`` list. Downstream MCP tools can
retrieve the email with :func:`current_user_email`.
"""

from __future__ import annotations

from typing import Any

from ivre import utils

try:
    from mcp.server.auth.middleware.auth_context import get_access_token
    from mcp.server.auth.provider import AccessToken, TokenVerifier
except ImportError:  # pragma: no cover - optional dependency
    AccessToken = None
    TokenVerifier = object

    def get_access_token() -> Any | None:
        return None


class IvreTokenVerifier(TokenVerifier):
    """Verify MCP bearer tokens against the IVRE API-key store."""

    async def verify_token(self, token: str) -> Any | None:
        """Return an :class:`AccessToken` if ``token`` matches an active
        IVRE API key, or ``None`` otherwise.
        """
        from ivre.db import db  # pylint: disable=import-outside-toplevel

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
        groups = list(user.get("groups", []) or [])
        return AccessToken(
            token=token,
            client_id=user["email"],
            scopes=groups,
        )


def current_user_email() -> str | None:
    """Return the authenticated user email from the current MCP call.

    Returns ``None`` outside of an MCP HTTP request context or when the
    caller is anonymous.
    """
    access_token = get_access_token()
    if access_token is None:
        return None
    # client_id is set to the user email by IvreTokenVerifier; for
    # anonymous/other providers we return whatever value is there so
    # that ``WEB_INIT_QUERIES`` keyed on a non-email string still works.
    return access_token.client_id or None


def current_user_groups() -> list[str]:
    """Return the authenticated user groups, or an empty list."""
    access_token = get_access_token()
    if access_token is None:
        return []
    return list(access_token.scopes or [])
