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

"""ASGI middleware for the IVRE MCP HTTP transport.

This module exposes :class:`PublicUrlRewriteMiddleware`, which rewrites
the OAuth-discovery URLs that FastMCP / Starlette emit on behalf of the
MCP server so they reflect the public origin the client actually used,
rather than a value frozen at server-startup time.

Rationale
---------

``mcp.server.auth.settings.AuthSettings.resource_server_url`` is captured
once when the FastMCP application is built. FastMCP then bakes the
configured URL into:

* the ``WWW-Authenticate: Bearer ..., resource_metadata="..."`` header
  emitted on 401 responses by ``RequireAuthMiddleware``, and
* the JSON body served at ``/.well-known/oauth-protected-resource{path}``
  (the ``resource`` and ``authorization_servers`` fields of an
  :class:`mcp.shared.auth.ProtectedResourceMetadata` document).

A bind-address-and-port heuristic for that value is wrong in every
realistic deployment (the bind address is the *internal* one, behind
nginx; the scheme on the public side is typically ``https`` even when
the bind is loopback). To avoid a config knob, we instead set the
field at startup to a fixed sentinel value rooted at the RFC 2606
reserved TLD ``placeholder.invalid``, and use this middleware to
rewrite the sentinel to the request-derived public origin on its way
out.

Trust model
-----------

The public origin is derived from each request's ``Host:`` and
``X-Forwarded-Proto:`` headers, the same trust surface as
:func:`ivre.web.base.check_referer`. The reference nginx snippet
shipped with IVRE forwards both correctly. Hostile values only ever
poison the OAuth-discovery URL the *attacker themselves* receive, so
the surface is information-neutral.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

# ASGI message / scope aliases. Starlette ships its own typing module
# but we don't want a hard runtime import on Starlette outside of the
# MCP HTTP path; describe the protocol structurally instead.
Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class PublicUrlRewriteMiddleware:
    """Rewrite OAuth-discovery URLs in MCP responses.

    The MCP HTTP server is started with
    ``AuthSettings.resource_server_url`` set to a fixed sentinel
    (``http://placeholder.invalid<path>``); this middleware substitutes
    the sentinel scheme+host with the public origin derived from the
    current request's ``Host:`` and ``X-Forwarded-Proto:`` headers.

    Rewriting happens in two places:

    * the ``WWW-Authenticate`` response header (a one-shot bytes
      replacement on 401 responses), and
    * the JSON body of responses to paths under
      ``/.well-known/oauth-protected-resource``.

    All other requests pass through untouched: the middleware is
    careful not to buffer streaming responses (the MCP endpoint itself
    relies on Server-Sent Events).
    """

    SENTINEL: bytes = b"http://placeholder.invalid"
    _WK_PREFIX: str = "/.well-known/oauth-protected-resource"

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        public_origin = self._public_origin(scope).encode("latin-1")
        if public_origin == self.SENTINEL:
            # Nothing meaningful to substitute; skip the wrapper.
            await self.app(scope, receive, send)
            return

        rewrite_body = scope.get("path", "").startswith(self._WK_PREFIX)

        body_chunks: list[bytes] = []
        start_message: Message | None = None

        async def _send(message: Message) -> None:
            nonlocal start_message
            mtype = message.get("type")

            if mtype == "http.response.start":
                # Always rewrite WWW-Authenticate; only buffer-and-rewrite
                # the body on the well-known paths.
                headers = [
                    (
                        name,
                        (
                            value.replace(self.SENTINEL, public_origin)
                            if name.lower() == b"www-authenticate"
                            else value
                        ),
                    )
                    for name, value in message.get("headers", [])
                ]
                rewritten = dict(message)
                rewritten["headers"] = headers
                if rewrite_body:
                    # Defer flushing the start message until we have
                    # the full body and can recompute Content-Length.
                    start_message = rewritten
                    return
                await send(rewritten)
                return

            if mtype == "http.response.body" and rewrite_body:
                body_chunks.append(message.get("body", b""))
                if message.get("more_body"):
                    return
                assert start_message is not None
                body = b"".join(body_chunks).replace(self.SENTINEL, public_origin)
                headers = [
                    (
                        name,
                        (
                            str(len(body)).encode("latin-1")
                            if name.lower() == b"content-length"
                            else value
                        ),
                    )
                    for name, value in start_message["headers"]
                ]
                final_start = dict(start_message)
                final_start["headers"] = headers
                await send(final_start)
                await send({"type": "http.response.body", "body": body})
                return

            await send(message)

        await self.app(scope, receive, _send)

    @staticmethod
    def _public_origin(scope: Scope) -> str:
        """Return ``scheme://host`` derived from the request scope.

        Honours ``Host:`` and ``X-Forwarded-Proto:``. Falls back to the
        ASGI ``server`` tuple and ``scheme`` keys when those headers are
        absent (e.g. HTTP/1.0 clients hitting the bind address
        directly).
        """
        host: str | None = None
        proto: str | None = None
        for name, value in scope.get("headers", []):
            lname = name.lower()
            if lname == b"host" and host is None:
                host = value.decode("latin-1")
            elif lname == b"x-forwarded-proto" and proto is None:
                # Take the leftmost value if the header is a list.
                proto = value.split(b",", 1)[0].strip().decode("latin-1")
        if host is None:
            server = scope.get("server") or ("localhost", None)
            if server[1]:
                host = f"{server[0]}:{server[1]}"
            else:
                host = str(server[0])
        if not proto:
            proto = scope.get("scheme") or "http"
        return f"{proto}://{host}"
