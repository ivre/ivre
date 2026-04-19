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

from functools import wraps

from bottle import Bottle, request, response

from ivre import config, utils
from ivre.web import utils as webutils

application = Bottle()


@application.hook("after_request")
def add_security_headers():
    response.set_header("X-Frame-Options", "DENY")
    response.set_header("Content-Security-Policy", "frame-ancestors 'none'")


def check_referer(func):
    """Wrapper for route functions to implement a basic anti-CSRF check
    based on the Referer: header.

        It will abort (status code 400) if the referer is invalid.

    """

    if config.WEB_ALLOWED_REFERERS is False:
        return func

    def _die(referer):
        utils.LOGGER.critical("Invalid Referer header [%r]", referer)
        response.set_header("Content-Type", "application/javascript")
        response.status = "400 Bad Request"
        return webutils.js_alert(
            "referer", "error", "Invalid Referer header. Check your configuration."
        )

    @wraps(func)
    def _newfunc(*args, **kargs):
        # Header with an existing X-API-Key header or an
        # Authorization: Bearer XXX are OK as anti-CSRF protections.
        # When auth is enabled, they are also validated against the
        # auth backend in get_user().
        if request.headers.get("X-API-Key") or (
            request.headers.get("Authorization")
            and (
                request.headers.get("Authorization", "").split(None, 1)[0].lower()
                == "bearer"
            )
        ):
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
