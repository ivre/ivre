#! /usr/bin/env python

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


"""Web-module exposure helpers.

The web layer exposes a fixed set of "data section" modules: each
maps to one (or, in the case of ``dns``, two) ``db.<purpose>``
backends. An operator can narrow that set via the ``WEB_MODULES``
config knob; the effective set is the intersection of
``WEB_MODULES`` (or every known module when unset) and the
backends actually configured.

The same enabled-list is consumed by:

  - ``/cgi/config`` (server-side), so the React UI can hide nav
    entries for modules the server does not expose;
  - the per-route ``require_module()`` gate, so direct HTTP probes
    against a disabled module return 404.

This module is import-light on purpose (no Bottle imports at
module load) so it can be reused from CLIs and the unit-test
suite without spinning up the web app.
"""

from __future__ import annotations

from collections.abc import Sequence

from bottle import abort

from ivre import config
from ivre.db import db

# Canonical order. The React UI does not rely on this order
# (``SECTIONS`` in ``web-ui/src/lib/sections.ts`` carries its own),
# but emitting it deterministically makes ``/cgi/config`` diffable
# in operator runbooks.
ALL_MODULES: tuple[str, ...] = (
    "view",
    "active",
    "passive",
    "dns",
    "rir",
    "flow",
)

# Per-module backend requirements. A module is available when
# *all* its requirements are met, except for the ones in
# ``_BACKEND_REQUIRES_ANY`` where *any* requirement is enough.
_BACKEND_REQUIRES: dict[str, tuple[str, ...]] = {
    "view": ("view",),
    "active": ("nmap",),
    "passive": ("passive",),
    # ``dns`` is the merged ``db.nmap.iter_dns`` ∪
    # ``db.passive.iter_dns`` route; either backend on its own is
    # enough to surface useful DNS data.
    "dns": ("nmap", "passive"),
    "rir": ("rir",),
    "flow": ("flow",),
}

_BACKEND_REQUIRES_ANY: frozenset[str] = frozenset({"dns"})


def _backend_present(purpose: str) -> bool:
    """Return ``True`` when ``db.<purpose>`` is wired (``not
    None``). The ``MetaDB`` property returns ``None`` when no
    ``DB_<purpose>`` URL falls through from the operator's
    ``ivre.conf``."""
    return getattr(db, purpose, None) is not None


def _module_available(module: str) -> bool:
    """Return ``True`` when ``module``'s backend requirement is
    met. Unknown modules are reported as unavailable."""
    reqs = _BACKEND_REQUIRES.get(module)
    if reqs is None:
        return False
    check = any if module in _BACKEND_REQUIRES_ANY else all
    return check(_backend_present(p) for p in reqs)


def enabled_modules() -> list[str]:
    """Return the canonically-ordered list of modules currently
    exposed by this server. The result is the intersection of
    the operator's ``WEB_MODULES`` allowlist (or every module
    when ``WEB_MODULES is None``) and the modules whose backends
    are configured.

    Recomputed on every call so reloading ``ivre.conf`` or
    swapping the ``MetaDB`` urls in tests is picked up
    immediately."""
    allowlist: Sequence[str]
    if config.WEB_MODULES is None:
        allowlist = ALL_MODULES
    else:
        allowlist = config.WEB_MODULES
    requested = set(allowlist)
    return [m for m in ALL_MODULES if m in requested and _module_available(m)]


def is_module_enabled(module: str) -> bool:
    """Convenience wrapper around :func:`enabled_modules`."""
    return module in enabled_modules()


def require_module(module: str) -> None:
    """Bottle helper: ``abort(404)`` when ``module`` is not in
    the currently-exposed set. 404 (rather than 503) so direct
    probes against a disabled module look like the endpoint
    never existed, matching the React UI's catch-all behaviour
    for unknown sections."""
    if not is_module_enabled(module):
        abort(404, f"Module {module!r} is not exposed by this server.")
