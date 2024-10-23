#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
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

from __future__ import annotations  # drop when Python 3.10+ only is supported

from typing import Any, Callable, TypeVar

class Bottle:
    def mount(self, prefix: str, app: Bottle) -> None: ...

class HTTPResponse: ...

# https://mypy.readthedocs.io/en/stable/generics.html#decorator-factories
F = TypeVar("F", bound=Callable[..., Any])

def get(
    path: str | None = None, method: str = "GET", **options: Any
) -> Callable[[F], F]: ...
def default_app() -> Bottle: ...
def static_file(
    filename: str,
    root: str,
    mimetype: str = "auto",
    download: bool = False,
    charset: str = "UTF-8",
) -> HTTPResponse: ...
def redirect(url: str, code: int | None = None) -> None: ...
def run(
    app: Bottle | None = None,
    server: str = "wsgiref",
    host: str = "127.0.0.1",
    port: int = 8080,
    interval: int = 1,
    reloader: bool = False,
    quiet: bool = False,
    debug: bool | None = None,
) -> None: ...
