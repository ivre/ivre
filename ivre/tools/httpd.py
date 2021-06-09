#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
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


"""
This program runs a simple httpd server to provide an out-of-the-box
access to the web user interface.

This script should only be used for testing purposes. Production
deployments should use "real" web servers (IVRE has been successfully
tested with both Apache and Nginx).
"""


from argparse import ArgumentParser, Namespace
import os


from bottle import HTTPResponse, default_app, get, redirect, run, static_file


from ivre.config import DEBUG, WEB_DOKU_PATH, WEB_STATIC_PATH
from ivre.web import app as webapp


#
# Index page
#


@get("/")
def server_index() -> None:
    """Needed to redirect / to index.html"""
    redirect("index.html")


@get("/doc")
def server_doc_index() -> None:
    """Needed to redirect / to index.html"""
    redirect("doc/index.html")


@get("/doc/<subdir:re:dev|install|usage>")
def server_doc_subindex(subdir: str) -> None:
    """Needed to redirect / to index.html"""
    redirect("%s/index.html" % subdir)


@get("/doc/")
@get("/doc/<:re:dev|install|usage>/")
def server_doc_subindex2() -> None:
    """Needed to redirect / to index.html"""
    redirect("index.html")


#
# Static files
#


@get("/dokuwiki/<filepath:path>")
def server_doku(filepath: str) -> HTTPResponse:
    """This function serves Dokuwiki files as static text files. This is
    far from being great...

    """
    filepath = filepath.lower().replace(":", "/")
    if "." not in os.path.basename(filepath):
        filepath += ".txt"
    assert WEB_DOKU_PATH is not None
    return static_file(filepath, root=WEB_DOKU_PATH)


@get("/<filepath:path>")
def server_static(filepath: str) -> HTTPResponse:
    """Serve the static (HTML, JS, CSS, ...) content."""
    assert WEB_STATIC_PATH is not None
    return static_file(filepath, root=WEB_STATIC_PATH)


def parse_args() -> Namespace:
    """Imports the available module to parse the arguments and return
    the parsed arguments.

    """
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bind-address",
        "-b",
        default="127.0.0.1",
        help="(IP) Address to bind the server to (defaults to 127.0.0.1).",
    )
    parser.add_argument(
        "--port", "-p", type=int, default=80, help="(TCP) Port to use (defaults to 80)"
    )
    return parser.parse_args()


def main() -> None:
    """Function run when the tool is called."""
    args = parse_args()
    print(__doc__)
    application = default_app()
    application.mount("/cgi/", webapp.application)
    run(host=args.bind_address, port=args.port, debug=DEBUG)
