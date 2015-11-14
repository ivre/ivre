#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This program is part of IVRE.
#
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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

from ivre import config

import os

from BaseHTTPServer import HTTPServer
from CGIHTTPServer import CGIHTTPRequestHandler

BASEDIR, CGIDIR, DOKUWIKIDIR = None, None, None

class IvreRequestHandler(CGIHTTPRequestHandler):
    """Request handler to serve both static files from
    [PREFIX]/share/ivre/web/static/ and the CGI from
    [PREFIX]/share/ivre/web/cgi-bin/.

    """
    def translate_path(self, path):
        if not path:
            return path
        if path.startswith('/cgi-bin/'):
            return os.path.join(CGIDIR, os.path.basename(path))
        if path.startswith('/dokuwiki/'):
            path = os.path.basename(path).lower().replace(':', '/')
            if '.' not in os.path.basename(path):
                path += '.txt'
            print os.path.join(DOKUWIKIDIR, path)
            return os.path.join(DOKUWIKIDIR, path)
        while path.startswith('/'):
            path = path[1:]
        path = os.path.join(BASEDIR, path)
        if path.startswith(BASEDIR):
            return path
        raise ValueError("Invalid translated path")

def parse_args():
    """Imports the available module to parse the arguments and return
    the parsed arguments.

    """
    try:
        import argparse
        parser = argparse.ArgumentParser(description=__doc__)
    except ImportError:
        import optparse
        parser = optparse.OptionParser(description=__doc__)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
    parser.add_argument('--bind-address', '-b',
                        help='(IP) Address to bind the server to (defaults '
                        'to 127.0.0.1).',
                        default="127.0.0.1")
    parser.add_argument('--port', '-p', type=int, default=80,
                        help='(TCP) Port to use (defaults to 80)')
    return parser.parse_args()


def main():
    """This function is called when __name__ == "__main__"."""
    global BASEDIR, CGIDIR, DOKUWIKIDIR
    print __doc__
    BASEDIR = config.guess_prefix(directory='web/static')
    CGIDIR = config.guess_prefix(directory='web/cgi-bin')
    DOKUWIKIDIR = config.guess_prefix(directory='dokuwiki')
    if BASEDIR is None or CGIDIR is None or DOKUWIKIDIR is None:
        raise Exception('Cannot find where IVRE is installed')
    args = parse_args()
    httpd = HTTPServer((args.bind_address, args.port), IvreRequestHandler)
    httpd.serve_forever()
