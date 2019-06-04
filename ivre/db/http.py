#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2019 Pierre LALET <pierre.lalet@cea.fr>
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

"""This sub-module contains functions to interact with another IVRE
instance via an HTTP server.

"""


import json
try:
    from urllib.request import URLopener
    from urllib.parse import urlparse
except ImportError:
    from urllib import URLopener
    from urlparse import urlparse


from ivre.db import DB, DBActive, DBNmap, DBView


class HttpDB(DB):

    flt_empty = ""

    def __init__(self, url, **_):
        super(HttpDB, self).__init__()
        url = urlparse(url)
        self.baseurl = url._replace(fragment="").geturl()
        self.db = urlop = URLopener()
        for hdr, val in (
            tuple(x.split("=", 1)) if "=" in x else (x, "")
            for x in url.fragment.split("&")
            if x
        ):
            urlop.addheader(hdr, val)

    def get(self, spec, **kargs):
        # TODO: handle "pages"
        url = '%s/%s' % (self.baseurl, self.route)
        if spec:
            url += '?q=%s' % spec
        req = self.db.open(url)
        req.readline()
        for line in req:
            if line == b']\n':
                break
            line = line.rstrip(b'\n,')
            if line:
                yield json.loads(line.decode())

    def count(self, spec, **kargs):
        url = '%s/%s/count' % (self.baseurl, self.route)
        if spec:
            url += '?q=%s' % spec
        req = self.db.open(url)
        return int(req.read().rstrip(b'\n'))

    @staticmethod
    def flt_and(*args):
        return '%20'.join(arg for arg in args if arg)


class HttpDBActive(HttpDB, DBActive):

    @staticmethod
    def searchhost(addr, neg=False):
        return '%s%s' % ('!' if neg else '', addr)


class HttpDBNmap(HttpDBActive, DBNmap):

    route = 'scans'


class HttpDBView(HttpDBActive, DBView):

    route = 'view'
