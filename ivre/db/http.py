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
except ImportError:
    from urllib import URLopener


from ivre.db import DB, DBActive, DBNmap, DBView


class HttpDB(DB):

    flt_empty = ""

    def __init__(self, url):
        super(HttpDB, self).__init__()
        self.baseurl = url._replace(fragment="").geturl()
        self.db = urlop = URLopener()
        for hdr, val in (
            tuple(x.split("=", 1)) if "=" in x else (x, "")
            for x in url.fragment.split("&")
            if x
        ):
            urlop.addheader(hdr, val)

    def get(self, spec, limit=None, skip=None, sort=None, fields=None):
        url = '%s/%s?q=%sskip:' % (self.baseurl, self.route,
                                   ('%s%%20' % spec) if spec else '')
        if skip is None:
            skip = 0
        while True:
            cururl = '%s%d' % (url, skip)
            if limit is not None:
                cururl += '%%20limit:%d' % limit
            req = self.db.open(cururl)
            data = json.loads(req.read().decode())
            if not data:
                break
            if limit is None:
                for rec in data:
                    yield rec
            else:
                for rec in data:
                    yield rec
                    limit -= 1
                    if limit == 0:
                        break
                if limit == 0:
                    break
            skip += len(data)

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
