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

"""This sub-module contains functions to interact with another IVRE
instance via an HTTP server.

"""


from functools import partial
import json
from urllib.parse import quote
from urllib.request import URLopener


from ivre.db import DB, DBActive, DBNmap, DBView


class HttpDB(DB):

    flt_empty = {}

    def __init__(self, url):
        super().__init__()
        self.baseurl = url._replace(fragment="").geturl()
        self.db = urlop = URLopener()
        for hdr, val in (
            tuple(x.split("=", 1)) if "=" in x else (x, "")
            for x in url.fragment.split("&")
            if x
        ):
            urlop.addheader(hdr, val)

    @staticmethod
    def _output_filter(spec):
        return quote(json.dumps(spec, separators=(",", ":"), indent=None))

    def get(self, spec, limit=None, skip=None, sort=None, fields=None):
        url = "%s/%s?f=%s&q=skip:" % (
            self.baseurl,
            self.route,
            self._output_filter(spec),
        )
        if skip is None:
            skip = 0
        while True:
            cururl = "%s%d" % (url, skip)
            if limit is not None:
                cururl += "%%20limit:%d" % limit
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
        url = "%s/%s/count?f=%s" % (self.baseurl, self.route, self._output_filter(spec))
        req = self.db.open(url)
        return int(req.read().rstrip(b"\n"))

    @staticmethod
    def flt_and(*args):
        return {"f": "and", "a": list(a for a in args if a)}

    @classmethod
    def flt_or(cls, *args):
        return {"f": "or", "a": list(args)}

    @staticmethod
    def _search(func, *args, **kargs):
        return dict(
            f=func, **{"a": list(args)} if args else {}, **{"k": kargs} if kargs else {}
        )

    def __getattribute__(self, attr):
        if attr.startswith("search") and attr[6:]:
            return partial(self._search, attr[6:])
        return super().__getattribute__(attr)


class HttpDBActive(HttpDB, DBActive):

    pass


class HttpDBNmap(HttpDBActive, DBNmap):

    route = "scans"


class HttpDBView(HttpDBActive, DBView):

    route = "view"
