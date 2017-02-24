#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
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

import json
import logging
import random
import sys
import time

try:
    from ivre import config, utils, webutils
    from ivre.db import db
    from ivre.utils import str2pyval
except Exception as exc:
    sys.stdout.write('Content-Type: application/javascript\r\n\r\n')
    sys.stdout.write(
        'alert("ERROR: Could not import ivre. Check the server\'s logs!");'
    )
    sys.stderr.write(
        "CRITICAL:ivre:Cannot import ivre [%s (%r)].\n" % (exc.message, exc)
    )
    sys.exit(1)

logging.basicConfig(level=logging.ERROR)
log = logging.getLogger("flowjson")
log.setLevel(logging.DEBUG)

webutils.check_referer()


def main():
    # write headers
    sys.stdout.write(webutils.JS_HEADERS)
    params = webutils.parse_query_string()

    callback = params.get("callback")

    action = params.get("action", "")
    if callback is None:
        sys.stdout.write('Content-Disposition: attachment; '
                         'filename="IVRE-results.json"\r\n')
    sys.stdout.write("\r\n")

    if callback is not None:
        sys.stdout.write(webutils.js_del_alert("param-unused"))
        sys.stdout.write("%s(\n" % callback)


    log.info("%s", params)
    query = json.loads(params.get('q', {}) or "{}")
    limit = query.get("limit", config.WEB_GRAPH_LIMIT)
    skip = query.get("skip", config.WEB_GRAPH_LIMIT)
    mode = query.get("mode", "default")
    count = query.get("count", False)
    orderby = query.get("orderby", None)
    timeline = query.get("timeline", False)
    log.info("Query: %s", query)

    if action == "details":
        # TODO: error
        if "Host" in query["labels"]:
            res = db.flow.host_details(query["id"])
        else:
            res = db.flow.flow_details(query["id"])
    else:
        cquery = db.flow.from_filters(query, limit=limit, skip=skip,
                                      orderby=orderby, mode=mode,
                                      timeline=timeline)
        if count:
            res = db.flow.count(cquery)
        else:
            res = db.flow.to_graph(cquery)

    sys.stdout.write("%s" % json.dumps(res, default=utils.serialize))

    if callback is not None:
        sys.stdout.write(");\n")

if __name__ == '__main__':
    main()
