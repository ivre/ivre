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
import sys

try:
    from ivre import config, utils, webutils, VERSION
except Exception as exc:
    sys.stdout.write('Content-Type: application/javascript\r\n\r\n')
    sys.stdout.write(
        'alert("ERROR: Could not import ivre. Check the server\'s logs!");'
    )
    sys.stderr.write(
        "CRITICAL:ivre:Cannot import ivre [%s (%r)].\n" % (exc.message, exc)
    )
    sys.exit(1)


def main():
    # write headers
    sys.stdout.write(webutils.JS_HEADERS)
    sys.stdout.write("\r\n")
    sys.stdout.writelines(
        'config.%s = %s;\n' % (key, json.dumps(value))
        for key, value in {
                "notesbase": config.WEB_NOTES_BASE,
                "dflt_limit": config.WEB_LIMIT,
                "warn_dots_count": config.WEB_WARN_DOTS_COUNT,
                "publicsrv": config.WEB_PUBLIC_SRV,
                "uploadok": config.WEB_UPLOAD_OK,
                "flow_time_precision": config.FLOW_TIME_PRECISION,
                "version": VERSION,
        }.iteritems()
    )


if __name__ == '__main__':
    main()
