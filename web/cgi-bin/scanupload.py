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

import sys
import cgi
import zlib
import bz2
import tempfile

try:
    from ivre import config, utils, webutils
    from ivre.db import db
except Exception as exc:
    sys.stdout.write('Content-Type: text/plain\r\n\r\n')
    sys.stdout.write(
        "ERROR: Could not import ivre. Check the server's logs!\n"
    )
    sys.stderr.write(
        "CRITICAL:ivre:Cannot import ivre [%s (%r)].\n" % (exc.message, exc)
    )
    sys.exit(1)

if not config.WEB_UPLOAD_OK:
    sys.stdout.write('Content-Type: text/plain\r\n\r\n')
    sys.stdout.write(
        "ERROR: upload not allowed (set 'WEB_UPLOAD_OK = True' in "
        "ivre.conf)\n"
    )
    utils.LOGGER.critical("Upload not allowed (set 'WEB_UPLOAD_OK = True' in "
                          "ivre.conf)")
    sys.exit(1)

def parse_form():
    form = cgi.FieldStorage()
    categories = (set(form["categories"].value.split(','))
                  if "categories" in form and form["categories"] else set())
    try:
        source = form["source"].value
    except KeyError:
        sys.stdout.write('Content-Type: text/plain\r\n\r\n')
        sys.stdout.write("ERROR: source is mandatory\n")
        utils.LOGGER.critical("source is mandatory")
        sys.exit(1)
    files = form["result"]
    files = ([felt.value for felt in files]
             if isinstance(files, list) else
             [files.value])
    if config.WEB_PUBLIC_SRV:
        if webutils.get_user() is None:
            sys.stdout.write('Content-Type: text/plain\r\n\r\n')
            sys.stdout.write(
                "ERROR: username is mandatory on public instances\n"
            )
            utils.LOGGER.critical("username is mandatory on public instances")
            sys.exit(0)
        if "public" in form and form["public"].value == "on":
            categories.add("Shared")
        if webutils.get_user() is not None:
            user = webutils.get_anonymized_user()
            categories.add(user)
            source = "%s-%s" % (user, source)
    return (form["referer"].value if "referer" in form else None,
            source, categories, files)

def import_files(source, categories, files):
    # archive records from same source
    def gettoarchive(addr, source):
        return db.nmap.get(
            db.nmap.flt_and(db.nmap.searchhost(addr),
                            db.nmap.searchsource(source))
        )
    count = 0
    for fileelt in files:
        if fileelt.startswith('\x1f\x8b'):
            fileelt = zlib.decompress(fileelt, 16+zlib.MAX_WBITS)
        elif fileelt.startswith('BZ'):
            fileelt = bz2.decompress(fileelt)
        with tempfile.NamedTemporaryFile(delete=False) as fdesc:
            fdesc.write(fileelt)
        if db.nmap.store_scan(fdesc.name, categories=list(categories),
                              source=source, gettoarchive=gettoarchive):
            count += 1
            fdesc.unlink(fdesc.name)
        else:
            utils.LOGGER.warning("Could not import %s" % fdesc.name)
    return count

def main():
    webutils.check_referer()
    referer, source, categories, files = parse_form()
    count = import_files(source, categories, files)
    sys.stdout.write('Content-Type: text/html\r\n')
    if referer:
        sys.stdout.write('Refresh: 5;url=%s\r\n' % referer)
    sys.stdout.write('\r\n')
    sys.stdout.write("""<html>
  <head>
    <title>IVRE Web UI</title>
  </head>
  <body style="padding-top: 2%%; padding-left: 2%%">
    <h1>%d result%s uploaded</h1>
  </body>
</html>""" % (count, 's' if count > 1 else ''))

if __name__ == "__main__":
    main()
