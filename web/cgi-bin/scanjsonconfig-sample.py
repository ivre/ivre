# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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

# This is for anti-CSRF check. Set this to None to disable the
# check. But you probably don't want that.
ALLOWED_REFERERS = [
    'http://localhost/',
    'http://localhost/index.html'
]
# MAXRESULTS = None

# Initial queries. Use it for access control

# No access control (that's the default)
# INIT_QUERIES = {}
# DEFAULT_INIT_QUERY = {}

# Simple ACL
# from ivre.db import db
# INIT_QUERIES = {
#     'admin': db.nmap.flt_empty,
#     'admin-site-a': db.nmap.searchcategory('site-a'),
#     'admin-scanner-a': db.nmap.searchsource('scanner-a')
# }
# DEFAULT_INIT_QUERY = db.nmap.searchhost('inexistant')

# More complex with realm handling
# class Users(object):
#     def __init__(self, Users={}, Realms={}):
#         self.Users = Users
#         self.Realms = Realms
#     def get(self, user, default):
#         if type(user) is str and '@' in user:
#             realm = user[user.index('@')+1:]
#         else: realm = None
#         return self.Users.get(user, self.Realms.get(realm, default))
# from ivre.db import db
# INIT_QUERIES = Users(Users={"admin": db.nmap.flt_empty},
#                      Realms={"admin.sitea": db.nmap.searchcategory('sitea')})
# DEFAULT_INIT_QUERY = db.nmap.searchhost('inexistant')

# Warn the user he is about to display a *lot* of dots and it might be
# a lot of work for his browser or event freeze/crash it.
# WARN_DOTS_COUNT = 20000

# Default values (overridden by query)
# These settings must be coherent with those in static/scan.js
# skip = 0
# limit = 10

# This is an example that should work with a local dokuwiki
# installation using distribution packages on Debian/Ubuntu and
# RHEL/CentOS.
import ivre.utils
import re
import os
ipaddr = re.compile('^\d+\.\d+\.\d+\.\d+$')
get_notepad_pages = lambda: [
    ivre.utils.ip2int(x[:-4])
    for x in os.listdir("/var/lib/dokuwiki/data/pages")
    if x.endswith('.txt') and ipaddr.match(x[:-4])
]

# Another example which should work with a remote MediaWiki, when
# relevant pages start with "IvreNotepad/".
# import ivre.utils
# import MySQLdb
# def get_notepad_pages():
#     c = MySQLdb.Connect("dbserver", "user", "password", "dbname").cursor()
#     c.execute("SELECT `page_title` FROM `wiki_page` WHERE `page_title` "
#               "REGEXP '^IvreNotepad/[0-9]+\\\.[0-9]+\\\.[0-9]+\\\.[0-9]+$'")
#     ## [12:] because len("IvreNotepad/") == 12
#     return [ivre.utils.ip2int(x[0][12:]) for x in c]


# If you don't need this, use:
# get_notepad_pages = None
