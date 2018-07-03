#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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

"""This sub-module contains functions that might be usefull to any CGI
script.

"""

import hmac
import functools
import datetime
import os
import re
import shlex
import sys
try:
    import MySQLdb
    HAVE_MYSQL = True
except ImportError:
    HAVE_MYSQL = False


from future.utils import viewitems
from past.builtins import basestring


from ivre import config, utils
from ivre.db import db


IPADDR = re.compile('^\\d+\\.\\d+\\.\\d+\\.\\d+$')
NETADDR = re.compile('^\\d+\\.\\d+\\.\\d+\\.\\d+'
                     '/\\d+(\\.\\d+\\.\\d+\\.\\d+)?$')


def js_alert(ident, level, message):
    """This function returns a string containing JS code to
    generate an alert message.

    """
    return ('try {add_message("%(ident)s", "%(level)s", "%(message)s");}\n'
            'catch(err) {alert("%(levelup)s: %(message)s");}\n'
            '' % {"ident": ident, "level": level, "levelup": level.upper(),
                  "message": message.replace('"', '\\"')})


def js_del_alert(ident):
    """This function returns a string containing JS code to
    remove an alert message.

    """
    return 'try {del_message("%s");} catch(err) {}\n' % ident


GET_NOTEPAD_PAGES = {}


def get_notepad_pages_localdokuwiki(pagesdir="/var/lib/dokuwiki/data/pages"):
    """Returns a list of the IP addresses for which a Dokuwiki page
    exists.

    """
    ipaddr_page = re.compile('^\\d+\\.\\d+\\.\\d+\\.\\d+\\.txt$')
    return [page[:-4]
            for page in os.listdir(pagesdir)
            if ipaddr_page.match(page)]


GET_NOTEPAD_PAGES["localdokuwiki"] = get_notepad_pages_localdokuwiki


if HAVE_MYSQL:
    def get_notepad_pages_mediawiki(server, username, password, dbname,
                                    base="IvreNotepad"):
        """Returns a list of the IP addresses for which a Mediawiki
        page exists.

        """
        ipaddr_page = '^' + re.escape(base) + '\\/\\d+\\.\\d+\\.\\d+\\.\\d+$'
        cur = MySQLdb.Connect(server, username, password, dbname).cursor()
        cur.execute("SELECT `page_title` FROM `wiki_page` WHERE `page_title` "
                    "REGEXP '%s'" % ipaddr_page)
        return [page[0][len(base) + 1:] for page in cur]

    GET_NOTEPAD_PAGES["mediawiki"] = get_notepad_pages_mediawiki


def _find_get_notepad_pages():
    """This function finds and returns the get_notepad_pages() based
    on the configuration.

    """
    if config.WEB_GET_NOTEPAD_PAGES is None:
        return None
    if not isinstance(config.WEB_GET_NOTEPAD_PAGES, tuple):
        config.WEB_GET_NOTEPAD_PAGES = (config.WEB_GET_NOTEPAD_PAGES, ())
    return functools.partial(
        GET_NOTEPAD_PAGES[config.WEB_GET_NOTEPAD_PAGES[0]],
        *config.WEB_GET_NOTEPAD_PAGES[1]
    )


get_notepad_pages = _find_get_notepad_pages()


def query_from_params(params):
    """This function *consumes* the 'q' parameter (if it exists) and
    returns the query as a list of three elements list: [boolean
    `neg`, `param`, `value`].

    This function will write an error message and abort the CGI if an
    error occurs with `shlex.split()`.

    """
    try:
        query = params.pop('q')
    except KeyError:
        return []
    try:
        return [
            [neg] + pval.split(':', 1) if ':' in pval
            else [neg, pval, None]
            for neg, pval in (
                (True, x[1:]) if x[:1] in '!-' else (False, x)
                for x in shlex.split(query)
            )
        ]
    except ValueError as exc:
        sys.stdout.write(
            js_alert("param-parsing", "warning",
                     "Parameter parsing error. Check the server's logs "
                     "for more information.")
        )
        utils.LOGGER.critical('Parameter parsing error [%s (%r)]', exc, exc)
        raise ValueError("Parameter parsing error.")


def get_user():
    """Return the connected user.

    """
    return os.getenv('REMOTE_USER')


def get_anonymized_user():
    """Return the HMAC value of the current user authenticated with
    the HMAC secret.

    """
    return utils.encode_b64(hmac.new(config.WEB_SECRET,
                                     msg=get_user().encode()).digest()[:9])


def _parse_query(query):
    """Returns a DB filter (valid for db.view) from a query string
    usable in WEB_DEFAULT_INIT_QUERY and WEB_INIT_QUERIES
    configuration items.

    """
    if query is None:
        query = 'full'
    query = query.split(':')
    return {
        'full': lambda: db.view.flt_empty,
        'noaccess': db.view.searchnonexistent,
        'category': lambda cat: db.view.searchcategory(cat.split(',')),
    }[query[0]](*query[1:])


def get_init_flt():
    """Return a filter corresponding to the current user's
    privileges.

    """
    init_queries = dict([key, _parse_query(value)]
                        for key, value in viewitems(config.WEB_INIT_QUERIES))
    user = get_user()
    if user in init_queries:
        return init_queries[user]
    if isinstance(user, basestring) and '@' in user:
        realm = user[user.index('@'):]
        if realm in init_queries:
            return init_queries[realm]
    if config.WEB_PUBLIC_SRV:
        return db.view.searchcategory(["Shared", get_anonymized_user()])
    return _parse_query(config.WEB_DEFAULT_INIT_QUERY)


def flt_from_query(query, base_flt=None):
    """Return a tuple (`flt`, `sortby`, `unused`, `skip`, `limit`):

      - a filter based on the query

      - a list of [`key`, `order`] to sort results

      - a list of the unused elements of the query (errors)

      - an integer for the number of results to skip

      - an integer for the maximum number of results to return

    """
    unused = []
    sortby = []
    skip = 0
    limit = None
    flt = get_init_flt() if base_flt is None else base_flt

    def add_unused(neg, param, value):
        """Add to the `unused` list a string representing (neg, param,
        value).

        """
        unused.append("%s%s" % (
            '-' if neg else '',
            "%s=%s" % (param, value) if value is not None else param
        ))
    for (neg, param, value) in query:
        if not neg and param == 'skip':
            skip = int(value)
        elif not neg and param == 'limit':
            limit = int(value)
        elif param == "id":
            flt = db.view.flt_and(flt, db.view.searchobjectid(
                value.replace('-', ',').split(','),
                neg=neg))
        elif param == "host":
            flt = db.view.flt_and(flt, db.view.searchhost(value, neg=neg))
        elif param == "net":
            flt = db.view.flt_and(flt, db.view.searchnet(value, neg=neg))
        elif param == "range":
            flt = db.view.flt_and(flt, db.view.searchrange(
                *value.replace('-', ',').split(',', 1),
                neg=neg))
        elif param == "countports":
            vals = [int(val) for val in value.replace('-', ',').split(',', 1)]
            if len(vals) == 1:
                flt = db.view.flt_and(flt, db.view.searchcountopenports(
                    minn=vals[0], maxn=vals[0], neg=neg))
            else:
                flt = db.view.flt_and(flt, db.view.searchcountopenports(
                    minn=vals[0], maxn=vals[1], neg=neg))
        elif param == "hostname":
            flt = db.view.flt_and(
                flt, db.view.searchhostname(utils.str2regexp(value), neg=neg))
        elif param == "domain":
            flt = db.view.flt_and(
                flt, db.view.searchdomain(utils.str2regexp(value), neg=neg))
        elif param == "category":
            flt = db.view.flt_and(flt, db.view.searchcategory(
                utils.str2regexp(value), neg=neg))
        elif param == "country":
            flt = db.view.flt_and(flt, db.view.searchcountry(
                utils.str2list(value.upper()), neg=neg))
        elif param == "city":
            flt = db.view.flt_and(flt, db.view.searchcity(
                utils.str2regexp(value), neg=neg))
        elif param == "asnum":
            flt = db.view.flt_and(flt, db.view.searchasnum(
                utils.str2list(value), neg=neg))
        elif param == "asname":
            flt = db.view.flt_and(flt, db.view.searchasname(
                utils.str2regexp(value), neg=neg))
        elif param == "source":
            flt = db.view.flt_and(flt, db.view.searchsource(value, neg=neg))
        elif param == "timerange":
            flt = db.view.flt_and(flt, db.view.searchtimerange(
                *(float(val) for val in value.replace('-', ',').split(',')),
                neg=neg))
        elif param == 'timeago':
            if value and value[-1].isalpha():
                unit = {
                    's': 1,
                    'm': 60,
                    'h': 3600,
                    'd': 86400,
                    'y': 31557600,
                }[value[-1]]
                timeago = int(value[:-1]) * unit
            else:
                timeago = int(value)
            flt = db.view.flt_and(flt, db.view.searchtimeago(
                datetime.timedelta(0, timeago), neg=neg))
        elif not neg and param == "service":
            if ':' in value:
                req, port = value.split(':', 1)
                port = int(port)
                flt = db.view.flt_and(
                    flt,
                    db.view.searchservice(utils.str2regexp(req), port=port))
            else:
                flt = db.view.flt_and(
                    flt,
                    db.view.searchservice(utils.str2regexp(value)))
        elif not neg and param == "product" and ":" in value:
            product = value.split(':', 2)
            if len(product) == 2:
                flt = db.view.flt_and(
                    flt,
                    db.view.searchproduct(
                        utils.str2regexp(product[1]),
                        service=utils.str2regexp(product[0])
                    )
                )
            else:
                flt = db.view.flt_and(
                    flt,
                    db.view.searchproduct(
                        utils.str2regexp(product[1]),
                        service=utils.str2regexp(product[0]),
                        port=int(product[2])
                    )
                )
        elif not neg and param == "version" and value.count(":") >= 2:
            product = value.split(':', 3)
            if len(product) == 3:
                flt = db.view.flt_and(
                    flt,
                    db.view.searchproduct(
                        utils.str2regexp(product[1]),
                        version=utils.str2regexp(product[2]),
                        service=utils.str2regexp(product[0]),
                    )
                )
            else:
                flt = db.view.flt_and(
                    flt,
                    db.view.searchproduct(
                        utils.str2regexp(product[1]),
                        version=utils.str2regexp(product[2]),
                        service=utils.str2regexp(product[0]),
                        port=int(product[3])
                    )
                )
        elif not neg and param == "script":
            value = value.split(':', 1)
            if len(value) == 1:
                flt = db.view.flt_and(
                    flt,
                    db.view.searchscript(name=utils.str2regexp(value[0])),
                )
            else:
                flt = db.view.flt_and(
                    flt,
                    db.view.searchscript(
                        name=utils.str2regexp(value[0]),
                        output=utils.str2regexp(value[1]),
                    ),
                )
        # results of scripts or version scans
        elif not neg and param == "anonftp":
            flt = db.view.flt_and(flt, db.view.searchftpanon())
        elif not neg and param == 'anonldap':
            flt = db.view.flt_and(flt, db.view.searchldapanon())
        elif not neg and param == 'authbypassvnc':
            flt = db.view.flt_and(flt, db.view.searchvncauthbypass())
        elif not neg and param == "authhttp":
            flt = db.view.flt_and(flt, db.view.searchhttpauth())
        elif not neg and param == 'banner':
            flt = db.view.flt_and(
                flt,
                db.view.searchbanner(utils.str2regexp(value)))
        elif param == 'cookie':
            flt = db.view.flt_and(flt, db.view.searchcookie(value))
        elif param == 'file':
            if value is None:
                flt = db.view.flt_and(flt, db.view.searchfile())
            else:
                value = value.split(':', 1)
                if len(value) == 1:
                    flt = db.view.flt_and(flt, db.view.searchfile(
                        fname=utils.str2regexp(value[0])))
                else:
                    flt = db.view.flt_and(flt, db.view.searchfile(
                        fname=utils.str2regexp(value[1]),
                        scripts=value[0].split(',')))
        elif param == 'vuln':
            try:
                vulnid, status = value.split(':', 1)
            except ValueError:
                vulnid = value
                status = None
            except AttributeError:
                vulnid = None
                status = None
            flt = db.view.flt_and(flt, db.view.searchvuln(vulnid=vulnid,
                                                          status=status))
        elif not neg and param == 'geovision':
            flt = db.view.flt_and(flt, db.view.searchgeovision())
        elif param == 'httptitle':
            flt = db.view.flt_and(
                flt,
                db.view.searchhttptitle(utils.str2regexp(value)))
        elif not neg and param == "nfs":
            flt = db.view.flt_and(flt, db.view.searchnfs())
        elif not neg and param in ["nis", "yp"]:
            flt = db.view.flt_and(flt, db.view.searchypserv())
        elif not neg and param == 'mssqlemptypwd':
            flt = db.view.flt_and(flt, db.view.searchmssqlemptypwd())
        elif not neg and param == 'mysqlemptypwd':
            flt = db.view.flt_and(flt, db.view.searchmysqlemptypwd())
        elif not neg and param == 'sshkey':
            if value:
                flt = db.view.flt_and(flt, db.view.searchsshkey(
                    output=utils.str2regexp(value)))
            else:
                flt = db.view.flt_and(flt, db.view.searchsshkey())
        elif not neg and param.startswith('sshkey.'):
            subfield = param.split('.', 1)[1]
            if subfield in ['fingerprint', 'key', 'type', 'bits']:
                if subfield == 'type':
                    subfield = 'keytype'
                flt = db.view.flt_and(flt, db.view.searchsshkey(
                    **{subfield: utils.str2regexp(value)}))
            else:
                add_unused(neg, param, value)
        elif not neg and param == 'httphdr':
            if value is None:
                flt = db.view.flt_and(flt, db.view.searchhttphdr())
            elif ':' in value:
                name, value = (utils.str2regexp(string) for
                               string in value.split(':', 1))
                flt = db.view.flt_and(flt, db.view.searchhttphdr(name=name,
                                                                 value=value))
            else:
                flt = db.view.flt_and(flt, db.view.searchhttphdr(
                    name=utils.str2regexp(value)
                ))
        elif not neg and param == 'owa':
            flt = db.view.flt_and(flt, db.view.searchowa())
        elif param == 'phpmyadmin':
            flt = db.view.flt_and(flt, db.view.searchphpmyadmin())
        elif not neg and param.startswith('smb.'):
            flt = db.view.flt_and(flt, db.view.searchsmb(
                **{param[4:]: utils.str2regexp(value)}))
        elif not neg and param == 'smbshare':
            flt = db.view.flt_and(
                flt,
                db.view.searchsmbshares(access="" if value is None else value),
            )
        elif param == 'torcert':
            flt = db.view.flt_and(flt, db.view.searchtorcert())
        elif not neg and param == 'webfiles':
            flt = db.view.flt_and(flt, db.view.searchwebfiles())
        elif not neg and param == "webmin":
            flt = db.view.flt_and(flt, db.view.searchwebmin())
        elif not neg and param == 'x11srv':
            flt = db.view.flt_and(flt, db.view.searchx11())
        elif not neg and param == 'x11open':
            flt = db.view.flt_and(flt, db.view.searchx11access())
        elif not neg and param == 'xp445':
            flt = db.view.flt_and(flt, db.view.searchxp445())
        # OS fingerprint
        elif not neg and param == "os":
            flt = db.view.flt_and(
                flt,
                db.view.searchos(utils.str2regexp(value)))
        # device types
        elif param in ['devicetype', 'devtype']:
            flt = db.view.flt_and(
                flt,
                db.view.searchdevicetype(utils.str2regexp(value)))
        elif param in ['netdev', 'networkdevice']:
            flt = db.view.flt_and(flt, db.view.searchnetdev())
        elif param == 'phonedev':
            flt = db.view.flt_and(flt, db.view.searchphonedev())
        # traceroute
        elif param == 'hop':
            if ':' in value:
                hop, ttl = value.split(':', 1)
                flt = db.view.flt_and(flt,
                                      db.view.searchhop(hop, ttl=int(ttl),
                                                        neg=neg))
            else:
                flt = db.view.flt_and(flt,
                                      db.view.searchhop(value, neg=neg))
        elif param == 'hopname':
            flt = db.view.flt_and(flt,
                                  db.view.searchhopname(value, neg=neg))
        elif param == 'hopdomain':
            flt = db.view.flt_and(flt,
                                  db.view.searchhopdomain(value, neg=neg))
        elif not neg and param in ["ike.vendor_id.name",
                                   "ike.vendor_id.value"]:
            flt = db.view.flt_and(
                flt,
                db.view.searchscript(
                    name="ike-info",
                    values={
                        'vendor_ids.%s' % param[14:]: utils.str2regexp(value)
                    },
                ),
            )
        elif not neg and param == "ike.notification":
            flt = db.view.flt_and(
                flt,
                db.view.searchscript(
                    name="ike-info",
                    values={
                        'notification_type': utils.str2regexp(value)
                    },
                ),
            )
        # sort
        elif param == 'sortby':
            if neg:
                sortby.append((value, -1))
            else:
                sortby.append((value, 1))
        elif param in ['open', 'filtered', 'closed']:
            value = value.replace('_', '/').split(',')
            protos = {}
            for port in value:
                if '/' in port:
                    proto, port = port.split('/')
                else:
                    proto, port = "tcp", port
                protos.setdefault(proto, []).append(int(port))
            for proto, ports in viewitems(protos):
                flt = db.view.flt_and(
                    flt,
                    db.view.searchport(ports[0], protocol=proto, state=param)
                    if len(ports) == 1 else
                    db.view.searchports(ports, protocol=proto, state=param)
                )
        elif param == 'otheropenport':
            flt = db.view.flt_and(
                flt, db.view.searchportsother([int(val) for val in
                                               value.split(',')])
            )
        elif param == "screenshot":
            if value is None:
                flt = db.view.flt_and(flt, db.view.searchscreenshot(neg=neg))
            elif value.isdigit():
                flt = db.view.flt_and(flt, db.view.searchscreenshot(
                    port=int(value), neg=neg))
            elif value.startswith('tcp/') or value.startswith('udp/'):
                value = value.split('/', 1)
                flt = db.view.flt_and(flt, db.view.searchscreenshot(
                    port=int(value[1]), protocol=value[0], neg=neg))
            else:
                flt = db.view.flt_and(flt, db.view.searchscreenshot(
                    service=value, neg=neg))
        elif param == "screenwords":
            if value is None:
                flt = db.view.flt_and(
                    flt, db.view.searchscreenshot(words=not neg)
                )
            else:
                params = value.split(':', 1)
                words = ([utils.str2regexp(elt) for elt in
                          params[0].split(',')]
                         if ',' in params[0] else utils.str2regexp(params[0]))
                if len(params) == 1:
                    flt = db.view.flt_and(flt, db.view.searchscreenshot(
                        words=words, neg=neg))
                elif params[1].isdigit():
                    flt = db.view.flt_and(flt, db.view.searchscreenshot(
                        port=int(value), neg=neg, words=words))
                elif (params[1].startswith('tcp/') or
                      params[1].startswith('udp/')):
                    params[1] = params[1].split('/', 1)
                    flt = db.view.flt_and(flt, db.view.searchscreenshot(
                        port=int(params[1][1]), protocol=params[1][0],
                        neg=neg, words=words))
                else:
                    flt = db.view.flt_and(flt, db.view.searchscreenshot(
                        service=value, neg=neg, words=words))
        elif param == "cpe":
            if value:
                cpe_kwargs = {}
                cpe_fields = ["cpe_type", "vendor", "product", "version"]
                for field, cpe_arg in zip(cpe_fields, value.split(':', 3)):
                    cpe_kwargs[field] = utils.str2regexp(cpe_arg)
                flt = db.view.flt_and(flt, db.view.searchcpe(**cpe_kwargs))
            else:
                flt = db.view.flt_and(flt, db.view.searchcpe())
        elif param == 'display':
            # ignore this parameter
            pass
        elif value is None:
            if param.startswith('tcp_') or param.startswith('tcp/') or \
               param.startswith('udp_') or param.startswith('udp/'):
                proto, port = param.replace('_', '/').split('/', 1)
                port = int(port)
                flt = db.view.flt_and(flt, db.view.searchport(port,
                                                              protocol=proto,
                                                              neg=neg))
            elif param == "openport":
                flt = db.view.flt_and(flt, db.view.searchopenport(neg=neg))
            elif param.isdigit():
                flt = db.view.flt_and(flt, db.view.searchport(int(param),
                                                              neg=neg))
            elif all(x.isdigit() for x in param.split(',')):
                flt = db.view.flt_and(
                    flt,
                    db.view.searchports([int(val) for val in param.split(',')],
                                        neg=neg)
                )
            elif IPADDR.match(param):
                flt = db.view.flt_and(flt, db.view.searchhost(param, neg=neg))
            elif NETADDR.match(param):
                flt = db.view.flt_and(flt, db.view.searchnet(param, neg=neg))
            elif get_notepad_pages is not None and param == 'notes':
                flt = db.view.flt_and(flt, db.view.searchhosts(
                    get_notepad_pages(), neg=neg))
            elif '<' in param:
                param = param.split('<', 1)
                if param[1] and param[1][0] == '=':
                    flt = db.view.flt_and(flt, db.view.searchcmp(
                        param[0],
                        int(param[1][1:]),
                        '>' if neg else '<='))
                else:
                    flt = db.view.flt_and(flt, db.view.searchcmp(
                        param[0],
                        int(param[1]),
                        '>=' if neg else '<'))
            elif '>' in param:
                param = param.split('>', 1)
                if param[1] and param[1][0] == '=':
                    flt = db.view.flt_and(flt, db.view.searchcmp(
                        param[0],
                        int(param[1][1:]),
                        '<' if neg else '>='))
                else:
                    flt = db.view.flt_and(flt, db.view.searchcmp(
                        param[0],
                        int(param[1]),
                        '<=' if neg else '>'))
            else:
                add_unused(neg, param, value)
        else:
            add_unused(neg, param, value)
    return flt, sortby, unused, skip, limit
