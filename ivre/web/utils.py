#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

"""This sub-module contains functions that might be useful to any CGI
script.

"""

import datetime
import functools
import hmac
import os
import re
import shlex
import sys
from typing import List, Optional

try:
    import MySQLdb  # type: ignore

    HAVE_MYSQL = True
except ImportError:
    HAVE_MYSQL = False


from bottle import request  # type: ignore


from ivre import config, utils


def js_alert(ident, level, message):
    """This function returns a string containing JS code to
    generate an alert message.

    """
    return (
        'try {add_message("%(ident)s", "%(level)s", "%(message)s");}\n'
        'catch(err) {alert("%(levelup)s: %(message)s");}\n'
        ""
        % {
            "ident": ident,
            "level": level,
            "levelup": level.upper(),
            "message": message.replace('"', '\\"'),
        }
    )


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
    ipaddr_page = re.compile("^\\d+\\.\\d+\\.\\d+\\.\\d+\\.txt$")
    return [page[:-4] for page in os.listdir(pagesdir) if ipaddr_page.match(page)]


GET_NOTEPAD_PAGES["localdokuwiki"] = get_notepad_pages_localdokuwiki


if HAVE_MYSQL:

    def get_notepad_pages_mediawiki(
        server, username, password, dbname, base="IvreNotepad"
    ):
        """Returns a list of the IP addresses for which a Mediawiki
        page exists.

        """
        ipaddr_page = "^" + re.escape(base) + "\\/\\d+\\.\\d+\\.\\d+\\.\\d+$"
        cur = MySQLdb.Connect(server, username, password, dbname).cursor()
        cur.execute(
            "SELECT `page_title` FROM `wiki_page` WHERE `page_title` "
            "REGEXP '%s'" % ipaddr_page
        )
        return [page[0][len(base) + 1 :] for page in cur]

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
        *config.WEB_GET_NOTEPAD_PAGES[1],
    )


get_notepad_pages = _find_get_notepad_pages()


def _split_param(pval: str) -> List[Optional[str]]:
    # This is needed for IPv6 filters
    if utils.IPADDR.search(pval):
        return [pval, None]
    if utils.NETADDR.search(pval):
        return [pval, None]
    if ":" in pval:
        return pval.split(":", 1)
    return [pval, None]


def query_from_params(params):
    """This function *consumes* the 'q' parameter (if it exists) and
    returns the query as a list of three elements list: [boolean
    `neg`, `param`, `value`].

    This function will write an error message and abort the CGI if an
    error occurs with `shlex.split()`.

    """
    try:
        query = params.pop("q")
    except KeyError:
        return []
    try:
        query = query.replace("\\", "\\\\")
        return [
            [neg] + _split_param(pval)
            for neg, pval in (
                (True, x[1:]) if x[:1] in "!-" else (False, x)
                for x in shlex.split(query)
            )
        ]
    except ValueError as exc:
        sys.stdout.write(
            js_alert(
                "param-parsing",
                "warning",
                "Parameter parsing error. Check the server's logs "
                "for more information.",
            )
        )
        utils.LOGGER.critical("Parameter parsing error [%s (%r)]", exc, exc)
        raise ValueError("Parameter parsing error.")


def get_user():
    """Return the connected user."""
    return request.environ.get("REMOTE_USER")


def get_anonymized_user():
    """Return the HMAC value of the current user authenticated with
    the HMAC secret.

    """
    try:
        secret = config.WEB_SECRET.encode()
    except AttributeError:
        secret = config.WEB_SECRET
    return utils.encode_b64(
        hmac.new(secret, msg=get_user().encode(), digestmod="sha256").digest()[:9]
    )


def _parse_query(dbase, query):
    """Returns a DB filter (valid for dbase) from a query string
    usable in WEB_DEFAULT_INIT_QUERY and WEB_INIT_QUERIES
    configuration items.

    """
    if query is None:
        query = "full"
    query = query.split(":")
    return {
        "full": lambda dbase: dbase.flt_empty,
        "noaccess": lambda dbase: dbase.searchnonexistent(),
        "category": lambda dbase, cat: dbase.searchcategory(cat.split(",")),
        "source": lambda dbase, source: dbase.searchsource(source),
    }[query[0]](dbase, *query[1:])


def get_init_flt(dbase):
    """Return a filter corresponding to the current user's
    privileges.

    """
    init_queries = {
        key: _parse_query(dbase, value)
        for key, value in config.WEB_INIT_QUERIES.items()
    }
    user = get_user()
    if user in init_queries:
        return init_queries[user]
    if isinstance(user, str) and "@" in user:
        realm = user[user.index("@") :]
        if realm in init_queries:
            return init_queries[realm]
    if config.WEB_PUBLIC_SRV:
        return dbase.searchcategory(["Shared", get_anonymized_user()])
    return _parse_query(dbase, config.WEB_DEFAULT_INIT_QUERY)


PORT = re.compile("^(?:(tcp|udp)[/_])?([0-9]+)$")


def flt_from_query(dbase, query, base_flt=None):
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
    flt = get_init_flt(dbase) if base_flt is None else base_flt

    def add_unused(neg, param, value):
        """Add to the `unused` list a string representing (neg, param,
        value).

        """
        unused.append(
            "%s%s"
            % (
                "-" if neg else "",
                "%s=%s" % (param, value) if value is not None else param,
            )
        )

    for (neg, param, value) in query:
        if not neg and param == "skip":
            skip = int(value)
        elif not neg and param == "limit":
            limit = int(value)
        elif param == "id":
            flt = dbase.flt_and(
                flt, dbase.searchobjectid(value.replace("-", ",").split(","), neg=neg)
            )
        elif param == "host":
            flt = dbase.flt_and(flt, dbase.searchhost(value, neg=neg))
        elif param == "net":
            flt = dbase.flt_and(flt, dbase.searchnet(value, neg=neg))
        elif param == "range":
            flt = dbase.flt_and(
                flt, dbase.searchrange(*value.replace("-", ",").split(",", 1), neg=neg)
            )
        elif param == "countports":
            vals = [int(val) for val in value.replace("-", ",").split(",", 1)]
            if len(vals) == 1:
                flt = dbase.flt_and(
                    flt, dbase.searchcountopenports(minn=vals[0], maxn=vals[0], neg=neg)
                )
            else:
                flt = dbase.flt_and(
                    flt, dbase.searchcountopenports(minn=vals[0], maxn=vals[1], neg=neg)
                )
        elif param == "hostname":
            flt = dbase.flt_and(
                flt, dbase.searchhostname(utils.str2regexp(value), neg=neg)
            )
        elif param == "domain":
            flt = dbase.flt_and(
                flt, dbase.searchdomain(utils.str2regexp(value), neg=neg)
            )
        elif param == "category":
            flt = dbase.flt_and(
                flt, dbase.searchcategory(utils.str2regexp(value), neg=neg)
            )
        elif param == "country":
            flt = dbase.flt_and(
                flt, dbase.searchcountry(utils.str2list(value.upper()), neg=neg)
            )
        elif param == "city":
            flt = dbase.flt_and(flt, dbase.searchcity(utils.str2regexp(value), neg=neg))
        elif param == "asnum":
            flt = dbase.flt_and(flt, dbase.searchasnum(utils.str2list(value), neg=neg))
        elif param == "asname":
            flt = dbase.flt_and(
                flt, dbase.searchasname(utils.str2regexp(value), neg=neg)
            )
        elif param == "source":
            flt = dbase.flt_and(
                flt, dbase.searchsource(utils.str2regexp(value), neg=neg)
            )
        elif param == "timerange":
            flt = dbase.flt_and(
                flt,
                dbase.searchtimerange(
                    *(float(val) for val in value.replace("-", ",").split(",")), neg=neg
                ),
            )
        elif param == "timeago":
            if value and value[-1].isalpha():
                unit = {
                    "s": 1,
                    "m": 60,
                    "h": 3600,
                    "d": 86400,
                    "y": 31557600,
                }[value[-1]]
                timeago = int(value[:-1]) * unit
            else:
                timeago = int(value)
            flt = dbase.flt_and(
                flt, dbase.searchtimeago(datetime.timedelta(0, timeago), neg=neg)
            )
        elif not neg and param == "service":
            if ":" in value:
                req, port = value.split(":", 1)
                port = int(port)
                flt = dbase.flt_and(
                    flt, dbase.searchservice(utils.str2regexpnone(req), port=port)
                )
            else:
                flt = dbase.flt_and(
                    flt, dbase.searchservice(utils.str2regexpnone(value))
                )
        elif not neg and param == "product" and ":" in value:
            product = value.split(":", 2)
            if len(product) == 2:
                flt = dbase.flt_and(
                    flt,
                    dbase.searchproduct(
                        product=utils.str2regexpnone(product[1]),
                        service=utils.str2regexpnone(product[0]),
                    ),
                )
            else:
                flt = dbase.flt_and(
                    flt,
                    dbase.searchproduct(
                        product=utils.str2regexpnone(product[1]),
                        service=utils.str2regexpnone(product[0]),
                        port=int(product[2]),
                    ),
                )
        elif not neg and param == "version" and value.count(":") >= 2:
            product = value.split(":", 3)
            if len(product) == 3:
                flt = dbase.flt_and(
                    flt,
                    dbase.searchproduct(
                        product=utils.str2regexpnone(product[1]),
                        version=utils.str2regexpnone(product[2]),
                        service=utils.str2regexpnone(product[0]),
                    ),
                )
            else:
                flt = dbase.flt_and(
                    flt,
                    dbase.searchproduct(
                        product=utils.str2regexpnone(product[1]),
                        version=utils.str2regexpnone(product[2]),
                        service=utils.str2regexpnone(product[0]),
                        port=int(product[3]),
                    ),
                )
        elif param == "script":
            value = value.split(":", 1)
            if len(value) == 1:
                flt = dbase.flt_and(
                    flt,
                    dbase.searchscript(name=utils.str2regexp(value[0]), neg=neg),
                )
            else:
                flt = dbase.flt_and(
                    flt,
                    dbase.searchscript(
                        name=utils.str2regexp(value[0]),
                        output=utils.str2regexp(value[1]),
                        neg=neg,
                    ),
                )
        # results of scripts or version scans
        elif not neg and param == "anonftp":
            flt = dbase.flt_and(flt, dbase.searchftpanon())
        elif not neg and param == "anonldap":
            flt = dbase.flt_and(flt, dbase.searchldapanon())
        elif not neg and param == "authbypassvnc":
            flt = dbase.flt_and(flt, dbase.searchvncauthbypass())
        elif not neg and param == "authhttp":
            flt = dbase.flt_and(flt, dbase.searchhttpauth())
        elif not neg and param == "banner":
            flt = dbase.flt_and(flt, dbase.searchbanner(utils.str2regexp(value)))
        elif param == "cookie":
            flt = dbase.flt_and(flt, dbase.searchcookie(value))
        elif param == "file":
            if value is None:
                flt = dbase.flt_and(flt, dbase.searchfile())
            else:
                value = value.split(":", 1)
                if len(value) == 1:
                    flt = dbase.flt_and(
                        flt, dbase.searchfile(fname=utils.str2regexp(value[0]))
                    )
                else:
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchfile(
                            fname=utils.str2regexp(value[1]),
                            scripts=value[0].split(","),
                        ),
                    )
        elif param == "vuln":
            try:
                vulnid, status = value.split(":", 1)
            except ValueError:
                vulnid = value
                status = None
            except AttributeError:
                vulnid = None
                status = None
            flt = dbase.flt_and(flt, dbase.searchvuln(vulnid=vulnid, status=status))
        elif not neg and param == "geovision":
            flt = dbase.flt_and(flt, dbase.searchgeovision())
        elif param == "httptitle":
            flt = dbase.flt_and(flt, dbase.searchhttptitle(utils.str2regexp(value)))
        elif not neg and param == "nfs":
            flt = dbase.flt_and(flt, dbase.searchnfs())
        elif not neg and param in ["nis", "yp"]:
            flt = dbase.flt_and(flt, dbase.searchypserv())
        elif not neg and param == "mssqlemptypwd":
            flt = dbase.flt_and(flt, dbase.searchmssqlemptypwd())
        elif not neg and param == "mysqlemptypwd":
            flt = dbase.flt_and(flt, dbase.searchmysqlemptypwd())
        elif not neg and param == "sshkey":
            if value:
                flt = dbase.flt_and(
                    flt, dbase.searchsshkey(output=utils.str2regexp(value))
                )
            else:
                flt = dbase.flt_and(flt, dbase.searchsshkey())
        elif not neg and param.startswith("sshkey."):
            subfield = param.split(".", 1)[1]
            if subfield in ["fingerprint", "key", "type", "bits"]:
                if subfield == "type":
                    subfield = "keytype"
                elif subfield == "bits":
                    try:
                        value = int(value)
                    except (ValueError, TypeError):
                        pass
                else:
                    value = utils.str2regexp(value)
                flt = dbase.flt_and(flt, dbase.searchsshkey(**{subfield: value}))
            else:
                add_unused(neg, param, value)
        elif not neg and param == "cert":
            flt = dbase.flt_and(flt, dbase.searchcert())
        elif param.startswith("cert."):
            subfield = param.split(".", 1)[1]
            if subfield == "self_signed" and value is None:
                flt = dbase.flt_and(flt, dbase.searchcert(self_signed=not neg))
            elif not neg:
                if subfield in ["md5", "sha1", "sha256", "subject", "issuer"]:
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchcert(
                            **{
                                subfield: utils.str2regexp(value),
                            }
                        ),
                    )
                elif subfield in ["pubkey.md5", "pubkey.sha1", "pubkey.sha256"]:
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchcert(
                            **{
                                "pk%s" % subfield[7:]: utils.str2regexp(value),
                            }
                        ),
                    )
                else:
                    add_unused(neg, param, value)
            else:
                add_unused(neg, param, value)
        elif not neg and param == "httphdr":
            if value is None:
                flt = dbase.flt_and(flt, dbase.searchhttphdr())
            elif ":" in value:
                name, value = value.split(":", 1)
                name = utils.str2regexp(name.lower())
                value = utils.str2regexp(value)
                flt = dbase.flt_and(flt, dbase.searchhttphdr(name=name, value=value))
            else:
                flt = dbase.flt_and(
                    flt, dbase.searchhttphdr(name=utils.str2regexp(value.lower()))
                )
        elif not neg and param == "httpapp":
            if value is None:
                flt = dbase.flt_and(flt, dbase.searchhttpapp())
            elif ":" in value:
                name, version = (
                    utils.str2regexp(string) for string in value.split(":", 1)
                )
                flt = dbase.flt_and(
                    flt, dbase.searchhttpapp(name=name, version=version)
                )
            else:
                flt = dbase.flt_and(
                    flt, dbase.searchhttpapp(name=utils.str2regexp(value))
                )
        elif not neg and param == "owa":
            flt = dbase.flt_and(flt, dbase.searchowa())
        elif param == "phpmyadmin":
            flt = dbase.flt_and(flt, dbase.searchphpmyadmin())
        elif not neg and param.startswith("smb."):
            flt = dbase.flt_and(
                flt, dbase.searchsmb(**{param[4:]: utils.str2regexp(value)})
            )
        elif not neg and param.startswith("ntlm."):
            key = {
                "name": "Target_Name",
                "server": "NetBIOS_Computer_Name",
                "domain": "NetBIOS_Domain_Name",
                "workgroup": "Workgroup",
                "domain_dns": "DNS_Domain_Name",
                "forest": "DNS_Tree_Name",
                "fqdn": "DNS_Computer_Name",
                "os": "Product_Version",
                "version": "NTLM_Version",
            }
            flt = dbase.flt_and(
                flt,
                dbase.searchntlm(
                    **{key.get(param[5:], param[5:]): utils.str2regexp(value)}
                ),
            )
        elif not neg and param == "smbshare":
            flt = dbase.flt_and(
                flt,
                dbase.searchsmbshares(access="" if value is None else value),
            )
        elif param == "torcert":
            flt = dbase.flt_and(flt, dbase.searchtorcert())
        elif not neg and param == "webfiles":
            flt = dbase.flt_and(flt, dbase.searchwebfiles())
        elif not neg and param == "webmin":
            flt = dbase.flt_and(flt, dbase.searchwebmin())
        elif not neg and param == "x11srv":
            flt = dbase.flt_and(flt, dbase.searchx11())
        elif not neg and param == "x11open":
            flt = dbase.flt_and(flt, dbase.searchx11access())
        elif not neg and param == "xp445":
            flt = dbase.flt_and(flt, dbase.searchxp445())
        elif param == "ssl-ja3-client":
            flt = dbase.flt_and(
                flt,
                dbase.searchja3client(
                    value_or_hash=(None if value is None else utils.str2regexp(value)),
                    neg=neg,
                ),
            )
        elif param == "ssl-ja3-server":
            if value is None:
                # There are no additional arguments
                flt = dbase.flt_and(flt, dbase.searchja3server(neg=neg))
            else:
                split = [
                    utils.str2regexp(v) if v else None for v in value.split(":", 1)
                ]
                if len(split) == 1:
                    # Only a JA3 server is given
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchja3server(
                            value_or_hash=(split[0]),
                            neg=neg,
                        ),
                    )
                else:
                    # Both client and server JA3 are specified
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchja3server(
                            value_or_hash=split[0],
                            client_value_or_hash=split[1],
                            neg=neg,
                        ),
                    )
        elif param == "useragent":
            if value:
                flt = dbase.flt_and(
                    flt, dbase.searchuseragent(useragent=utils.str2regexp(value))
                )
            else:
                flt = dbase.flt_and(flt, dbase.searchuseragent())
        # OS fingerprint
        elif not neg and param == "os":
            flt = dbase.flt_and(flt, dbase.searchos(utils.str2regexp(value)))
        # device types
        elif param in ["devicetype", "devtype"]:
            flt = dbase.flt_and(flt, dbase.searchdevicetype(utils.str2regexp(value)))
        elif param in ["netdev", "networkdevice"]:
            flt = dbase.flt_and(flt, dbase.searchnetdev())
        elif param == "phonedev":
            flt = dbase.flt_and(flt, dbase.searchphonedev())
        # traceroute
        elif param == "hop":
            if ":" in value:
                hop, ttl = value.split(":", 1)
                flt = dbase.flt_and(flt, dbase.searchhop(hop, ttl=int(ttl), neg=neg))
            else:
                flt = dbase.flt_and(flt, dbase.searchhop(value, neg=neg))
        elif param == "hopname":
            flt = dbase.flt_and(flt, dbase.searchhopname(value, neg=neg))
        elif param == "hopdomain":
            flt = dbase.flt_and(flt, dbase.searchhopdomain(value, neg=neg))
        elif not neg and param in ["ike.vendor_id.name", "ike.vendor_id.value"]:
            flt = dbase.flt_and(
                flt,
                dbase.searchscript(
                    name="ike-info",
                    values={"vendor_ids.%s" % param[14:]: utils.str2regexp(value)},
                ),
            )
        elif not neg and param == "ike.notification":
            flt = dbase.flt_and(
                flt,
                dbase.searchscript(
                    name="ike-info",
                    values={"notification_type": utils.str2regexp(value)},
                ),
            )
        # sort
        elif param == "sortby":
            if neg:
                sortby.append((value, -1))
            else:
                sortby.append((value, 1))
        elif param in ["open", "filtered", "closed"]:
            value = value.replace("_", "/").split(",")
            protos = {}
            for port in value:
                if "/" in port:
                    proto, port = port.split("/")
                else:
                    proto = "tcp"
                protos.setdefault(proto, []).append(int(port))
            for proto, ports in protos.items():
                flt = dbase.flt_and(
                    flt,
                    dbase.searchport(ports[0], protocol=proto, state=param)
                    if len(ports) == 1
                    else dbase.searchports(ports, protocol=proto, state=param),
                )
        elif param == "otheropenport":
            flt = dbase.flt_and(
                flt, dbase.searchportsother([int(val) for val in value.split(",")])
            )
        elif param == "screenshot":
            if value is None:
                flt = dbase.flt_and(flt, dbase.searchscreenshot(neg=neg))
            elif value.isdigit():
                flt = dbase.flt_and(
                    flt, dbase.searchscreenshot(port=int(value), neg=neg)
                )
            elif value.startswith("tcp/") or value.startswith("udp/"):
                value = value.split("/", 1)
                flt = dbase.flt_and(
                    flt,
                    dbase.searchscreenshot(
                        port=int(value[1]), protocol=value[0], neg=neg
                    ),
                )
            else:
                flt = dbase.flt_and(flt, dbase.searchscreenshot(service=value, neg=neg))
        elif param == "screenwords":
            if value is None:
                flt = dbase.flt_and(flt, dbase.searchscreenshot(words=not neg))
            else:
                params = value.split(":", 1)
                words = (
                    [utils.str2regexp(elt) for elt in params[0].split(",")]
                    if "," in params[0]
                    else utils.str2regexp(params[0])
                )
                if len(params) == 1:
                    flt = dbase.flt_and(
                        flt, dbase.searchscreenshot(words=words, neg=neg)
                    )
                elif params[1].isdigit():
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchscreenshot(port=int(value), neg=neg, words=words),
                    )
                elif params[1].startswith("tcp/") or params[1].startswith("udp/"):
                    params[1] = params[1].split("/", 1)
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchscreenshot(
                            port=int(params[1][1]),
                            protocol=params[1][0],
                            neg=neg,
                            words=words,
                        ),
                    )
                else:
                    flt = dbase.flt_and(
                        flt, dbase.searchscreenshot(service=value, neg=neg, words=words)
                    )
        elif param == "cpe":
            if value:
                cpe_kwargs = {}
                cpe_fields = ["cpe_type", "vendor", "product", "version"]
                for field, cpe_arg in zip(cpe_fields, value.split(":", 3)):
                    cpe_kwargs[field] = utils.str2regexp(cpe_arg)
                flt = dbase.flt_and(flt, dbase.searchcpe(**cpe_kwargs))
            else:
                flt = dbase.flt_and(flt, dbase.searchcpe())
        elif param == "display":
            # ignore this parameter
            pass
        elif value is None:
            if PORT.search(param) is not None:
                # Python >= 3.8: if (match := PORT.search(param)) is not None
                proto, port = PORT.search(param).groups()
                flt = dbase.flt_and(
                    flt, dbase.searchport(int(port), protocol=proto or "tcp", neg=neg)
                )
            elif param == "openport":
                flt = dbase.flt_and(flt, dbase.searchopenport(neg=neg))
            elif param == "ipv4":
                if neg:
                    flt = dbase.flt_and(flt, dbase.searchipv6())
                else:
                    flt = dbase.flt_and(flt, dbase.searchipv4())
            elif param == "ipv6":
                if neg:
                    flt = dbase.flt_and(flt, dbase.searchipv4())
                else:
                    flt = dbase.flt_and(flt, dbase.searchipv6())
            elif all(PORT.search(x) is not None for x in param.split(",")):
                proto_ports = {}
                for port in param.split(","):
                    proto, port = PORT.search(port).groups()
                    proto_ports.setdefault(proto or "tcp", set()).add(int(port))
                for proto, ports in proto_ports.items():
                    if len(ports) > 1:
                        flt = dbase.flt_and(
                            flt,
                            dbase.searchports(list(ports), protocol=proto, neg=neg),
                        )
                    else:
                        flt = dbase.flt_and(
                            flt,
                            dbase.searchport(
                                next(iter(ports)), protocol=proto, neg=neg
                            ),
                        )
            elif utils.IPADDR.search(param):
                flt = dbase.flt_and(flt, dbase.searchhost(param, neg=neg))
            elif utils.NETADDR.search(param):
                flt = dbase.flt_and(flt, dbase.searchnet(param, neg=neg))
            elif get_notepad_pages is not None and param == "notes":
                flt = dbase.flt_and(
                    flt, dbase.searchhosts(get_notepad_pages(), neg=neg)
                )
            elif "<" in param:
                param = param.split("<", 1)
                if param[1] and param[1][0] == "=":
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchcmp(
                            param[0], int(param[1][1:]), ">" if neg else "<="
                        ),
                    )
                else:
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchcmp(param[0], int(param[1]), ">=" if neg else "<"),
                    )
            elif ">" in param:
                param = param.split(">", 1)
                if param[1] and param[1][0] == "=":
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchcmp(
                            param[0], int(param[1][1:]), "<" if neg else ">="
                        ),
                    )
                else:
                    flt = dbase.flt_and(
                        flt,
                        dbase.searchcmp(param[0], int(param[1]), "<=" if neg else ">"),
                    )
            else:
                add_unused(neg, param, value)
        else:
            add_unused(neg, param, value)
    return flt, sortby, unused, skip, limit


def parse_arg(data):
    if not isinstance(data, dict):
        return data
    if "f" not in data or not isinstance(data["f"], str):
        return data
    if "a" not in data or not isinstance(data["a"], list):
        return data
    args = data["a"]
    if len(args) != 1:
        return data
    if any(k not in "af" for k in data):
        return data
    try:
        func = {
            "regexp": utils.str2regexp,
            "datetime": datetime.datetime.fromtimestamp,
        }[data["f"]]
    except KeyError:
        return data
    return func(*args)


def parse_filter(dbase, data):
    if not isinstance(data, dict):
        raise ValueError("Unsupported filter")
    if not data:
        return dbase.flt_empty
    func = data.pop("f")
    if not isinstance(func, str):
        raise ValueError("Unsupported filter")
    args = data.pop("a", [])
    try:
        func = {"and": dbase.flt_and, "or": dbase.flt_or}[func]
    except KeyError:
        pass
    else:
        return func(*(parse_filter(dbase, a) for a in args))
    func = "search%s" % func
    kargs = data.pop("k", {})
    if data:
        raise ValueError("Unsupported filter")
    if not hasattr(dbase, func):
        raise ValueError("Unsupported filter")
    return getattr(dbase, func)(
        *(parse_arg(a) for a in args), **{k: parse_arg(v) for k, v in kargs.items()}
    )
