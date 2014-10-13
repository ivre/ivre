#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

"""
This module is part of IVRE.
Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains functions to interact with the
database.
"""

from ivre import config, utils, xmlnmap

import sys
import re
import urlparse
import urllib
import xml.sax
import os
import subprocess
import shutil
import tempfile
import pickle

# tests: I don't want to depend on cluster for now
try:
    import cluster
    USE_CLUSTER = True
except ImportError:
    USE_CLUSTER = False


class DB(object):
    """The base database object. Must remain backend-independent and
    purpose-independent.

    For now, the only implemented backend is MongoDB, and there are
    three purposes: Nmap, Passive and Data.

    It is not mandatory for each backend to be ready to be used for
    each purpose (e.g., an SQL backend would probably fit for the
    Passive and Data purposes but not for the Nmap purpose). We need a
    subclass for each (backend, purpose) combination wanted.

    We have backend-independent, purpose-specific subclasses to factor
    some code, and purpose-independent, backend-specific subclasses
    for the same reason.

    The backend-specific purpose-specific classes inherit from both
    the relevant backend-independent, purpose-specific class and the
    relevant purpose-independent, backend-specific class.

    """
    globaldb = None

    # filters

    def flt_and(self, *args):
        """Returns a condition that is true iff all of the given
        conditions is true.

        """
        return reduce(self._flt_and, args)

    def _flt_and(self, cond1, cond2):
        """Returns a condition that is true iff both `cond1` and
        `cond2` are true.

        This is typically implemented in the backend-specific
        subclass.

        """
        raise NotImplementedError

    def flt_or(self, *args):
        """Returns a condition that is true iff any of the given
        conditions is true.

        """
        return reduce(self._flt_or, args)

    def _flt_or(self, cond1, cond2):
        """Returns a condition that is true iff either `cond1` or
        `cond2` is true.

        This is typically implemented in the backend-specific
        subclass.

        """
        raise NotImplementedError

    def searchnet(self, net, neg=False):
        """Filters (if `neg` == True, filters out) one particular IP
        network (CIDR notation).

        """
        return self.searchrange(*utils.net2range(net), neg=neg)

    def searchrange(self, start, stop, neg=False):
        """Filters (if `neg` == True, filters out) one particular IP
        range given its boudaries `start` and `stop`.

        """
        raise NotImplementedError

    def searchphpmyadmin(self):
        """Finds phpMyAdmin instances based on its cookies."""
        return self.searchcookie('phpMyAdmin')

    def searchcookie(self, name):
        """Finds specific cookie names.

        This is typically implemented in the backend-specific
        purpose-specific subclass.

        """
        raise NotImplementedError

    def searchwebfiles(self):
        """Finds shared files or directories that are typical of a web
        application.

        Being able to write web files often leads to arbitrary code
        execution.

        Being able to read directly web files (without a
        PHP/ASP/... interpreter) often leads to privilege escalation
        in the application and sometimes to arbitrary code
        execution by finding backdoors/shells/vulnerabilities.

        """
        return self.searchfile(re.compile(
            'vhost|www|web\\.config|\\.htaccess|\\.([aj]sp|php|html?|js|css)',
            re.I))

    def searchfile(self, fname):
        """Finds shared files or directories from a name or a
        pattern.

        """
        raise NotImplementedError

    def searchjavaua(self):
        """Finds Java User-Agent."""
        return self.searchuseragent(re.compile('(^| )(Java|javaws)/', flags=0))

    def searchuseragent(self, useragent):
        """Finds specified User-Agent(s)."""
        raise NotImplementedError

    def get(self, spec, **kargs):
        """Gets a cursor, which can be iterated to get results.

        The type of that cursor is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    def getid(self, record):
        """Gets a unique identifier for a specified `record`.

        The type of the identifier is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    def searchid(self, idval, neg=False):
        """Gets a specific record given its unique identifier `idval`.

        The type of the identifier is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    def str2id(self, string):
        """Returns a unique identifier from `string`.

        The type of the identifier is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    if USE_CLUSTER:
        def hierarchical_clustering(self, values):
            """Returns a cluster
            """
            return cluster.HierarchicalClustering(
                [rec for rec in values],
                lambda x, y: abs(x['mean'] - y['mean'])
                )


class DBNmap(DB):

    content_handler = xmlnmap.Nmap2Txt

    def __init__(self):
        try:
            import argparse
            self.argparser = argparse.ArgumentParser(add_help=False)
        except ImportError:
            self.argparser = utils.FakeArgparserParent()
        self.argparser.add_argument(
            '--category', metavar='CAT',
            help='show only results from this category')
        self.argparser.add_argument(
            '--country', metavar='CODE',
            help='show only results from this country')
        self.argparser.add_argument(
            '--as', '--asnum', metavar='NUM',
            help='show only results from this AS')
        self.argparser.add_argument('--source', metavar='SRC',
                                    help='show only results from this source')
        self.argparser.add_argument('--timeago', metavar='SECONDS', type=int)
        self.argparser.add_argument('--host', metavar='IP')
        self.argparser.add_argument('--hostname')
        self.argparser.add_argument('--domain')
        self.argparser.add_argument('--net', metavar='IP/MASK')
        self.argparser.add_argument('--hop', metavar='IP')
        self.argparser.add_argument('--port', metavar='PORT')
        self.argparser.add_argument('--openport', action='store_true')
        self.argparser.add_argument('--service', metavar='SVC')
        self.argparser.add_argument('--script', metavar='SCRIPT')
        self.argparser.add_argument('--hostscript', metavar='SCRIPT')
        self.argparser.add_argument('--svchostname')
        self.argparser.add_argument('--os')
        self.argparser.add_argument('--anonftp', action='store_true')
        self.argparser.add_argument('--anonldap', action='store_true')
        self.argparser.add_argument('--authhttp', action='store_true')
        self.argparser.add_argument('--authbypassvnc', action='store_true')
        self.argparser.add_argument('--ypserv', '--nis', action='store_true')
        self.argparser.add_argument('--nfs', action='store_true')
        self.argparser.add_argument('--x11', action='store_true')
        self.argparser.add_argument('--xp445', action='store_true')
        self.argparser.add_argument('--owa', action='store_true')
        self.argparser.add_argument('--vuln-boa', '--vuln-intersil',
                                    action='store_true')
        self.argparser.add_argument('--torcert', action='store_true')
        self.argparser.add_argument('--sshkey')

    def store_scan(self, fname, **kargs):
        """This method parses a scan result, displays a JSON version
        of the result, and return True if everything went fine, False
        otherwise.

        In backend-specific subclasses, this method stores the result
        instead of displaying it, thanks to the `content_handler`
        attribute.

        """
        parser = xml.sax.make_parser()
        try:
            content_handler = self.content_handler(fname, **kargs)
        except Exception as exc:
            sys.stderr.write("WARNING: %s [%r] [fname=%s]\n" % (
                exc.message, exc, fname))
        else:
            parser.setContentHandler(content_handler)
            parser.setEntityResolver(xmlnmap.NoExtResolver())
            parser.parse(fname)
            content_handler.outputresults()
            return True
        return False

    def get_mean_open_ports(self, flt, archive=False):
        """This method returns for a specific query `flt` a list of
        dictionary objects whose keys are `id` and `mean`; the value
        for `id` is a backend-dependant and uniquely identifies a
        record, and the value for `mean` is given by:

        (number of open ports) * sum(port number for each open port)

        """
        return [
            {
                "id": self.getid(host),
                "mean": reduce(
                    lambda x, y: x * y,
                    reduce(
                        lambda x, y: (x[0] + y[0], x[1] + y[1]),
                        ((1, port['port'])
                         for port in host.get('ports', [])
                         if port['state_state'] == 'open'),
                        (0, 0)
                    )
                )
            } for host in self.get(flt, archive=archive, fields=["ports"])
        ]
        # result = []
        # for host in self.get(flt, fields=["ports"]):
        #     count = 0
        #     ports = 1
        #     for port in host.get('ports', []):
        #         if port['state_state'] == 'open':
        #             count += 1
        #             ports += port['port']
        #     result.append((self.getid(host), count * ports))
        # return result

    def searchsshkey(self, key):
        return self.searchscriptidout(
            'ssh-hostkey',
            re.compile(re.escape(key), flags=re.I))

    def searchx11access(self):
        return self.searchscriptidout('x11-access',
                                      'X server access is granted')

    def searchbanner(self, banner):
        return self.searchscriptidout('banner', banner)

    def searchvncauthbypass(self):
        return self.searchscriptid("realvnc-auth-bypass")

    def searchmssqlemptypwd(self):
        return self.searchscriptidout(
            'ms-sql-empty-password',
            re.compile('Login\\ Success', flags=0))

    def searchmysqlemptypwd(self):
        return self.searchscriptidout(
            'mysql-empty-password',
            re.compile('account\\ has\\ empty\\ password', flags=0))

    def searchcookie(self, name):
        return self.searchscriptidout(
            'http-headers',
            re.compile('^ *Set-Cookie: %s=' % re.escape(name),
                       flags=re.MULTILINE | re.I))

    def searchftpanon(self):
        return self.searchscriptidout(
            'ftp-anon',
            re.compile('^Anonymous\\ FTP\\ login\\ allowed',
                       flags=0))

    def searchhttpauth(self, newscript=True, oldscript=False):
        # $or queries are too slow, by default support only new script
        # output.
        res = []
        if newscript:
            res.append(self.searchscriptidout(
                'http-default-accounts',
                re.compile('credentials\\ found')))
        if oldscript:
            res.append(self.searchscriptidout(
                'http-auth',
                re.compile('HTTP\\ server\\ may\\ accept')))
        if not res:
            raise Exception('"newscript" and "oldscript" are both False')
        if len(res) == 1:
            return res[0]
        return self.flt_or(*res)

    def searchowa(self):
        return self.flt_or(
            self.searchscriptidout(
                'http-headers',
                re.compile('^ *(Location:.*(owa|exchweb)|X-OWA-Version)',
                           flags=re.MULTILINE | re.I)),
            self.searchscriptidout(
                'http-auth-finder',
                re.compile('/(owa|exchweb)',
                           flags=re.I)),
            self.searchscriptidout(
                'http-title',
                re.compile('Outlook Web A|(Requested resource was|'
                           'Did not follow redirect to ).*/(owa|exchweb)',
                           flags=re.I)),
            self.searchscriptidout(
                'html-title',
                re.compile('Outlook Web A|(Requested resource was|'
                           'Did not follow redirect to ).*/(owa|exchweb)',
                           flags=re.I))
        )

    def searchxp445(self):
        return self.flt_and(
            self.searchport(445),
            self.searchhostscriptidout(
                'smb-os-discovery',
                re.compile(re.escape('OS: Windows XP'))))

    def searchypserv(self):
        return self.searchscriptidout('rpcinfo', re.compile('ypserv', flags=0))

    def searchnfs(self):
        return self.searchscriptidout('rpcinfo', re.compile('nfs', flags=0))

    def searchtorcert(self):
        return self.searchscriptidout(
            'ssl-cert',
            re.compile('^Subject: CN=www\\.[a-z2-7]{8,20}\\.(net|com)($|\n)',
                       flags=0))

    def searchgeovision(self):
        return self.searchproduct(re.compile('^GeoVision', re.I))

    def searchwebcam(self):
        return self.searchdevicetype('webcam')

    def searchscriptidout(self, name, output):
        raise NotImplementedError

    def searchscriptid(self, name):
        raise NotImplementedError

    def searchhostscriptidout(self, name, out):
        raise NotImplementedError

    def searchport(self, port, protocol='tcp', state='open', neg=False):
        raise NotImplementedError

    def searchproduct(self, product):
        raise NotImplementedError

    def searchdevicetype(self, devtype):
        raise NotImplementedError


class DBPassive(DB):

    def searchtorcert(self):
        return self.searchcertsubject(
            re.compile('^CN=www\\.[a-z2-7]{8,20}\\.(net|com)$',
                       flags=0))

    def searchcertsubject(self, expr):
        raise NotImplementedError


class DBData(DB):
    pass


class DBAgent(DB):
    """Backend-independent code to handle agents-in-DB"""

    def add_agent(self, host, remotepath, rsync=None, source=None,
                  maxwaiting=60):
        """Prepares an agent and adds it to the DB using
        `self._add_agent()`

        """
        if rsync is None:
            rsync = ["rsync"]
        if not remotepath.endswith('/'):
            remotepath += '/'
        if source is None:
            source = ("" if host is None
                      else "%s:" % host) + remotepath
        utils.makedirs(config.AGENT_MASTER_PATH)
        localpath = tempfile.mkdtemp(prefix="",
                                     dir=config.AGENT_MASTER_PATH)
        for dirname in ["input", "remoteinput", "remotecur", "remoteoutput"]:
            utils.makedirs(os.path.join(localpath, dirname))
        agent = {
            "host": host,
            "path": {
                "remote": remotepath,
                "local": localpath,
            },
            "source": source,
            "rsync": rsync,
            "maxwaiting": maxwaiting,
            "scan": None,
            "sync": True,
        }
        return self._add_agent(agent)

    def add_agent_from_string(self, string, source=None, maxwaiting=60):
        """Adds an agent from a description string of the form
        [tor:][hostname:]path.

        """
        string = string.split(':', 1)
        if string[0].lower() == 'tor':
            string = string[1].split(':', 1)
            rsync = ['torify', 'rsync']
        else:
            rsync = None
        if len(string) == 1:
            return self.add_agent(None, string[0], rsync=rsync,
                                  source=source,
                                  maxwaiting=maxwaiting)
        return self.add_agent(string[0], string[1], rsync=rsync,
                              source=source,
                              maxwaiting=maxwaiting)

    def may_receive(self, agentid):
        """Returns the number of targets that can be added to an agent
        without exceeding its `maxwaiting` limit (the returned value
        cannot be negative).

        """
        agent = self.get_agent(agentid)
        curwaiting = sum(
            len(os.listdir(self.get_local_path(agent, p)))
            for p in ['input', 'remoteinput']
        )
        return max(agent["maxwaiting"] - curwaiting, 0)

    def has_waiting_targets(self, agentid):
        """Returns the number of waiting targets an agent has.

        """
        agent = self.get_agent(agentid)
        return (
            len(os.listdir(self.get_local_path(agent, 'input')))
            + len(os.listdir(self.get_local_path(agent, 'remoteinput')))
            + len(os.listdir(self.get_local_path(agent, 'remotecur'))) / 2
        )

    def get_local_path(self, agent, dirname):
        if not dirname.endswith('/'):
            dirname += '/'
        return os.path.join(agent["path"]["local"], dirname)

    def get_remote_path(self, agent, dirname):
        if not dirname.endswith('/'):
            dirname += '/'
        return ("%s:" % agent['host']
                if agent['host'] is not None
                else ''
            ) +  os.path.join(agent["path"]["remote"], dirname)

    def sync_all(self):
        for agentid in self.get_agents():
            self.sync(agentid)

    def sync(self, agentid):
        agent = self.get_agent(agentid)
        subprocess.call(agent['rsync'] + [
            '-a',
            self.get_local_path(agent, 'input'),
            self.get_local_path(agent, 'remoteinput')
        ])
        subprocess.call(agent['rsync'] + [
            '-a', '--remove-source-files',
            self.get_local_path(agent, 'input'),
            self.get_remote_path(agent, 'input')
        ])
        subprocess.call(agent['rsync'] + [
            '-a', '--delete',
            self.get_remote_path(agent, 'input'),
            self.get_local_path(agent, 'remoteinput')
        ])
        subprocess.call(agent['rsync'] + [
            '-a', '--delete',
            self.get_remote_path(agent, 'cur'),
            self.get_local_path(agent, 'remotecur')
        ])
        subprocess.call(agent['rsync'] + [
            '-a', '--remove-source-files',
            self.get_remote_path(agent, 'output'),
            self.get_local_path(agent, 'remoteoutput')
        ])
        outpath = self.get_local_path(agent, 'remoteoutput')
        for fname in os.listdir(outpath):
            scanid = fname.split('-', 1)[0]
            scan = self.get_scan(self.str2id(scanid))
            storedir = os.path.join(
                config.AGENT_MASTER_PATH,
                "output",
                scanid,
                str(agentid),
            )
            utils.makedirs(storedir)
            with tempfile.NamedTemporaryFile(dir=storedir,
                                             delete=False) as fdesc:
                pass
            shutil.move(
                os.path.join(outpath, fname),
                fdesc.name
            )
            self.globaldb.nmap.store_scan(
                fdesc.name,
                categories=scan['target'].target.infos['categories'],
                source=agent['source'],
            )
            # TODO gettoarchive parameter
            self.incr_scan_results(self.str2id(scanid))

    def feed_all(self):
        for scanid in self.get_scans():
            self.feed(scanid)

    def feed(self, scanid):
        scan = self.get_scan(scanid)
        # TODO: lock
        target = scan['target']
        try:
            for agentid in scan['agents']:
                for _ in xrange(self.may_receive(agentid)):
                    self.add_target(agentid, scanid, target.next())
        except StopIteration:
            # This scan is over, let's free its agents
            for agentid in scan['agents']:
                self.unassign_agent(agentid)
        self.update_scan_target(scanid, target)

    def add_target(self, agentid, scanid, addr):
        agent = self.get_agent(agentid)
        try:
            addr = utils.ip2int(addr)
        except (TypeError, utils.socket.error):
            pass
        with tempfile.NamedTemporaryFile(
                prefix=str(scanid) + '-',
                dir=self.get_local_path(agent, "input"),
                delete=False,
        ) as fdesc:
            fdesc.write("%s\n" % addr)
            return True
        return False

    def _add_agent(self, agent):
        """Adds an agent and returns its (backend-specific) unique
        identifier.

        This is implemented in the backend-specific class.

        """
        raise NotImplementedError

    def get_agent(self, agentid):
        """Gets an agent from its (backend-specific) unique
        identifier.

        This is implemented in the backend-specific class.

        """
        raise NotImplementedError

    def get_free_agents(self):
        raise NotImplementedError

    def get_agents(self):
        raise NotImplementedError

    def del_agent(self, agentid, wait_results=True):
        """Removes an agent from its (backend-specific) unique
        identifier.
        """
        agent = self.get_agent(agentid)
        # stop adding targets
        self.unassign_agent(agentid, dont_reuse=True)
        # remove not-yet-sent targets
        path = self.get_local_path(agent, "input")
        dstdir = os.path.join(config.AGENT_MASTER_PATH, "onhold")
        for fname in os.listdir(path):
            shutil.move(os.path.join(path, fname), dstdir)
        if wait_results:
            self.sync(agentid)

    def _del_agent(self, agentid):
        """Removes an agent's database entry from its
        (backend-specific) unique identifier.

        This is implemented in the backend-specific class.

        """
        raise NotImplementedError

    def add_scan(self, target, assign_to_free_agents=True):
        scan = {
            "target": pickle.dumps(target.__iter__()),
            "agents": [],
            "results": 0,
        }
        scanid = self._add_scan(scan)
        if assign_to_free_agents:
            for agentid in self.get_free_agents():
                self.assign_agent(agentid, scanid)

    def _add_scan(self, scan):
        raise NotImplementedError

    def get_scan(self, scanid):
        scan = self._get_scan(scanid)
        scan['target'] = pickle.loads(scan['target'])
        return scan

    def get_scans(self):
        raise NotImplementedError

    def _get_scan(self, scanid):
        raise NotImplementedError

    def assign_agent(self, agentid, scanid,
                     only_if_unassigned=False,
                     force=False):
        raise NotImplementedError

    def unassign_agent(self, agentid, dont_reuse=False):
        raise NotImplementedError

    def update_scan_target(self, scanid, target):
        return self._update_scan_target(scanid, pickle.dumps(target))

    def _update_scan_target(self, scanid, target):
        raise NotImplementedError

    def incr_scan_results(self, scanid):
        raise NotImplementedError


class MetaDB(object):
    db_types = {
        "nmap": {},
        "passive": {},
        "data": {},
        "agent": {},
    }
    nmap = None
    passive = None
    data = None

    def url2dbinfos(self, url):
        url = urlparse.urlparse(url)
        userinfo = {}
        if '@' in url.netloc:
            username = url.netloc[:url.netloc.index('@')]
            if ':' in username:
                userinfo = dict(zip(["username", "password"],
                                    map(urllib.unquote,
                                        username.split(':', 1))))
            else:
                username = urllib.unquote(username)
                if username == 'GSSAPI':
                    import krbV
                    userinfo = {
                        'username': (krbV
                                     .default_context()
                                     .default_ccache()
                                     .principal().name),
                        'mechanism': 'GSSAPI'}
                elif '@' in username:
                    userinfo = {'username': username,
                                'mechanism': 'GSSAPI'}
                else:
                    userinfo = {'username': username}
            hostname = url.netloc[url.netloc.index('@') + 1:]
        else:
            hostname = url.netloc
        if not hostname:
            hostname = None
        dbname = url.path.lstrip('/')
        if not dbname:
            dbname = 'ivre'
        params = dict(x.split('=', 1) if '=' in x else [x, None]
                      for x in url.query.split('&') if x)
        params.update(userinfo)
        return (url.scheme,
                (hostname, dbname),
                params)

    def __init__(self, url=None, urls=None):
        try:
            from ivre.db.mongo import MongoDBNmap, MongoDBPassive, MongoDBData, MongoDBAgent
            self.db_types["nmap"]["mongodb"] = MongoDBNmap
            self.db_types["passive"]["mongodb"] = MongoDBPassive
            self.db_types["data"]["mongodb"] = MongoDBData
            self.db_types["agent"]["mongodb"] = MongoDBAgent
        except ImportError:
            pass
        if urls is None:
            urls = {}
        for datatype, dbtypes in self.db_types.iteritems():
            specificurl = urls.get(datatype, url)
            if specificurl is not None:
                (spurlscheme,
                 spurlhostdb,
                 spurlparams) = self.url2dbinfos(specificurl)
                setattr(
                    self,
                    datatype,
                    dbtypes[spurlscheme](*spurlhostdb, **spurlparams))
                getattr(self, datatype).globaldb = self

db = MetaDB(
    url=config.DB if hasattr(config, "DB") else None,
    urls=dict([x[3:].lower(), getattr(config, x)]
              for x in dir(config) if x.startswith('DB_')))
