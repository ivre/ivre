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
import socket
import re
import struct
import urllib
try:
    import urlparse
except ImportError:
    from urllib import parse as urlparse
import xml.sax
import os
import subprocess
import shutil
import tempfile
import pickle
import uuid
from six import iteritems
from functools import reduce

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

    @staticmethod
    def _flt_and(cond1, cond2):
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

    @staticmethod
    def _flt_or(cond1, cond2):
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

    @staticmethod
    def searchrange(start, stop, neg=False):
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

    @staticmethod
    def searchuseragent(useragent):
        """Finds specified User-Agent(s)."""
        raise NotImplementedError

    def get(self, spec, **kargs):
        """Gets a cursor, which can be iterated to get results.

        The type of that cursor is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    @staticmethod
    def getid(record):
        """Gets a unique identifier for a specified `record`.

        The type of the identifier is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    @staticmethod
    def searchid(idval, neg=False):
        """Gets a specific record given its unique identifier `idval`.

        The type of the identifier is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    @staticmethod
    def str2id(string):
        """Returns a unique identifier from `string`.

        The type of the identifier is backend-specific, and this is
        typically implemented in the backend-specific subclasses

        """
        raise NotImplementedError

    if USE_CLUSTER:
        @staticmethod
        def hierarchical_clustering(values):
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
            '--asnum', metavar='NUM[,NUM[...]]',
            help='show only results from this(those) AS(es)')
        self.argparser.add_argument(
            '--asname', metavar='NAME',
            help='show only results from this(those) AS(es)')
        self.argparser.add_argument('--source', metavar='SRC',
                                    help='show only results from this source')
        self.argparser.add_argument('--timeago', metavar='SECONDS', type=int)
        self.argparser.add_argument('--host', metavar='IP')
        self.argparser.add_argument('--hostname')
        self.argparser.add_argument('--domain')
        self.argparser.add_argument('--net', metavar='IP/MASK')
        self.argparser.add_argument('--hop', metavar='IP')
        self.argparser.add_argument('--port', metavar='PORT')
        self.argparser.add_argument('--not-port', metavar='PORT')
        self.argparser.add_argument('--openport', action='store_true')
        self.argparser.add_argument('--no-openport', action='store_true')
        self.argparser.add_argument('--service', metavar='SVC')
        self.argparser.add_argument('--script', metavar='ID[:OUTPUT]')
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
        self.argparser.add_argument('--archives', action='store_true')

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
                str(exc), exc, fname))
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
            self.searchsmb(os="Windows 5.1"),
        )

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

    @staticmethod
    def searchscriptidout(name, output):
        raise NotImplementedError

    @staticmethod
    def searchscriptid(name):
        raise NotImplementedError

    @staticmethod
    def searchhostscriptidout(name, out):
        raise NotImplementedError

    @staticmethod
    def searchport(port, protocol='tcp', state='open', neg=False):
        raise NotImplementedError

    @staticmethod
    def searchproduct(product, version=None, service=None, port=None):
        raise NotImplementedError

    @staticmethod
    def searchdevicetype(devtype):
        raise NotImplementedError

    @staticmethod
    def searchsmb(**args):
        """Search particular results from smb-os-discovery host
        script. Example:

        .searchsmb(os="Windows 5.1", workgroup="WORKGROUP\\x00")

        """
        raise NotImplementedError


class DBPassive(DB):

    def insert_or_update(self, timestamp, spec, getinfos=None):
        raise NotImplementedError

    def insert_or_update_bulk(self, specs, getinfos=None):
        """Like `.insert_or_update()`, but `specs` parameter has to be
        an iterable of (timestamp, spec) values. This generic
        implementation does not use bulk capacity of the underlying DB
        implementation but rather calls its `.insert_or_update()`
        method.

        """
        for timestamp, spec in specs:
            self.insert_or_update(timestamp, spec, getinfos=getinfos)

    def searchtorcert(self):
        return self.searchcertsubject(
            re.compile('^CN=www\\.[a-z2-7]{8,20}\\.(net|com)$',
                       flags=0))

    @staticmethod
    def searchcertsubject(expr):
        raise NotImplementedError


class DBData(DB):
    country_codes = None

    def parse_line_country(self, line, feedipdata=None,
                           createipdata=False):
        if line.endswith('\n'):
            line = line[:-1]
        if line.endswith('"'):
            line = line[:-1]
        if line.startswith('"'):
            line = line[1:]
        line = line.split('","')
        if line[4] not in self.country_codes:
            self.country_codes[line[4]] = line[5]
        if feedipdata is not None:
            for dbinst in feedipdata:
                dbinst.update_country(
                    int(line[2]), int(line[3]), line[4],
                    create=createipdata
                )
        return {'start': int(line[2]),
                'stop': int(line[3]),
                'country_code': line[4]}

    @staticmethod
    def parse_line_city(line, feedipdata=None, createipdata=False):
        if line.endswith('\n'):
            line = line[:-1]
        if line.endswith('"'):
            line = line[:-1]
        if line.startswith('"'):
            line = line[1:]
        line = line.split('","')
        if feedipdata is not None:
            for dbinst in feedipdata:
                dbinst.update_city(
                    int(line[0]), int(line[1]), line[2],
                    create=createipdata
                )
        return {'start': int(line[0]),
                'stop': int(line[1]),
                'location_id': int(line[2])}

    @staticmethod
    def parse_line_city_location(line):
        if line.endswith('\n'):
            line = line[:-1]
        # Get an integer
        i = line.index(',')
        parsedline = {'location_id': int(line[:i])}
        line = line[i + 1:]
        # Get 4 strings
        for field in ['country_code', 'region_code', 'city',
                      'postal_code']:
            i = line.index('",')
            curval = line[1:i]
            if curval:
                parsedline[field] = curval.decode('latin-1')
            line = line[i + 2:]
        # Get 2 floats
        coords = []
        for i in xrange(2):
            i = line.index(',')
            curval = line[:i]
            if curval:
                coords.append(float(curval))
            line = line[i + 1:]
        if len(coords) == 2:
            parsedline['loc'] = {
                'type': 'Point',
                'coordinates': [coords[1], coords[0]],
            }
        # Get 1 int
        i = line.index(',')
        curval = line[:i]
        if curval:
            parsedline['metro_code'] = int(curval)
        line = line[i + 1:]
        # Pop 1 int or None (at the end of the line)
        if line:
            parsedline['area_code'] = int(line)
        return parsedline

    @staticmethod
    def parse_line_asnum(line, feedipdata=None, createipdata=False):
        if line.endswith('\n'):
            line = line[:-1]
        line = line.split(',', 2)
        parsedline = {
            'start': int(line[0]),
            'stop': int(line[1]),
        }
        data = line[2]
        if data.endswith('"'):
            data = data[:-1]
        if data.startswith('"'):
            data = data[1:]
        if data.startswith('AS'):
            data = data.split(None, 1)
            parsedline['as_num'] = int(data[0][2:])
            if len(data) == 2:
                parsedline['as_name'] = data[1].decode('latin-1')
        else:
            parsedline['as_num'] = -1
            parsedline['as_name'] = data.decode('latin-1')
        if feedipdata is not None:
            for dbinst in feedipdata:
                dbinst.update_as(parsedline['start'],
                                 parsedline['stop'],
                                 parsedline['as_num'],
                                 parsedline.get('as_name'),
                                 create=createipdata)
        return parsedline


class DBAgent(DB):
    """Backend-independent code to handle agents-in-DB"""

    def add_agent(self, masterid, host, remotepath,
                  rsync=None, source=None, maxwaiting=60):
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
        master = self.get_master(masterid)
        localpath = tempfile.mkdtemp(prefix="", dir=master['path'])
        for dirname in ["input"] + [os.path.join("remote", dname)
                                    for dname in ["input", "cur",
                                                  "output"]]:
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
            "master": masterid,
        }
        return self._add_agent(agent)

    def add_agent_from_string(self, masterid, string,
                              source=None, maxwaiting=60):
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
            return self.add_agent(masterid, None, string[0],
                                  rsync=rsync,
                                  source=source,
                                  maxwaiting=maxwaiting)
        return self.add_agent(masterid, string[0], string[1],
                              rsync=rsync,
                              source=source,
                              maxwaiting=maxwaiting)

    def may_receive(self, agentid):
        """Returns the number of targets that can be added to an agent
        without exceeding its `maxwaiting` limit (the returned value
        cannot be negative).

        """
        agent = self.get_agent(agentid)
        return max(agent["maxwaiting"] - self.count_waiting_targets(agentid),
                   0)

    def count_waiting_targets(self, agentid):
        """Returns the number of waiting targets an agent has.

        """
        agent = self.get_agent(agentid)
        return sum(
            len(os.listdir(self.get_local_path(agent, path)))
            for path in ['input', os.path.join('remote', 'input')]
        )

    def count_current_targets(self, agentid):
        """Returns the number of waiting targets an agent has.

        """
        agent = self.get_agent(agentid)
        return sum(
            1 for fname in os.listdir(self.get_local_path(
                agent,
                os.path.join("remote", "cur")))
            if fname.endswith('.xml')
        )

    @staticmethod
    def get_local_path(agent, dirname):
        if not dirname.endswith('/'):
            dirname += '/'
        return os.path.join(agent["path"]["local"], dirname)

    @staticmethod
    def get_remote_path(agent, dirname):
        if dirname and not dirname.endswith('/'):
            dirname += '/'
        return "%s%s" % (
            '' if agent['host'] is None else "%s:" % agent['host'],
            os.path.join(agent["path"]["remote"], dirname)
        )

    def sync_all(self, masterid):
        for agentid in self.get_agents_by_master(masterid):
            self.sync(agentid)

    def sync(self, agentid):
        agent = self.get_agent(agentid)
        master = self.get_master(agent['master'])
        subprocess.call(agent['rsync'] + [
            '-a',
            self.get_local_path(agent, 'input'),
            self.get_local_path(agent, os.path.join('remote', 'input'))
        ])
        subprocess.call(agent['rsync'] + [
            '-a', '--remove-source-files',
            self.get_local_path(agent, 'input'),
            self.get_remote_path(agent, 'input')
        ])
        for dname in ['input', 'cur']:
            subprocess.call(agent['rsync'] + [
                '-a', '--delete',
                self.get_remote_path(agent, dname),
                self.get_local_path(agent, os.path.join('remote', dname))
            ])
        subprocess.call(agent['rsync'] + [
            '-a', '--remove-source-files',
            self.get_remote_path(agent, 'output'),
            self.get_local_path(agent, os.path.join('remote', 'output'))
        ])
        outpath = self.get_local_path(agent, os.path.join('remote', 'output'))
        for fname in os.listdir(outpath):
            scanid = fname.split('-', 1)[0]
            scan = self.get_scan(self.str2id(scanid))
            storedir = os.path.join(
                master["path"],
                "output",
                scanid,
                str(agentid),
            )
            utils.makedirs(storedir)
            with tempfile.NamedTemporaryFile(prefix="",
                                             suffix=".xml",
                                             dir=storedir,
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

    def feed_all(self, masterid):
        for scanid in self.get_scans():
            self.feed(masterid, scanid)

    def feed(self, masterid, scanid):
        scan = self.lock_scan(scanid)
        if scan is None:
            raise StandardError(
                "Could not acquire lock for scan %s" % scanid
            )
        # TODO: handle "onhold" targets
        target = scan['target']
        try:
            for agentid in scan['agents']:
                if self.get_agent(agentid)['master'] == masterid:
                    for _ in xrange(self.may_receive(agentid)):
                        self.add_target(agentid, scanid, target.next())
        except StopIteration:
            # This scan is over, let's free its agents
            for agentid in scan['agents']:
                self.unassign_agent(agentid)
        self.update_scan_target(scanid, target)
        self.unlock_scan(scan)

    def add_target(self, agentid, scanid, addr):
        agent = self.get_agent(agentid)
        try:
            addr = int(addr)
            addr = utils.int2ip(addr)
        except (ValueError, struct.error):
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

    def get_agents_by_master(self, masterid):
        raise NotImplementedError

    def get_agents(self):
        raise NotImplementedError

    def del_agent(self, agentid, wait_results=True):
        """Removes an agent from its (backend-specific) unique
        identifier.
        """
        agent = self.get_agent(agentid)
        master = self.get_master(agent['master'])
        # stop adding targets
        self.unassign_agent(agentid, dont_reuse=True)
        # remove not-yet-sent targets
        path = self.get_local_path(agent, "input")
        dstdir = os.path.join(master["path"], "onhold")
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
            "lock": None
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

    def lock_scan(self, scanid):
        lockid = uuid.uuid1()
        scan = self._lock_scan(scanid, None, lockid.bytes)
        scan['target'] = pickle.loads(scan['target'])
        if scan['lock'] is not None:
            scan['lock'] = uuid.UUID(bytes=scan['lock'])
        if scan['lock'] == lockid:
            return scan

    def unlock_scan(self, scan):
        scan = self._lock_scan(scan['_id'], scan['lock'].bytes, None)
        return scan['lock'] is None

    def _lock_scan(self, scanid, oldlockid, newlockid):
        raise NotImplementedError

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

    def add_local_master(self, path):
        masterid = self.add_master(socket.gethostname(), path)
        with open(os.path.join(path, "whoami"), "w") as fdesc:
            fdesc.write(str(masterid))
        return masterid

    def add_master(self, hostname, path):
        """Prepares a master and adds it to the DB using
        `self._add_master()`

        """
        master = {
            "hostname": hostname,
            "path": path,
        }
        return self._add_master(master)

    def _add_master(self, master):
        """Adds a master and returns its (backend-specific) unique
        identifier.

        This is implemented in the backend-specific class.

        """
        raise NotImplementedError

    def get_master(self, masterid):
        raise NotImplementedError

    def masterid_from_dir(self, path):
        with open(os.path.join(path, "whoami")) as fdesc:
            return self.str2id(fdesc.read())


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
    agent = None

    @staticmethod
    def url2dbinfos(url):
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
            from ivre.db.mongo import (MongoDBNmap, MongoDBPassive,
                                       MongoDBData, MongoDBAgent)
            self.db_types["nmap"]["mongodb"] = MongoDBNmap
            self.db_types["passive"]["mongodb"] = MongoDBPassive
            self.db_types["data"]["mongodb"] = MongoDBData
            self.db_types["agent"]["mongodb"] = MongoDBAgent
        except ImportError:
            pass
        if urls is None:
            urls = {}
        for datatype, dbtypes in iteritems(self.db_types):
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
