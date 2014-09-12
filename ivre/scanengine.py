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

This sub-module is responsible for handling scanning agents.
"""

from ivre import utils

import os
import glob
import subprocess
import random
import time
import re


class Agent(object):

    """An Agent instance is a (possibly remote) scanner."""

    def __init__(self, host, remotepathbase, localpathbase,
                 name=None, usetor=False, maxwaiting=60):
        self.host = host
        self.remotepathbase = remotepathbase
        self.localpathbase = localpathbase
        self.maxwaiting = maxwaiting
        if host is None:
            self.rsyncbase = remotepathbase
        else:
            self.rsyncbase = '%s:%s' % (host, remotepathbase)
        if self.rsyncbase[-1] not in ':/':
            self.rsyncbase += '/'
        if name is None:
            self.name = localpathbase.lstrip('./')
        else:
            self.name = name
        if usetor:
            self.rsync = ['torify', 'rsync']
        else:
            self.rsync = ['rsync']
        self.campaigns = []

    @classmethod
    def from_string(cls, string, localbase='', maxwaiting=60):
        """Builds an Agent instance from a description string of the
        form [tor:][hostname:]path.

        """
        string = string.split(':', 1)
        if string[0].lower() == 'tor':
            string = string[1].split(':', 1)
            usetor = True
        else:
            usetor = False
        if len(string) == 1:
            return cls(None, string[0],
                       os.path.join(localbase, string[0].replace('/', '_')),
                       maxwaiting=maxwaiting)
        return cls(string[0], string[1],
                   os.path.join(localbase, '%s_%s' % (
                       string[0].replace('@', '_'),
                       string[1].replace('/', '_'))),
                   usetor=usetor, maxwaiting=maxwaiting)

    def get_local_path(self, name):
        return os.path.join(self.localpathbase, name) + '/'

    def get_remote_path(self, name):
        if name and name[-1] != '/':
            name += '/'
        return self.rsyncbase + name

    def create_local_dirs(self):
        for dirname in ['input', 'remoteinput', 'remotecur', 'remoteoutput']:
            utils.makedirs(self.get_local_path(dirname))

    def may_receive(self):
        curwaiting = sum(len(os.listdir(self.get_local_path(p)))
                         for p in ['input', 'remoteinput'])
        return self.maxwaiting - curwaiting

    def add_target(self, category, addr):
        with open(os.path.join(self.get_local_path('input'),
                               '%s.%s' % (category, addr)), 'w') as fdesc:
            fdesc.write('%s\n' % addr)
            return True
        return False

    def sync(self):
        subprocess.call(self.rsync + ['-a',
                                      self.get_local_path('input'),
                                      self.get_local_path('remoteinput')])
        subprocess.call(self.rsync + ['-a', '--remove-source-files',
                                      self.get_local_path('input'),
                                      self.get_remote_path('input')])
        subprocess.call(self.rsync + ['-a', '--delete',
                                      self.get_remote_path('input'),
                                      self.get_local_path('remoteinput')])
        subprocess.call(self.rsync + ['-a', '--delete',
                                      self.get_remote_path('cur'),
                                      self.get_local_path('remotecur')])
        subprocess.call(self.rsync + ['-a', '--remove-source-files',
                                      self.get_remote_path('output'),
                                      self.get_local_path('remoteoutput')])
        for campaign in self.campaigns:
            campaign.sync(self)


class Campaign(object):

    def __init__(self, targets, category, agents, outputpath,
                 visiblecategory=None, maxfeed=None, sleep=2,
                 storedown=True):
        self.targets = targets
        self.targiter = targets.__iter__()
        self.category = category
        for agent in agents:
            agent.campaigns.append(self)
        self.agents = agents
        self.outputpath = outputpath
        if visiblecategory is None:
            self.visiblecategory = ''.join(chr(random.randrange(65, 91))
                                           for _ in xrange(10))
        else:
            self.visiblecategory = visiblecategory
        self.maxfeed = maxfeed
        self.sleep = sleep
        self.storedown = storedown

    def sync(self, agent):
        remout = agent.get_local_path('remoteoutput')
        for remfname in glob.glob(
                os.path.join(remout, self.visiblecategory + '.*.xml')):
            locfname = os.path.basename(remfname).split('.', 4)
            locfname[0] = self.category
            status = 'unknown'
            with open(remfname) as remfdesc:
                remfcontent = remfdesc.read()
                if '<status state="up"' in remfcontent:
                    status = 'up'
                elif '<status state="down"' in remfcontent:
                    if not self.storedown:
                        remfdesc.close()
                        os.unlink(remfname)
                        continue
                    status = 'down'
                del remfcontent
            locfname = os.path.join(
                self.outputpath,
                locfname[0],
                status,
                re.sub('[/@:]', '_', agent.name),
                *locfname[1:])
            utils.makedirs(os.path.dirname(locfname))
            os.rename(remfname, locfname)

    def feed(self, agent, maxnbr=None):
        for _ in xrange(max(agent.may_receive(), maxnbr)):
            addr = utils.int2ip(self.targiter.next())
            with open(os.path.join(agent.get_local_path('input'),
                                   '%s.%s' % (self.visiblecategory, addr)),
                      'w') as fdesc:
                fdesc.write('%s\n' % addr)

    def feedloop(self):
        while True:
            for agent in self.agents:
                try:
                    self.feed(agent, maxnbr=self.maxfeed)
                except StopIteration:
                    return
            time.sleep(self.sleep)


def syncloop(agents, sleep=2):
    while True:
        for agent in agents:
            agent.sync()
        time.sleep(sleep)
