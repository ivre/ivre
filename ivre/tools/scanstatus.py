#! /usr/bin/env python

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

import sys
import re
import datetime

def main():
    statusline = re.compile(
        '<task(?P<status>begin|end|progress) task="(?P<task>[^"]*)" '
        'time="(?P<time>[^"]*)"(?P<otherinfo>.*)/>')
    progressinfo = re.compile(
        'percent="(?P<percent>[^"]*)" remaining="(?P<remaining>[^"]*)" '
        'etc="(?P<etc>[^"]*)"')
    endinfo = re.compile('extrainfo="(?P<extrainfo>[^"]*)"')
    curtask = None
    curprogress = None
    for line in sys.stdin:
        line = statusline.match(line)
        if line is None:
            continue
        line = line.groupdict()
        if line['status'] == 'begin':
            curtask = (line['task'], int(line['time']))
            curprogress = None
            continue
        if curtask[0] != line['task']:
            raise Exception('curtask != task (%r != %r)' % (curtask,
                                                            line['task']))
        elif line['status'] == 'progress':
            progress = progressinfo.search(line['otherinfo'])
            if progress is None:
                raise Exception(
                    'progress line not understood [%r]' % line['otherinfo'])
            progress = progress.groupdict()
            curprogress = (
                int(line['time']),
                float(progress['percent']),
                int(progress['remaining']),
                int(progress['etc']),
            )
        elif line['status'] == 'end':
            end = endinfo.search(line['otherinfo'])
            if end is None:
                end = ''
            else:
                end = ' ' + end.group('extrainfo') + '.'
            print 'task %s completed in %d seconds.%s' % (
                curtask[0],
                int(line['time']) - curtask[1],
                end)
            curtask = None
            curprogress = None

    if curtask is not None:
        now = int(datetime.datetime.now().strftime('%s'))
        if curprogress is None:
            progress = ''
        else:
            progress = '\n     %d seconds ago: %.2f %% done, ' \
                       'remaining %d seconds.\n     ETC %s.' % (
                           now - curprogress[0],
                           curprogress[1],
                           curprogress[2],
                           datetime.datetime.fromtimestamp(curprogress[3]))
        print "task %s running for %d seconds.%s" % (
            curtask[0],
            now - curtask[1],
            progress
        )
