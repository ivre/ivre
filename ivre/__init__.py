#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

"""
This module is part of IVRE.
Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
"""

import os
import re
import subprocess


_DIR = os.path.dirname(__file__)
_VERSION_FILE = os.path.join(_DIR, 'VERSION')


def _get_version_from_file():
    try:
        with open(_VERSION_FILE) as fdesc:
            return fdesc.read()
    except IOError:
        return

def _get_version_from_git():
    proc = subprocess.Popen(['git', 'describe', '--always'],
                            stdout=subprocess.PIPE, stderr=open(os.devnull),
                            cwd=os.path.join(_DIR, os.path.pardir))
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, err)
    tag = out.strip()
    match = re.match(r'^v?(.+?)-(\d+)-g[a-f0-9]+$', tag)
    if match:
        # remove the 'v' prefix and add a '.devN' suffix
        value = '%s.dev%s' % match.groups()
    else:
        # just remove the 'v' prefix
        value = tag[1:] if tag.startswith('v') else tag
    return value

def _version():
    try:
        tag = _get_version_from_git()
    except subprocess.CalledProcessError as exc:
        pass
    else:
        try:
            with open(_VERSION_FILE, 'w') as fdesc:
                fdesc.write(tag)
        except IOError:
            pass
        return tag
    try:
        with open(_VERSION_FILE) as fdesc:
            return fdesc.read()
    except IOError:
        pass
    hashval, refnames = '$Format:%h %D$'.split(' ', 1)
    try:
        return next(ref[6:] for ref in refnames.split(', ') if ref.startswith('tag: v'))
    except StopIteration:
        pass
    return hashval if hashval else 'unknown.version'


VERSION = _version()
