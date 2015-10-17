#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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

"""This sub-module contains the StackCli class that might be usefull
to implement a context-dependant CLI.

"""

from cmd import Cmd


COLORS = {
    'std': '\033[0m',   # White
    'red': '\033[31m',
    'green': '\033[32m',
    'orange': '\033[33m',
    'blue': '\033[34m',
    'purple': '\033[35m',
    'cyan': '\033[36m',
    'gray': '\033[37m',
    'tan': '\033[93m',
}


LOG_LEVELS = {
    'usage': {'name': 'USAGE', 'color': COLORS['green']},
    'info': {'name': 'INFO', 'color': COLORS['orange']},
    'warning': {'name': 'WARNING', 'color': COLORS['red']}
}


def colorize_log(info_level, text):
    """
    Print `text` to stdout considering its `info_level`
    `info_level` can be 'usage', 'info' or 'warning'
    """
    if info_level not in LOG_LEVELS.keys():
        raise ValueError('Wrong `info_level` value: %s' % info_level)
    log = LOG_LEVELS[info_level]
    print '[%s%s%s] %s' % (log['color'], log['name'], COLORS['std'], text)


class StackCli(Cmd):
    """
    Base class for stacked contexts CLI
    """
    def __init__(self):
        Cmd.__init__(self)
        self._context_stack = []
        self.prompt = '> '

    def parseline(self, line):
        """Hook to transform '..' in 'back'"""
        # Hack for '..' to be considered as 'back'.
        if line.strip().startswith('..'):
            return ('back', '', 'back')
        return Cmd.parseline(self, line)

    def _make_prompt(self):
        """Update prompt with context_stack"""
        self.prompt = '/'.join(map(str, self._context_stack[-3:]))
        if not self.prompt:
            self.prompt = '> '
        else:
            self.prompt = COLORS['blue'] + self.prompt + COLORS['std'] + ' > '

    def push(self, context):
        """Stack one context"""
        self._context_stack.append(context)
        self._make_prompt()

    def pop(self):
        """Unstack one context"""
        if len(self._context_stack) <= 1:
            raise IndexError('Cannot pop last context!')
        self._context_stack.pop()
        self._make_prompt()

    def get_context(self):
        """Return current context"""
        if not self._context_stack:
            raise IndexError('No context available!')
        return self._context_stack[-1]

    def do_pwd(self, _):
        """Print full context on 'pwd' command"""
        print '/'.join(map(str, self._context_stack))

    def do_back(self, _):
        """Unstack one context on 'back' command"""
        try:
            self.pop()
        except IndexError:
            pass

    @staticmethod
    def do_EOF(_):
        """Properly exit program when 'EOF' is typed"""
        print ''
        # Exit properly.
        return True
