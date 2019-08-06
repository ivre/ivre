#! /bin/sh

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

PIP_INSTALL_OPTIONS=""
# We only run codespell and pylint once, with Python 3.7
test "$TRAVIS_PYTHON_VERSION" = 3.7 && pip install -U $PIP_INSTALL_OPTIONS codespell pylint
# flake8 won't run with Python 2.6 or 3.3
test "$TRAVIS_PYTHON_VERSION" = 2.6 || test "$TRAVIS_PYTHON_VERSION" = 3.3 || pip install -U $PIP_INSTALL_OPTIONS flake8
