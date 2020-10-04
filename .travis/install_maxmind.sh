#! /bin/sh

# This file is part of IVRE.
# Copyright 2011 - 2020 Pierre LALET <pierre@droids-corp.org>
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
# We only run codespell and pylint once, with Python 3.8
if [ "$TRAVIS_PYTHON_VERSION" = 3.8 ]; then
    pip install -U $PIP_INSTALL_OPTIONS -r requirements-linting.txt
else
    pip install -U $PIP_INSTALL_OPTIONS flake8
fi
