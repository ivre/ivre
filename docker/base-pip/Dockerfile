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

FROM debian:stable
LABEL maintainer="Pierre LALET <pierre.lalet@cea.fr>"

ENV DEBIAN_FRONTEND noninteractive

# Install pip, get IVRE, uninstall pip
RUN apt-get -q update
RUN apt-get -qy install python python-dev python-pip && \
    pip install ivre && \
    apt-get -qy autoremove python-dev python-pip

# Config
COPY ivre.conf /etc/ivre.conf
