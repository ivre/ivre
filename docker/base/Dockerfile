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

FROM ubuntu:latest
MAINTAINER Pierre LALET <pierre.lalet@cea.fr>

ENV DEBIAN_FRONTEND noninteractive

# Dependencies
RUN apt-get -q update
RUN apt-get -qy install python-pymongo python-crypto

# IVRE
ADD https://github.com/cea-sec/ivre/zipball/master ./ivre.zip
RUN apt-get -qy install unzip && \
    unzip ivre.zip && rm ivre.zip && \
    apt-get -qy --purge remove unzip && \
    apt-get -qy --purge autoremove && \
    mv cea-sec-ivre-* ivre && \
    cd ivre/ && \
    python setup.py build && python setup.py install && \
    cd ../ && rm -rf ivre/

# Config
ADD ivre.conf /etc/ivre.conf
