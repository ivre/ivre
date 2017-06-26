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

FROM debian:stable
MAINTAINER Pierre LALET <pierre.lalet@cea.fr>

ENV DEBIAN_FRONTEND noninteractive

# Dependencies
RUN echo "deb http://deb.debian.org/debian stable-backports main" >> /etc/apt/sources.list
RUN apt-get -q update
RUN apt-get -qy install python-pymongo python-crypto python-setuptools python-future

# Py2neo
ADD https://github.com/nigelsmall/py2neo/tarball/py2neo-3.0.0 ./py2neo.tar.gz
RUN tar zxf ./py2neo.tar.gz && rm ./py2neo.tar.gz && \
    mv nigelsmall-py2neo-* py2neo && cd py2neo && \
    python setup.py build && python setup.py install && \
    cd ../ && rm -rf py2neo/

# IVRE
RUN apt-get -qy install git && git clone https://github.com/cea-sec/ivre && \
    cd ivre/ && python setup.py build && python setup.py install && \
    apt-get -qy --purge autoremove git && cd ../ && rm -rf ivre/

# Config
ADD ivre.conf /etc/ivre.conf
