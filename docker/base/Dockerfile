# This file is part of IVRE.
# Copyright 2011 - 2022 Pierre LALET <pierre@droids-corp.org>
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
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

ENV DEBIAN_FRONTEND noninteractive

# Dependencies
RUN echo "deb http://deb.debian.org/debian stable-backports main" >> /etc/apt/sources.list
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install python3-pymongo python3-cryptography \
        python3-setuptools python3-bottle python3-openssl ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# IVRE
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install git && \
    git clone https://github.com/ivre/ivre && \
    cd ivre/ && python3 setup.py build && python3 setup.py install && \
    apt-get -qy --purge autoremove git && cd ../ && rm -rf ivre/ && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Fix version
RUN echo -en "-docker" >> /usr/local/lib/python*/dist-packages/ivre/VERSION && \
    sed -ri 's#(VERSION = .*)(['\''"])$#\1-docker\2#' /usr/local/lib/python*/dist-packages/ivre/__init__.py

RUN echo 'DB = "mongodb://ivredb/"' > /etc/ivre.conf
