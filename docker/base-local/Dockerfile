# This file is part of IVRE.
# Copyright 2011 - 2019 Pierre LALET <pierre.lalet@cea.fr>
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

# Dependencies
RUN echo "deb http://deb.debian.org/debian stable-backports main" >> /etc/apt/sources.list
RUN apt-get -q update
RUN apt-get -qy install python-pymongo python-crypto python-setuptools \
    python-future python-bottle ca-certificates

# IVRE
ADD ivre.tar ./
RUN cd ivre/ && \
    python setup.py build && python setup.py install && \
    cd ../ && rm -rf ivre/

RUN echo 'DB = "mongodb://ivredb/"' > /etc/ivre.conf
