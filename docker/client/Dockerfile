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

FROM ivre/base
MAINTAINER Pierre LALET <pierre.lalet@cea.fr>

# Tools
RUN apt-get -qy install nmap p0f rsync screen ipython

# Install bro
ADD https://www.bro.org/downloads/release/bro-2.3.2.tar.gz ./bro-2.3.2.tar.gz
RUN apt-get -qy install build-essential cmake libssl-dev libpcap-dev \
                        flex bison libpython2.7-dev swig && \
    cd tmp/ && tar zxf ../bro-2.3.2.tar.gz && \
    cd bro-2.3.2 && ./configure && make -j 4 && make install && \
    cd / && rm -rf tmp/bro-2.3.2 bro-2.3.2.tar.gz && \
    apt-get -qy --purge autoremove build-essential cmake libssl-dev \
                        libpcap-dev flex bison libpython2.7-dev swig

# Create user
RUN groupadd -g 1000 ivre && \
    useradd -g ivre -d /home/ivre -m -s /sbin/nologin -u 1000 ivre && \
    mkdir /var/lib/ivre && \
    chown ivre:ivre /var/lib/ivre /usr/local/share/ivre/geoip

USER ivre
ENV HOME /home/ivre
WORKDIR /home/ivre
