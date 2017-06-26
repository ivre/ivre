# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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
## non-free: s3270
RUN sed -i 's/ main/ main non-free/' /etc/apt/sources.list
RUN apt-get -q update
## openssl: IVRE depends on openssl exec + libssl needed for Nmap
## libfreetype6 libfontconfig1 fonts-dejavu: screenshots w/ phantomjs
RUN apt-get -qy install p0f rsync screen ipython openssl tesseract-ocr \
    libfreetype6 libfontconfig1 fonts-dejavu imagemagick ffmpeg s3270 \
    patch bash-completion bzip2 bro

# Install Nmap. Use included libpcap because to use the workaround for
# Nmap issue #34 (https://github.com/nmap/nmap/issues/34) since we do
# not know which kernel version will be used
# ADD https://github.com/nmap/nmap/tarball/master ./nmap.tar.gz
# Use 7.25BETA2 to have Lua 5.3
ADD https://nmap.org/dist/nmap-7.40.tgz ./nmap.tar.gz
RUN apt-get -qy install build-essential libssl-dev && \
    tar zxf nmap.tar.gz && \
    mv nmap-* nmap && \
    cd nmap && \
    ./configure --without-ndiff --without-zenmap --without-nping \
                --without-ncat --without-nmap-update \
                --with-libpcap=included && \
    make && make install && \
    cd ../ && rm -rf nmap nmap.tar.gz && \
    apt-get -qy --purge autoremove build-essential libssl-dev

# "Install" phantomjs for our http-screenshot NSE script replacement
# wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-1.9.8-linux-x86_64.tar.bz2 -O ./phantomjs-1.9.8-linux-x86_64.tar.bz2
ADD https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-1.9.8-linux-x86_64.tar.bz2 ./phantomjs-1.9.8-linux-x86_64.tar.bz2
RUN tar jxf phantomjs-1.9.8-linux-x86_64.tar.bz2 phantomjs-1.9.8-linux-x86_64/bin/phantomjs && \
    mv phantomjs-1.9.8-linux-x86_64/bin/phantomjs /usr/local/bin/ && \
    rm -rf phantomjs-1.9.8-linux-x86_64*

# Add our *-screenshot NSE scripts
RUN for d in /usr /usr/local; do \
        d="$d/share/ivre/nmap_scripts"; \
        [ -d "$d" ] && ( \
	    cp $d/*.nse /usr/local/share/nmap/scripts; \
	    cd /usr/local/share/nmap/; \
	    for p in $d/patches/*.patch; do \
	         patch -p0 < $p; \
            done \
	) \
    done; true
RUN nmap --script-update

RUN mkdir /var/lib/ivre
