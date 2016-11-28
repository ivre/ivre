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

FROM debian:stable
MAINTAINER Pierre LALET <pierre.lalet@cea.fr>

ENV DEBIAN_FRONTEND noninteractive

# non-free: s3270; backports: ffmpeg
RUN sed -i 's/ main/ main non-free/' /etc/apt/sources.list
RUN echo deb http://httpredir.debian.org/debian stable-backports main contrib non-free >> /etc/apt/sources.list
RUN apt-get -q update
RUN apt-get -qy install screen bzip2 openssl libfreetype6 libfontconfig1 \
    fonts-dejavu imagemagick ffmpeg s3270 patch

# Install Nmap. Use included libpcap because to use the workaround for
# Nmap issue #34 (https://github.com/nmap/nmap/issues/34) since we do
# not know which kernel version will be used
# ADD https://github.com/nmap/nmap/tarball/master ./nmap.tar.gz
# Use 7.25BETA2 to have Lua 5.3
ADD https://nmap.org/dist/nmap-7.25BETA2.tgz ./nmap.tar.gz
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
RUN apt-get -qy install bzip2 && \
    tar jxf phantomjs-1.9.8-linux-x86_64.tar.bz2 phantomjs-1.9.8-linux-x86_64/bin/phantomjs && \
    mv phantomjs-1.9.8-linux-x86_64/bin/phantomjs /usr/local/bin/ && \
    rm -rf phantomjs-1.9.8-linux-x86_64* && \
    apt-get -qy --purge autoremove bzip2

# Add our *-screenshot NSE scripts
ADD https://raw.githubusercontent.com/cea-sec/ivre/master/nmap_scripts/http-screenshot.nse /usr/local/share/nmap/scripts/http-screenshot.nse
ADD https://raw.githubusercontent.com/cea-sec/ivre/master/nmap_scripts/mainframe-banner.nse /usr/local/share/nmap/scripts/mainframe-banner.nse
ADD https://raw.githubusercontent.com/cea-sec/ivre/master/nmap_scripts/mainframe-screenshot.nse /usr/local/share/nmap/scripts/mainframe-screenshot.nse
ADD https://raw.githubusercontent.com/cea-sec/ivre/master/nmap_scripts/rtsp-screenshot.nse /usr/local/share/nmap/scripts/rtsp-screenshot.nse
ADD https://raw.githubusercontent.com/cea-sec/ivre/master/nmap_scripts/vnc-screenshot.nse /usr/local/share/nmap/scripts/vnc-screenshot.nse
ADD https://raw.githubusercontent.com/cea-sec/ivre/master/nmap_scripts/x11-screenshot.nse /usr/local/share/nmap/scripts/x11-screenshot.nse
ADD https://raw.githubusercontent.com/cea-sec/ivre/master/nmap_scripts/patches/rtsp-url-brute.patch /tmp/rtsp-url-brute.patch
RUN cd /usr/local/share/nmap/ && patch -p0 < /tmp/rtsp-url-brute.patch
RUN nmap --script-update

ADD https://raw.githubusercontent.com/cea-sec/ivre/master/agent/agent \
    /usr/bin/agent
RUN chmod +x /usr/bin/agent
ADD runagent /usr/bin/runagent

RUN chmod 777 /var/run/screen

VOLUME /var/lib/ivre-agent
WORKDIR /var/lib/ivre-agent
CMD exec /usr/bin/runagent
