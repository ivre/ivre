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

ARG TAG=latest
FROM ivre/base:${TAG}
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

# Tools
## non-free: s3270
RUN sed -i 's/ main/ main non-free/' /etc/apt/sources.list
## openssl: IVRE depends on openssl exec + libssl needed for Nmap
## libfreetype6 libfontconfig1 fonts-dejavu: screenshots w/ phantomjs
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install rsync screen ipython3 openssl \
        tesseract-ocr libfreetype6 libfontconfig1 fonts-dejavu imagemagick \
        ffmpeg s3270 patch bash-completion bzip2 python3-pil nfdump && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Nmap using the official RPM package.
ADD https://nmap.org/dist/nmap-7.92-1.x86_64.rpm ./nmap.rpm
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install alien && \
    alien ./nmap.rpm && \
    dpkg -i ./nmap*.deb && \
    rm -f ./nmap.rpm ./nmap*.deb && \
    apt-get -qy --purge autoremove alien && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Zeek
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install gnupg wget && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_11/ /' > /etc/apt/sources.list.d/zeek.list && \
    wget -qO - https://download.opensuse.org/repositories/security:zeek/Debian_11/Release.key | apt-key add - && \
    apt-get -q update && apt-get -qy --no-install-recommends install zeek && \
    apt-get -qy --purge autoremove gnupg wget && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install p0f
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install p0f && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# "Install" phantomjs for our http-screenshot NSE script replacement
ADD https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 ./phantomjs-2.1.1-linux-x86_64.tar.bz2
RUN tar jxf phantomjs-2.1.1-linux-x86_64.tar.bz2 phantomjs-2.1.1-linux-x86_64/bin/phantomjs && \
    mv phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/ && \
    rm -rf phantomjs-2.1.1-linux-x86_64*

# Add our *-screenshot NSE scripts
RUN for d in /usr /usr/local; do \
        d="$d/share/ivre/patches"; \
        [ -d "$d" ] && ( \
            cp $d/nmap/scripts/*.nse /usr/share/nmap/scripts; \
            cd /usr/share/nmap/; \
            for p in $d/nmap/*.patch; do \
                 patch -p0 < $p; \
            done ; \
            patch /etc/p0f/p0f.fp $d/p0f/p0f.fp.patch \
        ) \
    done; true
RUN nmap --script-update

RUN mkdir /var/lib/ivre
