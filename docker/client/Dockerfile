# This file is part of IVRE.
# Copyright 2011 - 2023 Pierre LALET <pierre@droids-corp.org>
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
FROM debian:12 AS builder

ENV DEBIAN_FRONTEND noninteractive

# Extract phantomjs binary
ADD https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 ./phantomjs-2.1.1-linux-x86_64.tar.bz2
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install bzip2 && \
    tar jxf phantomjs-2.1.1-linux-x86_64.tar.bz2 phantomjs-2.1.1-linux-x86_64/bin/phantomjs

# Install Nmap using the official RPM package.
ADD https://nmap.org/dist/nmap-7.94-1.x86_64.rpm ./nmap.rpm
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install alien && \
    alien ./nmap.rpm && \
    dpkg -i ./nmap*.deb

# Build scrying for RDP screenshots with Nmap
ADD https://github.com/nccgroup/scrying/archive/refs/heads/main.tar.gz ./main.tar.gz
RUN apt -qy --no-install-recommends install cargo ca-certificates pkg-config libssl-dev && \
    tar zxf main.tar.gz && \
    cd scrying-main && \
    cargo build --release


ARG TAG=latest
FROM ivre/base:${TAG}
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

# Tools
## non-free: s3270
RUN sed -i 's/ main/ main non-free/' /etc/apt/sources.list.d/debian.sources
## openssl: IVRE depends on openssl exec + libssl needed for Nmap
## libfreetype6 libfontconfig1 fonts-dejavu: screenshots w/ phantomjs
## nfdump argus-client: ivre flow2db
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install rsync screen ipython3 openssl \
        tesseract-ocr libfreetype6 libfontconfig1 fonts-dejavu imagemagick \
        ffmpeg s3270 bash-completion bzip2 python3-pil nfdump argus-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Nmap using the official RPM package.
COPY --from=builder /usr/bin/nmap /usr/bin/nmap
COPY --from=builder /usr/share/nmap /usr/share/nmap

# Install Zeek
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install gnupg wget && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' > /etc/apt/sources.list.d/zeek.list && \
    wget -qO - https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg && \
    apt-get -q update && apt-get -qy --no-install-recommends install zeek && \
    apt-get -qy --purge autoremove gnupg wget && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install p0f
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install p0f && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# "Install" phantomjs for our http-screenshot NSE script replacement
COPY --from=builder /phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs

# "Install" scrying for our rdp-screenshot NSE script
COPY --from=builder /scrying-main/target/release/scrying /usr/local/bin/scrying

# Add our *-screenshot NSE scripts  # /usr/local/share/ivre/patches
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install patch && \
    cp /usr/local/share/ivre/patches/nmap/scripts/*.nse /usr/share/nmap/scripts && \
    cd /usr/share/nmap/ && \
    for p in /usr/local/share/ivre/patches/nmap/*.patch; do patch -p0 < $p; done && \
    patch /etc/p0f/p0f.fp /usr/local/share/ivre/patches/p0f/p0f.fp.patch && \
    nmap --script-update && \
    apt-get -qy --purge autoremove patch && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir /var/lib/ivre
