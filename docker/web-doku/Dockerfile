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

FROM debian:stable
ARG TAG=latest
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install php-fpm php-gd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Download & install Dokuwiki
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install curl ca-certificates && \
    curl https://download.dokuwiki.org/src/dokuwiki/dokuwiki-stable.tgz | \
    tar --transform='s#^dokuwiki-\([^/]*\)#var/www/dokuwiki#' -zxf - && \
    apt-get -qy --purge autoremove curl ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# IVRE-specific
RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install curl ca-certificates patch && \
    curl https://raw.githubusercontent.com/ivre/ivre/$(echo ${TAG} | sed 's/^latest$/master/')/web/dokuwiki/media/logo.png > \
    /var/www/dokuwiki/data/media/wiki/logo.png && \
    curl https://raw.githubusercontent.com/ivre/ivre/$(echo ${TAG} | sed 's/^latest$/master/')/patches/dokuwiki/backlinks.patch | \
    patch var/www/dokuwiki/inc/Ui/Backlinks.php - && \
    rm -f /backlinks.patch && \
    apt-get -qy --purge autoremove curl ca-certificates patch && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure Dokuwiki
RUN rm var/www/dokuwiki/install.php
COPY doku-conf-local.php var/www/dokuwiki/conf/local.php
COPY doku-conf-plugins.local.php var/www/dokuwiki/conf/plugins.local.php
COPY doku-conf-acl.auth.php var/www/dokuwiki/conf/acl.auth.php
COPY doku-conf-users.auth.php var/www/dokuwiki/conf/users.auth.php
RUN mv var/www/dokuwiki/data var/www/dokuwiki/data-base && \
    mkdir var/www/dokuwiki/data && \
    chown -Rh www-data:www-data var/www/dokuwiki/data* var/www/dokuwiki/conf var/www/dokuwiki/lib/plugins

# Use a version-independent service name
RUN ln -s /usr/sbin/php-fpm?* /usr/sbin/php-fpm

# php-fpm listens on a socket
RUN sed -i 's/^listen *=.*/listen = 0.0.0.0:8000/' /etc/php/*/fpm/pool.d/www.conf

EXPOSE 8000
CMD [ -d "/var/www/dokuwiki/data/media/wiki" ] || (\
        # on first run, populate /var/www/dokuwiki/data
        cp -rp  /var/www/dokuwiki/data-base/* /var/www/dokuwiki/data && \
        cp -rp /var/www/dokuwiki/lib /var/www/dokuwiki/data/lib \
    ) && \
    mkdir -p /run/php && \
    chown -Rh www-data:www-data /var/www/dokuwiki/data && \
    /usr/sbin/php-fpm7.4 -F
