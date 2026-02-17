# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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
FROM ivre/base:${TAG} AS base

FROM debian:trixie-slim
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install php-fpm php-gd ca-certificates curl patch && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Download & install Dokuwiki
RUN set -e; \
    curl -fsSL https://download.dokuwiki.org/src/dokuwiki/dokuwiki-stable.tgz | \
    tar --transform='s#^dokuwiki-\([^/]*\)#var/www/dokuwiki#' -zxf -; \
    rm -rf /var/lib/apt/lists/*

# IVRE-specific
COPY --from=base /usr/local/share/ivre/dokuwiki/media/logo.png /var/www/dokuwiki/data/media/wiki/logo.png
COPY --from=base /usr/local/share/ivre/patches/dokuwiki/backlinks.patch /tmp/backlinks.patch
RUN set -e; \
    (cd var/www/dokuwiki/ && patch -p0 < /tmp/backlinks.patch); \
    rm -f /tmp/backlinks.patch

# Configure Dokuwiki
RUN rm -f var/www/dokuwiki/install.php
COPY doku-conf-local.php var/www/dokuwiki/conf/local.php
COPY doku-conf-plugins.local.php var/www/dokuwiki/conf/plugins.local.php
COPY doku-conf-acl.auth.php var/www/dokuwiki/conf/acl.auth.php
COPY doku-conf-users.auth.php var/www/dokuwiki/conf/users.auth.php
RUN mv var/www/dokuwiki/data var/www/dokuwiki/data-base && \
    mkdir var/www/dokuwiki/data && \
    chown -Rh www-data:www-data var/www/dokuwiki/data* var/www/dokuwiki/conf var/www/dokuwiki/lib/plugins

# Ensure /usr/sbin/php-fpm exists (version independent)
RUN set -e; \
    FPM=$(ls -1 /usr/sbin/php-fpm* | grep -E 'php-fpm[0-9]+\.[0-9]+$' | head -n1); \
    ln -sf "$FPM" /usr/sbin/php-fpm

# php-fpm listens on TCP
RUN sed -i 's/^listen *=.*/listen = 0.0.0.0:8000/' /etc/php/*/fpm/pool.d/www.conf

EXPOSE 8000

CMD ["sh", "-lc", "[ -d \"/var/www/dokuwiki/data/media/wiki\" ] || ( \
        cp -rp /var/www/dokuwiki/data-base/* /var/www/dokuwiki/data && \
        cp -rp /var/www/dokuwiki/lib /var/www/dokuwiki/data/lib \
    ); \
    mkdir -p /run/php; \
    chown -Rh www-data:www-data /var/www/dokuwiki/data; \
    exec /usr/sbin/php-fpm -F"]

