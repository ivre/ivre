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

RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install nginx && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY nginx-default-site /etc/nginx/sites-available/default

COPY --from=base /usr/local/share/ivre/web/static /usr/local/share/ivre/web/static

RUN mkdir -p /var/www/dokuwiki/ && \
    ln -sf /var/www/dokuwiki/data/lib /var/www/dokuwiki/

EXPOSE 80
CMD ["nginx", "-g", "daemon off; error_log stderr;"]
