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
FROM ivre/base:${TAG}
LABEL maintainer="Pierre LALET <pierre@droids-corp.org>"

RUN apt-get -q update && \
    apt-get -qy --no-install-recommends install uwsgi-plugin-python3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN echo 'WEB_GET_NOTEPAD_PAGES = ("localdokuwiki", ("/var/www/dokuwiki/data/pages",))' >> /etc/ivre.conf

USER nobody
EXPOSE 3031
CMD exec uwsgi \
    --master \
    --plugin /usr/lib/uwsgi/plugins/python3_plugin.so \
    --socket :3031 \
    --mount /cgi=/usr/local/share/ivre/web/wsgi/app.wsgi \
    --manage-script-name
