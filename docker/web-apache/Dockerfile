# This file is part of IVRE.
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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

# Install Apache2 & Dokuwiki
RUN apt-get -qy install apache2 dokuwiki

# Add links for IVRE Web UI
RUN rm var/www/html/index.html && \
    ln -s /usr/local/share/ivre/web/static/* var/www/html && \
    ln -s /usr/local/share/ivre/web/cgi-bin/* usr/lib/cgi-bin && \
    ln -s /usr/local/share/ivre/dokuwiki/doc var/lib/dokuwiki/data/pages && \
    ln -s /usr/local/share/ivre/dokuwiki/media/logo.png var/lib/dokuwiki/data/media/wiki && \
    mkdir var/lib/dokuwiki/data/media/doc && \
    ln -s /usr/local/share/doc/ivre/screenshots var/lib/dokuwiki/data/media/doc/

# Configure IVRE
RUN echo 'WEB_GET_NOTEPAD_PAGES = "localdokuwiki"' >> /etc/ivre.conf

# Patch Dokuwiki for backlinks to IVRE results
RUN apt-get -qy install patch && \
    cd usr/share/dokuwiki && \
    patch -p0 < /usr/local/share/ivre/dokuwiki/backlinks.patch && \
    apt-get -qy --purge autoremove patch

# Configure Apache for server-side URL rewrite
RUN sed -i 's/^\(\s*\)#Rewrite/\1Rewrite/' etc/dokuwiki/apache.conf
RUN ln -s /etc/apache2/mods-available/rewrite.load etc/apache2/mods-enabled
RUN ln -s /etc/apache2/mods-available/cgi.load etc/apache2/mods-enabled

# Configure Dokuwiki (access to everyone)
RUN mv etc/dokuwiki/acl.auth.php.dist etc/dokuwiki/acl.auth.php
RUN sed -i 's/Allow from localhost.*/Allow from all/' etc/dokuwiki/apache.conf
ADD doku-conf-local.php etc/dokuwiki/local.php

ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOCK_DIR /var/lock/apache2
ENV APACHE_LOG_DIR /var/log/apache2
ENV APACHE_PID_FILE /var/run/apache2.pid

EXPOSE 80
CMD exec /usr/sbin/apache2 -D FOREGROUND
