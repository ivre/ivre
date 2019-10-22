# This file is part of IVRE.
# Copyright 2011 - 2019 Pierre LALET <pierre.lalet@cea.fr>
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

FROM debian:buster
LABEL maintainer="Pierre LALET <pierre.lalet@cea.fr>"

ENV DEBIAN_FRONTEND noninteractive

# MongoDB
# https://docs.mongodb.com/manual/tutorial/install-mongodb-on-debian/
RUN apt-get -q update && apt-get -qy install --no-install-recommends gnupg && \
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 4B7C549A058F8B6B && \
    echo "deb http://repo.mongodb.org/apt/debian buster/mongodb-org/4.2 main" | tee /etc/apt/sources.list.d/mongodb-org-4.2.list && \
    apt-get -q update && apt-get -qy install --no-install-recommends mongodb-org && \
    apt-get -qy --purge autoremove gnupg && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Data & log directories
VOLUME /var/lib/mongodb
VOLUME /var/log/mongodb

# Accept remote connections to DBs
RUN sed -i 's/^  bindIp:.*/  bindIp: 0.0.0.0/' /etc/mongod.conf

# MongoDB instance
EXPOSE 27017

CMD /usr/bin/mongod -f /etc/mongod.conf
