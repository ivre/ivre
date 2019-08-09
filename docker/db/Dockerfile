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

FROM debian:jessie
LABEL maintainer="Pierre LALET <pierre.lalet@cea.fr>"

ENV DEBIAN_FRONTEND noninteractive

# MongoDB
# http://docs.mongodb.org/manual/tutorial/install-mongodb-on-debian/
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 68818C72E52529D4
RUN echo "deb http://repo.mongodb.org/apt/debian jessie/mongodb-org/4.0 main" | tee /etc/apt/sources.list.d/mongodb-org-4.0.list
RUN apt-get -q update && apt-get -qy install mongodb-org

# Data & log directories
VOLUME /var/lib/mongodb
VOLUME /var/log/mongodb

# Accept remote connections to DBs
RUN sed -i 's/^  bindIp:/  bindIp: 0.0.0.0/' /etc/mongod.conf

# MongoDB instance
EXPOSE 27017

CMD /usr/bin/mongod -f /etc/mongod.conf
