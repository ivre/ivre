# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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

FROM ubuntu:latest
MAINTAINER Pierre LALET <pierre.lalet@cea.fr>

ENV DEBIAN_FRONTEND noninteractive

# MongoDB install
# http://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10
RUN echo 'deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen' > /etc/apt/sources.list.d/10gen.list
RUN apt-get update && apt-get install -y mongodb-org

# Data directory
VOLUME /var/lib/mongodb

# MongoDB config
RUN sed -i 's/^bind_ip = /#bind_ip = /' /etc/mongod.conf

# MongoDB instance
EXPOSE 27017
ENTRYPOINT /usr/bin/sudo -u mongodb /usr/bin/mongod -f /etc/mongod.conf
