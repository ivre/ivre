# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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
MAINTAINER Pierre LALET <pierre.lalet@cea.fr>

ENV DEBIAN_FRONTEND noninteractive

# MongoDB
# http://docs.mongodb.org/manual/tutorial/install-mongodb-on-debian/
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927
RUN echo "deb http://repo.mongodb.org/apt/debian wheezy/mongodb-org/3.2 main" | tee /etc/apt/sources.list.d/mongodb-org-3.2.list

# Neo4j
# http://debian.neo4j.org/
ADD https://debian.neo4j.org/neotechnology.gpg.key /neotechnology.gpg.key
RUN apt-key add /neotechnology.gpg.key && rm /neotechnology.gpg.key
RUN echo 'deb http://debian.neo4j.org/repo stable/' > /etc/apt/sources.list.d/neo4j.list
RUN echo 'deb http://httpredir.debian.org/debian stable-backports main' >> /etc/apt/sources.list
RUN apt-get -q update && apt-get -qy install mongodb-org neo4j=2.3.3

# Data & log directories
VOLUME /var/lib/mongodb
VOLUME /var/log/mongodb
VOLUME /var/lib/neo4j/data
## v3
#VOLUME /var/lib/neo4j
VOLUME /var/log/neo4j

# Accept remote connections to DBs
RUN sed -i 's/^  bindIp:/#bindIp:/' /etc/mongod.conf
# Neo4j
RUN sed -ri 's/^(dbms\.security\.auth_enabled=)true/\1false/;s/^# *(org\.neo4j\.server\.webserver\.address=0\.0\.0\.0)/\1/' /etc/neo4j/neo4j-server.properties
## v3
# RUN sed -ri 's/^# *(dbms\.security\.auth_enabled=false|dbms\.connector\.http\.address=0\.0\.0\.0:7474|dbms\.connector\.bolt\.address=0\.0\.0\.0:7687)/\1/' /etc/neo4j/neo4j.conf


# MongoDB instance
EXPOSE 27017
# Neo4j
EXPOSE 7474
## v3
#EXPOSE 7687

ADD run.sh /
CMD /run.sh
