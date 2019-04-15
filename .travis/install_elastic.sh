#! /bin/sh

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

wget -q "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ELASTIC_VERSION-linux-x86_64.tar.gz" -O - | tar zxf -
export PATH="`pwd`/elasticsearch-$ELASTIC_VERSION/bin:$PATH"
PIP_INSTALL_OPTIONS=""
mkdir -p data/db
sudo mount -t tmpfs tmpfs data/db -o users,uid=travis,gid=travis,mode=0700
elasticsearch -d -h -E path.data=`pwd`/data/db

until nc -z localhost 9200 ; do echo Waiting for Elasticsearch; sleep 1; done
sleep 2

echo 'DB = "elastic://ivre@localhost:9200/ivre"' >> ~/.ivre.conf

curl http://127.0.0.1:9200
