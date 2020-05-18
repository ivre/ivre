#! /bin/sh

# This file is part of IVRE.
# Copyright 2011 - 2020 Pierre LALET <pierre@droids-corp.org>
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
# Since we are going to run a MongoDB server that will use data/db, we
# need to use a different name for Elasticsearch
mkdir -p data/db_es
sudo mount -t tmpfs tmpfs data/db_es -o users,uid=travis,gid=travis,mode=0700
elasticsearch -d -E path.data=`pwd`/data/db_es

until nc -z localhost 9200 ; do echo Waiting for Elasticsearch; sleep 1; done
sleep 2

echo 'DB_VIEW = "elastic://ivre@localhost:9200/ivre"' >> ~/.ivre.conf

curl http://127.0.0.1:9200

# We need a MongoDB server for the scan & nmap databases
MONGODB_VERSION=4.0.2 source ./.travis/install_mongo.sh

PYVERS=`python -c 'import sys;print("%d%d" % sys.version_info[:2])'`
if [ -f "requirements-mongo-$PYVERS.txt" ]; then
    pip install -U $PIP_INSTALL_OPTIONS -r "requirements-mongo-$PYVERS.txt"
else
    pip install -U $PIP_INSTALL_OPTIONS -r "requirements-mongo.txt"
fi
