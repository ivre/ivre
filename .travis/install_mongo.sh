#! /bin/sh

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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

# https://gist.github.com/roidrage/14e45c24b5a134e1f165
wget "http://fastdl.mongodb.org/linux/mongodb-linux-x86_64-$MONGODB_VERSION.tgz"
tar xfz "mongodb-linux-x86_64-$MONGODB_VERSION.tgz"
rm "mongodb-linux-x86_64-$MONGODB_VERSION.tgz"
export PATH="`pwd`/mongodb-linux-x86_64-$MONGODB_VERSION/bin:$PATH"
PIP_INSTALL_OPTIONS=""
mkdir -p data/db
sudo mount -t tmpfs tmpfs data/db -o users,mode=0777

mongod --dbpath=data/db >/dev/null 2>&1 &

# Wait for MongoDB
# https://github.com/travis-ci/travis-ci/issues/2246#issuecomment-51685471
until nc -z localhost 27017 ; do echo Waiting for MongoDB; sleep 1; done
