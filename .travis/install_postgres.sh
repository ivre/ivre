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

wget -q -O pgsql.tgz "http://get.enterprisedb.com/postgresql/postgresql-${POSTGRES_VERSION}-1-linux-x64-binaries.tar.gz"
tar zxf pgsql.tgz
rm pgsql.tgz
export PATH="`pwd`/pgsql/bin:$PATH"
if [ -z "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="`pwd`/pgsql/lib"
else
    export LD_LIBRARY_PATH="`pwd`/pgsql/lib:$LD_LIBRARY_PATH"
fi
PIP_INSTALL_OPTIONS="--global-option=build_ext --global-option=-L`pwd`/pgsql/lib --global-option=-I`pwd`/pgsql/include"
mkdir -p data/db
sudo mount -t tmpfs tmpfs data/db -o users,uid=travis,gid=travis,mode=0700
initdb -D data/db

# Port 5432 is already in use (Travis-CI's PostgreSQL)
pg_ctl -D data/db -l postgresql-logfile -o '-p 54321' start

until nc -z localhost 54321 ; do echo Waiting for PostgreSQL; sleep 1; done
sleep 2

echo 'DB = "postgresql://ivre@localhost:54321/ivre"' >> ~/.ivre.conf

createuser -h localhost -p 54321 ivre
createdb -h localhost -p 54321 -O ivre ivre
psql ivre ivre -h localhost -p 54321 -c "SELECT version();"
