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

DB=neo4j
NEO4J_VERSION=3.5.1

wget -q -O - "https://neo4j.com/artifact.php?name=neo4j-community-${NEO4J_VERSION}-unix.tar.gz" | tar zxf -
export PATH="`pwd`/neo4j-community-${NEO4J_VERSION}/bin:$PATH"

neo4j start

# Wait for Neo4j
until nc -z localhost 7474 ; do echo Waiting for Neo4j; sleep 1; done

# Remove "password change required" for user neo4j
neo4j stop
sed -i 's/:password_change_required$/:/' "`pwd`/neo4j-community-${NEO4J_VERSION}/data/dbms/auth"
neo4j start

# Wait for Neo4j (again)
until nc -z localhost 7474 ; do echo Waiting for Neo4j; sleep 1; done
