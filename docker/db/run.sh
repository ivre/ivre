#! /bin/sh

/var/lib/neo4j/bin/neo4j start
## v3
#/usr/bin/neo4j start
/usr/bin/mongod -f /etc/mongod.conf
/var/lib/neo4j/bin/neo4j stop
## v3
#/usr/bin/neo4j stop
