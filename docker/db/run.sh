#! /bin/sh

/usr/bin/neo4j start
/usr/bin/mongod -f /etc/mongod.conf
/usr/bin/neo4j stop
