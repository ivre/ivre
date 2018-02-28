#! /bin/sh

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
