#! /bin/sh

mkdir -p /tmp/ivredb
sudo mount -t tmpfs tmpfs /tmp/ivredb -o users,uid=travis,gid=travis,mode=0777

echo 'DB="sqlite:////tmp/ivredb/ivre.db"' >> ~/.ivre.conf
