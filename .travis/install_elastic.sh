#! /bin/sh

wget -O elastic.tgz "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${ELASTIC_VERSION}.tar.gz"
tar zxf elastic.tgz
rm elastic.tgz
export PATH="`pwd`/elasticsearch-${ELASTIC_VERSION}/bin:$PATH"

elasticsearch &

# Wait for Elasticsearch
until nc -z localhost 9200 ; do echo Waiting for Elasticsearch; sleep 1; done
sleep 2

echo 'DB = "elastic://localhost:/ivre"' >> ~/.ivre.conf
