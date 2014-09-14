This file is part of IVRE.

Copyright 2011 - 2014 [Pierre LALET](mailto:pierre.lalet@cea.fr)

# What is docker? #

Docker is an open-source platform that automates the deployment of
applications inside containers. See the [official
website](http://www.docker.com/).

This document describes the (easy) installation of [IVRE](README.md)
using Docker containers, including the database and web servers.

# Getting the images #

You can either get the images from a repository on the Internet or
build them. I'll consider you are on a computer with Docker installed
and an access to the Internet.

## From the Internet ##

    $ for img in agent base client db web ; do
    > docker pull "ivre/$img"
    > done

## Build the images ##

You can also build the images from the provided `Dockerfile`s. For
that, from the `docker/` directory, run:

    $ docker pull ubuntu:latest
    $ for img in agent base client db web ; do
    > docker build -t "ivre/$img" "$img"
    > done

This might take a long time.

# Running #

## The database server ##

To create the volume to store MongoDB data, run (`chmod`-ing to `1777`
is a bit overkill, `chown`-ing it to the UID of the MongoDB user in
the container would do):

    $ mkdir var_lib_mongodb
    $ chmod 1777 var_lib_mongodb

To run an instance of the MongoDB server ready for IVRE, issue (this
will run the instance and give it the name `ivredb`; we will use this
name later):

    $ docker run -d --name ivredb --hostname ivredb \
	>        --volume "`pwd`/var_lib_mongodb":/var/lib/mongodb \
	>        ivre/db

You can add the option `-p 27017:27017` to have the MongoDB service
accessible from the (physical) host.

## The web server ##

    $ docker run -d --name ivreweb --hostname ivreweb \
    >        --link ivredb:ivredb --publish 80:80 ivre/web

The `-p 80:80` option creates a redirection and makes the web server
accessible through the physical host.

## A command line client ##

First, place Nmap result files (XML format) in a specific directory:

    $ mkdir /tmp/ivre-share
    $ cp -r /path/to/my/nmap/results.xml /tmp/ivre-share

Now to get a shell in an IVRE client instance (for command line
actions), issue:

    $ docker run -i -t --name ivreclient --hostname ivreclient \
    >        --link ivredb:ivredb --volume /tmp/ivre-share:/ivre-share \
    >        ivre/client

This gives a shell in the `ivreclient` container, and from there we
can use IVRE's command line tools and Python API. For example, to
initialize the database:

    root@ivreclient:/# ipinfo --init
	This will remove any passive information in your database. Process ? [y/N] y
    root@ivreclient:/# ipdata --init
	This will remove any country/AS information in your database. Process ? [y/N] y
    root@ivreclient:/# scancli --init
	This will remove any scan result in your database. Process ? [y/N] y
    root@ivreclient:/# ipdata --download --import-all
    [...]

The latest command will take a long time. Then we can integrate the
Nmap results to the database:

    root@ivreclient:/# nmap2db -r -s MySource -c MyCategory /ivre-share

You can then exit the shell (`CTRL + d`), this will stop the
container.

    root@ivreclient:/# exit

You can start the container again by issuing:

    $ docker start -i ivreclient
    root@ivreclient:/#
