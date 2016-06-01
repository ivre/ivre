# What is Docker? #

Docker is an open-source platform that automates the deployment of
applications inside containers. See the [official
website](http://www.docker.com/).

This document describes the (easy) installation of [IVRE](README.md)
using Docker containers, including the database and web servers.

# Using Vagrant #

If you already manage your Docker containers using
[Vagrant](https://www.vagrantup.com/), or if you want to give it a try
(or if you are not running a Linux system and want to use Docker
anyway), you can use it to get the images, prepare and run the
containers.

You'll need a recent version of Vagrant (at least 1.6), since Docker
providers do not exist in prior versions.

With the `Vagrantfile` as it is provided, the TCP port 80 of your host
will be used, so you need either to make sure it is not already in
use, or to modify the `Vagrantfile` after the `cp` step in the
instructions below to use another port.

To use the `Vagrantfile` located in the `docker/` directory of the
source tree (or the `[PREFIX]/share/ivre/docker/` directory when IVRE
has been installed), run (from the folder where you want to store your
data):

    $ mkdir -m 1777 var_{lib,log}_{mongodb,neo4j} ivre-share
      # For people using SELinux enforced, you need to run
    $ sudo chcon -Rt svirt_sandbox_file_t var_{lib,log}_{mongodb,neo4j} ivre-share
    
    $ cp [path to ivre source]/docker/Vagrantfile .
    $ vagrant up --no-parallel

The `--no-parallel` option prevents Vagrant from starting the
`ivreweb` container before the `ivredb` is ready.

The DB and Web servers should now be running, with the TCP port 80 of
your host redirected to the `ivreweb` container.

To get a shell with the CLI tools and Python API, attach to the
`ivreclient` container:

    $ docker attach ivreclient
    root@fd983ba5e6fd:/#

You can detach from the container (without stopping it) by using `C-p
C-q` and attach to it again later with the same `docker attach
ivreclient` command.

To initialize the database and start playing with IVRE, you need to
enter some commands described in the
[related section below](#a-command-line-client).

# Without Vagrant #

## Getting the images ##

You can either get the images from a repository on the Internet or
build them. I'll consider you are on a computer with Docker installed
and an access to the Internet.

### From the Internet ###

    $ for img in agent base client db web ; do
    > docker pull "ivre/$img"
    > done

### Build the images ###

You can also build the images from the provided `Dockerfile`s. For
that, from the `docker/` directory, run:

    $ docker pull debian:stable
    $ for img in agent base client db web ; do
    > docker build -t "ivre/$img" "$img"
    > done

This might take a long time.

### Alternative builds for the base image ###

#### Local archive ####

It is also possible to build the `ivre/base` image without fetching
the *tarball* from GitHub, by creating it locally and using the
`base-local` directory instead of `base`. From the repository root,
run:

    $ git archive --format=tar --prefix=ivre/ HEAD -o docker/base-local/ivre.tar
    $ cd docker
    $ docker pull debian:stable
    $ docker build -t ivre/base base-local

#### Using pip ####

Another way to create the `ivre/base` image is to use
[pip](https://pypi.python.org/pypi/pip) and thus get IVRE from
[PyPI](https://pypi.python.org), the Python Package Index. Please note
that the version of IVRE on PyPI is not always up-to-date. From the
`docker/` directory, run:

    $ docker pull debian:stable
    $ docker build -t ivre/base base-pip

### Alternative build for the web image using Apache ###

To use Apache (rather than Nginx) for the `ivre/web` image, simply
run:

    $ docker pull debian:stable
    $ docker build -t ivre/web web-apache

Unlike the default `ivre/web` image, this image uses the Debian
package to install Dokuwiki (the Debian package for Dokuwiki can only
be used with Apache and the default `ivre/web` image uses Nginx). This
can explain some differences one could experience between the two
images.

## Running ##

### The database server ###

To create the volume to store MongoDB data, run (`chmod`-ing to `1777`
is a bit overkill, `chown`-ing it to the UID of the MongoDB user in
the container would do):

    $ mkdir -m 1777 var_{lib,log}_{mongodb,neo4j}

To run an instance of the MongoDB server ready for IVRE, issue (this
will run the instance and give it the name `ivredb`; we will use this
name later):

    $ docker run -d --name ivredb --hostname ivredb \
    >        --volume "`pwd`/var_lib_mongodb":/var/lib/mongodb \
    >        --volume "`pwd`/var_log_mongodb":/var/log/mongodb \
    >        ivre/db

You can add the option `-p 27017:27017` to have the MongoDB service
accessible through the host's TCP port 27017.

### The web server ###

    $ docker run -d --name ivreweb --hostname ivreweb \
    >        --link ivredb:ivredb --publish 80:80 ivre/web

The `--publish 80:80` option creates a redirection and makes the web
server accessible through the host's TCP port 80.

If you want to use modified configuration files, you can use
`--volume`. For example:

    $ docker run -d --name ivreweb --hostname ivreweb \
    >        --volume "`pwd`/ivre.conf:/etc/ivre.conf"
    >        --volume "`pwd`/nginx-default-site:/etc/nginx/sites-available/default"
    >        --link ivredb:ivredb --publish 80:80 ivre/web

### A command line client ###

First, place Nmap result files (XML format) in a specific directory:

    $ mkdir -m 1777 ivre-share
    $ cp -r /path/to/my/nmap/results.xml ivre-share

Now to get a shell in an IVRE client instance (for command line
actions), issue:

    $ docker run -i -t --name ivreclient --hostname ivreclient \
    >        --link ivredb:ivredb --volume "`pwd`/ivre-share":/ivre-share \
    >        ivre/client

This gives a shell in the `ivreclient` container, and from there we
can use IVRE's command line tools and Python API. For example, to
initialize the database:

    root@ivreclient:/# ivre ipinfo --init
    This will remove any passive information in your database. Process ? [y/N] y
    root@ivreclient:/# ivre ipdata --init
    This will remove any country/AS information in your database. Process ? [y/N] y
    root@ivreclient:/# ivre scancli --init
    This will remove any scan result in your database. Process ? [y/N] y
    root@ivreclient:/# ivre runscansagentdb --init
    This will remove any agent and/or scan in your database and files. Process ? [y/N] y
    root@ivreclient:/# ivre ipdata --download --import-all --no-update-passive-db
    [...]

The latest command will take a long time. Then we can integrate the
Nmap results to the database:

    root@ivreclient:/# ivre scan2db -r -s MySource -c MyCategory /ivre-share

You can then exit the shell (`C-d`), this will stop the
container.

    root@ivreclient:/# exit

You can start the container again later by issuing:

    $ docker start -i ivreclient
    root@ivreclient:/#

If you do not want to exit the shell but only detach from it, use `C-p
C-q`. You can attach to it again later by issuing `docker attach
ivreclient`.


---

This file is part of IVRE. Copyright 2011 - 2015
[Pierre LALET](mailto:pierre.lalet@cea.fr)
