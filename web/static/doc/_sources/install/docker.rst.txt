Docker
======

Versions
--------

The images published on Docker hub are built from the current
``master`` repository branch (tag ``latest``, will be used by default)
and from the current release (tag ``vX.Y.Z``, use
``ivre/<imagename>:vX.Y.Z`` to use it).

Using docker compose
--------------------

The easiest way, just run:

::

    $ docker compose up

The containers should now be running, with the TCP port 80 of your
host redirected to the ``ivreweb`` container.

To get a shell with the CLI tools and Python API, attach to the
``ivreclient`` container:

::

   $ docker attach ivreclient
   root@fd983ba5e6fd:/#

You can detach from the container (without stopping it) by using
``C-p C-q`` and attach to it again later with the same
``docker attach ivreclient`` command.

To initialize the database and start playing with IVRE, you need to
enter some commands described in the `related section
below <#initialization>`__.

Using Vagrant
-------------

If you already manage your Docker containers using `Vagrant
<https://www.vagrantup.com/>`__, you can use it to run the containers.

With the ``Vagrantfile`` as it is provided, the TCP port 80 of your host
will be used, so you need either to make sure it is not already in use,
or to modify the ``Vagrantfile`` after the ``cp`` step in the
instructions below to use another port.

To use the ``Vagrantfile`` located in the ``docker/`` directory of the
source tree (or the ``[PREFIX]/share/ivre/docker/`` directory when IVRE
has been installed), run (from the folder where you want to store your
data):

::

   $ mkdir -m 1777 var_lib_mongodb ivre-share dokuwiki_data
     # For people using SELinux enforced, you need to run
   $ sudo chcon -Rt svirt_sandbox_file_t var_lib_mongodb ivre-share dokuwiki_data

   $ cp [path to ivre source]/docker/Vagrantfile .
   $ vagrant up --no-parallel

The ``--no-parallel`` option prevents Vagrant from starting the
``ivreuwsgi`` container before the ``ivredb`` is ready.

To access the ``ivreclient`` container, see the `Using Docker Compose
<#using-docker-compose>`__ since it is similar.

Build the images
----------------

By default, the images will be downloaded from the Docker Hub. But you
also can build the images from the provided ``Dockerfile``\ s. For
that, from the ``docker/`` directory, run:

::

   $ docker pull debian:stable
   $ for img in base client agent web web-doku web-uwsgi ; do
   > docker build -t "ivre/$img" "$img"
   > done

This might take a long time.

Alternative builds for the base image
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Local archive
^^^^^^^^^^^^^

It is also possible to build the ``ivre/base`` image without fetching
the *tarball* from GitHub, by creating it locally and using the
``base-local`` directory instead of ``base``. From the repository root,
run:

::

   $ git archive --format=tar --prefix=ivre/ HEAD -o docker/base-local/ivre.tar
   $ tmp=`mktemp | sed 's#^/##'`; python setup.py --version | tr -d '\n' > "/$tmp"
   $ tar rf docker/base-local/ivre.tar --transform="s#$tmp#ivre/ivre/VERSION#" /$tmp
   $ rm "/$tmp"
   $ docker pull debian:stable
   $ docker build -t ivre/base docker/base-local

Using pip
^^^^^^^^^

Another way to create the ``ivre/base`` image is to use
`pip <https://pypi.python.org/pypi/pip>`__. From the
``docker/`` directory, run:

::

   $ docker pull debian:stable
   $ docker build -t ivre/base base-pip

Initialization
--------------

Attach to the ``ivreclient`` container and run the initialization
commands:

::

   user@host:~$ docker attach ivreclient
   root@ivreclient:/# yes | ivre ipinfo --init
   root@ivreclient:/# yes | ivre scancli --init
   root@ivreclient:/# yes | ivre view --init
   root@ivreclient:/# yes | ivre flowcli --init
   root@ivreclient:/# yes | ivre runscansagentdb --init
   root@ivreclient:/# ivre ipdata --download

Then we can integrate the Nmap results to the database
``nmap`` database and create a ``view`` from it:

::

   root@ivreclient:/# ivre scan2db -r -s MySource -c MyCategory /ivre-share
   root@ivreclient:/# ivre db2view nmap

You can then detach from the container (``C-p C-q``).

::

   root@ivreclient:/# exit

You can start the container again later by issuing:

::

   $ docker start -i ivreclient
   root@ivreclient:/#

If you do not want to exit the shell but only detach from it, use
``C-p C-q``. You can attach to it again later by issuing
``docker attach ivreclient``.
