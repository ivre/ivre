Installation guidelines
=======================

Database
--------

Depending on the backends you wan to use, install a database
server. Please keep in mind that currently, MongoDB is currently the
only supported backend for all the purposes. To learn more about the
different purposes, read the :ref:`overview/principles:principles`.

The database servers installation and setup is not covered here, and
depends on your platform and needs. Please refer to the server
documentation on how to install it. For MongoDB you can read `the
installation section <http://docs.mongodb.org/manual/installation/>`_
of their documentation.

Dependencies
------------

External programs
~~~~~~~~~~~~~~~~~

If you plan to run scans from a machine, install `Nmap
<https://nmap.org/>`_, `Masscan
<https://github.com/robertdavidgraham/masscan>`_, and/or `Zmap / Zgrab
/ Zgrab2 <https://zmap.io/>`_. If you want to integrate screenshots,
install `Tesseract <https://github.com/tesseract-ocr/tesseract>`_,
`ImageMagick <https://www.imagemagick.org/>`_, `FFmpeg
<http://ffmpeg.org/>`_ and `PhantomJS <http://phantomjs.org/>`_.

If you plan to analyze PCAP file on a machine, install, depending on
your needs:

- `Zeek <https://www.zeek.org/>`_ (previously known as Bro, version 3
  minimum).
- `Argus <http://qosient.com/argus/>`_.
- `Nfdump <http://nfdump.sourceforge.net/>`_.

Python
~~~~~~
  
To install IVRE, you'll need `Python <http://www.python.org/>`__ 2.7
or 3 (version 3.4 minimum), with the following modules:

- `bottle <https://bottlepy.org/>`_.
- `cryptography <https://cryptography.io/en/latest/>`_.
- `future <https://python-future.org/>`_.
- `pymongo <http://api.mongodb.org/python/>`_ version 2.7.2 minimum.
- `tinydb <https://tinydb.readthedocs.io/>`_, to use the
  **experimental** TinyDB backend (this does not require a database
  server).
- `sqlalchemy <http://www.sqlalchemy.org/>`_ and `psycopg2
  <http://initd.org/psycopg/>`_ to use the **experimental** PostgreSQL
  backend.
- `elasticsearch <https://github.com/elastic/elasticsearch-py>`_ and
  `elasticsearch-dsl
  <https://github.com/elastic/elasticsearch-dsl-py>`_ to use the
  **experimental** Elasticsearch backend.
- `PIL <http://www.pythonware.com/products/pil/>`_ optional, to trim
  screenshots.
- `pyOpenSSL <https://pypi.org/project/pyOpenSSL/>`_ version 16.1.0
  minimum, optional, to parse X509 certificates (a fallback exists
  that calls ``Popen()`` the ``openssl`` binary and parses its output,
  but it is much slower and less reliable).

Databases
~~~~~~~~~

IVRE's reference backend service is `MongoDB
<https://www.mongodb.org/>`_, version 3.2 minimum. It is highly
suggested that you use the latest stable release (the performances
tend to improve a lot).

The ``passive``, ``nmap`` and ``view`` purposes have an
**experimental** PostgreSQL backend that can be used in lieu of
MongoDB.

The ``view`` purpose has an **experimental** Elasticsearch backend. It
can be used to create views accessible to other Elasticsearch tools,
such as Kibana (see :ref:`usage/kibana:IVRE with Kibana`).

Please refer to the database servers (or your distribution)
documentation on how to install and configure them.

Web
~~~

For production services, it is recommended to install either `Apache
<https://httpd.apache.org/>`_ with the `WSGI module
<https://modwsgi.readthedocs.io/en/develop/>`_, or `Nginx
<https://www.nginx.com/>`_ with `uWSGI
<https://uwsgi-docs.readthedocs.io/en/latest/>`_.

IVRE can use `Dokuwiki <https://www.dokuwiki.org/dokuwiki>`_ as its
notepad, it is also recommended to install it.

Please refer to the servers (or your distribution) documentation on
how to install and configure them.

Configuration file samples are provided in IVRE's source repository,
under ``pkg/apache`` and ``pkg/nginx``. Also, the
:ref:`install/docker:Docker` creation files in ``docker/web`` and
``docker/web-apache`` can provide useful examples.

If you do not want (or cannot) to install a Web server, you can try
IVRE's integrated server, suited for tests or tiny installations. Just
run ``ivre httpd``!

IVRE
----

The installation of IVRE itself can be done:

- On `Kali <https://www.kali.org/>`_, just install the `package
  <https://pkg.kali.org/pkg/ivre>`_ by running ``apt update && apt
  install ivre``. You can also install ``ivre-doc`` if needed.

- On `Fedora <https://getfedora.org/fr/>`_, you can use the `Copr
  package <https://copr.fedorainfracloud.org/coprs/>`_; follow the
  `instructions
  <https://copr.fedorainfracloud.org/coprs/pessoft/IVRE/>`_.

- On other RPM-based Linux distributions, you can easily build RPM
  packages (using the provided ``pkg/buildrpm`` script, or use the
  ``setup.py`` script with your own options).

- On `Arch Linux <https://www.archlinux.org/>`_, there are `AUR
  <https://aur.archlinux.org/>`__ packages that can be installed using
  `yay <https://aur.archlinux.org/packages/yay/>`_ for example. The
  packages are:

   - ``ivre``: the main package, which depends on ``python-ivre``.

   - ``python-ivre`` and ``python2-ivre``: the Python 3 and Python 2
     libraries. You don't need ``python2-ivre`` unless you have Python
     2 only code relying on IVRE.

   - ``ivre-web``: the Web application

   - ``ivre-docs``: the documentation

  These packages are based on the latest stable version; they all have
  a ``-git`` version, based on the current development code from the
  `Github repository <https://github.com/cea-sec/ivre>`_. You can
  install for example ``ivre-git`` and ``ivre-web-git`` if you want to
  test the latest developments.

  All the packages are based on the same bases: `ivre
  <https://aur.archlinux.org/pkgbase/ivre/>`__ and `ivre-git
  <https://aur.archlinux.org/pkgbase/ivre-git/>`_.

- On `BlackArch Linux <https://blackarch.org/>`_ (an Arch Linux-based
  penetration testing distribution) IVRE is packaged (and installed in
  the Live ISO).

- Using `pip <https://pypi.org/project/pip>`__: run ``pip install
  ivre`` (this will download and install for you `the IVRE package
  <https://pypi.org/project/ivre>`_ and its Python dependencies from
  PyPI, the Python Package Index).

- From the source code, using the ``setup.py`` (classical ``./setup.py
  build; sudo ./setup.py install``) script.

- Using :ref:`install/docker:docker` (in this case you do not need to
  follow the instructions in
  :ref:`install/installation:configuration`, as the Docker containers
  are already configured).

Configuration
-------------

You can set configuration values in several files:

- system-wide: ``ivre.conf`` in the following directories: ``/etc/``,
  ``/etc/ivre``, ``/usr/local/etc``, ``/usr/local/etc/ivre``.

- user-specific: ``~/.ivre.conf`` (read after the system-wide
  configuration files, so highest priority).

- execution-specific: another configuration file can be specified
  using the ``$IVRE_CONF`` environment variable.

The configuration files are Python files. They may set, for example,
the variable ``DB`` to use a different database than the default
one.

See :ref:`install/config:Configuration` to learn more about the
different configuration parameters.

Initialization
--------------

Once IVRE has been properly configured, it's time to initialize its
databases.

For that, the command-line tools (namely ``ivre ipinfo``, ``ivre
scancli``, ``ivre view``, ``ivre flowcli`` and ``ivre
runscansagentdb``, respectively for information about IP addresses,
passive information, active information and running scans through
agents) have a ``--init`` option.

So you can run, with a user or from a host where the configuration has a
write access to the database (add ``< /dev/null`` to skip the
confirmation):

::

   $ yes | ivre ipinfo --init
   $ yes | ivre scancli --init
   $ yes | ivre view --init
   $ yes | ivre flowcli --init
   $ yes | sudo ivre runscansagentdb --init

Getting IP data
---------------

To fetch the IP address data files (mainly from `Maxmind
<https://www.maxmind.com/>`_) and parse them (required if you want to
scan or list all IP addresses from a country or an AS), just run the
following command (it takes a long time, usually more than 40 minutes
on a decent server):

::

   $ sudo ivre ipdata --download

It is advised to run this command on a regular basis (e.g.,
weekly). If you use IVRE on several machines, you may want to run the
command on one machine and create an ``ivre-data`` package containing
the files under the ``/usr/share/ivre/geoip`` directory (or distribute
those files somehow).

The URLs downloaded are stored in the configuration. By default, the
following files are downloaded:

::

   $ python
   >>> from ivre.config import IPDATA_URLS
   >>> for fname, url in IPDATA_URLS.items():
   ...     print("%s: %s" % (fname, url))
   ...
   GeoLite2-City.tar.gz: https://ivre.rocks/data/geolite/GeoLite2-City.tar.gz
   GeoLite2-City-CSV.zip: https://ivre.rocks/data/geolite/GeoLite2-City-CSV.zip
   GeoLite2-Country.tar.gz: https://ivre.rocks/data/geolite/GeoLite2-Country.tar.gz
   GeoLite2-Country-CSV.zip: https://ivre.rocks/data/geolite/GeoLite2-Country-CSV.zip
   GeoLite2-ASN.tar.gz: https://ivre.rocks/data/geolite/GeoLite2-ASN.tar.gz
   GeoLite2-ASN-CSV.zip: https://ivre.rocks/data/geolite/GeoLite2-ASN-CSV.zip
   GeoLite2-dumps.tar.gz: https://ivre.rocks/data/geolite/GeoLite2-dumps.tar.gz
   iso3166.csv: https://dev.maxmind.com/static/csv/codes/iso3166.csv
   BGP.raw: http://thyme.apnic.net/current/data-raw-table


Using Agents
------------

If you do not plan to run active scans with remote agents (where IVRE
will not be installed), you can skip this section.

The agent does not require IVRE to be installed. It is a script that
needs to be adapted to each situation.

The agent is only needed when you cannot install IVRE on the machine
used to scan or when you want to use several machines to run one scan.

It requires a POSIX environment, and the commands ``screen``,
``rsync`` and ``nmap`` (of course). See the
:ref:`install/agents:agents` documentation for more information about
that.
