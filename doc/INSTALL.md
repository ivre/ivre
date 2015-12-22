# DB Server #

Follow the [documentation from MongoDB
project](http://docs.mongodb.org/manual/installation/), depending on
your distribution. It is recommended to install packages from the
MongoDB project rather than the (possibly old) packages from your
distribution.

# IVRE #

## Dependencies ##

If you plan to run scans from a machine, install
[Nmap](http://nmap.org/) and optionally [ZMap](https://zmap.io/) and
[Masscan](https://github.com/robertdavidgraham/masscan). If you want
to integrate screenshots, install
[Tesseract](https://github.com/tesseract-ocr/tesseract).

If you plan to analyze PCAP file on a machine, install
[Bro](http://www.bro.org/) (version 2.3 minimum) and
[p0f](http://lcamtuf.coredump.cx/p0f/) (version 2, will not work with
version 3).

To install IVRE, you'll need [Python](http://www.python.org/) 2,
version 2.6 minimum (prefer 2.7), with the following modules:

  * [Crypto](http://www.pycrypto.org/)
  * [pymongo](http://api.mongodb.org/python/) version 2.7.2 minimum.
  * [PIL](http://www.pythonware.com/products/pil/) optional, to trim
    screenshots.
  * optionally [numpy](http://www.numpy.org/),
    [matplotlib](http://matplotlib.org/) &
    [sklearn](http://scikit-learn.org/stable/), to use the analyzer module

## Installation ##

The installation of [IVRE](README.md) itself can be done by:

  * using the `setup.py` (classical `./setup.py build; sudo ./setup.py
    install`) script.

  * using [pip](https://pypi.python.org/pypi/pip): on a Debian-based
    system for example, install the packages `python-pip` and
    `python-dev` (needed to build dependencies) and run `pip install
    ivre` (this will download and install for you IVRE and its Python
    dependencies from [PyPI](https://pypi.python.org), the Python
    Package Index).

  * building an RPM package (you can use the provided `buildrpm`
    script, or use the `setup.py` script with your own options) and
    then installing it.

  * using [Docker](DOCKER.md) (in this case you do not need to follow
    the following instructions, as the Docker containers are already
    configured).

## Configuration ##

Default configuration values are hard-coded in `ivre/config.py`. You
should not change this file, unless you are modifying IVRE and you
want to change the default configuration. You do not need
to do this if you want to install IVRE with a non-default
configuration, you just need to distribute a proper configuration
file.

You can override default values in three files:
  - two system-wide:
    - `/etc/ivre.conf`
    - `/usr/local/etc/ivre.conf` (read after, so higher priority)
  - one user-specific:
    - `~/.ivre.conf` (the last to be read, so highest priority)

The file should contain lines of type `key = value`. Empty lines and
comments (starting with the `#` character) are ignored. The following
values can be changed:

  - `DB`: the URL to use; default is `mongodb:///`, meaning use
    default database (`ivre`) on the default host (`localhost`). Here
    is a more complete example:
	`mongodb://user:password@host/db?colname_aaa=bbb&colname_ccc=ddd`

  - `DB_NMAP`, `DB_PASSIVE` and `DB_DATA`: specific URLs to use;
    default is to use the URL from `DB` setting.

  - `GEOIP_PATH`: default is `[INSTALL PREFIX]/share/ivre/geoip/`.

For the full and up-to-date list of settings that can be changed, see
the `ivre/config.py` file.

It might be a good idea to have a read-only account everywhere except
for some specific users or hosts that need write access to the
database (the users that insert scan results with `ivre scan2db`, the
users or the hosts that run `ivre p0f2db` and/or `ivre
passiverecon2db`). It is best to avoid using a configuration with
write access to the database when you only need a read access. This
can be achieved with users or hosts dedicated to insertion tasks.

## DB creation ##

Once IVRE has been properly configured, it's time to initialize its
databases.

For that, the command-line tools (namely `ivre ipdata`, `ivre ipinfo`,
`ivre scancli` and `ivre runscansagentdb`, respectively for
information about IP addresses, passive information, active
information and running scans through agents) have a `--init` option.

So you can run, with a user or from a host where the configuration has
a write access to the database (add `< /dev/null` to skip the
confirmation):

    $ ivre scancli --init
    This will remove any scan result in your database. Process ? [y/N] y
    $ ivre ipinfo --init
    This will remove any passive information in your database. Process ? [y/N] y
    $ ivre ipdata --init
    This will remove any country/AS information in your database. Process ? [y/N] y
    # ivre runscansagentdb --init
    This will remove any agent and/or scan in your database and files. Process ? [y/N] y

### Getting IP data ###

    # ivre ipdata --download
    $ ivre ipdata --import-all --dont-feed-ipdata-cols

### Web Server ###

Once IVRE has been installed, to also install the web interface, you
have to copy or symlink IVRE files to your web server directories, or
configure your web server to use IVRE files directly.

The files the web server should serve statically are located in
`[PREFIX]/share/ivre/web/static`, the folder the web server should
serve as CGI is located in `[PREFIX]/share/ivre/web/cgi-bin`, and the
(optional) folders to use as Dokuwiki content are located in
`[PREFIX]/share/ivre/dokuwiki/doc` and
`[PREFIX]/share/ivre/dokuwiki/media`. Make sure your Dokuwiki has been
configured with server-side URL rewriting; this means using proper
rewrite in your Web server configuration (with `mod_rewrite` when
using Apache; you can use the provided `Dockerfile`s as examples on
how to configure Apache or Nginx) and adding `$conf['userewrite'] = 1`
in your Dokuwiki config file.

You may want to change some values, by creating the file
`[PREFIX]/share/ivre/web/static/config.js` based on the `-sample`
file and by creating or modifying `/etc/ivre.conf`.

On a typical Debian/Ubuntu installation with Apache and Dokuwiki
installed with the distribution packages, these files should be copied
or (sym)linked at these locations:

 - `[PREFIX]/share/ivre/web/static/*` -> `/var/www` or `/var/www/html`
 - `[PREFIX]/share/ivre/web/cgi-bin/*` -> `/usr/lib/cgi-bin/`
 - `[PREFIX]/share/ivre/dokuwiki/doc`
     -> `/var/lib/dokuwiki/data/pages/`
 - `[PREFIX]/share/ivre/dokuwiki/media/logo.png`
     -> `/var/lib/dokuwiki/data/media/`
 - `[PREFIX]/share/ivre/dokuwiki/media/doc`
     -> `/var/lib/dokuwiki/data/media/`

The value `WEB_LIMIT` from IVRE's configuration must match the value
`limit` in the `dflt` object in `config.js`.

# Agent #

If you do not plan to run active scans with remote agents (where IVRE
will not be installed), you can skip this section.

The agent does not require IVRE to be installed. It is a script that
needs to be adapted to each situation.

The agent is only needed when you cannot install IVRE on the machine
used to scan or when you want to use many machines to run one scan.

It requires a POSIX environment, and the commands `screen`, `rsync`
and `nmap` (of course). See the [AGENT](AGENT.md) file for more
information about that.


---

This file is part of IVRE. Copyright 2011 - 2015
[Pierre LALET](mailto:pierre.lalet@cea.fr)
