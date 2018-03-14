# DB Server #

Follow the [documentation from MongoDB
project](http://docs.mongodb.org/manual/installation/), depending on
your distribution. It is recommended to install packages from the
MongoDB project rather than the (possibly old) packages from your
distribution.

If you want to use the "flow" module, you also need to install
[Neo4j](http://neo4j.com/).

# IVRE #

## Dependencies ##

If you plan to run scans from a machine, install
[Nmap](http://nmap.org/) and optionally [ZMap](https://zmap.io/) and
[Masscan](https://github.com/robertdavidgraham/masscan). If you want
to integrate screenshots, install
[Tesseract](https://github.com/tesseract-ocr/tesseract),
[ImageMagick](https://www.imagemagick.org/),
[FFmpeg](http://ffmpeg.org/) and [PhantomJS](http://phantomjs.org/).

If you plan to analyze PCAP file on a machine, install, depending on
your needs, [Bro](http://www.bro.org/) (version 2.3 minimum),
[p0f](http://lcamtuf.coredump.cx/p0f/) (version 2, will not work with
version 3), [Argus](http://qosient.com/argus/) and/or
[Nfdump](http://nfdump.sourceforge.net/).

To install IVRE, you'll need [Python](http://www.python.org/) 2
(version 2.6 minimum, prefer 2.7) or 3 (version 3.3 minimum), with the
following modules:

  * [Crypto](http://www.pycrypto.org/)
  * [pymongo](http://api.mongodb.org/python/) version 2.7.2 minimum.
  * [py2neo](http://py2neo.org/v3/) version 3 minimum, optional, to
    use the flow module.
  * [sqlalchemy](http://www.sqlalchemy.org/) and
    [psycopg2](http://initd.org/psycopg/) to use the experimental
    PostgreSQL backend.
  * [PIL](http://www.pythonware.com/products/pil/) optional, to trim
    screenshots.

## Installation ##

The installation of [IVRE](README.md) itself can be done by:

  * using the `setup.py` (classical `./setup.py build; sudo ./setup.py
    install`) script.

  * on Archlinux, there is an [AUR](https://aur.archlinux.org/)
    package that can be installed using
    [yaourt](https://aur.archlinux.org/packages/yaourt/) for example
    (`yaourt -S ivre`). Please vote for the
    [package](https://aur.archlinux.org/packages/ivre/) if you use it!

  * using [pip](https://pypi.python.org/pypi/pip): on a Debian-based
    system for example, install the packages `python-pip` and
    `python-dev` (needed to build dependencies) and run `pip install
    ivre` (this will download and install for you IVRE and its Python
    dependencies from [PyPI](https://pypi.python.org), the Python
    Package Index).

  * building an RPM package (you can use the provided `pkg/buildrpm`
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
  - one environment based:
    - `IVRE_CONF`, set it to the path of the configuration file to
      read

The file should contain lines of type `key = value`. Empty lines and
comments (starting with the `#` character) are ignored. The following
values can be changed:

  - `DB`: the URL to use; default is `mongodb:///ivre`, meaning use
    default database (`ivre`) on the default host (`localhost`). Here
    is a more complete example:
    `mongodb://user:password@host/db?colname_aaa=bbb&colname_ccc=ddd`

  - `DB_NMAP`, `DB_PASSIVE`, `DB_FLOW`, `DB_VIEW` and `DB_DATA`:
    specific URLs to use; default is to use the URL from `DB` setting.

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
`ivre scancli`, `ivre runscansagentdb` and `ivre viewcli`, respectively for
information about IP addresses, passive information, active information,
running scans through agents, and view access) have a `--init` option.

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
    # ivre viewcli --init
    This will remove any view in your database. Process ? [y/N] y

### Getting IP data ###

    # ivre ipdata --download
    $ ivre ipdata --import-all --no-update-passive-db

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

You may want to change some values, by creating or modifying
`/etc/ivre.conf`.

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

### Getting screenshots ###

Nmap does not take application screenshots by default. To do so, you
have to install the NSE screenshot scripts that come with IVRE. You
will also need to install PhantomJS, ImageMagick and FFMPEG. Also,
`vnc-screenshot.nse` requires Nmap version >= 7.25BETA2. If both Nmap
and IVRE have been installed in `/usr`:

    # cp /usr/share/ivre/nmap_scripts/*.nse /usr/share/nmap/scripts/
    # patch /usr/share/nmap/scripts/rtsp-url-brute.nse \
	> /usr/share/ivre/nmap_scripts/patches/rtsp-url-brute.patch
    # nmap --script-updatedb

And now, you can play:

	# nmap -sV --script screenshot [targets]

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

This file is part of IVRE. Copyright 2011 - 2017
[Pierre LALET](mailto:pierre.lalet@cea.fr)
