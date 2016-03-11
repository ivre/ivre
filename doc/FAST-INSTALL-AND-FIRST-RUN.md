This file describes the steps to install [IVRE](README.md), run the
first scans and add the results to the database with all components
(scanner, web server, database server) on the same (Debian or Ubuntu)
machine.

Please note that, depending on your distribution, the versions of some
softwares might not be recent enough, particularly for MongoDB
(version 2.6 minimum) and pymongo (version 2.7.2 minimum; see
[README](README.md) to know which versions can be used with IVRE). If
that's the case, you will have to install those softwares on you own,
refering to their documentation (see
[MongoDB on Debian](http://docs.mongodb.org/manual/tutorial/install-mongodb-on-debian/)
or
[MongoDB on Ubuntu](http://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/)
and [pymongo](https://pypi.python.org/pypi/pymongo/)), instead of
`apt-get`-ting them.

You might also want to adapt it to your needs, architecture, etc.

**For another way to run IVRE easily (probably more easily), see
  [Docker](DOCKER.md).**


# Install #

    $ sudo apt-get -y install mongodb python-pymongo python-crypto apache2 dokuwiki
    $ git clone https://github.com/cea-sec/ivre
    $ cd ivre
    $ python setup.py build
    $ sudo python setup.py install


# Setup #

    $ sudo -s
    # cd /var/www/html ## or depending on your version /var/www
    # rm index.html
    # ln -s /usr/local/share/ivre/web/static/* .
    # cd /usr/lib/cgi-bin
    # ln -s /usr/local/share/ivre/web/cgi-bin/* .
    # cd /var/lib/dokuwiki/data/pages
    # ln -s /usr/local/share/ivre/dokuwiki/doc
    # cd /var/lib/dokuwiki/data/media
    # ln -s /usr/local/share/ivre/dokuwiki/media/logo.png
    # ln -s /usr/local/share/ivre/dokuwiki/media/doc
    # cd /usr/share/dokuwiki
    # patch -p0 < /usr/local/share/ivre/dokuwiki/backlinks.patch
    # cd /etc/apache2/mods-enabled
    # for m in cgi rewrite ; do [ -L $m.load ] || ln -s ../mods-available/$m.load ; done
    # cd /usr/local/share/ivre/web/cgi-bin
    # sed -i 's/^\(\s*\)#Rewrite/\1Rewrite/' /etc/dokuwiki/apache.conf
    # service apache2 reload
    # exit

Open a web browser and visit [http://localhost/](http://localhost/).
IVRE Web UI should show up, with no result of course. Click the HELP
button to check if everything works.


# Database init, data download & importation #

    $ ivre scancli --init
    This will remove any scan result in your database. Process ? [y/N] y
    $ ivre ipinfo --init
    This will remove any passive information in your database. Process ? [y/N] y
    $ ivre ipdata --init
    This will remove any country/AS information in your database. Process ? [y/N] y
    $ sudo ivre runscansagentdb --init
    This will remove any agent and/or scan in your database and files. Process ? [y/N] y
    $ sudo ivre ipdata --download
    $ ivre ipdata --import-all --no-update-passive-db

The two latest steps may take a long time to run, nothing to worry
about.


# Run a first scan #

Against 1k (routable) IP addresses, with a single nmap process:

    $ sudo ivre runscans --routable --limit 1000

Go have some coffees and/or beers (remember that according to the
traveler's theorem, for any time of the day, there exists a time zone
in which it is OK to drink).

When the command has terminated, import the results:

    $ ivre scan2db -c ROUTABLE,ROUTABLE-CAMPAIGN-001 -s MySource -r \
    >              scans/ROUTABLE/up

The `-c` argument adds categories to the scan results. Categories are
arbitrary names used to filter results. In this example, the values
are `ROUTABLE`, meaning the results came out while scanning the entire
reachable address space (as opposed to while scanning a specific
network, AS or country, for example), and `ROUTABLE-CAMPAIGN-001`,
which is the name I have chosen to mark this particular scan campaign.

The `-s` argument adds a name for the source of the scan. Here again,
it is an arbitrary name you can use to unambiguously specify the
network access used to run the scan. This can be used later to
highlight result differences depending on where the scans are run
from.

Go back to the Web UI and browse your first scan results!


# Some remarks #

There is no tool (for now) to automatically import scan results to the
database. It is your job to do so, according to your settings.

If you run very large scans (particularly against random hosts on the
Internet), do NOT use the default `--output=XML` option. Rather, go
for the `--output=XMLFork`. This will fork one nmap process per IP to
scan, and is (sadly) much more reliable.

Another way to run scans efficiently is to use an [agent](AGENT.md)
and the `ivre runscansagent` command.


---

This file is part of IVRE. Copyright 2011 - 2015
[Pierre LALET](mailto:pierre.lalet@cea.fr)
