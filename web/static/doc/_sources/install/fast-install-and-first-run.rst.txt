Fast install & first run
========================

This file describes the steps to install IVRE, run the first scans and
add the results to the database with all components (scanner, web
server, database server) on the same (Debian or Ubuntu) machine.

You might also want to adapt it to your needs, architecture, etc.

For another way to run IVRE easily (probably even more easily), see
:ref:`install/docker:Docker`.

Install MongoDB
---------------

Follow the instructions from the MongoDB project, for example:

* `MongoDB on Debian <http://docs.mongodb.org/manual/tutorial/install-mongodb-on-debian/>`__
* `MongoDB on Ubuntu <http://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/>`__

Install IVRE
------------

::

   $ sudo apt -y --no-install-recommends install python3-pymongo \
   >   python3-cryptography python3-bottle python3-openssl \
   >   python3-pillow python3-pip apache2 libapache2-mod-wsgi-py3 \
   >   dokuwiki git
   $ git clone https://github.com/ivre/ivre
   $ cd ivre
   $ sudo pip3 install . --break-system-packages

Setup
-----

::

   $ sudo -s
   # cd /var/www/html ## or depending on your version /var/www
   # rm index.html
   # ln -s /usr/local/share/ivre/web/static/* .
   # cd /var/lib/dokuwiki/data/media
   # ln -s /usr/local/share/ivre/dokuwiki/media/logo.png
   # cd /usr/share/dokuwiki
   # patch -p0 < /usr/local/share/ivre/patches/dokuwiki/backlinks-20230404a.patch
   # cd /etc/apache2/mods-enabled
   # for m in rewrite.load wsgi.conf wsgi.load ; do
   >   [ -L $m ] || ln -s ../mods-available/$m ; done
   # cd ../
   # echo 'Alias /cgi "/usr/local/share/ivre/web/wsgi/app.wsgi"' > conf-enabled/ivre.conf
   # echo '<Location /cgi>' >> conf-enabled/ivre.conf
   # echo 'SetHandler wsgi-script' >> conf-enabled/ivre.conf
   # echo 'Options +ExecCGI' >> conf-enabled/ivre.conf
   # echo 'Require all granted' >> conf-enabled/ivre.conf
   # echo '</Location>' >> conf-enabled/ivre.conf
   # sed -i 's/^\(\s*\)#Rewrite/\1Rewrite/' /etc/dokuwiki/apache.conf
   # echo 'WEB_GET_NOTEPAD_PAGES = "localdokuwiki"' >> /etc/ivre.conf
   # service apache2 reload  ## or start
   # exit

Open a web browser and visit `http://localhost/ <http://localhost/>`__.
IVRE Web UI should show up, with no result of course. Click the HELP
button to check if everything works.

Database init, data download & importation
------------------------------------------

::

   $ yes | ivre ipinfo --init
   $ yes | ivre scancli --init
   $ yes | ivre view --init
   $ yes | ivre flowcli --init
   $ sudo ivre ipdata --download
   $ sudo ivre getwebdata

Run a first scan
----------------

Run an Nmap scan with the options of your choice; for example, against
a small list of routable IP addresses:

::

   $ sudo nmap -sS -Pn -p- --open --traceroute -oX scan.xml \
   >          -iL targets.txt

When the scan has terminated, import the results and create a view:

::

   $ ivre scan2db -c ROUTABLE,ROUTABLE-CAMPAIGN-001 -s MySource scan.xml
   $ ivre db2view nmap

The ``-c`` argument adds categories to the scan results. Categories are
arbitrary names used to filter results. In this example, the values are
``ROUTABLE``, meaning the results came out while scanning the entire
reachable address space (as opposed to while scanning a specific
network, AS or country, for example), and ``ROUTABLE-CAMPAIGN-001``,
which is the name I have chosen to mark this particular scan campaign.

The ``-s`` argument adds a name for the source of the scan. Here again,
it is an arbitrary name you can use to unambiguously specify the network
access used to run the scan. This can be used later to highlight result
differences depending on where the scans are run from.

Go back to the Web UI and browse your first scan results!

Some remarks
------------

There is no tool (for now) to automatically import scan results into
the database. It is your job to do so, according to your settings.

If you run very large scans (particularly against random hosts on the
Internet), running a single Nmap process is rarely the best
choice. Split the target into chunks and run several Nmap processes in
parallel; ``ivre scan2db`` will happily ingest the resulting XML
files, and Masscan / Zgrab2 output too.
