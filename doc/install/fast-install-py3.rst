Fast install with Python 3
==========================

This file describes the steps to install IVRE builded with Python 3, 
with all components (scanner, webserver, database server) on the same machine.
We assume that you use a fresh and up-to-date Ubuntu Server 18.04 LTS.

We are going to install the following components :

 - MongoDB Community Edition
 - Nmap
 - Masscan
 - Zeek (formerly Bro)
 - P0f
 - Argus
 - Nfdump
 - Neo4j
 - All required Python 3 dependencies
 - IVRE (CLI side)
 - IVRE (Apache2 side)
 
Although IVRE is compatible with Python 2, it will not be maintained past January 1, 2020. 
So, take the initiative and build IVRE with Python 3.
 
MongoDB Community Edition installation
--------------------------------------

::

  $ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4
  $ echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.0 multiverse" | \ 
  sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
  $ sudo apt update
  $ sudo apt install mongodb-org -y
  $ sudo systemctl enable mongod
  
Add to ``/etc/security/limits.conf`` :

::

  mongod           soft    fsize           unlimited
  mongod           hard    fsize           unlimited
  mongos           soft    fsize           unlimited
  mongos           hard    fsize           unlimited
  mongod           soft    cpu             unlimited
  mongod           hard    cpu             unlimited
  mongos           soft    cpu             unlimited
  mongos           hard    cpu             unlimited
  mongod           soft    as              unlimited
  mongod           hard    as              unlimited
  mongos           soft    as              unlimited
  mongos           hard    as              unlimited
  mongod           soft    memlock         unlimited
  mongod           hard    memlock         unlimited
  mongos           soft    memlock         unlimited
  mongos           hard    memlock         unlimited
  mongod           soft    nofile          64000
  mongod           hard    nofile          64000
  mongos           soft    nofile          64000
  mongos           hard    nofile          64000
  mongod           soft    nproc           64000
  mongod           hard    nproc           64000 
  mongos           soft    nproc           64000
  mongos           hard    nproc           64000

Then in both ``/etc/pam.d/common-session`` and  ``/etc/pam.d/common-session-noninteractive`` :

::

  session required        pam_limits.so

Start MongoDB service :

::

  sudo systemctl start mongod

Nmap installation
-----------------

::

  $ sudo apt install nmap

Masscan installation
--------------------

::

  $ cd /opt
  $ sudo apt install gcc make libpcap-dev -y
  $ sudo git clone https://github.com/robertdavidgraham/masscan.git
  $ cd masscan
  $ sudo make
  $ sudo cp bin/masscan /usr/local/bin

Zeek (formerly Bro) installation
--------------------------------

::

  $ wget -O- "http://download.opensuse.org/repositories/network:/bro/xUbuntu_18.04/Release.key" | \ 
  sudo apt-key add -
  $ echo 'deb http://download.opensuse.org/repositories/network:/bro/xUbuntu_18.04/ /' | \ 
  sudo tee '/etc/apt/sources.list.d/bro.list'
  $ sudo apt update
  $ sudo apt install bro -y

P0f installation
----------------

Don't try to install a version greater than 2.x because it is not supported.

::

  $ cd /opt
  $ sudo wget http://lcamtuf.coredump.cx/p0f3/releases/old/2.x/p0f-2.0.8.tgz
  $ sudo tar -xvf p0f-2.0.8.tgz
  $ cd p0f
  $ sudo make
  $ sudo make install
  
Argus installation
------------------

::

  $ sudo apt install argus-server
  

Nfdump installation
-------------------

:: 

  $ sudo apt install nfdump

Neo4j installation
-------------------

::

  $ wget -O - https://debian.neo4j.org/neotechnology.gpg.key | sudo apt-key add -
  $ echo 'deb https://debian.neo4j.org/repo stable/' | \ 
  sudo tee /etc/apt/sources.list.d/neo4j.list
  $ sudo apt update
  $ sudo apt install neo4j -y
  $ sudo systemctl enable neo4j
  $ sudo sed -i 's/#dbms.connectors.default_listen_address=0.0.0.0/dbms.connectors.default_listen_address=\
  0.0.0.0/g' /etc/neo4j/neo4j.conf
  $ sudo systemctl enable neo4j
  $ sudo systemctl start neo4j
  
Connect to your Ubuntu Server IP address on port 7474. Login with neo4j:neo4j and change your password as requested.

Python 3 dependencies installation
----------------------------------

::

  $ sudo apt install python3-pip python3-dev -y
  $ sudo -H pip3 install bottle pycrypto future pymongo py2neo==3.1.2

IVRE CLI installation
---------------------

::

  $ cd /opt
  $ sudo git clone https://github.com/cea-sec/ivre.git
  $ cd ivre
  $ sudo python3 setup.py build
  $ sudo python3 setup.py install
  $ echo 'DB_FLOW = "neo4j://neo4j:<new password>@localhost:7474/"' | sudo tee /etc/ivre.conf
  $ ivre ipinfo --init
  $ ivre scancli --init
  $ ivre view --init
  $ ivre flowcli --init
  $ sudo ivre runscansagentdb --init
  $ sudo ivre ipdata --download --import-all
  
This last command take 40 minutes to terminate. Be patient.

IVRE Webserver installation
---------------------------

::

  $ sudo apt install apache2 libapache2-mod-wsgi-py3 -y
  $ sudo -s
  $ cd /var/www/html
  $ rm index.html
  $ ln -s /usr/local/share/ivre/web/static/* .
  $ cd /etc/apache2/mods-enabled
  $ for m in rewrite.load wsgi.conf wsgi.load ; do
    [ -L $m ] || ln -s ../mods-available/$m ; done
  $ cd /etc/apache2
  $ echo 'Alias /cgi "/usr/local/share/ivre/web/wsgi/app.wsgi"' > conf-enabled/ivre.conf
  $ echo '<Location /cgi>' >> conf-enabled/ivre.conf
  $ echo 'SetHandler wsgi-script' >> conf-enabled/ivre.conf
  $ echo 'Options +ExecCGI' >> conf-enabled/ivre.conf
  $ echo 'Require all granted' >> conf-enabled/ivre.conf
  $ echo '</Location>' >> conf-enabled/ivre.conf
  $ chmod o+r /usr/local/share/ivre/web/wsgi/app.wsgi
  $ systemctl restart apache2
  $ exit
  
Open a web browser and visit ``http://<Ubuntu Server IP>``.
IVRE Web UI should show up, with no result of course. Click the HELP
button to check if everything works.

Some remarks
------------

There is no tool (for now) to automatically import scan results to the
database. It is your job to do so, according to your settings.
