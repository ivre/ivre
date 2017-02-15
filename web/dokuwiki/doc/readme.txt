====== What is it? ======

IVRE (Instrument de veille sur les réseaux extérieurs) or DRUNK (Dynamic Recon of UNKnown networks) is a network recon framework, including tools for passive recon (flow analytics relying on [[https://www.bro.org/|Bro]], [[http://qosient.com/argus/|Argus]], [[http://nfdump.sourceforge.net/|Nfdump]], fingerprint analytics based on Bro and [[http://lcamtuf.coredump.cx/p0f/|p0f]] and active recon (IVRE uses [[http://nmap.org/|Nmap]] to run scans, can use [[https://zmap.io/|ZMap]] as a pre-scanner; IVRE can also import XML output from Nmap and [[https://github.com/robertdavidgraham/masscan|Masscan]]).

The advertising slogans are:

  * (in French): IVRE, il scanne Internet.
  * (in English): Know the networks, get DRUNK!

The names IVRE and DRUNK have been chosen as a tribute to "Le Taullier".

===== Disclaimer =====

IVRE is a **framework**. Meaning it does **not** come with ready-to-run scripts to daemonize actions, etc. You need to do that work yourself, as it strongly depends on what system you use, your environment, and what you want to do.

===== External programs / dependencies =====

IVRE relies on:

  * [[http://www.python.org/|Python]] 2, version 2.6 minimum
    * the [[http://www.pycrypto.org/|Crypto]] module
    * the [[http://api.mongodb.org/python/|pymongo]] module, version 2.7.2 minimum.
    * optionally [[http://www.pythonware.com/products/pil/|PIL]], to trim screenshots.
    * optionally [[http://py2neo.org/v3/|py2neo]] to use the flow module, version 3 minimum.
    * optionally [[http://www.sqlalchemy.org/|sqlalchemy]] and [[http://initd.org/psycopg/|psycopg2]] to use the **experimental** PostgreSQL backend.
  * [[http://nmap.org/|Nmap]]
  * optionnaly [[https://zmap.io/|ZMap]] and/or [[https://github.com/robertdavidgraham/masscan|Masscan]]
  * [[http://www.bro.org/|Bro]] (version 2.3 minimum), [[http://qosient.com/argus/|Argus]], [[http://nfdump.sourceforge.net/|Nfdump]]& [[http://lcamtuf.coredump.cx/p0f/|p0f]] (version 2, will not work with version 3) for the passive fingerprint and flow modules.
  * [[http://www.mongodb.org/|MongoDB]], version 2.6 minimum (tests are run with versions 2.6.12, 3.0.14, 3.2.12, 3.4.2 and 3.5.3).
  * optionnaly [[http://neo4j.com/|Neo4j]] for the flow module.
  * optionnaly [[https://www.postgresql.org/|PostgreSQL]], version 9.5 minimum (tests are run with versions 9.5.6 and 9.6.2), for the **experimental** PostgreSQL backend.
  * a web server (successfully tested with [[https://httpd.apache.org/|Apache]] and [[http://nginx.org/|Nginx]], should work with anything capable of serving static files and run a Python-based CGI), although a test web server is now distributed with IVRE (''%%ivre httpd%%'').
  * a web browser (successfully tested with recent versions of [[https://www.mozilla.org/firefox/|Firefox]] and [[http://www.chromium.org/|Chromium]]).
  * Maxmind [[https://www.maxmind.com/en/geolocation_landing|GeoIP]] free databases.
  * optionally [[https://github.com/tesseract-ocr/tesseract|Tesseract]], if you plan to add screenshots to your Nmap scan results
  * optionally [[https://neo4j.com/|neo4j]] (version >= 2) & [[http://py2neo.org|py2neo]] (version >= 3) for ivre flow related tools
  * optionally [[http://qosient.com/argus/index.shtml|argus]] and/or [[http://nfdump.sourceforge.net/|nfdump]] for ivre flow2db
  * optionally [[http://www.docker.com/|Docker]] & [[https://www.vagrantup.com/|Vagrant]] (version 1.6 minimum)

IVRE comes with (refer to the [[doc:license-external|LICENSE-EXTERNAL]] file for the licenses):

  * [[https://angularjs.org/|AngularJS]]
  * [[http://getbootstrap.com/|Twitter Bootstrap]]
  * [[https://jquery.com/|jQuery]]
  * [[http://d3js.org/|D3.js]]
  * [[http://linkurio.us/|Linkurious]]
  * [[https://lipis.github.io/flag-icon-css/|flag-icon-css]]

====== Installation ======

See the [[doc:install|INSTALL]] file. You can also try to use [[doc:docker|Docker]] to easily setup and run an IVRE architecture.

====== Passive recon ======

The following steps will show some examples of **passive** network recon with IVRE. If you only want **active** (for example, Nmap-based) recon, you can skip this part.

===== Using Bro =====

You need to run bro (2.3 minimum) with the option ''%%-b%%'' and the location of the ''%%passiverecon.bro%%'' file. If you want to run it on the ''%%eth0%%'' interface, for example, run:

<code>
# mkdir logs
# LOG_PATH=logs/passiverecon \
> bro -b /usr/local/share/ivre/passiverecon/passiverecon.bro -i eth0
</code>
If you want to run it on the ''%%capture%%'' file (''%%capture%%'' needs to a PCAP file), run:

<code>
$ mkdir logs
$ LOG_PATH=logs/passiverecon \
> bro -b /usr/local/share/ivre/passiverecon/passiverecon.bro -r capture
</code>
This will produce log files in the ''%%logs%%'' directory. You need to run a ''%%ivre passivereconworker%%'' to process these files. You can try:

<code>
$ ivre passivereconworker --directory=logs
</code>
This program will not stop by itself. You can (''%%p%%'')''%%kill%%'' it, it will stop gently (as soon as it has finished to process the current file).

You can also send the data from ''%%bro%%'' to the database without using intermediate files:

<code>
$ bro -b /usr/local/share/ivre/passiverecon/passiverecon.bro [option] \
> | ivre passiverecon2db
</code>
===== Using p0f =====

To start filling your database with information from the ''%%eth0%%'' interface, you just need to run (''%%passiverecon%%'' is just a sensor name here):

<code>
# ivre p0f2db -s passiverecon iface:eth0
</code>
And from the same ''%%capture%%'' file:

<code>
$ ivre p0f2db -s passiverecon capture
</code>
===== Using the results =====

You have two options for now:

  * the ''%%ivre ipinfo%%'' command line tool
  * the ''%%db.passive%%'' object of the ''%%ivre.db%%'' Python module

For example, to show everything stored about an IP address or a network:

<code>
$ ivre ipinfo 1.2.3.4
$ ivre ipinfo 1.2.3.0/24
</code>
See the output of ''%%ivre help ipinfo%%''.

To use the Python module, run for example:

<code>
$ python
>>> from ivre.db import db
>>> db.passive.get(db.passive.flt_empty)[0]
</code>
For more, run ''%%help(db.passive)%%'' from the Python shell.

====== Active recon ======

===== Scanning =====

The easiest way is to install IVRE on the "scanning" machine and run:

<code>
# ivre runscans --routable --limit 1000 --output=XMLFork
</code>
This will run a standard scan against 1000 random hosts on the Internet by running 30 nmap processes in parallel. See the output of ''%%ivre help runscans%%'' if you want to do something else.

When it's over, to import the results in the database, run:

<code>
$ ivre scan2db -c ROUTABLE-CAMPAIGN-001 -s MySource -r scans/ROUTABLE/up
</code>
Here, ''%%ROUTABLE-CAMPAIGN-001%%'' is a category (just an arbitrary name that you will use later to filter scan results) and ''%%MySource%%'' is a friendly name for your scanning machine (same here, an arbitrary name usable to filter scan results; by default, when you insert a scan result, if you already have a scan result for the same host address with the same source, the previous result is moved to an "archive" collection (fewer indexes) and the new result is inserted in the database).

There is an alternative to installing IVRE on the scanning machine that allows to use several agents from one master. See the [[doc:agent|AGENT]] file, the program ''%%ivre runscansagent%%'' for the master and the ''%%agent/%%'' directory in the source tree.

===== Using the results =====

You have three options:

  * the ''%%ivre scancli%%'' command line tool
  * the ''%%db.nmap%%'' object of the ''%%ivre.db%%'' Python module
  * the web interface

==== CLI: ivre scancli ====

To get all the hosts with the port 22 open:

<code>
$ ivre scancli --port 22
</code>
See the output of ''%%ivre help scancli%%''.

==== Python module ====

To use the Python module, run for example:

<code>
$ python
>>> from ivre.db import db
>>> db.nmap.get(db.nmap.flt_empty)[0]
</code>
For more, run ''%%help(db.nmap)%%'' from the Python shell.

==== Web interface ====

The interface is meant to be easy to use, it has its own [[doc:webui|documentation]].

====== License ======

IVRE is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

IVRE is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License [[doc:license|along with IVRE]]. If not, see [[http://www.gnu.org/licenses/|the gnu.org web site]].

====== Support ======

Try ''%%ivre help%%'' for the CLI commands, ''%%help()%%'' under Python and the "HELP" button in the web interface.

Have a look at the [[doc:faq|FAQ]]!

Feel free to contact the author and offer him a beer if you need help!

If you don't like beer, a good scotch or any other good alcoholic beverage will do (it is the author's unalienable right to decide whether a beverage is good or not).

====== Contributing ======

Code contributions (pull-requests) are of course welcome!

The project needs scan results and capture files that can be provided as examples. If you can contribute some samples, or if you want to contribute some samples and would need some help to do so, or if you can provide a server to run scans, please contact the author.

====== Contact ======

For both support and contribution, the [[https://github.com/cea-sec/ivre|repository]] on Github should be used: feel free to create a new issue or a pull request!

You can also try to use the e-mail ''%%dev%%'' on the domain ''%%ivre.rocks%%'', or to join the IRC chan [[irc://irc.freenode.net/%23ivre|#ivre]] on [[https://freenode.net/|Freenode]].


----

This file is part of IVRE. Copyright 2011 - 2017 [[mailto:pierre.lalet@cea.fr|Pierre LALET]]

