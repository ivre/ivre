FAQ
===

If you cannot find the answer to your question, either here or in this
documentation, feel free to `open an issue
<https://github.com/cea-sec/ivre/issues/new>`_ and use the label
"question".

Web interface
-------------

Notebook shows "Forbidden"
~~~~~~~~~~~~~~~~~~~~~~~~~~

**I cannot access the notepad (the Dokuwiki content), and get a
"Forbidden" message.**

You need to configure your web server to allow access from other hosts
on the network to the Dokuwiki content. It is often restricted, by
default, to local users only. If you are using Apache, you can look
for an ACL like ``Allow from localhost 127.0.0.1 ::1`` and adapt it to
your network.

How can I restrict access to IVRE's Web interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**I want to prevent unauthorized access to IVRE's results.**

First, you have to configure your web server to authenticate remote
users. The most important, of course, is to protect access to CGI files
(the static files are publicly available and do not contain any result).

In an AD or Kerberos environment for example, Apache can be configured
to provide SSO authentication.

Then, if you want to restrict access to the results based on the user
login or domain, you can add the following lines to ``/etc/ivre.conf``:

::

   WEB_DEFAULT_INIT_QUERY = 'noaccess'
   WEB_INIT_QUERIES = {
       'admin@SUBNETWORK.NETWORK.AD': 'category:SubNetwork',
       '@ADMIN.NETWORK.AD': 'full',
   }

By default, users won't have access to any result. The user
``admin@SUBNETWORK.NETWORK.AD`` will have access to the results in the
category ``SubNetwork``. The users in the ``ADMIN.NETWORK.AD`` realm
will have access to all the results.

Scanning the Internet is slow!
------------------------------

This is based on `issue GH#822
<https://github.com/cea-sec/ivre/issues/822>`_.

When running ``ivre runscans --routable --limit 40``, one can notice
the scan really takes a long time to terminate.

First of all, IVRE is not guilty here. IVRE runs Nmap, feeds it with
targets, and wait for its output. You would get the same results using
the same Nmap options as IVRE.

That being said, we have several ways to speed up a scan.

Use Masscan rather that Nmap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is pretty radical, and have an important drawback: Masscan
results gather less intelligence than Nmap (a lot less in some
situations).

However, it is often the only option to get comprehensive scans of the
IPv4 routable address space.

A trade-off could be, for some protocols, to use Zmap /
Zgrab2. Compare the possibilities of Masscan (``--banner``) versus
Zgrab2 for the protocol(s) you want to scan.

IVRE will happily combine results from Nmap, Masscan and Zgrab /
Zgrab2: you can build your own, perfectly suited, scanning solution
and use IVRE to merge and browse the results.

Parallelize Nmap scans
~~~~~~~~~~~~~~~~~~~~~~

Another option is to run several Nmap processes instead of
one. Theoretically it should not work, since Nmap is supposed to
handle efficiently the resources, but it has proven useful in several
situations, particularly when scanning heavily filtered hosts or
random hosts across the Internet.

For that, one can either use an agent (see
:ref:`install/agents:Agents`) or ``ivre runscans --output
XMLFork --processes <n>`` where ``<n>`` is the number of simultaneous
Nmap processes to use.

Can IVRE be used to look for XXX?
---------------------------------

IVRE is not a scanner or a network traffic analyzer. It relies on
tools like Nmap, Masscan, Zgrab2, Zeek and p0f, parses their results
and stores them in a database.

So when you are asking, for example, "can IVRE scan a network for
hosts with the `Heartbleed
<https://en.wikipedia.org/wiki/Heartbleed>`_ vulnerability?", in
reality you are asking two different questions:

- "Can Nmap or Masscan or Zgrab2 detect when a scanned hosts is
  vulnerable to the Heartbleed vulnerability?"
- "How can IVRE list the hosts that have been found vulnerable to
  Heartbleed by Nmap or Masscan?"

The first question is not related to IVRE (and should probably be
asked to Nmap, Masscan or Zgrab2 developers), but the second question
is (and may be asked as a `"question" labeled issue
<https://github.com/cea-sec/ivre/issues/new?labels=question>`_).

For that particular Heartbleed example, Nmap, Masscan and Zgrab2 can
(reliably) report hosts with the Heartbleed vulnerability, and IVRE
can be used to find such hosts.

How can I configure iptables to get logs used by flow2db tool
-------------------------------------------------------------

When you don't have access to low level network data, an easy way to
discover a part of network traffic is to use netfilter logs collected
via syslog.

To be efficient, all the systems must have iptables activated and
configured to send logs.

For example

::

      -A INPUT   -j LOG --log-prefix "IPTABLES/INPUT: "
      -A OUTPUT  -j LOG --log-prefix "IPTABLES/OUTPUT: "
      -A FORWARD -j LOG --log-prefix "IPTABLES/FORWARD: "

To log all traffic, the rules can be set at the top of all rules. Be
careful with the OUTPUT rule if the logs are sent over the network!

On the syslog server or on each host, just run grep to collect the
data needed for the iptables flow2db parser:

.. code:: bash

      $ grep -l 'IPTABLES/' /var/log/syslog /var/log/kernel.log ... > syslog-iptables.log

Then import data to ivredb using flow2db tool:

.. code:: bash

      $ ivre flow2db -t iptables syslog-iptables.log
