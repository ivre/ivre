Some use cases
==============

As a *framework*, IVRE has several possible use cases. Of course, you
probably want to use only parts of what IVRE can do.

Your own Shodan / ZoomEye / Censys / Binaryedgeio / whatever
------------------------------------------------------------

You can use IVRE as a private (or even public, if you want)
alternative to Shodan (or any other similar service).

The main difference with public services is that you will have the
control of your data. You can scan whatever you want (your private
networks, public networks, a specific country or Autonomous System,
the whole Internet, etc.), for any port or protocol. You can run any
query on your data; no-one has to know what you are really looking
for.

Of course, this require more work than just using an existing public
service, but the benefits are huge!

IVRE does not come with a scanner, and takes advantage of `Nmap
<https://nmap.org/>`_, `Masscan
<https://github.com/robertdavidgraham/masscan>`_ and `Zgrab / Zgrab2
<https://zmap.io/>`_. Depending on your use case, you can choose one
or use both (IVRE will happily merge the results for you). Remember to
use the ``-oX`` option (which works with both Nmap and Masscan) or
``-o`` for Zgrab2, as IVRE needs the XML output file for Nmap and
Masscan, and JSON for Zgrab2.

You can use ``ivre runscans``, ``ivre runscansagent`` or
``ivre runscansagentdb`` to run Nmap scans against wide targets (more)
easily.

You will then store the results from the XML or JSON output files into
IVRE database using ``ivre scan2db``.

Finally, use ``ivre db2view nmap`` to create a ``view`` (see
:ref:`overview/principles:Purposes`) that you can explore with the
:ref:`usage/web-ui:Web User Interface`.

See :ref:`usage/kibana:IVRE with Kibana` if you want to use Kibana to
explore your scan results.

Your own Passive DNS service
----------------------------

Passive DNS services log DNS answers into a database and let you run
queries against them.

IVRE uses its `Zeek <https://www.zeek.org/>`_ script ``passiverecon``
to, among others, log DNS answers. They are stored in the ``passive``
purpose (see :ref:`overview/principles:Purposes`) via ``ivre
passiverecon2db`` CLI tool as ``DNS_ANSWER`` records.

They can be queried using ``ivre iphost`` CLI tool, as in the
following example (the results come from a PCAP file used in IVRE's
:ref:`dev/tests:Tests`):

::

   $ ivre iphost ipv4.icanhazip.com
   ipv4.icanhazip.com A 216.69.252.101 (109.0.66.10:53, 1 time, 2014-01-02 09:37:57.197000 - 2014-01-02 09:37:57.197000)
   ipv4.icanhazip.com A 216.69.252.100 (109.0.66.10:53, 1 time, 2014-01-02 09:37:57.197000 - 2014-01-02 09:37:57.197000)
   ipv4.icanhazip.com A 216.69.252.100 (109.0.66.20:53, 1 time, 2014-01-02 09:37:57.197000 - 2014-01-02 09:37:57.197000)
   ipv4.icanhazip.com A 216.69.252.101 (109.0.66.20:53, 1 time, 2014-01-02 09:37:57.197000 - 2014-01-02 09:37:57.197000)
   
   $ ivre iphost 216.69.252.101
   ipv4.icanhazip.com A 216.69.252.101 (109.0.66.10:53, 1 time, 2014-01-02 09:37:57.197000 - 2014-01-02 09:37:57.197000)
   ipv4.icanhazip.com A 216.69.252.101 (109.0.66.20:53, 1 time, 2014-01-02 09:37:57.197000 - 2014-01-02 09:37:57.197000)

To see an interactive session of IVRE using passive data (including
DNS answers), have a look at :ref:`overview/screenshots:Passive
network analysis`.

YETI plugin
-----------

`Yeti <https://yeti-platform.github.io/>`_ is a platform meant to
organize observables, indicators of compromise, TTPs, and knowledge on
threats in a single, unified repository.

It comes with an "analytics" plugin that uses IVRE's data to create
links between IP addresses, hostnames, certificates, etc.

To learn more about this plugin, have a look at `its documentation
<https://github.com/yeti-platform/yeti/tree/master/contrib/analytics/ivre_api>`_.

Blog posts and other resources
------------------------------

The author's blog has some `IVRE-related blog posts
<http://pierre.droids-corp.org/blog/html/tags/ivre.html>`_ that might be useful.

Here is a list of other blog posts about or around IVRE:

- Scan the hosts that hit your honeypots, and exploit the results!

   - `Who's Attacking Me?
     <https://isc.sans.edu/forums/diary/Whos+Attacking+Me/21933/>`_
      
   - `Three Honeypots and a Month After
     <https://www.serializing.me/2019/01/27/three-honeypots-and-a-month-after/>`_

- Scanning SAP Services:

   - `gelim/nmap-erpscan <https://github.com/gelim/nmap-erpscan>`_ on Github

   - `SAP Services detection via nmap probes
     <https://erpscan.io/press-center/blog/sap-services-detection-via-nmap-probes/>`_

   - `SAP Dispatcher Security <https://erpscan.io/press-center/blog/sap-dispatcher-security/>`_

- `Re-discover your company network with Ivre
  <https://blog.cybsec.xyz/re-discover-your-company-network-with-ivre/>`_

- IVRE tests & reviews:

   - `IVRE <https://security-bits.de/posts/2018/12/07/ivre.html>`_

   - `IVRE! Drunk Frenchman Port Scanner Framework!
     <https://mstajbakhsh.ir/ivre-drunk-frenchman-port-scanner-framework/>`_

   - `Visualizing Scans Part 1: IVRE
     <https://bestestredteam.com/2019/02/10/visualizing-scans-part-1-ivre/>`_

- Spanish:

   - `Reconocimiento de redes con IVRE
     <https://www.welivesecurity.com/la-es/2015/08/11/reconocimiento-de-redes-con-ivre/>`_

You have found (or written) a document that might help other use IVRE
or decide if they need it? Please let us know: `open an issue
<https://github.com/cea-sec/ivre/issues/new>`_ or :ref:`index:Contact`
us so that we can add a link here!
