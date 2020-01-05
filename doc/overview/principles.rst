Principles
==========

IVRE is a network cartography (or network recon) framework.

Purposes
--------

IVRE has five **purposes** (we use this word to refer to the different
types of data IVRE handles), which can be stored by one or more
**back-end** databases:

- ``data``: associates IP ranges to Autonomous Systems (AS numbers and
  names), and geographical information (country, region, city), based
  on data from `Maxmind GeoIP
  <https://www.maxmind.com/en/geoip2-services-and-databases>`_. It can
  be queried using:

   - Python API: the ``db.data`` object from the ``ivre.db`` module.
   - Command line: the ``ivre ipdata`` tool.
   - Web (JSON) API: the ``/cgi/ipdata/<address>`` URL.

- ``nmap`` (sometimes also referred to as ``scans``): contains `Nmap
  <http://nmap.org/>`_, `Masscan
  <https://github.com/robertdavidgraham/masscan/>`_ and `Zgrab /
  Zgrab2 <https://zmap.io/>`_ scan results. Each record represents one
  host seen during one network scan. It can be queried using:

   - Python API: the ``db.nmap`` object from the ``ivre.db`` module.
   - Command line: the ``ivre scancli`` tool.
   - Web (JSON) API: the ``/cgi/scans`` and ``/cgi/scans/*`` URLs.

- ``passive``: contains host intelligence captured from the network
  using a `Zeek <https://www.zeek.org/>`_ dedicated module called
  ``passiverecon``. Each record represents one piece of information
  (*e.g.*, the HTTP ``Server:`` header value ``Apache`` has been seen
  10 times on port 80 of host 1.2.3.4). It can be queried using:

   - Python API: the ``db.passive`` object from the ``ivre.db``
     module.
   - Command line: the ``ivre ipinfo`` tool.

- ``view``: contains a consolidated view of hosts based on data from
  ``nmap`` and ``passive``. The structure of the records is similar to
  ``nmap``, but each record represents a host, seen during one or more
  network scans and/or seen from network captures. It can be queried using:

   - Python API: the ``db.view`` object from the ``ivre.db`` module.
   - Command line: the ``ivre view`` tool.
   - Web (JSON) API: the ``/cgi/view`` and ``/cgi/view/*`` URLs.
   - Web UI: the ``/`` or ``/index.html`` Web page.

- ``flow``: contains aggregated network flows, as seen by `Zeek
  <https://www.zeek.org/>`__, `Argus <http://qosient.com/argus/>`_ or
  Netflows (using `Nfdump <http://nfdump.sourceforge.net/>`_). It can
  be queried using:

   - Python API: the ``db.flow`` object from the ``ivre.db`` module.
   - Command line: the ``ivre flowcli`` tool.
   - Web (JSON) API: the ``/flows`` URL.
   - Web UI: the ``/flow.html`` Web page.

The following (non-exhaustive) figure shows how the data gets from
your favorite open-source tools to IVRE's databases.

Storing data
------------

.. graphviz::

   digraph {
      "maxmind.com";
      FLOWS [label="flow files"];
      FLOW_LOG [label=".log files"];
      PASS_LOG [label="passive_recon.log"];
      XML [label="XML scan result"];
      JSON [label="JSON scan result"];
      db_data [label="db.data" shape="box" style="filled"];
      db_flow [label="db.flow" shape="box" style="filled"];
      db_passive [label="db.passive" shape="box" style="filled"];
      db_nmap [label="db.nmap" shape="box" style="filled"];
      db_view [label="db.view" shape="box" style="filled"];
      "maxmind.com" -> db_data [label="ivre\nipdata"];
      "Argus" -> FLOWS;
      "Nfdump" -> FLOWS;
      "Zeek" -> FLOW_LOG;
      "Zeek" -> PASS_LOG [label="passiverecon"];
      FLOWS -> db_flow [label="ivre\nflow2db"];
      "Nmap" -> XML [label="-oX"];
      "Masscan" -> XML [label="-oX"];
      "Zgrab2" -> JSON [label="-o"];
      FLOW_LOG -> db_flow [label="ivre\nzeek2db"];
      PASS_LOG -> db_passive [label="ivre\npassiverecon2db"];
      XML -> db_nmap [label="ivre\nscan2db"];
      JSON -> db_nmap [label="ivre\nscan2db"];
      db_passive -> db_view [label="ivre\ndb2view"];
      db_nmap -> db_view [label="ivre\ndb2view"];
   }

Accessing data
--------------

The following (also non-exhaustive) figures show how the data gets
from IVRE's databases back into your hands.

.. graphviz::

   digraph {
      db_data [label="db.data" shape="box" style="filled"];
      db_flow [label="db.flow" shape="box" style="filled"];
      db_passive [label="db.passive" shape="box" style="filled"];
      web_api_data [label="Web API\n/ipdata"];
      web_api_flows [label="Web API\n/flows"];
      web_ui_flow [label="Web UI\n/flow.html"];
      cli_ipdata [label="CLI\nipdata"];
      cli_flow [label="CLI\nflowcli"];
      cli_ipinfo [label="CLI\nipinfo"];
      cli_iphost [label="CLI\niphost"];
      db_data -> web_api_data;
      db_flow -> web_api_flows;
      db_flow -> cli_flow;
      db_passive -> cli_ipinfo;
      db_passive -> cli_iphost;
      web_api_flows -> web_ui_flow;
      db_data -> cli_ipdata;
  }

.. graphviz::

   digraph {
      db_nmap [label="db.nmap" shape="box" style="filled"];
      db_view [label="db.view" shape="box" style="filled"];
      web_api_scans [label="Web API\n/scans"];
      web_api_view [label="Web API\n/view"];
      web_ui_view [label="Web UI /"];
      cli_scancli [label="CLI\nscancli"];
      cli_view [label="CLI\nview"];
      db_nmap -> web_api_scans;
      db_view -> web_api_view;
      web_api_view -> web_ui_view;
      db_nmap -> cli_scancli;
      db_view -> cli_view;
  }
