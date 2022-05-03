Principles
==========

IVRE is a network cartography (or network recon) framework.

Purposes
--------

IVRE has five **purposes** (we use this word to refer to the different
types of data IVRE handles), which can be stored by one or more
**backend** databases:

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
  <https://github.com/robertdavidgraham/masscan/>`_, `Dismap
  <https://github.com/zhzyker/dismap/>`_, `Zgrab2
  <https://github.com/zmap/zgrab2/>`_, `ZDNS
  <https://github.com/zmap/zdns>`_, `Nuclei
  <https://github.com/projectdiscovery/nuclei>`_, `httpx
  <https://github.com/projectdiscovery/httpx>`_ and `dnsx
  <https://github.com/projectdiscovery/dnsx>`_ scan results, as well
  as ``ivre auditdom`` results. Each record represents one host seen
  during one network scan. It can be queried using:

   - Python API: the ``db.nmap`` object from the ``ivre.db`` module.
   - Command line: the ``ivre scancli`` tool.
   - Web (JSON) API: the ``/cgi/scans`` and ``/cgi/scans/*`` URLs.

- ``passive``: contains host intelligence captured from the network
  using a `Zeek <https://www.zeek.org/>`_ dedicated module called
  ``passiverecon``, `p0f <https://lcamtuf.coredump.cx/p0f3/>`_ and
  `airodump-ng <https://www.aircrack-ng.org/>`_ logs. Each record
  represents one piece of information (*e.g.*, the HTTP ``Server:``
  header value ``Apache`` has been seen 10 times on port 80 of host
  1.2.3.4). It can be queried using:

   - Python API: the ``db.passive`` object from the ``ivre.db``
     module.
   - Command line: the ``ivre ipinfo`` and ``ivre iphost`` tools. The
     latter is dedicated to passive DNS queries.
   - Web (JSON) APIs: the ``/cgi/passive`` and ``/cgi/passivedns``
     URLs. The latter is dedicated to passive DNS and is compatible
     with the `Common Output Format
     <https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/>`_
     implemented for example in CIRCL's `PyPDNS
     <https://github.com/CIRCL/PyPDNS>`_.

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
      graph [rankdir=LR];

      "maxmind.com";
      "Nmap";
      "Masscan";
      "ivre auditdom";
      "Zgrab2";
      "Zdns";
      "Nuclei";
      "httpx";
      "dnsx";
      "Dismap";
      "airodump-ng";
      "p0f";
      "Zeek";
      "Zeek";
      "Argus";
      "Nfdump";

      XML [label="XML scan result"];
      JSON [label="JSON scan result"];
      CSV_LOG [label="airodump .csv files"];
      P0F_LOG [label="p0f output files"];
      PASS_LOG [label="passive_recon.log"];
      FLOW_LOG [label=".log files"];
      FLOWS [label="flow files"];

      db_data [label="db.data" shape="box" style="filled"];
      db_nmap [label="db.nmap" shape="box" style="filled"];
      db_passive [label="db.passive" shape="box" style="filled"];
      db_flow [label="db.flow" shape="box" style="filled"];
      db_view [label="db.view" shape="box" style="filled"];

      "maxmind.com" -> db_data [label="ivre\nipdata"];
      "Nmap" -> XML [label="-oX"];
      "Masscan" -> XML [label="-oX"];
      "ivre auditdom" -> XML;
      "ivre auditdom" -> JSON [label="--json"];
      "Zgrab2" -> JSON [label="-o"];
      "Zdns" -> JSON [label="-o"];
      "Nuclei" -> JSON [label="-json -o"];
      "httpx" -> JSON [label="-json -o"];
      "dnsx" -> JSON [label="-json -o"];
      "Dismap" -> JSON [label="-j"];
      "airodump-ng" -> CSV_LOG [label="-w"];
      "p0f" -> P0F_LOG [label="-o"];
      "Zeek" -> PASS_LOG [label="passiverecon"];
      "Zeek" -> FLOW_LOG;
      "Argus" -> FLOWS;
      "Nfdump" -> FLOWS;

      XML -> db_nmap [label="ivre\nscan2db"];
      JSON -> db_nmap [label="ivre\nscan2db"];
      CSV_LOG -> db_passive [label="ivre\nairodump2db"];
      P0F_LOG -> db_passive [label="ivre\np0f2db"];
      PASS_LOG -> db_passive [label="ivre\npassiverecon2db"];
      FLOW_LOG -> db_flow [label="ivre\nzeek2db"];
      FLOWS -> db_flow [label="ivre\nflow2db"];
      db_passive -> db_view [label="ivre\ndb2view"];
      db_nmap -> db_view [label="ivre\ndb2view"];

      {
        rank = same;
        edge[style=invis];
        "maxmind.com" -> "Nmap" -> "Masscan" -> "ivre auditdom" -> "Zgrab2" -> "Zdns" -> "Nuclei" -> "httpx" -> "dnsx" -> "Dismap" -> "airodump-ng" -> "p0f" -> "Zeek" -> "Zeek" -> "Argus" -> "Nfdump";
        rankdir = UD;
      }
   }

Accessing data
--------------

The following (also non-exhaustive) figures show how the data gets
from IVRE's databases back into your hands.

.. graphviz::

   digraph {
      db_data [label="db.data" shape="box" style="filled"];
      db_flow [label="db.flow" shape="box" style="filled"];
      db_nmap [label="db.nmap" shape="box" style="filled"];
      web_api_data [label="Web API\n/ipdata"];
      web_api_flows [label="Web API\n/flows"];
      web_api_scans [label="Web API\n/scans"];
      web_ui_flow [label="Web UI\n/flow.html"];
      cli_ipdata [label="CLI\nipdata"];
      cli_flow [label="CLI\nflowcli"];
      cli_scancli [label="CLI\nscancli"];
      db_data -> web_api_data;
      db_flow -> web_api_flows;
      db_flow -> cli_flow;
      db_nmap -> web_api_scans;
      web_api_flows -> web_ui_flow;
      db_data -> cli_ipdata;
      db_nmap -> cli_scancli;
  }

.. graphviz::

   digraph {
      db_passive [label="db.passive" shape="box" style="filled"];
      db_view [label="db.view" shape="box" style="filled"];
      web_api_passive [label="Web API\n/passive"];
      web_api_passivedns [label="Web API\n/passivedns"];
      web_api_view [label="Web API\n/view"];
      web_ui_view [label="Web UI /"];
      cli_ipinfo [label="CLI\nipinfo"];
      cli_iphost [label="CLI\niphost"];
      cli_view [label="CLI\nview"];
      db_view -> web_api_view;
      web_api_view -> web_ui_view;
      db_view -> cli_view;
      db_passive -> web_api_passive;
      db_passive -> web_api_passivedns;
      db_passive -> cli_ipinfo;
      db_passive -> cli_iphost;
  }
