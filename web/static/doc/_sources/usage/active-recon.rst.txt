Active recon
============

Scanning
--------

With Nmap, Masscan or Zgrab2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can use network scanners directly:

- `Nmap <http://nmap.org/>`_
- `Masscan <https://github.com/robertdavidgraham/masscan/>`_
- `Zgrab2 <https://zmap.io/>`_ (``http`` and ``jarm`` commands)
- `ZDNS <https://github.com/zmap/zdns>`_
- `Nuclei <https://github.com/projectdiscovery/nuclei>`_
- `httpx <https://github.com/projectdiscovery/httpx>`_

IVRE can insert XML output files for Nmap and Masscan, and JSON output
files for Zgrab2, ZDNS, Nuclei and httpx, using the command line tool
``ivre scan2db``.

You can insert scan results from different tools, then use ``ivre
db2view nmap`` to merge results from different scans and create a view
you can explore with the the :ref:`usage/web-ui:Web User Interface`,
the ``ivre view`` command line tool or the Python API
(``ivre.db.db.view.*``).

With IVRE
~~~~~~~~~

Masscan does not provide results as complete as Nmap, when using the
"interesting" options (for example, ``-vv -A``) or scripts. That being
said, Nmap (with such "interesting" options) cannot run efficiently
against huge networks.

The ``ivre runscans`` tool can run one Nmap process per target (option
``--output=XMLFork``). This should be less efficient in theory,
because Nmap supposedly knows better how to handle the host and
network resources, but in practice it is much more efficient. You can
adjust how many Nmap processes you want to run in parallel using the
``--processes N`` option.

Another advantage of using ``ivre runscans --output=XMLFork`` over
using Nmap directly is that ``ivre runscans`` produces output files as
soon as each host has been scanned (in the ``scans/*/up`` directory).

Here is a simple example:

::

   $ sudo ivre runscans --routable --limit 1000 --output=XMLFork

This will run a standard scan against 1000 random hosts on the Internet
by running 30 nmap processes in parallel. See the output of
``ivre help runscans`` if you want to do something else.

When it's over, to import the results in the database and create a
view from them, run (``ROUTABLE-001`` is the category name, and
``MySource`` is the source name, usually referencing the machine used
to run the scan):

::

   $ ivre scan2db -c ROUTABLE-001 -s MySource -r scans/ROUTABLE/up
   $ ivre db2view nmap

Enjoying the results
--------------------

You have several options, depending on what you want to do:

- Command line interfaces: the ``ivre scancli`` tool.

- Python API: use the ``db.nmap`` object of the ``ivre.db`` module.

- Web API: ``/cgi/scans``.

If you want to combine several tools, for example Masscan and Nuclei
results, you need to use a view: run ``ivre db2view nmap`` to create
or update a view from the scan data, that can then be accessed by the
``view`` purpose (see :ref:`overview/principles:Purposes`), which
includes the :ref:`usage/web-ui:Web User Interface`.

CLI
~~~

To get all the hosts with the port 22 open:

::

   $ ivre scancli --port 22

See the output of ``ivre help scancli``.

Python module
~~~~~~~~~~~~~

To use the Python module, run for example:

::

   $ python
   >>> from ivre.db import db
   >>> db.nmap.get(db.nmap.flt_empty)[0]

For more, run ``help(db.nmap)`` from the Python shell.
