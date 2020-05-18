Passive
=======

With Zeek
---------

You need to run `Zeek <https://www.zeek.org/>`_ (formerly known as
Bro), version 3.0 minimum (tested with 3.0 and 3.1) with the option
``-b`` and the location of the ``passiverecon/bare.zeek`` file. If you
want to run it on the ``eth0`` interface, for example, run (replace
``/usr/share/ivre`` by the appropriate location; use ``python -c
'import ivre.config; print(ivre.config.guess_prefix())'`` if you
cannot find it):

::

   $ mkdir logs
   $ sudo LOG_PATH=logs/passiverecon \
   >   zeek -b /usr/share/ivre/zeek/ivre/passiverecon/bare.zeek -C -i eth0

If you want to run it on the ``capture`` file (``capture`` needs to a
PCAP file), run:

::

   $ mkdir logs
   $ LOG_PATH=logs/passiverecon \
   >   zeek -b /usr/share/ivre/zeek/ivre/passiverecon/bare.zeek -r capture

This will produce log files in the ``logs`` directory. You need to run a
``ivre passivereconworker`` to process these files. You can try:

::

   $ ivre passivereconworker --directory=logs

This program will not stop by itself. You can ``kill`` it, it will
stop gently (as soon as it has finished to process the current file).

You can also send the data from ``zeek`` to the database without using
intermediate files:

::

   $ zeek -b /usr/share/ivre/zeek/ivre/passiverecon/bare.zeek [option] \
   >   | ivre passiverecon2db

Enjoying the results
--------------------

You have several options, depending on what you want to do:

- Command line interfaces (see also :ref:`overview/screenshots:Passive
  network analysis` in the screenshots gallery):

   - ``ivre ipinfo`` tool, for any passive data.

   - ``ivre iphost`` tool, for Passive DNS data (see
     :ref:`usage/use-cases:Your own Passive DNS service`).


- Python API: use the ``db.passive`` object of the ``ivre.db`` module.

- Web interface:

   - Using ``ivre db2view``, you can create or update a view with
     passive data, that can then be accessed by the ``view`` purpose
     (see :ref:`overview/principles:Purposes`), which includes the
     :ref:`usage/web-ui:Web User Interface`.

CLI
~~~

To show everything stored about an IP address or a network:

::

   $ ivre ipinfo 1.2.3.4
   $ ivre ipinfo 1.2.3.0/24

See the output of ``ivre help ipinfo`` and ``ivre help iphost``.

Python module
~~~~~~~~~~~~~

To use the Python module, run for example:

::

   $ python
   >>> from ivre.db import db
   >>> db.passive.get(db.passive.flt_empty)[0]

For more, run ``help(db.passive)`` from the Python shell.
