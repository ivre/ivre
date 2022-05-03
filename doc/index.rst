Welcome to IVRE's documentation!
================================

`IVRE <https://ivre.rocks/>`_ (French: *Instrument de veille sur les
réseaux extérieurs*) or DRUNK (Dynamic Recon of UNKnown networks) is
an open-source framework for network recon, written in Python. It
relies on powerful open-source tools to gather intelligence from the
network, actively or passively.

It aims at leveraging network captures and scans to let you understand
how a network works. It is useful for pentests & red-teaming, incident
response, monitoring, etc.

- Web site: `https://ivre.rocks/ <https://ivre.rocks/>`_
- Twitter: `@IvreRocks <https://twitter.com/IvreRocks>`_
- Github: `ivre/ivre <https://github.com/ivre/ivre/>`_

Features
--------

IVRE can aggregate scan results as well as intelligence from network
captures. It accepts results from several tools:

- Active recon (network scanners):

    - `Nmap <http://nmap.org/>`_

    - `Masscan <https://github.com/robertdavidgraham/masscan/>`_

    - `Dismap <https://github.com/zhzyker/dismap/>`_

    - Tools from the `ZMap project <https://zmap.io/>`_:

        - `Zgrab2 <https://github.com/zmap/zgrab2/>`_
        - `ZDNS <https://github.com/zmap/zdns/>`_

    - Tools from the `Project Discovery <https://projectdiscovery.io/>`_:

        - `Nuclei <https://github.com/projectdiscovery/nuclei/>`_
        - `Httpx <https://github.com/projectdiscovery/httpx/>`_
        - `Dnsx <https://github.com/projectdiscovery/dnsx/>`_

- Passive recon (from network traffic and/or captures):

    - `Zeek <https://www.zeek.org/>`_ (formerly known as Bro)
    - `p0f <https://lcamtuf.coredump.cx/p0f3/>`_
    - `airodump-ng <https://www.aircrack-ng.org/>`_
    - `Argus <http://qosient.com/argus/>`_
    - `Nfdump <http://nfdump.sourceforge.net/>`_

Use-cases
---------

IVRE can prove useful in several different scenarios (you may want to
have a look at the :ref:`overview/screenshots:screenshots gallery`). Here are
some examples:

- Create your own Shodan-like service, using Nmap and/or Masscan
  and/or Zmap / Zgrab / Zgrab2, against the whole Internet or your own
  networks, (private or not).

- Store each X509 certificate seen in SSL/TLS connections, SSH public
  keys and algorithms, DNS answers, HTTP headers (``Server``,
  ``Host``, ``User-Agent``, etc.), and more... This can be useful to:

   - Validate X509 certificates independently from the clients.
   - Monitor phishing domains (based on DNS answers, HTTP ``Host``
     headers, X509 certificates) hit from your corporate network.
   - Run your own, private (or not) `passive DNS
     <http://www.enyo.de/fw/software/dnslogger/first2005-paper.pdf>`_
     service.

Getting started
---------------

If you want to learn more about the different purposes of IVRE, you
should start reading the :ref:`overview/principles:principles`.

After that, you can start the :ref:`install/index:installation`
process.

Once you are ready, dive into the "Usage" section!

Contributing
------------

Code contributions (pull-requests) are of course welcome!

The project needs scan results and capture files that can be provided as
examples. If you can contribute some samples, or if you want to
contribute some samples and would need some help to do so, or if you can
provide a server to run scans, please contact the author.

Contact
-------

For both support and contribution, the `repository
<https://github.com/ivre/ivre>`__ on Github should be used: feel free
to create a new issue or a pull request!

You can also join the `Gitter conversation
<https://gitter.im/ivre/ivre>`_ (that is the preferred way to get in
touch for questions), or use the e-mail ``dev`` on the domain
``ivre.rocks``.

On Twitter, you can follow and/or mention `@IvreRocks
<https://twitter.com/IvreRocks>`__.

Content
-------

.. toctree::
   :maxdepth: 3
   :glob:

   overview/index.rst

.. toctree::
   :maxdepth: 3
   :glob:

   install/index.rst

.. toctree::
   :maxdepth: 3
   :glob:

   usage/index.rst

.. toctree::
   :maxdepth: 3
   :glob:

   dev/index.rst

.. toctree::
   :maxdepth: 1
   :caption: Licenses:
   :glob:

   license
   license-external

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
