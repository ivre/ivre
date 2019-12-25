Configuration
=============

IVRE has several configuration variables. The default values are
hard-coded in ``ivre/config.py``. You should not change this file,
unless you are modifying IVRE and you want to change the default
configuration. You do not need to do this if you want to install IVRE
with a non-default configuration, you just need to distribute a proper
configuration file.

IVRE can be configured using different configuration files:

- system-wide: ``ivre.conf`` in the following directories: ``/etc/``,
  ``/etc/ivre``, ``/usr/local/etc``, ``/usr/local/etc/ivre``.

- user-specific: ``~/.ivre.conf`` (read after the system-wide
  configuration files, so higher priority).

- execution-specific: another configuration file can be specified
  using the ``$IVRE_CONF`` environment variable (read after the
  user-specific file, so highest priority).

The configuration files are Python files setting global variables.

Debug
-----

Debug messages are turned off by default, since IVRE has no
bugs. ``DEBUG_DB`` turns on database-specific debug messages, and can
be very noisy. Setting ``DEBUG`` to ``True`` is mandatory to run
IVRE's tests.

Databases
---------

Databases are specified using URLs:

::

   db_type://[username[:password]@][host[:port]]/databasename?options

``DB`` is the generic database URL (will be used for all
:ref:`overview/principles:purposes` unless a purpose-specific URL has
been specified). The value ``"mongodb:///ivre"`` is the default and
means "use MongoDB on localhost, database ``ivre``, default collection
names".

Purpose-specific URLs can be specified using
``DB_<purpose>``; ``DB_DATA`` is specific and defaults to ``None``,
which has the special meaning
``"maxmind:///<ivre_share_path>/geoip"``.

Here are some examples:

.. code:: python

   DB_PASSIVE = "sqlite:////tmp/ivre.db"
   DB_NMAP = "postgresql://ivre@localhost/ivre"
   DB_VIEW = "elastic://192.168.0.1:9200/ivre"
   DB_FLOW = "neo4j://neo4j:neo4j@localhost:7474/db/data/"
   DB_DATA = "maxmind:///share/data/ivre/geoip"

Batch insert or upsert operations can be tuned using backend-specific variables:

.. literalinclude:: ../../ivre/config.py
   :start-after: Begin batch sizes
   :end-before: End batch sizes

Paths and commands
------------------

All variables ending with ``_PATH`` (except ``AGENT_MASTER_PATH`` and
``NMAP_SHARE_PATH``) default to ``None``, a special value which means
"try to guess the path based on IVRE installation".

Here are the values with examples on a regular installation:

.. code:: python

   DATA_PATH = None                  # /usr/share/ivre/data
   GEOIP_PATH = None                 # /usr/share/ivre/geoip
   HONEYD_IVRE_SCRIPTS_PATH = None   # /usr/share/ivre/data/honeyd
   WEB_STATIC_PATH = None            # /usr/share/ivre/web/static
   WEB_DOKU_PATH = None              # /usr/share/ivre/dokuwiki

``AGENT_MASTER_PATH`` defaults to ``"/var/lib/ivre/master"``.

``NMAP_SHARE_PATH`` defaults to ``None``, which means IVRE will try
``"/usr/local/share/nmap"``, ``"/opt/nmap/share/nmap"``, then
``"/usr/share/nmap"``.

IVRE may need some executables:

.. literalinclude:: ../../ivre/config.py
   :start-after: Begin commands
   :end-before: End commands

Nmap scan templates
-------------------

Nmap scan templates are defined in the ``NMAP_SCAN_TEMPLATES``
variable. Usually, this variable should **not** be overridden, but
rather modified.

By default, ``NMAP_SCAN_TEMPLATES`` contains one template, named
``"default"``, which is defined as follows:

.. literalinclude:: ../../ivre/config.py
   :start-after: Begin default Nmap scan template
   :end-before: End default Nmap scan template

To create another template, the easiest is to copy, either using
``.copy()`` or using the ``dict()`` constructor, the ``"default"``
template; the following configuration entry creates an
``"aggressive"`` template that will run more scripts (including
potentially dangerous ones) and have more permissive timeout values:

.. code:: python

   NMAP_SCAN_TEMPLATES["aggressive"] = dict(
       NMAP_SCAN_TEMPLATES["default"],
       host_timeout="30m",
       script_timeout="5m",
       scripts_categories=['default', 'discovery', 'auth', 'brute',
                           'exploit', 'intrusive'],
       scripts_exclude=['broadcast', 'external'],
   )

It is possible to check the options a template will use by running the
following command (the output has been modified, the command line is
normally on one single line):

::

   $ ivre runscans --output CommandLine
   Command line to run a scan with template default
       nmap -A -PS -PE -sS -vv --host-timeout 15m --script-timeout 2m
            --script '(default or discovery or auth) and not (broadcast
            or brute or dos or exploit or external or fuzzer or intrusive)'

   $ ivre runscans --output CommandLine --nmap-template aggressive
   Command line to run a scan with template aggressive
       nmap -A -PS -PE -sS -vv --host-timeout 30m --script-timeout 5m
            --script '(default or discovery or auth or brute or exploit or
            intrusive) and not (broadcast or external)'

The ``flow`` purpose
--------------------

The ``flow`` purpose has several specific configuration options, which
may have important impacts on performances; here are the options and
their default values:

.. literalinclude:: ../../ivre/config.py
   :start-after: Begin flows
   :end-before: End flows

The ``data`` purpose
--------------------

The URLs used to get IP address databases are set in the dictionary ``IPDATA_URLS``:

.. literalinclude:: ../../ivre/config.py
   :start-after: Begin IPDATA_URLS
   :end-before: End IPDATA_URLS

GeoIP uses a locale to report country, region and city names. The
locale to use is set in ``GEOIP_LANG`` and defaults to ``"en"``.

Web server
----------

Paths
~~~~~

Two variables (``WEB_STATIC_PATH`` and ``WEB_DOKU_PATH``) are used for
the Web application; see :ref:`install/config:Paths and commands`.

Notepad
~~~~~~~

If Dokuwiki (or another web application for notes) is used, the
variable ``WEB_NOTES_BASE`` should be set to the URL path to access
the notes (``#IP#`` will be replaced with the IP address). This
variable defaults to ``/dokuwiki/#IP#``.

If you use Dokuwiki, you also want to set:

.. code:: python

   WEB_GET_NOTEPAD_PAGES = "localdokuwiki"

Or:

.. code:: python

   WEB_GET_NOTEPAD_PAGES = ("localdokuwiki", ("/path/to/dokuwiki/data/pages",))

The second option is needed if the path to Dokuwiki pages is different
from the default ``"/var/lib/dokuwiki/data/pages"``.

If you use Mediawiki, you need to set

.. code:: python

   WEB_GET_NOTEPAD_PAGES = ("mediawiki", ("server", "username", "password",
                                          "dbname", "base"))

Anti-CSRF
~~~~~~~~~

As an anti-CSRF option, IVRE will check the ``Referer:`` header of the
requests to any dynamic URLs (under ``/cgi/``). Normally (when ``ivre
httpd`` is used or when the WSGI application is exposed directly, IVRE
will figure out the allowed referrer URLs alone; under certain
circumstances however (e.g., when a reverse-proxy is used, or when the
IVRE dynamic URLs are used by another Web application), this is not
possible. In this case, the variable ``WEB_ALLOWED_REFERERS`` should
be set to a list or URLs that are allowed to trigger Web accesses to
the IVRE application; for example:

.. code:: python

   WEB_ALLOWED_REFERERS = [
       'http://reverse-proxy.local/ivre',
       'http://reverse-proxy.local/ivre/',
       'http://reverse-proxy.local/ivre/index.html',
       'http://reverse-proxy.local/ivre/report.html',
       'http://reverse-proxy.local/ivre/upload.html',
       'http://reverse-proxy.local/ivre/compare.html',
       'http://reverse-proxy.local/ivre/flow.html'
   ]

Authentication and ACLs
~~~~~~~~~~~~~~~~~~~~~~~
   
If you want to use an authentication in IVRE, you have to configure
your Web server (e.g., Apache or Nginx) to do so and set the
environment variable ``REMOTE_USER`` to the username.

If you want to do some authorization based on the authentication, you
can do so by setting a couple of variables; by default, ACL is
disabled, and everyone (that can access the ``/cgi/`` URLs) can access
to all the results:

.. code:: python

   WEB_DEFAULT_INIT_QUERY = None
   WEB_INIT_QUERIES = {}

In the following, we call and "access filter" either the special value
``None`` which means "unrestricted", or a string describing a filter
to apply before performing any query. The strings can be:

- "full": unrestricted.

- "noaccess": no result will be returned to the user.

- "category:[category name]": the user will only have access to
  results within ``[category name]`` category.

- "source:[source name]": the user will only have access to results
  within ``[source name]`` source.

``WEB_DEFAULT_INIT_QUERY`` should be set to an "access filter" that
will apply when the current user does not match any user in
``WEB_INIT_QUERIES``.

Here is a simple example, where user ``admin`` has full access, user
``admin-site-a`` has access to all results in category ``site-a``, and
user ``admin-scanner-a`` has access to all results with source
``scanner-a``:

.. code:: python

   WEB_DEFAULT_INIT_QUERY = 'noaccess'
   WEB_INIT_QUERIES = {
       'admin': 'full',
       'admin-site-a': 'category:site-a',
       'admin-scanner-a': 'source:scanner-a',
   }

If you user Kerberos authentication (or if you have ``@`` in your
usernames that provide some kind of "realms", you can use them; in the
following example, any user in the ``admin.sitea`` realm has access to
all results in category ``site-a``:

.. code:: python

   WEB_DEFAULT_INIT_QUERY = 'noaccess'
   WEB_INIT_QUERIES = {
       '@admin.sitea': 'category:site-a',
   }
   
Misc
----

IVRE handles DNS blacklist (as defined in the `RFC 5782
<https://tools.ietf.org/html/rfc5782>`_) answers, for domains listed
in the set ``DNS_BLACKLIST_DOMAINS``. By default, it is defined as:

.. literalinclude:: ../../ivre/config.py
   :start-after: Begin DNSBL
   :end-before: End DNSBL

To add a domain, just add in your configuration file:

.. code:: python

   DNS_BLACKLIST_DOMAIN.add("dnsbl.example.com")

Or, to add several entries at once:

.. code:: python

   DNS_BLACKLIST_DOMAIN.update([
       "dnsbl1.example.com",
       "dnsbl2.example.com",
   ])
