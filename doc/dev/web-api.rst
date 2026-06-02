Web API
=======

.. note::

   The endpoints below are listed under their **application
   paths** -- the paths each route handler registers. At runtime
   ``ivre httpd`` mounts the application under the ``/cgi/``
   prefix (and the bundled Apache / NGINX configurations map the
   same prefix), so every route is served one level deeper than
   it appears here: ``/scans`` is reached at ``/cgi/scans``,
   ``/audit/`` at ``/cgi/audit/``, and so on. Prepend ``/cgi``
   to every path in this reference when calling the API.

.. autobottle:: ivre.web.app:application
  :endpoints:
  :include-empty-docstring:
