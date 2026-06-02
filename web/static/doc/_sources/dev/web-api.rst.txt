Web API
=======

.. note::

   The endpoints below are listed under their **application
   paths** -- the paths each route handler registers. At runtime
   the application is served under a deployment-specific mount
   prefix, so every route is reached one level deeper than it
   appears here. ``ivre httpd`` and the bundled NGINX example use
   ``/cgi/`` (``/scans`` is reached at ``/cgi/scans``, ``/audit/``
   at ``/cgi/audit/``, and so on); the bundled Apache example
   instead mounts the application at ``/ivre/cgi``. Prepend your
   deployment's prefix to every path in this reference when
   calling the API.

.. autobottle:: ivre.web.app:application
  :endpoints:
  :include-empty-docstring:
