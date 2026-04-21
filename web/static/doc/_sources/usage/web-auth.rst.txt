Web Authentication
==================

IVRE supports optional built-in authentication for its web
interface. When enabled, users must sign in before accessing scan
results. Authentication is disabled by default.

Quick Start
~~~~~~~~~~~

1. Add to your ``ivre.conf``::

     WEB_AUTH_ENABLED = True
     WEB_SECRET = "generate-with: openssl rand -base64 42"

2. Initialize the auth database::

     $ ivre authcli init

3. Configure at least one authentication provider (see below).

4. Create the first admin user::

     $ ivre authcli add-user --admin your@email.com

   Or set ``WEB_AUTH_REGISTRATION = "open"`` to let the first user
   sign in and then promote them::

     $ ivre authcli set-admin your@email.com

Configuration Reference
~~~~~~~~~~~~~~~~~~~~~~~

All settings go in your ``ivre.conf`` file (``/etc/ivre.conf`` or
``~/.ivre.conf``).

General
-------

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Setting
     - Default
     - Description
   * - ``WEB_AUTH_ENABLED``
     - ``False``
     - Enable built-in authentication
   * - ``WEB_SECRET``
     - ``None``
     - Random secret for signing cookies and tokens. **Mandatory**
       when auth is enabled — IVRE will refuse to start without it.
       Generate with ``openssl rand -base64 42``
   * - ``WEB_AUTH_REGISTRATION``
     - ``"closed"``
     - Registration policy (see below)
   * - ``WEB_AUTH_SESSION_LIFETIME``
     - ``604800``
     - Session duration in seconds (default: 7 days)
   * - ``WEB_AUTH_BASE_URL``
     - ``None``
     - Base URL for callbacks (auto-detected if ``None``)

Registration Policy
-------------------

``WEB_AUTH_REGISTRATION`` controls who can create an account:

- ``"open"`` -- anyone can sign in and get an active account
- ``"domain:example.com,corp.net"`` -- only users with email
  addresses in the listed domains can register
- ``"closed"`` (default) -- users must be created by an admin
  (via ``ivre authcli add-user`` or the admin panel)

When a user signs in with a provider but is not yet in the
database:

- If registration is allowed, an account is created (active for
  ``"open"`` or ``"domain:..."``, pending for ``"closed"``)
- If registration is closed, access is denied

Providers
~~~~~~~~~

You can enable multiple providers simultaneously. Users see a
button for each enabled provider on the login page.

GitHub
------

1. Go to https://github.com/settings/developers
2. Click **New OAuth App**
3. Fill in:

   - **Application name**: e.g., "IVRE"
   - **Homepage URL**: your instance URL (e.g.,
     ``https://ivre.example.com``)
   - **Authorization callback URL**:
     ``https://ivre.example.com/cgi/auth/callback/github``

4. Click **Register application**
5. Copy the **Client ID**
6. Click **Generate a new client secret** and copy it

Add to ``ivre.conf``::

  WEB_AUTH_GITHUB_CLIENT_ID = "Iv1.xxxxxxxxxx"
  WEB_AUTH_GITHUB_CLIENT_SECRET = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

Google
------

1. Go to https://console.cloud.google.com/apis/credentials
2. Create a project if you don't have one
3. Click **Create Credentials** > **OAuth client ID**
4. Select **Web application**
5. Under **Authorized redirect URIs**, add:
   ``https://ivre.example.com/cgi/auth/callback/google``
6. Click **Create**
7. Copy the **Client ID** and **Client secret**

You may also need to configure the **OAuth consent screen**
(under APIs & Services > OAuth consent screen):

- Choose **External** or **Internal** depending on your needs
- Add the ``email``, ``profile``, and ``openid`` scopes

Add to ``ivre.conf``::

  WEB_AUTH_GOOGLE_CLIENT_ID = "xxxxxxxxxxxx-xxx.apps.googleusercontent.com"
  WEB_AUTH_GOOGLE_CLIENT_SECRET = "GOCSPX-xxxxxxxxxxxxxxxxxxxxxxxx"

Microsoft (Azure AD / Entra ID)
-------------------------------

1. Go to the `Azure portal App registrations
   <https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade>`_
2. Click **New registration**
3. Fill in:

   - **Name**: e.g., "IVRE"
   - **Supported account types**: choose based on your needs:

     - **Single tenant**: only your organization
     - **Multitenant**: any Azure AD organization
     - **Multitenant + personal accounts**: broadest access

   - **Redirect URI**: select **Web** and enter
     ``https://ivre.example.com/cgi/auth/callback/microsoft``

4. Click **Register**
5. Copy the **Application (client) ID**
6. Go to **Certificates & secrets** > **New client secret**
7. Copy the secret **Value** (not the Secret ID)

Add to ``ivre.conf``::

  WEB_AUTH_MICROSOFT_CLIENT_ID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  WEB_AUTH_MICROSOFT_CLIENT_SECRET = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

For single-tenant setups, also set the tenant ID::

  WEB_AUTH_MICROSOFT_TENANT = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

The default is ``"common"`` which allows any Microsoft account.

Generic OIDC
-------------

Works with any OpenID Connect provider: Keycloak, Authentik,
Authelia, Dex, Okta, etc.

There are two configuration modes:

**Discovery mode** (recommended): provide the OIDC discovery URL
and IVRE will auto-discover the endpoints::

  WEB_AUTH_OIDC_CLIENT_ID = "ivre"
  WEB_AUTH_OIDC_CLIENT_SECRET = "your-client-secret"
  WEB_AUTH_OIDC_DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration"

**Manual mode**: provide each endpoint explicitly::

  WEB_AUTH_OIDC_CLIENT_ID = "ivre"
  WEB_AUTH_OIDC_CLIENT_SECRET = "your-client-secret"
  WEB_AUTH_OIDC_AUTHORIZE_URL = "https://idp.example.com/auth"
  WEB_AUTH_OIDC_TOKEN_URL = "https://idp.example.com/token"
  WEB_AUTH_OIDC_USERINFO_URL = "https://idp.example.com/userinfo"

The redirect URI to configure in your IdP is:
``https://ivre.example.com/cgi/auth/callback/oidc``

.. list-table::
   :header-rows: 1
   :widths: 30 25 45

   * - Setting
     - Default
     - Description
   * - ``WEB_AUTH_OIDC_SCOPES``
     - ``"openid email profile"``
     - OAuth2 scopes to request
   * - ``WEB_AUTH_OIDC_LABEL``
     - ``"SSO"``
     - Button label on the login page (shown as "Sign in with
       {label}")

Keycloak example
^^^^^^^^^^^^^^^^

::

  WEB_AUTH_OIDC_CLIENT_ID = "ivre"
  WEB_AUTH_OIDC_CLIENT_SECRET = "your-keycloak-secret"
  WEB_AUTH_OIDC_DISCOVERY_URL = "https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration"
  WEB_AUTH_OIDC_LABEL = "Keycloak"

Authentik example
^^^^^^^^^^^^^^^^^

::

  WEB_AUTH_OIDC_CLIENT_ID = "ivre"
  WEB_AUTH_OIDC_CLIENT_SECRET = "your-authentik-secret"
  WEB_AUTH_OIDC_DISCOVERY_URL = "https://authentik.example.com/application/o/ivre/.well-known/openid-configuration"
  WEB_AUTH_OIDC_LABEL = "Authentik"

Email (Magic Link)
------------------

Users receive a login link by email. No password is stored.

1. You need an SMTP server for sending emails
2. Add to ``ivre.conf``::

     WEB_AUTH_MAGIC_LINK_ENABLED = True
     WEB_AUTH_SMTP_HOST = "smtp.example.com"
     WEB_AUTH_SMTP_PORT = 587
     WEB_AUTH_SMTP_USER = "noreply@example.com"
     WEB_AUTH_SMTP_PASSWORD = "smtp-password"
     WEB_AUTH_SMTP_FROM = "noreply@example.com"
     WEB_AUTH_SMTP_USE_TLS = True

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Setting
     - Default
     - Description
   * - ``WEB_AUTH_MAGIC_LINK_ENABLED``
     - ``False``
     - Enable magic link authentication
   * - ``WEB_AUTH_SMTP_HOST``
     - ``"localhost"``
     - SMTP server hostname
   * - ``WEB_AUTH_SMTP_PORT``
     - ``587``
     - SMTP server port
   * - ``WEB_AUTH_SMTP_USER``
     - ``None``
     - SMTP username (skip auth if ``None``)
   * - ``WEB_AUTH_SMTP_PASSWORD``
     - ``None``
     - SMTP password
   * - ``WEB_AUTH_SMTP_FROM``
     - ``"noreply@example.com"``
     - From address
   * - ``WEB_AUTH_SMTP_USE_TLS``
     - ``True``
     - Use STARTTLS
   * - ``WEB_AUTH_MAGIC_LINK_LIFETIME``
     - ``900``
     - Link validity in seconds (default: 15 min)
   * - ``WEB_AUTH_MAGIC_LINK_RATE_PER_EMAIL``
     - ``3``
     - Maximum magic link emails per address per time window
       (window = ``WEB_AUTH_MAGIC_LINK_LIFETIME``)
   * - ``WEB_AUTH_MAGIC_LINK_RATE_PER_IP``
     - ``10``
     - Maximum magic link emails per source IP per time window.
       IPv6 addresses are grouped by /48 (see
       :ref:`reverse-proxy-setup`)

.. _reverse-proxy-setup:

Reverse Proxy Setup
~~~~~~~~~~~~~~~~~~~

When IVRE is deployed behind a reverse proxy (nginx, Cloudflare,
HAProxy, etc.), the rate limiter and logging see the **proxy's IP
address** instead of the real client IP. This makes the per-IP
rate limit ineffective (all clients share one counter) and can
also affect logging.

To fix this, configure your reverse proxy to pass the real client
IP as the ``REMOTE_ADDR`` WSGI variable. This is **not** done by
reading ``X-Forwarded-For`` at the application level — it must be
handled by the proxy and WSGI server.

nginx + uwsgi
--------------

In your nginx configuration::

  # Trust the real client IP (adjust the set_real_ip_from
  # directive to match your proxy's address or range)
  set_real_ip_from 127.0.0.1;       # local uwsgi
  set_real_ip_from 172.16.0.0/12;   # Docker network
  set_real_ip_from 10.0.0.0/8;      # private range
  # set_real_ip_from 173.245.48.0/20;  # Cloudflare (see their IP list)
  real_ip_header X-Forwarded-For;
  real_ip_recursive on;

nginx passes ``REMOTE_ADDR`` to uwsgi automatically via the
``uwsgi_params`` file.

Cloudflare
----------

Cloudflare sends the real client IP in the ``CF-Connecting-IP``
header. Use it as the ``real_ip_header``::

  set_real_ip_from 173.245.48.0/20;
  set_real_ip_from 103.21.244.0/22;
  # ... (see https://www.cloudflare.com/ips/ for the full list)
  real_ip_header CF-Connecting-IP;

.. note::

   Without proper ``REMOTE_ADDR`` propagation, the per-IP magic
   link rate limit groups all clients under the proxy's address.
   The per-email rate limit still works correctly regardless of
   proxy configuration.

Web Server Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~

Instead of (or in addition to) using IVRE's built-in providers,
authentication can be handled entirely by the web server (Apache,
nginx, etc.). This is the recommended approach for protocols that
web servers already support natively, such as:

- HTTP Basic / Digest authentication
- LDAP / Active Directory (e.g., Apache ``mod_authnz_ldap``,
  nginx ``ngx_http_auth_ldap_module``)
- Kerberos / SPNEGO (e.g., Apache ``mod_auth_gssapi``)
- SAML (e.g., Apache ``mod_auth_mellon``)
- Client certificates

How it works
------------

When the web server authenticates a user, it sets the
``REMOTE_USER`` environment variable (or CGI/WSGI parameter) to
the authenticated username. IVRE reads this value and uses it as
the user's identity.

Without built-in auth
---------------------

When ``WEB_AUTH_ENABLED`` is ``False`` (the default), IVRE
simply reads ``REMOTE_USER`` from the WSGI environment. No IVRE
configuration is needed beyond the web server setup itself. The
value of ``REMOTE_USER`` is used directly in
``WEB_INIT_QUERIES`` lookups to apply per-user or per-domain
access control.

With built-in auth
------------------

When ``WEB_AUTH_ENABLED`` is ``True``, ``REMOTE_USER`` is
checked after session cookies and API keys. IVRE will
automatically create a user record in the auth database if one
does not exist yet. The user is immediately active (no admin
approval needed), which enables hybrid setups where some users
authenticate via the web server and others use the built-in
providers.

Authentication priority when ``WEB_AUTH_ENABLED`` is ``True``:

1. Session cookie (from built-in login)
2. API key (``X-API-Key`` or ``Authorization: Bearer`` header)
3. ``REMOTE_USER`` (web server)

API Keys
~~~~~~~~

Authenticated users can create API keys for programmatic access.
API keys provide the same identity and permissions as the user
who created them.

Via the Web UI
--------------

Click your name in the navbar > **API Keys** > **New key**.

The key is shown once. Store it securely.

Via the CLI
-----------

::

  $ ivre authcli create-api-key user@example.com "my-script"

Usage
-----

::

  # With X-API-Key header
  $ curl -H "X-API-Key: ivre_xxxxxxxxxxxx" https://ivre.example.com/cgi/view

  # With Authorization header
  $ curl -H "Authorization: Bearer ivre_xxxxxxxxxxxx" https://ivre.example.com/cgi/view

Groups and Access Control
~~~~~~~~~~~~~~~~~~~~~~~~~

Users can be assigned to groups. Groups control what data a user
can access via ``WEB_INIT_QUERIES``.

Assigning Groups
----------------

Via CLI::

  $ ivre authcli add-group user@example.com analysts

Via the admin panel: click **+ Group** next to a user.

Group-Based Filters
-------------------

In ``ivre.conf``, use the ``group:`` prefix in
``WEB_INIT_QUERIES``::

  WEB_INIT_QUERIES = {
      "admin@example.com": "full",
      "group:analysts": "category:production",
      "group:interns": "category:training",
      "@example.com": "category:shared",
  }

Lookup order:

1. Exact email match
2. ``@domain`` match
3. ``group:name`` match (first matching group wins)
4. ``WEB_DEFAULT_INIT_QUERY`` fallback

Admin Panel
~~~~~~~~~~~

Admins can manage users at
``https://ivre.example.com/admin.html``:

- Activate / deactivate users
- Grant / revoke admin privileges
- Add / remove group memberships
- Create new user accounts

CLI Reference
~~~~~~~~~~~~~

::

  $ ivre authcli init                          # Initialize auth database
  $ ivre authcli add-user [--admin] EMAIL      # Create a user
  $ ivre authcli del-user EMAIL                # Delete a user
  $ ivre authcli activate-user EMAIL           # Activate a pending user
  $ ivre authcli deactivate-user EMAIL         # Deactivate a user
  $ ivre authcli set-admin EMAIL               # Grant admin
  $ ivre authcli unset-admin EMAIL             # Revoke admin
  $ ivre authcli add-group EMAIL GROUP         # Add user to group
  $ ivre authcli del-group EMAIL GROUP         # Remove user from group
  $ ivre authcli list-users                    # List all users
  $ ivre authcli create-api-key EMAIL NAME     # Create an API key

Example Configuration
~~~~~~~~~~~~~~~~~~~~~

::

  # Authentication
  WEB_AUTH_ENABLED = True
  WEB_SECRET = "your-random-secret-here"
  WEB_AUTH_REGISTRATION = "domain:example.com"

  # Providers
  WEB_AUTH_GITHUB_CLIENT_ID = "..."
  WEB_AUTH_GITHUB_CLIENT_SECRET = "..."
  WEB_AUTH_GOOGLE_CLIENT_ID = "..."
  WEB_AUTH_GOOGLE_CLIENT_SECRET = "..."
  WEB_AUTH_OIDC_CLIENT_ID = "ivre"
  WEB_AUTH_OIDC_CLIENT_SECRET = "..."
  WEB_AUTH_OIDC_DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration"
  WEB_AUTH_OIDC_LABEL = "Company SSO"

  # Magic link
  WEB_AUTH_MAGIC_LINK_ENABLED = True
  WEB_AUTH_SMTP_HOST = "smtp.example.com"
  WEB_AUTH_SMTP_PORT = 587
  WEB_AUTH_SMTP_USER = "noreply@example.com"
  WEB_AUTH_SMTP_PASSWORD = "..."
  WEB_AUTH_SMTP_FROM = "IVRE <noreply@example.com>"

  # Access control
  WEB_INIT_QUERIES = {
      "group:admins": "full",
      "group:analysts": "category:production",
  }
  WEB_DEFAULT_INIT_QUERY = "noaccess"
