MCP server
##########

IVRE ships an `MCP <https://modelcontextprotocol.io/>`_ (Model Context
Protocol) server that exposes the database to LLM agents. It is
installed as the ``ivre mcp-server`` subcommand and communicates over
stdio, so it is meant to be launched by an MCP-capable client (Claude
Code, Claude Desktop, Cursor, OpenCode, ...).

Once wired up, the LLM can answer questions like:

- "How many hosts are running SSH?"
- "Show me the top 10 products on port 443 in Germany."
- "Find all hosts in 192.168.1.0/24 with open port 80."
- "What operating systems are most common in AS13335?"
- "List hosts affected by CVE-2021-44228."

The server requires a configured, populated IVRE instance; it reads
the regular ``ivre.conf`` like the rest of IVRE.

Installation
============

The server depends on the ``mcp`` Python package, which is declared as
an optional dependency. Install IVRE with the ``[mcp]`` extra::

    pip install 'ivre[mcp]'

The command can then be launched as::

    ivre mcp-server

Without a connected client, the process starts and waits for MCP
JSON-RPC messages on stdin/stdout. Stop it with ``Ctrl+C``.

Data purposes
=============

Every tool takes a ``purpose`` parameter that selects the data source:

=========== ==============================================================
Purpose     Description
=========== ==============================================================
``view``    Consolidated, deduplicated merge of ``nmap`` and ``passive``
``nmap``    Active scan results (Nmap, Masscan, etc.)
``passive`` Passively collected network traffic data
=========== ==============================================================

Default to ``view``. Use ``nmap`` or ``passive`` only when you need
source-specific data or a tool is not available under ``view``.

Tool reference
==============

Filter builders
---------------

Filters are opaque tokens. Build them with these tools and combine
them with ``flt_and`` / ``flt_or``.

================== ================================================
Tool               Filters by
================== ================================================
searchnet          Network (CIDR) or host address
searchhost         Exact host address
searchhostname     Hostname (exact or regex)
searchdomain       Domain name
searchport         Open port (TCP/UDP)
searchservice      Detected service name
searchproduct      Detected product name
searchdevicetype   Device type
searchcountry      Country code (ISO 3166-1 alpha-2)
searchasnum        Autonomous System number or name
searchos           Detected operating system
searchscript       Nmap script name or output
searchcve          CVE identifier (matches "Vulnerable" tag info)
searchcategory     Category
searchtag          Tag value (and optionally tag info)
searchrecontype    Passive reconnaissance type
searchsensor       Passive sensor name
================== ================================================

Filter combinators
------------------

=========== =====================================================
Tool        Description
=========== =====================================================
flt_and     Combine two filters with logical AND
flt_or      Combine two filters with logical OR
flt_empty   Return the empty filter (matches everything)
=========== =====================================================

Query tools
-----------

=================== ==================================================
Tool                Description
=================== ==================================================
count               Count matching records
get                 Retrieve matching records (paginated, sortable)
topvalues           Most frequent values of a field
distinct            Distinct values of a field
describe_schema     List available field paths for a given purpose
nmap_service_values Known Nmap service / product values (discovery)
=================== ==================================================

A resource at ``ivre://guides/scope-discovery`` is also exposed; the
server's top-level instructions point agents at it when they start
exploring a scope.

HTTP transport
==============

In addition to stdio, the server can be exposed over HTTP using the
Model Context Protocol *Streamable HTTP* transport. This is how
remote or shared MCP deployments are typically served.

Starting the HTTP transport
---------------------------

::

    ivre mcp-server --http \
                    --bind 127.0.0.1 \
                    --port 9100 \
                    --path /mcp

CLI flags:

===================== ========================================================
Flag                  Description
===================== ========================================================
``--http``            Switch from stdio to Streamable HTTP.
``--bind``            Bind address. Default ``127.0.0.1``.
``--port``            TCP port. Default ``9100``.
``--path``            HTTP path prefix for the MCP endpoint. Default ``/mcp``.
``--allow-anonymous`` Disable bearer-token auth. Required to bind a
                      non-loopback address when the IVRE Web auth
                      backend is not configured.
===================== ========================================================

Defaults can also be set from ``ivre.conf`` via ``MCP_HTTP_BIND``,
``MCP_HTTP_PORT``, ``MCP_HTTP_PATH`` and ``MCP_HTTP_ALLOW_ANONYMOUS``.

Authentication
--------------

The HTTP transport reuses the :doc:`web-auth` API-key infrastructure.
MCP clients authenticate with ``Authorization: Bearer <api-key>``;
the server verifies the token against ``db.auth.validate_api_key``
(the same code path used by the Web UI) and refuses unauthenticated
requests when ``WEB_AUTH_ENABLED`` is set.

Per-user access controls (``WEB_INIT_QUERIES``, ``WEB_DEFAULT_INIT_QUERY``,
group-based rules) are honoured for every MCP tool call: the
authenticated user is resolved from the bearer token and the resulting
init filter is AND-ed with any filter built by the client.

To create an API key, log in to the Web UI as the user, open
*Admin > API Keys* and click **Create**. Keep the key secret --
revoking it from the Web UI immediately invalidates MCP clients
carrying it.

Safety defaults
---------------

- When ``--bind`` is not a loopback address and authentication is not
  configured, ``ivre mcp-server --http`` refuses to start. Either
  bind to loopback, enable ``WEB_AUTH_ENABLED``, or pass
  ``--allow-anonymous`` to acknowledge the risk.
- Anonymous mode disables *all* access control. Use it only for
  single-user local development.

Reverse proxy (nginx)
---------------------

For production deployments, terminate TLS in nginx and reverse-proxy
to the MCP HTTP server. FastMCP registers the endpoint at exactly
``/mcp`` (no trailing slash), so use an exact-match location: a
prefix ``location /mcp/`` block would trigger nginx's automatic
trailing-slash 301 and Starlette's ``/mcp/`` -> ``/mcp`` redirect,
producing a loop, and a regex location is incompatible with a
``proxy_pass`` URI part. The Streamable-HTTP transport relies on
server-sent events, so disable response buffering and bump the read
timeout::

    location = /mcp {
        proxy_pass              http://127.0.0.1:9100/mcp;
        proxy_http_version      1.1;
        proxy_set_header        Host              $host;
        proxy_set_header        X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header        X-Forwarded-Proto $scheme;
        proxy_set_header        Authorization     $http_authorization;
        proxy_buffering         off;
        proxy_cache             off;
        proxy_read_timeout      1h;
        proxy_send_timeout      1h;
        chunked_transfer_encoding on;
    }

HTTP client configuration
-------------------------

Claude Desktop, Claude Code, Cursor, VS Code and Windsurf support
connecting to remote MCP servers. Example Claude Code snippet for
``~/.claude/settings.json`` or a project-level ``.mcp.json``::

    {
      "mcpServers": {
        "IVRE": {
          "type": "http",
          "url": "https://ivre.example.com/mcp",
          "headers": {
            "Authorization": "Bearer IVRE_API_KEY_HERE"
          }
        }
      }
    }

The exact JSON schema differs slightly between clients; consult the
client documentation for the precise key names.

Docker
------

The reference Docker deployment (see :doc:`../install/docker`) ships a
dedicated ``ivre/web-mcp`` image that runs ``ivre mcp-server --http``
on port 9100 inside the Compose network. The ``ivre/web`` nginx
container reverse-proxies it at ``/mcp``, so no extra configuration
is required to reach it from an MCP client at
``http(s)://<host>/mcp``.

The image starts with ``--allow-anonymous`` because the MCP port is
not published on the host. For any production use, enable the IVRE
Web auth backend (``WEB_AUTH_ENABLED = True`` in ``ivre.conf``),
create an API key from *Admin > API Keys* in the Web UI, and override
the ``ivremcp`` ``command:`` in ``docker-compose.yml`` to drop
``--allow-anonymous``.


Client setup
============

All snippets below assume ``ivre-mcp-server`` resolves to the console
script installed by the ``[mcp]`` extra. If it is installed in a
virtualenv that is not on the client's ``PATH``, use the absolute path
to the executable, or wrap the invocation in an activation script.

.. note::

   These snippets configure the ``ivre mcp-server`` subcommand. A
   convenience console-script entry for it is not installed; clients
   below all call ``ivre`` with ``mcp-server`` as the first argument.

OpenCode
--------

Add to your workspace ``opencode.json`` (or global
``~/.config/opencode/opencode.json``)::

    {
      "$schema": "https://opencode.ai/config.json",
      "mcp": {
        "ivre": {
          "type": "local",
          "command": ["ivre", "mcp-server"],
          "enabled": true
        }
      }
    }

Claude Code
-----------

Add to ``~/.claude/settings.json`` or to a project-level ``.mcp.json``::

    {
      "mcpServers": {
        "IVRE": {
          "command": "ivre",
          "args": ["mcp-server"]
        }
      }
    }

Claude Desktop
--------------

Add to ``claude_desktop_config.json`` (accessible via
*Settings > Developer > Edit Config*)::

    {
      "mcpServers": {
        "IVRE": {
          "command": "ivre",
          "args": ["mcp-server"]
        }
      }
    }

Cursor
------

Go to *Settings > Tools & Integrations > New MCP Server*, select
"command" type, and enter ``ivre mcp-server``. Alternatively, add to
``~/.cursor/mcp.json``::

    {
      "mcpServers": {
        "IVRE": {
          "command": "ivre",
          "args": ["mcp-server"]
        }
      }
    }

VS Code (GitHub Copilot)
------------------------

Requires the GitHub Copilot Chat extension. Add to your workspace
``.vscode/mcp.json``::

    {
      "servers": {
        "IVRE": {
          "type": "stdio",
          "command": "ivre",
          "args": ["mcp-server"]
        }
      }
    }

Windsurf
--------

Add to ``~/.codeium/windsurf/mcp_config.json``::

    {
      "mcpServers": {
        "IVRE": {
          "command": "ivre",
          "args": ["mcp-server"]
        }
      }
    }

JetBrains IDEs
--------------

Requires IntelliJ IDEA 2025.1+ (or equivalent). Go to
*Settings > Tools > AI Assistant > MCP Servers*, click **+**, and add::

    {
      "mcpServers": {
        "IVRE": {
          "command": "ivre",
          "args": ["mcp-server"]
        }
      }
    }

Extending the server
====================

Third parties can add tools and resources via entry points in the
``ivre.plugins.mcp_server`` group. See :ref:`dev/mcp-plugins:MCP
server plugins` for the plugin author guide.
