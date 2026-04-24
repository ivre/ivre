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
