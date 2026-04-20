MCP server plugins
##################

This page documents how to register additional tools and resources on
the ``ivre mcp-server`` (see :ref:`usage/mcp-server:MCP server`)
without modifying IVRE itself. The plugin hook uses IVRE's standard
entry-point conventions (see :mod:`ivre.plugins`).

Entry point
===========

Plugins register themselves under the
``ivre.plugins.mcp_server`` entry-point group. The entry-point name
**must** start with ``_install_`` (this is the convention enforced by
:func:`ivre.plugins.load_plugins`).

Example ``pyproject.toml`` snippet from the plugin distribution::

    [project.entry-points."ivre.plugins.mcp_server"]
    _install_myplugin = "mypkg.mcp:install"

The function referenced by the entry point is called with a single
argument, the ``scope`` dictionary, which is the module globals of
``ivre.tools.mcp_server``. The useful entries in ``scope`` are:

- ``scope["mcp"]`` -- the
  :class:`mcp.server.fastmcp.FastMCP` instance the tool is running. Use
  its ``@mcp.tool()`` / ``@mcp.resource(...)`` decorators to register
  tools and resources.
- ``scope["seal"]`` -- callable ``(dict | list) -> str`` that turns an
  IVRE filter (as produced by ``HTTP_DB[purpose].searchX(...)``) into
  the opaque token the MCP client exchanges with the server. Every
  filter-building tool **must** return ``seal(...)``.
- ``scope["HTTP_DB"]`` -- ``dict[str, ivre.db.http.HttpDB*]`` used only
  to build filters; keyed by ``"nmap"``, ``"passive"``, ``"view"``.
- ``scope["REAL_DB"]`` -- ``dict[str, ivre.db.DB*]`` used to execute
  queries (``count``, ``get``, ``topvalues``, ``distinct``, ...).
- ``scope["_parse"]`` -- callable ``(purpose: str, flt: str | None)
  -> IVRE filter`` that unseals a user-supplied token against the
  right backend and raises ``McpError(INVALID_PARAMS)`` on invalid
  input. Every action tool that accepts a ``flt`` argument **must**
  pass it through ``_parse`` before handing it to the backend.
- ``scope["AllPurpose"]`` / ``scope["ActivePurpose"]`` /
  ``scope["PassivePurpose"]`` -- ``typing.Literal`` types used to
  advertise purpose availability to the MCP client. Annotate the
  ``purpose`` parameter with the narrowest one that applies.

Minimal example
===============

The following plugin adds a ``searchbanner`` filter tool (selecting
hosts whose service banner contains a regex) and an ``exposed_count``
action tool (count of hosts matching a filter with at least one open
port)::

    # mypkg/mcp.py
    import re

    from mcp.shared.exceptions import McpError
    from mcp.types import INTERNAL_ERROR, ErrorData


    def install(scope: dict) -> None:
        mcp = scope["mcp"]
        seal = scope["seal"]
        HTTP_DB = scope["HTTP_DB"]
        REAL_DB = scope["REAL_DB"]
        _parse = scope["_parse"]
        ActivePurpose = scope["ActivePurpose"]
        AllPurpose = scope["AllPurpose"]

        @mcp.tool()
        def searchbanner(purpose: ActivePurpose, pattern: str) -> str:
            """Filter records whose service banner matches a regex."""
            return seal(HTTP_DB[purpose].searchbanner(re.compile(pattern)))

        @mcp.tool()
        def exposed_count(purpose: AllPurpose, flt: str | None = None) -> int:
            """Count matching hosts that have at least one open port."""
            try:
                parsed = _parse(purpose, flt)
                real = REAL_DB[purpose]
                narrowed = real.flt_and(parsed, real.searchopenport())
                return int(real.count(narrowed))
            except McpError:
                raise
            except Exception as exc:
                raise McpError(
                    ErrorData(code=INTERNAL_ERROR, message=str(exc))
                ) from exc

The matching ``pyproject.toml`` entry::

    [project.entry-points."ivre.plugins.mcp_server"]
    _install_mypkg = "mypkg.mcp:install"

Conventions
===========

- **Filters are opaque.** Never return raw filter objects to the
  client; always ``seal(...)`` them. Never parse filter tokens
  manually; always go through ``_parse``.
- **Pick the narrowest purpose type.** ``PassivePurpose`` if a tool
  only makes sense against passive data, ``ActivePurpose`` for
  nmap/view-only tools, otherwise ``AllPurpose``.
- **Error handling.** Wrap action-tool bodies with ``except McpError:
  raise`` first, then ``except Exception as exc: raise
  McpError(ErrorData(code=INTERNAL_ERROR, message=str(exc))) from
  exc`` -- without this pattern, raw tracebacks leak through MCP.
- **Strip ``_id`` from record payloads** before returning them, matching
  the built-in ``get`` tool. The MongoDB ``_id`` is an internal
  identifier and serializes poorly to JSON.
- **Do not rename IVRE-internal symbols.** ``parse_filter``,
  ``HttpDBNmap/Passive/View``, ``serialize`` are consumed from IVRE
  and must keep the same semantics; plugins should not monkey-patch
  them.

Discovery
=========

Installed plugins appear in the ``mcp_server`` category of
:func:`ivre.plugins.list_plugins` (e.g. ``ivre version``).
