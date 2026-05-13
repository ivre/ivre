IP range enumeration
====================

``ivre iprange`` enumerates the IPv4 addresses matching a selector
(country, autonomous system, region, city, CIDR, explicit range,
local file or all routable IPs) and renders them in one of four
output shapes: count, ranges, CIDRs, or every individual address.

The country / AS / region / city selectors and the
``--routable`` selector rely on the MaxMind GeoIP CSV dumps and
the APNIC BGP table populated by ``ivre ipdata --download``;
``--network``, ``--range`` and ``--file`` are pure arithmetic and
work without any GeoIP data.

CLI
---

::

   $ ivre iprange --network 192.0.2.0/24 --count
   256

   $ ivre iprange --network 192.0.2.0/30
   192.0.2.0/30

   $ ivre iprange --range 192.0.2.0 192.0.2.5 --cidrs
   192.0.2.0/30
   192.0.2.4/31

   $ ivre iprange --country FR --count
   83920880

   $ ivre iprange --asnum AS3215 --cidrs --limit 3
   2.3.0.0/16
   2.4.0.0/14
   2.8.0.0/13

   $ ivre iprange --routable --count
   3101530112

Country codes accept the same aliases as the rest of IVRE (``UK``
resolves to ``GB``; ``EU`` expands to every European Union
member state). The ``--asnum`` flag accepts both ``ASnnnn`` and
bare-integer forms; comma-separated lists are unioned
(``--country FR,DE``, ``--asnum AS3215,AS12876``).

The default output is ``--cidrs``. ``--addrs`` enumerates every
individual address and is capped at one million entries to guard
against accidental multi-gigabyte stdout floods; ``--force``
removes the cap.

See the output of ``ivre help iprange`` for the full flag list.

Web API
-------

The same selectors are exposed at ``/cgi/iprange``:

::

   $ curl 'http://localhost/cgi/iprange?network=192.0.2.0/30&output=count'
   {"count": 4}

   $ curl 'http://localhost/cgi/iprange?asnum=AS3215&output=cidrs&limit=3'
   {"count": 20035071, "cidrs": ["2.3.0.0/16", "2.4.0.0/14", "2.8.0.0/13"]}

The web route exposes ``output=count`` / ``ranges`` / ``cidrs``
(default) / ``addrs``; the ``json`` CLI shortcut is rejected over
HTTP, where the response shape is already structured.
``output=addrs`` is bounded by the ``WEB_IPRANGE_ADDR_CAP``
configuration knob (default 100 000) so a ``/0`` selector cannot
serialise billions of strings into a single response.

MCP tool
--------

The ``ip_range`` MCP tool exposes the same surface to LLM agents,
with a tighter 10 000-address cap on ``output=addrs`` (to keep
responses small enough to fit a model context window). Use
``output=cidrs`` (the default) or ``output=ranges`` for larger
selections.
