/**
 * Data sections of the Web UI. Each maps to one ``db.*`` purpose
 * on the IVRE backend (View, Active scans, Passive records, DNS
 * merge, Flow, RIR). Account and admin pages (Admin, API keys)
 * are *not* sections — they are pure routes registered in
 * ``routes/root.tsx`` and reached from the user menu.
 */

export type SectionId =
  | "view"
  | "active"
  | "passive"
  | "dns"
  | "flow"
  | "rir";

export interface SectionConfig {
  id: SectionId;
  label: string;
  /** Path relative to ``/cgi/`` for the host/record list endpoint
   *  (e.g. ``/view``, ``/scans``). The ``/cgi`` prefix is added by
   *  ``src/lib/api.ts``'s ``CGI_ROOT`` constant. */
  listEndpoint?: string;
  /** Path relative to ``/cgi/`` for the ``top/<field>`` faceting
   *  endpoint. */
  topEndpoint?: string;
  /** Path relative to ``/cgi/`` returning a GeoJSON
   *  GeometryCollection of Points (for the world map widget).
   *  ``undefined`` disables the map for that section. */
  mapEndpoint?: string;
  /** Default facets to render in the sidebar, in display order. */
  facets: readonly string[];
  /** Shape of the records returned by ``listEndpoint`` — drives
   *  which result list component to render. */
  resultType: "hosts" | "passive" | "dns" | "rir" | "flow";
  /** Marks the section as a stub during the rollout — the route
   *  renders an "Under construction" placeholder. */
  stub?: boolean;
}

export const SECTIONS: readonly SectionConfig[] = [
  {
    id: "view",
    label: "View",
    listEndpoint: "/view",
    topEndpoint: "/view/top",
    mapEndpoint: "/view/coordinates",
    facets: ["country", "as", "port:open", "product", "tag"],
    resultType: "hosts",
  },
  {
    id: "active",
    label: "Active",
    listEndpoint: "/scans",
    topEndpoint: "/scans/top",
    // Active scan results (``db.nmap``) are typically not enriched
    // with MaxMind GeoIP data — the IP-to-country / IP-to-AS columns
    // are populated when records are merged into the View
    // (``db2view``). The world-map widget and the country / AS
    // facets would mostly render as empty for raw scans, so we
    // omit them here. ``category`` is a scan-specific concept
    // (operator-defined groupings) that is not meaningful in the
    // View, hence its absence on the View facets list.
    facets: ["category", "source", "port:open", "service", "product", "tag"],
    resultType: "hosts",
  },
  {
    id: "passive",
    label: "Passive",
    listEndpoint: "/passive",
    topEndpoint: "/passive/top",
    // Passive records (``db.passive``) are not GeoIP-enriched and
    // the backend does not expose ``/cgi/passive/coordinates``;
    // omit the world-map widget for the same reason as Active.
    // ``addr`` may be present (most records) or absent (DNS
    // CNAME/MX/NS/PTR answers, where ``value`` is the queried
    // name and ``targetval`` is the canonical name).
    facets: ["sensor", "recontype", "source"],
    resultType: "passive",
  },
  {
    id: "dns",
    label: "DNS",
    // The DNS section talks to ``/cgi/dns`` — a dedicated
    // endpoint that merges DNS observations from the active
    // scan database (``db.nmap.iter_dns``) and the passive
    // observation database (``db.passive.iter_dns``) into a
    // single deduplicated stream of ``(name, addr)``
    // pseudo-records. The merged shape carries summed counts,
    // unioned ``types`` and ``sources`` sets, and extended
    // ``firstseen`` / ``lastseen`` intervals; the route returns
    // them sorted ``lastseen DESC, count DESC``.
    //
    // The endpoint is bespoke (no ``top/<field>`` companion is
    // exposed today), so the section omits ``topEndpoint`` and
    // therefore the FacetSidebar.
    listEndpoint: "/dns",
    facets: [],
    resultType: "dns",
  },
  {
    id: "flow",
    label: "Flow",
    // The Flow section talks to ``/cgi/flows`` \u2014 a single
    // route that takes a JSON-encoded ``q=`` carrying ``nodes``
    // / ``edges`` filter lists (the ``flow.Query`` grammar:
    // ``[ANY|ALL|ONE|LEN ][src.|dst.][meta.]<attr> [<op>
    // <value>] [OR ...]``), plus mode (default / flow_map /
    // talk_map), limit, skip, after/before, orderby, timeline,
    // count. The same route returns either a graph
    // (``{nodes, edges}``), a counts object
    // (``{clients, servers, flows}``), or details for a single
    // node / edge. There is no ``top/<field>`` companion, hence
    // ``facets: []``.
    listEndpoint: "/flows",
    facets: [],
    resultType: "flow",
  },
  {
    id: "rir",
    label: "RIR",
    // The RIR section talks to ``/cgi/rir`` (records) and
    // ``/cgi/rir/top/<field>`` (facet aggregations). Records
    // come in two families: ``inet[6]num`` (with ``start``,
    // ``stop``, ``netname``, ...) and ``aut-num`` (with
    // ``aut-num`` int and ``as-name``). The default sort on
    // ``/cgi/rir`` is narrowest-range first so a ``host:`` /
    // ``net:`` / ``range:`` filter naturally surfaces the
    // most-specific allocation at the top.
    listEndpoint: "/rir",
    topEndpoint: "/rir/top",
    facets: ["country", "source_file"],
    resultType: "rir",
  },
] as const;

export function getSection(id: string): SectionConfig | undefined {
  return SECTIONS.find((s) => s.id === id);
}

export const DEFAULT_SECTION: SectionId = "view";
