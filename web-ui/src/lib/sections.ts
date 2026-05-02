/**
 * Top-level sections of the Web UI. Each maps to one ``db.*``
 * purpose on the IVRE backend, plus an "Admin" stub for operator
 * controls.
 */

export type SectionId =
  | "view"
  | "active"
  | "passive"
  | "dns"
  | "flow"
  | "rir"
  | "admin";

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
  resultType: "hosts" | "passive" | "dns" | "rir" | "flow" | "admin";
  /** When ``true``, the section is only useful when authentication
   *  is enabled (e.g. Admin). */
  requiresAuth?: boolean;
  /** Marks the section as a stub during the M1 Stream B rollout —
   *  the route renders an "Under construction" placeholder. */
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
    facets: [],
    resultType: "dns",
    stub: true,
  },
  {
    id: "flow",
    label: "Flow",
    listEndpoint: "/flows",
    facets: [],
    resultType: "flow",
    stub: true,
  },
  {
    id: "rir",
    label: "RIR",
    listEndpoint: "/rir",
    topEndpoint: "/rir/top",
    facets: [],
    resultType: "rir",
    stub: true,
  },
  {
    id: "admin",
    label: "Admin",
    facets: [],
    resultType: "admin",
    requiresAuth: true,
    stub: true,
  },
] as const;

export function getSection(id: string): SectionConfig | undefined {
  return SECTIONS.find((s) => s.id === id);
}

export const DEFAULT_SECTION: SectionId = "view";
