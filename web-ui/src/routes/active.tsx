import { HostListRoute } from "./host-list";

/**
 * Active section: the raw ``db.nmap`` scan results. Renders the
 * generic host-list page with the Active section's facets and
 * ``/cgi/scans`` endpoints. The world map is omitted because raw
 * scan records are typically not GeoIP-enriched (that enrichment
 * happens at ``db2view`` time).
 */
export function ActiveRoute() {
  return <HostListRoute sectionId="active" />;
}
