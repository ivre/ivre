import { HostListRoute } from "./host-list";

/**
 * View section: the merged ``db.view`` host inventory. Renders the
 * generic host-list page with the View section's facets, world
 * map, and ``/cgi/view`` endpoints.
 */
export function ViewRoute() {
  return <HostListRoute sectionId="view" />;
}
