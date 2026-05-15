import { useCallback, useEffect, useState } from "react";

import { FacetGroup } from "@/components/FacetGroup";
import type { Filter, HighlightMap } from "@/lib/filter";
import type { SectionConfig } from "@/lib/sections";

export interface FacetSidebarProps {
  section: SectionConfig;
  query: string;
  highlights?: HighlightMap;
  onAddFilter: (filter: Filter) => void;
  /** When ``true``, render facets one at a time: each
   *  ``FacetGroup`` waits for the previous one to finish loading
   *  before it issues its own request. Defaults to ``false`` to
   *  preserve the legacy parallel behavior in callers that don't
   *  opt in. */
  sequential?: boolean;
  /** Gate for the whole sidebar in sequential mode. While
   *  ``false`` (typically because the results — and the map, if
   *  any — are still in flight) no facet request is fired.
   *  Ignored when ``sequential`` is ``false``. Defaults to
   *  ``true``. */
  enabled?: boolean;
}

const FACET_LABELS: Record<string, string> = {
  country: "Country",
  as: "AS",
  asnum: "AS",
  "aut-num": "AS number",
  "as-name": "AS name",
  source_file: "Source file",
  "port:open": "Open ports",
  product: "Product",
  service: "Service",
  tag: "Tag",
  sensor: "Sensor",
  recontype: "Recon type",
  source: "Source",
  category: "Category",
};

/**
 * Sidebar containing one ``FacetGroup`` per facet declared by the
 * section config. Each group fires its own request to ``top/<field>``
 * via ``useTop``; that request is keyed on the active query so the
 * counts are kept in sync as the filter changes.
 */
export function FacetSidebar({
  section,
  query,
  highlights,
  onAddFilter,
  sequential = false,
  enabled = true,
}: FacetSidebarProps) {
  // Count of facets that have already finished loading. Facet at
  // index ``i`` is enabled once ``loadedCount >= i`` AND the
  // sidebar itself is enabled (typically: results + map done).
  // The counter is reset whenever the cycle's identity changes
  // so a fresh search (or a section switch) re-runs the
  // sequence from the top.
  const [loadedCount, setLoadedCount] = useState(0);

  // Cycle identity is ``(query, section.id, section.topEndpoint)``.
  // ``section.id`` is the canonical section identifier and is
  // sufficient on its own, but we also include ``topEndpoint``
  // as a belt-and-braces signal: a future refactor that swaps
  // a section's endpoint at runtime (uncommon, but possible)
  // would still trigger the reset. ``section.id`` alone covers
  // the case the SECTIONS table is extended with a section that
  // happens to share ``topEndpoint`` with another (also
  // uncommon, but not currently prevented by the type system).
  useEffect(() => {
    setLoadedCount(0);
  }, [query, section.id, section.topEndpoint]);

  const handleLoaded = useCallback((index: number) => {
    // ``Math.max`` here makes the callback idempotent: a facet
    // re-rendering with the same state won't accidentally rewind
    // the counter.
    setLoadedCount((c) => Math.max(c, index + 1));
  }, []);

  if (!section.topEndpoint || section.facets.length === 0) {
    return null;
  }
  return (
    <aside className="space-y-6">
      {section.facets.map((field, index) => {
        const facetEnabled = sequential
          ? enabled && index <= loadedCount
          : true;
        return (
          <FacetGroup
            key={field}
            field={field}
            label={FACET_LABELS[field] ?? field}
            topEndpoint={section.topEndpoint as string}
            query={query}
            highlights={highlights}
            onAddFilter={onAddFilter}
            enabled={facetEnabled}
            onLoaded={
              sequential ? () => handleLoaded(index) : undefined
            }
          />
        );
      })}
    </aside>
  );
}
