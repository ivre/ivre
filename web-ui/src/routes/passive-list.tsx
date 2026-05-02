import { useCallback, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { FacetSidebar } from "@/components/FacetSidebar";
import { FilterBar, useFilterTitle } from "@/components/FilterBar";
import { PassiveRecordList } from "@/components/PassiveRecordList";
import { PassiveTimeline } from "@/components/PassiveTimeline";
import { usePassiveRecords } from "@/lib/api";
import { getConfig } from "@/lib/config";
import {
  buildHighlightMap,
  buildQueryFromFilters,
  parseFiltersFromQuery,
  type Filter,
} from "@/lib/filter";
import { getSection } from "@/lib/sections";

/**
 * Passive section route. Composes the filter bar, facet sidebar
 * (sensor / recontype / source — no GeoIP enrichment so no
 * country / AS facets and no world map), an SVG timeline of the
 * visible records, and a list of recontype-aware cards.
 *
 * Hover is two-way synced between the timeline and the cards:
 * mousing over a timeline line highlights the corresponding
 * card; mousing over a card brightens its timeline line.
 * Clicking a timeline line scrolls the card into view.
 */
export function PassiveRoute() {
  const section = getSection("passive");
  if (!section) {
    return <div className="p-8">Passive section not configured.</div>;
  }
  return <PassiveRouteInner />;
}

function PassiveRouteInner() {
  const section = getSection("passive")!;
  const config = getConfig();
  const [searchParams, setSearchParams] = useSearchParams();

  const filters: Filter[] = useMemo(
    () => parseFiltersFromQuery(searchParams.get("q") ?? ""),
    [searchParams],
  );
  const query = useMemo(() => buildQueryFromFilters(filters), [filters]);
  const highlights = useMemo(() => buildHighlightMap(filters), [filters]);

  useFilterTitle(filters);

  const setFilters = useCallback(
    (next: Filter[]) => {
      const nextQ = buildQueryFromFilters(next);
      const params = new URLSearchParams(searchParams);
      if (nextQ) params.set("q", nextQ);
      else params.delete("q");
      setSearchParams(params, { replace: false });
    },
    [searchParams, setSearchParams],
  );

  const addFilter = useCallback(
    (filter: Filter) => {
      const exists = filters.some(
        (f) => f.type === filter.type && f.value === filter.value,
      );
      if (exists) return;
      setFilters([...filters, filter]);
    },
    [filters, setFilters],
  );

  const limit =
    Number.parseInt(searchParams.get("limit") ?? "", 10) ||
    config.dflt_limit ||
    50;

  const {
    data: records = [],
    isLoading,
    error,
  } = usePassiveRecords(section.listEndpoint, {
    q: query,
    limit,
    skip: 0,
  });

  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const cardRefs = useRef<Array<HTMLDivElement | null>>([]);
  const registerCardRef = useCallback(
    (index: number, el: HTMLDivElement | null) => {
      cardRefs.current[index] = el;
    },
    [],
  );
  const scrollToCard = useCallback((index: number) => {
    const el = cardRefs.current[index];
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, []);

  return (
    <div className="flex w-full gap-6 px-6 py-2">
      <aside className="hidden w-[28rem] shrink-0 lg:block">
        <div className="sticky top-14 max-h-[calc(100vh-3.5rem)] space-y-6 overflow-y-auto pr-2 pt-2">
          <FilterBar filters={filters} onFiltersChange={setFilters} />
          <FacetSidebar
            section={section}
            query={query}
            highlights={highlights}
            onAddFilter={addFilter}
          />
        </div>
      </aside>
      <div className="flex flex-1 justify-center">
        <div className="w-full max-w-4xl space-y-4">
          <div className="flex items-baseline justify-between">
            <h2 className="text-xl font-semibold">
              Observations
              {!isLoading && !error ? (
                <span className="ml-2 text-sm font-normal text-muted-foreground">
                  ({records.length})
                </span>
              ) : null}
            </h2>
          </div>
          <div className="lg:hidden">
            <FilterBar filters={filters} onFiltersChange={setFilters} />
          </div>
          <PassiveTimeline
            records={records}
            hoveredIndex={hoveredIndex}
            onHover={setHoveredIndex}
            onSelect={scrollToCard}
          />
          <PassiveRecordList
            records={records}
            loading={isLoading}
            error={error as Error | null}
            highlights={highlights}
            onAddFilter={addFilter}
            hoveredIndex={hoveredIndex}
            onHover={setHoveredIndex}
            registerCardRef={registerCardRef}
          />
        </div>
      </div>
    </div>
  );
}
