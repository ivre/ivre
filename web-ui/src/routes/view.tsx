import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { FacetSidebar } from "@/components/FacetSidebar";
import { FilterBar, useFilterTitle } from "@/components/FilterBar";
import { HostCardList } from "@/components/HostCardList";
import { HostDetailSheet } from "@/components/HostDetailSheet";
import { WorldMap } from "@/components/WorldMap";
import { useHosts, type HostRecord } from "@/lib/api";
import { getConfig } from "@/lib/config";
import {
  buildHighlightMap,
  buildQueryFromFilters,
  parseFiltersFromQuery,
  type Filter,
} from "@/lib/filter";
import { getSection } from "@/lib/sections";

/**
 * The View section's main route. Composes the filter bar, facet
 * sidebar, world map, host card list, and host detail sheet.
 *
 * Filter state lives in the URL search params (``?q=…``) so the
 * page is shareable / bookmarkable.
 */
export function ViewRoute() {
  const section = getSection("view");
  if (!section) {
    return <div className="p-8">View section not configured.</div>;
  }

  return <ViewRouteInner />;
}

function ViewRouteInner() {
  const section = getSection("view")!;
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
      // Skip duplicates (same type + same value).
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
    data: hosts = [],
    isLoading,
    error,
  } = useHosts(section.listEndpoint, {
    q: query,
    limit,
    skip: 0,
  });

  // Host detail state.
  const [selectedAddr, setSelectedAddr] = useState<string | null>(null);
  const selectedIndex = useMemo(
    () =>
      selectedAddr ? hosts.findIndex((h) => h.addr === selectedAddr) : -1,
    [selectedAddr, hosts],
  );
  const selectedHost: HostRecord | null =
    selectedIndex >= 0 ? hosts[selectedIndex] : null;

  return (
    // Outer flex: tight ``py-2`` so the top/bottom margin matches
    // the visual weight of ``px-6`` on the sides. Sidebar on the
    // left, results horizontally centred in whatever space is left.
    <div className="flex w-full gap-6 px-6 py-2">
      {/*
        Left rail: map + filter bar + facet sidebar. The whole rail
        sticks below the header (h-14 = 3.5rem) and scrolls
        independently when its content overflows. ``w-[28rem]``
        matches the prototype's sidebar width, which is wide enough
        for the map widget and long facet labels.
       */}
      <aside className="hidden w-[28rem] shrink-0 lg:block">
        <div className="sticky top-14 max-h-[calc(100vh-3.5rem)] space-y-6 overflow-y-auto pr-2 pt-2">
          <WorldMap mapEndpoint={section.mapEndpoint} query={query} />
          <FilterBar filters={filters} onFiltersChange={setFilters} />
          <FacetSidebar
            section={section}
            query={query}
            highlights={highlights}
            onAddFilter={addFilter}
          />
        </div>
      </aside>
      {/*
        Cap the results column at ``max-w-4xl`` (56 rem ≈ 896 px) and
        centre it inside the post-sidebar flex cell with
        ``justify-center``. On wide viewports this leaves comfortable
        empty space on both sides of the cards, matching the
        prototype's visual rhythm.
       */}
      <div className="flex flex-1 justify-center">
        <div className="w-full max-w-4xl space-y-4">
          <div className="flex items-baseline justify-between">
            <h2 className="text-xl font-semibold">
              Results
              {!isLoading && !error ? (
                <span className="ml-2 text-sm font-normal text-muted-foreground">
                  ({hosts.length})
                </span>
              ) : null}
            </h2>
          </div>
          <div className="lg:hidden">
            <FilterBar filters={filters} onFiltersChange={setFilters} />
          </div>
          <HostCardList
            hosts={hosts}
            loading={isLoading}
            error={error as Error | null}
            highlights={highlights}
            onAddFilter={addFilter}
            onSelect={(h) => setSelectedAddr(h.addr)}
          />
        </div>
      </div>

      <HostDetailSheet
        host={selectedHost}
        open={selectedHost !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedAddr(null);
        }}
        hasPrev={selectedIndex > 0}
        hasNext={selectedIndex >= 0 && selectedIndex < hosts.length - 1}
        onPrev={() => {
          if (selectedIndex > 0) {
            setSelectedAddr(hosts[selectedIndex - 1].addr);
          }
        }}
        onNext={() => {
          if (selectedIndex >= 0 && selectedIndex < hosts.length - 1) {
            setSelectedAddr(hosts[selectedIndex + 1].addr);
          }
        }}
      />
    </div>
  );
}
