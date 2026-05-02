import { useCallback, useMemo } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";

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
  quoteValue,
  type Filter,
} from "@/lib/filter";
import { getSection, type SectionId } from "@/lib/sections";

export interface HostListRouteProps {
  /** Section to render. Drives the API endpoints, the facet list,
   *  and the URL prefix used for per-host deep links
   *  (``/<sectionId>`` and ``/<sectionId>/host/<addr>``). */
  sectionId: Extract<SectionId, "view" | "active">;
}

/**
 * Generic host-record list page used by both the View and Active
 * sections. Composes the filter bar, facet sidebar, optional world
 * map, host card list, and host detail sheet.
 *
 * Filter state lives in the URL search params (``?q=…``) so the
 * page is shareable / bookmarkable. The currently-displayed host
 * (when a sheet is open) lives in the path itself
 * (``/<sectionId>/host/<addr>``).
 *
 * Sections that do not declare a ``mapEndpoint`` skip the world map
 * widget entirely; this is the case for Active, where raw nmap
 * records are typically not GeoIP-enriched and the map would be
 * empty most of the time.
 */
export function HostListRoute({ sectionId }: HostListRouteProps) {
  const section = getSection(sectionId);
  if (!section) {
    return <div className="p-8">Section &quot;{sectionId}&quot; not configured.</div>;
  }
  return <HostListRouteInner sectionId={sectionId} />;
}

function HostListRouteInner({ sectionId }: HostListRouteProps) {
  const section = getSection(sectionId)!;
  const config = getConfig();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  // ``addr`` is set when the route is ``/<sectionId>/host/<addr>``
  // and ``undefined`` for the bare ``/<sectionId>``. Filter state is
  // preserved across both via the URL search params (which
  // react-router keeps when navigating between sibling routes).
  const { addr: routeAddr } = useParams<{ addr?: string }>();

  const filters: Filter[] = useMemo(
    () => parseFiltersFromQuery(searchParams.get("q") ?? ""),
    [searchParams],
  );
  const query = useMemo(() => buildQueryFromFilters(filters), [filters]);
  const highlights = useMemo(() => buildHighlightMap(filters), [filters]);

  useFilterTitle(filters);

  const searchSuffix = useMemo(() => {
    const s = searchParams.toString();
    return s ? `?${s}` : "";
  }, [searchParams]);

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

  // Host detail. ``routeAddr`` (from ``/<sectionId>/host/<addr>``)
  // is the single source of truth for "which host is currently
  // displayed in the sheet"; selecting a host or pressing prev/next
  // is just a ``navigate()`` call, and closing the sheet navigates
  // back to ``/<sectionId>`` (preserving the search params).
  const selectedIndex = useMemo(
    () => (routeAddr ? hosts.findIndex((h) => h.addr === routeAddr) : -1),
    [routeAddr, hosts],
  );
  // For direct navigation to ``/<sectionId>/host/<addr>`` (refresh,
  // share link), the addr usually isn't in the in-memory results
  // yet — fetch it as a one-host query.
  const directHostQuery = useMemo(() => {
    if (!routeAddr) return undefined;
    if (selectedIndex >= 0) return undefined;
    return `host:${quoteValue(routeAddr)}`;
  }, [routeAddr, selectedIndex]);
  const { data: directHostList = [] } = useHosts(
    directHostQuery ? section.listEndpoint : undefined,
    { q: directHostQuery, limit: 1, skip: 0 },
  );
  const selectedHost: HostRecord | null =
    selectedIndex >= 0
      ? hosts[selectedIndex]
      : routeAddr && directHostList[0]
        ? directHostList[0]
        : null;

  const goToHost = useCallback(
    (a: string) => {
      navigate(`/${sectionId}/host/${encodeURIComponent(a)}${searchSuffix}`);
    },
    [navigate, sectionId, searchSuffix],
  );
  const closeDetail = useCallback(() => {
    navigate(`/${sectionId}${searchSuffix}`);
  }, [navigate, sectionId, searchSuffix]);

  return (
    // Outer flex: tight ``py-2`` so the top/bottom margin matches
    // the visual weight of ``px-6`` on the sides. Sidebar on the
    // left, results horizontally centred in whatever space is left.
    <div className="flex w-full gap-6 px-6 py-2">
      {/*
        Left rail: optional map + filter bar + facet sidebar. The
        whole rail sticks below the header (h-14 = 3.5rem) and
        scrolls independently when its content overflows.
        ``w-[28rem]`` matches the prototype's sidebar width, which
        is wide enough for the map widget and long facet labels.
       */}
      <aside className="hidden w-[28rem] shrink-0 lg:block">
        <div className="sticky top-14 max-h-[calc(100vh-3.5rem)] space-y-6 overflow-y-auto pr-2 pt-2">
          {section.mapEndpoint ? (
            <WorldMap mapEndpoint={section.mapEndpoint} query={query} />
          ) : null}
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
            onSelect={(h) => goToHost(h.addr)}
          />
        </div>
      </div>

      <HostDetailSheet
        host={selectedHost}
        open={Boolean(routeAddr) && selectedHost !== null}
        onOpenChange={(open) => {
          if (!open) closeDetail();
        }}
        hasPrev={selectedIndex > 0}
        hasNext={selectedIndex >= 0 && selectedIndex < hosts.length - 1}
        onPrev={() => {
          if (selectedIndex > 0) {
            goToHost(hosts[selectedIndex - 1].addr);
          }
        }}
        onNext={() => {
          if (selectedIndex >= 0 && selectedIndex < hosts.length - 1) {
            goToHost(hosts[selectedIndex + 1].addr);
          }
        }}
        onAddFilter={addFilter}
        highlights={highlights}
      />
    </div>
  );
}
