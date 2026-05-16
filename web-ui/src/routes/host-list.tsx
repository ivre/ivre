import { useCallback, useMemo, useRef, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";

import { FacetSidebar } from "@/components/FacetSidebar";
import { FilterBar, useFilterTitle } from "@/components/FilterBar";
import { HostCardList } from "@/components/HostCardList";
import { HostDetailSheet } from "@/components/HostDetailSheet";
import { Timeline } from "@/components/Timeline";
import { WorldMap } from "@/components/WorldMap";
import {
  useCoordinates,
  useCount,
  useHosts,
  type HostRecord,
} from "@/lib/api";
import { getConfig, isSequentialLoading } from "@/lib/config";
import {
  buildHighlightMap,
  buildQueryFromFilters,
  parseFiltersFromQuery,
  quoteValue,
  type Filter,
} from "@/lib/filter";
import { formatResultsCount } from "@/lib/format";
import { getSection, type SectionId } from "@/lib/sections";
import { formatTimelineRange, type TimelineRecord } from "@/lib/timeline";

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

  const sequential = isSequentialLoading();

  const hostsQuery = useHosts(section.listEndpoint, {
    q: query,
    limit,
    skip: 0,
  });
  const { data: hosts = [], isLoading, error } = hostsQuery;
  // Total number of records matching ``q=`` — used to render the
  // ``loaded / total`` headline alongside the page-of-results
  // count. Fires in parallel with the hosts query (cheap server
  // operation; no need to serialise even under sequential mode).
  // Sections whose backend does not expose a ``/count`` companion
  // pass ``countEndpoint=undefined``; the hook is gated off and
  // ``data`` stays ``undefined``, falling back to the bare
  // ``(N)`` form.
  const { data: totalCount } = useCount(section.countEndpoint, { q: query });

  // Sequential-loading orchestration. In ``sequential`` mode the
  // map waits for the hosts request to settle (success OR error
  // — we don't want a failed hosts call to permanently block the
  // map), and the facets wait for whichever widgets exist above
  // them.
  //
  // The route is the *single owner* of the coordinates query;
  // ``<WorldMap>`` is purely presentational and just receives
  // ``coordsQuery.data``. That keeps a single ``QueryObserver``
  // on the cache entry rather than two (one in the route for
  // ``mapDone``, one in the component for ``data``) — which is
  // what we want both for fewer re-renders and for a clear
  // source of truth on "is the map done?".
  //
  // Scope: this gate intentionally targets the *first load* of
  // each ``(query, section)`` cycle. ``isSuccess || isError`` is
  // the "settled" predicate; once a query has settled, the gate
  // stays open even if a background refetch later flips
  // ``isFetching`` back to ``true``. That's correct for our
  // current usage because none of these queries have refetch
  // triggers (``refetchOnWindowFocus`` is globally off, no
  // polling, no explicit ``invalidateQueries`` on these keys —
  // see ``routes/root.tsx``). If background refetches are added
  // later and we still want serialisation, add ``&& !isFetching``
  // to the predicates and revisit the facet ratchet in
  // ``FacetSidebar`` (which is monotonic and would also need to
  // un-release on refetch).
  const resultsDone = hostsQuery.isSuccess || hostsQuery.isError;
  const mapEnabled = !sequential || resultsDone;
  const coordsQuery = useCoordinates(
    section.mapEndpoint,
    { q: query },
    { enabled: mapEnabled },
  );
  const mapDone =
    !section.mapEndpoint || coordsQuery.isSuccess || coordsQuery.isError;
  const facetsEnabled = !sequential || (resultsDone && mapDone);

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

  // Timeline ↔ card cross-highlight wiring. Active hosts have a
  // ``starttime`` / ``endtime`` pair (ISO string or epoch); we
  // project them into the generic :type:`TimelineRecord` shape
  // (firstseen / lastseen / count) so the same ``<Timeline>``
  // component used by Passive can plot them. Each row carries a
  // back-reference to the underlying host so the per-row tooltip
  // can surface the host's identity.
  //
  // The widget renders only on sections that don't already have
  // a left-rail visualisation (View has the world map; Active
  // gets the timeline). Sections may grow other widgets later;
  // the gate is intentionally explicit per-section rather than
  // "anything without a mapEndpoint".
  const showTimeline = sectionId === "active";
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
  const timelineRecords = useMemo<HostTimelineRow[]>(
    () =>
      showTimeline
        ? hosts.map((h) => ({
            // ``starttime`` / ``endtime`` come back as either a
            // Unix-epoch number (seconds OR milliseconds; the
            // Timeline auto-detects via ``timelineDateMs``) or an
            // ISO-ish string (``"2015-09-18 16:13:35"``). Pass
            // them through verbatim so the same auto-detection
            // applies. Hosts without a starttime fall back to 0
            // (1970) and stand out as obviously stale rather
            // than crashing the layout.
            firstseen: h.starttime ?? 0,
            // Default endtime to starttime: a host with no
            // recorded scan duration plots as an instant blip
            // rather than an unbounded line.
            lastseen: h.endtime ?? h.starttime ?? 0,
            // Active scans don't carry a multiplicity, so each
            // host counts as one observation. The Timeline's
            // density math then reduces to ``1 / duration``,
            // which renders short scans (instant blips) thicker
            // and long observation windows thinner — useful at
            // a glance.
            count: 1,
            host: h,
          }))
        : [],
    [hosts, showTimeline],
  );

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
            <WorldMap data={coordsQuery.data} />
          ) : null}
          {showTimeline ? (
            <Timeline
              records={timelineRecords}
              hoveredIndex={hoveredIndex}
              onHover={setHoveredIndex}
              onSelect={scrollToCard}
              getTitle={hostTimelineTitle}
              itemLabel={{ singular: "scan", plural: "scans" }}
              emptyLabel="No scans to plot."
              titleId="active-timeline-title"
            />
          ) : null}
          <FilterBar filters={filters} onFiltersChange={setFilters} />
          <FacetSidebar
            section={section}
            query={query}
            highlights={highlights}
            onAddFilter={addFilter}
            sequential={sequential}
            enabled={facetsEnabled}
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
                  ({formatResultsCount(hosts.length, totalCount)})
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
            hoveredIndex={showTimeline ? hoveredIndex : null}
            onHover={showTimeline ? setHoveredIndex : undefined}
            registerCardRef={showTimeline ? registerCardRef : undefined}
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

/** A :type:`TimelineRecord`-shaped projection of a
 *  :type:`HostRecord`, with a back-reference so the per-row
 *  tooltip can surface the host identity without re-deriving
 *  it. The Timeline component is generic over any record
 *  satisfying the three required fields. */
interface HostTimelineRow extends TimelineRecord {
  host: HostRecord;
}

/** Per-row tooltip body for the active timeline. Surfaces the
 *  host's address, the start → end range, and the computed
 *  density (here scans-per-second; an instant scan reports
 *  ``count / max(duration, 1)`` = ``1``). */
function hostTimelineTitle(row: HostTimelineRow, density: number): string {
  return [
    row.host.addr,
    formatTimelineRange(row),
    `density≈${density.toFixed(3)}/s`,
  ].join("\n");
}
