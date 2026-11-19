import {
  ChevronsLeft,
  ChevronsRight,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useCallback, useMemo, useRef, useState } from "react";

import { FacetSidebar } from "@/components/FacetSidebar";
import { FilterBar, useFilterTitle } from "@/components/FilterBar";
import { HostCardList } from "@/components/HostCardList";
import { ReportPagination } from "@/components/ReportPagination";
import { ReportStatus } from "@/components/ReportStatus";
import { Timeline } from "@/components/Timeline";
import { Button } from "@/components/ui/button";
import { WorldMap } from "@/components/WorldMap";
import { useCoordinates, useCount, useHosts, type HostRecord } from "@/lib/api";
import { getConfig, isSequentialLoading } from "@/lib/config";
import { buildQueryFromFilters } from "@/lib/filter";
import { formatResultsCount } from "@/lib/format";
import {
  hostRecordId,
  hostReportUrl,
  readHostNavigation,
  type HostNavigation,
} from "@/lib/host-report";
import { buildPagedQuery, computePagination, parseUrlInt } from "@/lib/paging";
import { getSection, type SectionId } from "@/lib/sections";
import { formatTimelineRange, type TimelineRecord } from "@/lib/timeline";
import { usePageScroll } from "@/lib/use-page-scroll";
import { useReportPaging } from "@/lib/use-report-paging";
import { useBrowseFilters } from "@/lib/use-browse-filters";
import { cn } from "@/lib/utils";

export interface HostListRouteProps {
  /** Section to render. Drives the API endpoints, the facet list,
   *  and the URL prefix used for per-host deep links
   *  (``/<sectionId>`` and ``/<sectionId>/host/<addr>``). */
  sectionId: Extract<SectionId, "view" | "active">;
  scopeAddr?: string;
}

/**
 * Generic host-record list page used by both the View and Active
 * sections. Composes the filter bar, facet sidebar, optional world
 * map and host card list. Details open a separate, full-page report.
 *
 * Filter state lives in the URL search params (``?q=…``) so the
 * page is shareable / bookmarkable.
 *
 * Sections that do not declare a ``mapEndpoint`` skip the world map
 * widget entirely; this is the case for Active, where raw nmap
 * records are typically not GeoIP-enriched and the map would be
 * empty most of the time.
 */
export function HostListRoute({ sectionId, scopeAddr }: HostListRouteProps) {
  const section = getSection(sectionId);
  if (!section) {
    return (
      <div className="p-8">Section &quot;{sectionId}&quot; not configured.</div>
    );
  }
  return <HostListRouteInner sectionId={sectionId} scopeAddr={scopeAddr} />;
}

function HostListRouteInner({ sectionId, scopeAddr }: HostListRouteProps) {
  const section = getSection(sectionId)!;
  const config = getConfig();
  const {
    filters,
    fixedFilters,
    query,
    highlights,
    setFilters,
    addFilter,
    searchParams,
    setSearchParams,
    location,
  } = useBrowseFilters(sectionId, scopeAddr);
  const restoreScrollY = location.state?.restoreScrollY;

  useFilterTitle(filters, !scopeAddr);

  // ``limit`` (min 1): any non-positive / non-numeric value
  // (``?limit=0``, ``?limit=-10``, ``?limit=abc``) falls back to the
  // default page size -- a negative would otherwise be truthy and
  // corrupt both the ``limit:N`` meta-token and the pagination math.
  const limit = scopeAddr
    ? Math.min(50, Math.max(1, config.dflt_limit || 25))
    : parseUrlInt(searchParams, "limit", {
        min: 1,
        fallback: config.dflt_limit || 50,
      });
  const paginationEnabled = sectionId === "view" || Boolean(scopeAddr);
  const skipKey = scopeAddr ? "recordsSkip" : "skip";
  // ``skip`` (min 0): a negative / non-numeric offset clamps to 0.
  const skip = paginationEnabled
    ? parseUrlInt(searchParams, skipKey, { fallback: 0 })
    : 0;
  const { previousSkip, stateForSkip } = useReportPaging(
    sectionId,
    query,
    limit,
    skip,
  );

  const sequential = isSequentialLoading();
  const pagedQuery = paginationEnabled
    ? buildPagedQuery(
        scopeAddr ? `${query} -sortby:endtime -sortby:starttime` : query,
        limit,
        skip,
      )
    : query;

  const listParams = {
    q: pagedQuery,
    limit: paginationEnabled ? undefined : limit,
    skip: paginationEnabled ? undefined : skip,
    includeId: sectionId === "active" ? true : undefined,
  };
  const hostsQuery = useHosts(section.listEndpoint, listParams);
  const { data: hosts = [], isLoading, error } = hostsQuery;
  usePageScroll(
    !isLoading,
    typeof restoreScrollY === "number" ? restoreScrollY : 0,
  );
  // Total number of records matching ``q=`` — used to render the
  // ``loaded / total`` headline alongside the page-of-results
  // count. Fires in parallel with the hosts query (cheap server
  // operation; no need to serialise even under sequential mode).
  // Sections whose backend does not expose a ``/count`` companion
  // pass ``countEndpoint=undefined``; the hook is gated off and
  // ``data`` stays ``undefined``, falling back to the bare
  // ``(N)`` form.
  const { data: totalCount } = useCount(section.countEndpoint, { q: query });

  const setSkip = useCallback(
    (nextSkip: number) => {
      const params = new URLSearchParams(searchParams);
      const normalized = Math.max(0, nextSkip);
      if (normalized === 0) params.delete(skipKey);
      else params.set(skipKey, String(normalized));
      setSearchParams(params, {
        state: scopeAddr ? stateForSkip(normalized) : undefined,
      });
    },
    [searchParams, setSearchParams, skipKey, scopeAddr, stateForSkip],
  );
  const showPagination =
    paginationEnabled && !isLoading && !error && (hosts.length > 0 || skip > 0);

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

  const navigationEntries = useMemo(
    () =>
      hosts.map((host) => ({
        addr: host.addr,
        record: sectionId === "active" ? hostRecordId(host) : undefined,
      })),
    [hosts, sectionId],
  );
  const getDetailsLink = (host: HostRecord, index: number) => {
    const params = new URLSearchParams(searchParams);
    const returnParams = new URLSearchParams(searchParams);
    if (sectionId === "active") {
      const recordId = navigationEntries[index].record;
      if (!recordId) return undefined;
      params.set("record", recordId);
      params.set("tab", "active");
      if (scopeAddr) {
        const extraQuery = buildQueryFromFilters(filters);
        params.set("activeQ", extraQuery);
        returnParams.set("activeQ", extraQuery);
        returnParams.set("tab", "active");
        returnParams.delete("record");
        returnParams.delete("section");
      }
    }
    const hostNavigation: HostNavigation = {
      returnTo: scopeAddr
        ? `${location.pathname}?${returnParams.toString()}`
        : location.pathname + location.search,
      returnScrollY: window.scrollY,
      returnKey: location.key,
      entries: navigationEntries,
      currentIndex: index,
    };
    return {
      to: hostReportUrl(sectionId, host.addr, params),
      state: {
        reportPaging: location.state?.reportPaging,
        hostNavigation,
        reportNavigation: scopeAddr
          ? readHostNavigation(location.state)
          : undefined,
      },
    };
  };

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
    <div
      className={cn("flex w-full min-w-0 gap-6 py-2", !scopeAddr && "px-6")}
      role={scopeAddr ? "region" : undefined}
      aria-label={scopeAddr ? "Active scans for this IP" : undefined}
    >
      {/*
        Left rail: optional map + filter bar + facet sidebar. The
        whole rail sticks below the header (h-14 = 3.5rem) and
        scrolls independently when its content overflows.
        ``w-[28rem]`` matches the prototype's sidebar width, which
        is wide enough for the map widget and long facet labels.
       */}
      <aside
        className={cn(
          "hidden shrink-0 lg:block",
          scopeAddr ? "w-[21rem]" : "w-[28rem]",
        )}
      >
        <div className="sticky top-14 max-h-[calc(100vh-3.5rem)] space-y-6 overflow-y-auto pr-2 pt-2">
          {section.mapEndpoint ? <WorldMap data={coordsQuery.data} /> : null}
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
          <FilterBar
            filters={filters}
            fixedFilters={fixedFilters}
            onFiltersChange={setFilters}
          />
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
      <div className="flex min-w-0 flex-1 justify-center">
        <div className="w-full min-w-0 max-w-4xl space-y-4">
          <div className="flex items-baseline justify-between">
            <h2 className="text-xl font-semibold">
              {scopeAddr ? "Active scans" : "Results"}
              {!isLoading && !error ? (
                <span className="ml-2 text-sm font-normal text-muted-foreground">
                  ({formatResultsCount(hosts.length, totalCount)})
                </span>
              ) : null}
            </h2>
          </div>
          <div className="space-y-4 lg:hidden">
            <FilterBar
              filters={filters}
              fixedFilters={fixedFilters}
              onFiltersChange={setFilters}
            />
            {scopeAddr && showTimeline ? (
              <Timeline
                records={timelineRecords}
                hoveredIndex={hoveredIndex}
                onHover={setHoveredIndex}
                onSelect={scrollToCard}
                getTitle={hostTimelineTitle}
                itemLabel={{ singular: "scan", plural: "scans" }}
                emptyLabel="No scans to plot."
                titleId="host-active-mobile-timeline-title"
              />
            ) : null}
          </div>
          {sectionId === "active" &&
          hosts.some((host) => !hostRecordId(host)) ? (
            <p role="status" className="text-sm text-muted-foreground">
              Database identifiers are missing for some scan records; their
              Details links are unavailable. Check that the server supports
              include_id=1.
            </p>
          ) : null}
          {scopeAddr && error ? (
            <ReportStatus error={error} />
          ) : (
            <HostCardList
              hosts={hosts}
              loading={isLoading}
              error={error as Error | null}
              highlights={highlights}
              onAddFilter={addFilter}
              getDetailsLink={getDetailsLink}
              showDates={sectionId === "active"}
              hoveredIndex={showTimeline ? hoveredIndex : null}
              onHover={showTimeline ? setHoveredIndex : undefined}
              registerCardRef={showTimeline ? registerCardRef : undefined}
            />
          )}
          {showPagination && scopeAddr ? (
            <ReportPagination
              loaded={hosts.length}
              total={totalCount}
              skip={skip}
              previousSkip={previousSkip}
              onSkipChange={setSkip}
            />
          ) : showPagination ? (
            <HostPagination
              loaded={hosts.length}
              limit={limit}
              skip={skip}
              total={totalCount}
              onSkipChange={setSkip}
            />
          ) : null}
        </div>
      </div>
    </div>
  );
}

function HostPagination({
  loaded,
  limit,
  skip,
  total,
  onSkipChange,
}: {
  loaded: number;
  limit: number;
  skip: number;
  total?: number;
  onSkipChange: (skip: number) => void;
}) {
  const { first, last, atStart, atEnd, lastSkip } = computePagination({
    loaded,
    limit,
    skip,
    total,
  });

  return (
    <nav
      aria-label="Pagination"
      className="flex flex-wrap items-center justify-between gap-3 pt-1 text-sm text-muted-foreground"
    >
      <span>
        {loaded === 0 ? (
          <>
            No results on this page
            {total !== undefined ? ` of ${total}` : null}
          </>
        ) : (
          <>
            Showing {first} to {last}
            {total !== undefined ? ` of ${total}` : null}
          </>
        )}
      </span>
      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="icon"
          className="size-8"
          disabled={atStart}
          onClick={() => onSkipChange(0)}
          aria-label="First page"
        >
          <ChevronsLeft className="size-4" aria-hidden />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="size-8"
          disabled={atStart}
          onClick={() => onSkipChange(skip - limit)}
          aria-label="Previous page"
        >
          <ChevronLeft className="size-4" aria-hidden />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="size-8"
          disabled={atEnd}
          onClick={() => onSkipChange(skip + limit)}
          aria-label="Next page"
        >
          <ChevronRight className="size-4" aria-hidden />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="size-8"
          disabled={atEnd || total === undefined}
          onClick={() => onSkipChange(lastSkip)}
          aria-label="Last page"
        >
          <ChevronsRight className="size-4" aria-hidden />
        </Button>
      </div>
    </nav>
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
