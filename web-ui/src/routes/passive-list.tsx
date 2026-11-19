import { useCallback, useRef, useState } from "react";

import { FacetSidebar } from "@/components/FacetSidebar";
import { FilterBar, useFilterTitle } from "@/components/FilterBar";
import { PassiveRecordList } from "@/components/PassiveRecordList";
import { ReportPagination } from "@/components/ReportPagination";
import { ReportStatus } from "@/components/ReportStatus";
import { Timeline } from "@/components/Timeline";
import { type PassiveRecord, useCount, usePassiveRecords } from "@/lib/api";
import { getConfig, isSequentialLoading } from "@/lib/config";
import { formatResultsCount } from "@/lib/format";
import { describePassiveValue } from "@/lib/passive";
import { getSection } from "@/lib/sections";
import { formatTimelineRange } from "@/lib/timeline";
import { useBrowseFilters } from "@/lib/use-browse-filters";
import { usePageScroll } from "@/lib/use-page-scroll";
import { useReportPaging } from "@/lib/use-report-paging";
import { buildPagedQuery, parseUrlInt } from "@/lib/paging";
import { cn } from "@/lib/utils";

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
export function PassiveRoute({ scopeAddr }: { scopeAddr?: string }) {
  const section = getSection("passive");
  if (!section) {
    return <div className="p-8">Passive section not configured.</div>;
  }
  return <PassiveRouteInner scopeAddr={scopeAddr} />;
}

function PassiveRouteInner({ scopeAddr }: { scopeAddr?: string }) {
  const section = getSection("passive")!;
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
  } = useBrowseFilters("passive", scopeAddr);
  useFilterTitle(filters, !scopeAddr);

  const limit = scopeAddr
    ? Math.min(50, Math.max(1, config.dflt_limit || 25))
    : Number.parseInt(searchParams.get("limit") ?? "", 10) ||
      config.dflt_limit ||
      50;

  const skip = scopeAddr
    ? parseUrlInt(searchParams, "passiveSkip", { fallback: 0 })
    : 0;
  const { previousSkip, stateForSkip } = useReportPaging(
    "passive",
    query,
    limit,
    skip,
  );
  const sequential = isSequentialLoading();
  const recordsQuery = usePassiveRecords(section.listEndpoint, {
    q: scopeAddr
      ? buildPagedQuery(`${query} -sortby:lastseen`, limit, skip)
      : query,
    limit: scopeAddr ? undefined : limit,
    skip: scopeAddr ? undefined : 0,
  });
  const { data: records = [], isLoading, error } = recordsQuery;
  usePageScroll(
    !isLoading,
    typeof location.state?.restoreScrollY === "number"
      ? location.state.restoreScrollY
      : 0,
  );
  // Total number of records matching ``q=`` — drives the
  // ``loaded / total`` headline in the results header. Fires in
  // parallel with the records query; the hook is auto-gated off
  // when ``countEndpoint`` is undefined.
  const { data: totalCount } = useCount(section.countEndpoint, { q: query });
  // No map for Passive; the timeline derives from ``records`` on
  // the client so there's no intermediate request to wait for.
  // Facets are gated directly on the records query settling.
  // Scope note: ``isSuccess || isError`` only targets the
  // first-load / query-change cycle — background refetches are
  // not re-serialised. See the longer rationale in
  // ``routes/host-list.tsx``.
  const resultsDone = recordsQuery.isSuccess || recordsQuery.isError;
  const facetsEnabled = !sequential || resultsDone;

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
    <div
      className={cn("flex w-full min-w-0 gap-6 py-2", !scopeAddr && "px-6")}
      role={scopeAddr ? "region" : undefined}
      aria-label={scopeAddr ? "Passive observations for this IP" : undefined}
    >
      <aside
        className={cn(
          "hidden shrink-0 lg:block",
          scopeAddr ? "w-[21rem]" : "w-[28rem]",
        )}
      >
        <div className="sticky top-14 max-h-[calc(100vh-3.5rem)] space-y-6 overflow-y-auto pr-2 pt-2">
          {/*
            Timeline lives in the left rail (mirroring the world
            map's spot in the View section). Hovering a row syncs
            with the corresponding card via ``hoveredIndex``;
            clicking a row scrolls the card into view.
          */}
          <Timeline
            records={records}
            hoveredIndex={hoveredIndex}
            onHover={setHoveredIndex}
            onSelect={scrollToCard}
            getTitle={passiveTimelineTitle}
            itemLabel={{
              singular: "passive observation",
              plural: "passive observations",
            }}
            emptyLabel="No passive observations to plot."
          />
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
      <div className="flex min-w-0 flex-1 justify-center">
        <div className="w-full min-w-0 max-w-4xl space-y-4">
          <div className="flex items-baseline justify-between">
            <h2 className="text-xl font-semibold">
              Observations
              {!isLoading && !error ? (
                <span className="ml-2 text-sm font-normal text-muted-foreground">
                  ({formatResultsCount(records.length, totalCount)})
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
            {scopeAddr ? (
              <Timeline
                records={records}
                hoveredIndex={hoveredIndex}
                onHover={setHoveredIndex}
                onSelect={scrollToCard}
                getTitle={passiveTimelineTitle}
                itemLabel={{
                  singular: "passive observation",
                  plural: "passive observations",
                }}
                emptyLabel="No passive observations to plot."
                titleId="host-passive-mobile-timeline-title"
              />
            ) : null}
          </div>
          {scopeAddr && error ? (
            <ReportStatus error={error} />
          ) : (
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
          )}
          {scopeAddr && !isLoading && !error ? (
            <ReportPagination
              loaded={records.length}
              total={totalCount}
              skip={skip}
              previousSkip={previousSkip}
              onSkipChange={(value) => {
                const params = new URLSearchParams(searchParams);
                if (value) params.set("passiveSkip", String(value));
                else params.delete("passiveSkip");
                setSearchParams(params, { state: stateForSkip(value) });
              }}
            />
          ) : null}
        </div>
      </div>
    </div>
  );
}

/** Per-row tooltip body for the passive timeline. Composed
 *  outside the component so the memoised ``computeLayout`` in
 *  ``<Timeline>`` reuses it across renders. */
function passiveTimelineTitle(record: PassiveRecord, density: number): string {
  const display = describePassiveValue(record);
  const heading = display.heading
    ? `${display.heading}: ${display.primary}`
    : `${record.recontype}: ${record.value}`;
  return [
    heading,
    formatTimelineRange(record),
    `count=${record.count} · density≈${density.toFixed(3)}/s`,
  ].join("\n");
}
