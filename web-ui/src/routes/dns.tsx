import { useCallback, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { DnsRecordCard } from "@/components/DnsRecordCard";
import { FilterBar, useFilterTitle } from "@/components/FilterBar";
import { Timeline } from "@/components/Timeline";
import { type DnsRecord, useDnsRecords } from "@/lib/api";
import { getConfig } from "@/lib/config";
import {
  buildHighlightMap,
  buildQueryFromFilters,
  parseFiltersFromQuery,
  type Filter,
} from "@/lib/filter";
import { formatTimelineRange } from "@/lib/timeline";

/**
 * DNS section: a merged view of every ``(name, addr)`` pair
 * observed across the active scan database (``db.nmap``) and
 * the passive observation database (``db.passive``). The data
 * is served by ``/cgi/dns`` — a dedicated route that runs
 * ``iter_dns`` on each backend and merges the results in
 * memory before paginating. See ``ivre/web/app.py``'s
 * ``get_dns`` for the backend implementation and the merge
 * semantics.
 *
 * The section has no facet sidebar (the ``/cgi/dns`` route
 * does not expose a ``top/<field>`` companion). Operators
 * narrow the result set by typing filter tokens in the
 * FilterBar — the same syntax the other sections use, applied
 * to *both* backends server-side. Filter tokens that are
 * meaningful on only one side (e.g. ``recontype:`` on
 * passive, ``port:`` on nmap) are silently dropped on the
 * other backend by ``flt_from_query``'s
 * ``hasattr(dbase, "searchXXX")`` gate.
 *
 * Records are sorted by the merged ``lastseen`` (most recent
 * first), with ``count`` as the tie-breaker.
 */
export function DnsRoute() {
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
  } = useDnsRecords({ q: query, limit, skip: 0 });

  // Timeline ↔ card cross-highlight wiring (mirrors the
  // pattern in ``routes/passive-list.tsx``). Hovering a card or
  // a timeline row sets ``hoveredIndex``; clicking a row
  // scrolls the corresponding card into view.
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
          <p className="text-xs text-muted-foreground">
            Filters apply to both the active (
            <span className="font-mono">db.nmap</span>) and passive (
            <span className="font-mono">db.passive</span>) backends. Tokens
            meaningful on only one side (e.g.{" "}
            <span className="font-mono">port:</span>,{" "}
            <span className="font-mono">recontype:</span>) are silently
            dropped on the other.
          </p>
        </div>
      </aside>
      <div className="flex flex-1 justify-center">
        <div className="w-full max-w-4xl space-y-4">
          <div className="flex items-baseline justify-between">
            <h2 className="text-xl font-semibold">
              DNS answers
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
          {isLoading ? (
            <p className="text-sm italic text-muted-foreground">
              Loading DNS records…
            </p>
          ) : error ? (
            <p className="text-sm text-destructive">
              Error: {(error as Error).message}
            </p>
          ) : records.length === 0 ? (
            <p className="text-sm italic text-muted-foreground">
              No matching DNS records.
            </p>
          ) : (
            <>
              <Timeline
                records={records}
                hoveredIndex={hoveredIndex}
                onHover={setHoveredIndex}
                onSelect={scrollToCard}
                getTitle={dnsTimelineTitle}
                itemLabel={{
                  singular: "DNS record",
                  plural: "DNS records",
                }}
                emptyLabel="No DNS records to plot."
              />
              <div className="space-y-3">
                {records.map((rec, idx) => (
                  <DnsRecordCard
                    key={`${rec.name}|${rec.addr}`}
                    record={rec}
                    highlights={highlights}
                    onAddFilter={addFilter}
                    highlighted={hoveredIndex === idx}
                    onHover={() => setHoveredIndex(idx)}
                    onLeave={() => setHoveredIndex(null)}
                    innerRef={(el) => registerCardRef(idx, el)}
                  />
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/** Per-row tooltip body for the DNS timeline. The merge key
 *  ``(name, addr)`` is the most useful identity to surface; the
 *  union of contributing types (and the raw count / density) go
 *  on the secondary lines. */
function dnsTimelineTitle(record: DnsRecord, density: number): string {
  const types =
    record.types.length > 0 ? ` [${record.types.join(", ")}]` : "";
  return [
    `${record.name} → ${record.addr}${types}`,
    formatTimelineRange(record),
    `count=${record.count} · density≈${density.toFixed(3)}/s`,
  ].join("\n");
}
