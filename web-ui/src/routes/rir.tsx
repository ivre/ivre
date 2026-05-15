import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

import { FacetSidebar } from "@/components/FacetSidebar";
import { FilterBar, useFilterTitle } from "@/components/FilterBar";
import { RirRecordCard } from "@/components/RirRecordCard";
import { useRirRecords } from "@/lib/api";
import { getConfig, isSequentialLoading } from "@/lib/config";
import {
  buildHighlightMap,
  buildQueryFromFilters,
  parseFiltersFromQuery,
  type Filter,
} from "@/lib/filter";
import { getSection } from "@/lib/sections";

/**
 * RIR section: WHOIS / RPSL records imported from the RIR
 * dumps (AfriNIC, APNIC, ARIN, LACNIC, RIPE) via
 * ``ivre rirlookup --download --insert``. Two record families
 * coexist in the column:
 *
 *  - ``inet[6]num`` — a contiguous IP range with optional
 *    ``netname``, ``descr``, ``country``, ``org``, ``remarks``,
 *    etc.
 *  - ``aut-num`` — an Autonomous System number with
 *    ``as-name``, ``descr``, etc.
 *
 * The backend (``/cgi/rir``) sorts narrowest-range first by
 * default — a ``host:`` / ``net:`` / ``range:`` filter
 * naturally surfaces the most-specific allocation at the top.
 *
 * The facet sidebar uses ``country`` and ``source_file`` (the
 * RIR dump basename, e.g. ``ripe.db.inetnum.gz``); other RPSL
 * fields are reachable via free-text search (``search:``) or
 * via direct filter tokens such as ``asnum:``, ``asname:``,
 * ``sourcefile:``.
 */
export function RirRoute() {
  const section = getSection("rir");
  if (!section) {
    return <div className="p-8">RIR section not configured.</div>;
  }
  return <RirRouteInner />;
}

function RirRouteInner() {
  const section = getSection("rir")!;
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

  const sequential = isSequentialLoading();
  const recordsQuery = useRirRecords({ q: query, limit, skip: 0 });
  const { data: records = [], isLoading, error } = recordsQuery;
  // No map / timeline on RIR; gate facets directly on the results.
  // Scope note: ``isSuccess || isError`` only targets the
  // first-load / query-change cycle — background refetches are
  // not re-serialised. See the longer rationale in
  // ``routes/host-list.tsx``.
  const resultsDone = recordsQuery.isSuccess || recordsQuery.isError;
  const facetsEnabled = !sequential || resultsDone;

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
            sequential={sequential}
            enabled={facetsEnabled}
          />
        </div>
      </aside>
      <div className="flex flex-1 justify-center">
        <div className="w-full max-w-4xl space-y-4">
          <div className="flex items-baseline justify-between">
            <h2 className="text-xl font-semibold">
              RIR records
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
              Loading RIR records…
            </p>
          ) : error ? (
            <p className="text-sm text-destructive">
              Error: {(error as Error).message}
            </p>
          ) : records.length === 0 ? (
            <p className="text-sm italic text-muted-foreground">
              No matching RIR records.
            </p>
          ) : (
            <div className="space-y-3">
              {records.map((rec, idx) => (
                <RirRecordCard
                  key={rirRecordKey(rec, idx)}
                  record={rec}
                  highlights={highlights}
                  onAddFilter={addFilter}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** RIR records have no canonical id on the wire (``_id`` is
 *  stripped server-side). Synthesise a stable React key from
 *  the record's identifying field(s); fall back to the index
 *  on the off-chance two records share the same identity (a
 *  duplicated ingest would). */
function rirRecordKey(
  rec: import("@/lib/api").RirRecord,
  idx: number,
): string {
  if ("aut-num" in rec) return `as-${rec["aut-num"]}-${idx}`;
  if ("start" in rec && "stop" in rec) {
    return `inet-${rec.start}-${rec.stop}-${idx}`;
  }
  return `idx-${idx}`;
}
