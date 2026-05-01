import { Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  buildQueryFromFilters,
  parseFiltersFromQuery,
  renderFilter,
  type Filter,
  FILTER_TYPES,
} from "@/lib/filter";
import { cn } from "@/lib/utils";

/* eslint-disable react-refresh/only-export-components --
 * The URL <-> filter helpers and the title-sync hook are tied
 * tightly to the FilterBar component's responsibilities; they are
 * intentionally co-located. The fast-refresh penalty is acceptable
 * here because the helpers are stable. */

export interface FilterBarProps {
  filters: readonly Filter[];
  onFiltersChange: (filters: Filter[]) => void;
}

/**
 * Free-text filter input + active filter chips.
 *
 * The user types tokens in IVRE filter syntax (``country:FR``,
 * ``port:tcp/443``, ``"tag:CDN:Cloudflare"``, …); pressing Enter
 * adds them to the active list. Suggestions appear as the user
 * types a colon-prefix (``coun`` → ``country:``).
 *
 * Active filters are rendered as chips that the user can remove by
 * clicking the trailing X.
 */
export function FilterBar({ filters, onFiltersChange }: FilterBarProps) {
  const [draft, setDraft] = useState("");

  const suggestions = useMemo(() => {
    const trimmed = draft.trim();
    if (!trimmed || trimmed.includes(":") || /\s/.test(trimmed)) {
      return [];
    }
    const lower = trimmed.toLowerCase();
    return FILTER_TYPES.filter((t) => t.startsWith(lower)).slice(0, 8);
  }, [draft]);

  const commit = () => {
    const trimmed = draft.trim();
    if (!trimmed) return;
    const newFilters = [...filters, ...parseFiltersFromQuery(trimmed)];
    onFiltersChange(newFilters);
    setDraft("");
  };

  const removeAt = (idx: number) => {
    onFiltersChange(filters.filter((_, i) => i !== idx));
  };

  return (
    <div className="space-y-2">
      <div className="relative">
        <Search
          className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          aria-label="Filter query"
          placeholder="country:FR port:tcp/443 …"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              commit();
            }
          }}
          className="pl-9"
        />
        {suggestions.length > 0 ? (
          <div className="absolute z-30 mt-1 w-full rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-md">
            {suggestions.map((s) => (
              <button
                key={s}
                type="button"
                className="block w-full rounded px-2 py-1 text-left text-sm hover:bg-accent"
                onClick={() => setDraft(`${s}:`)}
              >
                <span className="font-mono">{s}:</span>
              </button>
            ))}
          </div>
        ) : null}
      </div>
      {filters.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5">
          {filters.map((f, i) => (
            <FilterChip
              key={`${i}-${renderFilter(f)}`}
              filter={f}
              onRemove={() => removeAt(i)}
            />
          ))}
          {filters.length > 1 ? (
            <Button
              variant="link"
              size="sm"
              onClick={() => onFiltersChange([])}
            >
              Clear all
            </Button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function FilterChip({
  filter,
  onRemove,
}: {
  filter: Filter;
  onRemove: () => void;
}) {
  return (
    <Badge
      variant="secondary"
      className={cn(
        "gap-1 pl-2 pr-1 font-mono text-xs",
        filter.neg && "bg-red-100 text-red-900 dark:bg-red-900/40 dark:text-red-200",
      )}
    >
      {renderFilter(filter)}
      <button
        type="button"
        aria-label={`Remove filter ${renderFilter(filter)}`}
        onClick={onRemove}
        className="ml-1 inline-flex size-4 items-center justify-center rounded hover:bg-muted-foreground/20"
      >
        <X className="size-3" />
      </button>
    </Badge>
  );
}

/**
 * URL helpers — used by the View route to keep the hash in sync
 * with the filter list. Exported here for convenience and tested in
 * filter.test.ts (round-trip).
 */
export function filtersToHashSearch(filters: readonly Filter[]): string {
  const q = buildQueryFromFilters(filters);
  if (!q) return "";
  const params = new URLSearchParams({ q });
  return params.toString();
}

export function filtersFromHashSearch(search: string): Filter[] {
  if (!search) return [];
  const params = new URLSearchParams(
    search.startsWith("?") ? search.slice(1) : search,
  );
  return parseFiltersFromQuery(params.get("q") ?? "");
}

/** A noop hook that synchronises the document title with the
 *  current filter (placeholder for future SEO or accessibility
 *  improvements). */
export function useFilterTitle(filters: readonly Filter[]) {
  useEffect(() => {
    const q = buildQueryFromFilters(filters);
    document.title = q ? `IVRE — ${q}` : "IVRE";
  }, [filters]);
}
