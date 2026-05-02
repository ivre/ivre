import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { type TopValue, useTop } from "@/lib/api";
import { createFilter, displayLabel } from "@/lib/field-mapper";
import type { Filter, HighlightMap } from "@/lib/filter";
import { cn } from "@/lib/utils";

export interface FacetGroupProps {
  /** The ``top`` endpoint root (e.g. ``/cgi/view/top``). */
  topEndpoint: string;
  /** Field path (e.g. ``country``, ``port:open``). */
  field: string;
  /** Display label for the group. */
  label: string;
  /** Active filter list, rendered as the ``q=…`` parameter. */
  query: string;
  /** Used to highlight rows that correspond to active filters. */
  highlights?: HighlightMap;
  /** Click-to-add-filter callback. */
  onAddFilter: (filter: Filter) => void;
}

const COLLAPSED_LIMIT = 5;
const EXPANDED_LIMIT = 50;

/**
 * One facet group: a heading + a list of clickable count rows with
 * a relative-width bar behind each row.
 */
export function FacetGroup({
  topEndpoint,
  field,
  label,
  query,
  highlights,
  onAddFilter,
}: FacetGroupProps) {
  const [expanded, setExpanded] = useState(false);

  const limit = expanded ? EXPANDED_LIMIT : COLLAPSED_LIMIT;
  const { data, isLoading, error } = useTop(topEndpoint, field, {
    q: query,
    limit,
  });

  const items: readonly TopValue[] = data ?? [];
  const max = items.reduce((m, x) => (x.value > m ? x.value : m), 1);
  const highlightSet = highlightSetFor(field, highlights);

  return (
    <div className="space-y-1">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </h3>
      {isLoading ? (
        <p className="text-xs italic text-muted-foreground">Loading…</p>
      ) : error ? (
        <p className="text-xs text-destructive">Error: {error.message}</p>
      ) : items.length === 0 ? (
        <p className="text-xs italic text-muted-foreground">No values.</p>
      ) : (
        <ul className="space-y-0.5">
          {items.slice(0, COLLAPSED_LIMIT + (expanded ? EXPANDED_LIMIT : 0)).map(
            (item, idx) => (
              <FacetRow
                key={`${field}-${idx}`}
                item={item}
                field={field}
                max={max}
                highlightSet={highlightSet}
                onClick={() => {
                  const f = createFilter(field, item.label);
                  if (f) onAddFilter(f);
                }}
              />
            ),
          )}
        </ul>
      )}
      {items.length >= COLLAPSED_LIMIT ? (
        <Button
          variant="link"
          size="sm"
          className="px-1"
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded ? (
            <>
              <ChevronDown className="size-3" />
              Show less
            </>
          ) : (
            <>
              <ChevronRight className="size-3" />
              Show more
            </>
          )}
        </Button>
      ) : null}
    </div>
  );
}

function FacetRow({
  item,
  field,
  max,
  highlightSet,
  onClick,
}: {
  item: TopValue;
  field: string;
  max: number;
  highlightSet?: Set<string>;
  onClick: () => void;
}) {
  const display = displayLabel(field, item.label);
  const filterValue = highlightKey(field, item.label);
  const highlighted = filterValue
    ? highlightSet?.has(filterValue.toLowerCase())
    : false;
  const widthPercent = Math.max(2, Math.round((item.value / max) * 100));

  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        className={cn(
          "relative flex w-full items-center gap-2 rounded px-2 py-1 text-left text-sm hover:bg-accent",
          highlighted &&
            "bg-highlight text-highlight-foreground hover:brightness-95 dark:hover:brightness-110",
        )}
      >
        <span
          className="absolute left-0 top-0 h-full rounded bg-primary/10 dark:bg-primary/20"
          style={{ width: `${widthPercent}%` }}
          aria-hidden
        />
        <span className="relative flex-1 truncate">{display}</span>
        <span className="relative text-xs tabular-nums text-muted-foreground">
          {item.value}
        </span>
      </button>
    </li>
  );
}

/** Map a field name to the highlight-map key produced by
 *  ``buildHighlightMap``. */
function highlightSetFor(
  field: string,
  highlights: HighlightMap | undefined,
): Set<string> | undefined {
  if (!highlights) return undefined;
  const base = field.replace(/:\d+$/, "");
  const key =
    base === "as"
      ? "asnum"
      : base.startsWith("port:")
        ? "port"
        : base === "domains"
          ? "domain"
          : base === "hostnames"
            ? "hostname"
            : base;
  return highlights.get(key);
}

/** Compute the ``filter.value`` that ``createFilter`` would produce
 *  for this row; used to decide whether the row is highlighted. */
function highlightKey(
  field: string,
  label: TopValue["label"],
): string | null {
  const f = createFilter(field, label);
  return f?.value ?? null;
}
