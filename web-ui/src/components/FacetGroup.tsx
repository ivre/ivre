import { ChevronDown, ChevronRight } from "lucide-react";
import { useEffect, useRef, useState } from "react";

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
  /** When ``false``, the underlying ``useTop`` query is held back
   *  and the group renders the standard "Loading…" placeholder.
   *  Used by :class:`FacetSidebar` to serialize facet requests
   *  one at a time. Defaults to ``true``. */
  enabled?: boolean;
  /** Fired exactly once when the query transitions out of the
   *  pending state (either success or error), so the sidebar can
   *  release the next facet. */
  onLoaded?: () => void;
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
  enabled = true,
  onLoaded,
}: FacetGroupProps) {
  const [expanded, setExpanded] = useState(false);

  const limit = expanded ? EXPANDED_LIMIT : COLLAPSED_LIMIT;
  // ``isPending`` (not ``isLoading``) is the right "no data yet"
  // signal in React Query v5: a query held back with
  // ``enabled: false`` has ``isLoading === false`` (the request
  // is intentionally not in flight) but ``isPending === true``
  // (status is still ``"pending"``, no data has ever arrived).
  // Using ``isLoading`` here would make a held-back facet render
  // the "No values." empty-state instead of the "Loading…"
  // placeholder, defeating the sequential-loading UX.
  const { data, isPending, isSuccess, isError, error } = useTop(
    topEndpoint,
    field,
    { q: query, limit },
    { enabled },
  );

  // Notify the parent once per cycle so the sequential controller
  // can release the next facet. ``isSuccess`` terminates the
  // cycle; ``isError`` does too, EXCEPT when the error is an
  // ``AbortError`` raised because React Query cancelled the
  // ``fetch()`` (a filter change while the request was in flight,
  // a route unmount, or an explicit ``cancelQueries``). The new
  // cycle's :class:`FacetSidebar` has already reset
  // ``loadedCount`` to 0 via the ``query``-dependent
  // ``useEffect``; firing ``onLoaded`` from the cancelled cycle
  // would prematurely release one of the fresh cycle's facets
  // (advancing ``loadedCount`` with the previous cycle's index).
  // Successful cancellations are not failures from the operator's
  // point of view, so we silently drop them. A fresh
  // ``(field, topEndpoint, query, limit)`` tuple starts a new
  // cycle. ``onLoaded`` is deliberately *not* in the dep list —
  // parents like :class:`FacetSidebar` pass an inline
  // ``() => handleLoaded(index)`` that has a fresh identity on
  // every render, and we don't want each render to count as a
  // new cycle. We route the call through a ref so the latest
  // callback is always invoked even though the effect's closure
  // never mentions it.
  //
  // The ref is synced during render rather than in a
  // companion ``useEffect``: writing a ref during render is
  // safe for the sync-prop-into-ref pattern (we never *read*
  // the ref during render — only inside the post-commit
  // effect below), and it avoids a no-deps effect that would
  // otherwise re-run after every commit just to copy the
  // latest ``onLoaded`` over. Under Strict Mode's double-
  // render the assignment runs twice with the same value;
  // idempotent.
  //
  // The canonical fix for "I want a callback but its identity
  // shouldn't define the effect cycle" is React's
  // ``useEffectEvent``, but it's still experimental in 19.2 and
  // not exported from the stable ``react`` package — we'll
  // collapse this to ``useEffectEvent(onLoaded)`` once that ships.
  const onLoadedRef = useRef(onLoaded);
  onLoadedRef.current = onLoaded;
  // ``isAbort`` is derived at render time so the post-commit
  // effect below depends on a stable boolean instead of the
  // ``error`` instance.  React Query memoises ``error`` while a
  // query stays in the error state, so this is functionally
  // equivalent to listing ``error`` in the dep array today, but
  // it keeps the effect contract clean against future churn
  // (retries that recreate the error object, alternative result
  // shapes in a later React Query major, …) without relying on
  // the ratchet's ``Math.max`` idempotency to absorb spurious
  // re-fires.  The :class:`FacetSidebar` ratchet IS idempotent
  // (``setLoadedCount((c) => Math.max(c, index + 1))``); we treat
  // that as belt-and-braces, not as the primary correctness
  // story for this effect.
  const isAbort =
    isError && error instanceof DOMException && error.name === "AbortError";
  useEffect(() => {
    if (!enabled) return;
    if (isSuccess) {
      onLoadedRef.current?.();
      return;
    }
    // A cancellation propagated from the queryFn's
    // ``AbortSignal`` lands here as ``isError === true`` with
    // a ``DOMException`` whose ``name`` is ``"AbortError"``
    // (captured by ``isAbort`` above).  Skip the ratchet
    // advance in that case — the next cycle has already reset
    // the counter and a stale notify would mis-release one of
    // its facets.
    if (isError && !isAbort) onLoadedRef.current?.();
  }, [enabled, isSuccess, isError, isAbort, query, limit, field, topEndpoint]);

  const items: readonly TopValue[] = data ?? [];
  const max = items.reduce((m, x) => (x.value > m ? x.value : m), 1);
  const highlightSet = highlightSetFor(field, highlights);

  return (
    <div className="space-y-1">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </h3>
      {isPending ? (
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
