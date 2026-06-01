import { useVirtualizer } from "@tanstack/react-virtual";
import { Loader2, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { AuditEventRow } from "@/components/AuditEventsTable";
import { AuditEventDetailSheet } from "@/components/AuditEventDetailSheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  isoToLocalInput,
  localInputToIso,
  sanitizeWhen,
  useAuditCount,
  useAuditEvent,
  useAuditEvents,
  type AuditEvent,
  type AuditEventType,
  type AuditFilters,
} from "@/lib/audit";
import { formatQueryError, formatResultsCount } from "@/lib/format";

const EVENT_TYPE_CHOICES: ReadonlyArray<{
  value: string;
  label: string;
}> = [
  { value: "all", label: "All event types" },
  { value: "upload", label: "Upload" },
  { value: "admin_action", label: "Admin action" },
  { value: "oversize_query", label: "Oversize query" },
];

const EVENT_TYPE_VALUES = new Set<string>([
  "upload",
  "admin_action",
  "oversize_query",
]);

/**
 * Full audit-log Explorer.  Mounted at ``/audit/explorer`` and
 * reached from the Admin "Audit log" tab (admins) or directly
 * (any authenticated user — the backend forces ``user_email``
 * to the caller for non-admins).  This is the Step-2 surface of
 * the post-#1887 web-ui work: the full filter set
 * (``event_type`` / ``user_email`` / ``since`` / ``until``), a
 * virtualized result list, and a deep-linkable single-event
 * detail sheet.
 *
 * URL state (via :func:`useSearchParams`) carries every filter
 * plus the selected event id:
 *
 *   ``?type=`` ``?user=`` ``?since=`` ``?until=`` ``?event=``
 *
 * so a reload / back-forward / shared permalink reproduces the
 * exact view.  ``since`` / ``until`` are stored as canonical UTC
 * ISO strings (what the backend and a future ``auditcli``
 * invocation both accept — the groundwork for the #6 parity
 * item); the ``datetime-local`` inputs convert to/from the
 * browser's local zone.
 *
 * Pagination is the same ``useInfiniteQuery`` load-more the
 * Step-1 panels use; the rendered rows are virtualized with
 * ``@tanstack/react-virtual`` so a large filtered result set
 * stays responsive.
 */
export function AuditExplorer() {
  const [searchParams, setSearchParams] = useSearchParams();

  const rawType = searchParams.get("type") ?? "all";
  const eventType: AuditEventType | undefined = EVENT_TYPE_VALUES.has(rawType)
    ? (rawType as AuditEventType)
    : undefined;
  const userEmail = searchParams.get("user") ?? "";
  // Sanitize the time bounds on read: a malformed ``?since`` /
  // ``?until`` (hand-edited or stale permalink) is treated as
  // unset rather than forwarded to the backend, which would
  // reject it with HTTP 400 and leave the blank input
  // inconsistent with the URL.
  const since = sanitizeWhen(searchParams.get("since"));
  const until = sanitizeWhen(searchParams.get("until"));

  const filters: AuditFilters = {
    event_type: eventType,
    user_email: userEmail || undefined,
    since: since || undefined,
    until: until || undefined,
  };

  const eventsQuery = useAuditEvents(filters);
  const countQuery = useAuditCount(filters);

  const events = eventsQuery.data?.pages.flat() ?? [];

  // -- URL helpers ------------------------------------------------
  // Functional updater so the mutation always rebuilds from the
  // *latest* params at apply time.  This matters for the
  // debounced user-email commit below: a timer scheduled against
  // one render must not clobber filter changes (type / since /
  // until) made before it fires.
  const patchParams = (
    mutate: (p: URLSearchParams) => void,
    opts: { replace?: boolean } = {},
  ) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        mutate(next);
        return next;
      },
      { replace: opts.replace ?? false },
    );
  };

  const setEventType = (value: string) =>
    patchParams((p) => {
      if (value === "all") p.delete("type");
      else p.set("type", value);
    });

  const setSince = (localValue: string) =>
    patchParams((p) => {
      const iso = localInputToIso(localValue);
      if (iso) p.set("since", iso);
      else p.delete("since");
    });

  const setUntil = (localValue: string) =>
    patchParams((p) => {
      const iso = localInputToIso(localValue);
      if (iso) p.set("until", iso);
      else p.delete("until");
    });

  // -- user_email debounce ----------------------------------------
  // Commit the typed value to the URL 300ms after the last
  // keystroke.  The timer applies the change through a functional
  // ``setSearchParams`` updater (reading the latest params at
  // apply time), so a pending commit never overwrites filter
  // changes the operator made in the meantime.  ``setSearchParams``
  // is identity-stable, so the deps are exhaustive without a
  // suppression.
  const [userInput, setUserInput] = useState(userEmail);
  useEffect(() => {
    const timer = setTimeout(() => {
      const trimmed = userInput.trim();
      if (trimmed === userEmail) return;
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (trimmed) next.set("user", trimmed);
          else next.delete("user");
          return next;
        },
        { replace: true },
      );
    }, 300);
    return () => clearTimeout(timer);
  }, [userInput, userEmail, setSearchParams]);
  useEffect(() => {
    setUserInput(userEmail);
  }, [userEmail]);

  const anyFilterActive =
    eventType !== undefined || !!userEmail || !!since || !!until;
  const clearAll = () =>
    patchParams((p) => {
      p.delete("type");
      p.delete("user");
      p.delete("since");
      p.delete("until");
    });

  // -- detail-sheet resolution ------------------------------------
  // Normalize an empty ``?event=`` to ``null``: otherwise the
  // sheet would open (``open={selectedId !== null}``) on an empty
  // string while the single-event query stays disabled, leaving a
  // blank sheet.  ``null`` keeps the sheet closed when no id is
  // selected.
  const selectedId = searchParams.get("event") || null;
  const listSelected =
    events.find((ev) => ev.event_id === selectedId) ?? null;
  // Fall back to the single-event endpoint when the selected id
  // is not on a loaded page (deep link / out-of-window).  Keep
  // the query disabled when the list already carries it so we do
  // not hit the network for nothing.
  const fallbackEnabled = selectedId !== null && listSelected === null;
  const fallbackQuery = useAuditEvent(selectedId, {
    enabled: fallbackEnabled,
  });
  const selectedEvent = listSelected ?? fallbackQuery.data ?? null;

  const openEvent = (id: string) =>
    patchParams((p) => p.set("event", id));
  const closeSheet = () =>
    patchParams((p) => p.delete("event"), { replace: true });

  return (
    <div className="space-y-4">
      <FilterToolbar
        eventType={rawType}
        onEventType={setEventType}
        userInput={userInput}
        onUserInput={setUserInput}
        since={since}
        until={until}
        onSince={setSince}
        onUntil={setUntil}
        anyFilterActive={anyFilterActive}
        onClearAll={clearAll}
      />

      {eventsQuery.isLoading ? (
        <p
          className="text-sm italic text-muted-foreground"
          role="status"
          aria-label="Loading audit events"
          data-testid="audit-explorer-loading"
        >
          Loading audit events…
        </p>
      ) : eventsQuery.error ? (
        <div
          className="rounded border border-destructive/40 bg-destructive/10 p-4 text-sm"
          data-testid="audit-explorer-error"
        >
          <p className="text-destructive">
            Failed to load audit events: {formatQueryError(eventsQuery.error)}
          </p>
          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            onClick={() => eventsQuery.refetch()}
          >
            Retry
          </Button>
        </div>
      ) : (
        <>
          <p
            className="text-sm text-muted-foreground"
            data-testid="audit-explorer-header"
          >
            Showing{" "}
            <span className="font-medium text-foreground">
              {formatResultsCount(events.length, countQuery.data)}
            </span>{" "}
            {events.length === 1 ? "event" : "events"}
          </p>

          {events.length === 0 ? (
            <p
              className="rounded border border-dashed border-muted py-12 text-center text-sm italic text-muted-foreground"
              data-testid="audit-explorer-empty"
            >
              No audit events match the current filters.
            </p>
          ) : (
            <VirtualEventList
              events={events}
              selectedId={selectedId}
              onSelect={openEvent}
            />
          )}

          {eventsQuery.hasNextPage ? (
            <div className="pt-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  void eventsQuery.fetchNextPage();
                }}
                disabled={eventsQuery.isFetchingNextPage}
                data-testid="audit-explorer-load-more"
              >
                {eventsQuery.isFetchingNextPage ? (
                  <>
                    <Loader2 className="size-4 animate-spin" aria-hidden />
                    Loading…
                  </>
                ) : (
                  "Load more"
                )}
              </Button>
            </div>
          ) : null}
        </>
      )}

      <AuditEventDetailSheet
        event={selectedEvent}
        isLoading={fallbackEnabled && fallbackQuery.isLoading}
        error={fallbackEnabled ? fallbackQuery.error : null}
        open={selectedId !== null}
        onOpenChange={(open) => {
          if (!open) closeSheet();
        }}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Filter toolbar                                                     */
/* ------------------------------------------------------------------ */

function FilterToolbar({
  eventType,
  onEventType,
  userInput,
  onUserInput,
  since,
  until,
  onSince,
  onUntil,
  anyFilterActive,
  onClearAll,
}: {
  eventType: string;
  onEventType: (v: string) => void;
  userInput: string;
  onUserInput: (v: string) => void;
  since: string;
  until: string;
  onSince: (v: string) => void;
  onUntil: (v: string) => void;
  anyFilterActive: boolean;
  onClearAll: () => void;
}) {
  return (
    <div
      className="flex flex-wrap items-end gap-3"
      data-testid="audit-explorer-toolbar"
    >
      <label className="flex flex-col gap-1 text-xs text-muted-foreground">
        Event type
        {/* Native <select>: a fixed, tiny option set; the native
         *  element brings keyboard / mobile affordances for free
         *  (same rationale as NotesRoute). */}
        <select
          value={eventType}
          onChange={(e) => onEventType(e.target.value)}
          aria-label="Event type filter"
          data-testid="audit-explorer-type-select"
          className="h-9 rounded-md border border-input bg-transparent px-3 text-sm shadow-xs"
        >
          {EVENT_TYPE_CHOICES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
      </label>

      <label className="flex flex-col gap-1 text-xs text-muted-foreground">
        User email
        <Input
          type="email"
          autoComplete="off"
          placeholder="any user"
          value={userInput}
          onChange={(e) => onUserInput(e.target.value)}
          aria-label="Filter by user email"
          data-testid="audit-explorer-user-input"
          className="h-9 w-56"
        />
      </label>

      <label className="flex flex-col gap-1 text-xs text-muted-foreground">
        Since
        <Input
          type="datetime-local"
          value={isoToLocalInput(since)}
          onChange={(e) => onSince(e.target.value)}
          aria-label="Filter from (since)"
          data-testid="audit-explorer-since-input"
          className="h-9"
        />
      </label>

      <label className="flex flex-col gap-1 text-xs text-muted-foreground">
        Until
        <Input
          type="datetime-local"
          value={isoToLocalInput(until)}
          onChange={(e) => onUntil(e.target.value)}
          aria-label="Filter until"
          data-testid="audit-explorer-until-input"
          className="h-9"
        />
      </label>

      {anyFilterActive ? (
        <Button
          variant="outline"
          size="sm"
          onClick={onClearAll}
          aria-label="Clear all filters"
          data-testid="audit-explorer-clear"
          className="h-9"
        >
          <X className="size-4" aria-hidden />
          Clear
        </Button>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Virtualized list                                                   */
/* ------------------------------------------------------------------ */

function VirtualEventList({
  events,
  selectedId,
  onSelect,
}: {
  events: readonly AuditEvent[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: events.length,
    getScrollElement: () => parentRef.current,
    // Rows have variable height (details / actor lines wrap);
    // ``estimateSize`` seeds the layout and ``measureElement``
    // corrects each row to its real height after mount.
    estimateSize: () => 96,
    overscan: 8,
  });

  return (
    <div
      ref={parentRef}
      className="max-h-[60vh] overflow-auto"
      data-testid="audit-explorer-scroll"
    >
      <div
        style={{
          height: virtualizer.getTotalSize(),
          position: "relative",
          width: "100%",
        }}
      >
        {virtualizer.getVirtualItems().map((item) => {
          const ev = events[item.index];
          return (
            <div
              key={ev.event_id}
              data-index={item.index}
              ref={virtualizer.measureElement}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                transform: `translateY(${item.start}px)`,
                paddingBottom: 8,
              }}
            >
              <AuditEventRow
                event={ev}
                showActor
                selected={ev.event_id === selectedId}
                onSelect={() => onSelect(ev.event_id)}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}
