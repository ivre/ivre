import { Loader2, Search, X } from "lucide-react";
import { useState } from "react";

import { AuditEventsTable } from "@/components/AuditEventsTable";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  useAuditCount,
  useAuditEvents,
  type AuditFilters,
} from "@/lib/audit";
import { formatQueryError, formatResultsCount } from "@/lib/format";

/**
 * Admin-only cross-user audit panel.  Same row rendering as
 * :func:`AuditEventsPanel`, with one filter input added:
 * ``user_email`` (a text box, applied on Enter / button click,
 * cleared via the trailing ✕ button).
 *
 * Per the post-#1887 backlog Step-1 scope, the other axes
 * (``event_type`` / ``since`` / ``until``) are deferred to the
 * full Explorer page (Step 2).  The component is gated by the
 * Admin route's own ``is_admin`` check; the backend additionally
 * enforces the same gate at the route edge.
 */
export function AdminAuditEventsPanel() {
  // The Input is uncontrolled-feeling but actually controlled:
  // ``draft`` tracks the in-progress typed value, ``applied``
  // is the value passed to the query.  Decoupling them keeps
  // an inflight ``useAuditEvents`` from refetching on every
  // keystroke; the operator triggers an explicit apply via
  // Enter or the Search button.
  const [draft, setDraft] = useState("");
  const [applied, setApplied] = useState<string>("");

  const filters: AuditFilters = applied ? { user_email: applied } : {};
  const eventsQuery = useAuditEvents(filters);
  const countQuery = useAuditCount(filters);

  const apply = () => {
    const trimmed = draft.trim();
    setApplied(trimmed);
  };
  const clear = () => {
    setDraft("");
    setApplied("");
  };

  const events = eventsQuery.data?.pages.flat() ?? [];
  const total = countQuery.data;
  const loaded = events.length;
  const hasMore = eventsQuery.hasNextPage === true;
  const isFetchingMore = eventsQuery.isFetchingNextPage === true;

  return (
    <div className="space-y-4">
      <Card className="border-gray-200/60 py-0 shadow-none dark:border-blue-950/60">
        <CardContent className="p-4">
          <div className="mb-2 text-sm font-semibold">Filter by user</div>
          <div className="flex gap-1.5">
            <Input
              type="email"
              autoComplete="off"
              placeholder="alice@example.org (leave empty to see every user)"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  apply();
                }
              }}
              aria-label="Filter audit events by user email"
              data-testid="admin-audit-filter-input"
            />
            <Button
              variant="default"
              onClick={apply}
              aria-label="Apply user filter"
              data-testid="admin-audit-filter-apply"
            >
              <Search className="size-4" aria-hidden />
              Apply
            </Button>
            {applied ? (
              <Button
                variant="outline"
                onClick={clear}
                aria-label="Clear user filter"
                data-testid="admin-audit-filter-clear"
              >
                <X className="size-4" aria-hidden />
                Clear
              </Button>
            ) : null}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Admins see every user's audit trail.  Enter an email
            (and press Enter or click Apply) to narrow the list.
          </p>
        </CardContent>
      </Card>

      {eventsQuery.isLoading ? (
        <p
          className="text-sm italic text-muted-foreground"
          data-testid="admin-audit-loading"
          role="status"
          aria-label="Loading audit events"
        >
          Loading audit events…
        </p>
      ) : eventsQuery.error ? (
        <p
          className="text-sm text-destructive"
          data-testid="admin-audit-error"
        >
          Error: {formatQueryError(eventsQuery.error)}
        </p>
      ) : (
        <>
          <div
            className="flex items-baseline justify-between gap-3"
            data-testid="admin-audit-header"
          >
            <p className="text-sm text-muted-foreground">
              Showing{" "}
              <span className="font-medium text-foreground">
                {formatResultsCount(loaded, total)}
              </span>{" "}
              {loaded === 1 ? "event" : "events"}
              {applied ? (
                <>
                  {" for "}
                  <span className="font-mono text-foreground">
                    {applied}
                  </span>
                </>
              ) : null}
            </p>
          </div>
          <AuditEventsTable events={events} showActor />
          {hasMore ? (
            <div className="pt-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  void eventsQuery.fetchNextPage();
                }}
                disabled={isFetchingMore}
                data-testid="admin-audit-load-more"
              >
                {isFetchingMore ? (
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
    </div>
  );
}
