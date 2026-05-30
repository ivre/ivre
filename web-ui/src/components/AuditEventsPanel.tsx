import { Loader2 } from "lucide-react";

import { AuditEventsTable } from "@/components/AuditEventsTable";
import { Button } from "@/components/ui/button";
import { useAuditCount, useAuditEvents } from "@/lib/audit";
import { formatQueryError, formatResultsCount } from "@/lib/format";

/**
 * Self-service read-only audit panel.  Renders the caller's own
 * audit trail; relies on the backend's per-user gate (the route
 * forces ``user_email = <caller>`` for non-admins) so no
 * client-side filter UI is necessary here.
 *
 * Cross-user / admin variant lives in
 * :func:`AdminAuditEventsPanel`; both share
 * :func:`AuditEventsTable` for the row rendering.
 *
 * Pagination is load-more (per the post-#1887 backlog Step 1
 * scope): the panel fetches one page at a time, the operator
 * clicks ``Load more`` to advance ``skip += AUDIT_PAGE_SIZE``.
 * Cap is server-side via ``WEB_MAXRESULTS``; the button hides
 * itself once the last page is short.
 */
export function AuditEventsPanel() {
  // Empty filter dict: the per-user scope is forced server-side
  // by :func:`ivre.web.app._audit_read_gate` for non-admins,
  // so the self-service panel does not need to (and must not,
  // to keep the "minimal contract" intact) supply one.
  const eventsQuery = useAuditEvents({});
  const countQuery = useAuditCount({});

  if (eventsQuery.isLoading) {
    return (
      <p
        className="text-sm italic text-muted-foreground"
        data-testid="audit-events-loading"
        role="status"
        aria-label="Loading audit events"
      >
        Loading audit events…
      </p>
    );
  }
  if (eventsQuery.error) {
    return (
      <p
        className="text-sm text-destructive"
        data-testid="audit-events-error"
      >
        Error: {formatQueryError(eventsQuery.error)}
      </p>
    );
  }

  const events = eventsQuery.data?.pages.flat() ?? [];
  const total = countQuery.data;
  const loaded = events.length;
  const hasMore = eventsQuery.hasNextPage === true;
  const isFetchingMore = eventsQuery.isFetchingNextPage === true;

  return (
    <div className="space-y-3">
      <div
        className="flex items-baseline justify-between gap-3"
        data-testid="audit-events-header"
      >
        <p className="text-sm text-muted-foreground">
          Showing{" "}
          <span className="font-medium text-foreground">
            {formatResultsCount(loaded, total)}
          </span>{" "}
          {loaded === 1 ? "event" : "events"}
        </p>
      </div>
      <AuditEventsTable events={events} showActor={false} />
      {hasMore ? (
        <div className="pt-1">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void eventsQuery.fetchNextPage();
            }}
            disabled={isFetchingMore}
            data-testid="audit-events-load-more"
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
    </div>
  );
}
