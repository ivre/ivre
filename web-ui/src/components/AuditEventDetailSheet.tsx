import type { ReactNode } from "react";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import type { AuditEvent } from "@/lib/audit";
import { formatQueryError, formatTimestamp } from "@/lib/format";

export interface AuditEventDetailSheetProps {
  /** The event to display.  ``null`` while loading / on error /
   *  when nothing is selected. */
  event: AuditEvent | null;
  /** True while the single-event fetch (deep-link path) is in
   *  flight. */
  isLoading?: boolean;
  /** Set when the single-event fetch failed (e.g. 404 for an
   *  unknown / out-of-scope id). */
  error?: Error | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Right-side slide-over showing the full record of a single
 * audit event: actor, resource, outcome, and the per-event
 * ``details`` blob rendered as formatted JSON.
 *
 * Deep-linkable from the Explorer via ``?event=<id>``; the
 * parent (:func:`AuditExplorer`) resolves the event either from
 * the already-loaded listing page (fast path) or via
 * :func:`useAuditEvent` (the ``GET /cgi/audit/<event_id>``
 * single-fetch fallback for ids outside the current page), and
 * passes the loading / error state through so a stale or
 * out-of-scope link surfaces a clear message instead of an
 * empty sheet.
 *
 * Read-only by design: the audit log is append-only and has no
 * mutation surface.
 */
export function AuditEventDetailSheet({
  event,
  isLoading,
  error,
  open,
  onOpenChange,
}: AuditEventDetailSheetProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full max-w-2xl overflow-y-auto sm:max-w-2xl"
        data-testid="audit-event-detail-sheet"
      >
        {event ? (
          <AuditEventDetailBody event={event} />
        ) : isLoading ? (
          <div
            className="px-1 py-6 text-sm italic text-muted-foreground"
            role="status"
            aria-label="Loading audit event"
            data-testid="audit-event-detail-loading"
          >
            Loading event…
          </div>
        ) : error ? (
          <div
            className="px-1 py-6"
            data-testid="audit-event-detail-error"
          >
            <SheetHeader className="pb-2">
              <SheetTitle>Event unavailable</SheetTitle>
              <SheetDescription>
                {formatQueryError(error)}
              </SheetDescription>
            </SheetHeader>
            <p className="px-1 text-sm text-muted-foreground">
              The event may have been purged, or the id may not be
              one you are permitted to view.
            </p>
          </div>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

function AuditEventDetailBody({ event }: { event: AuditEvent }) {
  return (
    <>
      <SheetHeader className="pb-2">
        <SheetTitle className="font-mono text-base">
          {event.event_type}
        </SheetTitle>
        <SheetDescription>
          <span title={event.created_at}>
            {formatTimestamp(event.created_at)}
          </span>{" "}
          ·{" "}
          <span
            className="font-mono"
            data-testid="audit-event-detail-id"
          >
            {event.event_id}
          </span>
        </SheetDescription>
      </SheetHeader>

      <dl className="space-y-3 px-1 py-3 text-sm">
        <Field label="Actor">
          <KeyVal k="user_email" v={event.actor.user_email} />
          <KeyVal k="api_key_hash" v={event.actor.api_key_hash} />
          <KeyVal k="remote_addr" v={event.actor.remote_addr} />
        </Field>
        <Field label="Resource">
          <KeyVal k="method" v={event.resource.method} />
          <KeyVal k="route" v={event.resource.route} />
        </Field>
        <Field label="Outcome">
          <span
            className="font-mono"
            data-testid="audit-event-detail-outcome"
          >
            {event.outcome === null || event.outcome === undefined
              ? "—"
              : String(event.outcome)}
          </span>
        </Field>
        <Field label="Details">
          <pre
            className="max-h-80 overflow-auto rounded border border-border bg-muted/40 p-2 font-mono text-xs"
            data-testid="audit-event-detail-json"
          >
            {JSON.stringify(event.details ?? {}, null, 2)}
          </pre>
        </Field>
      </dl>
    </>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="border-t pt-2">
      <dt className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </dt>
      <dd className="space-y-0.5">{children}</dd>
    </div>
  );
}

function KeyVal({ k, v }: { k: string; v: string | null }) {
  return (
    <div className="flex gap-2">
      <span className="w-28 shrink-0 font-mono text-xs text-muted-foreground">
        {k}
      </span>
      <span className="font-mono text-xs break-all">
        {v ?? <span className="italic text-muted-foreground">—</span>}
      </span>
    </div>
  );
}
