import { CloudUpload, ScrollText, ShieldAlert, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import type { AuditEvent, AuditEventType } from "@/lib/audit";
import { formatTimestamp } from "@/lib/format";

export interface AuditEventsTableProps {
  events: readonly AuditEvent[];
  /** Whether to render an ``actor`` column.  False on the
   *  self-service surface (every row is the caller); true on the
   *  admin surface (rows span every user). */
  showActor: boolean;
}

/**
 * Read-only table of audit events.  Shared by
 * :func:`AuditEventsPanel` (self-service, every row is the
 * caller) and :func:`AdminAuditEventsPanel` (cross-user; renders
 * the ``actor.user_email`` column).
 *
 * Step-1 scope per the post-#1887 backlog: plain DOM scrolling,
 * no virtualization.  The load-more pagination caps the loaded
 * row count at a multiple of :data:`AUDIT_PAGE_SIZE`; on a
 * production-grade deployment a hot trail is bounded by
 * ``WEB_MAXRESULTS`` per fetch and the operator can stop
 * loading at any time.  The Explorer (Step 2) wires
 * ``@tanstack/react-virtual`` for the full filter set, where
 * thousands of rows can land in a single render.
 */
export function AuditEventsTable({
  events,
  showActor,
}: AuditEventsTableProps) {
  if (events.length === 0) {
    return (
      <p
        className="text-sm italic text-muted-foreground"
        data-testid="audit-events-empty"
      >
        No audit events match this filter.
      </p>
    );
  }
  return (
    <div className="space-y-2" data-testid="audit-events-list">
      {events.map((ev) => (
        <AuditEventRow
          key={ev.event_id}
          event={ev}
          showActor={showActor}
        />
      ))}
    </div>
  );
}

function AuditEventRow({
  event,
  showActor,
}: {
  event: AuditEvent;
  showActor: boolean;
}) {
  return (
    <Card
      className="border-gray-200/60 py-0 shadow-none dark:border-blue-950/60"
      data-testid="audit-events-row"
      data-event-id={event.event_id}
    >
      <CardContent className="space-y-1 p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex items-center gap-2">
              <EventTypeBadge type={event.event_type} />
              {event.resource.method ? (
                <Badge variant="outline" className="font-mono text-xs">
                  {event.resource.method}
                </Badge>
              ) : null}
              {event.resource.route ? (
                <span className="truncate font-mono text-xs text-muted-foreground">
                  {event.resource.route}
                </span>
              ) : null}
              <OutcomeBadge outcome={event.outcome} />
            </div>
            {showActor ? (
              <div className="text-xs">
                <span className="text-muted-foreground">by </span>
                <span className="font-mono">
                  {event.actor.user_email ?? (
                    <span className="italic text-muted-foreground">
                      anonymous
                    </span>
                  )}
                </span>
                {event.actor.remote_addr ? (
                  <span className="text-muted-foreground">
                    {" "}
                    from{" "}
                    <span className="font-mono">
                      {event.actor.remote_addr}
                    </span>
                  </span>
                ) : null}
              </div>
            ) : event.actor.remote_addr ? (
              <div className="text-xs text-muted-foreground">
                from{" "}
                <span className="font-mono">
                  {event.actor.remote_addr}
                </span>
              </div>
            ) : null}
            <DetailsLine details={event.details} />
            <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
              <span title={event.created_at}>
                {formatTimestamp(event.created_at)}
              </span>
              <span className="font-mono" title={event.event_id}>
                #{event.event_id.slice(0, 8)}
              </span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function EventTypeBadge({ type }: { type: AuditEventType }) {
  // Three event types map to three lucide icons + tone classes;
  // anything unknown (future event types added server-side
  // ahead of the client) falls through to the default tone so
  // the row still renders without a runtime error.
  switch (type) {
    case "upload":
      return (
        <Badge
          variant="default"
          className="bg-blue-600 hover:bg-blue-600"
          data-testid="audit-events-type-badge"
          data-event-type={type}
        >
          <CloudUpload className="size-3" aria-hidden />
          upload
        </Badge>
      );
    case "admin_action":
      return (
        <Badge
          variant="default"
          className="bg-purple-600 hover:bg-purple-600"
          data-testid="audit-events-type-badge"
          data-event-type={type}
        >
          <ShieldCheck className="size-3" aria-hidden />
          admin
        </Badge>
      );
    case "oversize_query":
      return (
        <Badge
          variant="default"
          className="bg-amber-600 hover:bg-amber-600"
          data-testid="audit-events-type-badge"
          data-event-type={type}
        >
          <ShieldAlert className="size-3" aria-hidden />
          oversize
        </Badge>
      );
    default:
      return (
        <Badge
          variant="outline"
          data-testid="audit-events-type-badge"
          data-event-type={type}
        >
          <ScrollText className="size-3" aria-hidden />
          {type}
        </Badge>
      );
  }
}

function OutcomeBadge({ outcome }: { outcome: number | string | null }) {
  if (outcome === null || outcome === undefined) return null;
  // Heuristic: HTTP-status-like integers colour by class; any
  // other shape (a string code, a domain-specific value) gets
  // the neutral outline so a future producer adding a non-HTTP
  // outcome still renders cleanly.
  if (typeof outcome === "number") {
    const cls =
      outcome >= 200 && outcome < 300
        ? "border-green-500/40 text-green-700 dark:text-green-300"
        : outcome >= 400 && outcome < 500
        ? "border-yellow-500/40 text-yellow-700 dark:text-yellow-300"
        : outcome >= 500
        ? "border-red-500/40 text-red-700 dark:text-red-300"
        : "border-gray-400/40 text-muted-foreground";
    return (
      <Badge variant="outline" className={`font-mono text-xs ${cls}`}>
        {outcome}
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="font-mono text-xs">
      {outcome}
    </Badge>
  );
}

function DetailsLine({ details }: { details: Record<string, unknown> }) {
  // Render a one-line ``key=value`` projection of the details
  // dict.  Audit ``details`` is intentionally schema-flexible
  // per event type (see :class:`ivre.db.DBAudit`); a generic
  // ``key=value`` render keeps Step 1 backend-agnostic without
  // hard-coding per-event-type field maps.  Step 2's Explorer
  // can grow a per-row expander with full JSON.
  const entries = Object.entries(details).filter(
    ([, v]) => v !== null && v !== undefined && v !== "",
  );
  if (entries.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2 text-xs">
      {entries.map(([k, v]) => (
        <span
          key={k}
          className="rounded border border-border bg-muted/40 px-1.5 py-0.5 font-mono"
        >
          <span className="text-muted-foreground">{k}=</span>
          <span>{formatDetailValue(v)}</span>
        </span>
      ))}
    </div>
  );
}

function formatDetailValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  // Arrays / objects: compact JSON, truncated so a hostile or
  // verbose ``details`` blob does not blow up the row layout.
  try {
    const s = JSON.stringify(value);
    return s.length > 80 ? `${s.slice(0, 77)}…` : s;
  } catch {
    return String(value);
  }
}
