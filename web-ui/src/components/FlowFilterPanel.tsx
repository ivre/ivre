import { Loader2, Play } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { FlowCounts, FlowMode, FlowQuery } from "@/lib/api";
import { cn } from "@/lib/utils";

/** Tiny inline replacement for the shadcn ``Label`` component
 *  (which isn't installed). Style mirrors the standard
 *  text-sm / font-medium / muted-foreground combo other forms
 *  use. */
function Label({
  htmlFor,
  children,
}: {
  htmlFor?: string;
  children: React.ReactNode;
}) {
  return (
    <label
      htmlFor={htmlFor}
      className="text-xs font-semibold uppercase tracking-wide text-muted-foreground"
    >
      {children}
    </label>
  );
}

export interface FlowFilterPanelProps {
  /** Working draft of the filter query \u2014 mutated locally as
   *  the user types. The route applies it to the URL on Apply. */
  draft: FlowQuery;
  onDraftChange: (next: FlowQuery) => void;
  /** Apply the draft to the URL (and trigger a refetch). */
  onApply: () => void;
  /** Counts header. ``undefined`` while the first request is in
   *  flight; never updated to ``null`` so we can disambiguate. */
  counts?: FlowCounts;
  /** Loading flags so the panel can disable Apply / show a
   *  spinner. */
  isFetching: boolean;
  isError: boolean;
}

/**
 * Left-rail filter form for the Flow section. Mirrors the
 * legacy AngularJS UI's "Explore" tab: two textareas for the
 * node / edge ``flow.Query`` filter clauses, plus mode, time
 * window, limit, and skip. The whole thing is a controlled
 * form: ``draft`` is the working state, ``onApply`` flushes it
 * to the URL.
 *
 * The textareas accept one filter clause per line, matching the
 * legacy bundle's whitespace-tolerant parser \u2014 the React
 * route splits on newlines + trims when it serialises ``draft``
 * into the JSON-encoded ``q.nodes`` / ``q.edges`` arrays.
 */
export function FlowFilterPanel({
  draft,
  onDraftChange,
  onApply,
  counts,
  isFetching,
  isError,
}: FlowFilterPanelProps) {
  const update = <K extends keyof FlowQuery>(key: K, value: FlowQuery[K]) =>
    onDraftChange({ ...draft, [key]: value });

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        onApply();
      }}
    >
      <CountsHeader counts={counts} isFetching={isFetching} isError={isError} />

      <div className="space-y-1">
        <Label htmlFor="flow-node-filters">Node filters</Label>
        <textarea
          id="flow-node-filters"
          value={(draft.nodes ?? []).join("\n")}
          onChange={(e) =>
            update("nodes", splitFilters(e.target.value))
          }
          className={cn(
            "min-h-20 w-full rounded-md border border-input bg-transparent",
            "px-3 py-2 font-mono text-xs shadow-sm",
            "placeholder:text-muted-foreground",
            "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
          )}
          placeholder={"# one clause per line, e.g.\naddr =~ 192.168.0.0/16"}
          spellCheck={false}
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="flow-edge-filters">Edge filters</Label>
        <textarea
          id="flow-edge-filters"
          value={(draft.edges ?? []).join("\n")}
          onChange={(e) =>
            update("edges", splitFilters(e.target.value))
          }
          className={cn(
            "min-h-20 w-full rounded-md border border-input bg-transparent",
            "px-3 py-2 font-mono text-xs shadow-sm",
            "placeholder:text-muted-foreground",
            "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
          )}
          placeholder={
            "# one clause per line, e.g.\nproto = tcp\ndport = 443\nmeta.http"
          }
          spellCheck={false}
        />
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label htmlFor="flow-mode">Mode</Label>
          <select
            id="flow-mode"
            value={draft.mode ?? "default"}
            onChange={(e) => update("mode", e.target.value as FlowMode)}
            className={cn(
              "h-9 w-full rounded-md border border-input bg-transparent",
              "px-2 text-sm shadow-sm",
              "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
            )}
          >
            <option value="default">Default</option>
            <option value="flow_map">Flow map</option>
            <option value="talk_map">Talk map</option>
          </select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="flow-orderby">Order by</Label>
          <select
            id="flow-orderby"
            value={draft.orderby ?? ""}
            onChange={(e) =>
              update(
                "orderby",
                (e.target.value || null) as FlowQuery["orderby"],
              )
            }
            className={cn(
              "h-9 w-full rounded-md border border-input bg-transparent",
              "px-2 text-sm shadow-sm",
              "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
            )}
          >
            <option value="">(none)</option>
            <option value="src">Source</option>
            <option value="dst">Destination</option>
            <option value="flow">Flow</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label htmlFor="flow-after">After</Label>
          <Input
            id="flow-after"
            type="datetime-local"
            value={toDatetimeLocal(draft.after)}
            onChange={(e) =>
              update("after", fromDatetimeLocal(e.target.value))
            }
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="flow-before">Before</Label>
          <Input
            id="flow-before"
            type="datetime-local"
            value={toDatetimeLocal(draft.before)}
            onChange={(e) =>
              update("before", fromDatetimeLocal(e.target.value))
            }
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label htmlFor="flow-limit">Limit</Label>
          <Input
            id="flow-limit"
            type="number"
            min={1}
            value={draft.limit ?? ""}
            onChange={(e) =>
              update(
                "limit",
                e.target.value === "" ? undefined : Number(e.target.value),
              )
            }
            placeholder="1000"
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="flow-skip">Skip</Label>
          <Input
            id="flow-skip"
            type="number"
            min={0}
            value={draft.skip ?? ""}
            onChange={(e) =>
              update(
                "skip",
                e.target.value === "" ? undefined : Number(e.target.value),
              )
            }
            placeholder="0"
          />
        </div>
      </div>

      <Button type="submit" disabled={isFetching} className="w-full">
        {isFetching ? (
          <>
            <Loader2 className="size-4 animate-spin" />
            Loading\u2026
          </>
        ) : (
          <>
            <Play className="size-4" />
            Apply
          </>
        )}
      </Button>
    </form>
  );
}

function CountsHeader({
  counts,
  isFetching,
  isError,
}: {
  counts?: FlowCounts;
  isFetching: boolean;
  isError: boolean;
}) {
  if (isError) {
    return (
      <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
        Failed to load flow counts.
      </div>
    );
  }
  if (!counts) {
    return (
      <div className="rounded-md border border-border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
        {isFetching ? "Loading\u2026" : "Apply a filter to load flows."}
      </div>
    );
  }
  return (
    <div className="grid grid-cols-3 gap-2 text-center">
      <CountTile label="Clients" value={counts.clients} />
      <CountTile label="Servers" value={counts.servers} />
      <CountTile label="Flows" value={counts.flows} />
    </div>
  );
}

function CountTile({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-2 py-1.5">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="font-mono text-base">{value.toLocaleString()}</div>
    </div>
  );
}

/** Split textarea content into one filter clause per non-empty
 *  trimmed line. Keeps blank-line tolerance so users can group
 *  clauses visually without polluting the wire ``q.nodes`` /
 *  ``q.edges`` arrays. */
function splitFilters(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/** Convert the wire ``"YYYY-MM-DD HH:MM"`` shape \u2014 what the
 *  ``/cgi/flows`` route expects in ``q.before`` / ``q.after`` \u2014
 *  to the ``"YYYY-MM-DDTHH:MM"`` shape an ``<input
 *  type="datetime-local">`` consumes. Returns ``""`` for
 *  ``undefined`` so the input renders empty. */
function toDatetimeLocal(wire: string | undefined): string {
  if (!wire) return "";
  return wire.replace(" ", "T");
}

/** Inverse of :func:`toDatetimeLocal`: ``""`` means "clear the
 *  field", emitted as ``undefined`` so the route omits it from
 *  the wire query entirely. */
function fromDatetimeLocal(local: string): string | undefined {
  if (!local) return undefined;
  return local.replace("T", " ");
}
