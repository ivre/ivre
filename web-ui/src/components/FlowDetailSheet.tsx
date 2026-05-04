import { Loader2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  type FlowEdgeDetails,
  type FlowHostDetails,
  useFlowDetails,
} from "@/lib/api";

export interface FlowDetailSheetProps {
  /** Selection in ``"<type>:<id>"`` form, where type is
   *  ``"node"`` (id is the host's IP address) or ``"edge"`` (id
   *  is the underlying flow document's ``_id``). ``null`` when
   *  the sheet is closed. */
  selection: { type: "node" | "edge"; id: string } | null;
  onClose: () => void;
}

/**
 * Read-only details panel for a flow element. Opens whenever
 * ``selection`` is non-null; fetches
 * ``GET /cgi/flows?action=details&q={type, id}`` lazily via
 * react-query and renders the response shape.
 *
 *  - For nodes: lists ``in_flows`` / ``out_flows`` / clients /
 *    servers as chip groups, plus the host's first/last-seen
 *    timestamps.
 *  - For edges: surfaces every field on the underlying flow
 *    document (counters, ports, ``firstseen`` / ``lastseen``)
 *    plus a per-protocol ``meta`` block when ``FLOW_STORE_METADATA``
 *    is enabled server-side.
 */
export function FlowDetailSheet({ selection, onClose }: FlowDetailSheetProps) {
  const detailsQuery = useFlowDetails(selection?.type, selection?.id);

  const isNode = selection?.type === "node";
  const title = selection
    ? isNode
      ? `Host ${selection.id}`
      : `Flow ${selection.id}`
    : "";

  return (
    <Sheet
      open={selection !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent
        side="right"
        className="w-full overflow-y-auto sm:max-w-xl"
      >
        <SheetHeader>
          <SheetTitle className="font-mono">{title}</SheetTitle>
          <SheetDescription>
            {isNode
              ? "Aggregated flows in/out of this host."
              : "Details for the selected flow."}
          </SheetDescription>
        </SheetHeader>

        {detailsQuery.isLoading ? (
          <div className="flex items-center gap-2 px-4 py-6 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
            Loading\u2026
          </div>
        ) : detailsQuery.error ? (
          <p className="px-4 py-6 text-sm text-destructive">
            Error: {(detailsQuery.error as Error).message}
          </p>
        ) : detailsQuery.data ? (
          isNode ? (
            <NodeDetails data={detailsQuery.data as FlowHostDetails} />
          ) : (
            <EdgeDetails data={detailsQuery.data as FlowEdgeDetails} />
          )
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

function NodeDetails({ data }: { data: FlowHostDetails }) {
  const elt = data.elt;
  return (
    <div className="space-y-4 px-4 py-2 text-sm">
      <KeyValueGrid
        rows={[
          ["addr", elt.addr],
          ["firstseen", elt.firstseen],
          ["lastseen", elt.lastseen],
        ]}
      />
      <ChipGroup label="In flows" items={data.in_flows.map(formatFlow)} />
      <ChipGroup label="Out flows" items={data.out_flows.map(formatFlow)} />
      <ChipGroup label="Clients" items={data.clients} />
      <ChipGroup label="Servers" items={data.servers} />
    </div>
  );
}

function EdgeDetails({ data }: { data: FlowEdgeDetails }) {
  const rows = Object.entries(data.elt)
    .filter(([k]) => k !== "meta")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => [k, formatValue(v)] as const);
  return (
    <div className="space-y-4 px-4 py-2 text-sm">
      <KeyValueGrid rows={rows} />
      {data.meta ? <MetaBlock meta={data.meta} /> : null}
    </div>
  );
}

function MetaBlock({
  meta,
}: {
  meta: NonNullable<FlowEdgeDetails["meta"]>;
}) {
  return (
    <div className="space-y-3">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Protocol metadata
      </h3>
      {Object.entries(meta).map(([proto, fields]) => (
        <div key={proto} className="space-y-1">
          <div className="font-mono text-xs">{proto}</div>
          <KeyValueGrid
            rows={Object.entries(fields)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([k, v]) => [k, formatValue(v)] as const)}
          />
        </div>
      ))}
    </div>
  );
}

function ChipGroup({
  label,
  items,
}: {
  label: string;
  items: ReadonlyArray<string>;
}) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </h3>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item, idx) => (
          <Badge
            key={`${label}-${idx}-${item}`}
            variant="outline"
            className="font-mono text-xs"
          >
            {item}
          </Badge>
        ))}
      </div>
    </div>
  );
}

function KeyValueGrid({
  rows,
}: {
  rows: ReadonlyArray<readonly [string, string | number | null | undefined]>;
}) {
  if (rows.length === 0) return null;
  return (
    <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 font-mono text-xs">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="break-all">{v ?? "\u2014"}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Render a flow tuple as a string. Backend emits either
 *  ``[proto, dport]`` or the literal ``"TALK"`` (talk_map mode). */
function formatFlow(flow: [string, number] | string | unknown): string {
  if (Array.isArray(flow) && flow.length === 2) {
    return `${flow[0]}/${flow[1]}`;
  }
  return String(flow);
}

/** Render any nested value the backend might emit. JSON
 *  primitives stringify directly; arrays / objects fall back
 *  to a JSON dump for the detail sheet's read-only view. */
function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "\u2014";
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
    return String(v);
  }
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
