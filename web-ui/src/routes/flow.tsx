import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { FlowDetailSheet } from "@/components/FlowDetailSheet";
import { FlowFilterPanel } from "@/components/FlowFilterPanel";
import { FlowGraph } from "@/components/FlowGraph";
import {
  type FlowQuery,
  useFlowCounts,
  useFlowGraph,
} from "@/lib/api";
import { getSection } from "@/lib/sections";

/** Default number of edges to render in the flow graph. Matches
 *  ``WEB_GRAPH_LIMIT`` on the server and the legacy AngularJS
 *  bundle's hard-coded ``query.limit = 1000``. The page-list
 *  default (``WEB_LIMIT`` = 10, exposed as ``window.config
 *  .dflt_limit``) is *not* the right default here \u2014 a
 *  graph with 10 random edges is rarely useful. */
const FLOW_DEFAULT_LIMIT = 1000;

/**
 * Flow section route. The Flow surface is shaped differently
 * from the other data sections \u2014 the backend's
 * ``/cgi/flows`` endpoint returns a graph (``{nodes, edges}``)
 * rather than a record list, takes a JSON-encoded ``q=``
 * carrying two parallel filter lists (``nodes`` / ``edges``),
 * and has no facet / map companion. This route mirrors the
 * legacy AngularJS UI's "Explore" tab feature set: dual filter
 * inputs, mode dropdown (default / flow_map / talk_map),
 * after / before time bounds, limit / skip, counts header,
 * graph canvas, and click-for-details.
 *
 * Filter state lives in the URL search params (``?q=<JSON>``)
 * so the page is shareable / bookmarkable. The currently-open
 * detail (when a node or edge is selected) lives in
 * ``?detail=<type>:<id>``.
 */
export function FlowRoute() {
  const section = getSection("flow");
  if (!section) {
    return <div className="p-8">Flow section not configured.</div>;
  }
  return <FlowRouteInner />;
}

function FlowRouteInner() {
  const [searchParams, setSearchParams] = useSearchParams();

  // Applied filter (decoded from ``?q=``). The hook below
  // consumes it directly; refetch happens whenever the URL
  // changes.
  const applied = useMemo<FlowQuery>(
    () => decodeQuery(searchParams.get("q")),
    [searchParams],
  );

  // Working draft state owned by the panel. Initialised from
  // the URL so reloads / shared links land on a consistent
  // form. Diverges from ``applied`` while the user is
  // typing; flushed on Apply.
  const [draft, setDraft] = useState<FlowQuery>(() => decodeQuery(
    searchParams.get("q"),
  ));

  // Re-sync the draft when the URL changes from outside this
  // route (e.g. browser back/forward).
  useEffect(() => {
    setDraft(decodeQuery(searchParams.get("q")));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams.get("q")]);

  const apply = useCallback(() => {
    const params = new URLSearchParams(searchParams);
    const cleaned = stripEmpty(draft);
    if (Object.keys(cleaned).length === 0) {
      params.delete("q");
    } else {
      params.set("q", JSON.stringify(cleaned));
    }
    setSearchParams(params, { replace: false });
  }, [draft, searchParams, setSearchParams]);

  // Effective query for the data hooks: applied + sensible
  // defaults so a fresh page load renders something useful even
  // when the URL has no ``?q=``. The flow route's pagination is
  // graph-scale (``WEB_GRAPH_LIMIT`` = 1000), not list-scale
  // (``WEB_LIMIT`` = 10), so ``dflt_limit`` is *not* the right
  // default here; pin to 1000 to match the legacy AngularJS
  // bundle and the route's own ``WEB_GRAPH_LIMIT`` fallback.
  //
  // ``skip`` is forced to 0: older servers (pre-fix) defaulted
  // ``skip`` to ``WEB_GRAPH_LIMIT`` when omitted \u2014 a
  // copy-paste bug that made every initial page load skip
  // past the entire result set, surfacing as
  // ``"0 nodes, 0 edges. No flows match the current filter."``
  // even when the counts header reported hundreds of flows.
  // Sending ``skip=0`` explicitly bypasses the bug on those
  // older servers; new servers default to 0 anyway.
  const effective = useMemo<FlowQuery>(
    () => ({
      ...applied,
      limit: applied.limit ?? FLOW_DEFAULT_LIMIT,
      skip: applied.skip ?? 0,
    }),
    [applied],
  );

  const graphQuery = useFlowGraph(effective);
  const countsQuery = useFlowCounts(effective);

  // Detail-sheet selection encoded as ``?detail=<type>:<id>``.
  // Nullable; ``null`` closes the sheet.
  const detailParam = searchParams.get("detail");
  const selection = useMemo(() => parseDetail(detailParam), [detailParam]);
  const setSelection = useCallback(
    (next: { type: "node" | "edge"; id: string } | null) => {
      const params = new URLSearchParams(searchParams);
      if (next === null) {
        params.delete("detail");
      } else {
        params.set("detail", `${next.type}:${next.id}`);
      }
      setSearchParams(params, { replace: false });
    },
    [searchParams, setSearchParams],
  );

  return (
    <div className="flex w-full gap-6 px-6 py-2">
      <aside className="hidden w-[28rem] shrink-0 lg:block">
        <div className="sticky top-14 max-h-[calc(100vh-3.5rem)] space-y-6 overflow-y-auto pr-2 pt-2">
          <FlowFilterPanel
            draft={draft}
            onDraftChange={setDraft}
            onApply={apply}
            counts={countsQuery.data}
            isFetching={countsQuery.isFetching || graphQuery.isFetching}
            isError={Boolean(countsQuery.error || graphQuery.error)}
          />
        </div>
      </aside>
      <div className="flex flex-1 flex-col">
        <div className="mb-2 flex items-baseline justify-between">
          <h2 className="text-xl font-semibold">
            Flow graph
            {graphQuery.data ? (
              <span className="ml-2 text-sm font-normal text-muted-foreground">
                ({graphQuery.data.nodes.length} nodes,{" "}
                {graphQuery.data.edges.length} edges)
              </span>
            ) : null}
          </h2>
        </div>
        <div className="lg:hidden">
          <FlowFilterPanel
            draft={draft}
            onDraftChange={setDraft}
            onApply={apply}
            counts={countsQuery.data}
            isFetching={countsQuery.isFetching || graphQuery.isFetching}
            isError={Boolean(countsQuery.error || graphQuery.error)}
          />
        </div>
        {graphQuery.isLoading ? (
          <p className="text-sm italic text-muted-foreground">
            Loading flow graph\u2026
          </p>
        ) : graphQuery.error ? (
          <p className="text-sm text-destructive">
            Error: {(graphQuery.error as Error).message}
          </p>
        ) : graphQuery.data ? (
          graphQuery.data.nodes.length === 0 ? (
            <p className="text-sm italic text-muted-foreground">
              No flows match the current filter.
            </p>
          ) : (
            <div className="flex-1 min-h-[36rem]">
              <FlowGraph
                graph={graphQuery.data}
                onSelectNode={(id) => setSelection({ type: "node", id })}
                onSelectEdge={(id) => setSelection({ type: "edge", id })}
              />
            </div>
          )
        ) : null}
      </div>
      <FlowDetailSheet
        selection={selection}
        onClose={() => setSelection(null)}
      />
    </div>
  );
}

/** Parse the URL ``?q=...`` parameter into a :type:`FlowQuery`.
 *  Tolerates an empty / missing / malformed value by returning
 *  the empty filter, so a hand-crafted bookmark with a typo
 *  still loads the page (rather than throwing). */
function decodeQuery(raw: string | null): FlowQuery {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

/** Drop ``undefined`` / empty-array / empty-string fields so the
 *  URL stays compact when the user hasn't filled in everything. */
function stripEmpty(query: FlowQuery): FlowQuery {
  const out: FlowQuery = {};
  for (const [k, v] of Object.entries(query) as Array<
    [keyof FlowQuery, FlowQuery[keyof FlowQuery]]
  >) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v) && v.length === 0) continue;
    (out as Record<string, unknown>)[k] = v;
  }
  return out;
}

/** Parse the ``?detail=<type>:<id>`` URL parameter into a
 *  selection object. Returns ``null`` for an absent / malformed
 *  value. */
function parseDetail(
  raw: string | null,
): { type: "node" | "edge"; id: string } | null {
  if (!raw) return null;
  const idx = raw.indexOf(":");
  if (idx <= 0) return null;
  const type = raw.slice(0, idx);
  const id = raw.slice(idx + 1);
  if (type !== "node" && type !== "edge") return null;
  if (!id) return null;
  return { type, id };
}
