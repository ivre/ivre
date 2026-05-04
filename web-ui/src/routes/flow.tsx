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
import { getConfig } from "@/lib/config";
import { getSection } from "@/lib/sections";

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
  const config = getConfig();
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

  // Effective query for the data hooks: applied + the default
  // ``limit`` from ``window.config`` (or the WEB_GRAPH_LIMIT
  // server fallback the route picks if absent).
  const effective = useMemo<FlowQuery>(
    () => ({
      ...applied,
      limit: applied.limit ?? config.dflt_limit ?? 1000,
    }),
    [applied, config.dflt_limit],
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
