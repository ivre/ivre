import cytoscape, { type ElementDefinition } from "cytoscape";
import { useEffect, useMemo, useRef } from "react";

import type { FlowEdge, FlowGraph as FlowGraphData, FlowNode } from "@/lib/api";

export interface FlowGraphProps {
  graph: FlowGraphData;
  /** Click handler for nodes; receives the node id (the host's
   *  IP address). The route opens the detail sheet on this. */
  onSelectNode?: (id: string) => void;
  /** Click handler for edges; receives the edge id (the
   *  underlying flow document's ``_id`` in default mode, or a
   *  synthetic key in flow_map / talk_map). */
  onSelectEdge?: (id: string) => void;
}

/**
 * Cytoscape-backed force-directed graph for the Flow section.
 *
 * Nodes are hosts; edges are flows. Initial positions come from
 * the backend's per-response random ``x`` / ``y`` floats in
 * ``[0, 1)``; cytoscape's ``cose`` layout then converges from
 * there. Click handlers let the route open a detail sheet for
 * the selected element.
 *
 * The widget owns its cytoscape instance for the lifetime of the
 * containing route. New ``graph`` props are diffed and applied
 * incrementally (cytoscape's ``json()`` import) rather than
 * tearing down and re-creating the renderer, so panning / zoom /
 * selection are preserved across refreshes.
 */
export function FlowGraph({ graph, onSelectNode, onSelectEdge }: FlowGraphProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  // Memoise the cytoscape elements list so the effect that pushes
  // them into the renderer fires only when the graph identity
  // changes \u2014 not on every parent re-render.
  const elements = useMemo<ElementDefinition[]>(
    () => graphToElements(graph),
    [graph],
  );

  // One-time mount: spin up cytoscape, wire selection callbacks.
  useEffect(() => {
    if (!containerRef.current) return;
    const cy = cytoscape({
      container: containerRef.current,
      style: STYLE,
      // Disable automatic layout on init; we run it ourselves
      // after the first elements are pushed in.
      layout: { name: "preset" },
      wheelSensitivity: 0.2,
    });
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // Bind / rebind selection callbacks whenever the prop
  // identities change.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const handleNodeTap = (evt: cytoscape.EventObject) => {
      onSelectNode?.(evt.target.id());
    };
    const handleEdgeTap = (evt: cytoscape.EventObject) => {
      onSelectEdge?.(evt.target.id());
    };
    cy.on("tap", "node", handleNodeTap);
    cy.on("tap", "edge", handleEdgeTap);
    return () => {
      cy.off("tap", "node", handleNodeTap);
      cy.off("tap", "edge", handleEdgeTap);
    };
  }, [onSelectNode, onSelectEdge]);

  // Push the elements in whenever they change. ``json()`` does a
  // diff-and-patch internally, so existing positions / selection
  // are preserved when only a subset of the graph changes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
    });
    // Re-run the layout on every refresh; the ``cose`` family
    // accepts initial positions from the imported elements'
    // ``position`` field, so the random-ish backend coordinates
    // act as a starting hint.
    cy.layout({
      name: "cose",
      // Quick (not iteration-bound) initial layout; users can
      // drag-fix nodes after for more readable graphs.
      animate: false,
      // ``cose`` uses ``randomize`` to ignore preset positions
      // when true; we want the backend's hint to count.
      randomize: false,
      fit: true,
      padding: 24,
      // ``cose`` is the only layout shipped with cytoscape core;
      // ``fcose`` / ``cola`` would be add-on packages. For MVP
      // ``cose`` is good enough at the WEB_GRAPH_LIMIT (1000)
      // edge ceiling.
    } as cytoscape.LayoutOptions).run();
  }, [elements]);

  return (
    <div
      ref={containerRef}
      role="img"
      aria-label={`Flow graph (${graph.nodes.length} nodes, ${graph.edges.length} edges)`}
      className="h-full min-h-[28rem] w-full rounded-md border border-border bg-muted/20"
    />
  );
}

/** Translate a backend ``FlowGraph`` into the
 *  ``ElementDefinition[]`` cytoscape consumes. The backend
 *  emits ``x`` / ``y`` in ``[0, 1)``; we scale to a comfortable
 *  pixel range (-500..500) so the ``cose`` layout's first pass
 *  starts from a varied seed instead of all-at-origin. */
function graphToElements(graph: FlowGraphData): ElementDefinition[] {
  const out: ElementDefinition[] = [];
  for (const n of graph.nodes) {
    out.push(nodeToElement(n));
  }
  for (const e of graph.edges) {
    out.push(edgeToElement(e));
  }
  return out;
}

function nodeToElement(n: FlowNode): ElementDefinition {
  return {
    group: "nodes",
    data: {
      id: n.id,
      label: n.label,
      addr: n.data.addr,
    },
    position: {
      x: (n.x - 0.5) * 1000,
      y: (n.y - 0.5) * 1000,
    },
  };
}

function edgeToElement(e: FlowEdge): ElementDefinition {
  return {
    group: "edges",
    data: {
      id: e.id,
      label: e.label,
      source: e.source,
      target: e.target,
      // Carry a few derived fields onto the cytoscape element so
      // styles can vary by protocol later (e.g. dotted UDP).
      proto: e.data.proto,
    },
  };
}

/** Static cytoscape stylesheet. Uses Tailwind-aligned colors via
 *  CSS variables would be ideal, but cytoscape resolves styles
 *  at render time and doesn't read ``var(--...)`` natively;
 *  pick palette values that read in both light and dark themes
 *  (mid-blue + neutral grey). */
const STYLE: cytoscape.StylesheetCSS[] = [
  {
    selector: "node",
    css: {
      "background-color": "#3b82f6",
      "border-color": "#1e3a8a",
      "border-width": 1,
      label: "data(label)",
      "font-size": 11,
      "text-valign": "bottom",
      "text-halign": "center",
      "text-margin-y": 4,
      color: "#475569",
      width: 14,
      height: 14,
    },
  },
  {
    selector: "node:selected",
    css: {
      "background-color": "#f97316",
      "border-color": "#9a3412",
    },
  },
  {
    selector: "edge",
    css: {
      width: 1.5,
      "line-color": "#94a3b8",
      "target-arrow-color": "#94a3b8",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "font-size": 9,
      label: "data(label)",
      color: "#64748b",
      "text-rotation": "autorotate",
      "text-margin-y": -6,
    },
  },
  {
    selector: "edge:selected",
    css: {
      "line-color": "#f97316",
      "target-arrow-color": "#f97316",
      width: 2.5,
    },
  },
  {
    // Dim everything when something is selected.
    selector: ".faded",
    css: {
      opacity: 0.25,
    },
  },
];
