import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Recursive collapsible domain tree.
 *
 * Given a set of host records' ``hostnames[*].domains`` arrays
 * (each entry is the longest-first list of domain components — e.g.
 * ``["foo.example.com", "example.com", "com"]``), build a tree
 * keyed by domain, with the top-most node being the TLD and leaves
 * being full hostnames. Clicking a leaf adds a ``hostname:`` filter;
 * clicking an internal node adds a ``domain:`` filter.
 */

interface DomainNode {
  /** Full domain at this level (e.g. ``com``, ``example.com``,
   *  ``foo.example.com``). */
  name: string;
  /** Direct children, keyed by their full name. */
  children: Map<string, DomainNode>;
  /** True when this node was reached via a host's ``hostnames[*].name``
   *  rather than ``domains[]`` — i.e. when it represents an actual
   *  full hostname rather than a synthetic TLD/domain ancestor. */
  isLeaf: boolean;
  /** Number of leaves at or below this node. */
  count: number;
}

export interface DomainTreeProps {
  /** Each entry is the full ``domains`` chain of one hostname,
   *  longest-first (e.g. ``["foo.example.com", "example.com", "com"]``). */
  hostnames: ReadonlyArray<{
    name: string;
    domains?: readonly string[];
  }>;
  /** Click handlers for the two filter modes. */
  onAddDomainFilter?: (domain: string) => void;
  onAddHostnameFilter?: (hostname: string) => void;
  /** Domains/hostnames currently in the active filter; matching
   *  nodes get a yellow highlight. Lower-case keys. */
  highlightedDomains?: ReadonlySet<string>;
  highlightedHostnames?: ReadonlySet<string>;
}

function buildTree(
  hostnames: DomainTreeProps["hostnames"],
): Map<string, DomainNode> {
  const roots = new Map<string, DomainNode>();
  for (const entry of hostnames) {
    if (!entry.name) continue;
    // Domains come longest-first; reverse so the TLD is first.
    const path: string[] = entry.domains ? [...entry.domains].reverse() : [];
    // Then append the full hostname so it lives as a leaf.
    if (path[path.length - 1] !== entry.name) {
      path.push(entry.name);
    }

    let layer = roots;
    let parent: DomainNode | undefined;
    for (let i = 0; i < path.length; i++) {
      const segment = path[i];
      let node = layer.get(segment);
      if (!node) {
        node = { name: segment, children: new Map(), isLeaf: false, count: 0 };
        layer.set(segment, node);
      }
      parent = node;
      layer = node.children;
    }
    if (parent) {
      parent.isLeaf = true;
    }
  }
  // Compute counts depth-first.
  function tally(node: DomainNode): number {
    if (node.children.size === 0) {
      node.count = node.isLeaf ? 1 : 0;
      return node.count;
    }
    let sum = node.isLeaf ? 1 : 0;
    for (const child of node.children.values()) {
      sum += tally(child);
    }
    node.count = sum;
    return sum;
  }
  for (const node of roots.values()) {
    tally(node);
  }
  return roots;
}

export function DomainTree(props: DomainTreeProps) {
  const tree = buildTree(props.hostnames);
  if (tree.size === 0) return null;
  return (
    <ul className="space-y-1 text-sm">
      {Array.from(tree.values()).map((node) => (
        <DomainTreeNode key={node.name} node={node} {...props} />
      ))}
    </ul>
  );
}

function DomainTreeNode({
  node,
  onAddDomainFilter,
  onAddHostnameFilter,
  highlightedDomains,
  highlightedHostnames,
  hostnames,
}: { node: DomainNode } & DomainTreeProps) {
  const [expanded, setExpanded] = useState(false);
  const hasChildren = node.children.size > 0;
  const isHostname = node.isLeaf && !hasChildren;

  const lowered = node.name.toLowerCase();
  const highlighted = isHostname
    ? highlightedHostnames?.has(lowered)
    : highlightedDomains?.has(lowered);

  const onClick = () => {
    if (isHostname) {
      onAddHostnameFilter?.(node.name);
    } else {
      onAddDomainFilter?.(node.name);
    }
  };

  // The "+ N" suffix mimics the prototype's "+ com (+2)" pattern;
  // we show ``(+<count-1>)`` because the leaf hostname is itself
  // counted.
  const extra = hasChildren && node.count > 1 ? `+${node.count - 1}` : null;

  return (
    <li>
      <div className="flex items-center gap-1">
        {hasChildren ? (
          <Button
            variant="ghost"
            size="icon"
            className="size-5"
            aria-expanded={expanded}
            aria-label={expanded ? "Collapse" : "Expand"}
            onClick={(e) => {
              e.stopPropagation();
              setExpanded((v) => !v);
            }}
          >
            {expanded ? (
              <ChevronDown className="size-3" />
            ) : (
              <ChevronRight className="size-3" />
            )}
          </Button>
        ) : (
          <span className="inline-block size-5" aria-hidden />
        )}
        <button
          type="button"
          onClick={onClick}
          className={cn(
            "rounded px-1 font-mono text-xs hover:underline",
            highlighted && "bg-highlight text-highlight-foreground",
          )}
        >
          {node.name}
        </button>
        {extra ? (
          <span className="text-xs text-muted-foreground">({extra})</span>
        ) : null}
      </div>
      {hasChildren && expanded ? (
        <ul className="ml-4 mt-1 space-y-1 border-l border-border pl-2">
          {Array.from(node.children.values()).map((child) => (
            <DomainTreeNode
              key={child.name}
              node={child}
              hostnames={hostnames}
              onAddDomainFilter={onAddDomainFilter}
              onAddHostnameFilter={onAddHostnameFilter}
              highlightedDomains={highlightedDomains}
              highlightedHostnames={highlightedHostnames}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}
