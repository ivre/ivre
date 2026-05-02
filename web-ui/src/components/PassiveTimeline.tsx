import { useMemo } from "react";

import type { PassiveRecord } from "@/lib/api";
import {
  formatPassiveRange,
  passiveDateMs,
  passiveDensity,
  passiveStrokeWidths,
} from "@/lib/passive";
import { cn } from "@/lib/utils";

export interface PassiveTimelineProps {
  records: readonly PassiveRecord[];
  /** Index of the currently-hovered record. The corresponding
   *  line is rendered with full opacity; the rest are dimmed.
   *  ``null`` means "no hover". */
  hoveredIndex: number | null;
  onHover: (index: number | null) => void;
  /** Optional click handler — used by the route to scroll the
   *  corresponding card into view. */
  onSelect?: (index: number) => void;
}

const SVG_HEIGHT_PER_ROW = 6;
const SVG_PADDING_Y = 4;
const SVG_PADDING_X = 8;
const VIEW_WIDTH = 1000;
const MIN_LINE_WIDTH_PX = 1;
const MAX_LINE_WIDTH_PX = 8;
/** Horizontal pixels reserved for instant (zero-duration) records
 *  rendered as a small ``<circle>`` at their single timestamp. */
const INSTANT_RADIUS_PX = 2.5;

/**
 * Horizontal SVG timeline of passive records.
 *
 * Each record is drawn as a horizontal line from its
 * ``firstseen`` to its ``lastseen``; the line's stroke-width is
 * proportional to its observation density (``count`` divided by
 * its duration in seconds, normalised against the maximum across
 * the visible set). Two records with the same ``count`` render
 * with thinner lines when their duration is longer; two records
 * with the same duration render with thicker lines when their
 * ``count`` is higher. Records that are observed at a single
 * instant (``firstseen === lastseen``) are rendered as a small
 * dot at that instant.
 *
 * The widget is purely visual — no axis labels are drawn. The
 * full date range of the visible set is reported as the
 * accessible title for screen readers. Hovering a row syncs with
 * the corresponding ``PassiveRecordCard`` via the parent's
 * ``hoveredIndex`` state.
 */
export function PassiveTimeline({
  records,
  hoveredIndex,
  onHover,
  onSelect,
}: PassiveTimelineProps) {
  const layout = useMemo(() => computeLayout(records), [records]);

  if (records.length === 0 || !layout) {
    return (
      <div className="rounded-md border border-border bg-muted/30 p-3 text-center text-xs italic text-muted-foreground">
        No passive observations to plot.
      </div>
    );
  }

  const { minMs, maxMs, rows, totalHeight } = layout;
  const titleId = `passive-timeline-title`;
  const dateLabel = (ms: number) =>
    new Date(ms).toISOString().slice(0, 16).replace("T", " ");

  return (
    <div
      className="rounded-md border border-border bg-muted/30 p-2"
      role="img"
      aria-labelledby={titleId}
    >
      <span id={titleId} className="sr-only">
        Timeline of {records.length} passive observation
        {records.length === 1 ? "" : "s"} from {dateLabel(minMs)} to{" "}
        {dateLabel(maxMs)}.
      </span>
      <div className="mb-1 flex justify-between font-mono text-[10px] text-muted-foreground">
        <span>{dateLabel(minMs)}</span>
        <span>{dateLabel(maxMs)}</span>
      </div>
      <svg
        viewBox={`0 0 ${VIEW_WIDTH} ${totalHeight}`}
        preserveAspectRatio="none"
        className="block h-auto w-full"
      >
        {rows.map((row, idx) => {
          const isHovered = hoveredIndex === idx;
          const dimmed = hoveredIndex !== null && !isHovered;
          if (row.kind === "line") {
            return (
              <line
                key={idx}
                x1={row.x1}
                x2={row.x2}
                y1={row.y}
                y2={row.y}
                strokeWidth={row.strokeWidth}
                strokeLinecap="round"
                className={cn(
                  "cursor-pointer transition-opacity",
                  "stroke-blue-500 dark:stroke-blue-400",
                  dimmed && "opacity-30",
                  isHovered && "stroke-orange-500 dark:stroke-orange-400",
                )}
                onMouseEnter={() => onHover(idx)}
                onMouseLeave={() => onHover(null)}
                onClick={() => onSelect?.(idx)}
              >
                <title>{row.title}</title>
              </line>
            );
          }
          return (
            <circle
              key={idx}
              cx={row.cx}
              cy={row.y}
              r={INSTANT_RADIUS_PX}
              className={cn(
                "cursor-pointer transition-opacity",
                "fill-blue-500 dark:fill-blue-400",
                dimmed && "opacity-30",
                isHovered && "fill-orange-500 dark:fill-orange-400",
              )}
              onMouseEnter={() => onHover(idx)}
              onMouseLeave={() => onHover(null)}
              onClick={() => onSelect?.(idx)}
            >
              <title>{row.title}</title>
            </circle>
          );
        })}
      </svg>
    </div>
  );
}

interface LineRow {
  kind: "line";
  x1: number;
  x2: number;
  y: number;
  strokeWidth: number;
  title: string;
}
interface InstantRow {
  kind: "instant";
  cx: number;
  y: number;
  title: string;
}
type Row = LineRow | InstantRow;

interface Layout {
  minMs: number;
  maxMs: number;
  rows: Row[];
  totalHeight: number;
}

function computeLayout(records: readonly PassiveRecord[]): Layout | null {
  if (records.length === 0) return null;
  const firsts = records.map((r) => passiveDateMs(r.firstseen));
  const lasts = records.map((r) => passiveDateMs(r.lastseen));
  const valid = firsts
    .concat(lasts)
    .filter((n) => Number.isFinite(n)) as number[];
  if (valid.length === 0) return null;
  const minMs = Math.min(...valid);
  const maxMs = Math.max(...valid);
  const span = Math.max(1, maxMs - minMs);

  const usableWidth = VIEW_WIDTH - 2 * SVG_PADDING_X;
  const xFor = (ms: number): number => {
    if (!Number.isFinite(ms)) return SVG_PADDING_X;
    return SVG_PADDING_X + ((ms - minMs) / span) * usableWidth;
  };

  const widths = passiveStrokeWidths(records, {
    minWidth: MIN_LINE_WIDTH_PX,
    maxWidth: MAX_LINE_WIDTH_PX,
  });

  const rows: Row[] = records.map((rec, idx) => {
    const y = SVG_PADDING_Y + idx * SVG_HEIGHT_PER_ROW + SVG_HEIGHT_PER_ROW / 2;
    const x1 = xFor(firsts[idx]);
    const x2 = xFor(lasts[idx]);
    const density = passiveDensity(rec);
    const titleParts = [
      `${rec.recontype}: ${rec.value}`,
      formatPassiveRange(rec),
      `count=${rec.count} · density≈${density.toFixed(3)}/s`,
    ];
    if (Math.abs(x2 - x1) < 1e-6 || firsts[idx] === lasts[idx]) {
      return { kind: "instant", cx: x1, y, title: titleParts.join("\n") };
    }
    return {
      kind: "line",
      x1,
      x2,
      y,
      strokeWidth: widths[idx],
      title: titleParts.join("\n"),
    };
  });

  const totalHeight =
    SVG_PADDING_Y * 2 + records.length * SVG_HEIGHT_PER_ROW;

  return { minMs, maxMs, rows, totalHeight };
}
