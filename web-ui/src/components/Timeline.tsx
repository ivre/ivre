import { useMemo } from "react";

import {
  type TimelineRecord,
  timelineDateMs,
  timelineDensity,
  timelineStrokeWidths,
} from "@/lib/timeline";
import { cn } from "@/lib/utils";

export interface TimelineProps<R extends TimelineRecord> {
  records: readonly R[];
  /** Index of the currently-hovered record. The corresponding
   *  line is rendered with full opacity; the rest are dimmed.
   *  ``null`` means "no hover". */
  hoveredIndex: number | null;
  onHover: (index: number | null) => void;
  /** Optional click handler — used by the route to scroll the
   *  corresponding card into view. */
  onSelect?: (index: number) => void;
  /** Per-row tooltip text. Receives the record and its computed
   *  density (events per second) so the caller can format a
   *  full multi-line ``<title>`` body. */
  getTitle: (record: R, density: number) => string;
  /** Singular/plural noun used for the screen-reader label
   *  ("Timeline of N <plural> from <date> to <date>." /
   *  "Timeline of 1 <singular>..."). Defaults to ``"record"`` /
   *  ``"records"``. */
  itemLabel?: { singular: string; plural: string };
  /** Empty-state message shown when ``records`` is empty.
   *  Defaults to ``"No observations to plot."``. */
  emptyLabel?: string;
  /** Stable id used as the ``aria-labelledby`` target for the
   *  enclosing region. Defaults to ``"timeline-title"``; pass a
   *  custom value if more than one Timeline is mounted on the
   *  same page. */
  titleId?: string;
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
 * Horizontal SVG timeline of time-ranged records.
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
 * the corresponding card via the parent's ``hoveredIndex`` state.
 *
 * The component is record-shape-agnostic: any object exposing
 * the three :type:`TimelineRecord` fields (``firstseen``,
 * ``lastseen``, ``count``) can be plotted. The per-row tooltip
 * is supplied by the caller via ``getTitle`` because the
 * identity columns vary by section (passive: ``recontype: value``,
 * DNS: ``name → addr``, ...).
 */
export function Timeline<R extends TimelineRecord>({
  records,
  hoveredIndex,
  onHover,
  onSelect,
  getTitle,
  itemLabel = { singular: "record", plural: "records" },
  emptyLabel = "No observations to plot.",
  titleId = "timeline-title",
}: TimelineProps<R>) {
  const layout = useMemo(
    () => computeLayout(records, getTitle),
    [records, getTitle],
  );

  if (records.length === 0 || !layout) {
    return (
      <div className="rounded-md border border-border bg-muted/30 p-3 text-center text-xs italic text-muted-foreground">
        {emptyLabel}
      </div>
    );
  }

  const { minMs, maxMs, rows, totalHeight } = layout;
  const dateLabel = (ms: number) =>
    new Date(ms).toISOString().slice(0, 16).replace("T", " ");
  const noun = records.length === 1 ? itemLabel.singular : itemLabel.plural;

  return (
    <div
      className="rounded-md border border-border bg-muted/30 p-2"
      role="img"
      aria-labelledby={titleId}
    >
      <span id={titleId} className="sr-only">
        Timeline of {records.length} {noun} from {dateLabel(minMs)} to{" "}
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

function computeLayout<R extends TimelineRecord>(
  records: readonly R[],
  getTitle: (record: R, density: number) => string,
): Layout | null {
  if (records.length === 0) return null;
  const firsts = records.map((r) => timelineDateMs(r.firstseen));
  const lasts = records.map((r) => timelineDateMs(r.lastseen));
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

  const widths = timelineStrokeWidths(records, {
    minWidth: MIN_LINE_WIDTH_PX,
    maxWidth: MAX_LINE_WIDTH_PX,
  });

  const rows: Row[] = records.map((rec, idx) => {
    const y = SVG_PADDING_Y + idx * SVG_HEIGHT_PER_ROW + SVG_HEIGHT_PER_ROW / 2;
    const x1 = xFor(firsts[idx]);
    const x2 = xFor(lasts[idx]);
    const density = timelineDensity(rec);
    const title = getTitle(rec, density);
    if (Math.abs(x2 - x1) < 1e-6 || firsts[idx] === lasts[idx]) {
      return { kind: "instant", cx: x1, y, title };
    }
    return {
      kind: "line",
      x1,
      x2,
      y,
      strokeWidth: widths[idx],
      title,
    };
  });

  const totalHeight =
    SVG_PADDING_Y * 2 + records.length * SVG_HEIGHT_PER_ROW;

  return { minMs, maxMs, rows, totalHeight };
}
