/**
 * Generic time-series helpers shared by every section that
 * renders a horizontal timeline of records (Passive, DNS, ...).
 *
 * The helpers operate on any record exposing the three fields
 * the timeline needs: ``firstseen`` and ``lastseen`` (Unix
 * seconds, milliseconds, or an ISO-ish string when the backend
 * was queried with ``datesasstrings=1``) and ``count`` (the
 * number of underlying observations represented by the row).
 * No other field is read.
 */

/** Minimal shape a record must satisfy to be plotted on a
 *  ``<Timeline>`` widget. */
export interface TimelineRecord {
  firstseen: number | string;
  lastseen: number | string;
  count: number;
}

/** Convert a record's ``firstseen`` / ``lastseen`` to
 *  milliseconds since the Unix epoch, regardless of whether the
 *  backend returned a number (default: seconds) or an ISO-ish
 *  string (when ``datesasstrings=1`` was requested). Returns
 *  ``NaN`` on parse failure so callers can filter out broken
 *  records without throwing. */
export function timelineDateMs(value: number | string | undefined): number {
  if (value === undefined || value === null) return Number.NaN;
  if (typeof value === "number") {
    // Heuristic: timestamps before 10^11 are seconds (anything up
    // to year 5138); larger values are already milliseconds.
    return value < 1e11 ? value * 1000 : value;
  }
  // ISO-ish string. The backend emits ``"2015-09-18 16:13:35.515000"``
  // (space, no timezone). Replace the space with ``T`` so
  // ``Date.parse`` treats it as ISO-8601; the absence of a timezone
  // means the browser interprets it as local time, which matches
  // the AngularJS UI's behaviour.
  const iso = value.replace(" ", "T");
  return Date.parse(iso);
}

/** A record's duration in seconds (``lastseen - firstseen``).
 *  Clamped to ``>= 0``; a record where both timestamps are
 *  identical reports ``0`` seconds. */
export function timelineDurationSeconds(record: TimelineRecord): number {
  const first = timelineDateMs(record.firstseen);
  const last = timelineDateMs(record.lastseen);
  if (Number.isNaN(first) || Number.isNaN(last)) return 0;
  return Math.max(0, (last - first) / 1000);
}

/** Density = ``count / max(duration_seconds, 1)``. Higher density
 *  → the record concentrates more observations per unit time and
 *  is rendered as a thicker line on the timeline. The ``max(_, 1)``
 *  prevents division-by-zero on instant records (``firstseen ===
 *  lastseen``) and stops single-second records from dominating
 *  the scale. */
export function timelineDensity(record: TimelineRecord): number {
  return record.count / Math.max(timelineDurationSeconds(record), 1);
}

/** Map a list of records to ``[strokeWidth_px, ...]`` according
 *  to the design spec: width grows with ``count / duration``,
 *  normalised against the max density of the visible set, then
 *  mapped onto the closed interval ``[minWidth, maxWidth]``.
 *
 *  Deterministic on the empty input (returns ``[]``) and on a
 *  list whose densities are all equal (returns ``maxWidth`` for
 *  every record). */
export function timelineStrokeWidths(
  records: readonly TimelineRecord[],
  options: { minWidth?: number; maxWidth?: number } = {},
): number[] {
  const minWidth = options.minWidth ?? 1;
  const maxWidth = options.maxWidth ?? 8;
  if (records.length === 0) return [];
  const densities = records.map(timelineDensity);
  const max = Math.max(...densities);
  if (max <= 0) {
    return records.map(() => minWidth);
  }
  return densities.map((d) => {
    const normalised = d / max;
    return minWidth + normalised * (maxWidth - minWidth);
  });
}

/** Format a record's date range as a compact human string
 *  (``"2024-01-02 10:00 → 2024-03-15 09:30"``). Used by record
 *  cards for the per-row date label. */
export function formatTimelineRange(record: TimelineRecord): string {
  const fmt = (ms: number): string => {
    if (!Number.isFinite(ms)) return "?";
    const d = new Date(ms);
    const pad = (n: number) => String(n).padStart(2, "0");
    return (
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
      ` ${pad(d.getHours())}:${pad(d.getMinutes())}`
    );
  };
  return `${fmt(timelineDateMs(record.firstseen))} → ${fmt(timelineDateMs(record.lastseen))}`;
}
