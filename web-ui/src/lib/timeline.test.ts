import { describe, expect, it } from "vitest";

import {
  type TimelineRecord,
  formatTimelineRange,
  timelineDateMs,
  timelineDensity,
  timelineDurationSeconds,
  timelineStrokeWidths,
} from "./timeline";

const baseRecord = (overrides: Partial<TimelineRecord> = {}): TimelineRecord => ({
  count: 1,
  firstseen: 1_700_000_000,
  lastseen: 1_700_000_000,
  ...overrides,
});

describe("timelineDateMs", () => {
  it("converts seconds to milliseconds", () => {
    expect(timelineDateMs(1_700_000_000)).toBe(1_700_000_000_000);
  });

  it("passes milliseconds through unchanged", () => {
    expect(timelineDateMs(1_700_000_000_000)).toBe(1_700_000_000_000);
  });

  it("parses the backend's space-separated ISO-ish strings", () => {
    // ``"2015-09-18 16:13:35.515000"`` (no timezone) — same shape
    // emitted by ``datesasstrings=1`` on the backend.
    const ms = timelineDateMs("2015-09-18 16:13:35.515000");
    expect(Number.isNaN(ms)).toBe(false);
    // ``Date.parse`` interprets the timezone-less ISO string as
    // local time; the absolute value depends on the host TZ, so
    // the test only checks the year/month/day round-trip.
    const d = new Date(ms);
    expect(d.getFullYear()).toBe(2015);
    expect(d.getMonth()).toBe(8); // 0-indexed; September.
    expect(d.getDate()).toBe(18);
  });

  it("returns NaN for unparsable input", () => {
    expect(Number.isNaN(timelineDateMs("not a date"))).toBe(true);
    expect(Number.isNaN(timelineDateMs(undefined))).toBe(true);
  });
});

describe("timelineDurationSeconds", () => {
  it("returns 0 for instant records", () => {
    const r = baseRecord({ firstseen: 100, lastseen: 100 });
    expect(timelineDurationSeconds(r)).toBe(0);
  });

  it("computes the difference in seconds when timestamps are seconds", () => {
    const r = baseRecord({ firstseen: 100, lastseen: 160 });
    expect(timelineDurationSeconds(r)).toBe(60);
  });

  it("clamps to 0 for inverted ranges", () => {
    const r = baseRecord({ firstseen: 200, lastseen: 100 });
    expect(timelineDurationSeconds(r)).toBe(0);
  });
});

describe("timelineDensity", () => {
  it("returns count for instant records (avoids div by zero)", () => {
    const r = baseRecord({ firstseen: 100, lastseen: 100, count: 5 });
    expect(timelineDensity(r)).toBe(5);
  });

  it("returns count / duration for spanning records", () => {
    // 60-second span, count=120 -> density 2/s.
    const r = baseRecord({ firstseen: 100, lastseen: 160, count: 120 });
    expect(timelineDensity(r)).toBeCloseTo(2);
  });

  it("higher density for higher count at constant duration", () => {
    const longA = baseRecord({ firstseen: 0, lastseen: 100, count: 10 });
    const longB = baseRecord({ firstseen: 0, lastseen: 100, count: 100 });
    expect(timelineDensity(longB)).toBeGreaterThan(timelineDensity(longA));
  });

  it("lower density for longer duration at constant count", () => {
    const shortA = baseRecord({ firstseen: 0, lastseen: 10, count: 10 });
    const longA = baseRecord({ firstseen: 0, lastseen: 100, count: 10 });
    expect(timelineDensity(shortA)).toBeGreaterThan(timelineDensity(longA));
  });
});

describe("timelineStrokeWidths (timeline thickness)", () => {
  it("returns an empty array for an empty input", () => {
    expect(timelineStrokeWidths([])).toEqual([]);
  });

  it("maps the densest record to maxWidth and proportionally less for others", () => {
    const records = [
      baseRecord({ firstseen: 0, lastseen: 100, count: 10 }), // 0.1/s
      baseRecord({ firstseen: 0, lastseen: 100, count: 100 }), // 1/s
    ];
    const widths = timelineStrokeWidths(records, {
      minWidth: 1,
      maxWidth: 10,
    });
    expect(widths[1]).toBe(10);
    // record[0] has density 0.1 / max=1 = 0.1; width = 1 + 0.1*9 = 1.9
    expect(widths[0]).toBeCloseTo(1.9);
  });

  it("collapses to minWidth when every density is zero", () => {
    const records = [
      baseRecord({ firstseen: 100, lastseen: 100, count: 0 }),
      baseRecord({ firstseen: 200, lastseen: 200, count: 0 }),
    ];
    const widths = timelineStrokeWidths(records, {
      minWidth: 1,
      maxWidth: 8,
    });
    expect(widths).toEqual([1, 1]);
  });

  it("two records with the same density get the same maxWidth", () => {
    const records = [
      baseRecord({ firstseen: 0, lastseen: 60, count: 60 }),
      baseRecord({ firstseen: 0, lastseen: 30, count: 30 }),
    ];
    const widths = timelineStrokeWidths(records, {
      minWidth: 1,
      maxWidth: 10,
    });
    expect(widths[0]).toBeCloseTo(10);
    expect(widths[1]).toBeCloseTo(10);
  });

  it("spec example: same count, longer duration → thinner line", () => {
    // Two records with count=60. The 60-second one has density
    // 1/s; the 600-second one has density 0.1/s. The longer
    // record renders thinner, exactly as the design spec says.
    const records = [
      baseRecord({ firstseen: 0, lastseen: 60, count: 60 }),
      baseRecord({ firstseen: 0, lastseen: 600, count: 60 }),
    ];
    const widths = timelineStrokeWidths(records, {
      minWidth: 1,
      maxWidth: 10,
    });
    expect(widths[0]).toBeGreaterThan(widths[1]);
  });
});

describe("formatTimelineRange", () => {
  it("renders both timestamps as ``YYYY-MM-DD HH:MM`` joined by an arrow", () => {
    const r = baseRecord({ firstseen: 1_700_000_000, lastseen: 1_700_003_600 });
    const s = formatTimelineRange(r);
    expect(s).toMatch(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2} → \d{4}-\d{2}-\d{2} \d{2}:\d{2}$/,
    );
  });
});
