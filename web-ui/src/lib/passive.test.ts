import { describe, expect, it } from "vitest";

import type { PassiveRecord } from "./api";
import {
  describePassiveValue,
  formatPassiveRange,
  passiveDateMs,
  passiveDensity,
  passiveDurationSeconds,
  passiveStrokeWidths,
} from "./passive";

const baseRecord = (
  overrides: Partial<PassiveRecord> = {},
): PassiveRecord => ({
  schema_version: 3,
  recontype: "DNS_ANSWER",
  value: "example.com",
  count: 1,
  firstseen: 1_700_000_000,
  lastseen: 1_700_000_000,
  ...overrides,
});

describe("passiveDateMs", () => {
  it("converts seconds to milliseconds", () => {
    expect(passiveDateMs(1_700_000_000)).toBe(1_700_000_000_000);
  });

  it("passes milliseconds through unchanged", () => {
    expect(passiveDateMs(1_700_000_000_000)).toBe(1_700_000_000_000);
  });

  it("parses the backend's space-separated ISO-ish strings", () => {
    // ``"2015-09-18 16:13:35.515000"`` (no timezone) — same shape
    // emitted by ``datesasstrings=1`` on the backend.
    const ms = passiveDateMs("2015-09-18 16:13:35.515000");
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
    expect(Number.isNaN(passiveDateMs("not a date"))).toBe(true);
    expect(Number.isNaN(passiveDateMs(undefined))).toBe(true);
  });
});

describe("passiveDurationSeconds", () => {
  it("returns 0 for instant records", () => {
    const r = baseRecord({ firstseen: 100, lastseen: 100 });
    expect(passiveDurationSeconds(r)).toBe(0);
  });

  it("computes the difference in seconds when timestamps are seconds", () => {
    const r = baseRecord({ firstseen: 100, lastseen: 160 });
    expect(passiveDurationSeconds(r)).toBe(60);
  });

  it("clamps to 0 for inverted ranges", () => {
    const r = baseRecord({ firstseen: 200, lastseen: 100 });
    expect(passiveDurationSeconds(r)).toBe(0);
  });
});

describe("passiveDensity", () => {
  it("returns count for instant records (avoids div by zero)", () => {
    const r = baseRecord({ firstseen: 100, lastseen: 100, count: 5 });
    expect(passiveDensity(r)).toBe(5);
  });

  it("returns count / duration for spanning records", () => {
    // 60-second span, count=120 -> density 2/s.
    const r = baseRecord({ firstseen: 100, lastseen: 160, count: 120 });
    expect(passiveDensity(r)).toBeCloseTo(2);
  });

  it("higher density for higher count at constant duration", () => {
    const longA = baseRecord({ firstseen: 0, lastseen: 100, count: 10 });
    const longB = baseRecord({ firstseen: 0, lastseen: 100, count: 100 });
    expect(passiveDensity(longB)).toBeGreaterThan(passiveDensity(longA));
  });

  it("lower density for longer duration at constant count", () => {
    const shortA = baseRecord({ firstseen: 0, lastseen: 10, count: 10 });
    const longA = baseRecord({ firstseen: 0, lastseen: 100, count: 10 });
    expect(passiveDensity(shortA)).toBeGreaterThan(passiveDensity(longA));
  });
});

describe("passiveStrokeWidths (timeline thickness)", () => {
  it("returns an empty array for an empty input", () => {
    expect(passiveStrokeWidths([])).toEqual([]);
  });

  it("maps the densest record to maxWidth and proportionally less for others", () => {
    const records = [
      baseRecord({ firstseen: 0, lastseen: 100, count: 10 }), // 0.1/s
      baseRecord({ firstseen: 0, lastseen: 100, count: 100 }), // 1/s
    ];
    const widths = passiveStrokeWidths(records, {
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
    const widths = passiveStrokeWidths(records, {
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
    const widths = passiveStrokeWidths(records, {
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
    const widths = passiveStrokeWidths(records, {
      minWidth: 1,
      maxWidth: 10,
    });
    expect(widths[0]).toBeGreaterThan(widths[1]);
  });
});

describe("formatPassiveRange", () => {
  it("renders both timestamps as ``YYYY-MM-DD HH:MM`` joined by an arrow", () => {
    const r = baseRecord({ firstseen: 1_700_000_000, lastseen: 1_700_003_600 });
    const s = formatPassiveRange(r);
    expect(s).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} → \d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
  });
});

describe("describePassiveValue (recontype-aware rendering)", () => {
  it("DNS A: renders ``name → addr``", () => {
    const r = baseRecord({
      recontype: "DNS_ANSWER",
      rrtype: "A",
      value: "example.com",
      addr: "1.2.3.4",
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("DNS A");
    expect(d.primary).toBe("example.com → 1.2.3.4");
  });

  it("DNS CNAME: renders ``name → targetval``", () => {
    const r = baseRecord({
      recontype: "DNS_ANSWER",
      rrtype: "CNAME",
      value: "time.windows.com",
      targetval: "time.microsoft.akadns.net",
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("DNS CNAME");
    expect(d.primary).toBe("time.windows.com → time.microsoft.akadns.net");
  });

  it("HTTP_SERVER_HEADER includes the header name in the heading", () => {
    const r = baseRecord({
      recontype: "HTTP_SERVER_HEADER",
      source: "SERVER",
      value: "Apache",
    });
    const d = describePassiveValue(r);
    expect(d.heading).toMatch(/HTTP server header.*SERVER/);
    expect(d.primary).toBe("Apache");
  });

  it("SSL_SERVER cert: surfaces subject + issuer + sha1", () => {
    const r = baseRecord({
      recontype: "SSL_SERVER",
      source: "cert",
      value: "MIIBvjCCASegAwIBAg...",
      infos: {
        subject_text: "commonName=example.com",
        issuer_text: "commonName=Example CA",
        sha1: "ce9cbaa461eef2b82e27d3dfc29aab381880732e",
      },
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("TLS server cert");
    expect(d.primary).toBe("commonName=example.com");
    expect(d.secondary).toContain("Example CA");
    expect(d.secondary).toContain("ce9cbaa461eef2b82e27d3dfc29aab381880732e");
  });

  it("SSL_SERVER ja3-*: surfaces JA3-S as primary, sha1 as secondary", () => {
    const r = baseRecord({
      recontype: "SSL_SERVER",
      source: "ja3-1be3ecebe5aa9d3654e6e703d81f6928",
      value: "a95ca7eab4d47d051a5cd4fb7b6005dc",
      infos: { sha1: "2bdc6a444280c528ff3f465d95a6425286a1faa2" },
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("JA3-S");
    expect(d.primary).toBe("a95ca7eab4d47d051a5cd4fb7b6005dc");
    expect(d.secondary).toBe(
      "SHA1: 2bdc6a444280c528ff3f465d95a6425286a1faa2",
    );
  });

  it("falls back to a humanised recontype for unknown shapes", () => {
    const r = baseRecord({
      recontype: "STUN_HONEYPOT_REQUEST",
      value: "Binding Request",
    });
    const d = describePassiveValue(r);
    expect(d.heading).toBe("stun honeypot request");
    expect(d.primary).toBe("Binding Request");
  });
});
