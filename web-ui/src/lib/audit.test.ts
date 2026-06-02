import { afterEach, describe, expect, it, vi } from "vitest";

import {
  fetchAuditCount,
  fetchAuditEvent,
  fetchAuditEvents,
  isoToLocalInput,
  localInputToIso,
  sanitizeWhen,
  type AuditEvent,
} from "./audit";

const realFetch = globalThis.fetch;

function mockFetch(impl: typeof fetch) {
  globalThis.fetch = impl as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

const sampleEvent: AuditEvent = {
  event_id: "deadbeefdead4bad9baddeadbeefcafe",
  event_type: "upload",
  created_at: "2026-05-25T12:00:00Z",
  actor: {
    user_email: "alice@example.org",
    api_key_hash: null,
    remote_addr: "203.0.113.7",
  },
  resource: { route: "/scans", method: "POST" },
  details: { count: 3 },
  outcome: 200,
};

/* ------------------------------------------------------------------ */
/* fetchAuditEvents                                                    */
/* ------------------------------------------------------------------ */

describe("fetchAuditEvents", () => {
  it("hits ``/cgi/audit/`` with no filters and parses the JSON array", async () => {
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify([sampleEvent]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    mockFetch(spy);

    const out = await fetchAuditEvents({});
    expect(out).toEqual([sampleEvent]);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/audit/",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("encodes filter and pagination params verbatim", async () => {
    const seenUrls: string[] = [];
    mockFetch(
      vi.fn(async (input: RequestInfo | URL) => {
        seenUrls.push(typeof input === "string" ? input : input.toString());
        return new Response("[]");
      }),
    );
    await fetchAuditEvents(
      {
        event_type: "admin_action",
        user_email: "alice+test@example.org",
        since: "2026-05-01T00:00:00Z",
        until: "2026-06-01T00:00:00Z",
      },
      { limit: 50, skip: 100 },
    );
    const url = seenUrls[0] ?? "";
    // Whichever ordering ``buildAuditQs`` settles on, every
    // configured filter must surface on the wire so the
    // backend gets the contract the caller asked for.
    expect(url).toContain("/cgi/audit/?");
    expect(url).toContain("event_type=admin_action");
    expect(url).toContain("user_email=alice%2Btest%40example.org");
    expect(url).toContain("since=2026-05-01T00%3A00%3A00Z");
    expect(url).toContain("until=2026-06-01T00%3A00%3A00Z");
    expect(url).toContain("limit=50");
    expect(url).toContain("skip=100");
  });

  it("omits skip when zero (matches the backend's default-skip path)", async () => {
    const seenUrls: string[] = [];
    mockFetch(
      vi.fn(async (input: RequestInfo | URL) => {
        seenUrls.push(typeof input === "string" ? input : input.toString());
        return new Response("[]");
      }),
    );
    await fetchAuditEvents({}, { limit: 50, skip: 0 });
    const url = seenUrls[0] ?? "";
    expect(url).toContain("limit=50");
    expect(url).not.toContain("skip=");
  });

  it("throws on non-2xx with the status surfaced in the message", async () => {
    mockFetch(vi.fn(async () => new Response("nope", { status: 401 })));
    await expect(fetchAuditEvents({})).rejects.toThrow(/audit.*401/);
  });
});

/* ------------------------------------------------------------------ */
/* fetchAuditCount                                                     */
/* ------------------------------------------------------------------ */

describe("fetchAuditCount", () => {
  it("parses the ``<int>\\n`` plain-text body", async () => {
    mockFetch(vi.fn(async () => new Response("42\n")));
    expect(await fetchAuditCount({})).toBe(42);
  });

  it("returns 0 on a non-numeric body rather than NaN", async () => {
    // Defensive: a future server-side bug that returns an
    // empty string (or whitespace) should not poison
    // downstream arithmetic with ``NaN``.
    mockFetch(vi.fn(async () => new Response("")));
    expect(await fetchAuditCount({})).toBe(0);
  });

  it("threads filters through to ``/cgi/audit/count``", async () => {
    const seenUrls: string[] = [];
    mockFetch(
      vi.fn(async (input: RequestInfo | URL) => {
        seenUrls.push(typeof input === "string" ? input : input.toString());
        return new Response("7\n");
      }),
    );
    await fetchAuditCount({
      event_type: "upload",
      user_email: "alice@example.org",
    });
    const url = seenUrls[0] ?? "";
    expect(url).toContain("/cgi/audit/count?");
    expect(url).toContain("event_type=upload");
    expect(url).toContain("user_email=alice%40example.org");
  });

  it("throws on non-2xx", async () => {
    mockFetch(vi.fn(async () => new Response("forbidden", { status: 403 })));
    await expect(fetchAuditCount({})).rejects.toThrow(/audit\/count.*403/);
  });
});

/* ------------------------------------------------------------------ */
/* fetchAuditEvent                                                     */
/* ------------------------------------------------------------------ */

describe("fetchAuditEvent", () => {
  it("hits ``/cgi/audit/<event_id>`` URL-encoded", async () => {
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify(sampleEvent), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    mockFetch(spy);
    const out = await fetchAuditEvent("dead/with weird");
    expect(out).toEqual(sampleEvent);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/audit/dead%2Fwith%20weird",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("throws on 404", async () => {
    mockFetch(vi.fn(async () => new Response("nf", { status: 404 })));
    await expect(fetchAuditEvent("abc")).rejects.toThrow(/audit\/abc.*404/);
  });
});

/* ------------------------------------------------------------------ */
/* datetime-local <-> ISO helpers                                     */
/* ------------------------------------------------------------------ */

describe("localInputToIso", () => {
  it("returns undefined for an empty value (filter dropped)", () => {
    expect(localInputToIso("")).toBeUndefined();
  });

  it("returns undefined for an unparsable value", () => {
    expect(localInputToIso("not-a-date")).toBeUndefined();
  });

  it("produces a UTC ISO string ending in Z for a valid local value", () => {
    const iso = localInputToIso("2026-05-25T12:00");
    expect(iso).toBeDefined();
    // Canonical UTC form: ends in ``Z`` so the backend's ISO
    // parser reads it as UTC-aware, matching ``created_at``.
    expect(iso).toMatch(/Z$/);
    // It must denote the same instant the local input did,
    // regardless of the test runner's timezone.
    expect(new Date(iso as string).getTime()).toBe(
      new Date("2026-05-25T12:00").getTime(),
    );
  });
});

describe("isoToLocalInput", () => {
  it("returns '' for empty / null / undefined", () => {
    expect(isoToLocalInput("")).toBe("");
    expect(isoToLocalInput(null)).toBe("");
    expect(isoToLocalInput(undefined)).toBe("");
  });

  it("returns '' for an unparsable value", () => {
    expect(isoToLocalInput("garbage")).toBe("");
  });

  it("round-trips with localInputToIso (timezone-independent)", () => {
    // The key invariant: a value typed into the datetime-local
    // input survives a URL store (as UTC ISO) and a reload back
    // into the input unchanged, whatever the runner's TZ is.
    for (const local of [
      "2026-05-25T12:00",
      "2026-01-01T00:00",
      "2025-12-31T23:59",
    ]) {
      expect(isoToLocalInput(localInputToIso(local))).toBe(local);
    }
  });
});

describe("sanitizeWhen", () => {
  it("returns '' for empty / null / undefined", () => {
    expect(sanitizeWhen("")).toBe("");
    expect(sanitizeWhen(null)).toBe("");
    expect(sanitizeWhen(undefined)).toBe("");
  });

  it("returns '' for an unparsable value (would 400 the backend)", () => {
    expect(sanitizeWhen("garbage")).toBe("");
    expect(sanitizeWhen("2026-13-99T99:99")).toBe("");
  });

  it("passes a valid ISO / timestamp value through unchanged", () => {
    expect(sanitizeWhen("2026-05-25T00:00:00.000Z")).toBe(
      "2026-05-25T00:00:00.000Z",
    );
    expect(sanitizeWhen("2026-05-25")).toBe("2026-05-25");
    // A bare epoch-seconds string is a valid backend input but
    // not a JS Date string; the Explorer never writes one, and
    // ``new Date("1716595200")`` is invalid, so it is treated as
    // unset here.  Documented as a known narrowing, not a bug.
    expect(sanitizeWhen("not-a-date")).toBe("");
  });
});
