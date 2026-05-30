import { afterEach, describe, expect, it, vi } from "vitest";

import {
  fetchAuditCount,
  fetchAuditEvent,
  fetchAuditEvents,
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
