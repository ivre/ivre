import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fetchCount, fetchHostNote, type Note } from "./api";

const realFetch = globalThis.fetch;

function mockFetch(impl: typeof fetch) {
  globalThis.fetch = impl as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("fetchCount", () => {
  beforeEach(() => {
    mockFetch(vi.fn());
  });

  it("hits ``/cgi/<endpoint>`` and forwards ``q=`` in the query string", async () => {
    const spy = vi.fn(async () => new Response("42\n", { status: 200 }));
    mockFetch(spy);

    const out = await fetchCount("/view/count", { q: "country:FR" });

    expect(out).toBe(42);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      expect.stringMatching(/^\/cgi\/view\/count\?.*q=country%3AFR/),
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("parses a bare decimal integer body (the happy path)", async () => {
    mockFetch(vi.fn(async () => new Response("45643", { status: 200 })));
    await expect(fetchCount("/view/count", {})).resolves.toBe(45643);
  });

  it("parses ``0`` (no-match) and tolerates trailing whitespace / newline", async () => {
    mockFetch(vi.fn(async () => new Response("0\n", { status: 200 })));
    await expect(fetchCount("/view/count", {})).resolves.toBe(0);

    mockFetch(vi.fn(async () => new Response("   123  \n", { status: 200 })));
    await expect(fetchCount("/view/count", {})).resolves.toBe(123);
  });

  it("throws on a non-2xx response (delegated to ensureOk)", async () => {
    mockFetch(vi.fn(async () => new Response("oops", { status: 500 })));
    await expect(fetchCount("/view/count", {})).rejects.toThrow(
      /view\/count.*500/,
    );
  });

  it("rejects an empty body (e.g. a 204 No Content)", async () => {
    mockFetch(vi.fn(async () => new Response("", { status: 200 })));
    await expect(fetchCount("/view/count", {})).rejects.toThrow(
      /non-numeric body/,
    );
  });

  it("rejects a partially-numeric body that ``parseInt`` would accept", async () => {
    // ``Number.parseInt("12abc", 10)`` returns ``12`` — a
    // banner-appended response would silently masquerade as a
    // valid count under lenient parsing. Strict validation
    // catches it.
    mockFetch(vi.fn(async () => new Response("12abc", { status: 200 })));
    await expect(fetchCount("/view/count", {})).rejects.toThrow(
      /non-numeric body/,
    );

    // ``Number.parseInt("1.5", 10)`` returns ``1``; a decimal
    // body is not a valid count and must error.
    mockFetch(vi.fn(async () => new Response("1.5", { status: 200 })));
    await expect(fetchCount("/view/count", {})).rejects.toThrow(
      /non-numeric body/,
    );

    // Two numbers separated by whitespace: ``parseInt`` would
    // happily return the first.
    mockFetch(vi.fn(async () => new Response("123 456", { status: 200 })));
    await expect(fetchCount("/view/count", {})).rejects.toThrow(
      /non-numeric body/,
    );
  });

  it("rejects a JSON envelope (forward-compat: schema drift on the server)", async () => {
    mockFetch(
      vi.fn(async () => new Response('{"count":123}', { status: 200 })),
    );
    await expect(fetchCount("/view/count", {})).rejects.toThrow(
      /non-numeric body/,
    );
  });

  it("rejects an HTML error page that begins with a tag", async () => {
    mockFetch(
      vi.fn(
        async () =>
          new Response("<html><body>Internal error</body></html>", {
            status: 200,
          }),
      ),
    );
    await expect(fetchCount("/view/count", {})).rejects.toThrow(
      /non-numeric body/,
    );
  });

  it("rejects a signed integer (counts are non-negative)", async () => {
    mockFetch(vi.fn(async () => new Response("-1", { status: 200 })));
    await expect(fetchCount("/view/count", {})).rejects.toThrow(
      /non-numeric body/,
    );
  });
});

describe("fetchHostNote", () => {
  const sampleNote: Note = {
    entity_type: "host",
    entity_key: "192.0.2.10",
    body: "Investigation in progress.",
    revision: 3,
    created_at: "2026-05-01T10:00:00Z",
    created_by: "alice@example.org",
    updated_at: "2026-05-12T14:32:11Z",
    updated_by: "bob@example.org",
  };

  it("returns ``found`` when the route returns 200 + JSON body", async () => {
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify(sampleNote), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    mockFetch(spy);

    const out = await fetchHostNote("192.0.2.10");

    expect(out).toEqual({ kind: "found", note: sampleNote });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/notes/host/192.0.2.10",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("URL-encodes the address so IPv6 colons round-trip safely", async () => {
    const spy = vi.fn(
      async () => new Response("{}", { status: 404 }),
    );
    mockFetch(spy);

    await fetchHostNote("2001:db8::1");

    expect(spy).toHaveBeenCalledWith(
      "/cgi/notes/host/2001%3Adb8%3A%3A1",
      expect.anything(),
    );
  });

  it("returns ``absent`` when the route returns 404", async () => {
    mockFetch(
      vi.fn(
        async () => new Response("no note for host/192.0.2.10", { status: 404 }),
      ),
    );

    await expect(fetchHostNote("192.0.2.10")).resolves.toEqual({
      kind: "absent",
    });
  });

  it("returns ``unavailable`` when the route returns 501", async () => {
    mockFetch(
      vi.fn(
        async () =>
          new Response("Notes backend not available", { status: 501 }),
      ),
    );

    await expect(fetchHostNote("192.0.2.10")).resolves.toEqual({
      kind: "unavailable",
    });
  });

  it("throws on other non-2xx responses (5xx / 401 / 400 / ...)", async () => {
    mockFetch(vi.fn(async () => new Response("oops", { status: 500 })));

    await expect(fetchHostNote("192.0.2.10")).rejects.toThrow(
      /notes\/host\/192\.0\.2\.10.*500/,
    );
  });
});
