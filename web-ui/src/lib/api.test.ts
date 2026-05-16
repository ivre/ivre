import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { fetchCount } from "./api";

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
