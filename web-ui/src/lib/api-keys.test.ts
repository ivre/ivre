import { afterEach, describe, expect, it, vi } from "vitest";

import { createApiKey, deleteApiKey, fetchApiKeys } from "./api-keys";

const realFetch = globalThis.fetch;

function mockFetch(impl: typeof fetch) {
  globalThis.fetch = impl as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("fetchApiKeys", () => {
  it("hits ``/cgi/auth/api-keys`` (owner-scoped) and parses the JSON array", async () => {
    const sample = [
      {
        key_hash: "abc123",
        key_prefix: "ivre_aaaa",
        user_email: "alice@example.com",
        name: "ci-pipeline",
        created_at: "2024-01-02T10:00:00",
        last_used: null,
        expires_at: null,
      },
    ];
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify(sample), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    mockFetch(spy);
    expect(await fetchApiKeys()).toEqual(sample);
    // Self-service path: the URL is the bare ``/auth/api-keys``,
    // *not* the admin variant ``/auth/admin/api-keys`` which lives
    // in ``lib/admin``.
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/api-keys",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("throws on non-2xx", async () => {
    mockFetch(vi.fn(async () => new Response("nope", { status: 401 })));
    await expect(fetchApiKeys()).rejects.toThrow(/api-keys.*401/);
  });
});

describe("createApiKey", () => {
  it("POSTs the name and returns the one-shot ``{key, name}`` body", async () => {
    const spy = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ key: "ivre_secrettoken123", name: "ci" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    mockFetch(spy);

    const out = await createApiKey("ci");
    expect(out).toEqual({ key: "ivre_secrettoken123", name: "ci" });
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/api-keys",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        body: JSON.stringify({ name: "ci" }),
      }),
    );
  });

  it("throws on non-2xx", async () => {
    mockFetch(vi.fn(async () => new Response("bad", { status: 400 })));
    await expect(createApiKey("")).rejects.toThrow(/POST.*api-keys.*400/);
  });
});

describe("deleteApiKey", () => {
  it("DELETEs ``/cgi/auth/api-keys/<key_hash>`` URL-encoded", async () => {
    const spy = vi.fn(async () => new Response('{"status":"ok"}'));
    mockFetch(spy);
    await deleteApiKey("abc123/with weird chars");
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/api-keys/abc123%2Fwith%20weird%20chars",
      expect.objectContaining({
        method: "DELETE",
        credentials: "same-origin",
      }),
    );
  });

  it("throws on non-2xx", async () => {
    mockFetch(vi.fn(async () => new Response("not found", { status: 404 })));
    await expect(deleteApiKey("xyz")).rejects.toThrow(
      /DELETE.*api-keys.*404/,
    );
  });
});
