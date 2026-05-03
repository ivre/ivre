import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createApiKey,
  deleteApiKey,
  fetchAdminUsers,
  fetchApiKeys,
  updateAdminUser,
} from "./admin";

const realFetch = globalThis.fetch;

function mockFetch(impl: typeof fetch) {
  globalThis.fetch = impl as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("fetchAdminUsers", () => {
  beforeEach(() => {
    mockFetch(vi.fn());
  });

  it("hits ``/cgi/auth/admin/users`` and returns the parsed body", async () => {
    const sample = [
      {
        email: "alice@example.com",
        display_name: "Alice",
        is_admin: true,
        is_active: true,
        groups: ["staff"],
        created_at: "2024-01-02T10:00:00",
        last_login: "2024-03-15T09:30:00",
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

    const out = await fetchAdminUsers();
    expect(out).toEqual(sample);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/admin/users",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("throws on a non-2xx response", async () => {
    mockFetch(vi.fn(async () => new Response("nope", { status: 403 })));
    await expect(fetchAdminUsers()).rejects.toThrow(/admin\/users.*403/);
  });
});

describe("updateAdminUser", () => {
  it("PUTs JSON with the partial update body and URL-encodes the email", async () => {
    const spy = vi.fn(async () => new Response('{"status":"ok"}'));
    mockFetch(spy);

    await updateAdminUser("alice+test@example.com", {
      is_admin: true,
      groups: ["staff", "ops"],
    });

    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/admin/users/alice%2Btest%40example.com",
      expect.objectContaining({
        method: "PUT",
        credentials: "same-origin",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
        }),
        body: JSON.stringify({
          is_admin: true,
          groups: ["staff", "ops"],
        }),
      }),
    );
  });

  it("propagates a non-2xx as an Error", async () => {
    mockFetch(vi.fn(async () => new Response("forbidden", { status: 403 })));
    await expect(
      updateAdminUser("a@b", { is_active: false }),
    ).rejects.toThrow(/PUT.*admin\/users.*403/);
  });
});

describe("fetchApiKeys", () => {
  it("hits ``/cgi/auth/api-keys`` and parses the JSON array", async () => {
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
    mockFetch(
      vi.fn(
        async () =>
          new Response(JSON.stringify(sample), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    expect(await fetchApiKeys()).toEqual(sample);
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
