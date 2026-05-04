import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  adminDeleteApiKey,
  fetchAdminApiKeys,
  fetchAdminUsers,
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

describe("fetchAdminApiKeys", () => {
  it("hits the cross-user audit endpoint and parses the JSON array", async () => {
    const sample = [
      {
        key_hash: "abc",
        key_prefix: "ivre_aaaa",
        user_email: "alice@example.com",
        name: "ci-pipeline",
        created_at: "2024-01-02T10:00:00",
        last_used: null,
        expires_at: null,
      },
      {
        key_hash: "def",
        key_prefix: "ivre_bbbb",
        user_email: "bob@example.com",
        name: "dashboard",
        created_at: "2024-02-01T08:00:00",
        last_used: "2024-03-01T12:00:00",
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

    const out = await fetchAdminApiKeys();
    expect(out).toEqual(sample);
    // The admin variant is intentionally a separate URL from the
    // owner-scoped ``/cgi/auth/api-keys`` — see ``lib/api-keys``.
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/admin/api-keys",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("throws on a non-2xx response", async () => {
    mockFetch(vi.fn(async () => new Response("nope", { status: 403 })));
    await expect(fetchAdminApiKeys()).rejects.toThrow(
      /admin\/api-keys.*403/,
    );
  });
});

describe("adminDeleteApiKey", () => {
  it("DELETEs the admin variant URL with the key hash URL-encoded", async () => {
    const spy = vi.fn(async () => new Response('{"status":"ok"}'));
    mockFetch(spy);
    await adminDeleteApiKey("abc/with weird chars");
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/admin/api-keys/abc%2Fwith%20weird%20chars",
      expect.objectContaining({
        method: "DELETE",
        credentials: "same-origin",
      }),
    );
  });

  it("throws on non-2xx", async () => {
    mockFetch(vi.fn(async () => new Response("not found", { status: 404 })));
    await expect(adminDeleteApiKey("xyz")).rejects.toThrow(
      /DELETE.*admin\/api-keys.*404/,
    );
  });
});
