import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  fetchAuthConfig,
  fetchAuthMe,
  loginUrl,
  logout,
  sendMagicLink,
} from "./auth";

const realFetch = globalThis.fetch;

function mockFetch(impl: typeof fetch) {
  globalThis.fetch = impl as typeof fetch;
}

describe("loginUrl", () => {
  it("builds a CGI-rooted login URL for a known provider", () => {
    expect(loginUrl("google")).toBe("/cgi/auth/login/google");
  });

  it("URL-encodes provider names with special characters", () => {
    // Realistically the backend only accepts a fixed set of
    // alphabetic identifiers, but the helper stays safe regardless.
    expect(loginUrl("a/b c")).toBe("/cgi/auth/login/a%2Fb%20c");
  });

  it("forwards a ``next`` parameter when provided", () => {
    // The post-login redirect target is URL-encoded so the
    // browser preserves the slashes / query string on the way
    // through ``/cgi/auth/login/<provider>``.  The server-side
    // ``_validate_next_url`` is the authoritative
    // open-redirect guard; the SPA is just a transport.
    expect(loginUrl("google", "/cgi/auth/oauth/consent?request_id=abc")).toBe(
      "/cgi/auth/login/google?next=%2Fcgi%2Fauth%2Foauth%2Fconsent%3Frequest_id%3Dabc",
    );
  });

  it("omits ``next`` when null / undefined / empty", () => {
    expect(loginUrl("google", null)).toBe("/cgi/auth/login/google");
    expect(loginUrl("google", undefined)).toBe("/cgi/auth/login/google");
    expect(loginUrl("google", "")).toBe("/cgi/auth/login/google");
  });
});

describe("fetchAuthMe", () => {
  beforeEach(() => {
    mockFetch(vi.fn());
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("returns the parsed body when the endpoint returns 200", async () => {
    mockFetch(
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            authenticated: true,
            email: "alice@example.com",
            display_name: "Alice",
            is_admin: true,
            groups: ["staff"],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const me = await fetchAuthMe();
    expect(me).toEqual({
      authenticated: true,
      email: "alice@example.com",
      display_name: "Alice",
      is_admin: true,
      groups: ["staff"],
    });
  });

  it("treats a non-2xx (auth disabled / bad referer) as anonymous", async () => {
    mockFetch(vi.fn(async () => new Response("", { status: 404 })));
    const me = await fetchAuthMe();
    expect(me).toEqual({ authenticated: false });
  });

  it("treats a network error as anonymous", async () => {
    mockFetch(
      vi.fn(async () => {
        throw new TypeError("network down");
      }),
    );
    const me = await fetchAuthMe();
    expect(me).toEqual({ authenticated: false });
  });

  it("hits ``/cgi/auth/me`` with same-origin credentials", async () => {
    const spy = vi.fn(
      async () => new Response(JSON.stringify({ authenticated: false })),
    );
    mockFetch(spy);
    await fetchAuthMe();
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/me",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });
});

describe("fetchAuthConfig", () => {
  beforeEach(() => {
    mockFetch(vi.fn());
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("returns the parsed body when the endpoint is reachable", async () => {
    mockFetch(
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            enabled: true,
            providers: ["google", "oidc"],
            magic_link: true,
            provider_labels: { oidc: "Corp SSO" },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );
    const cfg = await fetchAuthConfig();
    expect(cfg).toEqual({
      enabled: true,
      providers: ["google", "oidc"],
      magic_link: true,
      provider_labels: { oidc: "Corp SSO" },
    });
  });

  it("returns a disabled config on 404 (auth disabled server-side)", async () => {
    mockFetch(vi.fn(async () => new Response("", { status: 404 })));
    const cfg = await fetchAuthConfig();
    expect(cfg).toEqual({
      enabled: false,
      providers: [],
      magic_link: false,
    });
  });

  it("returns a disabled config on a network error", async () => {
    mockFetch(
      vi.fn(async () => {
        throw new TypeError("offline");
      }),
    );
    const cfg = await fetchAuthConfig();
    expect(cfg.enabled).toBe(false);
  });
});

describe("logout", () => {
  beforeEach(() => {
    mockFetch(vi.fn());
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("POSTs to ``/cgi/auth/logout`` with same-origin credentials", async () => {
    const spy = vi.fn(async () => new Response("{\"status\":\"ok\"}"));
    mockFetch(spy);
    await logout();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/logout",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
      }),
    );
  });
});

describe("sendMagicLink", () => {
  beforeEach(() => {
    mockFetch(vi.fn());
  });
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("POSTs the email as JSON and returns the parsed body", async () => {
    const spy = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ status: "ok", message: "Check your email" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    mockFetch(spy);
    const result = await sendMagicLink("alice@example.com");
    expect(result).toEqual({ status: "ok", message: "Check your email" });
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/magic-link",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
        }),
        body: JSON.stringify({ email: "alice@example.com" }),
      }),
    );
  });

  it("throws on a non-2xx response", async () => {
    mockFetch(
      vi.fn(async () => new Response("nope", { status: 400 })),
    );
    await expect(sendMagicLink("bad")).rejects.toThrow(/Magic link/);
  });

  it("forwards a ``next`` parameter in the JSON body when provided", async () => {
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify({ status: "ok" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    mockFetch(spy);
    await sendMagicLink("alice@example.com", "/cgi/auth/oauth/consent?id=z");
    expect(spy).toHaveBeenCalledWith(
      "/cgi/auth/magic-link",
      expect.objectContaining({
        body: JSON.stringify({
          email: "alice@example.com",
          next: "/cgi/auth/oauth/consent?id=z",
        }),
      }),
    );
  });

  it("omits ``next`` from the JSON body when null / undefined / empty", async () => {
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify({ status: "ok" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    mockFetch(spy);
    await sendMagicLink("alice@example.com");
    await sendMagicLink("alice@example.com", null);
    await sendMagicLink("alice@example.com", "");
    // ``vi.fn(async () => Response)`` infers an empty-tuple
    // parameter signature, so ``spy.mock.calls[i][1]`` would
    // not typecheck.  Use the ``toHaveBeenNthCalledWith``
    // matcher instead -- it checks the call arguments
    // structurally without leaking the inferred signature into
    // the test code.
    expect(spy).toHaveBeenCalledTimes(3);
    const expectedBody = JSON.stringify({ email: "alice@example.com" });
    for (let i = 1; i <= 3; i += 1) {
      expect(spy).toHaveBeenNthCalledWith(
        i,
        "/cgi/auth/magic-link",
        expect.objectContaining({ body: expectedBody }),
      );
    }
  });
});
