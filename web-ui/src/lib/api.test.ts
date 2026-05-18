/* @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  deleteHostNote,
  fetchCount,
  fetchHostNote,
  fetchHostNoteRevisions,
  fetchNotes,
  saveHostNote,
  useDeleteHostNote,
  useSaveHostNote,
  type Note,
  type NoteRevision,
} from "./api";

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

describe("saveHostNote", () => {
  const persistedNote: Note = {
    entity_type: "host",
    entity_key: "192.0.2.10",
    body: "Updated content",
    revision: 4,
    created_at: "2026-05-01T10:00:00Z",
    created_by: "alice@example.org",
    updated_at: "2026-05-12T15:00:00Z",
    updated_by: "bob@example.org",
  };

  it("sends If-Match for update mode and returns the persisted note", async () => {
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify(persistedNote), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    mockFetch(spy);

    const out = await saveHostNote("192.0.2.10", "Updated content", {
      kind: "update",
      expectedRevision: 3,
    });

    expect(out).toEqual({ kind: "saved", note: persistedNote });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/notes/host/192.0.2.10",
      expect.objectContaining({
        method: "PUT",
        credentials: "same-origin",
        body: "Updated content",
        // Update mode -> If-Match: <revision>; no If-None-Match.
        // Content-Type carries the markdown media type so a
        // server-side parser can dispatch correctly even when
        // the route eventually negotiates more than one body
        // shape.
        headers: expect.objectContaining({
          "If-Match": "3",
          "Content-Type": expect.stringMatching(/text\/markdown/),
        }),
      }),
    );
  });

  it("sends If-None-Match: * for create mode", async () => {
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify(persistedNote), { status: 200 }),
    );
    mockFetch(spy);

    await saveHostNote("192.0.2.10", "New note", { kind: "create" });

    expect(spy).toHaveBeenCalledWith(
      "/cgi/notes/host/192.0.2.10",
      expect.objectContaining({
        method: "PUT",
        headers: expect.objectContaining({ "If-None-Match": "*" }),
      }),
    );
  });

  it("URL-encodes IPv6 addresses", async () => {
    const spy = vi.fn(async () => new Response("{}", { status: 200 }));
    mockFetch(spy);
    await saveHostNote("2001:db8::1", "...", { kind: "create" });
    expect(spy).toHaveBeenCalledWith(
      "/cgi/notes/host/2001%3Adb8%3A%3A1",
      expect.anything(),
    );
  });

  it("returns conflict on 409, surfacing the route's body as the message", async () => {
    mockFetch(
      vi.fn(
        async () =>
          new Response("stored revision 5 does not match expected=3", {
            status: 409,
          }),
      ),
    );

    const out = await saveHostNote("192.0.2.10", "...", {
      kind: "update",
      expectedRevision: 3,
    });

    expect(out).toEqual({
      kind: "conflict",
      message: "stored revision 5 does not match expected=3",
    });
  });

  it("returns unauthorized on 401", async () => {
    mockFetch(
      vi.fn(async () => new Response("Authentication required", { status: 401 })),
    );

    await expect(
      saveHostNote("192.0.2.10", "...", { kind: "create" }),
    ).resolves.toEqual({ kind: "unauthorized" });
  });

  it("returns too_large on 413", async () => {
    mockFetch(
      vi.fn(async () => new Response("body exceeds cap", { status: 413 })),
    );

    await expect(
      saveHostNote("192.0.2.10", "x".repeat(10), { kind: "create" }),
    ).resolves.toEqual({ kind: "too_large" });
  });

  it("returns not_found on 404 (update-after-delete race)", async () => {
    mockFetch(
      vi.fn(async () => new Response("no note", { status: 404 })),
    );

    await expect(
      saveHostNote("192.0.2.10", "...", {
        kind: "update",
        expectedRevision: 3,
      }),
    ).resolves.toEqual({ kind: "not_found" });
  });

  it("throws on other failures (5xx)", async () => {
    mockFetch(vi.fn(async () => new Response("server down", { status: 503 })));

    await expect(
      saveHostNote("192.0.2.10", "...", { kind: "create" }),
    ).rejects.toThrow(/notes\/host\/192\.0\.2\.10.*503/);
  });
});

describe("deleteHostNote", () => {
  it("returns true on 204", async () => {
    // Fetch's Response constructor rejects a non-null body on
    // 204 No Content (per the HTTP spec); pass ``null`` so the
    // mock matches what a real DELETE would return.
    const spy = vi.fn(async () => new Response(null, { status: 204 }));
    mockFetch(spy);

    await expect(deleteHostNote("192.0.2.10")).resolves.toBe(true);
    expect(spy).toHaveBeenCalledWith(
      "/cgi/notes/host/192.0.2.10",
      expect.objectContaining({ method: "DELETE", credentials: "same-origin" }),
    );
  });

  it("returns false on 404 (no note to delete; idempotent)", async () => {
    mockFetch(
      vi.fn(async () => new Response("no note", { status: 404 })),
    );

    await expect(deleteHostNote("192.0.2.10")).resolves.toBe(false);
  });

  it("throws a helpful error on 401", async () => {
    mockFetch(
      vi.fn(async () => new Response("auth required", { status: 401 })),
    );

    await expect(deleteHostNote("192.0.2.10")).rejects.toThrow(
      /Authentication required/,
    );
  });

  it("throws on other failures (5xx)", async () => {
    mockFetch(vi.fn(async () => new Response("server down", { status: 500 })));

    await expect(deleteHostNote("192.0.2.10")).rejects.toThrow(
      /DELETE.*notes\/host\/192\.0\.2\.10.*500/,
    );
  });
});

describe("fetchHostNoteRevisions", () => {
  it("returns the revisions array", async () => {
    const revisions: NoteRevision[] = [
      {
        revision: 3,
        body: "Third revision body",
        created_at: "2026-05-12T15:00:00Z",
        created_by: "bob@example.org",
      },
      {
        revision: 2,
        body: "Second revision body",
        created_at: "2026-05-10T12:00:00Z",
        created_by: "alice@example.org",
      },
    ];
    const spy = vi.fn(
      async () =>
        new Response(JSON.stringify(revisions), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    mockFetch(spy);

    await expect(fetchHostNoteRevisions("192.0.2.10")).resolves.toEqual(
      revisions,
    );
    expect(spy).toHaveBeenCalledWith(
      "/cgi/notes/host/192.0.2.10/revisions",
      expect.anything(),
    );
  });

  it("throws on non-2xx responses", async () => {
    mockFetch(vi.fn(async () => new Response("oops", { status: 500 })));

    await expect(fetchHostNoteRevisions("192.0.2.10")).rejects.toThrow(
      /notes\/host\/192\.0\.2\.10\/revisions.*500/,
    );
  });
});

/* ------------------------------------------------------------------ */
/* Mutation-hook invalidation behaviour                                */
/* ------------------------------------------------------------------ */

/** Build a QueryClient + Provider wrapper so the mutation hooks
 *  can run inside ``renderHook``.  The client is fresh per call
 *  so tests don't cross-contaminate via cached data. */
function withQueryClient(): {
  client: QueryClient;
  wrapper: React.FC<{ children: React.ReactNode }>;
} {
  const client = new QueryClient({
    defaultOptions: {
      // Mutations re-throwing failures during tests are noisy
      // and bypass the discriminated-union outcome path we
      // exercise here; silence the retry chatter.
      mutations: { retry: false },
      queries: { retry: false },
    },
  });
  const wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) =>
    React.createElement(QueryClientProvider, { client }, children);
  return { client, wrapper };
}

describe("useSaveHostNote invalidation", () => {
  it("invalidates both the host-note and its revisions cache on saved", async () => {
    const persistedNote: Note = {
      entity_type: "host",
      entity_key: "192.0.2.10",
      body: "Updated",
      revision: 4,
      created_at: "2026-05-01T10:00:00Z",
      created_by: "alice@example.org",
      updated_at: "2026-05-12T15:00:00Z",
      updated_by: "alice@example.org",
    };
    mockFetch(
      vi.fn(
        async () => new Response(JSON.stringify(persistedNote), { status: 200 }),
      ),
    );
    const { client, wrapper } = withQueryClient();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    const { result } = renderHook(() => useSaveHostNote("192.0.2.10"), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync({
        body: "Updated",
        mode: { kind: "update", expectedRevision: 3 },
      });
    });

    // Both query keys are invalidated explicitly -- not relying
    // on React Query's default prefix-match behaviour to catch
    // the revisions cache.  A future ``exact: true`` migration
    // or queryKey reshape would silently leave stale revisions
    // after a save without this explicit invalidation.
    const calls = invalidateSpy.mock.calls.map((c) => c[0]?.queryKey);
    expect(calls).toContainEqual(["notes", "host", "192.0.2.10"]);
    expect(calls).toContainEqual([
      "notes",
      "host",
      "192.0.2.10",
      "revisions",
    ]);
  });

  it("does NOT invalidate on conflict / unauthorized / too_large / not_found outcomes", async () => {
    mockFetch(
      vi.fn(async () => new Response("conflict", { status: 409 })),
    );
    const { client, wrapper } = withQueryClient();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    const { result } = renderHook(() => useSaveHostNote("192.0.2.10"), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync({
        body: "...",
        mode: { kind: "update", expectedRevision: 3 },
      });
    });

    // Discriminated-union outcomes that are not ``saved`` do
    // not represent real success from the operator's
    // perspective; invalidating the cache on them would force
    // an unnecessary refetch and possibly mask the conflict
    // state the panel is showing.
    expect(invalidateSpy).not.toHaveBeenCalled();
  });
});

describe("fetchNotes", () => {
  const noteRow = (addr: string): Note => ({
    entity_type: "host",
    entity_key: addr,
    body: `Note for ${addr}`,
    revision: 1,
    created_at: "2026-05-01T10:00:00Z",
    created_by: "alice@example.org",
    updated_at: "2026-05-12T15:00:00Z",
    updated_by: "alice@example.org",
  });

  it("calls GET /cgi/notes/ with no params and parses the JSON array", async () => {
    const spy = vi.fn(
      async () =>
        new Response(
          JSON.stringify([noteRow("192.0.2.1"), noteRow("192.0.2.2")]),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    mockFetch(spy);

    const out = await fetchNotes();

    expect(out).toHaveLength(2);
    expect(out[0].entity_key).toBe("192.0.2.1");
    expect(spy).toHaveBeenCalledWith(
      "/cgi/notes/",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("forwards entity_type / q / limit / skip as URL parameters", async () => {
    const spy = vi.fn(async () => new Response("[]", { status: 200 }));
    mockFetch(spy);

    await fetchNotes({
      entityType: "host",
      q: "c2",
      limit: 25,
      skip: 50,
    });

    // Use ``toHaveBeenCalledWith`` rather than indexing into
    // ``mock.calls`` so the TS tuple-narrowing doesn't trip.
    // ``qs()`` URL-encodes values; we check the decoded form
    // via ``expect.stringMatching`` for the path prefix and
    // ``calledWith.stringContaining`` for each param.
    expect(spy).toHaveBeenCalledWith(
      expect.stringMatching(/^\/cgi\/notes\/\?/),
      expect.objectContaining({ credentials: "same-origin" }),
    );
    const url = (spy.mock.calls[0] as unknown as [string])[0];
    const decoded = decodeURIComponent(url);
    expect(decoded).toContain("entity_type=host");
    expect(decoded).toContain("q=c2");
    expect(decoded).toContain("limit=25");
    expect(decoded).toContain("skip=50");
  });

  it("throws on non-2xx responses", async () => {
    mockFetch(vi.fn(async () => new Response("oops", { status: 500 })));

    await expect(fetchNotes()).rejects.toThrow(/notes\/.*500/);
  });
});

describe("useDeleteHostNote invalidation", () => {
  it("invalidates the host-note + revisions cache on a 204 success", async () => {
    mockFetch(vi.fn(async () => new Response(null, { status: 204 })));
    const { client, wrapper } = withQueryClient();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    const { result } = renderHook(() => useDeleteHostNote("192.0.2.10"), {
      wrapper,
    });
    await act(async () => {
      await result.current.mutateAsync();
    });

    await waitFor(() => expect(invalidateSpy).toHaveBeenCalled());
    const calls = invalidateSpy.mock.calls.map((c) => c[0]?.queryKey);
    expect(calls).toContainEqual(["notes", "host", "192.0.2.10"]);
    expect(calls).toContainEqual([
      "notes",
      "host",
      "192.0.2.10",
      "revisions",
    ]);
  });

  it("invalidates the cache even when the server returned 404 (note already gone)", async () => {
    // The previous implementation only invalidated when the
    // server confirmed deletion (``existed=true``).  That left
    // the cache holding a previously-found note when the
    // server returned 404 (someone else deleted it before
    // we did), so the panel would keep showing the stale
    // entry until something else triggered a reload.
    // Unconditional invalidation keeps the local cache and
    // the authoritative server state in sync regardless of
    // which side won the race.
    mockFetch(
      vi.fn(async () => new Response("no note", { status: 404 })),
    );
    const { client, wrapper } = withQueryClient();
    const invalidateSpy = vi.spyOn(client, "invalidateQueries");

    const { result } = renderHook(() => useDeleteHostNote("192.0.2.10"), {
      wrapper,
    });
    await act(async () => {
      const existed = await result.current.mutateAsync();
      expect(existed).toBe(false);
    });

    await waitFor(() => expect(invalidateSpy).toHaveBeenCalled());
    const calls = invalidateSpy.mock.calls.map((c) => c[0]?.queryKey);
    expect(calls).toContainEqual(["notes", "host", "192.0.2.10"]);
    expect(calls).toContainEqual([
      "notes",
      "host",
      "192.0.2.10",
      "revisions",
    ]);
  });
});
