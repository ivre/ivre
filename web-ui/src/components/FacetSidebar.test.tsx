/* @vitest-environment jsdom */
import { render, screen } from "@testing-library/react";
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FacetSidebar } from "./FacetSidebar";

import type { SectionConfig } from "@/lib/sections";

// One call record per ``useTop`` invocation, captured in the mock
// below. Each entry holds the ``enabled`` flag the caller passed in
// and a controllable result so a test can transition a single facet
// from "loading" to "loaded" and observe the sidebar releasing the
// next one in order.
interface TopCall {
  field: string;
  enabled: boolean;
  resolve: () => void;
}

const calls: TopCall[] = [];

// Latest per-call mutable state, indexed by field. The mock returns
// an object whose ``isSuccess`` / ``isLoading`` flip live so the
// FacetGroup's ``useEffect`` notifies the sidebar.
const state: Record<string, { isSuccess: boolean }> = {};

vi.mock("@/lib/api", () => {
  return {
    useTop: (
      _topEndpoint: string,
      field: string,
      _params: { q?: string; limit?: number },
      options?: { enabled?: boolean },
    ) => {
      const enabled = options?.enabled !== false;
      // Push a fresh entry for every render so a test can inspect
      // the sequence of ``enabled`` values per facet.
      calls.push({
        field,
        enabled,
        resolve: () => {
          state[field] = { isSuccess: true };
        },
      });
      const s = state[field] ?? { isSuccess: false };
      // Mirror React Query v5's state machine: a query held back
      // with ``enabled: false`` keeps ``status === "pending"`` and
      // ``isPending: true`` (no data yet), while ``isLoading``
      // stays ``false`` (no request actually in flight). Once
      // ``isSuccess`` is true the query has terminated, so
      // ``isPending`` is false.
      return {
        data: s.isSuccess ? [] : undefined,
        isLoading: enabled && !s.isSuccess,
        isPending: !s.isSuccess,
        isSuccess: s.isSuccess,
        isError: false,
        error: null,
      };
    },
  };
});

const SECTION: SectionConfig = {
  id: "view",
  label: "View",
  listEndpoint: "/view",
  topEndpoint: "/view/top",
  facets: ["country", "as", "port:open"],
  resultType: "hosts",
};

beforeEach(() => {
  calls.length = 0;
  for (const k of Object.keys(state)) delete state[k];
});

afterEach(() => {
  // Defensive: leave no residual state between tests.
  calls.length = 0;
  for (const k of Object.keys(state)) delete state[k];
});

/** Return, for each facet field declared on the section, whether
 *  ``useTop`` was last called with ``enabled === true``. The mock
 *  pushes a fresh entry on every render so the most recent state
 *  for ``field`` is the last matching entry. */
function lastEnabledByField(): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const c of calls) out[c.field] = c.enabled;
  return out;
}

describe("FacetSidebar — sequential mode", () => {
  it("fires every facet in parallel when sequential is false", () => {
    render(
      <FacetSidebar
        section={SECTION}
        query=""
        onAddFilter={() => {}}
        sequential={false}
      />,
    );
    // No gating: every facet is enabled on first render.
    expect(lastEnabledByField()).toEqual({
      country: true,
      as: true,
      "port:open": true,
    });
  });

  it("holds every facet back while the sidebar gate is closed", () => {
    render(
      <FacetSidebar
        section={SECTION}
        query=""
        onAddFilter={() => {}}
        sequential
        enabled={false}
      />,
    );
    // Sidebar gate is shut (e.g. results / map still in flight).
    expect(lastEnabledByField()).toEqual({
      country: false,
      as: false,
      "port:open": false,
    });
  });

  it("releases facets one at a time, in declared order", async () => {
    const { rerender } = render(
      <FacetSidebar
        section={SECTION}
        query=""
        onAddFilter={() => {}}
        sequential
        enabled
      />,
    );

    // Only the first facet starts loading.
    expect(lastEnabledByField()).toEqual({
      country: true,
      as: false,
      "port:open": false,
    });

    // Simulate the first facet completing. The mock's ``state``
    // map drives ``isSuccess``; we then re-render so React flushes
    // the FacetGroup's ``useEffect``, which calls ``onLoaded`` and
    // bumps the sidebar's counter.
    await act(async () => {
      state["country"] = { isSuccess: true };
      rerender(
        <FacetSidebar
          section={SECTION}
          query=""
          onAddFilter={() => {}}
          sequential
          enabled
        />,
      );
    });

    expect(lastEnabledByField()).toMatchObject({
      country: true,
      as: true,
      "port:open": false,
    });

    // Release the second facet.
    await act(async () => {
      state["as"] = { isSuccess: true };
      rerender(
        <FacetSidebar
          section={SECTION}
          query=""
          onAddFilter={() => {}}
          sequential
          enabled
        />,
      );
    });

    expect(lastEnabledByField()).toMatchObject({
      country: true,
      as: true,
      "port:open": true,
    });
  });

  it("resets the sequence when the active query changes", async () => {
    const { rerender } = render(
      <FacetSidebar
        section={SECTION}
        query=""
        onAddFilter={() => {}}
        sequential
        enabled
      />,
    );

    // Walk the sequence to completion.
    await act(async () => {
      state["country"] = { isSuccess: true };
      rerender(
        <FacetSidebar
          section={SECTION}
          query=""
          onAddFilter={() => {}}
          sequential
          enabled
        />,
      );
    });
    await act(async () => {
      state["as"] = { isSuccess: true };
      rerender(
        <FacetSidebar
          section={SECTION}
          query=""
          onAddFilter={() => {}}
          sequential
          enabled
        />,
      );
    });
    await act(async () => {
      state["port:open"] = { isSuccess: true };
      rerender(
        <FacetSidebar
          section={SECTION}
          query=""
          onAddFilter={() => {}}
          sequential
          enabled
        />,
      );
    });
    expect(lastEnabledByField()).toMatchObject({
      country: true,
      as: true,
      "port:open": true,
    });

    // Now reset the per-field mock state to simulate a fresh
    // search invalidating the cache, change the query, and verify
    // only the first facet is re-enabled — the rest wait again.
    await act(async () => {
      for (const k of Object.keys(state)) delete state[k];
      rerender(
        <FacetSidebar
          section={SECTION}
          query="country:fr"
          onAddFilter={() => {}}
          sequential
          enabled
        />,
      );
    });

    expect(lastEnabledByField()).toMatchObject({
      country: true,
      as: false,
      "port:open": false,
    });
  });

  it("renders Loading… (not 'No values.') for held-back facets", async () => {
    // Regression guard against the React Query v5 pitfall: a
    // facet held back with ``enabled: false`` has
    // ``isLoading === false`` and ``data === undefined``. If the
    // FacetGroup keyed its placeholder off ``isLoading`` the
    // held-back facets would render the "No values." empty-state
    // instead of "Loading…". Keying off ``isPending`` (which is
    // ``true`` whenever no data has yet arrived) keeps the right
    // placeholder up until the query is released.
    const { rerender } = render(
      <FacetSidebar
        section={SECTION}
        query=""
        onAddFilter={() => {}}
        sequential
        enabled
      />,
    );

    // All three facets — the one being fetched and the two held
    // back — should display "Loading…", and none of them should
    // display the empty-results placeholder.
    expect(screen.getAllByText("Loading…")).toHaveLength(3);
    expect(screen.queryByText("No values.")).toBeNull();

    // Release the first facet (with an empty result). The first
    // facet now renders the empty-state; the other two are still
    // held back and still show "Loading…".
    await act(async () => {
      state["country"] = { isSuccess: true };
      rerender(
        <FacetSidebar
          section={SECTION}
          query=""
          onAddFilter={() => {}}
          sequential
          enabled
        />,
      );
    });
    expect(screen.getAllByText("Loading…")).toHaveLength(2);
    expect(screen.getAllByText("No values.")).toHaveLength(1);
  });

  it("renders nothing when the section declares no facets", () => {
    const empty: SectionConfig = { ...SECTION, facets: [] };
    const { container } = render(
      <FacetSidebar
        section={empty}
        query=""
        onAddFilter={() => {}}
        sequential
        enabled
      />,
    );
    expect(container).toBeEmptyDOMElement();
    // Sanity check: the heading from a real facet would have been
    // visible if the component had rendered.
    expect(screen.queryByText(/country/i)).toBeNull();
  });
});
