import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import {
  MemoryRouter,
  useLocation,
  useNavigate,
  useSearchParams,
} from "react-router-dom";
import { describe, expect, it } from "vitest";

import { useReportPaging } from "./use-report-paging";

function renderPaging(search = "", state?: unknown) {
  return renderHook(
    () => {
      const [params, setParams] = useSearchParams();
      const location = useLocation();
      const navigate = useNavigate();
      const skip = Number(params.get("skip") ?? 0);
      const { previousSkip, stateForSkip } = useReportPaging(
        "active",
        params.get("q") ?? "host:192.0.2.42",
        Number(params.get("limit") ?? 10),
        skip,
      );
      return {
        skip,
        previousSkip,
        location,
        navigate,
        setSkip: (value: number) => {
          const next = new URLSearchParams(params);
          next.set("skip", String(value));
          setParams(next, { state: stateForSkip(value) });
        },
        setQuery: (query: string) => {
          const next = new URLSearchParams(params);
          next.set("q", query);
          setParams(next, { state: location.state });
        },
        setLimit: (limit: number) => {
          const next = new URLSearchParams(params);
          next.set("limit", String(limit));
          setParams(next, { state: location.state });
        },
      };
    },
    {
      wrapper: ({ children }: { children: ReactNode }) => (
        <MemoryRouter initialEntries={[{ pathname: "/", search, state }]}>
          {children}
        </MemoryRouter>
      ),
    },
  );
}

describe("report page boundaries", () => {
  it("uses visited offsets through browser Back, Forward and a remount", () => {
    const { result, unmount } = renderPaging("", {
      hostNavigation: { returnTo: "/view?q=country%3AFR" },
    });
    act(() => result.current.setSkip(4));
    act(() => result.current.setSkip(7));
    expect(result.current.previousSkip).toBe(4);
    act(() => {
      void result.current.navigate(-1);
    });
    expect(result.current.skip).toBe(4);
    expect(result.current.previousSkip).toBe(0);
    act(() => {
      void result.current.navigate(1);
    });
    expect(result.current.skip).toBe(7);
    expect(result.current.previousSkip).toBe(4);
    expect(result.current.location.state.hostNavigation).toEqual({
      returnTo: "/view?q=country%3AFR",
    });
    const { search, state } = result.current.location;
    unmount();
    const refreshed = renderPaging(search, state);
    expect(refreshed.result.current.previousSkip).toBe(4);
    act(() => refreshed.result.current.setSkip(4));
    expect(refreshed.result.current.previousSkip).toBe(0);
  });

  it.each(["query", "limit"] as const)(
    "does not reuse page boundaries after changing the %s",
    (change) => {
      const { result } = renderPaging();
      act(() => result.current.setSkip(20));
      act(() => result.current.setSkip(40));
      expect(result.current.previousSkip).toBe(20);
      act(() => {
        if (change === "query") result.current.setQuery("host:192.0.2.99");
        else result.current.setLimit(30);
      });
      expect(result.current.previousSkip).toBe(change === "query" ? 30 : 10);
      act(() => result.current.setSkip(45));
      expect(result.current.previousSkip).toBe(40);
      act(() => result.current.setSkip(40));
      expect(result.current.previousSkip).toBe(change === "query" ? 30 : 10);
    },
  );

  it.each([
    undefined,
    { query: "host:192.0.2.42", limit: 10, skip: 30, previous: [0, 4, 7] },
    ...[[0, 4, 3], [-1, 4], [0, 4, 4], [0, 40], [0, "4"], [NaN], [0.5]].map(
      (previous) => ({
        query: "host:192.0.2.42",
        limit: 10,
        skip: 40,
        previous,
      }),
    ),
  ])("ignores missing, stale or malformed history %j", (entry) => {
    const { result } = renderPaging("?skip=40", {
      reportPaging: { active: entry },
    });
    expect(result.current.previousSkip).toBe(30);
  });
});
