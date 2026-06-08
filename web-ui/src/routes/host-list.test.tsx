/* @vitest-environment jsdom */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { HostListRoute } from "./host-list";

import type { HostRecord, ListParams } from "@/lib/api";

const hostCalls: Array<{
  endpoint: string | undefined;
  params: ListParams;
}> = [];

const hosts: HostRecord[] = Array.from({ length: 10 }, (_, idx) => ({
  addr: `192.0.2.${idx + 1}`,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    useHosts: (endpoint: string | undefined, params: ListParams) => {
      hostCalls.push({ endpoint, params });
      return {
        data: hosts,
        isLoading: false,
        isSuccess: true,
        isError: false,
        error: null,
      };
    },
    useCount: () => ({ data: 35 }),
    useCoordinates: () => ({
      data: undefined,
      isSuccess: true,
      isError: false,
    }),
  };
});

vi.mock("@/lib/config", () => ({
  getConfig: () => ({ dflt_limit: 10 }),
  isSequentialLoading: () => false,
}));

vi.mock("@/components/FacetSidebar", () => ({
  FacetSidebar: () => <div data-testid="facet-sidebar" />,
}));

vi.mock("@/components/FilterBar", () => ({
  FilterBar: () => <div data-testid="filter-bar" />,
  useFilterTitle: () => {},
}));

vi.mock("@/components/HostCardList", () => ({
  HostCardList: ({ hosts: rows }: { hosts: HostRecord[] }) => (
    <div data-testid="host-list">{rows.map((h) => h.addr).join(",")}</div>
  ),
}));

vi.mock("@/components/HostDetailSheet", () => ({
  HostDetailSheet: () => null,
}));

vi.mock("@/components/Timeline", () => ({
  Timeline: () => <div data-testid="timeline" />,
}));

vi.mock("@/components/WorldMap", () => ({
  WorldMap: () => <div data-testid="world-map" />,
}));

beforeEach(() => {
  hostCalls.length = 0;
});

function renderHostRoute(sectionId: "view" | "active", entry: string) {
  render(
    <MemoryRouter initialEntries={[entry]}>
      <Routes>
        <Route
          path={`/${sectionId}`}
          element={<HostListRoute sectionId={sectionId} />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

function lastHostParams(): ListParams {
  const call = hostCalls.filter((c) => c.endpoint).at(-1);
  if (!call) throw new Error("useHosts was not called");
  return call.params;
}

describe("HostListRoute pagination", () => {
  it("uses URL skip for the View section and advances with Next", async () => {
    renderHostRoute("view", "/view?skip=10&limit=10");

    expect(lastHostParams()).toMatchObject({
      q: "limit:10 skip:10",
      limit: undefined,
      skip: undefined,
    });
    expect(screen.getByText("Showing 11 to 20 of 35")).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText("Next page"));

    await waitFor(() =>
      expect(lastHostParams()).toMatchObject({
        q: "limit:10 skip:20",
        limit: undefined,
        skip: undefined,
      }),
    );
  });

  it("ignores URL skip for the Active section", () => {
    renderHostRoute("active", "/active?skip=10&limit=10");

    expect(lastHostParams()).toMatchObject({ limit: 10, skip: 0 });
    expect(screen.queryByLabelText("Next page")).toBeNull();
  });
});
