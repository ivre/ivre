import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { HostReportRoute } from "./host-report";

import type { HostRecord, PassiveRecord } from "@/lib/api";
import { hostRecordId } from "@/lib/host-report";

vi.mock("@/components/HostNotesPanel", () => ({
  HostNotesPanel: ({ addr }: { addr: string }) => <p>Notes for {addr}</p>,
}));

const address = "192.0.2.42";
const latest: HostRecord = {
  addr: address,
  _id: "000000000000000000000001",
  source: "lab-new",
  starttime: "2026-11-18T09:42:00Z",
  endtime: "2026-11-18T09:44:00Z",
  hostnames: [{ name: "edge.example.net" }],
  ports: [
    {
      port: 443,
      protocol: "tcp",
      state_state: "open",
      service_name: "https",
      service_product: "nginx",
      scripts: [
        {
          id: "ssl-cert",
          output: "Subject: CN=edge.example.net\nIssuer: Example Lab CA",
        },
      ],
    },
    {
      port: 22,
      protocol: "tcp",
      state_state: "open",
      service_name: "ssh",
      scripts: [{ id: "ssh-hostkey", output: "Example SSH key" }],
    },
    {
      port: -1,
      protocol: "tcp",
      scripts: [{ id: "clock-skew", output: "mean: 1s" }],
    },
  ],
  traces: [
    {
      protocol: "tcp",
      port: 443,
      hops: [
        { ttl: 2, ipaddr: address, rtt: 2 },
        { ttl: 1, ipaddr: "192.0.2.1", rtt: 1 },
      ],
    },
  ],
  os: { osclass: [{ osfamily: "Linux", accuracy: 95 }] },
  cpes: [
    {
      type: "o",
      vendor: "linux",
      product: "linux_kernel",
      version: "",
      origins: ["os"],
    },
    {
      type: "a",
      vendor: "openbsd",
      product: "openssh",
      version: "9.6p1",
      origins: ["ports.port:22"],
    },
  ],
};
const older: HostRecord = {
  ...latest,
  _id: "000000000000000000000002",
  source: ["lab-old"],
  starttime: "2026-11-12T09:00:00Z",
  endtime: "2026-11-12T09:02:00Z",
  ports: [
    {
      port: 443,
      protocol: "tcp",
      state_state: "open",
      scripts: [{ id: "ssl-cert", output: "Older certificate" }],
    },
  ],
};
const observation: PassiveRecord = {
  addr: address,
  schema_version: 3,
  recontype: "HTTP_SERVER_HEADER",
  source: "SERVER",
  port: 443,
  sensor: "sensor-east",
  value: "nginx/1.24.0",
  count: 4,
  firstseen: 1794988800,
  lastseen: 1794992400,
};
let viewRecords: HostRecord[];
let activeRecords: HostRecord[];
let passiveRecords: PassiveRecord[];
let failure: { endpoint: string; status: number } | undefined;
let idsSupported: boolean;
let responseCap: number | ((skip: number) => number);
const calls: URL[] = [];

function matchesActivePort(record: HostRecord, query: string) {
  const match =
    /(?:^|\s)(?:(open|closed|filtered):)?(tcp|udp)\/(\d+)(?:\s|$)/.exec(query);
  return (
    !match ||
    record.ports?.some(
      (port) =>
        port.protocol === match[2] &&
        port.port === Number(match[3]) &&
        port.state_state === (match[1] ?? "open"),
    )
  );
}

function Location() {
  const location = useLocation();
  return (
    <p data-testid="location">
      {location.pathname}
      {location.search}
    </p>
  );
}

function renderReport(
  entry = `/view/host/${address}`,
  sectionId: "view" | "active" = "view",
  state?: unknown,
) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter
        initialEntries={[
          {
            pathname: entry.split("?")[0],
            search: entry.includes("?") ? `?${entry.split("?")[1]}` : "",
            state,
            key: crypto.randomUUID(),
          },
        ]}
      >
        <Location />
        <Routes>
          <Route
            path="/view/host/:addr"
            element={<HostReportRoute sectionId={sectionId} />}
          />
          <Route
            path="/active/host/:addr"
            element={<HostReportRoute sectionId="active" />}
          />
          <Route path="/view" element={<p>Original search results</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  viewRecords = [latest];
  activeRecords = [latest, older];
  passiveRecords = [observation];
  failure = undefined;
  idsSupported = true;
  responseCap = Infinity;
  calls.length = 0;
  window.config = {
    modules: ["view", "active", "passive", "notes"],
    dflt_limit: 10,
  };
  vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  HTMLElement.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      const url = new URL(input, "http://localhost");
      calls.push(url);
      if (url.pathname === failure?.endpoint)
        return new Response("Denied", { status: failure.status });
      if (url.pathname.includes("/top/")) return Response.json([]);
      if (url.pathname.endsWith("/count"))
        return new Response(
          String(
            url.pathname.includes("/scans")
              ? activeRecords.filter((record) =>
                  matchesActivePort(record, url.searchParams.get("q") ?? ""),
                ).length
              : passiveRecords.length,
          ),
        );
      let records: Array<HostRecord | PassiveRecord> =
        url.pathname === "/cgi/view"
          ? viewRecords
          : url.pathname === "/cgi/scans"
            ? activeRecords
            : passiveRecords;
      if (url.pathname === "/cgi/scans")
        records = activeRecords.filter((record) =>
          matchesActivePort(record, url.searchParams.get("q") ?? ""),
        );
      const host = /host:(?:"([^"]+)"|(\S+))/.exec(
        url.searchParams.get("q") ?? "",
      );
      if (host)
        records = records.filter(
          (record) => record.addr === (host[1] ?? host[2]),
        );
      const recordId = url.searchParams.get("record");
      if (recordId !== null)
        records = records.filter((record) => record._id === recordId);
      const skip = Number(
        /(?:^|\s)skip:(\d+)/.exec(url.searchParams.get("q") ?? "")?.[1] ?? 0,
      );
      const limit = Number(
        /(?:^|\s)limit:(\d+)/.exec(url.searchParams.get("q") ?? "")?.[1] ?? 50,
      );
      const cap =
        url.pathname === "/cgi/view"
          ? limit
          : Math.min(
              limit,
              typeof responseCap === "number" ? responseCap : responseCap(skip),
            );
      return new Response(
        records
          .slice(skip, skip + cap)
          .map((record) => {
            const output = { ...record };
            if (!idsSupported || url.searchParams.get("include_id") !== "1")
              delete output._id;
            return JSON.stringify(output);
          })
          .join("\n"),
        { headers: { "Content-Type": "application/x-ndjson" } },
      );
    }),
  );
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete window.config;
});

const sourceNav = () =>
  screen.getByRole("navigation", { name: "Host evidence sources" });

describe("full-page IP reports", () => {
  it.each(
    (["view", "active"] as const).flatMap((origin) =>
      (["view", "active", "passive", "notes"] as const).map((tab) => ({
        origin,
        tab,
      })),
    ),
  )(
    "preserves the $tab tab between neighbors from $origin results",
    async ({ origin, tab }) => {
      const nextAddress = "192.0.2.99";
      const nextRecordId = "000000000000000000000003";
      viewRecords.push({ ...latest, addr: nextAddress });
      activeRecords.push({ ...latest, addr: nextAddress, _id: nextRecordId });
      passiveRecords.push({ ...observation, addr: nextAddress });
      const scanNavigation = origin === "active" && tab === "active";
      const record = scanNavigation ? `&record=${latest._id}` : "";
      renderReport(
        `/${origin}/host/${address}?tab=${tab}&q=country%3AFR&skip=30${record}`,
        origin,
        {
          hostNavigation: {
            returnTo: `/${origin}?q=country%3AFR&skip=30`,
            returnScrollY: 900,
            entries: [
              {
                addr: address,
                record: origin === "active" ? latest._id : undefined,
              },
              {
                addr: nextAddress,
                record: origin === "active" ? nextRecordId : undefined,
              },
            ],
            currentIndex: 0,
          },
        },
      );
      const label = {
        view: /^View/,
        active: /^Active scans/,
        passive: /^Passive/,
        notes: /^Notes/,
      }[tab];
      expect(
        within(sourceNav()).getByRole("link", { name: label }),
      ).toHaveAttribute("aria-current", "page");
      const next = screen.getByRole("link", {
        name: scanNavigation ? "Next scan" : "Next host",
      });
      const nextUrl = new URL(next.getAttribute("href")!, "http://localhost");
      expect(nextUrl.pathname).toBe(`/${origin}/host/${nextAddress}`);
      expect(nextUrl.searchParams.get("tab")).toBe(tab);
      expect(nextUrl.searchParams.get("record")).toBe(
        scanNavigation ? nextRecordId : null,
      );
      fireEvent.click(next);
      await waitFor(() =>
        expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
          nextAddress,
        ),
      );
      expect(
        within(sourceNav()).getByRole("link", { name: label }),
      ).toHaveAttribute("aria-current", "page");
      expect(screen.getByTestId("location")).toHaveTextContent(
        "q=country%3AFR&skip=30",
      );
      expect(
        screen.getByRole("link", { name: "Back to results" }),
      ).toHaveAttribute("href", `/${origin}?q=country%3AFR&skip=30`);
      fireEvent.click(
        screen.getByRole("link", {
          name: scanNavigation ? "Previous scan" : "Previous host",
        }),
      );
      await waitFor(() =>
        expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
          address,
        ),
      );
      expect(
        within(sourceNav()).getByRole("link", { name: label }),
      ).toHaveAttribute("aria-current", "page");
      expect(
        screen.getByRole("link", {
          name: scanNavigation ? "Next scan" : "Next host",
        }),
      ).toBeVisible();
    },
  );

  it("renders sorted ports and visible scripts, including host scripts, without a dialog or result-list requests", async () => {
    renderReport(`/view/host/${address}?q=country%3AFR&skip=30&limit=10`);
    expect(await screen.findByText("Example SSH key")).toBeVisible();
    expect(screen.getByText(/Subject: CN=edge.example.net/)).toBeVisible();
    expect(screen.getByText("mean: 1s")).toBeVisible();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    const headings = screen
      .getAllByRole("heading", { level: 2 })
      .map((item) => item.textContent);
    expect(headings.indexOf("22/tcp")).toBeLessThan(
      headings.indexOf("443/tcp"),
    );
    expect(headings).not.toContain("-1/tcp");
    const cpes = screen.getByRole("table", {
      name: "Common Platform Enumeration",
    });
    expect(
      within(cpes).getByRole("cell", { name: "linux_kernel" }),
    ).toBeVisible();
    expect(within(cpes).getByRole("cell", { name: "9.6p1" })).toBeVisible();
    expect(screen.queryByText("Unknown CPE")).not.toBeInTheDocument();
    const viewCall = calls.find((url) => url.pathname === "/cgi/view")!;
    expect(viewCall.searchParams.get("q")).toBe(`host:${address} limit:1`);
    expect(
      calls.some(
        (url) =>
          url.pathname.includes("/top/") ||
          url.pathname.includes("/coordinates"),
      ),
    ).toBe(false);
    expect(
      screen.getByRole("link", { name: "Back to results" }),
    ).toHaveAttribute("href", "/view?q=country%3AFR&skip=30&limit=10");
  });

  it("supports optional collapse, wrapping, and shareable section links", async () => {
    renderReport();
    const output = await screen.findByText("Example SSH key");
    expect(output).toHaveClass("bg-muted", "dark:bg-muted/40");
    fireEvent.click(
      screen.getByRole("button", { name: "Collapse ssh-hostkey" }),
    );
    expect(output).not.toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Expand ssh-hostkey" }));
    expect(output).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Line wrapping: on" }));
    expect(output).toHaveClass("whitespace-pre");
    fireEvent.click(
      within(
        screen.getByRole("navigation", { name: "Report sections" }),
      ).getByRole("link", { name: /443\/tcp/ }),
    );
    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent(
        "section=port-tcp-443",
      ),
    );
    await waitFor(() =>
      expect(HTMLElement.prototype.scrollIntoView).toHaveBeenCalled(),
    );
  });

  it("returns to the View header without changing filters and can revisit the same section", async () => {
    renderReport(
      `/view/host/${address}?q=country%3AFR&skip=30&section=port-tcp-443`,
    );
    await screen.findByText("Example SSH key");
    fireEvent.click(
      within(
        screen.getByRole("navigation", { name: "Report sections" }),
      ).getByRole("button", { name: "Back to top" }),
    );
    await waitFor(() => expect(window.scrollTo).toHaveBeenCalledWith(0, 0));
    expect(screen.getByRole("heading", { level: 1 })).toHaveFocus();
    expect(screen.getByTestId("location")).toHaveTextContent(
      "q=country%3AFR&skip=30",
    );
    expect(screen.getByTestId("location")).not.toHaveTextContent("section=");
    fireEvent.click(
      within(
        screen.getByRole("navigation", { name: "Report sections" }),
      ).getByRole("link", { name: /443\/tcp/ }),
    );
    await waitFor(() =>
      expect(HTMLElement.prototype.scrollIntoView).toHaveBeenCalled(),
    );
    expect(screen.getByTestId("location")).toHaveTextContent(
      "section=port-tcp-443",
    );
  });

  it("does not replay the section jump when report data changes without navigation", async () => {
    const client = renderReport(`/view/host/${address}?section=port-tcp-443`);
    await waitFor(() =>
      expect(document.getElementById("port-tcp-443")).toHaveFocus(),
    );
    vi.mocked(HTMLElement.prototype.scrollIntoView).mockClear();
    vi.mocked(window.scrollTo).mockClear();
    act(() => {
      client.setQueryData(
        ["hosts", "/view", { q: `host:${address} limit:1` }],
        [{ ...latest, source: "updated-report-source" }],
      );
    });
    expect(
      await screen.findByText(/View sources: updated-report-source/),
    ).toBeVisible();
    await act(
      () =>
        new Promise<void>((resolve) => {
          requestAnimationFrame(() => resolve());
        }),
    );
    expect(HTMLElement.prototype.scrollIntoView).not.toHaveBeenCalled();
    expect(window.scrollTo).not.toHaveBeenCalled();
  });

  it("selects individual active records without inheriting result filters and retains their identity on reload", async () => {
    renderReport(
      `/active/host/${address}?q=country%3AFR&skip=200&record=${hostRecordId(older)}`,
      "active",
    );
    expect(await screen.findByText("Older certificate")).toBeVisible();
    expect(screen.queryByText("Example SSH key")).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Individual active record"),
    ).not.toBeInTheDocument();
    const request = calls.find((url) => url.pathname === "/cgi/scans")!;
    expect(request.searchParams.get("q")).toBe(`host:${address} limit:1`);
    expect(request.searchParams.get("record")).toBe(older._id);
    expect(request.searchParams.get("include_id")).toBe("1");
    fireEvent.click(screen.getByRole("link", { name: "Back to active scans" }));
    const browser = await screen.findByRole("region", {
      name: "Active scans for this IP",
    });
    expect(
      await within(browser).findAllByRole("img", {
        name: /Timeline of 2 scans/,
      }),
    ).toHaveLength(2);
    fireEvent.click(
      (await within(browser).findAllByRole("link", { name: "Details" }))[0],
    );
    expect(await screen.findByText("Example SSH key")).toBeVisible();
  });

  it("never substitutes another snapshot when a selected record is missing", async () => {
    renderReport(
      `/active/host/${address}?record=000000000000000000000099`,
      "active",
    );
    expect(
      await screen.findByText(/This active scan record is no longer available/),
    ).toBeVisible();
    expect(screen.queryByText("Example SSH key")).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("link", { name: "Browse active scans →" }),
    );
    fireEvent.click(
      (await screen.findAllByRole("link", { name: "Details" }))[0],
    );
    expect(await screen.findByText("Example SSH key")).toBeVisible();
  });

  it("loads an old record outside the first page without cache or originating search filters", async () => {
    activeRecords = [
      ...Array.from({ length: 30 }, (_, index) => ({
        ...latest,
        _id: String(index + 100),
      })),
      older,
    ];
    renderReport(
      `/active/host/${address}?q=source%3Alab-new&skip=900&activeQ=source%3Alab-new&recordsSkip=20&record=${hostRecordId(older)}`,
      "active",
    );
    expect(await screen.findByText("Older certificate")).toBeVisible();
    const requests = calls.filter((url) => url.pathname === "/cgi/scans");
    expect(requests).toHaveLength(1);
    expect(requests[0].searchParams.get("q")).toBe(`host:${address} limit:1`);
    expect(requests[0].searchParams.get("record")).toBe(older._id);
  });

  it("keeps database identity when record content changes", async () => {
    activeRecords = [
      {
        ...older,
        source: "renamed-source",
        ports: [
          {
            port: 443,
            protocol: "tcp",
            scripts: [{ id: "ssl-cert", output: "Updated certificate" }],
          },
        ],
      },
    ];
    renderReport(
      `/active/host/${address}?record=${older._id}&activeQ=source%3Alab-old`,
      "active",
    );
    expect(await screen.findByText("Updated certificate")).toBeVisible();
    const request = calls.find((url) => url.pathname === "/cgi/scans")!;
    expect(request.searchParams.get("record")).toBe(older._id);
    expect(request.searchParams.get("q")).toBe(`host:${address} limit:1`);
  });

  it("disables individual scan links when the server does not return identifiers", async () => {
    idsSupported = false;
    renderReport(`/active/host/${address}`, "active");
    expect(
      await screen.findByText(/Database identifiers are missing/),
    ).toBeVisible();
    expect(
      screen.queryByRole("link", { name: "Details" }),
    ).not.toBeInTheDocument();
    for (const control of screen.getAllByRole("button", { name: "Details" }))
      expect(control).toBeDisabled();
  });

  it("does not fall back to a different record when ID metadata is unavailable", async () => {
    idsSupported = false;
    renderReport(`/active/host/${address}?record=${latest._id}`, "active");
    expect(
      await screen.findByText(/The server did not return database identifiers/),
    ).toBeVisible();
    expect(screen.queryByText("Example SSH key")).not.toBeInTheDocument();
  });

  it("opens Passive evidence for the exact IP and port, with explicit filters and observation dates", async () => {
    renderReport(`/view/host/${address}?q=service%3Ahttps&skip=40`);
    await screen.findByText(/Subject: CN=edge.example.net/);
    const port = document.getElementById("port-tcp-443")!;
    fireEvent.click(
      within(port).getByRole("link", { name: "Passive observations →" }),
    );
    expect(await screen.findByText("nginx/1.24.0")).toBeVisible();
    expect(
      screen.getAllByRole("button", { name: "Remove filter tcp/443" }),
    ).toHaveLength(2);
    expect(screen.getAllByTitle("Fixed IP scope")[0]).toHaveTextContent(
      `host:${address}`,
    );
    expect(
      screen.queryByRole("button", { name: `Remove filter host:${address}` }),
    ).not.toBeInTheDocument();
    const request = calls.find((url) => url.pathname === "/cgi/passive")!;
    expect(request.searchParams.get("q")).toBe(
      `host:${address} tcp/443 -sortby:lastseen limit:10`,
    );
    expect(
      screen.getAllByRole("img", { name: /Timeline of 1 passive observation/ }),
    ).toHaveLength(2);
    expect(
      screen.getByRole("button", { name: "sensor:sensor-east" }),
    ).toBeVisible();
    const input = screen.getAllByRole("textbox", { name: "Filter query" })[0];
    fireEvent.change(input, { target: { value: "sensor:sensor-west" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(
        calls.some((url) =>
          url.searchParams.get("q")?.includes("sensor:sensor-west"),
        ),
      ).toBe(true),
    );
  });

  it.each(
    (["tcp", "udp"] as const).flatMap((protocol) =>
      (["open", "closed", "filtered"] as const).map((state) => ({
        protocol,
        state,
      })),
    ),
  )(
    "matches $protocol/443 $state observations in related Active scans",
    async ({ protocol, state }) => {
      const port = {
        protocol,
        port: 443,
        state_state: state,
      };
      viewRecords = [{ ...latest, ports: [port] }];
      activeRecords = (["open", "closed", "filtered"] as const).map(
        (value, index) => ({
          ...latest,
          _id: String(index + 100),
          source: `scan-${value}`,
          ports: [{ ...port, state_state: value }],
        }),
      );
      renderReport(
        `/view/host/${address}?q=country%3AFR&skip=900&activeQ=source%3Aold&recordsSkip=20`,
      );
      const related = await screen.findByRole("link", {
        name: "Active scans →",
      });
      const url = new URL(related.getAttribute("href")!, "http://localhost");
      expect(url.searchParams.get("activeQ")).toBe(`${state}:${protocol}/443`);
      expect(url.searchParams.has("recordsSkip")).toBe(false);
      fireEvent.click(related);
      const browser = await screen.findByRole("region", {
        name: "Active scans for this IP",
      });
      expect(
        await within(browser).findByText("Showing 1–1 of 1"),
      ).toBeVisible();
      expect(
        within(browser).getByRole("button", {
          name: `scan-${state}`,
        }),
      ).toBeVisible();
      expect(
        within(browser).getAllByRole("link", { name: "Details" }),
      ).toHaveLength(1);
      const requests = calls.filter(
        (request) => request.pathname === "/cgi/scans",
      );
      expect(requests.length).toBeGreaterThan(0);
      for (const request of requests) {
        expect(request.searchParams.get("q")).toBe(
          `host:${address} ${state}:${protocol}/443 -sortby:endtime -sortby:starttime limit:10`,
        );
      }
      expect(
        screen.getByRole("link", { name: "Back to results" }),
      ).toHaveAttribute("href", "/view?q=country%3AFR&skip=900");
    },
  );

  it.each([undefined, "open|filtered", "unfiltered", "unknown"])(
    "does not substitute open observations for an unmatchable displayed state %j",
    async (state) => {
      viewRecords = [
        {
          ...latest,
          ports: [{ protocol: "tcp", port: 443, state_state: state }],
        },
      ];
      renderReport();
      expect(await screen.findByText("Active scans unavailable")).toBeVisible();
      expect(
        screen.queryByRole("link", { name: "Active scans →" }),
      ).not.toBeInTheDocument();
      expect(
        screen.getByRole("link", { name: "Passive observations →" }),
      ).toBeVisible();
      expect(calls.some((request) => request.pathname === "/cgi/scans")).toBe(
        false,
      );
    },
  );

  it("keeps Active and Passive usable when no merged View record exists", async () => {
    viewRecords = [];
    renderReport();
    expect(await screen.findByText(/No merged View record/)).toBeVisible();
    fireEvent.click(
      within(sourceNav()).getByRole("link", { name: /Active scans/ }),
    );
    const browser = await screen.findByRole("region", {
      name: "Active scans for this IP",
    });
    expect(screen.queryByText("Example SSH key")).not.toBeInTheDocument();
    fireEvent.click(
      (await within(browser).findAllByRole("link", { name: "Details" }))[0],
    );
    expect(await screen.findByText("Example SSH key")).toBeVisible();
  });

  it("does not query disabled evidence modules and explains direct disabled-tab URLs", async () => {
    window.config = { modules: ["view"] };
    renderReport(`/view/host/${address}?tab=passive`);
    expect(await screen.findByText(/This source is not exposed/)).toBeVisible();
    expect(
      within(sourceNav()).queryByRole("link", { name: /Passive/ }),
    ).not.toBeInTheDocument();
    expect(
      calls.some(
        (url) =>
          url.pathname.startsWith("/cgi/passive") ||
          url.pathname.startsWith("/cgi/scans"),
      ),
    ).toBe(false);
  });

  it("distinguishes denied access from a genuinely empty source", async () => {
    failure = { endpoint: "/cgi/passive", status: 403 };
    renderReport(`/view/host/${address}?tab=passive`);
    expect(await screen.findByRole("alert")).toHaveTextContent("Access denied");
    expect(
      screen.queryByText(/No passive observations match/),
    ).not.toBeInTheDocument();
  });

  it("paginates active evidence independently of the originating search", async () => {
    activeRecords = Array.from({ length: 12 }, (_, index) => ({
      ...latest,
      _id: String(index + 100),
      source: `lab-${index}`,
    }));
    renderReport(`/active/host/${address}?q=country%3AFR&skip=200`, "active");
    expect(await screen.findByText("Showing 1–10 of 12")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Next records" }));
    expect(await screen.findByText("Showing 11–12 of 12")).toBeVisible();
    expect(
      calls.some(
        (url) =>
          url.pathname === "/cgi/scans" &&
          url.searchParams.get("q") ===
            `host:${address} -sortby:endtime -sortby:starttime limit:10 skip:10`,
      ),
    ).toBe(true);
    expect(
      screen.getByRole("link", { name: "Back to results" }),
    ).toHaveAttribute("href", "/active?q=country%3AFR&skip=200");
    fireEvent.click(screen.getByRole("button", { name: "Previous records" }));
    expect(await screen.findByText("Showing 1–10 of 12")).toBeVisible();
  });

  it("paginates passive observations and resets paging when filters change", async () => {
    passiveRecords = Array.from({ length: 12 }, (_, index) => ({
      ...observation,
      sensor: `sensor-${index}`,
    }));
    renderReport(`/view/host/${address}?tab=passive&skip=900&passivePort=443`);
    expect(await screen.findByText("Showing 1–10 of 12")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Next records" }));
    expect(await screen.findByText("Showing 11–12 of 12")).toBeVisible();
    const input = screen.getAllByRole("textbox", { name: "Filter query" })[0];
    fireEvent.change(input, { target: { value: "sensor:sensor-1" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => {
      const request = calls
        .filter((url) => url.pathname === "/cgi/passive")
        .at(-1);
      expect(request?.searchParams.get("q")).toBe(
        `host:${address} tcp/443 sensor:sensor-1 -sortby:lastseen limit:10`,
      );
    });
  });

  it.each(["active", "passive"] as const)(
    "reverses actual %s page boundaries under variable server caps and a short final page",
    async (source) => {
      activeRecords = Array.from({ length: 9 }, (_, index) => ({
        ...latest,
        _id: String(index + 100),
        source: `lab-${index}`,
      }));
      passiveRecords = Array.from({ length: 9 }, (_, index) => ({
        ...observation,
        sensor: `sensor-${index}`,
      }));
      responseCap = (skip) => (skip === 4 ? 3 : 4);
      renderReport(
        `/view/host/${address}?tab=${source}&q=country%3AFR&skip=900`,
      );
      expect(await screen.findByText("Showing 1–4 of 9")).toBeVisible();
      expect(
        screen.getByRole("button", { name: "Previous records" }),
      ).toBeDisabled();
      fireEvent.click(screen.getByRole("button", { name: "Next records" }));
      expect(await screen.findByText("Showing 5–7 of 9")).toBeVisible();
      fireEvent.click(screen.getByRole("button", { name: "Next records" }));
      expect(await screen.findByText("Showing 8–9 of 9")).toBeVisible();
      expect(
        screen.getByRole("button", { name: "Next records" }),
      ).toBeDisabled();
      fireEvent.click(screen.getByRole("button", { name: "Previous records" }));
      expect(await screen.findByText("Showing 5–7 of 9")).toBeVisible();
      const key = source === "active" ? "recordsSkip" : "passiveSkip";
      expect(screen.getByTestId("location")).toHaveTextContent(`${key}=4`);
      fireEvent.click(screen.getByRole("button", { name: "Previous records" }));
      expect(await screen.findByText("Showing 1–4 of 9")).toBeVisible();
      expect(screen.getByTestId("location")).not.toHaveTextContent(`${key}=`);
      expect(screen.getByTestId("location")).toHaveTextContent("skip=900");
    },
  );

  it("retains independent capped page histories when switching evidence tabs", async () => {
    activeRecords = Array.from({ length: 12 }, (_, index) => ({
      ...latest,
      _id: String(index + 100),
    }));
    passiveRecords = Array.from({ length: 12 }, (_, index) => ({
      ...observation,
      sensor: `sensor-${index}`,
    }));
    responseCap = 4;
    renderReport(`/view/host/${address}?tab=active`);
    expect(await screen.findByText("Showing 1–4 of 12")).toBeVisible();
    for (const label of ["Showing 5–8 of 12", "Showing 9–12 of 12"]) {
      fireEvent.click(screen.getByRole("button", { name: "Next records" }));
      expect(await screen.findByText(label)).toBeVisible();
    }
    responseCap = 3;
    fireEvent.click(within(sourceNav()).getByRole("link", { name: /Passive/ }));
    expect(await screen.findByText("Showing 1–3 of 12")).toBeVisible();
    for (const label of ["Showing 4–6 of 12", "Showing 7–9 of 12"]) {
      fireEvent.click(screen.getByRole("button", { name: "Next records" }));
      expect(await screen.findByText(label)).toBeVisible();
    }
    responseCap = 4;
    fireEvent.click(
      within(sourceNav()).getByRole("link", { name: /Active scans/ }),
    );
    expect(await screen.findByText("Showing 9–12 of 12")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Previous records" }));
    expect(await screen.findByText("Showing 5–8 of 12")).toBeVisible();
    responseCap = 3;
    fireEvent.click(within(sourceNav()).getByRole("link", { name: /Passive/ }));
    expect(await screen.findByText("Showing 7–9 of 12")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Previous records" }));
    expect(await screen.findByText("Showing 4–6 of 12")).toBeVisible();
  });

  it("retains capped page history after opening a scan and returning to its browser", async () => {
    activeRecords = Array.from({ length: 11 }, (_, index) => ({
      ...latest,
      _id: String(index + 100),
    }));
    responseCap = 4;
    renderReport(`/view/host/${address}?tab=active`);
    expect(await screen.findByText("Showing 1–4 of 11")).toBeVisible();
    for (const label of ["Showing 5–8 of 11", "Showing 9–11 of 11"]) {
      fireEvent.click(screen.getByRole("button", { name: "Next records" }));
      expect(await screen.findByText(label)).toBeVisible();
    }
    fireEvent.click(screen.getAllByRole("link", { name: "Details" })[0]);
    expect(await screen.findByText("Example SSH key")).toBeVisible();
    fireEvent.click(screen.getByRole("link", { name: "Back to active scans" }));
    expect(await screen.findByText("Showing 9–11 of 11")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Previous records" }));
    expect(await screen.findByText("Showing 5–8 of 11")).toBeVisible();
  });

  it.each(["active", "passive"] as const)(
    "keeps capped %s pages navigable without a total, including back from an empty page",
    async (source) => {
      activeRecords = Array.from({ length: 5 }, (_, index) => ({
        ...latest,
        _id: String(index + 100),
      }));
      passiveRecords = Array.from({ length: 5 }, (_, index) => ({
        ...observation,
        sensor: `sensor-${index}`,
      }));
      responseCap = 3;
      failure = {
        endpoint:
          source === "active" ? "/cgi/scans/count" : "/cgi/passive/count",
        status: 403,
      };
      renderReport(`/view/host/${address}?tab=${source}`);
      expect(
        await screen.findByText("Showing 1–3 · total unavailable"),
      ).toBeVisible();
      fireEvent.click(screen.getByRole("button", { name: "Next records" }));
      expect(
        await screen.findByText("Showing 4–5 · total unavailable"),
      ).toBeVisible();
      fireEvent.click(screen.getByRole("button", { name: "Next records" }));
      expect(
        await screen.findByText("No records on this page · total unavailable"),
      ).toBeVisible();
      expect(
        screen.getByRole("button", { name: "Next records" }),
      ).toBeDisabled();
      fireEvent.click(screen.getByRole("button", { name: "Previous records" }));
      expect(
        await screen.findByText("Showing 4–5 · total unavailable"),
      ).toBeVisible();
      fireEvent.click(screen.getByRole("button", { name: "Previous records" }));
      expect(
        await screen.findByText("Showing 1–3 · total unavailable"),
      ).toBeVisible();
    },
  );

  it("keeps the active evidence page when navigating between individual scans", async () => {
    activeRecords = Array.from({ length: 12 }, (_, index) => ({
      ...latest,
      _id: String(index + 100),
      source: `lab-${index}`,
    }));
    renderReport(`/active/host/${address}?recordsSkip=10`, "active");
    const links = await screen.findAllByRole("link", { name: "Details" });
    expect(links).toHaveLength(2);
    fireEvent.click(links[0]);
    expect(await screen.findByText("Example SSH key")).toBeVisible();
    fireEvent.click(screen.getByRole("link", { name: "Next scan" }));
    await waitFor(() => {
      expect(screen.getByTestId("location")).toHaveTextContent(
        "recordsSkip=10",
      );
      expect(screen.getByTestId("location")).toHaveTextContent(
        `record=${hostRecordId(activeRecords[11])}`,
      );
    });
    expect(
      screen.getByRole("link", { name: "Back to active scans" }),
    ).toHaveAttribute("href", expect.stringContaining("recordsSkip=10"));
  });

  it("does not present a failed count as zero records", async () => {
    failure = { endpoint: "/cgi/scans/count", status: 403 };
    renderReport(`/active/host/${address}`, "active");
    expect(
      (await screen.findAllByRole("link", { name: "Details" })).length,
    ).toBeGreaterThan(0);
    expect(
      within(sourceNav()).getByRole("link", {
        name: "Active scans",
      }),
    ).toBeVisible();
    expect(screen.getByText(/total unavailable/)).toBeVisible();
  });

  it("distinguishes an unavailable source from empty observations", async () => {
    failure = { endpoint: "/cgi/passive", status: 404 };
    renderReport(`/view/host/${address}?tab=passive`);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Source unavailable",
    );
    expect(
      screen.queryByText(/No passive observations match/),
    ).not.toBeInTheDocument();
  });

  it("shows structured script data when no text output exists", async () => {
    viewRecords = [
      {
        addr: address,
        ports: [
          {
            port: 443,
            protocol: "tcp",
            scripts: [
              { id: "example-script", findings: [{ name: "example finding" }] },
            ],
          },
        ],
      },
    ];
    renderReport();
    expect(await screen.findByText(/"name": "example finding"/)).toBeVisible();
  });

  it("preserves all backend CPE components, including version suffixes and unspecified fields", async () => {
    viewRecords = [
      {
        addr: address,
        cpes: [
          {
            type: "a",
            vendor: "example",
            product: "service",
            version: "1.2.3:update:edition",
            origins: ["ports.port:443"],
          },
          { type: "o", vendor: "linux", product: "linux_kernel", version: "" },
          { type: "h", vendor: "example" },
        ],
      },
    ];
    renderReport();
    const table = await screen.findByRole("table", {
      name: "Common Platform Enumeration",
    });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toEqual(["Type", "Vendor", "Product", "Version"]);
    const rows = within(table).getAllByRole("row").slice(1);
    expect(
      rows.map((row) =>
        within(row)
          .getAllByRole("cell")
          .map((cell) => cell.textContent),
      ),
    ).toEqual([
      ["a", "example", "service", "1.2.3:update:edition"],
      ["o", "linux", "linux_kernel", "—"],
      ["h", "example", "—", "—"],
    ]);
  });

  it("renders CPE component values as text, not markup", async () => {
    const product =
      '<img src="https://attacker.invalid/pixel" onerror="alert(1)">';
    viewRecords = [
      {
        addr: address,
        cpes: [{ type: "a", vendor: "example", product, version: "1.0" }],
      },
    ];
    renderReport();
    const table = await screen.findByRole("table", {
      name: "Common Platform Enumeration",
    });
    expect(within(table).getByRole("cell", { name: product })).toBeVisible();
    expect(within(table).queryByRole("img")).not.toBeInTheDocument();
    expect(calls.every((url) => url.origin === "http://localhost")).toBe(true);
  });

  it("renders hostile script text as text and refuses external screenshot URLs", async () => {
    const payload =
      '<img src="https://attacker.invalid/pixel" onerror="alert(1)">';
    viewRecords = [
      {
        addr: address,
        ports: [
          {
            port: 443,
            protocol: "tcp",
            screenshot: "field",
            screendata: "https://attacker.invalid/pixel",
            scripts: [{ id: "http-title", output: payload }],
          },
        ],
      },
    ];
    renderReport();
    expect(await screen.findByText(payload)).toBeVisible();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(calls.every((url) => url.origin === "http://localhost")).toBe(true);
  });

  it("supports IPv6 report addresses", async () => {
    viewRecords = [{ addr: "2001:db8::42", ports: latest.ports }];
    renderReport("/view/host/2001%3Adb8%3A%3A42");
    expect(await screen.findByText("Example SSH key")).toBeVisible();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "2001:db8::42",
    );
    expect(
      calls.find((url) => url.pathname === "/cgi/view")?.searchParams.get("q"),
    ).toBe('host:"2001:db8::42" limit:1');
  });
});
