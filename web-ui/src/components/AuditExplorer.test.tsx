/* @vitest-environment jsdom */
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuditExplorer } from "./AuditExplorer";

import type { AuditEvent, AuditFilters } from "@/lib/audit";

/* ------------------------------------------------------------------ */
/* Mocks                                                               */
/* ------------------------------------------------------------------ */

interface EventsState {
  isLoading: boolean;
  error: Error | null;
  data: { pages: AuditEvent[][]; pageParams: number[] } | undefined;
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
}

let eventsState: EventsState;
let countState: { data: number | undefined };
let eventState: {
  data: AuditEvent | undefined;
  isLoading: boolean;
  error: Error | null;
};

const fetchNextPageSpy = vi.fn(async () => undefined);
const refetchSpy = vi.fn(async () => undefined);
const useAuditEventsCalls: AuditFilters[] = [];
const useAuditEventCalls: Array<{ id: string | null; enabled?: boolean }> = [];

vi.mock("@/lib/audit", async () => {
  const actual = await vi.importActual<typeof import("@/lib/audit")>(
    "@/lib/audit",
  );
  return {
    ...actual,
    useAuditEvents: (filters: AuditFilters) => {
      useAuditEventsCalls.push({ ...filters });
      return {
        ...eventsState,
        fetchNextPage: fetchNextPageSpy,
        refetch: refetchSpy,
      };
    },
    useAuditCount: () => countState,
    useAuditEvent: (id: string | null, opts?: { enabled?: boolean }) => {
      useAuditEventCalls.push({ id, enabled: opts?.enabled });
      return eventState;
    },
  };
});

// Render every row so the virtualized list is assertable under
// jsdom (which has no layout, so the real virtualizer would
// render nothing). We test our wiring, not react-virtual.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (opts: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: opts.count }, (_, i) => ({
        index: i,
        key: i,
        start: i * 96,
        size: 96,
      })),
    getTotalSize: () => opts.count * 96,
    measureElement: () => {},
  }),
}));

beforeEach(() => {
  eventsState = {
    isLoading: false,
    error: null,
    data: { pages: [[]], pageParams: [0] },
    hasNextPage: false,
    isFetchingNextPage: false,
  };
  countState = { data: 0 };
  eventState = { data: undefined, isLoading: false, error: null };
});

afterEach(() => {
  fetchNextPageSpy.mockClear();
  refetchSpy.mockClear();
  useAuditEventsCalls.length = 0;
  useAuditEventCalls.length = 0;
  vi.useRealTimers();
});

function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    event_id: "deadbeefdead4bad9baddeadbeefcafe",
    event_type: "upload",
    created_at: "2026-05-25T12:00:00Z",
    actor: {
      user_email: "alice@example.org",
      api_key_hash: null,
      remote_addr: "203.0.113.7",
    },
    resource: { route: "/scans", method: "POST" },
    details: { count: 3 },
    outcome: 200,
    ...overrides,
  };
}

let currentSearch = "";
function LocationProbe() {
  currentSearch = useLocation().search;
  return null;
}

function renderExplorer(initialUrl = "/audit/explorer") {
  currentSearch = "";
  return render(
    <MemoryRouter initialEntries={[initialUrl]}>
      <Routes>
        <Route
          path="/audit/explorer"
          element={
            <>
              <AuditExplorer />
              <LocationProbe />
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

/* ------------------------------------------------------------------ */
/* Toolbar + listing                                                   */
/* ------------------------------------------------------------------ */

describe("AuditExplorer toolbar + listing", () => {
  it("renders all four filter controls", () => {
    renderExplorer();
    expect(
      screen.getByTestId("audit-explorer-type-select"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("audit-explorer-user-input"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("audit-explorer-since-input"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("audit-explorer-until-input"),
    ).toBeInTheDocument();
  });

  it("renders one row per event and the count header", () => {
    eventsState.data = {
      pages: [
        [
          makeEvent({ event_id: "1".repeat(32) }),
          makeEvent({ event_id: "2".repeat(32), event_type: "admin_action" }),
        ],
      ],
      pageParams: [0],
    };
    countState.data = 2;

    renderExplorer();

    expect(screen.getAllByTestId("audit-events-row")).toHaveLength(2);
    expect(screen.getByTestId("audit-explorer-header")).toHaveTextContent(
      /showing\s*2\s*events/i,
    );
  });

  it("shows the empty placeholder when no events match", () => {
    renderExplorer();
    expect(
      screen.getByTestId("audit-explorer-empty"),
    ).toBeInTheDocument();
  });

  it("renders an error panel with a Retry button", () => {
    eventsState.error = new Error("GET /cgi/audit/ failed: 500 Server Error");
    eventsState.data = undefined;

    renderExplorer();

    expect(screen.getByTestId("audit-explorer-error")).toHaveTextContent(
      /500 Server Error/,
    );
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(refetchSpy).toHaveBeenCalledTimes(1);
  });
});

/* ------------------------------------------------------------------ */
/* URL-state filter wiring                                             */
/* ------------------------------------------------------------------ */

describe("AuditExplorer filter <-> URL wiring", () => {
  it("derives filters from the initial URL and passes them to the query", () => {
    renderExplorer(
      "/audit/explorer?type=admin_action&user=bob@example.org" +
        "&since=2026-05-01T00:00:00.000Z&until=2026-06-01T00:00:00.000Z",
    );

    expect(
      useAuditEventsCalls.some(
        (f) =>
          f.event_type === "admin_action" &&
          f.user_email === "bob@example.org" &&
          f.since === "2026-05-01T00:00:00.000Z" &&
          f.until === "2026-06-01T00:00:00.000Z",
      ),
    ).toBe(true);
  });

  it("ignores an unknown event_type in the URL (treated as no filter)", () => {
    renderExplorer("/audit/explorer?type=bogus");
    expect(
      useAuditEventsCalls.every((f) => f.event_type === undefined),
    ).toBe(true);
  });

  it("writes ?type= when the event-type select changes", () => {
    renderExplorer();
    fireEvent.change(screen.getByTestId("audit-explorer-type-select"), {
      target: { value: "oversize_query" },
    });
    expect(currentSearch).toContain("type=oversize_query");
  });

  it("offers the auth event type with a human label and writes ?type=auth", () => {
    renderExplorer();
    const select = screen.getByTestId(
      "audit-explorer-type-select",
    ) as HTMLSelectElement;
    const authOption = [...select.options].find((o) => o.value === "auth");
    expect(authOption).toBeDefined();
    expect(authOption?.textContent).toBe("Authentication");
    fireEvent.change(select, { target: { value: "auth" } });
    expect(currentSearch).toContain("type=auth");
  });

  it("removes ?type= when reset to 'all'", () => {
    renderExplorer("/audit/explorer?type=upload");
    fireEvent.change(screen.getByTestId("audit-explorer-type-select"), {
      target: { value: "all" },
    });
    expect(currentSearch).not.toContain("type=");
  });

  it("stores since as a canonical UTC ISO (Z) string in the URL", () => {
    renderExplorer();
    fireEvent.change(screen.getByTestId("audit-explorer-since-input"), {
      target: { value: "2026-05-25T12:00" },
    });
    // URL-encoded ':' is %3A; assert the decoded form carries a
    // Z-suffixed ISO instant equal to the typed local time.
    const params = new URLSearchParams(currentSearch);
    const since = params.get("since");
    expect(since).toBeTruthy();
    expect(since).toMatch(/Z$/);
    expect(new Date(since as string).getTime()).toBe(
      new Date("2026-05-25T12:00").getTime(),
    );
  });

  it("debounces the user-email box, then writes ?user=", () => {
    vi.useFakeTimers();
    renderExplorer();
    fireEvent.change(screen.getByTestId("audit-explorer-user-input"), {
      target: { value: "carol@example.org" },
    });
    // Nothing committed before the debounce elapses.
    expect(currentSearch).not.toContain("user=");
    // Flush the debounce timer *and* the React re-render it
    // schedules (the setSearchParams in the timeout callback).
    act(() => {
      vi.advanceTimersByTime(350);
    });
    expect(currentSearch).toContain("user=carol%40example.org");
  });

  it("Clear removes every filter param", () => {
    renderExplorer(
      "/audit/explorer?type=upload&user=bob@example.org" +
        "&since=2026-05-01T00:00:00.000Z",
    );
    fireEvent.click(screen.getByTestId("audit-explorer-clear"));
    expect(currentSearch).not.toContain("type=");
    expect(currentSearch).not.toContain("user=");
    expect(currentSearch).not.toContain("since=");
  });

  it("a pending user-email debounce does not clobber a later filter change", () => {
    // Regression: the debounce timer must apply through a
    // functional setSearchParams updater so it rebuilds from the
    // latest params.  Type into the user box (timer pending),
    // change the event type, then let the timer fire -- both the
    // type change and the user commit must survive.
    vi.useFakeTimers();
    renderExplorer();

    fireEvent.change(screen.getByTestId("audit-explorer-user-input"), {
      target: { value: "carol@example.org" },
    });
    // Before the debounce fires, change another filter.
    fireEvent.change(screen.getByTestId("audit-explorer-type-select"), {
      target: { value: "upload" },
    });
    expect(currentSearch).toContain("type=upload");

    act(() => {
      vi.advanceTimersByTime(350);
    });

    const params = new URLSearchParams(currentSearch);
    expect(params.get("type")).toBe("upload"); // not clobbered
    expect(params.get("user")).toBe("carol@example.org");
  });

  it("treats a malformed ?since as unset (not forwarded to the backend)", () => {
    renderExplorer("/audit/explorer?since=garbage&type=upload");
    // The bad bound is sanitized to ``undefined`` in the filter
    // dict so the events query never forwards it (which would
    // 400); the rest of the filter set is unaffected.
    expect(
      useAuditEventsCalls.some(
        (f) => f.since === undefined && f.event_type === "upload",
      ),
    ).toBe(true);
    // The since input renders blank (consistent with "no bound").
    expect(
      (screen.getByTestId(
        "audit-explorer-since-input",
      ) as HTMLInputElement).value,
    ).toBe("");
  });
});

/* ------------------------------------------------------------------ */
/* Detail sheet                                                        */
/* ------------------------------------------------------------------ */

describe("AuditExplorer detail sheet", () => {
  it("opens the sheet and sets ?event= when a row is clicked (fast path)", async () => {
    eventsState.data = {
      pages: [[makeEvent({ event_id: "a".repeat(32) })]],
      pageParams: [0],
    };
    countState.data = 1;

    const { container } = renderExplorer();
    const row = container.querySelector(
      `[data-event-id="${"a".repeat(32)}"]`,
    ) as HTMLElement;
    fireEvent.click(row);

    expect(currentSearch).toContain(`event=${"a".repeat(32)}`);
    await waitFor(() =>
      expect(
        screen.getByTestId("audit-event-detail-sheet"),
      ).toBeInTheDocument(),
    );
    // Fast path: the event came from the loaded list, so the
    // single-event endpoint must NOT have been enabled.
    expect(
      useAuditEventCalls.every((c) => c.enabled !== true),
    ).toBe(true);
    expect(screen.getByTestId("audit-event-detail-id")).toHaveTextContent(
      "a".repeat(32),
    );
  });

  it("falls back to the single-event endpoint for a deep link not on the page", async () => {
    // List does not contain the targeted id -> the fallback
    // query must be enabled and its result rendered.
    eventsState.data = { pages: [[]], pageParams: [0] };
    countState.data = 0;
    eventState.data = makeEvent({
      event_id: "f".repeat(32),
      event_type: "oversize_query",
      outcome: 413,
    });

    renderExplorer(`/audit/explorer?event=${"f".repeat(32)}`);

    expect(
      useAuditEventCalls.some(
        (c) => c.id === "f".repeat(32) && c.enabled === true,
      ),
    ).toBe(true);
    await waitFor(() =>
      expect(
        screen.getByTestId("audit-event-detail-id"),
      ).toHaveTextContent("f".repeat(32)),
    );
  });

  it("surfaces a fallback error in the sheet (stale / forbidden id)", async () => {
    eventsState.data = { pages: [[]], pageParams: [0] };
    eventState.error = new Error("GET /cgi/audit/xxx failed: 404 Not Found");

    renderExplorer(`/audit/explorer?event=${"e".repeat(32)}`);

    await waitFor(() =>
      expect(
        screen.getByTestId("audit-event-detail-error"),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText(/404 Not Found/)).toBeInTheDocument();
  });

  it("clears ?event= when the sheet is closed", async () => {
    eventsState.data = {
      pages: [[makeEvent({ event_id: "b".repeat(32) })]],
      pageParams: [0],
    };
    const { container } = renderExplorer();
    fireEvent.click(
      container.querySelector(
        `[data-event-id="${"b".repeat(32)}"]`,
      ) as HTMLElement,
    );
    expect(currentSearch).toContain("event=");

    // Radix Dialog close button carries an accessible name.
    fireEvent.click(screen.getByRole("button", { name: /close/i }));
    await waitFor(() => expect(currentSearch).not.toContain("event="));
  });

  it("keeps the sheet closed for an empty ?event= (no blank sheet)", () => {
    // ``searchParams.get("event")`` is "" for ``?event=``;
    // normalizing to null must keep the sheet closed and the
    // single-event query disabled rather than opening a blank
    // sheet.
    eventsState.data = { pages: [[makeEvent()]], pageParams: [0] };

    renderExplorer("/audit/explorer?event=");

    expect(
      screen.queryByTestId("audit-event-detail-sheet"),
    ).not.toBeInTheDocument();
    // The fallback single-event query must not be enabled for an
    // empty id.
    expect(useAuditEventCalls.every((c) => c.enabled !== true)).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Load more                                                           */
/* ------------------------------------------------------------------ */

describe("AuditExplorer load more", () => {
  it("renders Load more when more pages remain and fires fetchNextPage", async () => {
    eventsState.data = {
      pages: [[makeEvent()]],
      pageParams: [0],
    };
    eventsState.hasNextPage = true;

    renderExplorer();
    fireEvent.click(screen.getByTestId("audit-explorer-load-more"));
    await waitFor(() =>
      expect(fetchNextPageSpy).toHaveBeenCalledTimes(1),
    );
  });
});
