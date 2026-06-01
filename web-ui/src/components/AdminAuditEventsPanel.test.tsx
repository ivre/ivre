/* @vitest-environment jsdom */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AdminAuditEventsPanel } from "./AdminAuditEventsPanel";

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

let eventsState: EventsState = {
  isLoading: false,
  error: null,
  data: { pages: [[]], pageParams: [0] },
  hasNextPage: false,
  isFetchingNextPage: false,
};

let countState: {
  isLoading: boolean;
  error: Error | null;
  data: number | undefined;
} = { isLoading: false, error: null, data: 0 };

const fetchNextPageSpy = vi.fn(async () => undefined);
// Tests inspect this to assert that the panel only re-queries
// when the operator actually applies the filter (not on every
// keystroke).
const useAuditEventsCalls: AuditFilters[] = [];
const useAuditCountCalls: AuditFilters[] = [];

vi.mock("@/lib/audit", async () => {
  const actual = await vi.importActual<typeof import("@/lib/audit")>(
    "@/lib/audit",
  );
  return {
    ...actual,
    useAuditEvents: (filters: AuditFilters) => {
      useAuditEventsCalls.push({ ...filters });
      return { ...eventsState, fetchNextPage: fetchNextPageSpy };
    },
    useAuditCount: (filters: AuditFilters) => {
      useAuditCountCalls.push({ ...filters });
      return countState;
    },
  };
});

afterEach(() => {
  eventsState = {
    isLoading: false,
    error: null,
    data: { pages: [[]], pageParams: [0] },
    hasNextPage: false,
    isFetchingNextPage: false,
  };
  countState = { isLoading: false, error: null, data: 0 };
  fetchNextPageSpy.mockClear();
  useAuditEventsCalls.length = 0;
  useAuditCountCalls.length = 0;
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

/* ------------------------------------------------------------------ */
/* Filter wiring                                                       */
/* ------------------------------------------------------------------ */

describe("AdminAuditEventsPanel filter wiring", () => {
  it("renders the filter input and a Search button on mount", () => {
    render(<AdminAuditEventsPanel />);

    expect(
      screen.getByTestId("admin-audit-filter-input"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("admin-audit-filter-apply"),
    ).toBeInTheDocument();
    // No Clear button on first render (nothing applied yet).
    expect(
      screen.queryByTestId("admin-audit-filter-clear"),
    ).not.toBeInTheDocument();
  });

  it("does not refetch on every keystroke; query only changes when Apply is clicked", () => {
    render(<AdminAuditEventsPanel />);
    useAuditEventsCalls.length = 0;

    const input = screen.getByTestId(
      "admin-audit-filter-input",
    ) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "alice@example.org" } });

    // Typing into the input may re-render and re-invoke the
    // hooks (React state update), but the filter passed to
    // them must still be the unapplied (empty) one until the
    // operator clicks Apply.
    expect(
      useAuditEventsCalls.every((f) => f.user_email === undefined),
    ).toBe(true);
  });

  it("Apply commits the filter and the count companion sees it too", () => {
    render(<AdminAuditEventsPanel />);

    fireEvent.change(
      screen.getByTestId("admin-audit-filter-input"),
      { target: { value: "alice@example.org" } },
    );
    useAuditEventsCalls.length = 0;
    useAuditCountCalls.length = 0;

    fireEvent.click(screen.getByTestId("admin-audit-filter-apply"));

    expect(
      useAuditEventsCalls.some(
        (f) => f.user_email === "alice@example.org",
      ),
    ).toBe(true);
    expect(
      useAuditCountCalls.some(
        (f) => f.user_email === "alice@example.org",
      ),
    ).toBe(true);
  });

  it("Enter key in the filter input triggers Apply", () => {
    render(<AdminAuditEventsPanel />);

    const input = screen.getByTestId(
      "admin-audit-filter-input",
    ) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "bob@example.org" } });
    useAuditEventsCalls.length = 0;

    fireEvent.keyDown(input, { key: "Enter" });

    expect(
      useAuditEventsCalls.some((f) => f.user_email === "bob@example.org"),
    ).toBe(true);
  });

  it("Clear resets the input and the applied filter", () => {
    render(<AdminAuditEventsPanel />);

    fireEvent.change(
      screen.getByTestId("admin-audit-filter-input"),
      { target: { value: "alice@example.org" } },
    );
    fireEvent.click(screen.getByTestId("admin-audit-filter-apply"));

    // Clear button materialises once a filter is applied.
    const clearBtn = screen.getByTestId("admin-audit-filter-clear");
    useAuditEventsCalls.length = 0;
    fireEvent.click(clearBtn);

    expect(
      (screen.getByTestId(
        "admin-audit-filter-input",
      ) as HTMLInputElement).value,
    ).toBe("");
    expect(
      useAuditEventsCalls.every((f) => f.user_email === undefined),
    ).toBe(true);
  });

  it("trims surrounding whitespace before applying the filter", () => {
    // Pasting an email with stray whitespace is a common
    // operator mistake; the route would otherwise either 404
    // or return nothing, and the empty result would look like
    // a backend bug.  Trim at the panel boundary.
    render(<AdminAuditEventsPanel />);

    fireEvent.change(
      screen.getByTestId("admin-audit-filter-input"),
      { target: { value: "  alice@example.org  " } },
    );
    useAuditEventsCalls.length = 0;
    fireEvent.click(screen.getByTestId("admin-audit-filter-apply"));

    expect(
      useAuditEventsCalls.some(
        (f) => f.user_email === "alice@example.org",
      ),
    ).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Cross-user rendering                                                */
/* ------------------------------------------------------------------ */

describe("AdminAuditEventsPanel cross-user rendering", () => {
  it("shows the actor email on every row (cross-user surface)", () => {
    eventsState = {
      ...eventsState,
      data: {
        pages: [
          [
            makeEvent({
              event_id: "1".repeat(32),
              actor: {
                user_email: "alice@example.org",
                api_key_hash: null,
                remote_addr: null,
              },
            }),
            makeEvent({
              event_id: "2".repeat(32),
              actor: {
                user_email: "bob@example.org",
                api_key_hash: null,
                remote_addr: null,
              },
            }),
          ],
        ],
        pageParams: [0],
      },
    };
    countState = { ...countState, data: 2 };

    render(<AdminAuditEventsPanel />);

    expect(screen.getByText(/alice@example\.org/)).toBeInTheDocument();
    expect(screen.getByText(/bob@example\.org/)).toBeInTheDocument();
  });

  it("surfaces the applied user_email in the header for context", () => {
    eventsState = {
      ...eventsState,
      data: { pages: [[makeEvent()]], pageParams: [0] },
    };
    countState = { ...countState, data: 1 };

    render(<AdminAuditEventsPanel />);

    fireEvent.change(
      screen.getByTestId("admin-audit-filter-input"),
      { target: { value: "alice@example.org" } },
    );
    fireEvent.click(screen.getByTestId("admin-audit-filter-apply"));

    expect(screen.getByTestId("admin-audit-header")).toHaveTextContent(
      /for\s+alice@example\.org/i,
    );
  });

  it("renders a NULL-actor row as anonymous (the partial-index NULL bucket)", () => {
    // ``oversize_query`` events from anonymous callers carry a
    // null ``actor.user_email``; the admin row must still
    // render and label them so an operator can see the
    // anonymous-traffic baseline (which is the bulk of the
    // NULL-actor rows the per-user partial index excludes).
    eventsState = {
      ...eventsState,
      data: {
        pages: [
          [
            makeEvent({
              event_type: "oversize_query",
              actor: {
                user_email: null,
                api_key_hash: null,
                remote_addr: "198.51.100.1",
              },
              outcome: 413,
            }),
          ],
        ],
        pageParams: [0],
      },
    };
    countState = { ...countState, data: 1 };

    render(<AdminAuditEventsPanel />);

    expect(screen.getByText(/anonymous/i)).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/* Load more                                                           */
/* ------------------------------------------------------------------ */

describe("AdminAuditEventsPanel load more", () => {
  it("fires fetchNextPage on Load more click", async () => {
    eventsState = {
      ...eventsState,
      data: { pages: [[makeEvent()]], pageParams: [0] },
      hasNextPage: true,
    };

    render(<AdminAuditEventsPanel />);

    fireEvent.click(screen.getByTestId("admin-audit-load-more"));
    await waitFor(() =>
      expect(fetchNextPageSpy).toHaveBeenCalledTimes(1),
    );
  });
});
