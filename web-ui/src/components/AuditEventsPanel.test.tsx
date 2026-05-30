/* @vitest-environment jsdom */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuditEventsPanel } from "./AuditEventsPanel";

import type { AuditEvent } from "@/lib/audit";

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
  data: undefined,
  hasNextPage: false,
  isFetchingNextPage: false,
};

let countState: {
  isLoading: boolean;
  error: Error | null;
  data: number | undefined;
} = {
  isLoading: false,
  error: null,
  data: undefined,
};

const fetchNextPageSpy = vi.fn(async () => undefined);

vi.mock("@/lib/audit", async () => {
  const actual = await vi.importActual<typeof import("@/lib/audit")>(
    "@/lib/audit",
  );
  return {
    ...actual,
    useAuditEvents: () => ({
      ...eventsState,
      fetchNextPage: fetchNextPageSpy,
    }),
    useAuditCount: () => countState,
  };
});

afterEach(() => {
  eventsState = {
    isLoading: false,
    error: null,
    data: undefined,
    hasNextPage: false,
    isFetchingNextPage: false,
  };
  countState = { isLoading: false, error: null, data: undefined };
  fetchNextPageSpy.mockClear();
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
/* Loading / error                                                     */
/* ------------------------------------------------------------------ */

describe("AuditEventsPanel loading + error", () => {
  it("renders an accessible loading status while the first page is in flight", () => {
    eventsState = { ...eventsState, isLoading: true };

    render(<AuditEventsPanel />);

    const status = screen.getByTestId("audit-events-loading");
    expect(status).toHaveAttribute("role", "status");
    expect(status).toHaveAccessibleName(/loading audit events/i);
  });

  it("surfaces a fetch error verbatim", () => {
    eventsState = {
      ...eventsState,
      error: new Error("GET /cgi/audit/ failed: 401 Unauthorized"),
    };

    render(<AuditEventsPanel />);

    expect(screen.getByTestId("audit-events-error")).toHaveTextContent(
      /401 Unauthorized/,
    );
  });
});

/* ------------------------------------------------------------------ */
/* Empty state                                                         */
/* ------------------------------------------------------------------ */

describe("AuditEventsPanel empty state", () => {
  it("renders the empty placeholder when the backend returns no rows", () => {
    eventsState = {
      ...eventsState,
      data: { pages: [[]], pageParams: [0] },
    };
    countState = { ...countState, data: 0 };

    render(<AuditEventsPanel />);

    expect(screen.getByTestId("audit-events-empty")).toBeInTheDocument();
    // Header singularises correctly at zero (English: "events"
    // for any count != 1) and reflects the count companion.
    expect(screen.getByTestId("audit-events-header")).toHaveTextContent(
      /showing\s*0\s*events/i,
    );
  });
});

/* ------------------------------------------------------------------ */
/* Populated state                                                     */
/* ------------------------------------------------------------------ */

describe("AuditEventsPanel populated state", () => {
  it("renders one row per event and tags each event_type with the right badge", () => {
    eventsState = {
      ...eventsState,
      data: {
        pages: [
          [
            makeEvent({
              event_id: "1".repeat(32),
              event_type: "upload",
            }),
            makeEvent({
              event_id: "2".repeat(32),
              event_type: "admin_action",
              resource: { route: "/auth/admin/users/bob@example.org", method: "PUT" },
              details: { update: { is_admin: true } },
            }),
            makeEvent({
              event_id: "3".repeat(32),
              event_type: "oversize_query",
              resource: { route: "/scans", method: "GET" },
              details: { count: 12345 },
              outcome: 413,
            }),
          ],
        ],
        pageParams: [0],
      },
    };
    countState = { ...countState, data: 3 };

    render(<AuditEventsPanel />);

    expect(screen.getAllByTestId("audit-events-row")).toHaveLength(3);
    const badges = screen.getAllByTestId("audit-events-type-badge");
    expect(badges.map((b) => b.getAttribute("data-event-type"))).toEqual([
      "upload",
      "admin_action",
      "oversize_query",
    ]);
    // Header reflects the count companion -- the panel does not
    // double-count from ``data.pages.flat().length`` when a
    // server-side total is available.
    expect(screen.getByTestId("audit-events-header")).toHaveTextContent(
      /showing\s*3\s*events/i,
    );
  });

  it("does not render the actor field on the self-service surface (every row is the caller)", () => {
    // The self-service panel passes ``showActor={false}`` to
    // :func:`AuditEventsTable`, so the row body must not
    // mention the actor's email -- pinning that here catches a
    // regression that would leak the actor on a route the
    // backend already scopes to the caller.
    eventsState = {
      ...eventsState,
      data: {
        pages: [[makeEvent({ actor: { user_email: "alice@example.org", api_key_hash: null, remote_addr: null } })]],
        pageParams: [0],
      },
    };
    countState = { ...countState, data: 1 };

    render(<AuditEventsPanel />);

    expect(
      screen.queryByText(/alice@example\.org/i),
    ).not.toBeInTheDocument();
  });

  it("renders 'X of Y' when more pages remain to load", () => {
    eventsState = {
      ...eventsState,
      data: { pages: [[makeEvent()]], pageParams: [0] },
      hasNextPage: true,
    };
    countState = { ...countState, data: 137 };

    render(<AuditEventsPanel />);

    expect(screen.getByTestId("audit-events-header")).toHaveTextContent(
      /showing\s*1\/137\s*event/i,
    );
  });
});

/* ------------------------------------------------------------------ */
/* Load more                                                           */
/* ------------------------------------------------------------------ */

describe("AuditEventsPanel load more", () => {
  it("renders the Load more button when hasNextPage is true and fires fetchNextPage on click", async () => {
    eventsState = {
      ...eventsState,
      data: { pages: [[makeEvent()]], pageParams: [0] },
      hasNextPage: true,
    };

    render(<AuditEventsPanel />);

    const btn = screen.getByTestId("audit-events-load-more");
    expect(btn).toBeEnabled();
    fireEvent.click(btn);
    await waitFor(() => expect(fetchNextPageSpy).toHaveBeenCalledTimes(1));
  });

  it("hides the Load more button when the last page was short", () => {
    eventsState = {
      ...eventsState,
      data: { pages: [[makeEvent()]], pageParams: [0] },
      hasNextPage: false,
    };

    render(<AuditEventsPanel />);

    expect(
      screen.queryByTestId("audit-events-load-more"),
    ).not.toBeInTheDocument();
  });

  it("disables the Load more button with a Loading… label while a fetch is in flight", () => {
    eventsState = {
      ...eventsState,
      data: { pages: [[makeEvent()]], pageParams: [0] },
      hasNextPage: true,
      isFetchingNextPage: true,
    };

    render(<AuditEventsPanel />);

    const btn = screen.getByTestId("audit-events-load-more");
    expect(btn).toBeDisabled();
    expect(btn).toHaveTextContent(/loading…/i);
  });
});
