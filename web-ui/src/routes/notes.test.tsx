/* @vitest-environment jsdom */
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { NotesRoute } from "./notes";

import type { Note } from "@/lib/api";

/* ------------------------------------------------------------------ */
/* Mocks                                                               */
/* ------------------------------------------------------------------ */

const sampleNotes: Note[] = [
  {
    entity_type: "host",
    entity_key: "192.0.2.10",
    body: "First note body",
    revision: 1,
    created_at: "2026-05-01T10:00:00Z",
    created_by: "alice@example.org",
    updated_at: "2026-05-01T10:00:00Z",
    updated_by: "alice@example.org",
  },
  {
    entity_type: "host",
    entity_key: "192.0.2.20",
    body: "Second note body",
    revision: 2,
    created_at: "2026-05-02T10:00:00Z",
    created_by: "bob@example.org",
    updated_at: "2026-05-03T10:00:00Z",
    updated_by: "bob@example.org",
  },
];

// Mutable state the ``useNotes`` mock reads on every render so
// individual tests can seed the slices they need.  ``refetch``
// is a spy so the error-state Retry button can be asserted.
const refetchSpy = vi.fn(async () => undefined);
let notesState: {
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  data: Note[] | undefined;
  refetch: typeof refetchSpy;
} = {
  isLoading: false,
  isError: false,
  error: null,
  data: sampleNotes,
  refetch: refetchSpy,
};

// Recorded ``useNotes`` invocations -- tests assert the right
// parameters travel through from the URL state to the query
// hook.
const notesCalls: Array<Parameters<typeof import("@/lib/api").useNotes>[0]> = [];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>(
    "@/lib/api",
  );
  return {
    ...actual,
    useNotes: (params: Parameters<typeof actual.useNotes>[0]) => {
      notesCalls.push(params);
      return notesState;
    },
  };
});

vi.mock("@/lib/config", async () => {
  const actual = await vi.importActual<typeof import("@/lib/config")>(
    "@/lib/config",
  );
  return {
    ...actual,
    getConfig: () => ({
      dflt_limit: 10,
      auth_enabled: false,
    }),
  };
});

afterEach(() => {
  // Restore real timers in case a test enabled fake ones.
  vi.useRealTimers();
  notesState = {
    isLoading: false,
    isError: false,
    error: null,
    data: sampleNotes,
    refetch: refetchSpy,
  };
  refetchSpy.mockClear();
  notesCalls.length = 0;
});

/** Small test harness that mounts the route under a
 *  ``MemoryRouter`` so ``useSearchParams`` has somewhere to read
 *  from / write to.  ``LocationSpy`` captures the current
 *  pathname + search on every render so tests can assert URL
 *  state mutations from the route. */
function renderRoute(initialEntries: string[] = ["/notes"]) {
  const locationSpy = { value: { pathname: "", search: "" } };
  function LocationSpy() {
    const location = useLocation();
    locationSpy.value = {
      pathname: location.pathname,
      search: location.search,
    };
    return null;
  }
  const utils = render(
    <MemoryRouter initialEntries={initialEntries}>
      <Routes>
        <Route
          path="/notes"
          element={
            <>
              <NotesRoute />
              <LocationSpy />
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
  return { ...utils, locationSpy };
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

describe("NotesRoute states", () => {
  it("renders the loading skeleton with role=status while the query is in flight", () => {
    notesState = { ...notesState, isLoading: true, data: undefined };

    renderRoute();

    const skeleton = screen.getByTestId("notes-list-loading");
    expect(skeleton).toHaveAttribute("role", "status");
    expect(skeleton).toHaveAccessibleName(/loading notes/i);
  });

  it("renders the error panel + Retry button on query failure", () => {
    notesState = {
      ...notesState,
      isError: true,
      error: new Error("GET /cgi/notes/ failed: 500 Server Error"),
      data: undefined,
    };

    renderRoute();

    expect(screen.getByTestId("notes-list-error")).toBeInTheDocument();
    expect(screen.getByText(/500 Server Error/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(refetchSpy).toHaveBeenCalledTimes(1);
  });

  it("renders an empty-state placeholder when the listing is empty", () => {
    notesState = { ...notesState, data: [] };

    renderRoute();

    expect(screen.getByTestId("notes-list-empty")).toBeInTheDocument();
    expect(
      screen.getByText(/no notes match the current filters/i),
    ).toBeInTheDocument();
  });

  it("renders one ``<NoteCard>`` row per note returned by the API", () => {
    renderRoute();

    expect(screen.getAllByTestId("notes-list-item")).toHaveLength(2);
    expect(screen.getAllByTestId("note-card")).toHaveLength(2);
    expect(screen.getByText("192.0.2.10")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.20")).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/* URL state                                                           */
/* ------------------------------------------------------------------ */

describe("NotesRoute URL state", () => {
  it("seeds the search input from ?q= and forwards it to useNotes", () => {
    renderRoute(["/notes?q=c2"]);

    const input = screen.getByTestId(
      "notes-search-input",
    ) as HTMLInputElement;
    expect(input.value).toBe("c2");
    // Last call to ``useNotes`` carries the current ``q``.
    expect(notesCalls.at(-1)).toEqual(
      expect.objectContaining({ q: "c2" }),
    );
  });

  it("seeds the entity-type select from ?type= and forwards it as entityType", () => {
    renderRoute(["/notes?type=host"]);

    const select = screen.getByTestId(
      "notes-entity-type-select",
    ) as HTMLSelectElement;
    expect(select.value).toBe("host");
    expect(notesCalls.at(-1)).toEqual(
      expect.objectContaining({ entityType: "host" }),
    );
  });

  it("debounces the search input by 300ms and then updates ?q=", async () => {
    // Fake timers scoped to this test only -- the rest of the
    // suite uses real timers so React Testing Library's
    // ``waitFor`` polling keeps working.  Without the
    // debounce, every keystroke would hit the API; without
    // *some* delay, the URL would flicker on each character.
    vi.useFakeTimers();
    const { locationSpy } = renderRoute(["/notes"]);

    fireEvent.change(screen.getByTestId("notes-search-input"), {
      target: { value: "needle" },
    });
    // Before the debounce fires, the URL still lacks ``q=``.
    expect(locationSpy.value.search).toBe("");

    // Advance past the 300 ms debounce and let React flush
    // the resulting state update.
    await act(async () => {
      vi.advanceTimersByTime(300);
    });

    expect(locationSpy.value.search).toMatch(/[?&]q=needle\b/);
  });

  it("changing the entity-type select updates ?type= (or removes it for ``all``)", async () => {
    const { locationSpy } = renderRoute(["/notes"]);

    fireEvent.change(screen.getByTestId("notes-entity-type-select"), {
      target: { value: "host" },
    });
    await waitFor(() => {
      expect(locationSpy.value.search).toMatch(/[?&]type=host\b/);
    });

    // Switching back to ``all`` drops the parameter entirely
    // rather than leaving ``?type=all`` lingering in the URL.
    fireEvent.change(screen.getByTestId("notes-entity-type-select"), {
      target: { value: "all" },
    });
    await waitFor(() => {
      expect(locationSpy.value.search).not.toMatch(/[?&]type=/);
    });
  });
});

/* ------------------------------------------------------------------ */
/* Row click → detail sheet                                            */
/* ------------------------------------------------------------------ */

describe("NotesRoute detail sheet", () => {
  it("clicking a row sets ?addr= and opens the matching detail sheet", async () => {
    const { locationSpy } = renderRoute(["/notes"]);

    // Sheet starts closed.
    expect(screen.queryByTestId("note-detail-sheet")).toBeNull();

    fireEvent.click(screen.getAllByTestId("note-card")[1]);

    await waitFor(() => {
      expect(locationSpy.value.search).toMatch(/[?&]addr=192\.0\.2\.20\b/);
    });
    // Sheet body for the matching note is now in the DOM.
    expect(
      screen.getByTestId("note-detail-entity-key"),
    ).toHaveTextContent("192.0.2.20");
    // Deep-link to host detail for that addr.
    expect(
      screen.getByTestId("note-detail-deep-link"),
    ).toHaveAttribute("href", "#/view/host/192.0.2.20");
  });

  it("?addr= in the initial URL opens the sheet preselected", () => {
    renderRoute(["/notes?addr=192.0.2.10"]);

    // The matching note's body / headline is visible inside
    // the sheet.
    expect(
      screen.getByTestId("note-detail-entity-key"),
    ).toHaveTextContent("192.0.2.10");
  });
});
