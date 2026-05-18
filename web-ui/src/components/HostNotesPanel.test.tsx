/* @vitest-environment jsdom */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HostNotesPanel } from "./HostNotesPanel";

import type {
  HostNoteResult,
  Note,
  NoteRevision,
  SaveHostNoteMode,
  SaveHostNoteResult,
} from "@/lib/api";

/* ------------------------------------------------------------------ */
/* Mocks                                                               */
/* ------------------------------------------------------------------ */

// Mutable state the API hooks read on every render.  Each test
// seeds the slices it needs; ``afterEach`` resets to defaults.
// ``refetch`` lets tests assert that the conflict-dialog's
// "Reload latest version" path actually triggers a refetch on
// the host-note query (instead of the previous broken
// implementation that just closed the editor and asked the
// operator to manually reopen).
const refetchSpy = vi.fn(async () => undefined);
let noteState: {
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  data: HostNoteResult | undefined;
  refetch: typeof refetchSpy;
} = {
  isLoading: false,
  isError: false,
  error: null,
  data: undefined,
  refetch: refetchSpy,
};

let authState: {
  data: { authenticated: boolean; email?: string } | undefined;
} = { data: { authenticated: false } };

let revisionsState: {
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  data: NoteRevision[] | undefined;
} = {
  isLoading: false,
  isError: false,
  error: null,
  data: undefined,
};

// Recorded save-mutation invocations and deletion calls.  Tests
// inspect these to confirm the right HTTP shape was emitted.
interface SaveCall {
  body: string;
  mode: SaveHostNoteMode;
}
const saveCalls: SaveCall[] = [];
let saveNextResult: SaveHostNoteResult | undefined;
let saveNextError: Error | undefined;
let savePending = false;

const deleteCalls: number[] = [];
let deleteNextResult: boolean | undefined;

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>(
    "@/lib/api",
  );
  return {
    ...actual,
    useHostNote: () => noteState,
    useHostNoteRevisions: () => revisionsState,
    useSaveHostNote: () => ({
      mutate: (
        vars: SaveCall,
        opts?: {
          onSuccess?: (r: SaveHostNoteResult) => void;
          onError?: (e: Error) => void;
        },
      ) => {
        saveCalls.push(vars);
        // Defer the callback so the component sees the
        // ``isPending`` state transition (mirrors what React
        // Query does between mutate() and onSuccess/onError).
        queueMicrotask(() => {
          if (saveNextError) {
            opts?.onError?.(saveNextError);
          } else if (saveNextResult) {
            opts?.onSuccess?.(saveNextResult);
          }
        });
      },
      isPending: savePending,
    }),
    useDeleteHostNote: () => ({
      mutate: (
        _: undefined,
        opts?: {
          onSuccess?: (existed: boolean) => void;
          onError?: (e: Error) => void;
        },
      ) => {
        deleteCalls.push(deleteCalls.length + 1);
        queueMicrotask(() => {
          if (deleteNextResult !== undefined) {
            opts?.onSuccess?.(deleteNextResult);
          } else {
            opts?.onError?.(new Error("delete mock not seeded"));
          }
        });
      },
      isPending: false,
    }),
  };
});

vi.mock("@/lib/auth", () => ({
  useAuthMe: () => authState,
}));

// ``@uiw/react-md-editor`` is a heavy WYSIWYG component whose
// internals (toolbar, syntax highlighter, live preview pane) do
// not render cleanly under jsdom and are not what we are
// testing.  Replace with a thin textarea that calls back
// ``onChange`` with the new value -- enough for the parent
// component's state machine + Save-button wiring to be
// exercised.
vi.mock("@uiw/react-md-editor", () => ({
  __esModule: true,
  default: ({
    value,
    onChange,
    textareaProps,
  }: {
    value: string;
    onChange: (val: string | undefined) => void;
    textareaProps?: { "aria-label"?: string; placeholder?: string };
  }) => (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label={textareaProps?.["aria-label"]}
      placeholder={textareaProps?.placeholder}
      data-testid="host-notes-editor-textarea"
    />
  ),
}));

// ``next-themes`` is consumed by the editor wrapper to pick its
// dark/light skin.  Stub a resolved theme so the wrapper
// renders deterministically.
vi.mock("next-themes", () => ({
  useTheme: () => ({ resolvedTheme: "light", setTheme: vi.fn() }),
}));

// ``sonner`` toast spy so tests can assert success / error
// notifications fired without depending on the toast renderer.
const toastSpies = {
  success: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
  message: vi.fn(),
};
vi.mock("sonner", () => ({
  toast: {
    success: (...args: unknown[]) => toastSpies.success(...args),
    error: (...args: unknown[]) => toastSpies.error(...args),
    info: (...args: unknown[]) => toastSpies.info(...args),
    warning: (...args: unknown[]) => toastSpies.warning(...args),
    message: (...args: unknown[]) => toastSpies.message(...args),
  },
}));

afterEach(() => {
  noteState = {
    isLoading: false,
    isError: false,
    error: null,
    data: undefined,
    refetch: refetchSpy,
  };
  refetchSpy.mockClear();
  authState = { data: { authenticated: false } };
  revisionsState = {
    isLoading: false,
    isError: false,
    error: null,
    data: undefined,
  };
  saveCalls.length = 0;
  saveNextResult = undefined;
  saveNextError = undefined;
  savePending = false;
  deleteCalls.length = 0;
  deleteNextResult = undefined;
  toastSpies.success.mockClear();
  toastSpies.error.mockClear();
  toastSpies.info.mockClear();
  toastSpies.warning.mockClear();
  toastSpies.message.mockClear();
});

const sampleNote: Note = {
  entity_type: "host",
  entity_key: "192.0.2.10",
  body: "## Investigation\n\nFollowing up on the **C2** traffic.",
  revision: 3,
  created_at: "2026-05-01T10:00:00Z",
  created_by: "alice@example.org",
  updated_at: "2026-05-12T14:32:11Z",
  updated_by: "bob@example.org",
};

/* ------------------------------------------------------------------ */
/* Read-mode display                                                   */
/* ------------------------------------------------------------------ */

describe("HostNotesPanel read mode", () => {
  it("shows a loading skeleton with role=status while the query is in flight", () => {
    noteState = { ...noteState, isLoading: true };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(
      screen.getByRole("heading", { name: /^notes$/i }),
    ).toBeInTheDocument();
    const skeleton = screen.getByTestId("host-notes-loading");
    expect(skeleton).toHaveAttribute("role", "status");
    expect(skeleton).toHaveAccessibleName(/loading note/i);
  });

  it("renders the markdown body + footer when a note exists", () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);

    // ``## Investigation`` lands on ``<h5>`` after the
    // heading-level remap.
    expect(
      screen.getByRole("heading", { name: /investigation/i, level: 5 }),
    ).toBeInTheDocument();
    expect(screen.getByText(/bob@example\.org/)).toBeInTheDocument();
    expect(screen.getByText(/rev 3/)).toBeInTheDocument();
  });

  it("shows the empty-state placeholder when the note is absent (404)", () => {
    noteState = { ...noteState, data: { kind: "absent" } };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(screen.getByTestId("host-notes-empty")).toBeInTheDocument();
    expect(
      screen.getByText(/no notes for this host yet/i),
    ).toBeInTheDocument();
  });

  it("hides the entire section when the backend is unavailable (501)", () => {
    noteState = { ...noteState, data: { kind: "unavailable" } };

    const { container } = render(<HostNotesPanel addr="192.0.2.10" />);

    expect(container).toBeEmptyDOMElement();
  });

  it("renders an error message on other failures", () => {
    noteState = {
      ...noteState,
      isError: true,
      error: new Error("GET /cgi/notes/... failed: 500 Server Error"),
    };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(screen.getByTestId("host-notes-error")).toBeInTheDocument();
    expect(
      screen.getByText(/500 Server Error/),
    ).toBeInTheDocument();
  });

  it("suppresses <img> tags and surfaces the alt text instead", () => {
    noteState = {
      ...noteState,
      data: {
        kind: "found",
        note: {
          ...sampleNote,
          body: "Caption: ![viewer-tracking-pixel](https://attacker.example/track)",
        },
      },
    };

    const { container } = render(<HostNotesPanel addr="192.0.2.10" />);

    expect(container.querySelectorAll("img")).toHaveLength(0);
    expect(screen.getByText("viewer-tracking-pixel")).toBeInTheDocument();
  });

  it("adds rel=noopener noreferrer to outbound links", () => {
    noteState = {
      ...noteState,
      data: {
        kind: "found",
        note: {
          ...sampleNote,
          body: "See [the writeup](https://example.org/) for details.",
        },
      },
    };

    const { container } = render(<HostNotesPanel addr="192.0.2.10" />);
    const link = container.querySelector("a");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });
});

/* ------------------------------------------------------------------ */
/* Auth gating                                                         */
/* ------------------------------------------------------------------ */

describe("HostNotesPanel auth gating", () => {
  it("does NOT show edit / delete buttons when user is anonymous", () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = { data: { authenticated: false } };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(screen.queryByTestId("host-notes-edit-button")).toBeNull();
    expect(screen.queryByTestId("host-notes-delete-button")).toBeNull();
  });

  it("shows edit + delete buttons when user is authenticated", () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(
      screen.getByTestId("host-notes-edit-button"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("host-notes-delete-button"),
    ).toBeInTheDocument();
  });

  it("does NOT show Add-note button when anonymous + empty", () => {
    noteState = { ...noteState, data: { kind: "absent" } };
    authState = { data: { authenticated: false } };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(screen.queryByTestId("host-notes-add-button")).toBeNull();
  });

  it("shows Add-note button when authenticated + empty", () => {
    noteState = { ...noteState, data: { kind: "absent" } };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(
      screen.getByTestId("host-notes-add-button"),
    ).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/* Edit flow                                                           */
/* ------------------------------------------------------------------ */

describe("HostNotesPanel edit flow", () => {
  it("clicking Edit swaps the display for the editor (update mode)", async () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));

    expect(
      screen.getByTestId("host-notes-editor"),
    ).toBeInTheDocument();
    // The textarea is pre-filled with the existing note body.
    const textarea = screen.getByTestId(
      "host-notes-editor-textarea",
    ) as HTMLTextAreaElement;
    expect(textarea.value).toBe(sampleNote.body);
  });

  it("Save in update mode sends If-Match with the current revision", async () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    saveNextResult = {
      kind: "saved",
      note: { ...sampleNote, body: "Updated", revision: 4 },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));
    fireEvent.change(
      screen.getByTestId("host-notes-editor-textarea"),
      { target: { value: "Updated" } },
    );
    fireEvent.click(screen.getByTestId("host-notes-save-button"));

    await waitFor(() => expect(saveCalls).toHaveLength(1));
    expect(saveCalls[0]).toEqual({
      body: "Updated",
      mode: { kind: "update", expectedRevision: 3 },
    });
    // The mutation's onSuccess fires asynchronously via
    // queueMicrotask; flush it.
    await waitFor(() => expect(toastSpies.success).toHaveBeenCalled());
  });

  it("Save in create mode (from empty state) sends If-None-Match: *", async () => {
    noteState = { ...noteState, data: { kind: "absent" } };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    saveNextResult = {
      kind: "saved",
      note: { ...sampleNote, body: "Brand new", revision: 1 },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-add-button"));
    fireEvent.change(
      screen.getByTestId("host-notes-editor-textarea"),
      { target: { value: "Brand new" } },
    );
    fireEvent.click(screen.getByTestId("host-notes-save-button"));

    await waitFor(() => expect(saveCalls).toHaveLength(1));
    expect(saveCalls[0]).toEqual({
      body: "Brand new",
      mode: { kind: "create" },
    });
  });

  it("Cancel returns to read-mode without saving", () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));
    fireEvent.click(screen.getByTestId("host-notes-cancel-button"));

    expect(screen.queryByTestId("host-notes-editor")).toBeNull();
    expect(saveCalls).toHaveLength(0);
  });

  it("opens the conflict dialog on a 409 conflict response", async () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    saveNextResult = {
      kind: "conflict",
      message: "stored revision 5 does not match expected=3",
    };

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));
    fireEvent.click(screen.getByTestId("host-notes-save-button"));

    // ``waitFor`` rather than direct assert because the
    // conflict state is set inside the mutation's onSuccess
    // callback, which fires via queueMicrotask.
    await waitFor(() => {
      expect(
        screen.getByTestId("host-notes-conflict-dialog"),
      ).toBeInTheDocument();
    });
    expect(
      screen.getByText(/stored revision 5/),
    ).toBeInTheDocument();
  });

  it("Reload latest version refetches the note and preserves the operator's draft via clipboard", async () => {
    // The conflict-dialog Reload button must actually trigger
    // a refetch on the underlying ``useHostNote`` query (not
    // just close the editor) AND preserve the operator's
    // pending body to the clipboard so they can paste back
    // to merge against the latest version.  This pins both
    // behaviours together since they were missing in the
    // first cut of the conflict dialog.
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    saveNextResult = {
      kind: "conflict",
      message: "stored revision 5 does not match expected=3",
    };
    const writeTextSpy = vi.fn(async () => undefined);
    // jsdom does not provide a real ``navigator.clipboard``;
    // install a writeable stub.
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: writeTextSpy },
      writable: true,
      configurable: true,
    });

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));
    // Type something so the pending body is non-trivial -- the
    // clipboard preservation needs real content to be useful.
    fireEvent.change(
      screen.getByTestId("host-notes-editor-textarea"),
      { target: { value: "My pending edits" } },
    );
    fireEvent.click(screen.getByTestId("host-notes-save-button"));

    await waitFor(() => {
      expect(
        screen.getByTestId("host-notes-conflict-dialog"),
      ).toBeInTheDocument();
    });

    fireEvent.click(
      screen.getByRole("button", { name: /reload latest version/i }),
    );

    // The operator's pending body was copied to the clipboard.
    await waitFor(() =>
      expect(writeTextSpy).toHaveBeenCalledWith("My pending edits"),
    );
    // A toast confirms the clipboard preservation.
    expect(toastSpies.info).toHaveBeenCalledWith(
      expect.stringMatching(/clipboard/i),
    );
    // The host-note query was refetched.  The parent passes
    // ``query.refetch`` down to the editor; the click must
    // route through.
    expect(refetchSpy).toHaveBeenCalledTimes(1);
    // The dialog closed (the conflict state was reset before
    // the refetch).
    expect(
      screen.queryByTestId("host-notes-conflict-dialog"),
    ).toBeNull();
  });

  it("Reload latest still refetches even when the clipboard is unavailable", async () => {
    // ``navigator.clipboard.writeText`` can throw (insecure
    // context, missing permission); the refetch must still
    // happen so the operator at least sees the latest body
    // even when the draft preservation fails.  A warning
    // toast replaces the success info toast.
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    saveNextResult = {
      kind: "conflict",
      message: "stored revision 5 does not match expected=3",
    };
    const writeTextSpy = vi.fn(async () => {
      throw new Error("permission denied");
    });
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: writeTextSpy },
      writable: true,
      configurable: true,
    });

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));
    fireEvent.click(screen.getByTestId("host-notes-save-button"));
    await waitFor(() =>
      expect(
        screen.getByTestId("host-notes-conflict-dialog"),
      ).toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: /reload latest version/i }),
    );

    await waitFor(() => expect(refetchSpy).toHaveBeenCalledTimes(1));
    // The warning toast surfaces the clipboard failure -- the
    // refetch happened, but the operator's draft is gone.
    expect(toastSpies.warning).toHaveBeenCalledWith(
      expect.stringMatching(/clipboard/i),
    );
  });

  it("surfaces too_large as an error toast", async () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    saveNextResult = { kind: "too_large" };

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));
    fireEvent.click(screen.getByTestId("host-notes-save-button"));

    await waitFor(() =>
      expect(toastSpies.error).toHaveBeenCalledWith(
        expect.stringMatching(/too large/i),
      ),
    );
  });

  it("on not_found, refetches the note and preserves the operator's draft via clipboard", async () => {
    // ``not_found`` fires when the note was deleted between
    // load and save (e.g. another operator deleted it while
    // this one was editing).  The handler must (a) copy the
    // operator's pending body to the clipboard so they can
    // paste back to recreate, and (b) refetch the underlying
    // ``useHostNote`` query so the parent re-renders with
    // ``existingNote = null`` and the editor's
    // ``key`` change remounts it in create mode.  The editor
    // stays open across the refetch.
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    saveNextResult = { kind: "not_found" };
    const writeTextSpy = vi.fn(async () => undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: writeTextSpy },
      writable: true,
      configurable: true,
    });

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));
    fireEvent.change(
      screen.getByTestId("host-notes-editor-textarea"),
      { target: { value: "My pending recreate" } },
    );
    fireEvent.click(screen.getByTestId("host-notes-save-button"));

    // The operator's pending body landed on the clipboard.
    await waitFor(() =>
      expect(writeTextSpy).toHaveBeenCalledWith("My pending recreate"),
    );
    // The query was refetched -- the parent will switch to
    // ``existingNote = null`` once the refetch resolves.
    await waitFor(() => expect(refetchSpy).toHaveBeenCalledTimes(1));
    // The toast surfaces the deletion + clipboard
    // preservation.
    expect(toastSpies.error).toHaveBeenCalledWith(
      expect.stringMatching(/deleted while you were editing/i),
    );
  });

  it("renders Save button as disabled with a loader while the mutation is pending", () => {
    // The real ``useMutation`` returns a hook that re-renders
    // with ``isPending: true`` synchronously on
    // ``mutate()`` invocation.  Our mock cannot track that
    // transition cheaply, so this test pre-seeds the
    // pending state and pins the rendered output of the
    // pending branch -- the button text changes from
    // "Save" to "Saving…", the button is disabled, and the
    // Cancel button is also disabled.  The transition itself
    // is exercised end-to-end by the Playwright e2e against
    // the real ``useMutation`` implementation.
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    savePending = true;

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-edit-button"));

    const saveButton = screen.getByTestId("host-notes-save-button");
    expect(saveButton).toBeDisabled();
    expect(saveButton).toHaveTextContent(/saving…/i);
    // The Cancel button is also disabled so the operator
    // does not lose their draft mid-save by clicking it
    // accidentally.
    expect(screen.getByTestId("host-notes-cancel-button")).toBeDisabled();
  });
});

/* ------------------------------------------------------------------ */
/* Delete flow                                                         */
/* ------------------------------------------------------------------ */

describe("HostNotesPanel delete flow", () => {
  it("clicking Delete calls deleteHostNote after confirmation", async () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    deleteNextResult = true;
    // jsdom's ``window.confirm`` returns false by default;
    // stub it to true so the deletion path proceeds.
    const confirmSpy = vi
      .spyOn(window, "confirm")
      .mockImplementation(() => true);

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-delete-button"));

    await waitFor(() => expect(deleteCalls.length).toBe(1));
    await waitFor(() =>
      expect(toastSpies.success).toHaveBeenCalledWith(
        expect.stringMatching(/deleted/i),
      ),
    );
    confirmSpy.mockRestore();
  });

  it("clicking Delete then declining the confirmation aborts", () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    authState = {
      data: { authenticated: true, email: "alice@example.org" },
    };
    const confirmSpy = vi
      .spyOn(window, "confirm")
      .mockImplementation(() => false);

    render(<HostNotesPanel addr="192.0.2.10" />);
    fireEvent.click(screen.getByTestId("host-notes-delete-button"));

    expect(deleteCalls).toHaveLength(0);
    confirmSpy.mockRestore();
  });
});

/* ------------------------------------------------------------------ */
/* Revision history                                                    */
/* ------------------------------------------------------------------ */

describe("HostNotesPanel revision history", () => {
  it("toggles the history expander on click", () => {
    noteState = {
      ...noteState,
      data: { kind: "found", note: sampleNote },
    };
    // Three revisions in the audit log -- matches
    // ``sampleNote.revision`` so the label is consistent
    // whether the trigger draws from
    // ``revisionsQuery.data.length`` (preferred once
    // settled) or ``currentRevision`` (proxy fallback).
    revisionsState = {
      isLoading: false,
      isError: false,
      error: null,
      data: [
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
        {
          revision: 1,
          body: "First revision body",
          created_at: "2026-05-01T10:00:00Z",
          created_by: "alice@example.org",
        },
      ],
    };

    render(<HostNotesPanel addr="192.0.2.10" />);
    const toggle = screen.getByTestId("host-notes-history-toggle");
    // The label surfaces the revision count so the operator
    // sees how many to expect before expanding.
    expect(toggle).toHaveTextContent(/history.*3 revisions/i);

    fireEvent.click(toggle);
    // After expanding, the revisions list is in the DOM.
    expect(
      screen.getByTestId("host-notes-history-list"),
    ).toBeInTheDocument();
    // Each revision row carries the author + timestamp.
    // ``getAllByText`` because two of the three seeded
    // revisions are by alice (rev 1 + rev 2) and the
    // multi-match would otherwise trip
    // ``getByText``'s strict-mode safeguard.
    expect(screen.getByText(/by bob@example\.org/)).toBeInTheDocument();
    expect(screen.getAllByText(/by alice@example\.org/)).toHaveLength(2);
  });

  it("pluralises the revision count correctly", () => {
    noteState = {
      ...noteState,
      data: {
        kind: "found",
        note: { ...sampleNote, revision: 1 },
      },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);
    expect(
      screen.getByTestId("host-notes-history-toggle"),
    ).toHaveTextContent(/history.*1 revision\b/i);
  });

  it("prefers the fetched revisions length over the revision-number proxy", () => {
    // ``currentRevision`` is a proxy for the revision count
    // that holds only while no revisions are pruned or
    // gapped.  Once ``useHostNoteRevisions`` has settled,
    // the trigger label switches to
    // ``revisionsQuery.data.length`` as the authoritative
    // count.  Pin the fallback ordering so a future feature
    // that introduces pruning / gaps will surface the right
    // count without re-deriving from the revision number.
    noteState = {
      ...noteState,
      data: {
        kind: "found",
        // Revision number says 5, but only 3 revisions are
        // actually in the audit log (e.g. 2 were pruned).
        note: { ...sampleNote, revision: 5 },
      },
    };
    revisionsState = {
      isLoading: false,
      isError: false,
      error: null,
      data: [
        {
          revision: 5,
          body: "rev5",
          created_at: "2026-05-12T15:00:00Z",
          created_by: "bob@example.org",
        },
        {
          revision: 4,
          body: "rev4",
          created_at: "2026-05-11T15:00:00Z",
          created_by: "alice@example.org",
        },
        {
          revision: 3,
          body: "rev3",
          created_at: "2026-05-10T15:00:00Z",
          created_by: "alice@example.org",
        },
      ],
    };

    render(<HostNotesPanel addr="192.0.2.10" />);
    // Label reflects the *actual* fetched length (3), not
    // the revision-number proxy (5).
    expect(
      screen.getByTestId("host-notes-history-toggle"),
    ).toHaveTextContent(/history.*3 revisions\b/i);
  });
});
