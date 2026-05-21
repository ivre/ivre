/* @vitest-environment jsdom */
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { NoteDetailSheet } from "./NoteDetailSheet";

import type { Note } from "@/lib/api";

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

describe("NoteDetailSheet (closed)", () => {
  it("renders nothing in the DOM when ``open`` is false", () => {
    const { container, baseElement } = render(
      <NoteDetailSheet
        note={null}
        open={false}
        onOpenChange={vi.fn()}
      />,
    );

    // ``<Sheet>`` is a Radix Dialog that only portals its
    // content while open; assert the sheet body never made it
    // into the DOM.
    expect(container.querySelectorAll("[data-testid='note-detail-sheet']"))
      .toHaveLength(0);
    expect(
      baseElement.querySelectorAll("[data-testid='note-detail-sheet']"),
    ).toHaveLength(0);
  });
});

describe("NoteDetailSheet (open)", () => {
  it("renders the entity headline + revision/author description", () => {
    render(
      <NoteDetailSheet
        note={sampleNote}
        open={true}
        onOpenChange={vi.fn()}
      />,
    );

    expect(screen.getByText("host")).toBeInTheDocument();
    expect(
      screen.getByTestId("note-detail-entity-key"),
    ).toHaveTextContent("192.0.2.10");
    expect(
      screen.getByText(/Note rev 3, last updated by/),
    ).toBeInTheDocument();
    expect(screen.getByText(/bob@example\.org/)).toBeInTheDocument();
  });

  it("renders the markdown body with heading-level remap (## → h5)", () => {
    render(
      <NoteDetailSheet
        note={sampleNote}
        open={true}
        onOpenChange={vi.fn()}
      />,
    );

    // ``## Investigation`` lands on ``<h5>`` after the
    // heading-level remap (sheet title is the document's
    // ``<h2>``; body headings shift two levels down to keep
    // screen-reader heading navigation monotone).
    expect(
      screen.getByRole("heading", { name: /investigation/i, level: 5 }),
    ).toBeInTheDocument();
    // ``**C2**`` rendered as ``<strong>``.
    expect(screen.getByText("C2").tagName.toLowerCase()).toBe("strong");
  });

  it("surfaces a deep link to the host detail page for host entities", () => {
    render(
      <NoteDetailSheet
        note={sampleNote}
        open={true}
        onOpenChange={vi.fn()}
      />,
    );

    const link = screen.getByTestId("note-detail-deep-link");
    // Hash-router URL so the SPA picks it up without a full
    // page navigation.  The entity_key is URI-encoded so the
    // future ``host:1.2.3.4`` / unicode-domain cases route
    // safely.
    expect(link).toHaveAttribute("href", "#/view/host/192.0.2.10");
    expect(link).toHaveTextContent(/Open host details/i);
  });

  it("URI-encodes the entity key in the deep link", () => {
    const note: Note = {
      ...sampleNote,
      // An IPv6 entity key carries colons; the encoder must
      // turn them into ``%3A`` so the hash router parses
      // correctly.
      entity_key: "2001:db8::1",
    };

    render(
      <NoteDetailSheet
        note={note}
        open={true}
        onOpenChange={vi.fn()}
      />,
    );

    expect(screen.getByTestId("note-detail-deep-link")).toHaveAttribute(
      "href",
      "#/view/host/2001%3Adb8%3A%3A1",
    );
  });

  it("omits the deep link for entity types without a detail route yet", () => {
    // Forward-compat: when storage starts accepting other
    // entity types (e.g. ``network`` / ``domain``) the sheet
    // must still render their body; just no deep link until
    // those routes ship.
    const note: Note = { ...sampleNote, entity_type: "future-thing" };

    render(
      <NoteDetailSheet
        note={note}
        open={true}
        onOpenChange={vi.fn()}
      />,
    );

    expect(screen.queryByTestId("note-detail-deep-link")).toBeNull();
    // The body still renders.
    expect(screen.getByTestId("note-detail-body")).toBeInTheDocument();
  });

  it("suppresses <img> tags and surfaces the alt text instead", () => {
    // Mirrors the HostNotesPanel markdown-hardening assertion:
    // a tracking pixel pasted into a note body must not
    // trigger an outbound fetch on view.
    const note: Note = {
      ...sampleNote,
      body: "Caption: ![viewer-tracking-pixel](https://attacker.example/track)",
    };

    const { baseElement } = render(
      <NoteDetailSheet
        note={note}
        open={true}
        onOpenChange={vi.fn()}
      />,
    );

    expect(baseElement.querySelectorAll("img")).toHaveLength(0);
    expect(screen.getByText("viewer-tracking-pixel")).toBeInTheDocument();
  });

  it("adds rel=noopener noreferrer to operator-pasted outbound links", () => {
    const note: Note = {
      ...sampleNote,
      body: "See [the writeup](https://example.org/) for details.",
    };

    const { baseElement } = render(
      <NoteDetailSheet
        note={note}
        open={true}
        onOpenChange={vi.fn()}
      />,
    );

    // Two ``<a>``s land in the DOM here: the deep-link button
    // and the operator-pasted body link.  Filter to the one
    // whose href matches the markdown link.
    const links = Array.from(baseElement.querySelectorAll("a"));
    const bodyLink = links.find(
      (a) => a.getAttribute("href") === "https://example.org/",
    );
    expect(bodyLink).toBeDefined();
    expect(bodyLink).toHaveAttribute("rel", "noopener noreferrer");
  });
});
