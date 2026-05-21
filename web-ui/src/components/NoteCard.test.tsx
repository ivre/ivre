/* @vitest-environment jsdom */
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { NoteCard } from "./NoteCard";

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

describe("NoteCard", () => {
  it("renders entity badge + key + revision + author footer", () => {
    render(<NoteCard note={sampleNote} />);

    // Entity-type badge.
    expect(screen.getByText("host")).toBeInTheDocument();
    // Entity key in the headline.
    expect(
      screen.getByTestId("note-card-entity-key"),
    ).toHaveTextContent("192.0.2.10");
    // Revision tag in the corner.
    expect(screen.getByText(/rev 3/)).toBeInTheDocument();
    // Footer surfaces updated_by + a UTC-formatted timestamp.
    expect(screen.getByText(/bob@example\.org/)).toBeInTheDocument();
    expect(
      screen.getByText(/2026-05-12 14:32:11Z/),
    ).toBeInTheDocument();
  });

  it("renders a markdown-stripped excerpt (no headings, no emphasis markers)", () => {
    render(<NoteCard note={sampleNote} />);

    const excerpt = screen.getByTestId("note-card-excerpt");
    // ``##`` heading prefix stripped, ``**...**`` emphasis stripped.
    // Whitespace collapsed so the heading + body land on one line.
    expect(excerpt.textContent).toBe(
      "Investigation Following up on the C2 traffic.",
    );
    expect(excerpt.textContent).not.toContain("**");
    expect(excerpt.textContent).not.toContain("##");
  });

  it("drops fenced code blocks from the excerpt", () => {
    // Operators routinely paste command output / payloads /
    // config dumps inside fenced blocks; the listing-side
    // excerpt should keep the surrounding prose without the
    // noisy dump (the full body is still visible after the
    // operator opens the detail sheet).
    const note: Note = {
      ...sampleNote,
      body: "Recap:\n\n```\nnc -lvp 4444\nwhoami\n```\n\nThe payload was caught by our IDS.",
    };

    render(<NoteCard note={note} />);

    const excerpt = screen.getByTestId("note-card-excerpt").textContent ?? "";
    expect(excerpt).toContain("Recap:");
    expect(excerpt).toContain("The payload was caught by our IDS.");
    expect(excerpt).not.toContain("nc -lvp 4444");
    expect(excerpt).not.toContain("whoami");
  });

  it("preserves literal _ / * / ` characters in non-emphasis context", () => {
    // The previous excerpt stripper used a blanket
    // ``/[*_`]{1,3}/g`` which mangled identifiers like
    // ``CVE_2026_1234`` into ``CVE20261234`` and globs like
    // ``foo*bar`` into ``foobar``.  Pin the paired-only
    // behaviour so a future refactor cannot silently regress
    // to the blanket strip.
    const note: Note = {
      ...sampleNote,
      body: "See CVE_2026_1234 and the glob foo*bar plus a stray ` tick.",
    };

    render(<NoteCard note={note} />);

    const text = screen.getByTestId("note-card-excerpt").textContent ?? "";
    expect(text).toContain("CVE_2026_1234");
    expect(text).toContain("foo*bar");
    expect(text).toContain("` tick");
  });

  it("still strips paired emphasis markers and inline code spans", () => {
    // The complement of the test above: paired ``**...**`` /
    // ``*...*`` / ``_..._`` / `` `...` `` runs are real
    // markdown emphasis and *should* be unwrapped in the
    // excerpt.
    const note: Note = {
      ...sampleNote,
      body: "Look at **the C2** and *this host* and _that flag_ plus `nc -lvp`.",
    };

    render(<NoteCard note={note} />);

    const text = screen.getByTestId("note-card-excerpt").textContent ?? "";
    expect(text).toBe(
      "Look at the C2 and this host and that flag plus nc -lvp.",
    );
  });

  it("truncates very long bodies with an ellipsis at the 240-char mark", () => {
    const note: Note = {
      ...sampleNote,
      body: "x".repeat(500),
    };

    render(<NoteCard note={note} />);

    const text = screen.getByTestId("note-card-excerpt").textContent ?? "";
    // 240 chars + the U+2026 horizontal-ellipsis suffix.
    expect(text.endsWith("\u2026")).toBe(true);
    expect(text.length).toBeLessThanOrEqual(241);
  });

  it("fires onSelect when the card is clicked", () => {
    const onSelect = vi.fn();
    render(<NoteCard note={sampleNote} onSelect={onSelect} />);

    fireEvent.click(screen.getByTestId("note-card"));

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith(sampleNote);
  });

  it("fires onSelect on Enter / Space when the card has focus", () => {
    // The card is the keyboard-actionable affordance for the
    // detail sheet; pin both Enter and Space so the row stays
    // reachable without a mouse.
    const onSelect = vi.fn();
    render(<NoteCard note={sampleNote} onSelect={onSelect} />);
    const card = screen.getByTestId("note-card");

    fireEvent.keyDown(card, { key: "Enter" });
    fireEvent.keyDown(card, { key: " " });
    fireEvent.keyDown(card, { key: "Escape" });

    expect(onSelect).toHaveBeenCalledTimes(2);
  });
});
