/* @vitest-environment jsdom */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { NoteMarkdownBody } from "./NoteMarkdownBody";

/* ------------------------------------------------------------------ */
/* Security contract                                                   */
/* ------------------------------------------------------------------ */

/**
 * Every read-only notes consumer in the SPA renders bodies via
 * this shared component.  The tests below pin the security /
 * a11y contract documented on the component, so a future
 * hardening fix (or accidental regression) is caught here
 * regardless of which call site is being touched.  The
 * per-call-site tests (``HostNotesPanel.test.tsx``,
 * ``NoteDetailSheet.test.tsx``) still cover the integration
 * but the contract owner is this file.
 */

describe("NoteMarkdownBody security contract", () => {
  it("suppresses <img> tags and surfaces the alt text in italic", () => {
    // A tracking pixel pasted into a note body must never
    // trigger an outbound fetch on view -- doing so would
    // leak the viewer's IP / Referer / cookies to whatever
    // server the URL points at.  The alt text falls back to
    // an italic placeholder so the operator still sees what
    // the image was meant to convey.
    const { container } = render(
      <NoteMarkdownBody body="Caption: ![viewer-tracking-pixel](https://attacker.example/track)" />,
    );

    expect(container.querySelectorAll("img")).toHaveLength(0);
    const alt = screen.getByText("viewer-tracking-pixel");
    expect(alt.tagName.toLowerCase()).toBe("em");
  });

  it("drops <img> entirely (no placeholder) when alt is empty", () => {
    // ``![](url)`` is the no-alt form.  We don't fabricate a
    // visible placeholder in that case -- the operator did
    // not give us text to show, and the visual gap is the
    // least surprising fallback.
    const { container } = render(
      <NoteMarkdownBody body="![](https://attacker.example/track)" />,
    );
    expect(container.querySelectorAll("img")).toHaveLength(0);
    expect(container.querySelectorAll("em")).toHaveLength(0);
  });

  it("adds rel=noopener noreferrer to operator-pasted outbound links", () => {
    // A click on an operator-pasted link must NOT leak the
    // IVRE URL as ``Referer`` and the destination must NOT
    // be able to ``window.opener``-pivot back into the SPA.
    const { container } = render(
      <NoteMarkdownBody body="See [the writeup](https://example.org/) for details." />,
    );

    const link = container.querySelector("a");
    expect(link).not.toBeNull();
    expect(link).toHaveAttribute("href", "https://example.org/");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("wraps GFM tables in an overflow-x-auto container", () => {
    // A wide GFM table must not overflow the surrounding
    // panel / slide-over horizontally.  The wrapper carries
    // a scroll affordance instead.
    const { container } = render(
      <NoteMarkdownBody
        body={
          "| header | header |\n" +
          "| --- | --- |\n" +
          "| cell | cell |\n"
        }
      />,
    );
    const table = container.querySelector("table");
    expect(table).not.toBeNull();
    const wrapper = table?.parentElement;
    expect(wrapper?.className).toContain("overflow-x-auto");
  });
});

/* ------------------------------------------------------------------ */
/* Heading-level remap                                                 */
/* ------------------------------------------------------------------ */

describe("NoteMarkdownBody heading remap", () => {
  // The component is rendered inside containers whose document
  // outline already uses h2/h3 for the section / sheet title.
  // Operator-authored ``#`` must therefore land on ``<h4>`` to
  // keep screen-reader heading navigation monotone.

  it("maps `#` to <h4>", () => {
    render(<NoteMarkdownBody body="# top-level" />);
    expect(
      screen.getByRole("heading", { name: /top-level/i, level: 4 }),
    ).toBeInTheDocument();
  });

  it("maps `##` to <h5>", () => {
    render(<NoteMarkdownBody body="## second" />);
    expect(
      screen.getByRole("heading", { name: /second/i, level: 5 }),
    ).toBeInTheDocument();
  });

  it("clamps `###` through `######` to <h6>", () => {
    render(
      <NoteMarkdownBody
        body={
          "### three\n\n" +
          "#### four\n\n" +
          "##### five\n\n" +
          "###### six\n"
        }
      />,
    );
    // ``<h6>`` would otherwise be ambiguous in a single
    // ``getByRole`` query -- assert on each individually so
    // a regression that promotes one of them back to <h3..h5>
    // is caught.
    for (const name of [/three/i, /four/i, /five/i, /six/i]) {
      expect(
        screen.getByRole("heading", { name, level: 6 }),
      ).toBeInTheDocument();
    }
  });
});

/* ------------------------------------------------------------------ */
/* GFM passthrough                                                     */
/* ------------------------------------------------------------------ */

describe("NoteMarkdownBody GFM features", () => {
  it("renders bold / italic / inline code", () => {
    render(
      <NoteMarkdownBody body="**bold** _italic_ `inline`" />,
    );
    expect(screen.getByText("bold").tagName.toLowerCase()).toBe(
      "strong",
    );
    expect(screen.getByText("italic").tagName.toLowerCase()).toBe(
      "em",
    );
    expect(screen.getByText("inline").tagName.toLowerCase()).toBe(
      "code",
    );
  });

  it("renders ordered + unordered lists with task-list markers", () => {
    const { container } = render(
      <NoteMarkdownBody
        body={"- [x] done\n- [ ] todo\n\n1. first\n2. second\n"}
      />,
    );
    // Two list types in the DOM.
    expect(container.querySelectorAll("ul")).toHaveLength(1);
    expect(container.querySelectorAll("ol")).toHaveLength(1);
    // ``remark-gfm`` task lists render as disabled checkboxes.
    const boxes = container.querySelectorAll(
      "input[type='checkbox']",
    );
    expect(boxes).toHaveLength(2);
    expect((boxes[0] as HTMLInputElement).checked).toBe(true);
    expect((boxes[1] as HTMLInputElement).checked).toBe(false);
  });
});
