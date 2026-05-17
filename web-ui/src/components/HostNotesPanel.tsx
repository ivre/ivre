import { useDeferredValue } from "react";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

import { useHostNote } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface HostNotesPanelProps {
  /** Caller-facing host address (printable IP string) used as the
   *  ``entity_key`` against ``/cgi/notes/host/<addr>``. */
  addr: string;
}

/**
 * Read-only display of the markdown note attached to a host.
 *
 * Drops into the host detail sheet as a self-contained section --
 * the component renders its own ``<section>`` wrapper + heading so
 * it can ``return null`` entirely when the server reports the
 * notes backend is unavailable (HTTP 501).  Hiding the whole
 * section on unsupported backends (e.g. PostgreSQL deployments)
 * avoids surfacing a permanent "feature missing" notice to every
 * viewer.
 *
 * Markdown rendering goes through ``react-markdown`` + ``remark-gfm``
 * (tables / strikethrough / autolinks / task lists), with three
 * security / a11y hardenings layered on top of the defaults via
 * ``components`` overrides (see :func:`MarkdownBody`):
 *
 *   * ``<img>`` rendering is *disabled* -- a note author cannot
 *     embed a third-party tracking pixel that would leak the
 *     viewer's IP / Referer / cookies when the panel paints.
 *     Alt text falls back as italicised plain text so operators
 *     who paste ``![alt](url)`` still see *something*.
 *   * ``<a>`` links get ``rel="noopener noreferrer"`` so a user
 *     click does not leak the IVRE detail-sheet URL (which
 *     usually contains the target IP) as Referer to the third
 *     party.
 *   * Markdown heading levels (``#``..``######``) are shifted so
 *     ``#`` becomes ``<h4>`` rather than ``<h1>`` -- the section
 *     heading above is ``<h3>``, and an operator-authored ``#``
 *     would otherwise create a backwards jump in the document's
 *     heading order that screen-reader heading navigation would
 *     mis-announce.
 *
 * The renderer also explicitly *does not* configure ``rehype-raw``
 * so any inline HTML in the body renders as escaped literal
 * text rather than executing.
 *
 * Writing / editing affordances are intentionally absent here;
 * they live in a follow-up component (the editable variant of
 * this panel).
 */
export function HostNotesPanel({ addr }: HostNotesPanelProps) {
  const query = useHostNote(addr);

  // Hide the whole section when the backend has no notes
  // implementation.  ``unavailable`` is the ``HostNoteResult``
  // discriminant the API client surfaces for HTTP 501 -- see
  // :func:`fetchHostNote` for the contract.  Deployments that
  // intentionally have no notes backend (Postgres, etc.) get a
  // clean detail sheet with no permanent warning chrome.
  if (query.data?.kind === "unavailable") {
    return null;
  }

  return (
    <section data-testid="host-notes-section">
      <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
        Notes
      </h3>
      <HostNotesBody query={query} />
    </section>
  );
}

function HostNotesBody({
  query,
}: {
  query: ReturnType<typeof useHostNote>;
}) {
  if (query.isLoading) {
    // Skeleton bars sized roughly like a short note paragraph so
    // the layout does not jump when the body arrives.  Two bars
    // is the visual cue "loading" without committing to a
    // specific final height.
    //
    // ``role="status"`` (which implies ``aria-live="polite"``)
    // makes the SR-only "Loading note..." text announced when
    // the element first appears; the skeleton bars themselves
    // are decorative.
    return (
      <div
        className="space-y-2"
        data-testid="host-notes-loading"
        role="status"
        aria-label="Loading note"
      >
        <span className="sr-only">Loading note…</span>
        <div className="h-3 w-3/4 animate-pulse rounded bg-muted" />
        <div className="h-3 w-2/3 animate-pulse rounded bg-muted" />
      </div>
    );
  }

  if (query.isError) {
    return (
      <p
        className="text-sm text-destructive"
        data-testid="host-notes-error"
      >
        Failed to load note: {(query.error as Error).message}
      </p>
    );
  }

  const result = query.data;
  if (!result || result.kind === "absent") {
    return (
      <p
        className="text-sm italic text-muted-foreground"
        data-testid="host-notes-empty"
      >
        No notes for this host yet.
      </p>
    );
  }

  // ``unavailable`` was handled above and would have hidden the
  // entire section; we are guaranteed ``found`` at this point but
  // narrow explicitly for the type-checker.
  if (result.kind !== "found") {
    return null;
  }

  const { note } = result;
  return (
    <div data-testid="host-notes-content">
      <MarkdownBody body={note.body} />
      <p className="mt-3 text-xs text-muted-foreground">
        Last updated by{" "}
        <span className="font-medium">{note.updated_by}</span> on{" "}
        {formatTimestamp(note.updated_at)} (rev {note.revision})
      </p>
    </div>
  );
}

/** ``react-markdown`` ``components`` overrides that harden the
 *  default renderer.  Declared at module scope so the object
 *  identity is stable across renders (passing a fresh object
 *  literal on every render would defeat any internal memoisation
 *  ``react-markdown`` performs).  See :func:`HostNotesPanel`'s
 *  docstring for the per-override rationale. */
/** Strip the ``node`` prop ``react-markdown`` passes to every
 *  component override -- it is the hast AST node, not a valid
 *  DOM attribute, and spreading it onto an HTML element would
 *  emit a runtime ``Unknown DOM attribute`` warning.  Returning
 *  a fresh object also keeps the override pure (no mutation of
 *  the props object react-markdown reuses across renders). */
function stripHastNode<T extends { node?: unknown }>(
  props: T,
): Omit<T, "node"> {
  const { node, ...rest } = props;
  // ``void node`` acknowledges the binding so it satisfies the
  // no-unused-vars rule without ``// eslint-disable`` or an
  // ``_node`` underscore alias.  The value is intentionally
  // discarded.
  void node;
  return rest;
}

const MARKDOWN_COMPONENTS: Components = {
  // Suppress image fetches.  An operator-authored
  // ``![alt](https://attacker/track?h=...)`` would otherwise
  // cause the viewing browser to GET the URL on render,
  // leaking IP / Referer / cookies to the third party -- the
  // standard email-tracking-pixel attack in a notes context.
  // Fall back to the alt text in italic so operators who pasted
  // ``![diagram](...)`` still see "diagram" instead of nothing.
  img: ({ alt }) =>
    alt ? <em className="text-muted-foreground">{alt}</em> : null,
  // Outbound links get ``noopener noreferrer`` so a click does
  // not leak the IVRE detail-sheet URL (which typically contains
  // the host IP being viewed) as ``Referer``, and the destination
  // page cannot access ``window.opener``.  ``target="_blank"``
  // is left to the operator's link-emission preferences -- we
  // do not force it here.
  a: (props) => {
    const { children, ...rest } = stripHastNode(props);
    return (
      <a {...rest} rel="noopener noreferrer">
        {children}
      </a>
    );
  },
  // Wrap GFM tables in a horizontally-scrollable container.
  // Without this, a wide table (many columns or long
  // unbreakable cells -- URLs / hashes / IPv6 addresses) forces
  // the entire host detail sheet to widen and produces page-
  // level horizontal scroll.  ``overflow-x-auto`` keeps the
  // overflow scoped to the table.
  table: (props) => (
    <div className="overflow-x-auto">
      <table {...stripHastNode(props)} />
    </div>
  ),
  // Remap markdown heading levels.  The section above this body
  // is ``<h3>``; an operator-authored ``#`` would otherwise emit
  // an ``<h1>`` inside a ``<h3>`` section, breaking the
  // document's heading hierarchy and confusing screen-reader
  // heading navigation.  Shift everything two levels down so
  // ``#`` -> ``<h4>`` (one level below the section).  ``<h6>``
  // is HTML's deepest heading level; we cap there.
  h1: (props) => <h4 {...stripHastNode(props)} />,
  h2: (props) => <h5 {...stripHastNode(props)} />,
  h3: (props) => <h6 {...stripHastNode(props)} />,
  h4: (props) => <h6 {...stripHastNode(props)} />,
  h5: (props) => <h6 {...stripHastNode(props)} />,
  h6: (props) => <h6 {...stripHastNode(props)} />,
};

const MARKDOWN_PLUGINS = [remarkGfm];

/** Tailwind-flavoured prose container for the rendered markdown.
 *  We do not use ``@tailwindcss/typography`` (not in the dep tree),
 *  so the styling is hand-rolled via element-class targeting that
 *  matches what ``react-markdown`` emits.  After the heading
 *  override (see ``MARKDOWN_COMPONENTS``) markdown headings land
 *  on ``<h4>`` / ``<h5>`` / ``<h6>`` rather than ``<h1>`` /
 *  ``<h2>`` / ``<h3>``, so the heading styling rules target the
 *  shifted levels. */
function MarkdownBody({ body }: { body: string }) {
  // ``useDeferredValue`` marks the heavy ``react-markdown`` parse
  // as low-priority work.  The host detail sheet chrome and the
  // surrounding section's heading + footer paint immediately;
  // the markdown body fills in on a subsequent low-priority
  // pass.  This does not change the rendered output; it only
  // changes the React commit order so a 1 MiB body (the soft cap
  // on the notes API) does not block the sheet's open animation
  // on the same tick.  Full virtualisation / web-worker parsing
  // is a follow-up if real-world reports show this isn't
  // enough.
  const deferredBody = useDeferredValue(body);
  return (
    <div
      className={cn(
        "text-sm leading-relaxed",
        // Headings: smaller scale than the page chrome so the
        // section heading above keeps visual primacy.  Markdown
        // ``#`` lands on ``<h4>`` after the level remap.
        "[&_h4]:mt-3 [&_h4]:mb-2 [&_h4]:text-base [&_h4]:font-semibold",
        "[&_h5]:mt-3 [&_h5]:mb-2 [&_h5]:text-sm [&_h5]:font-semibold",
        "[&_h6]:mt-3 [&_h6]:mb-1 [&_h6]:text-sm [&_h6]:font-semibold",
        // Paragraphs / spacing.
        "[&_p]:my-2",
        "[&_ul]:my-2 [&_ul]:list-disc [&_ul]:pl-5",
        "[&_ol]:my-2 [&_ol]:list-decimal [&_ol]:pl-5",
        "[&_li]:my-1",
        // Inline + block code.
        "[&_code]:rounded [&_code]:bg-muted [&_code]:px-1 [&_code]:py-0.5 [&_code]:font-mono [&_code]:text-xs",
        "[&_pre]:my-2 [&_pre]:overflow-x-auto [&_pre]:rounded [&_pre]:bg-muted [&_pre]:p-2",
        "[&_pre_code]:bg-transparent [&_pre_code]:p-0",
        // Blockquotes.
        "[&_blockquote]:my-2 [&_blockquote]:border-l-2 [&_blockquote]:border-muted [&_blockquote]:pl-3 [&_blockquote]:italic [&_blockquote]:text-muted-foreground",
        // Tables (gfm).  Styling targets the inner ``<table>``;
        // the wrapping ``<div class="overflow-x-auto">`` is
        // installed by the ``components.table`` override above.
        "[&_table]:my-2 [&_table]:w-full [&_table]:border-collapse",
        "[&_th]:border [&_th]:border-muted [&_th]:bg-muted/50 [&_th]:px-2 [&_th]:py-1 [&_th]:text-left",
        "[&_td]:border [&_td]:border-muted [&_td]:px-2 [&_td]:py-1",
        // Links.
        "[&_a]:text-primary [&_a]:underline [&_a]:underline-offset-2 hover:[&_a]:no-underline",
        // Hard rule.
        "[&_hr]:my-3 [&_hr]:border-muted",
      )}
    >
      <Markdown
        remarkPlugins={MARKDOWN_PLUGINS}
        components={MARKDOWN_COMPONENTS}
      >
        {deferredBody}
      </Markdown>
    </div>
  );
}
