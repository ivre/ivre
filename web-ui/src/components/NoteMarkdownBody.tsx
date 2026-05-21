import { useDeferredValue } from "react";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

import { cn } from "@/lib/utils";

/** Strip the ``node`` prop ``react-markdown`` passes to custom
 *  component overrides.  ``...props`` would forward it to a
 *  native DOM element which then warns about the unknown HTML
 *  attribute.  ``void node`` acknowledges the binding so it
 *  satisfies the no-unused-vars rule without a
 *  ``// eslint-disable`` line or an ``_node`` rename. */
function stripHastNode<T extends { node?: unknown }>(
  props: T,
): Omit<T, "node"> {
  const { node, ...rest } = props;
  void node;
  return rest;
}

/** Single source of truth for the markdown renderer used by
 *  every read-only note display in the SPA (host detail panel
 *  + Notes Explorer detail sheet, today; future per-entity
 *  panels reuse this).  Centralising the renderer means a
 *  future hardening fix (banning a new dangerous tag, tweaking
 *  a relation hint, etc.) lands in one place instead of
 *  having to be applied to each call site -- a class of
 *  silent-regression bug the reviewer flagged on the earlier
 *  per-component renderers.
 *
 *  Security / a11y contract pinned by
 *  :file:`NoteMarkdownBody.test.tsx`:
 *
 *   - ``<img>`` rendering disabled; the markdown ``![alt](url)``
 *     surfaces as italic alt text.  Operator-pasted tracking
 *     pixels never trigger an outbound fetch on view.
 *   - ``<a>`` carries ``rel="noopener noreferrer"`` so a click
 *     does not leak the IVRE URL as ``Referer`` and the
 *     destination cannot access ``window.opener``.
 *   - GFM tables wrapped in an ``overflow-x-auto`` container so
 *     a wide table cannot overflow the slide-over / panel.
 *   - Heading levels remapped two down so an operator-authored
 *     ``#`` lands on ``<h4>`` rather than ``<h1>``, keeping
 *     screen-reader heading navigation monotone across the
 *     surrounding document outline (host detail's
 *     ``<h3>`` section heading, Notes detail sheet's ``<h2>``
 *     sheet title -- both want notes-body headings to start at
 *     ``<h4>``).
 *
 *  Performance: ``useDeferredValue(body)`` marks the
 *  ``react-markdown`` parse as low-priority work so a large
 *  note (up to ``WEB_HOST_NOTES_MAX_BYTES`` -- 1 MiB by
 *  default) does not block the surrounding container's open
 *  animation on the same React commit.
 */
const MARKDOWN_COMPONENTS: Components = {
  img: ({ alt }) =>
    alt ? <em className="text-muted-foreground">{alt}</em> : null,
  a: (props) => {
    const { children, ...rest } = stripHastNode(props);
    return (
      <a {...rest} rel="noopener noreferrer">
        {children}
      </a>
    );
  },
  table: (props) => (
    <div className="overflow-x-auto">
      <table {...stripHastNode(props)} />
    </div>
  ),
  h1: (props) => <h4 {...stripHastNode(props)} />,
  h2: (props) => <h5 {...stripHastNode(props)} />,
  h3: (props) => <h6 {...stripHastNode(props)} />,
  h4: (props) => <h6 {...stripHastNode(props)} />,
  h5: (props) => <h6 {...stripHastNode(props)} />,
  h6: (props) => <h6 {...stripHastNode(props)} />,
};

const MARKDOWN_PLUGINS = [remarkGfm];

export interface NoteMarkdownBodyProps {
  /** The note body to render.  Markdown text; rendered with
   *  the GFM extension (tables, strikethrough, task lists,
   *  autolinks).  Empty / whitespace-only bodies are allowed
   *  -- they render as an empty container. */
  body: string;
}

/** Read-only markdown renderer for note bodies.  See the
 *  module docstring for the security / a11y contract this
 *  component carries on behalf of every notes consumer. */
export function NoteMarkdownBody({ body }: NoteMarkdownBodyProps) {
  const deferredBody = useDeferredValue(body);
  return (
    <div
      className={cn(
        "text-sm leading-relaxed",
        "[&_h4]:mt-3 [&_h4]:mb-2 [&_h4]:text-base [&_h4]:font-semibold",
        "[&_h5]:mt-3 [&_h5]:mb-2 [&_h5]:text-sm [&_h5]:font-semibold",
        "[&_h6]:mt-3 [&_h6]:mb-1 [&_h6]:text-sm [&_h6]:font-semibold",
        "[&_p]:my-2",
        "[&_ul]:my-2 [&_ul]:list-disc [&_ul]:pl-5",
        "[&_ol]:my-2 [&_ol]:list-decimal [&_ol]:pl-5",
        "[&_li]:my-1",
        "[&_code]:rounded [&_code]:bg-muted [&_code]:px-1 [&_code]:py-0.5 [&_code]:font-mono [&_code]:text-xs",
        "[&_pre]:my-2 [&_pre]:overflow-x-auto [&_pre]:rounded [&_pre]:bg-muted [&_pre]:p-2",
        "[&_pre_code]:bg-transparent [&_pre_code]:p-0",
        "[&_blockquote]:my-2 [&_blockquote]:border-l-2 [&_blockquote]:border-muted [&_blockquote]:pl-3 [&_blockquote]:italic [&_blockquote]:text-muted-foreground",
        "[&_table]:my-2 [&_table]:w-full [&_table]:border-collapse",
        "[&_th]:border [&_th]:border-muted [&_th]:bg-muted/50 [&_th]:px-2 [&_th]:py-1 [&_th]:text-left",
        "[&_td]:border [&_td]:border-muted [&_td]:px-2 [&_td]:py-1",
        "[&_a]:text-primary [&_a]:underline [&_a]:underline-offset-2 hover:[&_a]:no-underline",
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
