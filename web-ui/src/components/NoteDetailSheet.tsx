import { ExternalLink } from "lucide-react";
import Markdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import type { Note } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface NoteDetailSheetProps {
  /** The note to display.  ``null`` keeps the sheet closed. */
  note: Note | null;
  /** Driven by the sheet's own open/close affordances + the
   *  parent's selection state (see :func:`NotesExplorerPage`). */
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/** Right-side slide-over showing the full markdown body of a
 *  note plus a deep-link to the matching entity's detail page
 *  (currently host detail; future entity types extend the
 *  switch below).
 *
 *  Read-only by design: this is the listing-side viewer.  All
 *  edit affordances live on the per-host ``HostNotesPanel`` --
 *  the deep-link is what brings the operator there.
 *
 *  Markdown rendering mirrors the security / a11y hardenings
 *  from :func:`HostNotesPanel.MarkdownBody`:
 *
 *   - ``<img>`` rendering disabled (no third-party
 *     tracking-pixel exfil on view).
 *   - ``<a>`` carries ``rel="noopener noreferrer"`` (no
 *     ``Referer`` leak to operator-pasted links).
 *   - Markdown heading levels remapped two down so an
 *     in-body ``#`` lands on ``<h4>`` (below the sheet's own
 *     ``<h2>`` title) -- keeps screen-reader heading
 *     navigation monotone.
 */
export function NoteDetailSheet({
  note,
  open,
  onOpenChange,
}: NoteDetailSheetProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full max-w-2xl overflow-y-auto sm:max-w-2xl"
        data-testid="note-detail-sheet"
      >
        {note ? <NoteDetailBody note={note} /> : null}
      </SheetContent>
    </Sheet>
  );
}

function NoteDetailBody({ note }: { note: Note }) {
  const deepLink = entityDeepLink(note);
  return (
    <>
      <SheetHeader className="pb-2">
        <SheetTitle className="flex items-center gap-2 font-mono">
          <Badge variant="outline" className="font-mono text-xs">
            {note.entity_type}
          </Badge>
          <span data-testid="note-detail-entity-key">
            {note.entity_key}
          </span>
        </SheetTitle>
        <SheetDescription>
          Note rev {note.revision}, last updated by{" "}
          <span className="font-medium">{note.updated_by}</span> on{" "}
          {formatTimestamp(note.updated_at)}.
        </SheetDescription>
      </SheetHeader>
      {deepLink ? (
        <div className="px-1 py-2">
          <Button asChild variant="outline" size="sm">
            <a href={deepLink} data-testid="note-detail-deep-link">
              <ExternalLink className="mr-1 h-3 w-3" />
              Open {note.entity_type} details
            </a>
          </Button>
        </div>
      ) : null}
      <div className="border-t px-1 py-3" data-testid="note-detail-body">
        <MarkdownBody body={note.body} />
      </div>
      <p className="px-1 pt-2 text-xs text-muted-foreground">
        Created by{" "}
        <span className="font-medium">{note.created_by}</span> on{" "}
        {formatTimestamp(note.created_at)}.
      </p>
    </>
  );
}

/** Build the deep link to the entity's detail page.  Only
 *  ``host`` resolves today (``/view/host/<addr>``); future
 *  entity types extend this switch as their respective detail
 *  routes land.  Returns ``null`` for entity types without a
 *  detail page yet -- the sheet renders the body without a
 *  link in that case. */
function entityDeepLink(note: Note): string | null {
  if (note.entity_type === "host") {
    return `#/view/host/${encodeURIComponent(note.entity_key)}`;
  }
  return null;
}

function stripHastNode<T extends { node?: unknown }>(
  props: T,
): Omit<T, "node"> {
  const { node, ...rest } = props;
  void node;
  return rest;
}

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

function MarkdownBody({ body }: { body: string }) {
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
        {body}
      </Markdown>
    </div>
  );
}
