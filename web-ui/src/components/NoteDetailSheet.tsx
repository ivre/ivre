import { ExternalLink } from "lucide-react";

import { NoteMarkdownBody } from "@/components/NoteMarkdownBody";
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

export interface NoteDetailSheetProps {
  /** The note to display.  ``null`` keeps the sheet closed. */
  note: Note | null;
  /** Driven by the sheet's own open/close affordances + the
   *  parent's selection state (see :func:`NotesRoute`). */
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
 *  Markdown rendering goes through :func:`NoteMarkdownBody`,
 *  the shared read-only renderer.  It carries the security /
 *  a11y contract (``<img>`` suppressed, ``<a>``
 *  ``rel="noopener noreferrer"``, heading-level remap two
 *  down so an in-body ``#`` lands on ``<h4>``) on behalf of
 *  every notes consumer; see its module docstring for the
 *  full list.
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
        <NoteMarkdownBody body={note.body} />
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


