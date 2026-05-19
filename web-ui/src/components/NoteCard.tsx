import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import type { Note } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";

export interface NoteCardProps {
  note: Note;
  /** Click handler for opening the in-page detail sheet.  The
   *  Notes Explorer's row click opens an overlay showing the
   *  full markdown body + an entity deep link (see
   *  :func:`NoteDetailSheet`); the card surfaces a short
   *  metadata strip + a body excerpt only. */
  onSelect?: (note: Note) => void;
}

/** Maximum number of characters of the body shown in the
 *  collapsed row.  Operators routinely write multi-paragraph
 *  notes; rendering the full body in every row would defeat
 *  the listing's "skim across many entities" purpose.  Long
 *  bodies are truncated with an ellipsis; the full content is
 *  visible after the operator opens the detail sheet. */
const BODY_EXCERPT_CHARS = 240;

/** Compact row for the Notes Explorer.  Surfaces the entity
 *  ``(type, key)`` headline, a markdown-free excerpt of the
 *  body, and the author / timestamp / revision footer.  Click
 *  anywhere on the card to open the detail sheet.
 */
export function NoteCard({ note, onSelect }: NoteCardProps) {
  return (
    <Card
      data-testid="note-card"
      className="cursor-pointer transition-colors hover:bg-accent/40"
      role="button"
      tabIndex={0}
      onClick={() => onSelect?.(note)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect?.(note);
        }
      }}
    >
      <CardContent className="space-y-2 p-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="font-mono text-xs">
              {note.entity_type}
            </Badge>
            <span
              className="font-mono text-sm font-semibold"
              data-testid="note-card-entity-key"
            >
              {note.entity_key}
            </span>
          </div>
          <span className="text-xs text-muted-foreground">
            rev {note.revision}
          </span>
        </div>
        <p
          className="text-sm text-foreground/80 whitespace-pre-line"
          data-testid="note-card-excerpt"
        >
          {excerpt(note.body)}
        </p>
        <p className="text-xs text-muted-foreground">
          Last updated by{" "}
          <span className="font-medium">{note.updated_by}</span> on{" "}
          {formatTimestamp(note.updated_at)}
        </p>
      </CardContent>
    </Card>
  );
}

/** Strip markdown markers in a minimal way + truncate.  Full
 *  markdown rendering happens in the detail sheet; the listing
 *  shows a plain-text-ish excerpt to keep rows uniform-height
 *  and scannable.  We only remove the most common heading /
 *  emphasis markers and code fences -- not a full markdown
 *  parser -- because a full parse on every row of a large
 *  listing would dominate the render budget. */
function excerpt(body: string): string {
  const trimmed = body
    // Drop fenced code blocks entirely; their content is
    // typically commands / payloads / config dumps that the
    // operator won't recognise without the surrounding prose.
    .replace(/```[\s\S]*?```/g, "")
    // Strip leading ``#``s from headings.
    .replace(/^#{1,6}\s+/gm, "")
    // Strip emphasis markers ``**``/``__``/``*``/``_``/`` ` ``.
    .replace(/[*_`]{1,3}/g, "")
    // Collapse runs of whitespace.
    .replace(/\s+/g, " ")
    .trim();
  if (trimmed.length <= BODY_EXCERPT_CHARS) return trimmed;
  return trimmed.slice(0, BODY_EXCERPT_CHARS).trimEnd() + "…";
}
