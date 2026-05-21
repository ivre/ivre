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

/** Upper bound on how many characters of the raw body are
 *  processed by the regex chain.  Note bodies can be up to
 *  ``WEB_HOST_NOTES_MAX_BYTES`` (1 MiB by default); scanning
 *  the full body for every row on a page of results would
 *  waste CPU proportional to body size, not excerpt size.
 *  4 KiB is enough to produce a 240-character excerpt even
 *  when the body starts with a large code block or dense
 *  heading section.  The actual display limit is
 *  ``BODY_EXCERPT_CHARS`` (240 chars); this cap just
 *  prevents the regex chain from scanning megabytes it will
 *  never surface. */
const EXCERPT_INPUT_CHARS = 4096;

/** Strip markdown markers in a minimal way + truncate.  Full
 *  markdown rendering happens in the detail sheet; the listing
 *  shows a plain-text-ish excerpt to keep rows uniform-height
 *  and scannable.  We only remove the most common heading /
 *  emphasis markers and code fences -- not a full markdown
 *  parser -- because a full parse on every row of a large
 *  listing would dominate the render budget.
 *
 *  Emphasis stripping is paired-only so literal occurrences of
 *  ``*``, ``_`` and ``` ` ``` inside operator text survive
 *  (e.g. token names like ``CVE_2026_1234``, glob-ish snippets
 *  like ``foo*bar``).  A previous version used a blanket
 *  ``/[*_`]{1,3}/g`` strip which mangled those into
 *  ``CVE20261234`` / ``foobar``.  The replacements below mirror
 *  the CommonMark rule that emphasis runs come in matched
 *  delimiter pairs around their content, with the additional
 *  guard that ``_`` between alphanumerics never opens or
 *  closes emphasis. */
function excerpt(body: string): string {
  const trimmed = body.slice(0, EXCERPT_INPUT_CHARS)
    // Drop fenced code blocks entirely; their content is
    // typically commands / payloads / config dumps that the
    // operator won't recognise without the surrounding prose.
    .replace(/```[\s\S]*?```/g, "")
    // Strip leading ``#``s from headings.
    .replace(/^#{1,6}\s+/gm, "")
    // Code spans first (`` `text` ``): the inner text may
    // contain ``*`` / ``_`` we want to keep, and the emphasis
    // passes below must not look inside the span.  The regex
    // matches a run of N backticks, the smallest possible
    // run of non-backtick characters, then the same N
    // backticks again (``\1`` back-reference) -- which
    // unwraps both `` `text` `` and `` ``text`` ``.  The
    // ``[^`]+?`` capture intentionally forbids literal
    // backticks inside the span content: the CommonMark
    // ``` `` `a` `` ``` corner case (an embedded backtick
    // surrounded by N>=2 fence backticks) lands on the next
    // emphasis pass with its ``` `` ``` markers intact rather
    // than being unwrapped, which is acceptable for a
    // listing-row excerpt where operators rarely paste raw
    // backtick characters.  Switch to a full markdown parser
    // if that ever stops being the case.
    .replace(/(`+)([^`]+?)\1/g, "$2")
    // Strong emphasis: ``**text**`` / ``__text__``.  Lazy
    // match so two adjacent runs on the same line don't get
    // glued together by a greedy capture.
    .replace(/(\*\*|__)(?=\S)([\s\S]+?\S)\1/g, "$2")
    // Em emphasis with ``*``: paired and non-empty, no
    // intraword constraint (CommonMark allows ``foo*bar*baz``).
    .replace(/\*(?=\S)([^*\n]+?\S)\*/g, "$1")
    // Em emphasis with ``_``: same shape, but the opening /
    // closing ``_`` must not sit between two alphanumerics
    // (CommonMark's intraword-underscore rule, the one that
    // keeps ``CVE_2026_1234`` from being parsed as emphasis).
    .replace(
      /(^|[^A-Za-z0-9_])_(?=\S)([^_\n]+?\S)_(?![A-Za-z0-9_])/g,
      "$1$2",
    )
    // Collapse runs of whitespace.
    .replace(/\s+/g, " ")
    .trim();
  if (trimmed.length <= BODY_EXCERPT_CHARS) return trimmed;
  return trimmed.slice(0, BODY_EXCERPT_CHARS).trimEnd() + "…";
}
