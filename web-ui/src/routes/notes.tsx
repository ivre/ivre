import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { NoteCard } from "@/components/NoteCard";
import { NoteDetailSheet } from "@/components/NoteDetailSheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useNotes, type Note } from "@/lib/api";
import { getConfig } from "@/lib/config";

/** Per-page default for the Notes Explorer.  Bounded by the
 *  server's ``WEB_MAXRESULTS`` regardless of what we ask for;
 *  matches the value the rest of the SPA uses for list pages
 *  (``WEB_LIMIT`` defaults to 50 on the server, ``dflt_limit``
 *  in ``window.config``). */
const DEFAULT_LIMIT = 50;

/** Known entity types operators can filter on.  ``"all"`` is the
 *  no-filter case (sent as no ``entity_type`` query parameter).
 *  As new entity types ship in the storage layer, add them
 *  here -- the dropdown surfaces them automatically. */
const ENTITY_TYPE_CHOICES: ReadonlyArray<{
  value: string;
  label: string;
}> = [
  { value: "all", label: "All entity types" },
  { value: "host", label: "Host" },
];

/**
 * Notes Explorer: browse + free-text search the per-entity
 * notes the operator team has authored.  The page is reached
 * from the Notes tab in the section nav (the last tab, after
 * Flow).  Hidden on backends that do not implement the notes
 * purpose via the ``WEB_MODULES`` gate in ``ivre/web/modules.py``.
 *
 * Layout: a top filter strip (free-text search + entity-type
 * dropdown + sort) followed by a single-column list of
 * :func:`NoteCard` rows.  Clicking a card opens a
 * :func:`NoteDetailSheet` overlay with the full markdown body
 * and a deep-link to the matching entity's detail page (host
 * detail today; other entity types extend the deep-link switch
 * as their detail routes land).
 *
 * URL state: ``?q=`` (free-text), ``?type=`` (entity type), and
 * ``?addr=`` (selected entity_key for the detail sheet).  The
 * query / type live in the URL so reload + back/forward
 * preserve the operator's search context, and so the page can
 * be shared via permalink.
 */
export function NotesRoute() {
  const config = getConfig();
  const [searchParams, setSearchParams] = useSearchParams();

  const q = searchParams.get("q") ?? "";
  const entityType = searchParams.get("type") ?? "all";
  const limit = config.dflt_limit || DEFAULT_LIMIT;

  // Debounce the search box so we don't spam ``/cgi/notes/``
  // with one request per keystroke.  300 ms matches the
  // FilterBar / FacetSidebar idle thresholds elsewhere in the
  // SPA.
  const [searchInput, setSearchInput] = useState(q);
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchInput === q) return;
      const next = new URLSearchParams(searchParams);
      if (searchInput) next.set("q", searchInput);
      else next.delete("q");
      setSearchParams(next, { replace: true });
    }, 300);
    return () => clearTimeout(timer);
  }, [searchInput, q, searchParams, setSearchParams]);

  // Keep the input synced when the URL changes externally
  // (browser back / link click).  The ``searchInput === q``
  // bailout above prevents the debounce from looping when the
  // URL change came from the input itself.
  useEffect(() => {
    setSearchInput(q);
  }, [q]);

  const setEntityType = (next: string) => {
    const params = new URLSearchParams(searchParams);
    if (next === "all") params.delete("type");
    else params.set("type", next);
    setSearchParams(params, { replace: false });
  };

  const notesQuery = useNotes({
    entityType: entityType === "all" ? undefined : entityType,
    q: q || undefined,
    limit,
  });

  const selectedKey = searchParams.get("addr");
  const selectedNote =
    notesQuery.data?.find(
      (note) =>
        note.entity_key === selectedKey &&
        (entityType === "all" || note.entity_type === entityType),
    ) ?? null;
  const sheetOpen = selectedNote !== null;
  const setSheetOpen = (open: boolean) => {
    if (open) return; // we only ever close from here
    const params = new URLSearchParams(searchParams);
    params.delete("addr");
    setSearchParams(params, { replace: true });
  };
  const onSelectNote = (note: Note) => {
    const params = new URLSearchParams(searchParams);
    params.set("addr", note.entity_key);
    setSearchParams(params, { replace: false });
  };

  return (
    <div className="mx-auto w-full max-w-4xl space-y-4 px-6 py-4">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold">Notes</h1>
        <p className="text-sm text-muted-foreground">
          Browse operator-authored annotations across hosts and
          (eventually) other entity types.  Click a row for the
          full markdown body and a deep link to the matching
          entity.
        </p>
      </header>
      <div
        className="flex flex-wrap items-center gap-2"
        data-testid="notes-explorer-toolbar"
      >
        <Input
          type="search"
          placeholder="Search note bodies…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          className="max-w-sm flex-1"
          aria-label="Search notes"
          data-testid="notes-search-input"
        />
        {/* Native ``<select>`` rather than the shadcn ``Select``
         *  primitive: this control has at most a handful of
         *  options (one per registered entity type; one today),
         *  and the native element brings keyboard / mobile
         *  affordances for free without pulling another
         *  shadcn-managed component into the workspace.  Styled
         *  to roughly match ``<Input>``. */}
        <select
          value={entityType}
          onChange={(e) => setEntityType(e.target.value)}
          aria-label="Entity type filter"
          data-testid="notes-entity-type-select"
          className="h-9 rounded-md border border-input bg-transparent px-3 text-sm shadow-xs"
        >
          {ENTITY_TYPE_CHOICES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </select>
      </div>
      <NotesList query={notesQuery} onSelect={onSelectNote} />
      <NoteDetailSheet
        note={selectedNote}
        open={sheetOpen}
        onOpenChange={setSheetOpen}
      />
    </div>
  );
}

function NotesList({
  query,
  onSelect,
}: {
  query: ReturnType<typeof useNotes>;
  onSelect: (note: Note) => void;
}) {
  if (query.isLoading) {
    return (
      <div
        className="space-y-2"
        role="status"
        aria-label="Loading notes"
        data-testid="notes-list-loading"
      >
        <span className="sr-only">Loading notes…</span>
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="h-20 animate-pulse rounded border border-muted bg-muted/30"
          />
        ))}
      </div>
    );
  }
  if (query.isError) {
    return (
      <div
        className="rounded border border-destructive/40 bg-destructive/10 p-4 text-sm"
        data-testid="notes-list-error"
      >
        <p className="text-destructive">
          Failed to load notes: {(query.error as Error).message}
        </p>
        <Button
          variant="outline"
          size="sm"
          className="mt-2"
          onClick={() => query.refetch()}
        >
          Retry
        </Button>
      </div>
    );
  }
  const notes = query.data ?? [];
  if (notes.length === 0) {
    return (
      <p
        className="rounded border border-dashed border-muted py-12 text-center text-sm italic text-muted-foreground"
        data-testid="notes-list-empty"
      >
        No notes match the current filters.
      </p>
    );
  }
  return (
    <ul
      className="space-y-2"
      data-testid="notes-list"
    >
      {notes.map((note) => (
        <li
          key={`${note.entity_type}-${note.entity_key}`}
          data-testid="notes-list-item"
        >
          <NoteCard note={note} onSelect={onSelect} />
        </li>
      ))}
    </ul>
  );
}
