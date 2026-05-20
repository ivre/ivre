import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";

import { NoteCard } from "@/components/NoteCard";
import { NoteDetailSheet } from "@/components/NoteDetailSheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useHostNote, useNotes, type Note } from "@/lib/api";
import { getConfig } from "@/lib/config";

/** SPA-side fallback for the per-page limit, used only when
 *  ``window.config.dflt_limit`` is missing or zero (i.e. an
 *  older server that does not emit the field).  Matches the
 *  ``config.dflt_limit || 50`` pattern used by every other
 *  section route (``host-list.tsx``, ``rir.tsx``,
 *  ``passive-list.tsx``, ``dns.tsx``) -- not the server's
 *  ``WEB_LIMIT`` default (10, see ``ivre/config.py``).
 *  Always bounded server-side by ``WEB_MAXRESULTS`` regardless
 *  of what we ask for. */
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
 * dropdown) followed by a single-column list of
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
 *
 * Deep-link robustness: ``?addr=`` resolves first against the
 * current listing page (fast path: row click in the same view);
 * on miss, the route falls back to a per-entity single-note
 * fetch (today: :func:`useHostNote` for ``host`` entities) so a
 * link to a note outside the current ``limit`` window or
 * filtered out by ``q`` / ``type`` still opens the sheet.  If
 * the fallback fetch resolves to ``absent`` / ``unavailable``
 * the route drops ``?addr=`` and surfaces a toast rather than
 * leaving the sheet silently closed.
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
  // Fast path: the targeted note is already on the current
  // listing page -- use it without an extra request so an
  // in-page row click opens the sheet instantly.
  const listSelectedNote =
    notesQuery.data?.find(
      (note) =>
        note.entity_key === selectedKey &&
        (entityType === "all" || note.entity_type === entityType),
    ) ?? null;
  // Fallback path: a deep link can point at a note outside the
  // current ``limit`` window, or filtered out by ``q`` /
  // ``type``.  Without a backup fetch, ``/notes?addr=...`` would
  // silently leave the sheet closed.  Today the only entity
  // type with a single-note endpoint wired is ``host``; the
  // gate matches what the per-entity deep-link switch in
  // :func:`NoteDetailSheet` supports.  When the list already
  // carries the match, we keep the query disabled so we don't
  // hit the network for nothing.
  const hostLookupEnabled =
    selectedKey !== null &&
    listSelectedNote === null &&
    (entityType === "all" || entityType === "host");
  const fallbackQuery = useHostNote(
    hostLookupEnabled ? selectedKey ?? undefined : undefined,
    { enabled: hostLookupEnabled },
  );
  const fallbackNote =
    fallbackQuery.data?.kind === "found" ? fallbackQuery.data.note : null;
  const selectedNote = listSelectedNote ?? fallbackNote;
  // Stale-link handling: the deep link points at a key that
  // does not exist (404), whose backend is not wired (501),
  // or whose fetch failed outright (network error / 5xx /
  // malformed JSON -- ``react-query`` surfaces these as
  // ``isError`` rather than a discriminated ``kind``).  In
  // all three cases we drop ``?addr=`` from the URL so the
  // operator doesn't end up stuck with a permanently-closed
  // sheet, and surface a toast so the failure is visible.
  useEffect(() => {
    if (!hostLookupEnabled) return;
    if (fallbackQuery.isLoading) return;
    if (fallbackNote !== null) return;
    const kind = fallbackQuery.data?.kind;
    const isError = fallbackQuery.isError;
    if (kind !== "absent" && kind !== "unavailable" && !isError) return;
    const params = new URLSearchParams(searchParams);
    params.delete("addr");
    setSearchParams(params, { replace: true });
    let message: string;
    if (isError) {
      // ``react-query`` types ``error`` as ``Error | null``;
      // we land here only when ``isError`` is true so the
      // ``message`` access is safe, but guard against a
      // shape-only test stub that leaves ``error`` unset.
      const errMsg = fallbackQuery.error?.message ?? "request failed";
      message = `Could not load note for ${selectedKey}: ${errMsg}`;
    } else if (kind === "absent") {
      message = `No note for ${selectedKey}; link is stale.`;
    } else {
      message = "Notes backend is not available on this server.";
    }
    toast.error(message);
  }, [
    hostLookupEnabled,
    fallbackQuery.isLoading,
    fallbackQuery.isError,
    fallbackQuery.error,
    fallbackQuery.data,
    fallbackNote,
    searchParams,
    setSearchParams,
    selectedKey,
  ]);
  // No-fallback cleanup: the deep link points at a key the
  // current list page does not carry AND no per-entity
  // fallback fetch is wired for the current ``entityType``.
  // The most common trigger is a crafted URL whose ``type=``
  // is a not-yet-supported entity type (today, anything
  // other than ``all`` / ``host``); future entity types
  // will lift the gate as their single-note hooks land.
  // Without this cleanup the URL keeps ``addr=`` while the
  // sheet stays permanently closed, with no UI affordance to
  // clear it.  We wait for ``notesQuery`` to settle so a
  // race against the initial load can still resolve the key
  // via the fast path before we drop it.
  useEffect(() => {
    if (selectedKey === null) return;
    if (listSelectedNote !== null) return;
    if (hostLookupEnabled) return; // handled by the effect above
    if (notesQuery.isLoading) return;
    const params = new URLSearchParams(searchParams);
    params.delete("addr");
    setSearchParams(params, { replace: true });
    toast.error(
      `No note for ${selectedKey} under the current filters; link cleared.`,
    );
  }, [
    selectedKey,
    listSelectedNote,
    hostLookupEnabled,
    notesQuery.isLoading,
    searchParams,
    setSearchParams,
  ]);
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
