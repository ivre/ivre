import MDEditor from "@uiw/react-md-editor";
import { Loader2, PencilLine, Plus, Trash2 } from "lucide-react";
import { useTheme } from "next-themes";
import { useState } from "react";
import { toast } from "sonner";

import { NoteMarkdownBody } from "@/components/NoteMarkdownBody";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  useDeleteHostNote,
  useHostNote,
  useHostNoteRevisions,
  useSaveHostNote,
  type Note,
  type NoteRevision,
  type SaveHostNoteResult,
} from "@/lib/api";
import { useAuthMe } from "@/lib/auth";
import { formatQueryError, formatTimestamp } from "@/lib/format";

export interface HostNotesPanelProps {
  /** Caller-facing host address (printable IP string) used as the
   *  ``entity_key`` against ``/cgi/notes/host/<addr>``. */
  addr: string;
}

/**
 * Editable display of the markdown note attached to a host.
 *
 * Drops into the host detail sheet as a self-contained section --
 * the component renders its own ``<section>`` wrapper + heading
 * so it can ``return null`` entirely when the server reports the
 * notes backend is unavailable (HTTP 501).
 *
 * Three modes the operator transitions between:
 *
 * * **viewing** -- the rendered markdown + footer + edit / delete
 *   / history affordances (each auth-gated; an anonymous viewer
 *   sees the rendered note but no write controls).
 * * **editing** -- a ``@uiw/react-md-editor`` instance with
 *   live preview, plus Save / Cancel buttons.  Used for both
 *   create (``If-None-Match: *``) and update
 *   (``If-Match: <revision>``) paths; the mode is driven by
 *   whether the loaded note exists.
 * * **conflict** -- transient overlay shown when the storage
 *   layer rejects the save with HTTP 409
 *   (``NoteConcurrencyError`` / ``NoteAlreadyExists``).  Two
 *   buttons: "Keep editing" dismisses the dialog so the
 *   operator can refine the draft and retry; "Reload latest
 *   version" copies the pending draft to the clipboard (so
 *   it can be pasted back to merge against the latest body),
 *   then triggers a refetch of the underlying ``useHostNote``
 *   query.  The editor's ``key`` is driven by
 *   ``existingNote.revision`` so the refetched note remounts
 *   the editor with the latest body as the new draft
 *   baseline.  There is *no* "overwrite anyway / LWW" button;
 *   that path was considered then dropped -- the optimistic
 *   concurrency contract is the point of the dialog.
 *
 * Read-mode security / a11y hardenings (image-fetch suppression,
 * ``rel="noopener noreferrer"`` on links, markdown heading-level
 * remap, GFM table overflow containment) are owned by
 * :func:`NoteMarkdownBody` -- the shared renderer reused by
 * every read-only notes consumer in the SPA.
 */
export function HostNotesPanel({ addr }: HostNotesPanelProps) {
  const query = useHostNote(addr);

  // Hide the whole section when the backend has no notes
  // implementation (HTTP 501).  Deployments that intentionally
  // have no notes backend (Postgres, etc.) get a clean detail
  // sheet with no permanent warning chrome.
  if (query.data?.kind === "unavailable") {
    return null;
  }

  return (
    <section data-testid="host-notes-section">
      <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
        Notes
      </h3>
      <HostNotesBody addr={addr} query={query} />
    </section>
  );
}

function HostNotesBody({
  addr,
  query,
}: {
  addr: string;
  query: ReturnType<typeof useHostNote>;
}) {
  // Auth gate.  Write affordances are hidden when the operator is
  // not authenticated -- the route would 401 the call anyway but
  // surfacing the buttons would be misleading.  ``useAuthMe``
  // returns ``authenticated: false`` cleanly when auth is
  // disabled or the user is anonymous, so the check is uniform.
  const meQuery = useAuthMe();
  const canEdit = Boolean(meQuery.data?.authenticated);

  const [isEditing, setIsEditing] = useState(false);

  if (query.isLoading) {
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
        Failed to load note: {formatQueryError(query.error)}
      </p>
    );
  }

  const result = query.data;

  if (isEditing) {
    // Editing branch covers both create (no existing note) and
    // update (existing note).  ``NoteEditor`` decides the save
    // mode based on whether ``existingNote`` is non-null.
    //
    // The ``key`` is driven by the loaded note's revision so a
    // conflict-triggered refetch (see ``NoteEditor``'s
    // ``onReloadLatest``) forces a fresh editor instance whose
    // ``draft`` reinitialises from the new ``existingNote.body``.
    // Without this, ``draft`` is local state that would survive
    // the refetch and keep the operator's stale text.
    const existingNote =
      result?.kind === "found" ? result.note : null;
    return (
      <NoteEditor
        key={existingNote?.revision ?? "new"}
        addr={addr}
        existingNote={existingNote}
        onCancel={() => setIsEditing(false)}
        onSaved={() => setIsEditing(false)}
        onReloadNote={() => query.refetch()}
      />
    );
  }

  if (!result || result.kind === "absent") {
    return (
      <EmptyState
        canEdit={canEdit}
        onAddClick={() => setIsEditing(true)}
      />
    );
  }

  // ``unavailable`` was handled above.
  if (result.kind !== "found") {
    return null;
  }

  return (
    <NoteDisplay
      note={result.note}
      addr={addr}
      canEdit={canEdit}
      onEditClick={() => setIsEditing(true)}
    />
  );
}

/* ------------------------------------------------------------------ */
/* Empty state                                                         */
/* ------------------------------------------------------------------ */

function EmptyState({
  canEdit,
  onAddClick,
}: {
  canEdit: boolean;
  onAddClick: () => void;
}) {
  return (
    <div
      className="flex items-center justify-between gap-2"
      data-testid="host-notes-empty"
    >
      <p className="text-sm italic text-muted-foreground">
        No notes for this host yet.
      </p>
      {canEdit ? (
        <Button
          size="sm"
          variant="outline"
          onClick={onAddClick}
          data-testid="host-notes-add-button"
        >
          <Plus className="mr-1 h-3 w-3" />
          Add note
        </Button>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Read-mode display                                                   */
/* ------------------------------------------------------------------ */

function NoteDisplay({
  note,
  addr,
  canEdit,
  onEditClick,
}: {
  note: Note;
  addr: string;
  canEdit: boolean;
  onEditClick: () => void;
}) {
  const [showHistory, setShowHistory] = useState(false);
  const deleteMutation = useDeleteHostNote(addr);

  const onDelete = () => {
    // Confirm deletion via the native ``confirm`` dialog rather
    // than a custom modal -- this is an operator-rare action and
    // the simpler UX matches the destructiveness.
    if (
      !window.confirm(
        `Delete the note for ${addr}? The full revision history will be removed too.`,
      )
    ) {
      return;
    }
    deleteMutation.mutate(undefined, {
      onSuccess: (existed) => {
        if (existed) {
          toast.success("Note deleted");
        } else {
          // Either someone beat us to the delete or the route
          // changed under us.  The query invalidation in the
          // mutation hook will re-fetch and show the empty
          // state regardless.
          toast.info("Note was already absent");
        }
      },
      onError: (err) => {
        toast.error(`Delete failed: ${err.message}`);
      },
    });
  };

  return (
    <div data-testid="host-notes-content">
      <NoteMarkdownBody body={note.body} />
      <div className="mt-3 flex items-center justify-between gap-2">
        <p className="text-xs text-muted-foreground">
          Last updated by{" "}
          <span className="font-medium">{note.updated_by}</span> on{" "}
          {formatTimestamp(note.updated_at)} (rev {note.revision})
        </p>
        {canEdit ? (
          <div className="flex shrink-0 gap-1">
            <Button
              size="sm"
              variant="outline"
              onClick={onEditClick}
              data-testid="host-notes-edit-button"
            >
              <PencilLine className="mr-1 h-3 w-3" />
              Edit
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={onDelete}
              disabled={deleteMutation.isPending}
              data-testid="host-notes-delete-button"
            >
              <Trash2 className="mr-1 h-3 w-3" />
              Delete
            </Button>
          </div>
        ) : null}
      </div>
      <RevisionsExpander
        addr={addr}
        currentRevision={note.revision}
        open={showHistory}
        onOpenChange={setShowHistory}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Revision history                                                    */
/* ------------------------------------------------------------------ */

function RevisionsExpander({
  addr,
  currentRevision,
  open,
  onOpenChange,
}: {
  addr: string;
  currentRevision: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  // Defer the revisions fetch until the operator actually
  // expands the section (``enabled: open``).  Once the fetch
  // has settled, the trigger label below prefers
  // ``revisionsQuery.data.length`` as the authoritative count
  // and falls back to ``currentRevision`` as a proxy until
  // then.  The proxy is correct only while no revisions are
  // pruned or gapped, which holds under the current storage
  // protocol: ``set_note`` only does ``$inc: {revision: 1}``
  // on every write, and ``delete_note`` sweeps the entire
  // audit log along with the parent.  So revision N today
  // means N revisions exist.  A future feature introducing
  // revision pruning, TTL on old revisions, or rollback /
  // gap-creating semantics would break the proxy, but the
  // ``data?.length ?? currentRevision`` fallback would
  // self-correct as soon as the operator opened the
  // expander.
  const revisionsQuery = useHostNoteRevisions(addr, {
    enabled: open,
  });
  const revisionCount = revisionsQuery.data?.length ?? currentRevision;
  return (
    <Collapsible
      open={open}
      onOpenChange={onOpenChange}
      className="mt-2"
    >
      <CollapsibleTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs text-muted-foreground"
          data-testid="host-notes-history-toggle"
        >
          {open
            ? "Hide history"
            : `History (${revisionCount} revision${revisionCount === 1 ? "" : "s"})`}
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <RevisionsList query={revisionsQuery} />
      </CollapsibleContent>
    </Collapsible>
  );
}

function RevisionsList({
  query,
}: {
  query: ReturnType<typeof useHostNoteRevisions>;
}) {
  if (query.isLoading) {
    return (
      <p
        className="mt-2 text-xs italic text-muted-foreground"
        role="status"
      >
        Loading revisions…
      </p>
    );
  }
  if (query.isError) {
    return (
      <p className="mt-2 text-xs text-destructive">
        Failed to load history: {formatQueryError(query.error)}
      </p>
    );
  }
  const revisions = query.data ?? [];
  if (revisions.length === 0) {
    return (
      <p className="mt-2 text-xs italic text-muted-foreground">
        No revisions recorded.
      </p>
    );
  }
  return (
    <ol
      className="mt-2 space-y-2 border-l-2 border-muted pl-3"
      data-testid="host-notes-history-list"
    >
      {revisions.map((rev) => (
        <RevisionItem key={rev.revision} revision={rev} />
      ))}
    </ol>
  );
}

function RevisionItem({ revision }: { revision: NoteRevision }) {
  const [open, setOpen] = useState(false);
  return (
    <li>
      <Collapsible open={open} onOpenChange={setOpen}>
        <CollapsibleTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="h-auto justify-start p-1 text-xs"
          >
            <span className="font-mono text-muted-foreground">
              rev {revision.revision}
            </span>
            <span className="ml-2 text-muted-foreground">
              by {revision.created_by} on{" "}
              {formatTimestamp(revision.created_at)}
            </span>
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="mt-1 rounded border border-muted bg-muted/40 p-2">
            <NoteMarkdownBody body={revision.body} />
          </div>
        </CollapsibleContent>
      </Collapsible>
    </li>
  );
}

/* ------------------------------------------------------------------ */
/* Editor                                                              */
/* ------------------------------------------------------------------ */

function NoteEditor({
  addr,
  existingNote,
  onCancel,
  onSaved,
  onReloadNote,
}: {
  addr: string;
  existingNote: Note | null;
  onCancel: () => void;
  onSaved: () => void;
  /** Trigger a refetch of the underlying ``useHostNote`` query.
   *  Returns a promise that resolves once the new note has
   *  arrived.  The parent passes ``query.refetch`` here; the
   *  editor calls it from the conflict-dialog reload path. */
  onReloadNote: () => Promise<unknown>;
}) {
  const [draft, setDraft] = useState(existingNote?.body ?? "");
  const [conflict, setConflict] = useState<{
    message: string;
    pendingBody: string;
  } | null>(null);
  const saveMutation = useSaveHostNote(addr);
  // ``@uiw/react-md-editor`` reads ``data-color-mode`` off the
  // nearest ancestor to pick its dark/light skin.  Mirror the
  // resolved next-themes value onto a wrapping div so the
  // editor blends with the rest of the SPA's theme rather than
  // defaulting to whatever the system colour scheme is.
  const { resolvedTheme } = useTheme();

  const submit = (body: string) => {
    const mode = existingNote
      ? {
          kind: "update" as const,
          expectedRevision: existingNote.revision,
        }
      : { kind: "create" as const };
    saveMutation.mutate(
      { body, mode },
      {
        onSuccess: (result: SaveHostNoteResult) => {
          if (result.kind === "saved") {
            toast.success(
              existingNote ? "Note updated" : "Note created",
            );
            onSaved();
            return;
          }
          if (result.kind === "conflict") {
            // Keep the operator's draft in scope so the
            // ``onReloadLatest`` path in the conflict dialog
            // can write it to the clipboard before triggering
            // the refetch.
            setConflict({ message: result.message, pendingBody: body });
            return;
          }
          if (result.kind === "unauthorized") {
            toast.error("Sign in to save notes");
            return;
          }
          if (result.kind === "too_large") {
            toast.error("Note body is too large");
            return;
          }
          if (result.kind === "not_found") {
            // The note was deleted between load and save.
            // Mirror the conflict-reload path: preserve the
            // operator's pending body to the clipboard, then
            // refetch the query so the parent re-renders with
            // ``existingNote = null``.  The parent's
            // ``key={existingNote?.revision ?? "new"}`` will
            // flip the editor's identity, remounting it in
            // create mode with an empty ``draft``; the next
            // Save naturally uses ``If-None-Match: *``.  The
            // editor stays open so the operator can paste
            // back without an extra "Add note" click.  Errors
            // (no clipboard, refetch failure) surface via
            // toast; we fire-and-forget here because the
            // ``onSuccess`` callback itself is synchronous.
            void handleNotFound(body);
            return;
          }
        },
        onError: (err) => {
          toast.error(`Save failed: ${err.message}`);
        },
      },
    );
  };

  const handleNotFound = async (pendingBody: string) => {
    // Preserve the operator's pending edits via the clipboard
    // so they can paste back to recreate the note after the
    // refetch lands.  Same shape as :func:`onReloadLatest`'s
    // clipboard step (insecure-context / permission-denied
    // surfaces as a warning toast rather than blocking the
    // refetch).
    try {
      await navigator.clipboard.writeText(pendingBody);
      toast.error(
        "The note was deleted while you were editing.  " +
          "Your edits were copied to the clipboard; paste to recreate.",
      );
    } catch {
      toast.error(
        "The note was deleted while you were editing.  " +
          "Your in-editor draft will be lost on reload.",
      );
    }
    // Refetch so the parent's ``existingNote`` becomes
    // ``null``; the ``key`` change then remounts the editor
    // in create mode (empty ``draft``).  Errors here surface
    // via React Query's regular error path on the next
    // ``useHostNote`` consumer.
    await onReloadNote();
  };

  const onReloadLatest = async () => {
    if (!conflict) return;
    const pendingBody = conflict.pendingBody;
    // Close the dialog immediately so the operator sees the
    // reload in motion.  If the refetch ends up returning the
    // same revision (race resolved itself), the editor stays
    // mounted with the user's draft intact and they can save
    // again.  Otherwise, the parent's ``key`` (driven by
    // ``existingNote.revision``) trips a remount and the
    // editor reinitialises from the latest body.
    setConflict(null);
    // Preserve the operator's pending edits via the clipboard
    // so they can paste them back to merge against the latest
    // body.  ``navigator.clipboard.writeText`` requires a
    // secure context and an active user gesture; both hold
    // here (the click that opened the dialog is still the
    // active gesture).  Failure (insecure HTTP, permissions
    // denied) is surfaced as a warning toast rather than
    // blocking the refetch -- the operator still gets the
    // latest body; they just lose their unsaved draft.
    try {
      await navigator.clipboard.writeText(pendingBody);
      toast.info(
        "Your edits were copied to the clipboard; paste to merge.",
      );
    } catch {
      toast.warning(
        "Could not access clipboard; your in-editor draft will be lost on reload.",
      );
    }
    await onReloadNote();
  };

  return (
    <div data-testid="host-notes-editor" data-color-mode={resolvedTheme}>
      {/* Explicit ``<label htmlFor>`` so the editor's textarea
       *  has a programmatic accessible name regardless of
       *  whether ``@uiw/react-md-editor`` forwards
       *  ``textareaProps.aria-label`` to the inner ``<textarea>``
       *  in a given library version.  The ``sr-only`` class
       *  hides the label visually (the editor's toolbar /
       *  placeholder convey the affordance in the sighted UI).
       *  ``aria-label`` stays in ``textareaProps`` as
       *  redundancy. */}
      <label htmlFor="host-notes-body-textarea" className="sr-only">
        Note body
      </label>
      <MDEditor
        value={draft}
        onChange={(val) => setDraft(val ?? "")}
        // ``preview="live"`` shows editor + rendered preview
        // side-by-side.  Use the editor's built-in preview here
        // rather than our ``NoteMarkdownBody`` -- the editor's
        // textarea and toolbar are tightly coupled to its own
        // preview pane; swapping in a custom preview component
        // is non-trivial without losing the toolbar shortcuts.
        // The read-mode display below still uses
        // ``NoteMarkdownBody``.
        preview="live"
        height={300}
        textareaProps={{
          id: "host-notes-body-textarea",
          placeholder:
            "Markdown supported. Editing is private to your session until you Save.",
          "aria-label": "Note body",
        }}
      />
      <div className="mt-3 flex items-center justify-end gap-2">
        <Button
          size="sm"
          variant="outline"
          onClick={onCancel}
          disabled={saveMutation.isPending}
          data-testid="host-notes-cancel-button"
        >
          Cancel
        </Button>
        <Button
          size="sm"
          onClick={() => submit(draft)}
          disabled={saveMutation.isPending}
          data-testid="host-notes-save-button"
        >
          {saveMutation.isPending ? (
            <>
              <Loader2 className="mr-1 h-3 w-3 animate-spin" />
              Saving…
            </>
          ) : (
            "Save"
          )}
        </Button>
      </div>
      <ConflictDialog
        conflict={conflict}
        onClose={() => setConflict(null)}
        onReload={onReloadLatest}
      />
    </div>
  );
}

function ConflictDialog({
  conflict,
  onClose,
  onReload,
}: {
  conflict: { message: string; pendingBody: string } | null;
  onClose: () => void;
  onReload: () => void;
}) {
  return (
    <Dialog open={conflict !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent data-testid="host-notes-conflict-dialog">
        <DialogHeader>
          <DialogTitle>Note was modified elsewhere</DialogTitle>
          <DialogDescription>
            Another user or tab modified this note while you were
            editing.  The server rejected the save to prevent an
            accidental overwrite.
          </DialogDescription>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          Server message:{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">
            {conflict?.message ?? ""}
          </code>
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Keep editing
          </Button>
          <Button onClick={onReload}>
            Reload latest version
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}


