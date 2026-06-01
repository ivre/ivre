/**
 * Hooks for the read-side ``/cgi/audit/*`` routes exposed by
 * ``ivre/web/app.py``:
 *
 *   - ``GET /cgi/audit/``                 -- list events,
 *                                            ``limit`` / ``skip``
 *                                            for pagination,
 *                                            optional
 *                                            ``event_type`` /
 *                                            ``user_email`` /
 *                                            ``since`` / ``until``
 *                                            filters
 *   - ``GET /cgi/audit/count``            -- count events matching
 *                                            the same filters
 *   - ``GET /cgi/audit/<event_id>``       -- single event by id
 *
 * The backend gate is admin-or-self: an authenticated non-admin
 * caller only ever sees their own trail (the route ignores or
 * rejects a foreign ``user_email`` filter for them); admins may
 * filter by any email.  Anonymous callers get HTTP 401.
 *
 * All routes are ``@check_referer``-protected; same-origin
 * ``fetch()`` with ``credentials: "same-origin"`` satisfies the
 * Referer check and carries the ``_ivre_session`` cookie.
 */
import {
  useInfiniteQuery,
  useQuery,
  type UseInfiniteQueryResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { CGI_ROOT } from "@/lib/api";

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

/** The three canonical event types
 *  (:attr:`ivre.db.DBAudit.EVENT_TYPES`).  Pinned as a union so
 *  the admin filter UI can render a ``<select>`` against a
 *  closed set instead of free-form text. */
export type AuditEventType = "upload" | "admin_action" | "oversize_query";

export const AUDIT_EVENT_TYPES: readonly AuditEventType[] = [
  "upload",
  "admin_action",
  "oversize_query",
] as const;

/** Audit event as returned by ``GET /cgi/audit/`` and
 *  ``GET /cgi/audit/<event_id>``.  Mirrors the shape the storage
 *  layer persists (every backend reassembles the same key set,
 *  see :class:`ivre.db.mongo.MongoDBAudit.record` /
 *  :class:`ivre.db.sql.tables.AuditEvent`):
 *
 *  - ``event_id`` is the 32-char dashes-less hex form of the
 *    UUID; the storage layer normalises any of the four
 *    textual forms :class:`uuid.UUID` accepts to this form
 *    before insert.
 *  - ``created_at`` is an ISO 8601 string (UTC) emitted by the
 *    backend's :func:`ivre.utils.serialize`.
 *  - ``actor.user_email`` is ``null`` for anonymous / REMOTE_USER-
 *    less callers (e.g. an ``oversize_query`` from an
 *    unauthenticated GET); the per-user index is partial on
 *    PostgreSQL / Mongo so those rows do not bloat the trail
 *    lookup.
 *  - ``details`` is a free-form dict; the schema is per
 *    ``event_type`` (see :class:`ivre.db.DBAudit`).
 */
export interface AuditEvent {
  event_id: string;
  event_type: AuditEventType;
  created_at: string;
  actor: {
    user_email: string | null;
    api_key_hash: string | null;
    remote_addr: string | null;
  };
  resource: {
    route: string | null;
    method: string | null;
  };
  details: Record<string, unknown>;
  outcome: number | string | null;
}

/** Filter set accepted by ``GET /cgi/audit/`` and
 *  ``GET /cgi/audit/count``.  All fields optional; omitted /
 *  empty fields mean "no constraint on that axis". */
export interface AuditFilters {
  event_type?: AuditEventType;
  /** Backend forces this to the caller for non-admins; supplying
   *  a foreign value as a non-admin yields a 403.  Admins may
   *  filter by any user. */
  user_email?: string;
  /** Lower bound on ``created_at`` (inclusive); ISO 8601 string
   *  or Unix timestamp. */
  since?: string;
  /** Upper bound on ``created_at`` (exclusive); same format as
   *  ``since``. */
  until?: string;
}

/* ------------------------------------------------------------------ */
/* datetime-local <-> ISO helpers (Explorer since/until inputs)       */
/* ------------------------------------------------------------------ */

/** Convert an ``<input type="datetime-local">`` value (local
 *  wall-clock, ``YYYY-MM-DDTHH:mm``, no timezone) to a canonical
 *  UTC ISO string for the wire / URL.
 *
 *  The user picks a local time; we send the equivalent UTC
 *  instant.  The backend's ``_parse_audit_datetime`` accepts ISO
 *  with a ``Z`` offset directly, so the comparison aligns with
 *  the UTC-aware ``created_at`` column without any server-side
 *  guessing.  Returns ``undefined`` for an empty / unparseable
 *  value so callers can drop the filter cleanly. */
export function localInputToIso(local: string): string | undefined {
  if (!local) return undefined;
  const d = new Date(local); // parsed in the browser's local zone
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

/** Inverse of :func:`localInputToIso`: render a stored ISO /
 *  timestamp value back into the local ``YYYY-MM-DDTHH:mm`` shape
 *  a ``datetime-local`` input expects.  Returns ``""`` for an
 *  empty / unparseable value. */
export function isoToLocalInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}`
  );
}

/* ------------------------------------------------------------------ */
/* Raw fetchers                                                       */
/* ------------------------------------------------------------------ */

async function ensureOk(response: Response, label: string): Promise<void> {
  if (!response.ok) {
    throw new Error(
      `${label} failed: ${response.status} ${response.statusText}`,
    );
  }
}

/** Build the ``?event_type=...&user_email=...&...`` query string
 *  for the audit routes.  Empty / undefined values are skipped so
 *  the URL stays compact and the request hits the same cache key
 *  as the equivalent omitted-field call. */
function buildAuditQs(
  filters: AuditFilters,
  pagination: { limit?: number; skip?: number } = {},
): string {
  const entries: [string, string][] = [];
  if (filters.event_type) entries.push(["event_type", filters.event_type]);
  if (filters.user_email) entries.push(["user_email", filters.user_email]);
  if (filters.since) entries.push(["since", filters.since]);
  if (filters.until) entries.push(["until", filters.until]);
  if (pagination.limit !== undefined) {
    entries.push(["limit", String(pagination.limit)]);
  }
  if (pagination.skip !== undefined && pagination.skip > 0) {
    entries.push(["skip", String(pagination.skip)]);
  }
  if (entries.length === 0) return "";
  return (
    "?" +
    entries
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&")
  );
}

export async function fetchAuditEvents(
  filters: AuditFilters,
  pagination: { limit?: number; skip?: number } = {},
  signal?: AbortSignal,
): Promise<AuditEvent[]> {
  const url = `${CGI_ROOT}/audit/${buildAuditQs(filters, pagination)}`;
  const r = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(r, `GET ${url}`);
  return (await r.json()) as AuditEvent[];
}

export async function fetchAuditCount(
  filters: AuditFilters,
  signal?: AbortSignal,
): Promise<number> {
  const url = `${CGI_ROOT}/audit/count${buildAuditQs(filters)}`;
  const r = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(r, `GET ${url}`);
  // The backend returns ``"<int>\n"`` -- ``Number()`` trims the
  // trailing newline cleanly and yields ``NaN`` on garbage,
  // which we surface as 0 rather than poison downstream
  // arithmetic.
  const raw = await r.text();
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}

export async function fetchAuditEvent(
  eventId: string,
  signal?: AbortSignal,
): Promise<AuditEvent> {
  const url = `${CGI_ROOT}/audit/${encodeURIComponent(eventId)}`;
  const r = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(r, `GET ${url}`);
  return (await r.json()) as AuditEvent;
}

/* ------------------------------------------------------------------ */
/* React Query hooks                                                  */
/* ------------------------------------------------------------------ */

/** Default page size for the load-more pagination.  Bigger than
 *  the server-side ``WEB_LIMIT`` default (10) to cut roundtrips
 *  for an operator skimming the trail; the server still caps at
 *  ``WEB_MAXRESULTS`` so a deployment can pin a lower ceiling. */
export const AUDIT_PAGE_SIZE = 50;

const AUDIT_EVENTS_KEY = "audit-events" as const;
const AUDIT_COUNT_KEY = "audit-count" as const;

/** Stable query-key projection of an :type:`AuditFilters` value
 *  so equivalent filter dicts share a React Query cache slot
 *  regardless of key ordering / undefined fields. */
function filtersKey(filters: AuditFilters): Readonly<AuditFilters> {
  return {
    event_type: filters.event_type,
    user_email: filters.user_email,
    since: filters.since,
    until: filters.until,
  };
}

/** Infinite query backing the load-more pagination.  Each page
 *  is an ``AuditEvent[]`` of length ``AUDIT_PAGE_SIZE`` (or
 *  shorter on the last page; that's how
 *  :func:`getNextPageParam` detects the end).  Callers flatten
 *  the pages with ``data.pages.flat()`` for rendering. */
export function useAuditEvents(
  filters: AuditFilters,
  options: { enabled?: boolean } = {},
): UseInfiniteQueryResult<{ pages: AuditEvent[][]; pageParams: number[] }, Error> {
  return useInfiniteQuery<
    AuditEvent[],
    Error,
    { pages: AuditEvent[][]; pageParams: number[] },
    readonly [typeof AUDIT_EVENTS_KEY, Readonly<AuditFilters>],
    number
  >({
    queryKey: [AUDIT_EVENTS_KEY, filtersKey(filters)] as const,
    queryFn: ({ pageParam, signal }) =>
      fetchAuditEvents(
        filters,
        { limit: AUDIT_PAGE_SIZE, skip: pageParam },
        signal,
      ),
    initialPageParam: 0,
    getNextPageParam: (lastPage, _allPages, lastPageParam) => {
      // A short page (or empty page) means the server has no
      // more rows beyond this offset.  Otherwise advance the
      // skip by the page size for the next ``Load more`` click.
      if (lastPage.length < AUDIT_PAGE_SIZE) return undefined;
      return lastPageParam + AUDIT_PAGE_SIZE;
    },
    refetchOnWindowFocus: false,
    staleTime: 30_000,
    enabled: options.enabled ?? true,
  });
}

/** Count companion for the same filter dict.  Used by the panel
 *  header (``Showing N of M``); intentionally a separate query so
 *  the count refetches when filters change without forcing a
 *  full page reload. */
export function useAuditCount(
  filters: AuditFilters,
  options: { enabled?: boolean } = {},
): UseQueryResult<number, Error> {
  return useQuery<number, Error>({
    queryKey: [AUDIT_COUNT_KEY, filtersKey(filters)] as const,
    queryFn: ({ signal }) => fetchAuditCount(filters, signal),
    refetchOnWindowFocus: false,
    staleTime: 30_000,
    enabled: options.enabled ?? true,
  });
}

const AUDIT_EVENT_KEY = "audit-event" as const;

/** Single-event lookup backing the Explorer's deep-linkable
 *  detail sheet (``?event=<id>``).  ``eventId`` is the value
 *  from the URL; ``null`` keeps the query disabled (sheet
 *  closed).  The backend's ``GET /cgi/audit/<event_id>``
 *  normalises any UUID textual form, so the raw URL value is
 *  passed through untouched. */
export function useAuditEvent(
  eventId: string | null,
  options: { enabled?: boolean } = {},
): UseQueryResult<AuditEvent, Error> {
  return useQuery<AuditEvent, Error>({
    queryKey: [AUDIT_EVENT_KEY, eventId] as const,
    queryFn: ({ signal }) => fetchAuditEvent(eventId as string, signal),
    refetchOnWindowFocus: false,
    staleTime: 30_000,
    enabled: (options.enabled ?? true) && eventId !== null && eventId !== "",
  });
}
