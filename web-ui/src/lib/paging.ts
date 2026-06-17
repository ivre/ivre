/**
 * Pagination helpers for the host-list result pages.
 *
 * IVRE's Web API does not honour standalone ``skip=`` / ``limit=``
 * URL parameters on the host-list routes: ``query_from_params``
 * consumes only ``q=`` and ``flt_from_query`` extracts ``skip`` /
 * ``limit`` from *within* the query string (see
 * ``ivre/web/utils.py``). Paginated fetches therefore have to fold
 * the window into ``q=`` as the ``limit:N`` / ``skip:N`` meta-tokens
 * rather than passing them alongside it.
 */

/** Parse an integer URL search param, falling back to ``fallback``
 *  when it is absent, non-numeric, or below ``min`` (default ``0``).
 *  A value ``>= min`` is returned unchanged.
 *
 *  Unifies the "sanitise a URL-supplied int" idiom used for ``limit``
 *  (``min: 1`` -- a non-positive page size falls back to the default)
 *  and ``skip`` (``min: 0`` -- a negative offset clamps to 0). */
export function parseUrlInt(
  params: URLSearchParams,
  key: string,
  { min = 0, fallback }: { min?: number; fallback: number },
): number {
  const raw = Number.parseInt(params.get(key) ?? "", 10);
  return Number.isNaN(raw) || raw < min ? fallback : raw;
}

/** Append the ``limit:N`` / ``skip:N`` meta-tokens to a filter query
 *  so the backend returns the requested result window.
 *
 *  ``skip:0`` is omitted (the default), keeping the shared URL and
 *  the request as short as possible for the common first-page case. */
export function buildPagedQuery(
  query: string,
  limit: number,
  skip: number,
): string {
  return [query, `limit:${limit}`, skip > 0 ? `skip:${skip}` : ""]
    .filter(Boolean)
    .join(" ");
}

export interface PaginationInput {
  /** Number of records returned for the current page. */
  loaded: number;
  /** Requested page size (the ``limit:N`` meta-token). */
  limit: number;
  /** Offset of the current page (the ``skip:N`` meta-token). */
  skip: number;
  /** Total number of records matching the unpaginated query, when
   *  the section exposes a ``/count`` companion. ``undefined`` when
   *  the total is unknown. */
  total?: number;
}

export interface PaginationBounds {
  /** 1-based index of the first record shown (``skip + 1``). */
  first: number;
  /** 1-based index of the last record shown (``skip + loaded``). */
  last: number;
  /** ``true`` on the first page (no previous page). */
  atStart: boolean;
  /** ``true`` on the last page (no next page). When ``total`` is
   *  unknown this is inferred from a short/empty final page. */
  atEnd: boolean;
  /** ``skip`` value for the last page. Falls back to ``0`` when the
   *  total is unknown or zero (the "Last" control is disabled in
   *  that case). */
  lastSkip: number;
}

/** Derive the display bounds and navigation state for a result page.
 *
 *  When ``total`` is known the bounds are exact. When it is not
 *  (sections without a ``/count`` companion), ``atEnd`` is inferred:
 *  a page returning fewer rows than ``limit`` — or no rows at all —
 *  is the last one. */
export function computePagination({
  loaded,
  limit,
  skip,
  total,
}: PaginationInput): PaginationBounds {
  // Guard the division below against a non-positive limit (which would
  // yield Infinity/NaN for lastSkip). Callers sanitise limit, but this
  // is an exported helper and must stay well-defined on its own.
  const safeLimit = limit > 0 ? Math.floor(limit) : 1;
  const first = skip + 1;
  const last = skip + loaded;
  const atStart = skip === 0;
  const atEnd =
    total !== undefined ? last >= total : loaded < safeLimit || loaded === 0;
  const lastSkip =
    total === undefined || total === 0
      ? 0
      : Math.floor((total - 1) / safeLimit) * safeLimit;
  return { first, last, atStart, atEnd, lastSkip };
}
