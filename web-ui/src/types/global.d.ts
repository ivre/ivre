/**
 * Globals exposed by the legacy ``/cgi/config`` script tag.
 *
 * The server emits ``var config = { ... }`` at request time; we load
 * it via ``<script src="/cgi/config">`` from ``index.html`` (see the
 * comment there). The new web-ui reads it via ``window.config``.
 */

declare global {
  interface IvreConfig {
    notesbase?: string;
    dflt_limit?: number;
    warn_dots_count?: number;
    uploadok?: boolean;
    flow_time_precision?: number;
    version?: string;
    curver?: string;
    auth_enabled?: boolean;
    /** When ``true`` (the default), the React UI staggers the
     *  per-page requests so the backend never has to answer the
     *  results, the map and every facet at the same time. The
     *  order is: results first, then the map (only on View;
     *  other sections have no separate map request), then each
     *  facet in declared order. The timeline is not a gating
     *  stage — it is rendered client-side from the already-
     *  fetched results array. Set to ``false`` to restore the
     *  legacy "fire everything on mount" behavior.
     *
     *  Scope: the staggering targets the *first load* of each
     *  page and any query-change cycle. Background refetches
     *  are not re-serialised (none of the orchestrated query
     *  keys have refetch triggers today; see
     *  ``routes/host-list.tsx`` for the longer rationale). */
    sequential_loading?: boolean;
    /** Data sections this server exposes; intersection of
     *  ``WEB_MODULES`` and the configured ``DB_<purpose>``
     *  backends. ``undefined`` means "older server that does
     *  not emit this field" — the React UI treats the absence
     *  as "every section enabled" so legacy bundles keep
     *  rendering as before. */
    modules?: string[];
  }

  interface Window {
    config?: IvreConfig;
  }
}

export {};
