/**
 * Read the IVRE Web UI configuration emitted by the legacy
 * ``/cgi/config`` script.
 *
 * The backend serves ``/cgi/config`` as JavaScript that
 * mutates ``window.config``. Our ``index.html`` loads it via
 * ``<script src="/cgi/config">`` before the React entry, so by the
 * time any component renders, ``window.config`` (if reachable) is
 * populated. The script-tag approach keeps the legacy AngularJS UI
 * and the new React UI on the same source of truth.
 *
 * In dev (no backend): ``window.config`` is ``undefined``; consumers
 * should fall back to defaults.
 */

/** Defaults for the scalar config fields. ``modules`` is
 *  intentionally absent from this default set: an undefined
 *  ``modules`` is the wire-level signal "this server doesn't
 *  emit a module list" — older deployments — and we surface
 *  that as "every section enabled" via :func:`isModuleEnabled`. */
const SCALAR_DEFAULTS: Required<Omit<IvreConfig, "modules">> = {
  notesbase: "",
  dflt_limit: 10,
  warn_dots_count: 20000,
  uploadok: false,
  flow_time_precision: 3600,
  version: "",
  curver: "",
  auth_enabled: false,
  sequential_loading: true,
};

export type ConfigSnapshot = Required<Omit<IvreConfig, "modules">> & {
  /** ``undefined`` for older servers; the section nav treats
   *  that as "all enabled" so older deployments don't lose
   *  their nav. */
  modules?: string[];
};

export function getConfig(): ConfigSnapshot {
  const raw = (typeof window !== "undefined" && window.config) || {};
  return { ...SCALAR_DEFAULTS, ...raw };
}

export function isAuthEnabled(): boolean {
  return getConfig().auth_enabled === true;
}

/** Whether the per-page requests should be issued sequentially
 *  rather than all in parallel. The order is: results → map
 *  (only on sections that declare a ``mapEndpoint``) → facets,
 *  one facet at a time. The timeline is not a gating stage: it
 *  is derived client-side from the already-fetched results
 *  array, so it appears as soon as the results query settles
 *  and never blocks the facet sequence. Defaults to ``true`` so
 *  a server that doesn't emit the field still gets the gentler
 *  request profile.
 *
 *  Scope: the staggering targets the first load of a page and
 *  any query-change cycle. It does not re-serialise background
 *  refetches; today none of the orchestrated query keys have
 *  refetch triggers (see ``routes/host-list.tsx``). */
export function isSequentialLoading(): boolean {
  return getConfig().sequential_loading !== false;
}

/** Return ``true`` when ``id`` is in ``window.config.modules``,
 *  or when ``modules`` is absent (back-compat with older servers
 *  that didn't emit the field). The matching server-side gate is
 *  ``ivre.web.modules.is_module_enabled``; the two are kept in
 *  lockstep so the nav and the routes never disagree. */
export function isModuleEnabled(id: string): boolean {
  const { modules } = getConfig();
  if (modules === undefined) return true;
  return modules.includes(id);
}
