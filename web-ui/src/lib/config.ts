/**
 * Read the IVRE Web UI configuration emitted by the legacy
 * ``/cgi/config`` script.
 *
 * The legacy backend serves ``/cgi/config`` as JavaScript that
 * mutates ``window.config``. Our ``index.html`` loads it via
 * ``<script src="/cgi/config">`` before the React entry, so by the
 * time any component renders, ``window.config`` (if reachable) is
 * populated. The script-tag approach keeps the legacy AngularJS UI
 * and the new React UI on the same source of truth.
 *
 * In dev (no backend): ``window.config`` is ``undefined``; consumers
 * should fall back to defaults.
 */

const DEFAULTS: Required<IvreConfig> = {
  notesbase: "",
  dflt_limit: 10,
  warn_dots_count: 20000,
  uploadok: false,
  flow_time_precision: 3600,
  version: "",
  curver: "",
  auth_enabled: false,
};

export function getConfig(): Required<IvreConfig> {
  const raw = (typeof window !== "undefined" && window.config) || {};
  return { ...DEFAULTS, ...raw };
}

export function isAuthEnabled(): boolean {
  return getConfig().auth_enabled === true;
}
