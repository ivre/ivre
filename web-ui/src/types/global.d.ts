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
