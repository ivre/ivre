/**
 * IVRE filter language: parsing, building, and serialisation.
 *
 * Filters travel between the client and the IVRE Web API as a flat
 * space-separated string in the ``q`` query parameter (e.g.
 * ``country:FR port:tcp/443 "tag:CDN:Cloudflare"``). This matches
 * the legacy AngularJS UI and IVRE's existing ``ivre/web/utils.py``
 * request-to-DB-filter translation.
 *
 * The grammar is intentionally simple: each whitespace-separated
 * token is either ``type:value`` or a bare ``value`` (anonymous
 * filter, e.g. ``tcp/80``, ``1.2.3.4/24``). Values that contain
 * spaces, colons, or quotes are double-quoted with backslash escape.
 */

export interface Filter {
  /** Filter type prefix (e.g. ``country``, ``port``, ``tag``).
   *  ``undefined`` means an anonymous filter — the value travels as
   *  a bare token. */
  type?: string;
  /** Filter value, unquoted. */
  value: string;
  /** Negation. Renders as ``!type:value`` or ``-type:value``. */
  neg?: boolean;
}

const NEEDS_QUOTING = /[\s":]/;

/**
 * Quote a value if it contains whitespace, a colon, or a quote.
 * Embedded double quotes are backslash-escaped.
 */
export function quoteValue(value: string): string {
  if (!NEEDS_QUOTING.test(value)) {
    return value;
  }
  return `"${value.replace(/"/g, '\\"')}"`;
}

/**
 * Render a single filter back to the IVRE filter language.
 */
export function renderFilter(filter: Filter): string {
  const prefix = filter.neg ? "!" : "";
  if (filter.type === undefined) {
    return prefix + quoteValue(filter.value);
  }
  return `${prefix}${filter.type}:${quoteValue(filter.value)}`;
}

/**
 * Build a ``q=`` query string from a list of filters.
 */
export function buildQueryFromFilters(filters: readonly Filter[]): string {
  return filters.map(renderFilter).join(" ");
}

/**
 * Parse a ``q=`` query string back into a list of filters.
 *
 * Tokenisation respects double-quoted values with backslash escapes.
 * Whitespace outside quotes is the token separator. Negation is the
 * leading ``!`` or ``-`` (kept consistent with the legacy UI).
 */
export function parseFiltersFromQuery(query: string): Filter[] {
  const filters: Filter[] = [];
  let i = 0;
  const n = query.length;

  while (i < n) {
    while (i < n && /\s/.test(query[i])) i++;
    if (i >= n) break;

    let neg = false;
    if (query[i] === "!" || query[i] === "-") {
      neg = true;
      i++;
    }

    let token = "";
    let inQuotes = false;
    while (i < n) {
      const c = query[i];
      if (inQuotes) {
        if (c === "\\" && i + 1 < n) {
          token += query[i + 1];
          i += 2;
          continue;
        }
        if (c === '"') {
          inQuotes = false;
          i++;
          continue;
        }
        token += c;
        i++;
        continue;
      }
      if (c === '"') {
        inQuotes = true;
        i++;
        continue;
      }
      if (/\s/.test(c)) {
        break;
      }
      token += c;
      i++;
    }

    if (!token) continue;

    const colon = token.indexOf(":");
    if (colon === -1) {
      filters.push({ value: token, neg });
    } else {
      filters.push({
        type: token.slice(0, colon),
        value: token.slice(colon + 1),
        neg,
      });
    }
  }

  return filters;
}

/**
 * Highlight map keyed by filter type. Each value is the lowercased
 * raw value so a case-insensitive comparison works at render time.
 *
 * Components ask ``map.country?.has("fr")`` to decide whether to add
 * a ``bg-highlight`` highlight on the matching chip.
 */
export type HighlightMap = Map<string, Set<string>>;

const HIGHLIGHT_TYPES = new Set([
  "country",
  "city",
  "asnum",
  "asname",
  "as",
  "source",
  "sensor",
  "host",
  "domain",
  "hostname",
  "category",
  "tag",
  "type",
  "dataset",
  "name",
  "target",
  "service",
  "product",
  "version",
  "port",
  "recontype",
]);

export function buildHighlightMap(filters: readonly Filter[]): HighlightMap {
  const out: HighlightMap = new Map();
  for (const f of filters) {
    if (f.neg || f.type === undefined) continue;
    if (!HIGHLIGHT_TYPES.has(f.type)) continue;
    const key = f.type;
    let set = out.get(key);
    if (!set) {
      set = new Set();
      out.set(key, set);
    }
    set.add(f.value.toLowerCase());
  }
  return out;
}

/**
 * Type guard: does this string look like an IVRE filter type prefix?
 *
 * Used by FilterBar's autocomplete.
 */
export const FILTER_TYPES = [
  "host",
  "net",
  "range",
  "hostname",
  "domain",
  "category",
  "tag",
  "country",
  "city",
  "asnum",
  "asname",
  "source",
  "sensor",
  "type",
  "dataset",
  "name",
  "target",
  "timerange",
  "timeago",
  "service",
  "product",
  "version",
  "script",
  "port",
  "anonftp",
  "anonldap",
  "authbypassvnc",
  "authhttp",
  "banner",
  "cookie",
  "file",
  "geovision",
  "httptitle",
  "nfs",
  "nis",
  "yp",
  "mssqlemptypwd",
  "mysqlemptypwd",
  "httphdr",
  "httpapp",
  "owa",
  "phpmyadmin",
  "smb.dnsdomain",
  "smb.forest",
  "smb.lanmanager",
  "smb.os",
  "smb.workgroup",
] as const;

export type FilterType = (typeof FILTER_TYPES)[number];
