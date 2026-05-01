/**
 * Map an IVRE ``top`` field name (the path segment of
 * ``/cgi/<purpose>/top/<field>``) plus a returned label/value pair
 * to a click-to-filter ``Filter``.
 *
 * The IVRE backend's ``topvalues`` semantics return labels of
 * varying shapes:
 *  - string for simple fields (``country`` returns ``"FR"``)
 *  - ``[code, name]`` for human-readable pairs (``country`` returns
 *    ``["FR", "France"]`` when the metadata is enriched; ``asnum``
 *    returns ``[20940, "Akamai"]``; ``city`` returns
 *    ``[country, city]``)
 *  - ``[protocol, port]`` for ``port:open``
 *  - ``[name, product, version]`` for ``service``
 *
 * This module is the central translation point. It is a port of the
 * legacy ``js/field-mapper.js`` (Vue/Alpine prototype), retyped and
 * exhaustively tested.
 */

import type { Filter } from "./filter";

/** A label as returned by the backend. May be a primitive or a
 *  tuple. */
export type TopLabel = string | number | (string | number)[];

/** Convert a TopLabel and the originating field name to a click-to-
 *  filter ``Filter`` object. Returns ``null`` when no sensible
 *  mapping exists. */
export type FieldMapper = (label: TopLabel) => Filter | null;

/** Placeholder shown when a tuple slot (product, version, …) is
 *  missing. The IVRE backend emits JSON ``null`` (deserialised here
 *  as ``null``) or the literal string ``"null"`` when a sub-field
 *  was not detected; both render as ``(unknown)``. */
export const UNKNOWN_LABEL = "(unknown)";

/** Map an empty / nullish / literal-"null"-string slot to
 *  ``UNKNOWN_LABEL`` so the UI never shows the bare token ``null``. */
function placeholder(v: unknown): string {
  if (v === null || v === undefined) return UNKNOWN_LABEL;
  const s = String(v);
  if (s === "" || s === "null" || s === "undefined") return UNKNOWN_LABEL;
  return s;
}

function asString(value: TopLabel): string {
  if (Array.isArray(value)) return value.map(placeholder).join(":");
  return placeholder(value);
}

function firstString(value: TopLabel): string {
  if (Array.isArray(value)) return placeholder(value[0]);
  return placeholder(value);
}

const SIMPLE_FILTERS: Record<string, string> = {
  country: "country",
  asnum: "asnum",
  asname: "asname",
  source: "source",
  sensor: "sensor",
  category: "category",
  domain: "domain",
  hostname: "hostname",
  service: "service",
  product: "product",
  version: "version",
  recontype: "recontype",
  type: "type",
  dataset: "dataset",
  name: "name",
  target: "target",
};

/**
 * Special-case mappers keyed by exact field name. The fallback
 * (``DEFAULT_MAPPER``) handles SIMPLE_FILTERS and the ``port:*``
 * family.
 */
const SPECIAL_MAPPERS: Record<string, FieldMapper> = {
  // ``country`` returns ``["FR", "France"]`` when enriched, ``"FR"``
  // otherwise. We always filter by the code.
  country: (label) => ({ type: "country", value: firstString(label) }),

  // ``asnum`` returns ``[12345, "Some AS"]`` or ``12345``.
  asnum: (label) => ({ type: "asnum", value: firstString(label) }),

  // The ``as`` facet is an alias for ``asnum``.
  as: (label) => ({ type: "asnum", value: firstString(label) }),

  // ``city`` returns ``["FR", "Carcassonne"]``. We need both for
  // disambiguation.
  city: (label) => {
    if (Array.isArray(label) && label.length >= 2) {
      return {
        type: "city",
        value: `${label[0]}/${label[1]}`,
      };
    }
    return { type: "city", value: asString(label) };
  },

  // ``port:open`` returns ``["tcp", 443]``. Filter as a bare
  // ``tcp/443`` token (anonymous filter — IVRE recognises this
  // shape).
  "port:open": (label) => {
    if (Array.isArray(label) && label.length >= 2) {
      return { value: `${label[0]}/${label[1]}` };
    }
    return { value: asString(label) };
  },

  // ``service`` returns ``["http", "nginx", "1.18"]`` or just
  // ``"http"``. We filter by service name only.
  service: (label) => ({ type: "service", value: firstString(label) }),

  // ``product`` returns ``["http", "nginx"]`` (service, product) or
  // ``["nginx"]``. We want the product name, which is the second
  // element when the array has 2+ items.
  product: (label) => {
    if (Array.isArray(label)) {
      return { type: "product", value: String(label[label.length - 1] ?? "") };
    }
    return { type: "product", value: asString(label) };
  },

  // ``version`` returns ``["http", "nginx", "1.18"]``. Filter by
  // version string only (last element).
  version: (label) => {
    if (Array.isArray(label)) {
      return { type: "version", value: String(label[label.length - 1] ?? "") };
    }
    return { type: "version", value: asString(label) };
  },

  // ``cpe`` returns CPE URIs as strings.
  cpe: (label) => ({ type: "cpe", value: asString(label) }),

  // ``vulns`` returns ``[id, title]`` or just ``id``.
  vulns: (label) => ({ type: "vuln", value: firstString(label) }),

  // ``sshkey`` returns ``[type, fingerprint]``. We filter by
  // fingerprint.
  sshkey: (label) => {
    if (Array.isArray(label) && label.length >= 2) {
      return { type: "sshkey", value: String(label[1]) };
    }
    return { type: "sshkey", value: asString(label) };
  },

  // ``smb`` returns various ``smb.*`` keys.
  "smb.dnsdomain": (label) => ({
    type: "smb.dnsdomain",
    value: asString(label),
  }),
  "smb.forest": (label) => ({ type: "smb.forest", value: asString(label) }),
  "smb.lanmanager": (label) => ({
    type: "smb.lanmanager",
    value: asString(label),
  }),
  "smb.os": (label) => ({ type: "smb.os", value: asString(label) }),
  "smb.workgroup": (label) => ({
    type: "smb.workgroup",
    value: asString(label),
  }),

  // ``tag`` returns ``["category", "description"]``. The IVRE
  // filter is ``tag:category:description`` (with the ``:`` literal
  // — quoted by the renderer).
  tag: (label) => {
    if (Array.isArray(label) && label.length >= 2) {
      return { type: "tag", value: `${label[0]}:${label[1]}` };
    }
    return { type: "tag", value: asString(label) };
  },

  // ``domains`` returns the full hostname (e.g. ``foo.example.com``)
  // and we filter by the longest-prefix domain (``example.com``).
  // Without more context we treat the value as-is.
  domains: (label) => ({ type: "domain", value: asString(label) }),

  // ``hostnames`` returns the full FQDN.
  hostnames: (label) => ({ type: "hostname", value: asString(label) }),
};

/**
 * Returns the filter that should be added when the user clicks a
 * ``label`` row in the ``field`` facet group. A field name like
 * ``port:open`` is matched as a whole; trailing ``:N`` (top-N
 * limit) is stripped before lookup.
 */
export function createFilter(
  field: string,
  label: TopLabel,
): Filter | null {
  // Trim a trailing ``:<N>`` limit if present (e.g. ``country:15``).
  const baseField = field.replace(/:\d+$/, "");

  const special = SPECIAL_MAPPERS[baseField];
  if (special) return special(label);

  const simple = SIMPLE_FILTERS[baseField];
  if (simple) {
    return { type: simple, value: firstString(label) };
  }

  // Anything starting with ``port:`` (e.g. ``port:filtered``) flows
  // through the ``port:open`` shape.
  if (baseField.startsWith("port:")) {
    return SPECIAL_MAPPERS["port:open"](label);
  }

  // Anything starting with ``smb.`` flows through with type=field.
  if (baseField.startsWith("smb.")) {
    return { type: baseField, value: asString(label) };
  }

  // Last resort: bare value, no type prefix. The backend's
  // ``ivre/web/utils.py`` recognises a number of bare shapes (IP
  // literal, CIDR, hostname, …), so this is not always nonsense.
  return { value: asString(label) };
}

/**
 * Render a top-N row's label as a display string. Mirrors the
 * branching the prototype's ``js/field-mapper.js`` does at render
 * time.
 */
export function displayLabel(field: string, label: TopLabel): string {
  const baseField = field.replace(/:\d+$/, "");

  if (Array.isArray(label)) {
    if (baseField === "country" && label.length >= 2) {
      // ``["FR", "France"]`` → "France" with the code as title attr
      return placeholder(label[1]);
    }
    if (baseField === "asnum" && label.length >= 2) {
      return `AS${placeholder(label[0])} ${placeholder(label[1])}`;
    }
    if (baseField === "city" && label.length >= 2) {
      return `${placeholder(label[1])}, ${placeholder(label[0])}`;
    }
    if (baseField === "tag" && label.length >= 2) {
      return `${placeholder(label[0])}: ${placeholder(label[1])}`;
    }
    if (baseField.startsWith("port:") && label.length >= 2) {
      return `${placeholder(label[0])}/${placeholder(label[1])}`;
    }
    // ``service`` / ``product`` / ``version`` and any other tuple
    // facet: render slot-by-slot with `` / `` between, so missing
    // sub-fields stay positionally meaningful (e.g.
    // ``http / (unknown)`` rather than the bare ``http`` that
    // would lose the slot). Single-element arrays fall through to
    // the default join below.
    return label.map(placeholder).join(" / ");
  }
  return placeholder(label);
}
