/**
 * Formatting helpers used by the result cards.
 *
 * All functions are pure (no React, no DOM) so they are testable in
 * isolation and reusable across components.
 */

/** Map a 2-letter country code (ISO 3166-1 alpha-2) to its emoji
 *  flag. Returns the empty string for invalid input.
 *
 *  This is the regional-indicator construction (each letter is
 *  mapped to its REGIONAL INDICATOR SYMBOL counterpart at U+1F1E6
 *  for ``A``).
 */
export function getCountryFlag(countryCode: string | undefined): string {
  if (!countryCode) return "";
  const upper = countryCode.toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return "";
  const A = "A".charCodeAt(0);
  const REGIONAL_A = 0x1f1e6;
  return String.fromCodePoint(
    REGIONAL_A + (upper.charCodeAt(0) - A),
    REGIONAL_A + (upper.charCodeAt(1) - A),
  );
}

/** Tag colours by type. Keys mirror the IVRE tag schema's ``type``
 *  field (``info``, ``warning``, ``error``, ``success``). Anything
 *  else falls back to the neutral ``default`` palette. */
export type TagToneKey = "info" | "warning" | "error" | "success" | "default";

const TAG_TONES: Record<TagToneKey, string> = {
  info: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  warning:
    "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  error: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
  success: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  default:
    "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
};

export function getTagColor(type: string | undefined): string {
  if (type && type in TAG_TONES) {
    return TAG_TONES[type as TagToneKey];
  }
  return TAG_TONES.default;
}

/**
 * Importance rank used when collapsing long tag lists on the host
 * card / detail sheet.
 *
 * Lower rank = higher importance = shown first. Anything with an
 * unknown / missing ``type`` (e.g. the default-purple "Client …"
 * inventory tags emitted in bulk by some IVRE plugins) sorts to the
 * end so the signal tags remain visible when the list is collapsed.
 *
 * Order is ``error > warning > success > info > default``.
 */
export const TAG_TYPE_RANK: Record<string, number> = {
  error: 0,
  warning: 1,
  success: 2,
  info: 3,
};
const TAG_TYPE_DEFAULT_RANK = 4;

/**
 * Return a new array of tags sorted by importance (see
 * :data:`TAG_TYPE_RANK`). Stable: ties preserve the original server
 * order, so e.g. two ``info`` tags keep their incoming sequence.
 *
 * If ``isHighlighted`` is provided, tags it returns ``true`` for are
 * pulled to the head of the result and ranked among themselves by
 * the same importance order. Concretely the sort key is the tuple
 * ``(isHighlighted ? 0 : 1, typeRank, originalIndex)``, ascending,
 * so the final order is:
 *
 *   ``error★ > warning★ > success★ > info★ > default★ > error > warning > … > default``
 *
 * (``★`` = matches the highlight predicate.)
 *
 * Rationale: a highlighted tag is part of the active filter set, so
 * it's what the user cares about right now and should anchor the
 * head of the list — but severity still matters as a secondary key
 * within each bucket.
 */
export function sortTagsByImportance<T extends { type?: string }>(
  tags: readonly T[],
  isHighlighted?: (tag: T) => boolean,
): T[] {
  return tags
    .map((t, i) => ({
      t,
      i,
      hl: isHighlighted !== undefined && isHighlighted(t) ? 0 : 1,
      rank: t.type !== undefined && t.type in TAG_TYPE_RANK
        ? TAG_TYPE_RANK[t.type]
        : TAG_TYPE_DEFAULT_RANK,
    }))
    .sort((a, b) => a.hl - b.hl || a.rank - b.rank || a.i - b.i)
    .map((x) => x.t);
}

/** Port colours by ``state_state`` field on a port record. */
export function getPortColor(state: string | undefined): string {
  switch (state) {
    case "open":
      return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
    case "closed":
      return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
    case "filtered":
    case "open|filtered":
    case "closed|filtered":
      return "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200";
    default:
      return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200";
  }
}

export interface PortRecord {
  protocol?: string;
  port?: number;
  service_name?: string;
  service_product?: string;
  service_version?: string;
  state_state?: string;
}

/**
 * Concatenate the ``service_name`` of every open port in a host
 * record into a comma-separated preview string. Used in the result
 * card's "Services:" line.
 */
export function formatServices(ports: readonly PortRecord[]): string {
  const services = ports
    .filter((p) => p.state_state === "open" && p.service_name)
    .map((p) => {
      let label = p.service_name as string;
      if (p.service_product) {
        label += ` (${p.service_product}${
          p.service_version ? ` ${p.service_version}` : ""
        })`;
      }
      return label;
    });
  // dedupe while preserving order
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const s of services) {
    if (!seen.has(s)) {
      seen.add(s);
      unique.push(s);
    }
  }
  return unique.join(", ");
}

/**
 * Render a ``protocol/port`` token (e.g. ``tcp/443``) from a port
 * record. Returns ``""`` if either field is missing.
 */
export function formatPort(port: Pick<PortRecord, "protocol" | "port">): string {
  if (!port.protocol || port.port === undefined) return "";
  return `${port.protocol}/${port.port}`;
}

/**
 * Convert an ISO timestamp (or seconds-since-epoch number) to a
 * compact human-readable string (UTC, second resolution). Returns
 * the empty string on invalid input.
 */
export function formatTimestamp(value: string | number | undefined): string {
  if (value === undefined || value === null) return "";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}
