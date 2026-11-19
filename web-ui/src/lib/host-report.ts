import type { HostRecord } from "@/lib/api";

export type HostSection = "view" | "active";
export type ReportTab = HostSection | "passive" | "notes";

export const REPORT_PARAMS = [
  "tab",
  "record",
  "recordsSkip",
  "passiveSkip",
  "passivePort",
  "passiveType",
  "passiveSensor",
  "section",
  "activeQ",
  "passiveQ",
] as const;

export interface HostNavigationEntry {
  addr: string;
  record?: string;
}

export interface HostNavigation {
  returnTo: string;
  returnScrollY: number;
  returnKey?: string;
  entries: HostNavigationEntry[];
  currentIndex?: number;
}

/** IDs are supplied by the API. Never synthesize identity from record content. */
export function hostRecordId(record: HostRecord): string | undefined {
  return typeof record._id === "string" && record._id.length
    ? record._id
    : undefined;
}

export function hostReportUrl(
  section: HostSection,
  addr: string,
  params: URLSearchParams,
): string {
  const suffix = params.toString();
  return `/${section}/host/${encodeURIComponent(addr)}${suffix ? `?${suffix}` : ""}`;
}

export function hostResultsUrl(
  section: HostSection,
  params: URLSearchParams,
): string {
  const results = new URLSearchParams(params);
  for (const name of REPORT_PARAMS) results.delete(name);
  const suffix = results.toString();
  return `/${section}${suffix ? `?${suffix}` : ""}`;
}

export function readHostNavigation(value: unknown): HostNavigation | undefined {
  if (!value || typeof value !== "object" || !("hostNavigation" in value))
    return;
  const context = value.hostNavigation;
  if (
    !context ||
    typeof context !== "object" ||
    !("returnTo" in context) ||
    typeof context.returnTo !== "string" ||
    !validReturnTo(context.returnTo) ||
    !("returnScrollY" in context) ||
    typeof context.returnScrollY !== "number" ||
    !Number.isFinite(context.returnScrollY) ||
    context.returnScrollY < 0 ||
    !("entries" in context) ||
    !Array.isArray(context.entries)
  )
    return;
  const entries = context.entries.filter(
    (entry): entry is HostNavigationEntry =>
      !!entry &&
      typeof entry === "object" &&
      typeof entry.addr === "string" &&
      (entry.record === undefined || typeof entry.record === "string"),
  );
  const returnKey =
    "returnKey" in context && typeof context.returnKey === "string"
      ? context.returnKey
      : undefined;
  const currentIndex =
    "currentIndex" in context &&
    typeof context.currentIndex === "number" &&
    Number.isInteger(context.currentIndex)
      ? context.currentIndex
      : undefined;
  return {
    returnTo: context.returnTo,
    returnScrollY: context.returnScrollY,
    returnKey,
    entries,
    currentIndex,
  };
}

function validReturnTo(value: string): boolean {
  if (/^\/(view|active)(\?|$)/.test(value)) return true;
  if (!/^\/(view|active)\/host\/[^/?#]+\?/.test(value)) return false;
  const params = new URLSearchParams(value.slice(value.indexOf("?") + 1));
  return params.get("tab") === "active" && !params.has("record");
}
