import { ChevronDown, ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  isRirAutNum,
  isRirInetNum,
  type RirAutNum,
  type RirInetNum,
  type RirRecord,
} from "@/lib/api";
import type { Filter, HighlightMap } from "@/lib/filter";
import { rangeToCidr } from "@/lib/rir";
import { cn } from "@/lib/utils";

export interface RirRecordCardProps {
  record: RirRecord;
  onAddFilter?: (filter: Filter) => void;
  highlights?: HighlightMap;
}

/** Fields rendered in the compact (collapsed) card. The full
 *  RPSL key/value table is shown behind "Show more". */
const VISIBLE_KEYS_INETNUM = [
  "netname",
  "descr",
  "org",
  "country",
  "source_file",
] as const;
const VISIBLE_KEYS_AUTNUM = [
  "as-name",
  "descr",
  "org",
  "country",
  "source_file",
] as const;

/** Keys we surface as their own UI element (headline, badges,
 *  filter chips). Everything else is folded into the "Show more"
 *  RPSL table. */
const PROMOTED_KEYS = new Set<string>([
  "start",
  "stop",
  "size",
  "netname",
  "aut-num",
  "as-name",
  "country",
  "descr",
  "org",
  "source_file",
  "source_hash",
  "source",
  "schema_version",
  "_id",
]);

/**
 * One card per RIR record. Two record families are rendered with
 * distinct headlines:
 *
 *  - ``inet[6]num``: ``<CIDR>`` if the ``(start, stop)`` range
 *    collapses to a single prefix, else ``<start> — <stop>``.
 *    Optional ``netname`` shown as a chip.
 *  - ``aut-num``: ``AS<num>`` headline; optional ``as-name`` as a
 *    chip.
 *
 * "Show more" toggles a generic key/value table over every
 * remaining RPSL field the dump carried (multi-line values
 * preserved). Click chip values to add the matching filter
 * (``country:``, ``sourcefile:``, ``asnum:`` for the AS<num>
 * headline).
 */
export function RirRecordCard({
  record,
  onAddFilter,
  highlights,
}: RirRecordCardProps) {
  const [expanded, setExpanded] = useState(false);
  const countryHL = highlights?.get("country");
  const asnumHL = highlights?.get("asnum");
  const sourcefileHL = highlights?.get("sourcefile");

  const isAutNum = isRirAutNum(record);
  const isInetNum = isRirInetNum(record);

  const headline = useMemo(() => {
    if (isInetNum) {
      const inet = record as RirInetNum;
      return rangeToCidr(inet.start, inet.stop) ?? `${inet.start} — ${inet.stop}`;
    }
    if (isAutNum) {
      return `AS${(record as RirAutNum)["aut-num"]}`;
    }
    return "(unknown record)";
  }, [record, isInetNum, isAutNum]);

  const visibleKeys = isInetNum ? VISIBLE_KEYS_INETNUM : VISIBLE_KEYS_AUTNUM;

  const extraEntries = useMemo(
    () => collectExtraEntries(record),
    [record],
  );

  return (
    <Card className="border-gray-200/60 py-0 shadow-none transition-shadow hover:shadow-sm dark:border-blue-950/60">
      <CardContent className="space-y-2 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="break-all font-mono text-sm">
              {isAutNum ? (
                <button
                  type="button"
                  className={cn(
                    "rounded px-1 hover:underline",
                    asnumHL?.has(
                      String((record as RirAutNum)["aut-num"]).toLowerCase(),
                    ) && "bg-highlight text-highlight-foreground",
                  )}
                  onClick={() =>
                    onAddFilter?.({
                      type: "asnum",
                      value: String((record as RirAutNum)["aut-num"]),
                    })
                  }
                  title={`Add asnum:${(record as RirAutNum)["aut-num"]} filter`}
                >
                  {headline}
                </button>
              ) : (
                <span>{headline}</span>
              )}
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {visibleKeys.map((key) => {
                const val = readField(record, key);
                if (val === null) return null;
                return (
                  <FieldBadge
                    key={key}
                    fieldKey={key}
                    value={val}
                    highlighted={
                      key === "country"
                        ? countryHL?.has(val.toLowerCase())
                        : key === "source_file"
                          ? sourcefileHL?.has(val.toLowerCase())
                          : false
                    }
                    onClick={() => {
                      const f = filterFor(key, val);
                      if (f) onAddFilter?.(f);
                    }}
                  />
                );
              })}
            </div>
          </div>
        </div>
        {extraEntries.length > 0 ? (
          <Button
            variant="link"
            size="sm"
            className="px-1"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
          >
            {expanded ? (
              <>
                <ChevronDown className="size-3" />
                Show less
              </>
            ) : (
              <>
                <ChevronRight className="size-3" />
                Show more ({extraEntries.length})
              </>
            )}
          </Button>
        ) : null}
        {expanded && extraEntries.length > 0 ? (
          <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1 border-t border-border pt-2 font-mono text-xs">
            {extraEntries.map(([key, val]) => (
              <div key={key} className="contents">
                <dt className="text-muted-foreground">{key}:</dt>
                <dd className="whitespace-pre-wrap break-words">{val}</dd>
              </div>
            ))}
          </dl>
        ) : null}
      </CardContent>
    </Card>
  );
}

function FieldBadge({
  fieldKey,
  value,
  highlighted,
  onClick,
}: {
  fieldKey: string;
  value: string;
  highlighted?: boolean;
  onClick: () => void;
}) {
  const truncated = value.length > 80 ? value.slice(0, 79) + "…" : value;
  const filterable = isFilterable(fieldKey);
  const content = (
    <Badge
      variant={fieldKey === "country" ? "default" : "secondary"}
      className={cn(
        "max-w-[24rem] truncate font-mono text-xs",
        highlighted && "bg-highlight text-highlight-foreground",
      )}
      title={value}
    >
      <span className="text-muted-foreground/80">{fieldKey}:</span>
      <span>&nbsp;{truncated}</span>
    </Badge>
  );
  if (!filterable) return content;
  return (
    <button
      type="button"
      onClick={onClick}
      title={`Add ${filterTokenFor(fieldKey)}:${value} filter`}
    >
      {content}
    </button>
  );
}

/** Render any RPSL field value as a clean string. The dump's
 *  ``descr`` / ``remarks`` / ``notify`` / ``org`` are commonly
 *  arrays-of-strings (one entry per source line); join with
 *  newlines so the "Show more" table preserves the original
 *  layout. */
function fieldValueToString(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) {
    return value.map((v) => fieldValueToString(v)).join("\n");
  }
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  // Fall back to a JSON dump for unexpected nested shapes.
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function readField(record: RirRecord, key: string): string | null {
  const raw = (record as Record<string, unknown>)[key];
  if (raw === null || raw === undefined) return null;
  const s = fieldValueToString(raw).trim();
  return s === "" ? null : s;
}

function filterFor(fieldKey: string, value: string): Filter | null {
  const token = filterTokenFor(fieldKey);
  if (!token) return null;
  return { type: token, value };
}

function filterTokenFor(fieldKey: string): string | null {
  switch (fieldKey) {
    case "country":
      return "country";
    case "source_file":
      return "sourcefile";
    case "as-name":
      return "asname";
    default:
      return null;
  }
}

function isFilterable(fieldKey: string): boolean {
  return filterTokenFor(fieldKey) !== null;
}

/** Build the ``[key, formatted_value]`` list for the "Show more"
 *  RPSL table. Skips fields already surfaced in the headline /
 *  badges / chips, and drops empty values. Sorted alphabetically
 *  to match ``rirlookup --json`` output. */
function collectExtraEntries(record: RirRecord): [string, string][] {
  const out: [string, string][] = [];
  for (const [key, raw] of Object.entries(record)) {
    if (PROMOTED_KEYS.has(key)) continue;
    const s = fieldValueToString(raw).trim();
    if (s === "") continue;
    out.push([key, s]);
  }
  out.sort(([a], [b]) => a.localeCompare(b));
  return out;
}
