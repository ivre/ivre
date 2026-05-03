import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import type { DnsRecord } from "@/lib/api";
import type { Filter, HighlightMap } from "@/lib/filter";
import { cn } from "@/lib/utils";

export interface DnsRecordCardProps {
  record: DnsRecord;
  onAddFilter?: (filter: Filter) => void;
  highlights?: HighlightMap;
  /** ``true`` when the corresponding row in the
   *  ``<Timeline>`` is hovered. The card body lifts a ring to
   *  mirror the highlight. Same convention as
   *  :type:`PassiveRecordCardProps`. */
  highlighted?: boolean;
  /** Pointer-enter callback — used by the route to sync the
   *  hover state back to the timeline. */
  onHover?: () => void;
  /** Pointer-leave callback. */
  onLeave?: () => void;
  /** DOM ref forwarded by the parent so the timeline can scroll
   *  the card into view on click. */
  innerRef?: (el: HTMLDivElement | null) => void;
}

/**
 * One card per merged DNS pseudo-record. The headline is the
 * ``name → addr`` pair (the merge key). Badges below show the
 * union of hostname / DNS record types observed across the
 * active and passive backends, the contributing sensors /
 * scan-source strings, and a summed observation count. Click
 * targets add precise filters: ``host:<addr>``,
 * ``hostname:<name>``, ``sensor:<sensor>``,
 * ``source:<source>``.
 */
export function DnsRecordCard({
  record,
  onAddFilter,
  highlights,
  highlighted,
  onHover,
  onLeave,
  innerRef,
}: DnsRecordCardProps) {
  const addrHL = highlights?.get("host");
  const hostnameHL = highlights?.get("hostname");
  const sensorHL = highlights?.get("sensor");
  const sourceHL = highlights?.get("source");

  return (
    <Card
      ref={innerRef}
      onMouseEnter={onHover}
      onMouseLeave={onLeave}
      className={cn(
        "border-gray-200/60 py-0 shadow-none transition-shadow hover:shadow-sm dark:border-blue-950/60",
        highlighted && "ring-2 ring-orange-400 dark:ring-orange-300",
      )}
    >
      <CardContent className="space-y-2 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="break-all font-mono text-sm">
              <button
                type="button"
                className={cn(
                  "rounded px-1 hover:underline",
                  hostnameHL?.has(record.name.toLowerCase()) &&
                    "bg-highlight text-highlight-foreground",
                )}
                onClick={() =>
                  onAddFilter?.({
                    type: "hostname",
                    value: record.name,
                  })
                }
                title={`Add hostname:${record.name} filter`}
              >
                {record.name}
              </button>
              <span className="mx-1 text-muted-foreground">→</span>
              <button
                type="button"
                className={cn(
                  "rounded px-1 hover:underline",
                  addrHL?.has(record.addr.toLowerCase()) &&
                    "bg-highlight text-highlight-foreground",
                )}
                onClick={() =>
                  onAddFilter?.({ type: "host", value: record.addr })
                }
                title={`Add host:${record.addr} filter`}
              >
                {record.addr}
              </button>
            </div>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {record.types.map((t) => (
                <Badge
                  key={`type-${t}`}
                  variant="outline"
                  className="font-mono text-xs"
                >
                  {t}
                </Badge>
              ))}
            </div>
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1 text-xs text-muted-foreground">
            <span
              className="rounded bg-muted px-1.5 py-0.5 font-mono"
              title="Sum of active scan documents and passive observations"
            >
              ×{record.count}
            </span>
            <span className="font-mono">
              {formatRange(record.firstseen, record.lastseen)}
            </span>
          </div>
        </div>

        {record.sources.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {record.sources.map((s) => {
              // Sources can be either an active ``source``
              // (scan label) or a passive ``sensor`` name. We
              // surface them all under the ``source`` filter
              // type because that is what the legacy filter
              // bar accepts; the highlight check covers both
              // sensor and source highlight maps so either
              // active filter type matches.
              const lower = s.toLowerCase();
              const highlighted =
                sourceHL?.has(lower) || sensorHL?.has(lower);
              return (
                <button
                  key={`src-${s}`}
                  type="button"
                  onClick={() =>
                    onAddFilter?.({ type: "source", value: s })
                  }
                  title={`Add source:${s} filter`}
                >
                  <Badge
                    variant="secondary"
                    className={cn(
                      "font-mono text-xs",
                      highlighted &&
                        "bg-highlight text-highlight-foreground",
                    )}
                  >
                    {s}
                  </Badge>
                </button>
              );
            })}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function formatRange(
  firstseen: number | string,
  lastseen: number | string,
): string {
  const fmt = (v: number | string): string => {
    if (typeof v === "number") {
      // Backend emits Unix seconds by default.
      const ms = v < 1e11 ? v * 1000 : v;
      const d = new Date(ms);
      const pad = (n: number) => String(n).padStart(2, "0");
      return (
        `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
        ` ${pad(d.getHours())}:${pad(d.getMinutes())}`
      );
    }
    // ``datesasstrings`` form — the backend emits
    // ``"YYYY-MM-DD HH:MM:SS.ffffff"`` (no tz). Slice to the
    // minute for compact display.
    return v.replace("T", " ").slice(0, 16);
  };
  return `${fmt(firstseen)} → ${fmt(lastseen)}`;
}
