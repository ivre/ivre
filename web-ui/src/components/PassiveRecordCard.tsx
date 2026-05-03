import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import type { PassiveRecord } from "@/lib/api";
import type { Filter, HighlightMap } from "@/lib/filter";
import { describePassiveValue } from "@/lib/passive";
import { formatTimelineRange } from "@/lib/timeline";
import { cn } from "@/lib/utils";

export interface PassiveRecordCardProps {
  record: PassiveRecord;
  onAddFilter?: (filter: Filter) => void;
  highlights?: HighlightMap;
  /** Whether the card is currently hover-synced with the timeline. */
  highlighted?: boolean;
  onHover?: () => void;
  onLeave?: () => void;
  /** DOM ref forwarded by the parent so the timeline can scroll
   *  the card into view on click. */
  innerRef?: (el: HTMLDivElement | null) => void;
}

/**
 * One card per passive record. Top: ``recontype``-derived
 * heading + observation count + first → last range. Body: a
 * recontype-aware rendering of the ``value`` (DNS answers as
 * ``name → addr``, certs as ``subject`` + issuer/SHA1, JA3 as
 * hash, ...). Footer: clickable ``addr`` / ``sensor`` /
 * ``source`` / ``port`` chips that add the corresponding filter.
 */
export function PassiveRecordCard({
  record,
  onAddFilter,
  highlights,
  highlighted,
  onHover,
  onLeave,
  innerRef,
}: PassiveRecordCardProps) {
  const display = describePassiveValue(record);
  const addrHL = highlights?.get("host");
  const sensorHL = highlights?.get("sensor");
  const recontypeHL = highlights?.get("recontype");
  const sourceHL = highlights?.get("source");
  const portHL = highlights?.get("port");

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
            {display.heading ? (
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {display.heading}
              </div>
            ) : null}
            <div className="break-all font-mono text-sm">
              {display.primary}
            </div>
            {display.secondary ? (
              <div className="break-all font-mono text-xs text-muted-foreground">
                {display.secondary}
              </div>
            ) : null}
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1 text-xs text-muted-foreground">
            <span className="rounded bg-muted px-1.5 py-0.5 font-mono">
              ×{record.count}
            </span>
            <span className="font-mono">{formatTimelineRange(record)}</span>
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5 text-xs">
          {record.addr ? (
            <button
              type="button"
              onClick={() =>
                onAddFilter?.({ type: "host", value: record.addr as string })
              }
            >
              <Badge
                variant="outline"
                className={cn(
                  "font-mono",
                  addrHL?.has(record.addr.toLowerCase()) &&
                    "bg-highlight text-highlight-foreground",
                )}
              >
                {record.addr}
              </Badge>
            </button>
          ) : null}
          {record.recontype ? (
            <button
              type="button"
              onClick={() =>
                onAddFilter?.({ type: "recontype", value: record.recontype })
              }
            >
              <Badge
                variant="outline"
                className={cn(
                  recontypeHL?.has(record.recontype.toLowerCase()) &&
                    "bg-highlight text-highlight-foreground",
                )}
              >
                {record.recontype}
              </Badge>
            </button>
          ) : null}
          {record.sensor ? (
            <button
              type="button"
              onClick={() =>
                onAddFilter?.({
                  type: "sensor",
                  value: record.sensor as string,
                })
              }
            >
              <Badge
                variant="outline"
                className={cn(
                  sensorHL?.has(record.sensor.toLowerCase()) &&
                    "bg-highlight text-highlight-foreground",
                )}
              >
                sensor:{record.sensor}
              </Badge>
            </button>
          ) : null}
          {record.source ? (
            (() => {
              // ``source`` on passive is meaningful only relative
              // to ``recontype``; clicks add the
              // ``source:RECONTYPE:SOURCE`` tuple filter
              // (server-side: ``searchrecontype(rectype=…,
              // source=…)``). Highlight matches either the bare
              // source (legacy ``source:cert`` filter) or the
              // composite (``source:SSL_SERVER:cert`` filter).
              const compositeValue = `${record.recontype}:${record.source}`;
              const lower = (record.source as string).toLowerCase();
              const compositeLower = compositeValue.toLowerCase();
              const isHighlighted = Boolean(
                sourceHL?.has(lower) || sourceHL?.has(compositeLower),
              );
              return (
                <button
                  type="button"
                  onClick={() =>
                    onAddFilter?.({
                      type: "source",
                      value: compositeValue,
                    })
                  }
                >
                  <Badge
                    variant="outline"
                    className={cn(
                      isHighlighted &&
                        "bg-highlight text-highlight-foreground",
                    )}
                  >
                    source:{record.source}
                  </Badge>
                </button>
              );
            })()
          ) : null}
          {record.port !== undefined ? (
            <button
              type="button"
              onClick={() =>
                onAddFilter?.({ value: `tcp/${record.port}` })
              }
            >
              <Badge
                variant="outline"
                className={cn(
                  "font-mono",
                  portHL?.has(`tcp/${record.port}`) &&
                    "bg-highlight text-highlight-foreground",
                )}
              >
                :{record.port}
              </Badge>
            </button>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
