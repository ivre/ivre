import { PassiveRecordCard } from "@/components/PassiveRecordCard";
import type { PassiveRecord } from "@/lib/api";
import type { Filter, HighlightMap } from "@/lib/filter";

export interface PassiveRecordListProps {
  records: readonly PassiveRecord[];
  loading: boolean;
  error: Error | null;
  highlights?: HighlightMap;
  onAddFilter?: (filter: Filter) => void;
  hoveredIndex: number | null;
  onHover: (index: number | null) => void;
  /** Receives one DOM ref per record so the parent can scroll a
   *  given record into view (driven by clicks on the timeline). */
  registerCardRef?: (index: number, el: HTMLDivElement | null) => void;
}

export function PassiveRecordList({
  records,
  loading,
  error,
  highlights,
  onAddFilter,
  hoveredIndex,
  onHover,
  registerCardRef,
}: PassiveRecordListProps) {
  if (loading) {
    return (
      <p className="px-1 text-sm italic text-muted-foreground">
        Loading passive observations…
      </p>
    );
  }
  if (error) {
    return (
      <p className="px-1 text-sm text-destructive">Error: {error.message}</p>
    );
  }
  if (records.length === 0) {
    return (
      <p className="px-1 text-sm italic text-muted-foreground">
        No matching passive observations.
      </p>
    );
  }
  return (
    <div className="space-y-3">
      {records.map((rec, idx) => (
        <PassiveRecordCard
          key={`${rec.recontype}-${idx}`}
          record={rec}
          highlights={highlights}
          onAddFilter={onAddFilter}
          highlighted={hoveredIndex === idx}
          onHover={() => onHover(idx)}
          onLeave={() => onHover(null)}
          innerRef={(el) => registerCardRef?.(idx, el)}
        />
      ))}
    </div>
  );
}
