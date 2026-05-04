import { HostCard } from "@/components/HostCard";
import type { HostRecord } from "@/lib/api";
import type { Filter, HighlightMap } from "@/lib/filter";

export interface HostCardListProps {
  hosts: readonly HostRecord[];
  loading?: boolean;
  error?: Error | null;
  highlights?: HighlightMap;
  onAddFilter?: (filter: Filter) => void;
  onSelect?: (host: HostRecord) => void;
  /** Index of the currently-hovered host (synced with the
   *  section's ``<Timeline>``). ``null`` means "no hover". */
  hoveredIndex?: number | null;
  /** Two-way hover sync: a card's pointer-enter / pointer-leave
   *  pushes the index back to the parent so the timeline mirrors
   *  the highlight. */
  onHover?: (index: number | null) => void;
  /** DOM-ref registry: the parent collects card refs by index so
   *  it can ``scrollIntoView`` when the user clicks a timeline
   *  row. */
  registerCardRef?: (index: number, el: HTMLDivElement | null) => void;
}

export function HostCardList({
  hosts,
  loading,
  error,
  highlights,
  onAddFilter,
  onSelect,
  hoveredIndex = null,
  onHover,
  registerCardRef,
}: HostCardListProps) {
  if (loading) {
    return <ListMessage>Loading…</ListMessage>;
  }
  if (error) {
    return (
      <ListMessage>
        <span className="text-destructive">Error: {error.message}</span>
      </ListMessage>
    );
  }
  if (hosts.length === 0) {
    return <ListMessage>No results.</ListMessage>;
  }
  return (
    <div className="space-y-3">
      {hosts.map((host, idx) => (
        <HostCard
          key={host.addr}
          host={host}
          highlights={highlights}
          onAddFilter={onAddFilter}
          onSelect={onSelect}
          highlighted={hoveredIndex === idx}
          onHover={onHover ? () => onHover(idx) : undefined}
          onLeave={onHover ? () => onHover(null) : undefined}
          innerRef={
            registerCardRef ? (el) => registerCardRef(idx, el) : undefined
          }
        />
      ))}
    </div>
  );
}

function ListMessage({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-muted/30 px-4 py-12 text-center text-sm text-muted-foreground">
      {children}
    </div>
  );
}
