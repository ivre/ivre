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
}

export function HostCardList({
  hosts,
  loading,
  error,
  highlights,
  onAddFilter,
  onSelect,
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
      {hosts.map((host) => (
        <HostCard
          key={host.addr}
          host={host}
          highlights={highlights}
          onAddFilter={onAddFilter}
          onSelect={onSelect}
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
