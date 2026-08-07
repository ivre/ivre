import { useCount } from "@/lib/api";
import type { CompareQueries } from "@/lib/compare-filters";
import { cn } from "@/lib/utils";

export interface CompareCountersProps {
  queries: CompareQueries;
}

type CounterRow = {
  label: string;
  query: string;
  /** When ``false``, skip the count request (empty query). */
  fetch: boolean;
};

/**
 * Result counter table for the Compare page (legacy compare.html
 * thead "Result counters").
 */
export function CompareCounters({ queries }: CompareCountersProps) {
  const rows: CounterRow[] = [
    { label: "Common", query: queries.commonQ, fetch: Boolean(queries.commonQ) },
    { label: "Set 1", query: queries.set1Q, fetch: Boolean(queries.set1Q) },
    { label: "Set 2", query: queries.set2Q, fetch: Boolean(queries.set2Q) },
    {
      label: "Results in all sets",
      query: queries.allSetsQ,
      fetch: Boolean(queries.allSetsQ),
    },
  ];

  return (
    <div className="overflow-hidden rounded-md border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/40">
            <th className="px-3 py-2 text-left font-medium" colSpan={2}>
              Result counters
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <CounterRow key={row.label} label={row.label} query={row.query} fetch={row.fetch} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CounterRow({
  label,
  query,
  fetch,
}: {
  label: string;
  query: string;
  fetch: boolean;
}) {
  const { data, isPending, isError, isFetching } = useCount(
    "/view/count",
    { q: query },
    { enabled: fetch },
  );

  let cell: React.ReactNode;
  let rowClass = "";

  if (!fetch) {
    cell = <span className="text-muted-foreground">—</span>;
  } else if (isPending || isFetching) {
    cell = <span className="italic text-muted-foreground">Counting…</span>;
    rowClass = "bg-muted/30";
  } else if (isError) {
    cell = <span className="text-destructive">Error</span>;
    rowClass = "bg-destructive/10";
  } else if (data === 0) {
    cell = <span>No result!</span>;
    rowClass = "bg-destructive/10";
  } else {
    cell = <span>{data}</span>;
    rowClass = "bg-emerald-500/10 dark:bg-emerald-500/20";
  }

  return (
    <tr className={cn("border-b border-border last:border-0", rowClass)}>
      <td className="px-3 py-2">{label}</td>
      <td className="px-3 py-2 text-right tabular-nums">{cell}</td>
    </tr>
  );
}
