import { Button } from "@/components/ui/button";

export function ReportPagination({
  loaded,
  total,
  skip,
  previousSkip,
  onSkipChange,
}: {
  loaded: number;
  total?: number;
  skip: number;
  previousSkip: number;
  onSkipChange: (skip: number) => void;
}) {
  // A short response may be a server cap, not the end of the result set.
  const end = loaded === 0 || (total !== undefined && skip + loaded >= total);
  return (
    <div className="my-4 flex flex-wrap items-center justify-between gap-3 text-sm print:hidden">
      <p className="text-muted-foreground">
        {loaded
          ? `Showing ${skip + 1}–${skip + loaded}`
          : "No records on this page"}
        {total !== undefined ? ` of ${total}` : " · total unavailable"}
      </p>
      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          disabled={skip === 0}
          onClick={() => onSkipChange(previousSkip)}
          aria-label="Previous records"
        >
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={end}
          onClick={() => onSkipChange(skip + loaded)}
          aria-label="Next records"
        >
          Next
        </Button>
      </div>
    </div>
  );
}
