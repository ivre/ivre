import { useTop } from "@/lib/api";
import { displayLabel } from "@/lib/field-mapper";
import { cn } from "@/lib/utils";

export interface TopValuesChartProps {
  topEndpoint: string;
  field: string;
  query: string;
  limit?: number;
  /** When ``false``, no request is issued (report "Build" gate). */
  enabled?: boolean;
  /** Bar height multiplier (legacy ``size``). */
  size?: number;
  /** CSS color for bars (defaults to theme primary). */
  barColor?: string;
  className?: string;
}

const ROW_HEIGHT = 30;
const BAR_AREA_WIDTH = 100;

/**
 * Horizontal bar chart for ``/cgi/view/top/<field>`` data. Used by
 * the Report and Compare pages (legacy ``GraphTopValues``).
 */
export function TopValuesChart({
  topEndpoint,
  field,
  query,
  limit = 10,
  enabled = true,
  size = 5,
  barColor,
  className,
}: TopValuesChartProps) {
  const { data, isPending, isError, error } = useTop(
    topEndpoint,
    field,
    { q: query, limit },
    { enabled: enabled && Boolean(field) },
  );

  if (!enabled) {
    return (
      <p className="text-sm italic text-muted-foreground">
        Click Build to render this chart.
      </p>
    );
  }

  if (!field) {
    return (
      <p className="text-sm italic text-muted-foreground">
        Enter a top field to render this chart.
      </p>
    );
  }

  if (isPending) {
    return <p className="text-sm italic text-muted-foreground">Loading…</p>;
  }

  if (isError) {
    return (
      <p className="text-sm text-destructive">Error: {error?.message}</p>
    );
  }

  const items = data ?? [];
  if (items.length === 0) {
    return (
      <p className="text-sm italic text-muted-foreground">No values.</p>
    );
  }

  const max = items.reduce((m, x) => (x.value > m ? x.value : m), 1);
  const chartWidth = BAR_AREA_WIDTH * size;
  const chartHeight = ROW_HEIGHT * items.length;

  return (
    <div className={cn("w-full overflow-x-auto", className)}>
      <svg
        viewBox={`0 0 ${chartWidth} ${chartHeight}`}
        className="h-auto w-full max-w-full"
        role="img"
        aria-label={`Top values for ${field}`}
      >
        {items.map((item, idx) => {
          const label = displayLabel(field, item.label);
          const barWidth = Math.max(
            2,
            ((item.value / max) * (chartWidth - 120)) | 0,
          );
          const y = idx * ROW_HEIGHT;
          return (
            <g key={`${field}-${idx}`} transform={`translate(0, ${y})`}>
              <text
                x={0}
                y={ROW_HEIGHT * 0.65}
                className="fill-current text-[10px]"
                fontSize={10}
              >
                {label.length > 24 ? `${label.slice(0, 22)}…` : label}
              </text>
              <rect
                x={110}
                y={ROW_HEIGHT * 0.2}
                width={barWidth}
                height={ROW_HEIGHT * 0.55}
                fill={barColor ?? "hsl(var(--primary))"}
                opacity={0.85}
                rx={2}
              />
              <text
                x={chartWidth - 4}
                y={ROW_HEIGHT * 0.65}
                textAnchor="end"
                className="fill-current text-[10px] tabular-nums"
                fontSize={10}
              >
                {item.value}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
