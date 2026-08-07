import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { ChartPanel } from "@/components/charts/ChartPanel";
import { TopValuesChart } from "@/components/charts/TopValuesChart";
import { CompareCounters } from "@/components/CompareCounters";
import { FilterBar } from "@/components/FilterBar";
import { WorldMap } from "@/components/WorldMap";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useCoordinates } from "@/lib/api";
import {
  applyCompareToSearchParams,
  deriveCompareQueries,
  parseCompareFromSearchParams,
  type CompareFilterKey,
  type CompareFilterState,
} from "@/lib/compare-filters";
import { isModuleEnabled } from "@/lib/config";
import { type Filter } from "@/lib/filter";
import { getSection } from "@/lib/sections";

const VIEW_SECTION = getSection("view")!;

type CompareChartKind = "map" | "top" | null;

/**
 * Side-by-side graph comparison for two filter sets (legacy
 * ``compare.html`` / ``IvreCompareCtrl``). Common filters live in
 * ``?q=``; set-specific additions in ``?set1=`` / ``?set2=``.
 */
export function CompareRoute() {
  if (!isModuleEnabled("view")) {
    return <CompareModuleGate />;
  }

  return <CompareRouteInner />;
}

function CompareRouteInner() {
  const [searchParams, setSearchParams] = useSearchParams();
  const state = useMemo(
    () => parseCompareFromSearchParams(searchParams),
    [searchParams],
  );
  const queries = useMemo(() => deriveCompareQueries(state), [state]);

  const [topField, setTopField] = useState("port:open");
  const [chartKind, setChartKind] = useState<CompareChartKind>(null);
  const [buildGeneration, setBuildGeneration] = useState(0);

  const setFilterKey = useCallback(
    (key: CompareFilterKey, filters: Filter[]) => {
      const params = new URLSearchParams(searchParams);
      const next: CompareFilterState = { ...state, [key]: filters };
      applyCompareToSearchParams(next, params);
      setSearchParams(params, { replace: false });
    },
    [searchParams, setSearchParams, state],
  );

  const showCharts = chartKind !== null && buildGeneration > 0;

  const buildMap = () => {
    setChartKind("map");
    setBuildGeneration((g) => g + 1);
  };

  const buildTop = () => {
    setChartKind("top");
    setBuildGeneration((g) => g + 1);
  };

  const hideCharts = () => {
    setChartKind(null);
  };

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 px-6 py-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Compare graphs
        </h1>
        <p className="text-sm text-muted-foreground">
          Define a common filter plus two sets, then render matching charts
          side by side against the view database.
        </p>
      </div>

      <div className="grid gap-4 xl:grid-cols-4">
        <CompareCounters queries={queries} />
        <FilterColumn
          title="Common filters"
          filters={state.common}
          onChange={(f) => setFilterKey("common", f)}
        />
        <FilterColumn
          title="Filters for set 1"
          filters={state.set1}
          onChange={(f) => setFilterKey("set1", f)}
        />
        <FilterColumn
          title="Filters for set 2"
          filters={state.set2}
          onChange={(f) => setFilterKey("set2", f)}
        />
      </div>

      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-muted/20 p-3">
        <form
          className="flex min-w-[12rem] flex-1 items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            buildTop();
          }}
        >
          <Input
            placeholder="Top values field"
            value={topField}
            onChange={(e) => setTopField(e.target.value)}
            aria-label="Top values field"
            className="max-w-xs"
          />
          <Button type="submit" variant="secondary">
            Top values
          </Button>
        </form>
        <Button type="button" variant="secondary" onClick={buildMap}>
          Map
        </Button>
      </div>

      {showCharts ? (
        <div className="grid gap-4 md:grid-cols-2">
          <CompareChartSlot
            label="Set 1"
            kind={chartKind}
            query={queries.set1Q}
            topField={topField}
            buildGeneration={buildGeneration}
            onClose={hideCharts}
          />
          <CompareChartSlot
            label="Set 2"
            kind={chartKind}
            query={queries.set2Q}
            topField={topField}
            buildGeneration={buildGeneration}
            onClose={hideCharts}
          />
        </div>
      ) : null}
    </div>
  );
}

function FilterColumn({
  title,
  filters,
  onChange,
}: {
  title: string;
  filters: Filter[];
  onChange: (filters: Filter[]) => void;
}) {
  return (
    <div className="space-y-2 rounded-md border border-border p-3">
      <h2 className="text-sm font-semibold">{title}</h2>
      <FilterBar filters={filters} onFiltersChange={onChange} />
    </div>
  );
}

function CompareChartSlot({
  label,
  kind,
  query,
  topField,
  buildGeneration,
  onClose,
}: {
  label: string;
  kind: CompareChartKind;
  query: string;
  topField: string;
  buildGeneration: number;
  onClose: () => void;
}) {
  const enabled = buildGeneration > 0 && Boolean(query);
  const coordsQuery = useCoordinates(VIEW_SECTION.mapEndpoint, { q: query }, {
    enabled: enabled && kind === "map",
  });

  const title =
    kind === "map"
      ? `${label} — Map`
      : `${label} — Top ${topField}`;

  return (
    <ChartPanel title={title} onClose={onClose}>
      {!query ? (
        <p className="text-sm italic text-muted-foreground">
          No filter query for this set.
        </p>
      ) : kind === "map" ? (
        <WorldMap data={coordsQuery.data} />
      ) : (
        <TopValuesChart
          topEndpoint={VIEW_SECTION.topEndpoint!}
          field={topField}
          query={query}
          limit={10}
          enabled={enabled}
        />
      )}
    </ChartPanel>
  );
}

function CompareModuleGate() {
  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <h2 className="text-2xl font-semibold tracking-tight">
        Compare not available
      </h2>
      <p className="text-muted-foreground">
        The view module is not exposed on this server. Check{" "}
        <code className="text-xs">WEB_MODULES</code> and your database
        configuration.
      </p>
    </div>
  );
}
