import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { TopValuesChart } from "@/components/charts/TopValuesChart";
import { FilterBar, useFilterTitle } from "@/components/FilterBar";
import { ReportElementEditor } from "@/components/ReportElementEditor";
import { WorldMap } from "@/components/WorldMap";
import { Button } from "@/components/ui/button";
import { useCoordinates } from "@/lib/api";
import {
  buildQueryFromFilters,
  parseFiltersFromQuery,
  stripMetaFilters,
  type Filter,
} from "@/lib/filter";
import { isModuleEnabled } from "@/lib/config";
import {
  cloneReportElements,
  DEFAULT_REPORT_ELEMENTS,
  REPORT_COLORS,
  type ReportElement,
} from "@/lib/report-elements";
import { getSection } from "@/lib/sections";
import { cn } from "@/lib/utils";

const VIEW_SECTION = getSection("view")!;

/**
 * Configurable multi-chart report (legacy ``report.html`` /
 * ``IvreReportCtrl``). Filter travels in ``?q=``; chart rows are
 * edited locally until the operator clicks Build.
 */
export function ReportRoute() {
  if (!isModuleEnabled("view")) {
    return <ReportModuleGate />;
  }

  return <ReportRouteInner />;
}

function ReportRouteInner() {
  const [searchParams, setSearchParams] = useSearchParams();
  const filters: Filter[] = useMemo(() => {
    const parsed = parseFiltersFromQuery(searchParams.get("q") ?? "");
    return stripMetaFilters(parsed);
  }, [searchParams]);
  const query = useMemo(() => buildQueryFromFilters(filters), [filters]);
  useFilterTitle(filters);

  const [showConfig, setShowConfig] = useState(true);
  const [elements, setElements] = useState<ReportElement[]>(() =>
    cloneReportElements(DEFAULT_REPORT_ELEMENTS),
  );
  const [buildGeneration, setBuildGeneration] = useState(0);

  const [curType, setCurType] = useState<ReportElement["type"]>("Top-values");
  const [curTitle, setCurTitle] = useState("");
  const [curParam, setCurParam] = useState("");
  const [curColor, setCurColor] = useState(1);

  const setFilters = useCallback(
    (next: Filter[]) => {
      const nextQ = buildQueryFromFilters(next);
      const params = new URLSearchParams(searchParams);
      if (nextQ) params.set("q", nextQ);
      else params.delete("q");
      params.delete("skip");
      setSearchParams(params, { replace: false });
    },
    [searchParams, setSearchParams],
  );

  const addElement = () => {
    setElements((prev) => [
      ...prev,
      {
        type: curType,
        parameters: curParam,
        text: curTitle,
        color: curColor,
      },
    ]);
    setCurType("Top-values");
    setCurTitle("");
    setCurParam("");
    setCurColor(1);
  };

  const built = buildGeneration > 0;

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 px-6 py-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">IVRE Report</h1>
        <p className="text-sm text-muted-foreground">
          Build a printable dashboard of top-value charts and maps for the
          merged view database.
        </p>
      </div>

      {showConfig ? (
        <section className="space-y-4 rounded-lg border border-border p-4">
          <h2 className="text-lg font-semibold">Configuration</h2>
          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <div className="space-y-4">
              <FilterBar filters={filters} onFiltersChange={setFilters} />
              <div className="flex flex-col gap-2">
                <Button type="button" onClick={() => setBuildGeneration((g) => g + 1)}>
                  Build
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowConfig(false)}
                >
                  Hide configuration
                </Button>
              </div>
            </div>
            <ReportElementEditor
              elements={elements}
              onChange={setElements}
              curType={curType}
              onCurTypeChange={setCurType}
              curTitle={curTitle}
              onCurTitleChange={setCurTitle}
              curParam={curParam}
              onCurParamChange={setCurParam}
              curColor={curColor}
              onCurColorChange={setCurColor}
              onAdd={addElement}
            />
          </div>
        </section>
      ) : (
        <Button type="button" variant="outline" onClick={() => setShowConfig(true)}>
          Show configuration
        </Button>
      )}

      <header className="rounded-lg border border-border bg-muted/30 px-6 py-8 text-center">
        <h2 className="text-xl font-semibold">IVRE Report</h2>
        {query ? (
          <p className="mt-2 text-sm">
            With filter{filters.length > 1 ? "s" : ""}{" "}
            <span className="font-mono text-destructive">{query}</span>
          </p>
        ) : (
          <p className="mt-2 text-sm text-muted-foreground">No filter applied.</p>
        )}
      </header>

      <div className="space-y-8">
        {elements.map((element, index) => (
          <ReportElementBlock
            key={`${index}-${element.parameters}-${buildGeneration}`}
            element={element}
            query={query}
            built={built}
          />
        ))}
      </div>
    </div>
  );
}

function ReportElementBlock({
  element,
  query,
  built,
}: {
  element: ReportElement;
  query: string;
  built: boolean;
}) {
  const palette = REPORT_COLORS[element.color] ?? REPORT_COLORS[0];
  const barColor =
    palette.fg === "white" ? "rgba(255,255,255,0.9)" : "hsl(var(--primary))";
  const topLimit = element.type === "Map + Top-values" ? 6 : 10;
  const topSize = element.type === "Map + Top-values" ? 6 : 10;

  const coordsQuery = useCoordinates(VIEW_SECTION.mapEndpoint, { q: query }, {
    enabled: built && element.type === "Map + Top-values",
  });

  return (
    <section
      className="rounded-lg p-4"
      style={{ backgroundColor: palette.bg, color: palette.fg }}
    >
      {element.text ? (
        <h3 className="mb-4 text-center text-lg font-semibold">{element.text}</h3>
      ) : null}
      <div
        className={cn(
          "grid gap-4",
          element.type === "Map + Top-values"
            ? "lg:grid-cols-2"
            : "mx-auto max-w-3xl",
        )}
      >
        {element.type === "Map + Top-values" ? (
          <WorldMap data={built ? coordsQuery.data : undefined} />
        ) : null}
        <TopValuesChart
          topEndpoint={VIEW_SECTION.topEndpoint!}
          field={element.parameters}
          query={query}
          limit={topLimit}
          size={topSize}
          enabled={built}
          barColor={barColor}
        />
      </div>
    </section>
  );
}

function ReportModuleGate() {
  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <h2 className="text-2xl font-semibold tracking-tight">
        Report not available
      </h2>
      <p className="text-muted-foreground">
        The view module is not exposed on this server. Check{" "}
        <code className="text-xs">WEB_MODULES</code> and your database
        configuration.
      </p>
    </div>
  );
}
