import {
  buildQueryFromFilters,
  parseFiltersFromQuery,
  stripMetaFilters,
  type Filter,
} from "@/lib/filter";

export type EvidenceSource = "active" | "passive";

/** Evidence filters have their own URL namespace, separate from the search
 * that originally opened the IP report. Older port/type links still work. */
export function hostEvidenceFilters(
  params: URLSearchParams,
  source: EvidenceSource,
): Filter[] {
  const query = params.get(`${source}Q`);
  if (query !== null) return stripMetaFilters(parseFiltersFromQuery(query));
  if (source === "active") {
    // In older scan permalinks, section is a reading anchor, not a filter.
    if (params.has("record")) return [];
    const port = /^port-(tcp|udp)-(\d+)$/.exec(params.get("section") ?? "");
    return port && Number(port[2]) <= 65535
      ? [{ value: `${port[1]}/${port[2]}` }]
      : [];
  }
  const filters: Filter[] = [];
  const port = params.get("passivePort") ?? "";
  if (/^\d+$/.test(port) && Number(port) <= 65535)
    filters.push({ value: `tcp/${Number(port)}` });
  const type = params.get("passiveType");
  const sensor = params.get("passiveSensor");
  if (type) filters.push({ type: "recontype", value: type });
  if (sensor) filters.push({ type: "sensor", value: sensor });
  return filters;
}

export function hostEvidenceQuery(
  addr: string,
  filters: readonly Filter[],
): string {
  return buildQueryFromFilters([
    { type: "host", value: addr },
    ...stripMetaFilters(filters),
  ]);
}
