import { useCallback, useMemo } from "react";
import { useLocation, useSearchParams } from "react-router-dom";

import {
  buildHighlightMap,
  buildQueryFromFilters,
  parseFiltersFromQuery,
  stripMetaFilters,
  type Filter,
} from "@/lib/filter";
import { hostEvidenceFilters } from "@/lib/host-evidence";

/** The standalone and IP-scoped browsers share filtering behavior. The fixed
 * host is added to every request, never to the editable filter collection. */
export function useBrowseFilters(
  section: "view" | "active" | "passive",
  scopeAddr?: string,
) {
  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const filters = useMemo(() => {
    if (scopeAddr && section !== "view")
      return hostEvidenceFilters(searchParams, section);
    const parsed = parseFiltersFromQuery(searchParams.get("q") ?? "");
    return section === "view" ? stripMetaFilters(parsed) : parsed;
  }, [searchParams, section, scopeAddr]);
  const fixedFilters = useMemo<Filter[]>(
    () => (scopeAddr ? [{ type: "host", value: scopeAddr }] : []),
    [scopeAddr],
  );
  const allFilters = useMemo(
    () => [...fixedFilters, ...filters],
    [fixedFilters, filters],
  );
  const query = useMemo(() => buildQueryFromFilters(allFilters), [allFilters]);
  const highlights = useMemo(() => buildHighlightMap(allFilters), [allFilters]);
  const setFilters = useCallback(
    (next: Filter[]) => {
      const editable = scopeAddr
        ? stripMetaFilters(next).filter(
            (filter) =>
              !(
                filter.type === "host" &&
                filter.value === scopeAddr &&
                !filter.neg
              ),
          )
        : next;
      const nextQ = buildQueryFromFilters(editable);
      const params = new URLSearchParams(searchParams);
      const key = scopeAddr ? `${section}Q` : "q";
      if (nextQ) params.set(key, nextQ);
      else params.delete(key);
      if (scopeAddr) {
        params.delete(section === "active" ? "recordsSkip" : "passiveSkip");
        params.delete("section");
        params.delete("record");
        if (section === "passive") {
          for (const name of ["passivePort", "passiveType", "passiveSensor"])
            params.delete(name);
        }
      } else if (section === "view") params.delete("skip");
      setSearchParams(params, {
        state: scopeAddr ? location.state : undefined,
      });
    },
    [scopeAddr, section, searchParams, setSearchParams, location.state],
  );
  const addFilter = useCallback(
    (filter: Filter) => {
      if (
        allFilters.some(
          (item) =>
            item.type === filter.type &&
            item.value === filter.value &&
            Boolean(item.neg) === Boolean(filter.neg),
        )
      )
        return;
      setFilters([...filters, filter]);
    },
    [allFilters, filters, setFilters],
  );
  return {
    filters,
    fixedFilters,
    query,
    highlights,
    setFilters,
    addFilter,
    searchParams,
    setSearchParams,
    location,
  };
}
