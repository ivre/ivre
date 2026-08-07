/**
 * Three-way filter state for the Compare page: common filters plus
 * per-set additions. Query derivation mirrors legacy ``SubFilter``
 * composition in ``web/static/ivre/filters.js``.
 */

import {
  buildQueryFromFilters,
  parseFiltersFromQuery,
  stripMetaFilters,
  type Filter,
} from "@/lib/filter";

export interface CompareFilterState {
  common: Filter[];
  set1: Filter[];
  set2: Filter[];
}

export interface CompareQueries {
  commonQ: string;
  set1Q: string;
  set2Q: string;
  allSetsQ: string;
}

export function emptyCompareFilterState(): CompareFilterState {
  return { common: [], set1: [], set2: [] };
}

export function parseCompareFromSearchParams(
  params: URLSearchParams,
): CompareFilterState {
  return {
    common: stripMetaFilters(parseFiltersFromQuery(params.get("q") ?? "")),
    set1: stripMetaFilters(parseFiltersFromQuery(params.get("set1") ?? "")),
    set2: stripMetaFilters(parseFiltersFromQuery(params.get("set2") ?? "")),
  };
}

/** Write compare filter arrays into ``params`` (deletes empty keys). */
export function applyCompareToSearchParams(
  state: CompareFilterState,
  params: URLSearchParams,
): void {
  const commonQ = buildQueryFromFilters(state.common);
  const set1Q = buildQueryFromFilters(state.set1);
  const set2Q = buildQueryFromFilters(state.set2);
  if (commonQ) params.set("q", commonQ);
  else params.delete("q");
  if (set1Q) params.set("set1", set1Q);
  else params.delete("set1");
  if (set2Q) params.set("set2", set2Q);
  else params.delete("set2");
}

export function deriveCompareQueries(state: CompareFilterState): CompareQueries {
  const commonQ = buildQueryFromFilters(state.common);
  const set1Only = buildQueryFromFilters(state.set1);
  const set2Only = buildQueryFromFilters(state.set2);
  const set1Q = [commonQ, set1Only].filter(Boolean).join(" ");
  const set2Q = [commonQ, set2Only].filter(Boolean).join(" ");
  const allSetsQ = [set1Q, set2Q].filter(Boolean).join(" ");
  return { commonQ, set1Q, set2Q, allSetsQ };
}

export type CompareFilterKey = keyof CompareFilterState;
