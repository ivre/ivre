import { useLocation } from "react-router-dom";

function previousOffsets(
  value: unknown,
  query: string,
  limit: number,
  skip: number,
): number[] {
  if (
    !value ||
    typeof value !== "object" ||
    !("query" in value) ||
    value.query !== query ||
    !("limit" in value) ||
    value.limit !== limit ||
    !("skip" in value) ||
    value.skip !== skip ||
    !("previous" in value) ||
    !Array.isArray(value.previous)
  )
    return [];
  const offsets: unknown[] = value.previous;
  let last = -1;
  const previous: number[] = [];
  for (const offset of offsets) {
    if (
      typeof offset !== "number" ||
      !Number.isSafeInteger(offset) ||
      offset <= last ||
      offset >= skip
    )
      return [];
    previous.push(offset);
    last = offset;
  }
  return previous;
}

/** Keep real page boundaries in browser history: server caps can make each
 * response shorter than the requested limit, including by different amounts.
 * Query/limit matching prevents reusing boundaries after a filter change. */
export function useReportPaging(
  source: string,
  query: string,
  limit: number,
  skip: number,
) {
  const { state } = useLocation();
  const previous = previousOffsets(
    state?.reportPaging?.[source],
    query,
    limit,
    skip,
  );
  return {
    // A fresh deep link has no visited boundaries; retain the requested-window
    // fallback until the user navigates to another page.
    previousSkip: previous.at(-1) ?? Math.max(0, skip - limit),
    stateForSkip: (nextSkip: number) => ({
      ...state,
      reportPaging: {
        ...state?.reportPaging,
        [source]: {
          query,
          limit,
          skip: nextSkip,
          previous:
            nextSkip > skip
              ? [...previous, skip]
              : previous.filter((offset) => offset < nextSkip),
        },
      },
    }),
  };
}
