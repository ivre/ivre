/**
 * Configurable chart rows for the Report page (legacy
 * ``IvreReportCtrl.elements``).
 */

export type ReportElementType = "Top-values" | "Map + Top-values";

export interface ReportElement {
  type: ReportElementType;
  /** Top field path (e.g. ``country``, ``port:open``). */
  parameters: string;
  /** Heading shown above the chart. */
  text: string;
  /** Index into ``REPORT_COLORS``. */
  color: number;
}

export interface ReportColor {
  bg: string;
  fg: string;
}

/** Palette from legacy ``IvreReportCtrl`` (Bootstrap-era hex). */
export const REPORT_COLORS: readonly ReportColor[] = [
  { bg: "#FFFFFF", fg: "black" },
  { bg: "#CF5044", fg: "white" },
  { bg: "#5B9BD5", fg: "white" },
  { bg: "#73B348", fg: "white" },
  { bg: "#F37F31", fg: "white" },
  { bg: "#4674CA", fg: "white" },
] as const;

export const REPORT_ELEMENT_TYPES: readonly ReportElementType[] = [
  "Top-values",
  "Map + Top-values",
] as const;

export const DEFAULT_REPORT_ELEMENTS: readonly ReportElement[] = [
  {
    type: "Map + Top-values",
    parameters: "country",
    text: "Top countries",
    color: 0,
  },
  {
    type: "Top-values",
    parameters: "port:open",
    text: "Top ports",
    color: 1,
  },
  {
    type: "Top-values",
    parameters: "as",
    text: "Top AS",
    color: 2,
  },
];

export function cloneReportElements(
  elements: readonly ReportElement[],
): ReportElement[] {
  return elements.map((e) => ({ ...e }));
}

export function swapReportElements(
  elements: ReportElement[],
  from: number,
  to: number,
): ReportElement[] {
  if (from < 0 || to < 0 || from >= elements.length || to >= elements.length) {
    return elements;
  }
  const next = [...elements];
  const tmp = next[from];
  next[from] = next[to];
  next[to] = tmp;
  return next;
}
