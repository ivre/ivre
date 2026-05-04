import { FacetGroup } from "@/components/FacetGroup";
import type { Filter, HighlightMap } from "@/lib/filter";
import type { SectionConfig } from "@/lib/sections";

export interface FacetSidebarProps {
  section: SectionConfig;
  query: string;
  highlights?: HighlightMap;
  onAddFilter: (filter: Filter) => void;
}

const FACET_LABELS: Record<string, string> = {
  country: "Country",
  as: "AS",
  asnum: "AS",
  "aut-num": "AS number",
  "as-name": "AS name",
  source_file: "Source file",
  "port:open": "Open ports",
  product: "Product",
  service: "Service",
  tag: "Tag",
  sensor: "Sensor",
  recontype: "Recon type",
  source: "Source",
  category: "Category",
};

/**
 * Sidebar containing one ``FacetGroup`` per facet declared by the
 * section config. Each group fires its own request to ``top/<field>``
 * via ``useTop``; that request is keyed on the active query so the
 * counts are kept in sync as the filter changes.
 */
export function FacetSidebar({
  section,
  query,
  highlights,
  onAddFilter,
}: FacetSidebarProps) {
  if (!section.topEndpoint || section.facets.length === 0) {
    return null;
  }
  return (
    <aside className="space-y-6">
      {section.facets.map((field) => (
        <FacetGroup
          key={field}
          field={field}
          label={FACET_LABELS[field] ?? field}
          topEndpoint={section.topEndpoint as string}
          query={query}
          highlights={highlights}
          onAddFilter={onAddFilter}
        />
      ))}
    </aside>
  );
}
