import { Construction, EyeOff } from "lucide-react";
import { useParams } from "react-router-dom";

import { isModuleEnabled } from "@/lib/config";
import { getSection } from "@/lib/sections";

export interface SectionStubProps {
  /** Override the id resolution. Used by ``routes/root.tsx``'s
   *  module-gate wrapper, which renders this component for an
   *  *explicit* route (not the catch-all) and therefore has no
   *  ``:sectionId`` URL parameter to read. When unset, the
   *  component falls back to ``useParams<{ sectionId }>()``. */
  forceId?: string;
}

/**
 * Placeholder rendered for any path the explicit route table
 * does not match, AND for explicit section routes whose module
 * is disabled by the server's ``WEB_MODULES`` allowlist (via
 * the ``gateModule`` wrapper in ``routes/root.tsx``). Two
 * distinct cases:
 *
 *  - The id maps to a known section that the server has *not*
 *    exposed (``isModuleEnabled === false``): tell the operator
 *    the section is disabled by the server's ``WEB_MODULES``
 *    configuration.
 *  - The id is not a known section, or is a known section that
 *    is enabled but still in stub state during the rollout
 *    (currently only ``flow``): the original "under
 *    construction" copy.
 */
export function SectionStub({ forceId }: SectionStubProps = {}) {
  const params = useParams<{ sectionId: string }>();
  const sectionId = forceId ?? params.sectionId;
  const section = sectionId ? getSection(sectionId) : undefined;
  const label = section?.label ?? sectionId ?? "Section";

  // Disabled-by-server case: known section whose id is missing
  // from the server-side ``modules`` list. Use a different icon
  // and message so operators can distinguish the two.
  if (section && !isModuleEnabled(section.id)) {
    return (
      <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
        <EyeOff className="size-16 text-muted-foreground" aria-hidden />
        <h2 className="text-2xl font-semibold tracking-tight">{label}</h2>
        <p className="text-muted-foreground">
          This section is not exposed on this server. Ask your
          administrator about <code>WEB_MODULES</code> in
          <code> ivre.conf</code> and the corresponding
          <code> DB_</code>
          <em>purpose</em> backend.
        </p>
      </div>
    );
  }

  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <Construction className="size-16 text-muted-foreground" aria-hidden />
      <h2 className="text-2xl font-semibold tracking-tight">{label}</h2>
      <p className="text-muted-foreground">
        This section is under construction. Track progress in IVRE&rsquo;s
        roadmap; for now, use the View section to explore data.
      </p>
    </div>
  );
}
