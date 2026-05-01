import { Construction } from "lucide-react";
import { useParams } from "react-router-dom";

import { getSection } from "@/lib/sections";

/**
 * Placeholder rendered for sections that don't have a real
 * implementation yet. The View section ships first; everything
 * else lands in follow-up PRs.
 */
export function SectionStub() {
  const { sectionId } = useParams<{ sectionId: string }>();
  const section = sectionId ? getSection(sectionId) : undefined;
  const label = section?.label ?? sectionId ?? "Section";

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
