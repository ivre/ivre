import { NavLink, Outlet, useLocation } from "react-router-dom";

import { ThemeToggle } from "@/components/ThemeToggle";
import { UserMenu } from "@/components/UserMenu";
import { SECTIONS, type SectionConfig } from "@/lib/sections";
import { cn } from "@/lib/utils";

/**
 * Top-level chrome: brand on the left, section nav in the centre,
 * theme toggle and user menu on the right. The active route is
 * rendered through ``<Outlet />`` (react-router).
 *
 * The section nav is reserved for *data* sections (View, Active,
 * Passive, DNS, Flow, RIR). Account / admin pages — Admin, the
 * self-service API keys page — are surfaced exclusively through
 * ``UserMenu``; they are registered as routes in
 * ``routes/root.tsx`` but absent from ``SECTIONS``.
 */
export function AppShell() {
  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
        <div className="flex h-14 w-full items-center gap-4 px-6">
          <Brand />
          <nav className="flex flex-1 items-center justify-center gap-1">
            {SECTIONS.map((section) => (
              <SectionLink key={section.id} section={section} />
            ))}
          </nav>
          <div className="flex items-center gap-1">
            <UserMenu />
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main className="flex-1">
        <Outlet />
      </main>
    </div>
  );
}

function Brand() {
  return (
    <NavLink
      to="/view"
      className="flex items-center gap-2 font-semibold"
      aria-label="IVRE home"
    >
      <img src="favicon.png" alt="" className="h-6 w-6" />
      <span className="text-lg">IVRE</span>
    </NavLink>
  );
}

function SectionLink({ section }: { section: SectionConfig }) {
  // We use ``useLocation`` rather than NavLink's built-in active
  // detection because hash-router paths are sub-paths of the
  // current SPA URL; NavLink works fine but we want a custom
  // ``aria-current`` and pill style.
  const { pathname } = useLocation();
  const active = pathname === `/${section.id}` || pathname.startsWith(`/${section.id}/`);

  return (
    <NavLink
      to={`/${section.id}`}
      aria-current={active ? "page" : undefined}
      className={cn(
        "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
        active
          ? "bg-primary text-primary-foreground"
          : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
      )}
    >
      {section.label}
    </NavLink>
  );
}
