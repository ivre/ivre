import { Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";

import { Button } from "@/components/ui/button";

/**
 * Sun/moon button that toggles between light and dark modes.
 *
 * ``next-themes`` handles persistence and ``prefers-color-scheme``
 * defaults; we just flip ``light`` ↔ ``dark`` from the current
 * resolved theme. Clicking on ``system`` collapses to whatever the
 * OS reports next.
 */
export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      onClick={() => setTheme(isDark ? "light" : "dark")}
    >
      {isDark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </Button>
  );
}
