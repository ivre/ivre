import { Share2 } from "lucide-react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { isModuleEnabled } from "@/lib/config";

export interface ShareMenuProps {
  /** Active ``q=`` filter string for the current section. */
  query: string;
}

/**
 * Share menu (legacy ``MENU_MAIN.share``): open Report / Compare
 * with the current filter pre-filled.
 */
export function ShareMenu({ query }: ShareMenuProps) {
  if (!isModuleEnabled("view")) {
    return null;
  }

  const qParam = query ? `?q=${encodeURIComponent(query)}` : "";
  const reportHref = `/report${qParam}`;
  const compareHref = `/compare${qParam}`;
  const currentHref =
    typeof window !== "undefined"
      ? `${window.location.pathname}${window.location.hash}`
      : `#/view${qParam}`;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5">
          <Share2 className="size-4" aria-hidden />
          Share
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem asChild>
          <a href={currentHref} target="_blank" rel="noopener noreferrer">
            New tab
          </a>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link to={reportHref}>Report</Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <Link to={compareHref}>Compare graphs</Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
