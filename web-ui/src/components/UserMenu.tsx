import { LogIn, LogOut, User } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { isAuthEnabled } from "@/lib/config";

/**
 * Authentication menu slot for the AppShell's top-right corner.
 *
 * Behaviour:
 *  - When ``config.auth_enabled`` is false: renders nothing (the
 *    operator opted out of authentication entirely).
 *  - When auth is enabled and the user is anonymous: a ``Sign in``
 *    button. The actual sign-in flow against ``/cgi/auth/*`` is
 *    intentionally not wired in this PR — see PR-Auth.
 *  - When auth is enabled and the user is signed in: a dropdown
 *    with the user identity and a ``Sign out`` action.
 *
 * The current implementation always falls into the "anonymous"
 * branch (no session check yet). ``PR-Auth`` will add the
 * ``/cgi/auth/check`` round-trip and populate the menu.
 */
export function UserMenu() {
  const authEnabled = isAuthEnabled();

  if (!authEnabled) {
    return null;
  }

  // PR-Auth: replace this with a real session check
  // (e.g. ``useQuery({ queryKey: ['session'], queryFn: ... })``).
  const user: { name: string } | null = null;

  if (!user) {
    return (
      <Button variant="ghost" size="sm" aria-label="Sign in" disabled>
        <LogIn className="size-4" />
        Sign in
      </Button>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label="Account menu">
          <User className="size-4" />
          {(user as { name: string }).name}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>Account</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem disabled>
          <LogOut className="size-4" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
