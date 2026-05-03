import { KeyRound, LogIn, LogOut, ShieldCheck, User } from "lucide-react";
import { useState } from "react";

import { SignInDialog } from "@/components/SignInDialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuthConfig, useAuthMe, useLogout } from "@/lib/auth";
import { isAuthEnabled } from "@/lib/config";

/**
 * Authentication menu slot for the AppShell's top-right corner.
 *
 * Three states, driven by ``window.config.auth_enabled`` (from
 * ``/cgi/config``) and ``GET /cgi/auth/me``:
 *
 *  - ``auth_enabled === false``: nothing is rendered (the operator
 *    opted out of authentication entirely).
 *  - Authenticated: a dropdown showing the user's display name /
 *    email, an "API keys" shortcut to the self-service
 *    ``/api-keys`` page, an admin shortcut when ``is_admin``,
 *    and a sign-out action.
 *  - Anonymous: a "Sign in" button that opens ``SignInDialog``.
 *    The dialog pulls the available providers and magic-link
 *    availability from ``GET /cgi/auth/config``.
 */
export function UserMenu() {
  const authEnabled = isAuthEnabled();
  // Hooks must run unconditionally; we no-op the queries by
  // returning early after they're declared.
  const meQuery = useAuthMe();
  const configQuery = useAuthConfig();
  const logoutMut = useLogout();
  const [signInOpen, setSignInOpen] = useState(false);

  if (!authEnabled) {
    return null;
  }

  // Loading: render nothing while the first ``/cgi/auth/me`` call
  // is in flight to avoid the "Sign in" button briefly flashing on
  // top of an already-authenticated session.
  if (meQuery.isLoading) {
    return null;
  }

  const me = meQuery.data;
  const authConfig = configQuery.data ?? {
    enabled: false,
    providers: [],
    magic_link: false,
  };

  if (!me?.authenticated) {
    return (
      <>
        <Button
          variant="ghost"
          size="sm"
          aria-label="Sign in"
          onClick={() => setSignInOpen(true)}
        >
          <LogIn className="size-4" />
          Sign in
        </Button>
        <SignInDialog
          open={signInOpen}
          onOpenChange={setSignInOpen}
          authConfig={authConfig}
        />
      </>
    );
  }

  const displayName = me.display_name ?? me.email ?? "";
  const handleSignOut = () => {
    logoutMut.mutate(undefined, {
      onSettled: () => {
        // Hard reload: drop any in-memory state from queries that
        // were authorised and are about to start failing with 401
        // now that the session cookie is gone.
        window.location.reload();
      },
    });
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label="Account menu">
          <User className="size-4" />
          <span className="max-w-32 truncate">{displayName}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-56">
        <DropdownMenuLabel className="flex flex-col gap-0.5">
          <span className="font-medium">{displayName}</span>
          {me.email && me.email !== displayName ? (
            <span className="text-xs font-normal text-muted-foreground">
              {me.email}
            </span>
          ) : null}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <a href="#/api-keys">
            <KeyRound className="size-4" />
            API keys
          </a>
        </DropdownMenuItem>
        {me.is_admin ? (
          <DropdownMenuItem asChild>
            <a href="#/admin">
              <ShieldCheck className="size-4" />
              Admin
            </a>
          </DropdownMenuItem>
        ) : null}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={(e) => {
            e.preventDefault();
            handleSignOut();
          }}
          disabled={logoutMut.isPending}
        >
          <LogOut className="size-4" />
          {logoutMut.isPending ? "Signing out…" : "Sign out"}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
