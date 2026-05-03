import { KeyRound } from "lucide-react";

import { MyApiKeysPanel } from "@/components/MyApiKeysPanel";
import { useAuthMe } from "@/lib/auth";
import { isAuthEnabled } from "@/lib/config";

/**
 * Self-service API-key management route. Any authenticated
 * user (admin or not) can manage their own keys here. The
 * same backend route is owner-scoped: admins see only their
 * own keys on this page. Cross-user audit / revocation lives
 * on the Admin route's "API keys" tab.
 *
 * Like the Admin route, this page is reachable from the user
 * menu only — it does not appear in the section nav.
 *
 * Access is guarded client-side: when
 * ``window.config.auth_enabled`` is false, or when
 * ``GET /cgi/auth/me`` returns ``{authenticated: false}``,
 * an informational placeholder is rendered instead of the
 * panel. The backend enforces the same gating with HTTP 401.
 */
export function ApiKeysRoute() {
  const authEnabled = isAuthEnabled();
  const meQuery = useAuthMe();

  if (!authEnabled) {
    return (
      <ApiKeysGate message="Authentication is not enabled on this server." />
    );
  }

  if (meQuery.isLoading) {
    return null;
  }

  const me = meQuery.data;
  if (!me?.authenticated) {
    return (
      <ApiKeysGate message="Sign in to manage your API keys." />
    );
  }

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 px-6 py-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">API keys</h1>
        <p className="text-sm text-muted-foreground">
          Signed in as <span className="font-mono">{me.email}</span>. Keys
          listed here are owned by you; they grant the same access your
          session does, until you revoke them.
        </p>
      </div>
      <MyApiKeysPanel />
    </div>
  );
}

function ApiKeysGate({ message }: { message: string }) {
  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <KeyRound
        className="size-16 text-muted-foreground"
        aria-hidden
      />
      <h2 className="text-2xl font-semibold tracking-tight">API keys</h2>
      <p className="text-muted-foreground">{message}</p>
    </div>
  );
}
