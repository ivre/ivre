import { ShieldAlert } from "lucide-react";

import { AdminUsersPanel } from "@/components/AdminUsersPanel";
import { ApiKeysPanel } from "@/components/ApiKeysPanel";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { useAuthMe } from "@/lib/auth";
import { isAuthEnabled } from "@/lib/config";

/**
 * Admin section route. Two panels:
 *
 *  - **Users**: lists every user via ``/cgi/auth/admin/users``;
 *    quick toggles for ``is_active`` / ``is_admin``; an inline
 *    "Create user" form (PUT-as-upsert); a per-user dialog for
 *    display name / group membership.
 *  - **API keys**: lists the current user's keys via
 *    ``/cgi/auth/api-keys``; create a new key (response
 *    surfaces the secret once, in a copy-to-clipboard dialog);
 *    revoke an existing key.
 *
 * Access is guarded client-side: when ``window.config.auth_enabled``
 * is false, or when ``GET /cgi/auth/me`` returns
 * ``{authenticated: false}`` or ``is_admin: false``, an
 * informational placeholder is rendered instead of the panels.
 * The backend enforces the same gating with HTTP 401 / 403.
 */
export function AdminRoute() {
  const authEnabled = isAuthEnabled();
  const meQuery = useAuthMe();

  if (!authEnabled) {
    return <AdminGate message="Authentication is not enabled on this server." />;
  }

  if (meQuery.isLoading) {
    return null;
  }

  const me = meQuery.data;
  if (!me?.authenticated) {
    return (
      <AdminGate message="Sign in with an admin account to access this section." />
    );
  }
  if (!me.is_admin) {
    return (
      <AdminGate message="Your account does not have admin privileges." />
    );
  }

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 px-6 py-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Admin</h1>
        <p className="text-sm text-muted-foreground">
          Signed in as{" "}
          <span className="font-mono">{me.email}</span>.
        </p>
      </div>

      <Tabs defaultValue="users" className="space-y-4">
        <TabsList>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="api-keys">API keys</TabsTrigger>
        </TabsList>
        <TabsContent value="users">
          <AdminUsersPanel />
        </TabsContent>
        <TabsContent value="api-keys">
          <ApiKeysPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function AdminGate({ message }: { message: string }) {
  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <ShieldAlert
        className="size-16 text-muted-foreground"
        aria-hidden
      />
      <h2 className="text-2xl font-semibold tracking-tight">Admin</h2>
      <p className="text-muted-foreground">{message}</p>
    </div>
  );
}
