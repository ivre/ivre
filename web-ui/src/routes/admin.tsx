import { ShieldAlert, SlidersHorizontal } from "lucide-react";

import { AdminApiKeysPanel } from "@/components/AdminApiKeysPanel";
import { AdminAuditEventsPanel } from "@/components/AdminAuditEventsPanel";
import { AdminUsersPanel } from "@/components/AdminUsersPanel";
import { Button } from "@/components/ui/button";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { useAuthMe } from "@/lib/auth";
import { isAuthEnabled } from "@/lib/config";

/**
 * Admin route. Three panels:
 *
 *  - **Users**: lists every user via ``/cgi/auth/admin/users``;
 *    quick toggles for ``is_active`` / ``is_admin``; an inline
 *    "Create user" form (PUT-as-upsert); a per-user dialog for
 *    display name / group membership.
 *  - **API keys** (audit view): lists every API key issued to
 *    every user via ``/cgi/auth/admin/api-keys``; admins can
 *    revoke any key from here. The same admin (like every
 *    other user) manages their own keys from the
 *    ``/api-keys`` self-service page.
 *  - **Audit log**: cross-user audit trail via
 *    ``/cgi/audit/``; admins can filter by ``user_email`` to
 *    pivot to one user's trail.  The matching self-service
 *    surface (the caller's own trail) lives at ``/audit``.
 *
 * The Admin route is reachable from the user menu only — it
 * does not appear in the section nav (which is reserved for
 * data sections: View / Active / Passive / DNS / ...).
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
          <TabsTrigger value="audit">Audit log</TabsTrigger>
        </TabsList>
        <TabsContent value="users">
          <AdminUsersPanel />
        </TabsContent>
        <TabsContent value="api-keys">
          <AdminApiKeysPanel />
        </TabsContent>
        <TabsContent value="audit" className="space-y-3">
          <div className="flex justify-end">
            <Button asChild variant="outline" size="sm">
              <a href="#/audit/explorer" data-testid="admin-audit-open-explorer">
                <SlidersHorizontal className="size-4" aria-hidden />
                Open Explorer
              </a>
            </Button>
          </div>
          <AdminAuditEventsPanel />
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
