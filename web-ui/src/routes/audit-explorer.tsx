import { ScrollText } from "lucide-react";

import { AuditExplorer } from "@/components/AuditExplorer";
import { useAuthMe } from "@/lib/auth";
import { isAuthEnabled } from "@/lib/config";

/**
 * Full audit-log Explorer route (``/audit/explorer``).
 *
 * Reached from the Admin "Audit log" tab's "Open Explorer"
 * link, or directly by URL.  Any authenticated user may open it:
 * the backend's per-user gate
 * (:func:`ivre.web.app._audit_read_gate`) scopes a non-admin to
 * their own trail, while an admin sees every user's events and
 * can filter by ``user_email``.
 *
 * Like the other account/admin surfaces it is *not* a data
 * section (absent from the nav), and the access gate mirrors
 * ``/audit``: render an informational placeholder when auth is
 * disabled server-side or the caller is anonymous.  The backend
 * enforces the same with HTTP 401, so a client-side bypass leaks
 * nothing.
 */
export function AuditExplorerRoute() {
  const authEnabled = isAuthEnabled();
  const meQuery = useAuthMe();

  if (!authEnabled) {
    return (
      <AuditExplorerGate message="Authentication is not enabled on this server." />
    );
  }

  if (meQuery.isLoading) {
    return null;
  }

  const me = meQuery.data;
  if (!me?.authenticated) {
    return (
      <AuditExplorerGate message="Sign in to explore the audit log." />
    );
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 px-6 py-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Audit log explorer
        </h1>
        <p className="text-sm text-muted-foreground">
          {me.is_admin ? (
            <>
              Signed in as{" "}
              <span className="font-mono">{me.email}</span> (admin).
              Filter across every user's audit trail; click a row
              for the full event record.
            </>
          ) : (
            <>
              Signed in as{" "}
              <span className="font-mono">{me.email}</span>. You see
              your own audit trail; click a row for the full event
              record.
            </>
          )}
        </p>
      </div>
      <AuditExplorer />
    </div>
  );
}

function AuditExplorerGate({ message }: { message: string }) {
  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <ScrollText
        className="size-16 text-muted-foreground"
        aria-hidden
      />
      <h2 className="text-2xl font-semibold tracking-tight">
        Audit log explorer
      </h2>
      <p className="text-muted-foreground">{message}</p>
    </div>
  );
}
