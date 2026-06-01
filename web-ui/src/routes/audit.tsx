import { ScrollText } from "lucide-react";

import { AuditEventsPanel } from "@/components/AuditEventsPanel";
import { useAuthMe } from "@/lib/auth";
import { isAuthEnabled } from "@/lib/config";

/**
 * Self-service audit-log route ("My audit log").  Any
 * authenticated user can see their own trail here; the backend's
 * per-user gate (:func:`ivre.web.app._audit_read_gate` +
 * :func:`list_audit_events`) forces ``user_email = <caller>`` so
 * the same route is safe for non-admins.
 *
 * The cross-user / admin variant lives on the Admin route under
 * the "Audit log" tab; both consume :func:`AuditEventsTable`
 * for row rendering.
 *
 * Reachable from the user menu only — not in the section nav
 * (which is reserved for data sections: View / Active / Passive
 * / DNS / Flow / RIR).  Direct-URL access is allowed but gated
 * client-side:
 *
 * * ``window.config.auth_enabled`` is ``false``: render an
 *   informational placeholder (auth is off; the audit trail is
 *   not meaningful without an identifiable actor);
 * * ``GET /cgi/auth/me`` returns ``authenticated: false``: same
 *   placeholder.
 *
 * The backend enforces the same gating with HTTP 401 for the
 * read API itself, so a bypass attempt on the SPA does not leak
 * data.
 */
export function AuditRoute() {
  const authEnabled = isAuthEnabled();
  const meQuery = useAuthMe();

  if (!authEnabled) {
    return (
      <AuditGate message="Authentication is not enabled on this server." />
    );
  }

  if (meQuery.isLoading) {
    return null;
  }

  const me = meQuery.data;
  if (!me?.authenticated) {
    return (
      <AuditGate message="Sign in to view your audit log." />
    );
  }

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 px-6 py-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          My audit log
        </h1>
        <p className="text-sm text-muted-foreground">
          Signed in as <span className="font-mono">{me.email}</span>.
          Every API request you make against this server lands here:
          uploads, admin actions you perform, and query attempts
          rejected for exceeding the size cap.
        </p>
      </div>
      <AuditEventsPanel />
    </div>
  );
}

function AuditGate({ message }: { message: string }) {
  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <ScrollText
        className="size-16 text-muted-foreground"
        aria-hidden
      />
      <h2 className="text-2xl font-semibold tracking-tight">
        My audit log
      </h2>
      <p className="text-muted-foreground">{message}</p>
    </div>
  );
}
