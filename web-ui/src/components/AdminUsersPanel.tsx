import {
  CheckCircle2,
  Pencil,
  ShieldCheck,
  ShieldOff,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { EditUserDialog } from "@/components/EditUserDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  useAdminUsers,
  useUpdateAdminUser,
  type AdminUser,
} from "@/lib/admin";
import { cn } from "@/lib/utils";

/**
 * Admin user list. Each row carries quick toggles for
 * ``is_active`` and ``is_admin`` (single PUT roundtrip), and an
 * Edit button that opens the per-user dialog for display name
 * and group membership. A "Create user" form at the top creates
 * a new user via PUT-as-upsert (the backend's
 * ``/cgi/auth/admin/users/<email>`` endpoint creates on missing
 * target).
 */
export function AdminUsersPanel() {
  const usersQuery = useAdminUsers();
  const updateMut = useUpdateAdminUser();
  const [editing, setEditing] = useState<AdminUser | null>(null);
  const [newEmail, setNewEmail] = useState("");

  const toggle = (u: AdminUser, field: "is_active" | "is_admin") => {
    const next = !u[field];
    updateMut.mutate(
      { email: u.email, update: { [field]: next } },
      {
        onSuccess: () => {
          toast.success(
            `${u.email}: ${field} = ${next ? "true" : "false"}`,
          );
        },
        onError: (err) => toast.error(err.message),
      },
    );
  };

  const createUser = () => {
    const trimmed = newEmail.trim();
    if (!trimmed || !trimmed.includes("@")) {
      toast.error("Enter a valid email address.");
      return;
    }
    updateMut.mutate(
      // Defaults: active, non-admin, no display_name override.
      // The backend's PUT-as-upsert path requires at least one
      // allowed field in the body, so send ``is_active: true``
      // explicitly.
      { email: trimmed, update: { is_active: true } },
      {
        onSuccess: () => {
          toast.success(`Created ${trimmed}`);
          setNewEmail("");
        },
        onError: (err) => toast.error(err.message),
      },
    );
  };

  if (usersQuery.isLoading) {
    return (
      <p className="text-sm italic text-muted-foreground">Loading users…</p>
    );
  }
  if (usersQuery.error) {
    return (
      <p className="text-sm text-destructive">
        Error: {(usersQuery.error as Error).message}
      </p>
    );
  }

  const users = usersQuery.data ?? [];

  return (
    <div className="space-y-4">
      <Card className="border-gray-200/60 py-0 shadow-none dark:border-blue-950/60">
        <CardContent className="p-4">
          <div className="mb-2 text-sm font-semibold">Add a user</div>
          <div className="flex gap-1.5">
            <Input
              type="email"
              autoComplete="off"
              placeholder="user@example.com"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  createUser();
                }
              }}
              aria-label="New user email"
            />
            <Button
              variant="default"
              onClick={createUser}
              disabled={updateMut.isPending}
            >
              Create
            </Button>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Created users are active and non-admin. Toggle{" "}
            <span className="font-mono">is_admin</span> from the row
            below.
          </p>
        </CardContent>
      </Card>

      {users.length === 0 ? (
        <p className="text-sm italic text-muted-foreground">
          No users yet.
        </p>
      ) : (
        <div className="space-y-2">
          {users.map((u) => (
            <UserRow
              key={u.email}
              user={u}
              onEdit={() => setEditing(u)}
              onToggleActive={() => toggle(u, "is_active")}
              onToggleAdmin={() => toggle(u, "is_admin")}
              busy={updateMut.isPending}
            />
          ))}
        </div>
      )}

      <EditUserDialog
        user={editing}
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) setEditing(null);
        }}
      />
    </div>
  );
}

function UserRow({
  user,
  onEdit,
  onToggleActive,
  onToggleAdmin,
  busy,
}: {
  user: AdminUser;
  onEdit: () => void;
  onToggleActive: () => void;
  onToggleAdmin: () => void;
  busy: boolean;
}) {
  const displayName = user.display_name ?? user.email;
  return (
    <Card
      className={cn(
        "border-gray-200/60 py-0 shadow-none dark:border-blue-950/60",
        !user.is_active && "opacity-60",
      )}
    >
      <CardContent className="space-y-2 p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-baseline gap-2">
              <span className="truncate font-medium">{displayName}</span>
              {displayName !== user.email ? (
                <span className="truncate font-mono text-xs text-muted-foreground">
                  {user.email}
                </span>
              ) : null}
              {user.is_admin ? (
                <Badge
                  variant="default"
                  className="bg-blue-600 hover:bg-blue-600"
                >
                  admin
                </Badge>
              ) : null}
              {!user.is_active ? (
                <Badge variant="outline">inactive</Badge>
              ) : null}
            </div>
            {user.groups && user.groups.length > 0 ? (
              <div className="mt-1 flex flex-wrap gap-1">
                {user.groups.map((g) => (
                  <Badge
                    key={g}
                    variant="secondary"
                    className="font-mono text-xs"
                  >
                    {g}
                  </Badge>
                ))}
              </div>
            ) : null}
            <div className="mt-1 flex flex-wrap gap-3 text-xs text-muted-foreground">
              {user.created_at ? (
                <span>created {user.created_at.slice(0, 10)}</span>
              ) : null}
              {user.last_login ? (
                <span>last seen {user.last_login.slice(0, 10)}</span>
              ) : null}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              aria-label={
                user.is_active
                  ? `Deactivate ${user.email}`
                  : `Activate ${user.email}`
              }
              onClick={onToggleActive}
              disabled={busy}
              title={user.is_active ? "Deactivate" : "Activate"}
            >
              {user.is_active ? (
                <CheckCircle2 className="size-4 text-green-600" />
              ) : (
                <XCircle className="size-4 text-muted-foreground" />
              )}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              aria-label={
                user.is_admin
                  ? `Revoke admin from ${user.email}`
                  : `Grant admin to ${user.email}`
              }
              onClick={onToggleAdmin}
              disabled={busy}
              title={user.is_admin ? "Revoke admin" : "Grant admin"}
            >
              {user.is_admin ? (
                <ShieldCheck className="size-4 text-blue-600" />
              ) : (
                <ShieldOff className="size-4 text-muted-foreground" />
              )}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              aria-label={`Edit ${user.email}`}
              onClick={onEdit}
              disabled={busy}
              title="Edit display name and groups"
            >
              <Pencil className="size-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
