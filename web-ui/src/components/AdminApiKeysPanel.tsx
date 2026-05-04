import { Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAdminApiKeys, useAdminDeleteApiKey } from "@/lib/admin";
import type { ApiKey } from "@/lib/api-keys";

/**
 * Admin-only audit panel: lists every API key across every
 * user, fed by ``GET /cgi/auth/admin/api-keys``. Adds a
 * client-side owner / name filter and a per-row revoke action
 * that hits ``DELETE /cgi/auth/admin/api-keys/<key_hash>`` (no
 * owner-scope check on the backend, since admins can revoke
 * any user's key).
 *
 * No "create new key" form here on purpose: keys are bound to
 * a single owner (the caller of ``POST /cgi/auth/api-keys``)
 * and we do not expose an admin-on-behalf-of-user creation
 * path. Admins create their own keys on the My API keys page.
 */
export function AdminApiKeysPanel() {
  const keysQuery = useAdminApiKeys();
  const deleteMut = useAdminDeleteApiKey();
  const [filter, setFilter] = useState("");

  const keys = useMemo(
    () => sortedKeys(keysQuery.data ?? []),
    [keysQuery.data],
  );
  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return keys;
    return keys.filter(
      (k) =>
        (k.user_email ?? "").toLowerCase().includes(needle) ||
        k.name.toLowerCase().includes(needle),
    );
  }, [keys, filter]);

  const revoke = (key: ApiKey) => {
    const owner = key.user_email ?? "(unknown owner)";
    const confirmed = window.confirm(
      `Revoke API key "${key.name}" (${key.key_prefix}…) owned by ${owner}?` +
        " Existing clients using this key will start getting 401" +
        " immediately.",
    );
    if (!confirmed) return;
    deleteMut.mutate(key.key_hash, {
      onSuccess: () => {
        toast.success(`Revoked ${key.name} (${owner})`);
      },
      onError: (err) => toast.error(err.message),
    });
  };

  if (keysQuery.isLoading) {
    return (
      <p className="text-sm italic text-muted-foreground">
        Loading API keys…
      </p>
    );
  }
  if (keysQuery.error) {
    return (
      <p className="text-sm text-destructive">
        Error: {(keysQuery.error as Error).message}
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Input
          type="search"
          placeholder="Filter by owner email or key name…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          aria-label="Filter API keys"
          className="max-w-md"
        />
        <span className="text-xs text-muted-foreground">
          {visible.length} / {keys.length}
        </span>
      </div>

      {keys.length === 0 ? (
        <p className="text-sm italic text-muted-foreground">
          No API keys have been issued yet.
        </p>
      ) : visible.length === 0 ? (
        <p className="text-sm italic text-muted-foreground">
          No keys match the filter.
        </p>
      ) : (
        <div className="space-y-2">
          {visible.map((k) => (
            <AdminKeyRow
              key={k.key_hash}
              apiKey={k}
              onRevoke={() => revoke(k)}
              busy={deleteMut.isPending}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function sortedKeys(keys: readonly ApiKey[]): ApiKey[] {
  // Group by owner email (alphabetical), then by key name.
  // Keys without an owner_email sink to the bottom — they should
  // not happen in normal operation but we tolerate the shape.
  return [...keys].sort((a, b) => {
    const ownerA = a.user_email ?? "\uffff";
    const ownerB = b.user_email ?? "\uffff";
    if (ownerA !== ownerB) return ownerA.localeCompare(ownerB);
    return a.name.localeCompare(b.name);
  });
}

function AdminKeyRow({
  apiKey,
  onRevoke,
  busy,
}: {
  apiKey: ApiKey;
  onRevoke: () => void;
  busy: boolean;
}) {
  return (
    <Card className="border-gray-200/60 py-0 shadow-none dark:border-blue-950/60">
      <CardContent className="space-y-1 p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-baseline gap-2">
              <span className="truncate font-medium">{apiKey.name}</span>
              <Badge variant="outline" className="font-mono text-xs">
                {apiKey.key_prefix}…
              </Badge>
            </div>
            <div className="mt-1 flex flex-wrap gap-3 text-xs text-muted-foreground">
              <span className="font-mono">
                {apiKey.user_email ?? "(unknown owner)"}
              </span>
              {apiKey.created_at ? (
                <span>created {apiKey.created_at.slice(0, 10)}</span>
              ) : null}
              <span>
                last used{" "}
                {apiKey.last_used ? apiKey.last_used.slice(0, 10) : "never"}
              </span>
              {apiKey.expires_at ? (
                <span>expires {apiKey.expires_at.slice(0, 10)}</span>
              ) : null}
            </div>
          </div>
          <Button
            variant="ghost"
            size="sm"
            aria-label={`Revoke ${apiKey.name} owned by ${apiKey.user_email ?? "unknown"}`}
            onClick={onRevoke}
            disabled={busy}
            title="Revoke"
          >
            <Trash2 className="size-4 text-destructive" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
