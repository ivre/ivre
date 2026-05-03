import { Copy, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  useApiKeys,
  useCreateApiKey,
  useDeleteApiKey,
  type ApiKey,
} from "@/lib/admin";

/**
 * API-key management panel. Lists the keys owned by the current
 * user (the backend's ``/cgi/auth/api-keys`` endpoint is
 * owner-scoped, so admins do not see other users' keys here);
 * adds a "Create new key" form whose response carries the
 * one-and-only-time-the-secret-is-shown value, surfaced through
 * a modal with copy-to-clipboard.
 */
export function ApiKeysPanel() {
  const keysQuery = useApiKeys();
  const createMut = useCreateApiKey();
  const deleteMut = useDeleteApiKey();
  const [draftName, setDraftName] = useState("");
  const [createdKey, setCreatedKey] = useState<{
    name: string;
    secret: string;
  } | null>(null);

  const submitCreate = () => {
    const name = draftName.trim();
    if (!name) {
      toast.error("Enter a name for the new API key.");
      return;
    }
    createMut.mutate(name, {
      onSuccess: (resp) => {
        setCreatedKey({ name: resp.name, secret: resp.key });
        setDraftName("");
      },
      onError: (err) => toast.error(err.message),
    });
  };

  const revoke = (key: ApiKey) => {
    const confirmed = window.confirm(
      `Revoke API key "${key.name}" (${key.key_prefix}…)? Existing` +
        " clients using this key will start getting 401 immediately.",
    );
    if (!confirmed) return;
    deleteMut.mutate(key.key_hash, {
      onSuccess: () => {
        toast.success(`Revoked ${key.name}`);
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

  const keys = keysQuery.data ?? [];

  return (
    <div className="space-y-4">
      <Card className="border-gray-200/60 py-0 shadow-none dark:border-blue-950/60">
        <CardContent className="p-4">
          <div className="mb-2 text-sm font-semibold">
            Create a new API key
          </div>
          <div className="flex gap-1.5">
            <Input
              type="text"
              autoComplete="off"
              placeholder="e.g. ci-pipeline, dashboard-readonly"
              value={draftName}
              onChange={(e) => setDraftName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  submitCreate();
                }
              }}
              aria-label="New API key name"
            />
            <Button
              variant="default"
              onClick={submitCreate}
              disabled={createMut.isPending}
            >
              {createMut.isPending ? "Creating…" : "Create"}
            </Button>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            The full key is shown <strong>once</strong> after
            creation. Save it immediately — the server stores only
            its hash.
          </p>
        </CardContent>
      </Card>

      {keys.length === 0 ? (
        <p className="text-sm italic text-muted-foreground">
          No API keys yet.
        </p>
      ) : (
        <div className="space-y-2">
          {keys.map((k) => (
            <KeyRow
              key={k.key_hash}
              apiKey={k}
              onRevoke={() => revoke(k)}
              busy={deleteMut.isPending}
            />
          ))}
        </div>
      )}

      <NewApiKeyDialog
        created={createdKey}
        onClose={() => setCreatedKey(null)}
      />
    </div>
  );
}

function KeyRow({
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
              <Badge
                variant="outline"
                className="font-mono text-xs"
              >
                {apiKey.key_prefix}…
              </Badge>
            </div>
            <div className="mt-1 flex flex-wrap gap-3 text-xs text-muted-foreground">
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
            aria-label={`Revoke ${apiKey.name}`}
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

function NewApiKeyDialog({
  created,
  onClose,
}: {
  created: { name: string; secret: string } | null;
  onClose: () => void;
}) {
  const copyToClipboard = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.secret);
      toast.success("API key copied to clipboard.");
    } catch {
      toast.error("Could not copy — select the text and copy manually.");
    }
  };

  return (
    <Dialog
      open={created !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>API key created</DialogTitle>
          <DialogDescription>
            This is the only time the full key value is shown. Copy it
            now and store it somewhere safe; the server only keeps a
            SHA-256 hash.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <div className="text-xs font-semibold text-muted-foreground">
            {created?.name}
          </div>
          <div className="flex gap-1.5">
            <Input
              readOnly
              value={created?.secret ?? ""}
              className="font-mono text-xs"
              onFocus={(e) => e.currentTarget.select()}
              aria-label="New API key value"
            />
            <Button
              type="button"
              variant="outline"
              onClick={copyToClipboard}
              aria-label="Copy API key"
            >
              <Copy className="size-4" />
              Copy
            </Button>
          </div>
        </div>

        <DialogFooter>
          <Button onClick={onClose}>I have saved it</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
