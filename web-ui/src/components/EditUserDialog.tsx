import { Plus, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
  useUpdateAdminUser,
  type AdminUser,
  type AdminUserUpdate,
} from "@/lib/admin";

export interface EditUserDialogProps {
  user: AdminUser | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Modal that lets an admin edit a user's display name and group
 * membership. Toggling ``is_admin`` and ``is_active`` is done
 * inline on the row (single-button actions); this dialog only
 * surfaces the fields that need a multi-step UI.
 *
 * The PUT endpoint accepts a partial body, so we send only the
 * fields the operator actually changed. ``email`` is the URL
 * parameter and cannot be edited.
 */
export function EditUserDialog({
  user,
  open,
  onOpenChange,
}: EditUserDialogProps) {
  const updateMut = useUpdateAdminUser();
  const [displayName, setDisplayName] = useState("");
  const [groups, setGroups] = useState<string[]>([]);
  const [groupDraft, setGroupDraft] = useState("");

  // Reset the dialog state whenever a new user is opened so the
  // form does not show the previous user's pending edits.
  useEffect(() => {
    if (user) {
      setDisplayName(user.display_name ?? "");
      setGroups(user.groups ?? []);
      setGroupDraft("");
    }
  }, [user]);

  const initialDisplayName = user?.display_name ?? "";
  const initialGroups = useMemo(() => user?.groups ?? [], [user]);

  const dirty =
    displayName !== initialDisplayName ||
    groups.length !== initialGroups.length ||
    groups.some((g, i) => g !== initialGroups[i]);

  const addGroup = () => {
    const trimmed = groupDraft.trim();
    if (!trimmed) return;
    if (groups.includes(trimmed)) {
      setGroupDraft("");
      return;
    }
    setGroups([...groups, trimmed]);
    setGroupDraft("");
  };

  const removeGroup = (g: string) => {
    setGroups(groups.filter((x) => x !== g));
  };

  const submit = () => {
    if (!user) return;
    const update: AdminUserUpdate = {};
    if (displayName !== initialDisplayName) {
      update.display_name = displayName;
    }
    if (
      groups.length !== initialGroups.length ||
      groups.some((g, i) => g !== initialGroups[i])
    ) {
      update.groups = groups;
    }
    if (Object.keys(update).length === 0) {
      onOpenChange(false);
      return;
    }
    updateMut.mutate(
      { email: user.email, update },
      {
        onSuccess: () => {
          toast.success(`Updated ${user.email}`);
          onOpenChange(false);
        },
        onError: (err) => toast.error(err.message),
      },
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {user ? `Edit ${user.email}` : "Edit user"}
          </DialogTitle>
          <DialogDescription>
            Display name and group membership. ``is_admin`` and
            ``is_active`` are toggled directly from the row.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1">
            <label
              htmlFor="edit-user-display-name"
              className="text-sm font-medium"
            >
              Display name
            </label>
            <Input
              id="edit-user-display-name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder={user?.email ?? ""}
            />
          </div>

          <div className="space-y-1">
            <span className="text-sm font-medium">Groups</span>
            <div className="flex flex-wrap gap-1.5">
              {groups.length === 0 ? (
                <span className="text-xs italic text-muted-foreground">
                  No groups.
                </span>
              ) : (
                groups.map((g) => (
                  <Badge
                    key={g}
                    variant="secondary"
                    className="gap-1 pl-2 pr-1 font-mono text-xs"
                  >
                    {g}
                    <button
                      type="button"
                      aria-label={`Remove group ${g}`}
                      onClick={() => removeGroup(g)}
                      className="ml-1 inline-flex size-4 items-center justify-center rounded hover:bg-muted-foreground/20"
                    >
                      <X className="size-3" />
                    </button>
                  </Badge>
                ))
              )}
            </div>
            <div className="flex gap-1.5">
              <Input
                id="edit-user-group-draft"
                value={groupDraft}
                onChange={(e) => setGroupDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addGroup();
                  }
                }}
                placeholder="add a group"
                aria-label="Add a group"
              />
              <Button
                type="button"
                variant="outline"
                onClick={addGroup}
                disabled={!groupDraft.trim()}
              >
                <Plus className="size-4" />
                Add
              </Button>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="ghost"
            onClick={() => onOpenChange(false)}
            disabled={updateMut.isPending}
          >
            Cancel
          </Button>
          <Button
            onClick={submit}
            disabled={!dirty || updateMut.isPending}
          >
            {updateMut.isPending ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
