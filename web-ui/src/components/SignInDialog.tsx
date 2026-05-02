import { Mail } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

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
import { Separator } from "@/components/ui/separator";
import { loginUrl, useMagicLink, type AuthConfig } from "@/lib/auth";

export interface SignInDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  authConfig: AuthConfig;
}

const PROVIDER_DEFAULT_LABELS: Record<string, string> = {
  google: "Google",
  microsoft: "Microsoft",
  github: "GitHub",
  oidc: "SSO",
};

/**
 * Modal that drives the available sign-in flows: one button per
 * configured OAuth/OIDC provider, plus an inline magic-link form
 * when the operator has enabled it server-side.
 *
 * Provider clicks perform a full-page navigation to
 * ``/cgi/auth/login/<provider>``; the IVRE backend stamps a
 * signed state cookie and redirects to the upstream IdP. The
 * eventual callback (``/cgi/auth/callback/<provider>``) sets the
 * ``_ivre_session`` cookie and redirects back to ``/``.
 */
export function SignInDialog({
  open,
  onOpenChange,
  authConfig,
}: SignInDialogProps) {
  const [email, setEmail] = useState("");
  const magicLink = useMagicLink();

  const providers = authConfig.providers;
  const providerLabel = (key: string): string =>
    authConfig.provider_labels?.[key] ?? PROVIDER_DEFAULT_LABELS[key] ?? key;

  const handleProvider = (provider: string) => {
    // Full-page navigation: the OAuth flow completes by
    // server-side redirect, not a SPA route change.
    window.location.assign(loginUrl(provider));
  };

  const handleMagicLink = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = email.trim();
    if (!trimmed || !trimmed.includes("@")) {
      toast.error("Enter a valid email address.");
      return;
    }
    magicLink.mutate(trimmed, {
      onSuccess: (data) => {
        toast.success(data.message ?? "Check your email for a sign-in link.");
        setEmail("");
        onOpenChange(false);
      },
      onError: (err) => {
        toast.error(err.message);
      },
    });
  };

  const hasProviders = providers.length > 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Sign in to IVRE</DialogTitle>
          <DialogDescription>
            Choose a sign-in method enabled by your operator.
          </DialogDescription>
        </DialogHeader>

        {hasProviders ? (
          <div className="flex flex-col gap-2">
            {providers.map((provider) => (
              <Button
                key={provider}
                variant="outline"
                onClick={() => handleProvider(provider)}
              >
                Continue with {providerLabel(provider)}
              </Button>
            ))}
          </div>
        ) : null}

        {hasProviders && authConfig.magic_link ? <Separator /> : null}

        {authConfig.magic_link ? (
          <form
            className="flex flex-col gap-2"
            onSubmit={handleMagicLink}
            aria-label="Magic link sign-in"
          >
            <label
              htmlFor="magic-link-email"
              className="text-sm font-medium"
            >
              Email me a sign-in link
            </label>
            <Input
              id="magic-link-email"
              type="email"
              placeholder="you@example.com"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={magicLink.isPending}
              required
            />
            <Button
              type="submit"
              variant="default"
              disabled={magicLink.isPending}
            >
              <Mail className="size-4" />
              {magicLink.isPending ? "Sending…" : "Send sign-in link"}
            </Button>
          </form>
        ) : null}

        {!hasProviders && !authConfig.magic_link ? (
          <p className="text-sm text-muted-foreground">
            No sign-in methods are enabled. Ask your operator to configure an
            OAuth provider or enable magic-link sign-in.
          </p>
        ) : null}

        <DialogFooter />
      </DialogContent>
    </Dialog>
  );
}
