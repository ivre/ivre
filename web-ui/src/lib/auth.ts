/**
 * Wrappers over the IVRE Web API authentication endpoints
 * (mounted at ``/cgi/auth/`` by ``ivre httpd``). All routes return
 * plain JSON since the May 2026 JSONP removal; we use ``fetch()``
 * with ``credentials: "same-origin"`` so the browser sends the
 * ``_ivre_session`` cookie on same-origin requests.
 *
 * The helpers are tolerant: when ``WEB_AUTH_ENABLED`` is ``False``
 * server-side, ``/cgi/auth/config`` is not registered and returns
 * 404; we treat that as "auth disabled" rather than an error.
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { CGI_ROOT } from "@/lib/api";

/** Shape returned by ``GET /cgi/auth/me``. */
export interface AuthMe {
  authenticated: boolean;
  email?: string;
  display_name?: string;
  is_admin?: boolean;
  groups?: string[];
}

/** Shape returned by ``GET /cgi/auth/config``. */
export interface AuthConfig {
  enabled: boolean;
  /** Provider names with a configured client id. Possible values
   *  today: ``google``, ``microsoft``, ``github``, ``oidc``. */
  providers: string[];
  /** Whether the magic-link sign-in flow is enabled server-side. */
  magic_link: boolean;
  /** Per-provider human-readable labels (currently only set for
   *  ``oidc`` to surface the operator-chosen ``WEB_AUTH_OIDC_LABEL``
   *  in the UI). */
  provider_labels?: Record<string, string>;
}

/** Default config when auth is disabled or the endpoint is
 *  unreachable. */
const DISABLED_AUTH_CONFIG: AuthConfig = {
  enabled: false,
  providers: [],
  magic_link: false,
};

/* ------------------------------------------------------------------ */
/* Raw fetchers                                                       */
/* ------------------------------------------------------------------ */

/** Fetch the current session's user descriptor.
 *
 *  The endpoint is ``@check_referer``-protected; same-origin
 *  ``fetch()`` includes the ``Referer`` header by default, which
 *  satisfies the check. A non-2xx response (most commonly 400 from
 *  the Referer check, or 404 when auth is disabled) is treated as
 *  an anonymous session. */
export async function fetchAuthMe(): Promise<AuthMe> {
  try {
    const r = await fetch(`${CGI_ROOT}/auth/me`, {
      credentials: "same-origin",
    });
    if (!r.ok) {
      return { authenticated: false };
    }
    return (await r.json()) as AuthMe;
  } catch {
    return { authenticated: false };
  }
}

/** Fetch the auth configuration (providers, magic-link availability).
 *
 *  When auth is disabled server-side this endpoint is not
 *  registered and returns 404; we surface that as
 *  ``{enabled: false, ...}``. */
export async function fetchAuthConfig(): Promise<AuthConfig> {
  try {
    const r = await fetch(`${CGI_ROOT}/auth/config`, {
      credentials: "same-origin",
    });
    if (!r.ok) {
      return DISABLED_AUTH_CONFIG;
    }
    return (await r.json()) as AuthConfig;
  } catch {
    return DISABLED_AUTH_CONFIG;
  }
}

/** Drop the current session cookie server- and client-side.
 *
 *  The endpoint is idempotent: calling it without an active
 *  session is fine. */
export async function logout(): Promise<void> {
  await fetch(`${CGI_ROOT}/auth/logout`, {
    method: "POST",
    credentials: "same-origin",
  });
}

/** Trigger sending a magic-link sign-in email.
 *
 *  The backend always returns 200 on validation success
 *  (anti-enumeration) — we still surface the body so the caller
 *  can show the operator-defined message. */
export async function sendMagicLink(
  email: string,
): Promise<{ status?: string; message?: string }> {
  const r = await fetch(`${CGI_ROOT}/auth/magic-link`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!r.ok) {
    throw new Error(
      `Magic link request failed: ${r.status} ${r.statusText}`,
    );
  }
  return (await r.json()) as { status?: string; message?: string };
}

/** URL the browser should navigate to in order to start an
 *  OAuth/OIDC login flow. The browser performs a full navigation;
 *  we never call this from ``fetch()``. */
export function loginUrl(provider: string): string {
  return `${CGI_ROOT}/auth/login/${encodeURIComponent(provider)}`;
}

/* ------------------------------------------------------------------ */
/* React Query hooks                                                  */
/* ------------------------------------------------------------------ */

const AUTH_ME_KEY = ["auth", "me"] as const;
const AUTH_CONFIG_KEY = ["auth", "config"] as const;

export function useAuthMe(): UseQueryResult<AuthMe> {
  return useQuery<AuthMe>({
    queryKey: AUTH_ME_KEY,
    queryFn: fetchAuthMe,
    // Identity rarely changes during a session; refetch on focus
    // so a sign-in/out in another tab is reflected reasonably fast.
    refetchOnWindowFocus: true,
    staleTime: 60_000,
  });
}

export function useAuthConfig(): UseQueryResult<AuthConfig> {
  return useQuery<AuthConfig>({
    queryKey: AUTH_CONFIG_KEY,
    queryFn: fetchAuthConfig,
    // Auth config is essentially static for the lifetime of the
    // tab; no need to refetch eagerly.
    refetchOnWindowFocus: false,
    staleTime: Number.POSITIVE_INFINITY,
  });
}

/** Mutation hook for the sign-out action. On success the auth-me
 *  query is invalidated so the UserMenu swaps back to the
 *  anonymous state without a full reload. Callers may follow up
 *  with a hard reload if they want to drop other in-memory state. */
export function useLogout(): UseMutationResult<void, Error, void, unknown> {
  const queryClient = useQueryClient();
  return useMutation<void, Error, void>({
    mutationFn: logout,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: AUTH_ME_KEY });
    },
  });
}

export function useMagicLink(): UseMutationResult<
  { status?: string; message?: string },
  Error,
  string
> {
  return useMutation<{ status?: string; message?: string }, Error, string>({
    mutationFn: (email: string) => sendMagicLink(email),
  });
}
