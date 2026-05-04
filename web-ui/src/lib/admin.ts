/**
 * Admin-only hooks for the ``/cgi/auth/admin/*`` routes exposed
 * by ``ivre/web/auth.py``:
 *
 *   - ``GET    /cgi/auth/admin/users``            — list every user
 *   - ``PUT    /cgi/auth/admin/users/<email>``    — upsert
 *   - ``GET    /cgi/auth/admin/api-keys``         — list every key
 *                                                  across every user
 *                                                  (audit view)
 *   - ``DELETE /cgi/auth/admin/api-keys/<hash>``  — revoke any user's
 *                                                  key
 *
 * All admin routes go through a ``_ensure_admin`` check on the
 * backend (returns 401 / 403 for anonymous / non-admin callers).
 *
 * Self-service API-key management — ``GET /cgi/auth/api-keys``,
 * ``POST`` to create, ``DELETE`` to revoke one's own key — lives
 * in :mod:`lib/api-keys`. The two surfaces share the
 * :type:`ApiKey` shape but query different endpoints and have
 * different auth gates.
 *
 * All routes are ``@check_referer``-protected; same-origin
 * ``fetch()`` with ``credentials: "same-origin"`` satisfies the
 * Referer check and carries the ``_ivre_session`` cookie.
 */
import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { CGI_ROOT } from "@/lib/api";
import type { ApiKey } from "@/lib/api-keys";

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

/** A user record as returned by ``GET /cgi/auth/admin/users``.
 *  ``created_at`` / ``last_login`` are ISO-8601 strings (the
 *  backend converts them via ``datetime.isoformat()``). */
export interface AdminUser {
  email: string;
  display_name?: string;
  is_admin?: boolean;
  is_active?: boolean;
  groups?: string[];
  created_at?: string;
  last_login?: string | null;
}

/** Subset of fields a PUT may carry. The backend's allow-list is
 *  ``{is_active, is_admin, groups, display_name}``; an unknown
 *  key would be ignored. ``email`` is the URL parameter, not in
 *  the body. */
export interface AdminUserUpdate {
  is_active?: boolean;
  is_admin?: boolean;
  groups?: string[];
  display_name?: string;
}

/* ------------------------------------------------------------------ */
/* Raw fetchers                                                       */
/* ------------------------------------------------------------------ */

async function ensureOk(response: Response, label: string): Promise<void> {
  if (!response.ok) {
    throw new Error(
      `${label} failed: ${response.status} ${response.statusText}`,
    );
  }
}

export async function fetchAdminUsers(): Promise<AdminUser[]> {
  const url = `${CGI_ROOT}/auth/admin/users`;
  const r = await fetch(url, { credentials: "same-origin" });
  await ensureOk(r, `GET ${url}`);
  return (await r.json()) as AdminUser[];
}

export async function updateAdminUser(
  email: string,
  update: AdminUserUpdate,
): Promise<void> {
  const url = `${CGI_ROOT}/auth/admin/users/${encodeURIComponent(email)}`;
  const r = await fetch(url, {
    method: "PUT",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(update),
  });
  await ensureOk(r, `PUT ${url}`);
}

export async function fetchAdminApiKeys(): Promise<ApiKey[]> {
  const url = `${CGI_ROOT}/auth/admin/api-keys`;
  const r = await fetch(url, { credentials: "same-origin" });
  await ensureOk(r, `GET ${url}`);
  return (await r.json()) as ApiKey[];
}

export async function adminDeleteApiKey(keyHash: string): Promise<void> {
  const url = `${CGI_ROOT}/auth/admin/api-keys/${encodeURIComponent(keyHash)}`;
  const r = await fetch(url, {
    method: "DELETE",
    credentials: "same-origin",
  });
  await ensureOk(r, `DELETE ${url}`);
}

/* ------------------------------------------------------------------ */
/* React Query hooks                                                  */
/* ------------------------------------------------------------------ */

const ADMIN_USERS_KEY = ["admin", "users"] as const;
const ADMIN_API_KEYS_KEY = ["admin", "api-keys"] as const;

export function useAdminUsers(): UseQueryResult<AdminUser[]> {
  return useQuery<AdminUser[]>({
    queryKey: ADMIN_USERS_KEY,
    queryFn: fetchAdminUsers,
    refetchOnWindowFocus: false,
    staleTime: 30_000,
  });
}

export function useUpdateAdminUser(): UseMutationResult<
  void,
  Error,
  { email: string; update: AdminUserUpdate }
> {
  const queryClient = useQueryClient();
  return useMutation<
    void,
    Error,
    { email: string; update: AdminUserUpdate }
  >({
    mutationFn: ({ email, update }) => updateAdminUser(email, update),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ADMIN_USERS_KEY });
    },
  });
}

export function useAdminApiKeys(): UseQueryResult<ApiKey[]> {
  return useQuery<ApiKey[]>({
    queryKey: ADMIN_API_KEYS_KEY,
    queryFn: fetchAdminApiKeys,
    refetchOnWindowFocus: false,
    staleTime: 30_000,
  });
}

export function useAdminDeleteApiKey(): UseMutationResult<
  void,
  Error,
  string
> {
  const queryClient = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (keyHash) => adminDeleteApiKey(keyHash),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ADMIN_API_KEYS_KEY });
    },
  });
}
