/**
 * Wrappers over the admin / API-key endpoints exposed by
 * ``ivre/web/auth.py``:
 *
 *   - ``GET    /cgi/auth/admin/users``        — list (admin only)
 *   - ``PUT    /cgi/auth/admin/users/<email>``— upsert (admin only)
 *   - ``GET    /cgi/auth/api-keys``           — list (any authed user)
 *   - ``POST   /cgi/auth/api-keys``           — create (returns secret once)
 *   - ``DELETE /cgi/auth/api-keys/<key_hash>``— revoke (owner-scoped)
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

/** An API-key record as returned by ``GET /cgi/auth/api-keys``. The
 *  full key value is never returned; only the prefix (12 chars,
 *  for display) and the SHA-256 ``key_hash`` (the URL parameter
 *  for the DELETE endpoint). */
export interface ApiKey {
  key_hash: string;
  key_prefix: string;
  user_email?: string;
  name: string;
  created_at?: string;
  last_used?: string | null;
  expires_at?: string | null;
}

/** Body returned by ``POST /cgi/auth/api-keys``. The ``key`` is
 *  the one and only time the full secret crosses the wire — the
 *  caller must surface it to the user immediately and not store
 *  it. */
export interface ApiKeyCreated {
  key: string;
  name: string;
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

export async function fetchApiKeys(): Promise<ApiKey[]> {
  const url = `${CGI_ROOT}/auth/api-keys`;
  const r = await fetch(url, { credentials: "same-origin" });
  await ensureOk(r, `GET ${url}`);
  return (await r.json()) as ApiKey[];
}

export async function createApiKey(name: string): Promise<ApiKeyCreated> {
  const url = `${CGI_ROOT}/auth/api-keys`;
  const r = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  await ensureOk(r, `POST ${url}`);
  return (await r.json()) as ApiKeyCreated;
}

export async function deleteApiKey(keyHash: string): Promise<void> {
  const url = `${CGI_ROOT}/auth/api-keys/${encodeURIComponent(keyHash)}`;
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
const API_KEYS_KEY = ["admin", "api-keys"] as const;

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

export function useApiKeys(): UseQueryResult<ApiKey[]> {
  return useQuery<ApiKey[]>({
    queryKey: API_KEYS_KEY,
    queryFn: fetchApiKeys,
    refetchOnWindowFocus: false,
    staleTime: 30_000,
  });
}

export function useCreateApiKey(): UseMutationResult<
  ApiKeyCreated,
  Error,
  string
> {
  const queryClient = useQueryClient();
  return useMutation<ApiKeyCreated, Error, string>({
    mutationFn: (name) => createApiKey(name),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: API_KEYS_KEY });
    },
  });
}

export function useDeleteApiKey(): UseMutationResult<void, Error, string> {
  const queryClient = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (keyHash) => deleteApiKey(keyHash),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: API_KEYS_KEY });
    },
  });
}
