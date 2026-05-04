/**
 * Self-service API-key management hooks. Any authenticated user
 * can list, create, and revoke their own keys against the
 * owner-scoped routes exposed by ``ivre/web/auth.py``:
 *
 *   - ``GET    /cgi/auth/api-keys``           — list (caller's keys only)
 *   - ``POST   /cgi/auth/api-keys``           — create (returns the
 *                                              full secret once,
 *                                              never again)
 *   - ``DELETE /cgi/auth/api-keys/<key_hash>``— revoke (owner-scoped)
 *
 * The admin audit / cross-user variants live in :mod:`lib/admin`
 * (``GET /cgi/auth/admin/api-keys``,
 * ``DELETE /cgi/auth/admin/api-keys/<key_hash>``).
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

/** An API-key record. The full secret is never returned by the
 *  list/get endpoints — only the SHA-256 ``key_hash`` (used as
 *  the URL parameter for the DELETE endpoint) and the 12-char
 *  ``key_prefix`` for display. ``user_email`` is the owner; the
 *  self-service list returns the caller's email here, the admin
 *  list returns the owner of every key. */
export interface ApiKey {
  key_hash: string;
  key_prefix: string;
  user_email?: string;
  name: string;
  created_at?: string;
  last_used?: string | null;
  expires_at?: string | null;
}

/** Body returned by ``POST /cgi/auth/api-keys``. ``key`` is the
 *  one and only time the full secret crosses the wire — the
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

const API_KEYS_KEY = ["api-keys", "self"] as const;

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
