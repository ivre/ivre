/**
 * Internal helpers used by ``api.ts`` and its companion unit
 * tests. Nothing in this module is part of the public hook API:
 * routes and components must depend on ``api.ts`` (the hooks),
 * never on this file. The file-level separation is the structural
 * signal — anyone tempted to misuse these helpers has to type a
 * different import path, which a reviewer can spot at a glance.
 *
 * If TypeScript ever ships first-class "package-private" visibility,
 * this file collapses back into ``api.ts``.
 */

import type { UseQueryOptions } from "@tanstack/react-query";

/** Options accepted by every hook in ``api.ts``: every
 *  ``UseQueryOptions`` field *except* the two that the hook
 *  itself controls (``queryKey``, ``queryFn``). Kept here so
 *  the helper below can be typed against the same shape the
 *  hooks expose to callers. */
export type HookOptions<T> = Omit<
  UseQueryOptions<T>,
  "queryKey" | "queryFn"
>;

/**
 * Combine an internal precondition (e.g. ``Boolean(endpoint)``)
 * with the caller's optional ``enabled`` field, preserving every
 * shape React Query v5 accepts: ``boolean``, ``undefined``, and
 * the ``(query) => boolean`` predicate form.
 *
 * Semantics: if ``internal`` is ``false``, the query is strictly
 * disabled — the caller's ``enabled`` is overridden. Otherwise we
 * forward whatever the caller passed verbatim — ``undefined``
 * (React Query defaults to enabled), ``true``/``false`` (strict),
 * or a predicate function (React Query invokes it per-query).
 * The predicate is the caller's final word: there is no
 * meaningful "AND" between an internal boolean and a per-query
 * predicate beyond gating the predicate on the internal
 * precondition, which the early-return already accomplishes.
 *
 * Every hook in ``api.ts`` with an internal precondition routes
 * through this helper instead of placing ``enabled: <internal>``
 * before ``...options``: the spread order would let a caller's
 * ``enabled: true`` silently override the internal guard. The
 * sequential-loading gating relies on callers being able to pass
 * ``enabled: false`` (or a predicate) without disabling the
 * precondition; this helper is the single place where that
 * contract is enforced.
 */
export function gatedEnabled<T>(
  internal: boolean,
  options?: HookOptions<T>,
): HookOptions<T>["enabled"] {
  return internal ? options?.enabled : false;
}
