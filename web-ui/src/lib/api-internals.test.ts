/* @vitest-environment node */
import { describe, expect, it } from "vitest";

import { gatedEnabled } from "./api-internals";

/**
 * Focused tests for the ``gatedEnabled`` helper. The helper lives
 * in ``api-internals.ts`` (a deliberately-internal module);
 * production hooks in ``api.ts`` consume it via that import.
 * The semantics under test are documented on the helper itself.
 * We assert each row of the truth table plus the predicate
 * pass-through, which is the case the helper has historically
 * gotten wrong (silently dropped the function).
 */
describe("gatedEnabled", () => {
  it("returns false when the internal precondition fails (overrides caller)", () => {
    // Caller's preference doesn't matter when the internal guard
    // is closed — the query must not fire.
    expect(gatedEnabled(false)).toBe(false);
    expect(gatedEnabled(false, {})).toBe(false);
    expect(gatedEnabled(false, { enabled: true })).toBe(false);
    expect(gatedEnabled(false, { enabled: false })).toBe(false);
    expect(gatedEnabled(false, { enabled: undefined })).toBe(false);
    expect(gatedEnabled(false, { enabled: () => true })).toBe(false);
    expect(gatedEnabled(false, { enabled: () => false })).toBe(false);
  });

  it("forwards undefined caller-enabled when the precondition holds", () => {
    // React Query treats ``undefined`` as "enabled by default";
    // we preserve that signal rather than coercing to ``true``.
    expect(gatedEnabled(true)).toBeUndefined();
    expect(gatedEnabled(true, {})).toBeUndefined();
    expect(gatedEnabled(true, { enabled: undefined })).toBeUndefined();
  });

  it("forwards a boolean caller-enabled when the precondition holds", () => {
    expect(gatedEnabled(true, { enabled: true })).toBe(true);
    expect(gatedEnabled(true, { enabled: false })).toBe(false);
  });

  it("forwards a predicate function verbatim when the precondition holds", () => {
    // Regression guard for the bug the helper used to silently
    // exhibit: a ``(query) => boolean`` was collapsed to ``true``
    // because of a ``!== false`` check. The new contract is
    // pass-through, so React Query can invoke the predicate
    // per-query — same reference comes back out.
    const predicate = () => true;
    const result = gatedEnabled(true, { enabled: predicate });
    expect(result).toBe(predicate);
    expect(typeof result).toBe("function");

    // A predicate returning ``false`` is also forwarded as-is;
    // React Query (not us) is responsible for invoking it.
    const negPredicate = () => false;
    expect(gatedEnabled(true, { enabled: negPredicate })).toBe(
      negPredicate,
    );
  });

  it("does not invoke the predicate itself", () => {
    // The helper must never call the caller's predicate. React
    // Query calls it per-observation with a ``Query`` argument
    // that we don't have at hook-call time. If the helper ever
    // calls it, this test fails (the counter increments).
    let calls = 0;
    const predicate = () => {
      calls += 1;
      return true;
    };
    gatedEnabled(true, { enabled: predicate });
    gatedEnabled(false, { enabled: predicate });
    expect(calls).toBe(0);
  });
});
