/* @vitest-environment jsdom */
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { getConfig, isAuthEnabled, isModuleEnabled } from "./config";

const ORIGINAL_WINDOW_CONFIG = (window as unknown as { config?: unknown })
  .config;

function setWindowConfig(cfg: Record<string, unknown> | undefined) {
  (window as unknown as { config?: unknown }).config = cfg;
}

afterEach(() => {
  (window as unknown as { config?: unknown }).config = ORIGINAL_WINDOW_CONFIG;
});

describe("getConfig", () => {
  beforeEach(() => {
    setWindowConfig(undefined);
  });

  it("falls back to scalar defaults when window.config is missing", () => {
    const cfg = getConfig();
    expect(cfg.dflt_limit).toBe(10);
    expect(cfg.warn_dots_count).toBe(20000);
    expect(cfg.uploadok).toBe(false);
    expect(cfg.auth_enabled).toBe(false);
    // ``modules`` is intentionally absent from the defaults so
    // older servers that don't emit the field surface as
    // "everything enabled".
    expect(cfg.modules).toBeUndefined();
  });

  it("merges window.config over defaults", () => {
    setWindowConfig({ auth_enabled: true, dflt_limit: 50 });
    const cfg = getConfig();
    expect(cfg.auth_enabled).toBe(true);
    expect(cfg.dflt_limit).toBe(50);
    // Untouched fields keep defaults.
    expect(cfg.warn_dots_count).toBe(20000);
  });

  it("preserves modules when provided", () => {
    setWindowConfig({ modules: ["view", "rir"] });
    expect(getConfig().modules).toEqual(["view", "rir"]);
  });
});

describe("isAuthEnabled", () => {
  it("returns false when auth_enabled is missing", () => {
    setWindowConfig({});
    expect(isAuthEnabled()).toBe(false);
  });

  it("returns true only when auth_enabled === true (strict)", () => {
    setWindowConfig({ auth_enabled: true });
    expect(isAuthEnabled()).toBe(true);
    setWindowConfig({ auth_enabled: 1 as unknown as boolean });
    // Strict truthiness check — non-boolean truthy values do not
    // count.
    expect(isAuthEnabled()).toBe(false);
  });
});

describe("isModuleEnabled", () => {
  it("returns true for any id when modules is absent (back-compat)", () => {
    // Older server: ``/cgi/config`` omits the ``modules`` field.
    // The React UI must keep showing every section so the
    // upgrade path is non-breaking.
    setWindowConfig({});
    expect(isModuleEnabled("view")).toBe(true);
    expect(isModuleEnabled("active")).toBe(true);
    expect(isModuleEnabled("passive")).toBe(true);
    expect(isModuleEnabled("dns")).toBe(true);
    expect(isModuleEnabled("rir")).toBe(true);
    expect(isModuleEnabled("flow")).toBe(true);
    // Even unknown ids — there's no allowlist to compare against.
    expect(isModuleEnabled("made-up")).toBe(true);
  });

  it("returns true only for ids in the modules list", () => {
    setWindowConfig({ modules: ["view", "rir"] });
    expect(isModuleEnabled("view")).toBe(true);
    expect(isModuleEnabled("rir")).toBe(true);
    expect(isModuleEnabled("active")).toBe(false);
    expect(isModuleEnabled("passive")).toBe(false);
    expect(isModuleEnabled("dns")).toBe(false);
    expect(isModuleEnabled("flow")).toBe(false);
  });

  it("returns false for every id when modules is empty", () => {
    setWindowConfig({ modules: [] });
    expect(isModuleEnabled("view")).toBe(false);
    expect(isModuleEnabled("active")).toBe(false);
  });

  it("returns false for unknown ids when modules is provided", () => {
    setWindowConfig({ modules: ["view"] });
    expect(isModuleEnabled("made-up")).toBe(false);
  });
});
