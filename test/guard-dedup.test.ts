import { mkdtempSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  DEDUP_PRUNE_MS,
  DEDUP_WINDOW_MS,
  dedupApplies,
  dedupDir,
  dedupPath,
  priorDecision,
  readDedup,
  writeDedup,
} from "../main/guard/dedup.js";

/**
 * guard/dedup.ts — one call, one decision across the several events a host
 * fires for it (review P2, 2026-09-10). The rules that matter: only ACROSS
 * events, short-lived, and a pending hold is waited on, not skipped.
 */

const T0 = Date.parse("2026-09-10T12:00:00.000Z");
const shell = { key: "conv\u0000gen\u0000Bash\u0000rm -rf x", event: "beforeShellExecution" };
const generic = { ...shell, event: "preToolUse" };

describe("dedupApplies — pure rules", () => {
  it("never applies to the same event: a repeat is evaluated afresh, not granted", () => {
    const record = { event: "preToolUse", decision: "allow" as const, at: new Date(T0).toISOString() };
    expect(dedupApplies(record, generic, T0 + 10)).toBe(false);
    expect(dedupApplies(record, shell, T0 + 10)).toBe(true);
  });

  it("repeats a final decision only inside the window", () => {
    const record = { event: "beforeShellExecution", decision: "deny" as const, at: new Date(T0).toISOString(), reason: "r" };
    expect(dedupApplies(record, generic, T0 + DEDUP_WINDOW_MS)).toBe(true);
    expect(dedupApplies(record, generic, T0 + DEDUP_WINDOW_MS + 1)).toBe(false);
    // A record from the future (clock jump) is not trusted.
    expect(dedupApplies(record, generic, T0 - 1)).toBe(false);
  });

  it("honours a pending record only for its own budget", () => {
    const record = { event: "beforeShellExecution", decision: "pending" as const, at: new Date(T0).toISOString(), pending_budget_ms: 5_000 };
    expect(dedupApplies(record, generic, T0 + 4_999)).toBe(true);
    expect(dedupApplies(record, generic, T0 + 5_001)).toBe(false);
    // No budget at all → never waited on.
    expect(dedupApplies({ ...record, pending_budget_ms: undefined }, generic, T0 + 1)).toBe(false);
  });
});

describe("the dedup files", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "doorman-dedup-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("round-trips a record, keyed by host + call key, and reads garbage as nothing", () => {
    writeDedup(dir, "cursor", shell, { event: shell.event, decision: "deny", reason: "why", at: new Date().toISOString() });
    expect(readDedup(dir, "cursor", generic)).toMatchObject({ event: "beforeShellExecution", decision: "deny", reason: "why" });
    // Another host's identical key is another call.
    expect(readDedup(dir, "copilot", generic)).toBeUndefined();
    writeFileSync(dedupPath(dir, "cursor", shell), "{ not json");
    expect(readDedup(dir, "cursor", shell)).toBeUndefined();
    writeFileSync(dedupPath(dir, "cursor", shell), JSON.stringify({ event: "x", decision: "maybe", at: "now" }));
    expect(readDedup(dir, "cursor", shell)).toBeUndefined();
  });

  it("prunes stale siblings on write", () => {
    const stale = { key: "old", event: "preToolUse" };
    writeDedup(dir, "cursor", stale, { event: "preToolUse", decision: "allow", at: new Date().toISOString() });
    const old = new Date(Date.now() - DEDUP_PRUNE_MS - 60_000);
    utimesSync(dedupPath(dir, "cursor", stale), old, old);
    writeDedup(dir, "cursor", shell, { event: shell.event, decision: "allow", at: new Date().toISOString() });
    expect(readdirSync(dedupDir(dir))).toEqual([basename(dedupPath(dir, "cursor", shell))]);
  });

  it("priorDecision: nothing recorded → decide yourself; same event → decide yourself", async () => {
    expect(await priorDecision(dir, "cursor", generic, { pollMs: 5 })).toBeUndefined();
    writeDedup(dir, "cursor", shell, { event: "preToolUse", decision: "deny", reason: "r", at: new Date().toISOString() });
    expect(await priorDecision(dir, "cursor", generic, { pollMs: 5 })).toBeUndefined();
  });

  it("priorDecision: repeats the other event's final decision, and waits out its pending hold", async () => {
    writeDedup(dir, "cursor", shell, { event: shell.event, decision: "pending", at: new Date().toISOString(), pending_budget_ms: 2_000 });
    setTimeout(() => {
      writeDedup(dir, "cursor", shell, { event: shell.event, decision: "deny", reason: "You denied it.", at: new Date().toISOString() });
    }, 40);
    const prior = await priorDecision(dir, "cursor", generic, { pollMs: 5 });
    expect(prior).toMatchObject({ decision: "deny", reason: "You denied it." });
  });

  it("priorDecision: a pending hold past its budget is treated as absent", async () => {
    writeDedup(dir, "cursor", shell, { event: shell.event, decision: "pending", at: new Date(Date.now() - 500).toISOString(), pending_budget_ms: 100 });
    expect(await priorDecision(dir, "cursor", generic, { pollMs: 5 })).toBeUndefined();
  });
});
