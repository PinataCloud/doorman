import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  appListening,
  clearExchange,
  heartbeatFresh,
  heartbeatLive,
  heartbeatPath,
  holdForVerdict,
  parseRequest,
  pendingDir,
  pidAlive,
  readReply,
  replyPath,
  requestPath,
  writeReply,
  writeRequest,
  type ApprovalRequest,
} from "../main/guard/handshake.js";
import {
  ApprovalWatcher,
  GuardHeartbeat,
  guardDir,
} from "../main/enforcement.js";
import {
  guardHostFromArgv,
  holdForHuman,
  hookOutputForHost,
  unattendedOutcome,
} from "../main/guard/hold.js";
import { defaultPolicy, type GuardPolicy } from "../main/guard/policy.js";
import { approvalSummary, suppressHeldFindings } from "../main/lib/approvals.js";
import { mergeFinding, mintFindingRow, type FindingRow } from "../main/lib/findings.js";

/**
 * The hold-and-confirm handshake: a guard blocking a real tool call on one side,
 * the app on the other, a directory between them.
 *
 * These tests exist because every failure mode here is silent by construction —
 * a guard that waits for an app that isn't listening looks like a hung session,
 * and an app that answers a request nobody is waiting on looks like it worked.
 * So each case asserts BOTH halves: what the guard concludes, and what the app
 * did to make it conclude that.
 */

let userData: string;
let dir: string;

const request = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
  id: "req-1",
  at: new Date().toISOString(),
  source: "claude-code",
  session_id: "sess-1",
  tool_name: "Bash",
  target: "rm",
  detectors: ["destructive_command"],
  max_severity: "high",
  reason: "Doorman flagged this tool call: Destructive command.",
  preview: '{"command":"rm -rf /tmp/x"}',
  hold_seconds: 60,
  on_timeout: "deny",
  pid: process.pid,
  ...over,
});

/** Pretend the app is up, without running the interval. */
function beat(at = new Date().toISOString(), pid = process.pid): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(heartbeatPath(dir), JSON.stringify({ at, pid }));
}

/** The app's side of a hold whose id the test doesn't know (it's a fresh uuid). */
function firstPending(): ApprovalRequest | undefined {
  for (const entry of readdirSync(pendingDir(dir))) {
    if (!entry.endsWith(".json") || entry.endsWith(".reply.json")) continue;
    const parsed = parseRequest(readFileSync(join(pendingDir(dir), entry), "utf8"));
    if (parsed) return parsed;
  }
  return undefined;
}

function answerFirstPending(verdict: "allow" | "deny"): void {
  const pending = firstPending();
  if (pending) writeReply(dir, { id: pending.id, verdict, at: new Date().toISOString() });
}

beforeEach(() => {
  userData = mkdtempSync(join(tmpdir(), "doorman-approvals-"));
  dir = guardDir(userData);
  mkdirSync(pendingDir(dir), { recursive: true });
});

afterEach(() => {
  rmSync(userData, { recursive: true, force: true });
});

describe("heartbeat", () => {
  it("is fresh only inside its window, in both directions", () => {
    const now = Date.parse("2026-08-25T12:00:00.000Z");
    expect(heartbeatFresh(JSON.stringify({ at: "2026-08-25T11:59:50.000Z" }), now)).toBe(true);
    expect(heartbeatFresh(JSON.stringify({ at: "2026-08-25T11:58:00.000Z" }), now)).toBe(false);
    // A clock that jumped backwards must not read as fresh forever.
    expect(heartbeatFresh(JSON.stringify({ at: "2026-08-25T13:00:00.000Z" }), now)).toBe(false);
    expect(heartbeatFresh("not json", now)).toBe(false);
    expect(heartbeatFresh(undefined, now)).toBe(false);
  });

  it("stops claiming the app is there once it quits", () => {
    const heartbeat = new GuardHeartbeat({ userDataDir: userData, version: "1.2.3", log: () => {} });
    heartbeat.start(60_000);
    expect(appListening(dir)).toBe(true);
    expect(JSON.parse(readFileSync(heartbeatPath(dir), "utf8")).version).toBe("1.2.3");

    heartbeat.clear();
    // This is the "no human, no hold" gate: a guard spawned now falls through
    // to Claude Code's own prompt instead of waiting out the window.
    expect(appListening(dir)).toBe(false);
  });

  it("is not live once the process that wrote it is gone, however fresh", () => {
    // Found on Windows: a `doorman watch` killed with Stop-Process gets no
    // cleanup, so its last heartbeat stays on disk and is fresh for up to 45s
    // more — and every guard spawned in that window held its call for nobody.
    // A child that has already exited gives a pid that is really gone.
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    expect(dead).toBeGreaterThan(0);
    expect(pidAlive(dead)).toBe(false);
    const now = Date.now();
    const fresh = new Date(now).toISOString();
    expect(heartbeatLive(JSON.stringify({ at: fresh, pid: dead }), now)).toBe(false);
    beat(fresh, dead);
    expect(appListening(dir, now)).toBe(false);

    // The same fresh heartbeat from a running process is someone to ask…
    expect(heartbeatLive(JSON.stringify({ at: fresh, pid: process.pid }), now)).toBe(true);
    beat(fresh, process.pid);
    expect(appListening(dir, now)).toBe(true);
    // …but a live pid doesn't revive an old one (pids are reused), and a
    // heartbeat that names no process names nobody.
    expect(heartbeatLive(JSON.stringify({ at: new Date(now - 60_000).toISOString(), pid: process.pid }), now)).toBe(false);
    expect(heartbeatLive(JSON.stringify({ at: fresh }), now)).toBe(false);
  });
});

describe("holdForVerdict", () => {
  it("polls on a timer that keeps the guard process alive", () => {
    // A REGRESSION, found by running the compiled guard rather than this file:
    // the poll timer was unref'd (copied from the app's timer habit). The guard's
    // stdin has already ended while it waits, so an unref'd timer leaves node
    // with nothing referenced — it exits mid-hold, code 0, no output, and Claude
    // Code runs the tool call. A silent fail-open on precisely the calls this
    // module exists to hold, indistinguishable from success.
    //
    // vitest cannot catch it (its own event loop keeps the process up), so the
    // assertion is on the source: no unref anywhere near the sleep.
    const source = readFileSync(
      new URL("../main/guard/handshake.ts", import.meta.url),
      "utf8",
    );
    const sleepFn = /const sleep[\s\S]*?;\n/.exec(source);
    expect(sleepFn, "the sleep helper moved — re-point this test").toBeTruthy();
    expect(sleepFn![0]).not.toMatch(/unref/);
  });

  it("returns the app's answer", async () => {
    beat();
    const req = request();
    writeRequest(dir, req);
    setTimeout(() => writeReply(dir, { id: req.id, verdict: "allow", at: new Date().toISOString() }), 30);
    const held = await holdForVerdict(dir, req.id, 5, { pollMs: 10 });
    expect(held.outcome).toBe("answered");
    expect(held.outcome === "answered" && held.reply.verdict).toBe("allow");
  });

  it("times out when nobody answers, even with the app up", async () => {
    beat();
    const req = request();
    writeRequest(dir, req);
    const held = await holdForVerdict(dir, req.id, 0.2, { pollMs: 10 });
    expect(held.outcome).toBe("timeout");
  });

  it("gives up immediately when no app is listening", async () => {
    const req = request();
    writeRequest(dir, req);
    const started = Date.now();
    const held = await holdForVerdict(dir, req.id, 30, { pollMs: 10 });
    expect(held.outcome).toBe("app_gone");
    // Not "eventually" — a 30s hold with nobody home would freeze the session.
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("treats a swept request as withdrawn rather than waiting it out", async () => {
    beat();
    const req = request();
    writeRequest(dir, req);
    setTimeout(() => rmSync(requestPath(dir, req.id), { force: true }), 30);
    const held = await holdForVerdict(dir, req.id, 5, { pollMs: 10 });
    expect(held.outcome).toBe("app_gone");
  });

  it("ignores a reply for a different request", () => {
    writeReply(dir, { id: "someone-else", verdict: "allow", at: new Date().toISOString() });
    // Same id in the filename, wrong id inside: refuse it rather than acting on it.
    writeFileSync(replyPath(dir, "req-1"), JSON.stringify({ id: "req-2", verdict: "allow" }));
    expect(readReply(dir, "req-1")).toBeUndefined();
    writeFileSync(replyPath(dir, "req-1"), JSON.stringify({ id: "req-1", verdict: "maybe" }));
    expect(readReply(dir, "req-1")).toBeUndefined();
  });

  it("leaves nothing behind", () => {
    const req = request();
    writeRequest(dir, req);
    writeReply(dir, { id: req.id, verdict: "deny", at: new Date().toISOString() });
    clearExchange(dir, req.id);
    expect(existsSync(requestPath(dir, req.id))).toBe(false);
    expect(existsSync(replyPath(dir, req.id))).toBe(false);
  });

  it("parses a request defensively and never invents a verdict", () => {
    expect(parseRequest("{")).toBeUndefined();
    expect(parseRequest(JSON.stringify({ at: "2026-08-25T00:00:00.000Z" }))).toBeUndefined();
    expect(parseRequest(JSON.stringify({ id: "x", at: "whenever" }))).toBeUndefined();
    const parsed = parseRequest(JSON.stringify({ id: "x", at: "2026-08-25T00:00:00.000Z", detectors: [1, "env_dump"] }))!;
    expect(parsed.detectors).toEqual(["env_dump"]);
    expect(parsed.on_timeout).toBe("deny"); // the safe reading of a missing field
    expect(parsed.hold_seconds).toBe(60);
  });
});

describe("ApprovalWatcher", () => {
  const collect = () => {
    const changes: ApprovalRequest[][] = [];
    const fresh: ApprovalRequest[] = [];
    const watcher = new ApprovalWatcher({
      userDataDir: userData,
      onChange: (pending) => changes.push(pending),
      onNew: (req) => fresh.push(req),
      log: () => {},
    });
    return { watcher, changes, fresh };
  };

  it("surfaces a held call once, then answers it", () => {
    const { watcher, changes, fresh } = collect();
    writeRequest(dir, request());
    watcher.poll();
    watcher.poll(); // a second pass must not re-notify
    expect(fresh).toHaveLength(1);
    expect(fresh[0]!.tool_name).toBe("Bash");
    expect(changes).toHaveLength(1);
    expect(watcher.list()).toHaveLength(1);

    expect(watcher.resolve("req-1", "deny", ["destructive_command"])).toBe(true);
    const reply = readReply(dir, "req-1")!;
    expect(reply.verdict).toBe("deny");
    expect(reply.silenced).toEqual(["destructive_command"]);
    // The card goes the moment it's answered, not when the guard cleans up.
    expect(watcher.list()).toHaveLength(0);
    expect(watcher.resolve("req-1", "deny")).toBe(false);
  });

  it("sweeps a request whose window has passed", () => {
    const { watcher, fresh } = collect();
    writeRequest(
      dir,
      request({ at: new Date(Date.now() - 5 * 60_000).toISOString(), hold_seconds: 60 }),
    );
    watcher.poll();
    // The guard already timed out and answered on its own — collecting a verdict
    // now would be collecting it for nothing.
    expect(fresh).toHaveLength(0);
    expect(watcher.list()).toHaveLength(0);
    expect(existsSync(requestPath(dir, "req-1"))).toBe(false);
  });

  it("sweeps a request whose guard process is gone", () => {
    const { watcher, fresh } = collect();
    // pid 1 is alive; a pid we can prove is dead is the point, so use a
    // deliberately absent one.
    writeRequest(dir, request({ pid: 2_147_483_600 }));
    watcher.poll();
    expect(fresh).toHaveLength(0);
    expect(watcher.list()).toHaveLength(0);
  });

  it("drops a card when the guard withdraws its own request", () => {
    const { watcher, changes } = collect();
    writeRequest(dir, request());
    watcher.poll();
    rmSync(requestPath(dir, "req-1"), { force: true });
    watcher.poll();
    expect(watcher.list()).toHaveLength(0);
    expect(changes[changes.length - 1]).toEqual([]);
  });

  it("ignores reply files and half-written requests", () => {
    const { watcher, fresh } = collect();
    writeReply(dir, { id: "req-9", verdict: "allow", at: new Date().toISOString() });
    writeFileSync(join(pendingDir(dir), "req-8.json"), "{ half");
    watcher.poll();
    expect(fresh).toHaveLength(0);
    expect(watcher.list()).toHaveLength(0);
  });
});

describe("holdForHuman — what the guard ends up printing", () => {
  const decision = {
    decision: "ask" as const,
    reason: "Doorman flagged this tool call: Destructive command.",
    max_severity: "high" as const,
    detectors: ["destructive_command" as const],
    warned: [],
  };
  const policy = (over: Partial<GuardPolicy["confirm"]> = {}): GuardPolicy => ({
    ...defaultPolicy(),
    confirm: { interactive: true, hold_seconds: 0.4, on_timeout: "deny", unattended: "deny", ...over },
  });
  const context = { host: "claude" as const, session_id: "s", tool_name: "Bash", target: "rm", redacted: '{"command":"rm -rf x"}' };

  it("prints NOTHING when the person allows — our check is added, never removed", async () => {
    beat();
    setTimeout(() => answerFirstPending("allow"), 40);
    const held = await holdForHuman(dir, policy({ hold_seconds: 5 }), decision, context, { pollMs: 10 });
    // "allow" here is guard.ts's signal to write no output at all, so Claude
    // Code still runs its own permission prompt.
    expect(held).toMatchObject({ decision: "allow", resolution: "allowed" });
    // The telemetry the Analytics screen is built from: a reply with no `via`
    // (an older app build) reads as answered from the window.
    expect(held.telemetry.decided_via).toBe("window");
    expect(Number.isFinite(Date.parse(held.telemetry.held_at))).toBe(true);
    expect(Date.parse(held.telemetry.decided_at)).toBeGreaterThanOrEqual(Date.parse(held.telemetry.held_at));
    expect(held.telemetry.hold_ms).toBeGreaterThanOrEqual(0);
  });

  it("records which surface answered, and a project-scoped allow", async () => {
    beat();
    setTimeout(() => {
      const pending = firstPending();
      if (pending) writeReply(dir, { id: pending.id, verdict: "allow", at: new Date().toISOString(), via: "panel", allow_scope: "project" });
    }, 40);
    const held = await holdForHuman(dir, policy({ hold_seconds: 5 }), decision, context, { pollMs: 10 });
    expect(held.telemetry.decided_via).toBe("panel");
    expect(held.telemetry.allow_scope).toBe("project");
  });

  it("publishes the held keys and custom labels the scoped-allow flow reads", async () => {
    beat();
    let published: ApprovalRequest | undefined;
    setTimeout(() => {
      published = firstPending();
      if (published) writeReply(dir, { id: published.id, verdict: "deny", at: new Date().toISOString() });
    }, 40);
    await holdForHuman(
      dir,
      policy({ hold_seconds: 5 }),
      { ...decision, detectors: ["destructive_command", "custom:deploy"] },
      {
        ...context,
        held_keys: [{ detector: "destructive_command", key_name: "rm -rf near root" }, { detector: "custom:deploy" }],
        detector_labels: { "custom:deploy": "Deploy without a ticket" },
      },
      { pollMs: 10 },
    );
    expect(published?.held_keys).toEqual([
      { detector: "destructive_command", key_name: "rm -rf near root" },
      { detector: "custom:deploy" },
    ]);
    expect(published?.detector_labels).toEqual({ "custom:deploy": "Deploy without a ticket" });
  });

  it("denies with a reason that names the rule and the person", async () => {
    beat();
    setTimeout(() => answerFirstPending("deny"), 40);
    const held = await holdForHuman(dir, policy({ hold_seconds: 5 }), decision, context, { pollMs: 10 });
    expect(held.decision).toBe("deny");
    expect(held.resolution).toBe("denied");
    expect(held.reason).toContain("Destructive command");
    expect(held.reason).toContain("You denied it");
    expect(held.reason).not.toContain("rm -rf"); // the reason names rules, not values
  });

  it("denies on no answer, and says why", async () => {
    beat();
    const held = await holdForHuman(dir, policy(), decision, context, { pollMs: 10 });
    expect(held.decision).toBe("deny");
    expect(held.resolution).toBe("timeout");
    expect(held.reason).toContain("nobody approved it");
  });

  it("can be configured to hand a timeout to Claude Code instead", async () => {
    beat();
    const held = await holdForHuman(dir, policy({ on_timeout: "ask" }), decision, context, { pollMs: 10 });
    expect(held).toMatchObject({ decision: "ask", reason: decision.reason, resolution: "timeout" });
    expect(held.telemetry.decided_via).toBe("timeout");
  });

  it("falls back to Claude Code's own prompt when the app isn't there", async () => {
    const held = await holdForHuman(dir, policy({ hold_seconds: 30 }), decision, context, { pollMs: 10 });
    expect(held).toMatchObject({ decision: "ask", reason: decision.reason, resolution: "unattended" });
    expect(held.telemetry.decided_via).toBe("app-absent");
  });

  it("caps the window at a host's ceiling when asked, and says the window it really used", async () => {
    beat();
    let published: ApprovalRequest | undefined;
    setTimeout(() => {
      published = firstPending();
    }, 40);
    const held = await holdForHuman(dir, policy({ hold_seconds: 300 }), decision, context, { pollMs: 10, holdSeconds: 0.3 });
    expect(published?.hold_seconds).toBe(0.3);
    expect(held.decision).toBe("deny");
    expect(held.resolution).toBe("timeout");
    expect(held.reason).toContain("held for 0.3s");
  });

  it("publishes only redacted evidence, and cleans up after itself", async () => {
    beat();
    let published: ApprovalRequest | undefined;
    setTimeout(() => {
      published = firstPending();
      if (published) writeReply(dir, { id: published.id, verdict: "allow", at: new Date().toISOString() });
    }, 40);
    await holdForHuman(
      dir,
      policy({ hold_seconds: 5 }),
      decision,
      { ...context, redacted: 'AWS_SECRET="[redacted:aws]" ' + "x".repeat(2000) },
      { pollMs: 10 },
    );
    expect(published).toBeTruthy();
    expect(published!.preview).toContain("[redacted:aws]");
    expect(published!.preview.length).toBeLessThanOrEqual(700);
    expect(published!.pid).toBe(process.pid);
    expect(readdirSync(pendingDir(dir))).toEqual([]);
  });
});

describe("host-specific PreToolUse output", () => {
  it("selects Codex only for the explicit host argument", () => {
    expect(guardHostFromArgv(["node", "guard.js"])).toBe("claude");
    expect(guardHostFromArgv(["node", "guard.js", "--host", "codex"])).toBe("codex");
    expect(guardHostFromArgv(["node", "guard.js", "--host", "other"])).toBe("claude");
    expect(guardHostFromArgv(["node", "guard.js", "--host"])).toBe("claude");
  });

  it("keeps Claude's native ask and never emits unsupported ask to Codex", () => {
    const claude = JSON.parse(hookOutputForHost("claude", "ask", "Review this call")!);
    expect(claude.hookSpecificOutput.permissionDecision).toBe("ask");

    // Default (`unattended: "deny"`, 2026-09-10): an ask Codex cannot carry is
    // its valid deny — never a forged native ask, never a silent continue.
    const codex = JSON.parse(hookOutputForHost("codex", "ask", "Review this call")!);
    expect(codex.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(codex.hookSpecificOutput.permissionDecisionReason).toContain("Review this call");
    expect(codex.systemMessage).toBeUndefined();

    // The pre-2026-09-10 behaviour, one setting away: the visible warning.
    const lenient = JSON.parse(hookOutputForHost("codex", "ask", "Review this call", "continue")!);
    expect(lenient.hookSpecificOutput).toBeUndefined();
    expect(lenient.systemMessage).toContain("does not support native PreToolUse ask");
    expect(lenient.systemMessage).toContain("continuing");
  });

  describe("unattendedOutcome — an ask nobody can answer (review F1)", () => {
    const strict = { confirm: { interactive: true, hold_seconds: 60, on_timeout: "deny" as const, unattended: "deny" as const } };
    const lenient = { confirm: { ...strict.confirm, unattended: "continue" as const } };
    const native = { supportsNativeAsk: true };
    const noAsk = { supportsNativeAsk: false };

    it("leaves allow and deny alone whatever the host or policy", () => {
      for (const host of [native, noAsk]) {
        for (const policy of [strict, lenient]) {
          expect(unattendedOutcome(host, policy, "allow", undefined)).toEqual({ decision: "allow", resolution: undefined });
          expect(unattendedOutcome(host, policy, "deny", "denied")).toEqual({ decision: "deny", resolution: "denied" });
        }
      }
    });

    it("hands the question to a host with a native ask — that is a real ask, not a fail-open", () => {
      expect(unattendedOutcome(native, strict, "ask", undefined)).toEqual({ decision: "ask", resolution: undefined });
      expect(unattendedOutcome(native, strict, "ask", "unattended")).toEqual({ decision: "ask", resolution: "unattended" });
    });

    it("denies on a host without one: unavailable when nobody was reached, the hold's own resolution otherwise", () => {
      // No hold at all (app absent, or holding off).
      expect(unattendedOutcome(noAsk, strict, "ask", undefined)).toEqual({ decision: "deny", resolution: "unavailable" });
      // App vanished mid-hold.
      expect(unattendedOutcome(noAsk, strict, "ask", "unattended")).toEqual({ decision: "deny", resolution: "unavailable" });
      // Timeout with the `ask` fallback: still a deny here, and it stays a timeout.
      expect(unattendedOutcome(noAsk, strict, "ask", "timeout")).toEqual({ decision: "deny", resolution: "timeout" });
    });

    it("passes the ask through under `continue`, so hostEmit prints the host's warning", () => {
      expect(unattendedOutcome(noAsk, lenient, "ask", undefined)).toEqual({ decision: "ask", resolution: undefined });
      expect(unattendedOutcome(noAsk, lenient, "ask", "unattended")).toEqual({ decision: "ask", resolution: "unattended" });
    });

    it("treats a PROMPT hold as unattended on every host — no host has a native ask for one", () => {
      expect(unattendedOutcome(native, strict, "ask", undefined, { prompt: true })).toEqual({ decision: "deny", resolution: "unavailable" });
      expect(unattendedOutcome(native, lenient, "ask", undefined, { prompt: true })).toEqual({ decision: "ask", resolution: undefined });
    });
  });

  it("denies both hosts and leaves an approved call silent", () => {
    for (const host of ["claude", "codex"] as const) {
      const denied = JSON.parse(hookOutputForHost(host, "deny", "Blocked")!);
      expect(denied.hookSpecificOutput.permissionDecision).toBe("deny");
      expect(hookOutputForHost(host, "allow")).toBeUndefined();
    }
  });
});

describe("what the person is told", () => {
  it("names rules and the target, never a value", () => {
    expect(approvalSummary(request())).toBe("Destructive command · Bash → rm");
    expect(
      approvalSummary(request({ detectors: ["secret_egress", "env_dump"], target: undefined, tool_name: undefined })),
    ).toBe("Secret egress over the network, Environment dump");
    expect(approvalSummary(request({ detectors: [] }))).toBe("Security policy · Bash → rm");
  });

  it("doesn't double-notify about the call it is already asking about", () => {
    const row = (over: Partial<FindingRow>): FindingRow =>
      ({
        finding_id: "f1",
        detector: "destructive_command",
        severity: "high",
        excerpt: "rm -rf",
        occurrences: 1,
        source: "claude-code",
        origin: "guard",
        session_id: "sess-1",
        status: "open",
        first_seen_at: "2026-08-25T00:00:00.000Z",
        last_seen_at: "2026-08-25T00:00:00.000Z",
        ...over,
      }) as FindingRow;

    const pending = [request()];
    expect(suppressHeldFindings([row({})], pending)).toHaveLength(0);
    // A different session, or a rule that isn't what's being held, still notifies.
    expect(suppressHeldFindings([row({ session_id: "sess-2" })], pending)).toHaveLength(1);
    expect(suppressHeldFindings([row({ detector: "env_dump" })], pending)).toHaveLength(1);
    expect(suppressHeldFindings([row({})], [])).toHaveLength(1);
  });
});

describe("the finding ledger records how a held call ended", () => {
  const detected = mintFindingRow(
    { detector: "destructive_command", severity: "high", excerpt: "rm -rf", occurrences: 1 },
    { source: "claude-code", origin: "guard", session_id: "s", at: "2026-08-25T10:00:00.000Z", enforced: "ask" },
  );

  it("lets the resolution line overrule the detection line", () => {
    const resolved = mintFindingRow(
      { detector: "destructive_command", severity: "high", excerpt: "rm -rf", occurrences: 1 },
      {
        source: "claude-code",
        origin: "guard",
        session_id: "s",
        at: "2026-08-25T10:00:05.000Z",
        enforced: "deny",
        resolution: "denied",
      },
    );
    const merged = mergeFinding(detected, resolved);
    // Without the override this would still read "asked", which is the one thing
    // the Radar's blocked/asked counts must not get wrong.
    expect(merged.enforced).toBe("deny");
    expect(merged.resolution).toBe("denied");
    expect(merged.finding_id).toBe(detected.finding_id);
  });

  it("reads the band off the newest sighting, so a lead confirmed later surfaces again", () => {
    const lead = { ...detected, confidence: "low" as const };
    // Re-sighted with the detector sure this time: absent means high, and the
    // first value must not ride along under `...existing`.
    const confirmed = mergeFinding(lead, { ...detected });
    expect(confirmed.confidence).toBeUndefined();
    // …and the other way: a sure row a model later stands down reads medium.
    expect(mergeFinding(detected, { ...detected, confidence: "medium" }).confidence).toBe("medium");
    expect(mergeFinding(lead, { ...detected, confidence: "medium" }).confidence).toBe("medium");
  });

  it("keeps the resolution when the same finding is merely re-observed later", () => {
    const resolved = { ...detected, enforced: "deny" as const, resolution: "timeout" as const };
    const reobserved = mergeFinding(resolved, { ...detected, enforced: undefined });
    expect(reobserved.resolution).toBe("timeout");
    expect(reobserved.enforced).toBe("deny");
  });
});
