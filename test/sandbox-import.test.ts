import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CaptureEngine, type EngineDeps } from "../main/capture.js";
import { defaultPolicy } from "../main/guard/policy.js";
import { detectionsExportFor, ledgerExportFor, radarFeedRows, radarRows } from "../main/lib/app-views.js";
import { EvidenceVault, type VaultCrypto } from "../main/lib/evidence-vault.js";
import { resumeCommand } from "../main/lib/terminal-handoff.js";
import {
  buildSandboxBundle,
  drainImports,
  importsDir,
  pendingImports,
  sandboxRecords,
  validateSandboxBundle,
  writeDropFile,
  type SandboxBundle,
} from "../main/lib/sandbox-import.js";

/**
 * A Docker Sandbox's record brought to the host: the bundle built from a
 * sandbox's engine, the drop file, and the host engine ingesting it — once,
 * idempotently, visible where the host's own transcript rule would hide it,
 * labelled with the sandbox, and never holding a value.
 */

const SANDBOX_SESSION = "5b0c0000-1111-2222-3333-444444444444";
const HOST_SESSION = "a0570000-1111-2222-3333-444444444444";
/** Shaped like a GitHub token, random enough not to read as a placeholder. */
const TOKEN = "ghp_R8xK2mQ9vL4tZ7wN3pB6yH1jF5cD0sA2eG8u";

const keychain: VaultCrypto = {
  isAvailable: () => true,
  encrypt: (plain) => Buffer.from(Buffer.from(plain, "utf8").map((b) => b ^ 0x5a)),
  decrypt: (cipher) => Buffer.from(cipher.map((b) => b ^ 0x5a)).toString("utf8"),
};

/** Two days back: past the grace in which a fresh sighting is shown on trust. */
const at = (minutes: number) => new Date(Date.now() - 2 * 86_400_000 + minutes * 60_000).toISOString();

/** A Claude Code session that pastes a token and dumps the environment. */
function transcript(session: string, cwd: string): string {
  const usage = { input_tokens: 1000, output_tokens: 200, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
  return `${[
    { type: "user", uuid: `${session}-p1`, timestamp: at(0), sessionId: session, cwd, message: { role: "user", content: `push the release with ${TOKEN} please` } },
    {
      type: "assistant",
      timestamp: at(1),
      sessionId: session,
      cwd,
      message: { id: `msg_${session}_1`, model: "claude-opus-5", role: "assistant", content: [{ type: "tool_use", id: "tu_1", name: "Bash", input: { command: "printenv" } }], usage },
    },
    {
      type: "assistant",
      timestamp: at(2),
      sessionId: session,
      cwd,
      message: { id: `msg_${session}_2`, model: "claude-opus-5", role: "assistant", content: [{ type: "text", text: "Pushed." }], usage },
    },
  ]
    .map((line) => JSON.stringify(line))
    .join("\n")}\n`;
}

function engineAt(home: string, vault?: EvidenceVault): CaptureEngine {
  const deps: EngineDeps = {
    storeDir: join(home, "store"),
    claudeProjectsDir: join(home, ".claude", "projects"),
    codexSessionsDir: join(home, ".codex", "sessions"),
    home,
    policy: () => defaultPolicy(),
    retentionDays: () => 0,
    onUpdate: () => {},
    onNewFindings: () => {},
    log: () => {},
    ...(vault ? { vault } : {}),
  };
  return new CaptureEngine(deps);
}

describe("sandbox import", () => {
  let root: string;
  let sandboxHome: string;
  let hostHome: string;
  let dataDir: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-sandbox-import-"));
    sandboxHome = join(root, "sandbox");
    hostHome = join(root, "host");
    dataDir = join(root, "host-data");
    for (const [home, session, cwd] of [
      [sandboxHome, SANDBOX_SESSION, "/home/agent/workspace"],
      [hostHome, HOST_SESSION, "/Users/dev/app"],
    ] as const) {
      const project = join(home, ".claude", "projects", "-project");
      mkdirSync(project, { recursive: true });
      writeFileSync(join(project, `${session}.jsonl`), transcript(session, cwd));
    }
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  /** What `doorman export bundle` builds inside the sandbox, from its engine. */
  async function sandboxBundle(): Promise<SandboxBundle> {
    const engine = engineAt(sandboxHome);
    engine.open();
    await engine.scan();
    const now = new Date();
    const bundle = buildSandboxBundle({
      detections: detectionsExportFor(engine, defaultPolicy(), "0.0.0-test", now).bundle,
      ledger: ledgerExportFor(engine, undefined, "0.0.0-test", now)!.bundle,
      sandbox: { name: "box-a", id: "sbx-123" },
      app_version: "0.0.0-test",
      generated_at: now,
    });
    engine.stop();
    return bundle;
  }

  /** The host's engine, its own transcript scanned (so its rail is listed). */
  async function hostEngine(): Promise<CaptureEngine> {
    const engine = engineAt(hostHome, new EvidenceVault(join(hostHome, "store"), keychain));
    engine.open();
    await engine.scan();
    return engine;
  }

  it("validates, carries no value, and scopes every id to the sandbox", async () => {
    const bundle = await sandboxBundle();
    expect(validateSandboxBundle(bundle)).toEqual([]);
    expect(bundle.detections.detections.length).toBeGreaterThan(0);
    expect(bundle.ledger.sessions.map((s) => s.id)).toEqual([SANDBOX_SESSION]);
    const file = writeDropFile(dataDir, bundle, new Date("2026-10-20T09:15:02.123Z"));
    expect(file).toBe(join(importsDir(dataDir), "sandbox-box-a-20261020T091502Z.json"));
    const text = readFileSync(file, "utf8");
    expect(text).not.toContain(TOKEN);
    expect(text).toContain("[redacted:");
    const records = sandboxRecords(bundle);
    expect(records.turns.every((t) => t.id.endsWith("@box-a") && t.session_id === `${SANDBOX_SESSION}@box-a` && t.sandbox === "box-a")).toBe(true);
    expect(records.findings.every((f) => f.finding_id.endsWith("@box-a") && f.sandbox === "box-a" && (f.session_id === undefined || f.session_id.endsWith("@box-a")))).toBe(true);
    // A sandbox session can't be resumed here: the id is refused as a shell word.
    expect(resumeCommand("claude-code", `${SANDBOX_SESSION}@box-a`)).toBeUndefined();
    // Even a value an older Doorman left unmasked in the bundle is masked on the way in.
    const leaky: SandboxBundle = JSON.parse(text);
    leaky.ledger.sessions[0]!.items[0]!.text = `leaked ${TOKEN}`;
    leaky.detections.detections[0]!.excerpt = `leaked ${TOKEN}`;
    expect(JSON.stringify(sandboxRecords(leaky))).not.toContain(TOKEN);
  });

  it("ingests the drop file once: visible, labelled, and a re-import adds nothing", async () => {
    const bundle = await sandboxBundle();
    const host = await hostEngine();
    const before = host.shownFindings().length;
    writeDropFile(dataDir, bundle, new Date());
    const first = drainImports(dataDir, (b) => host.importSandboxBundle(b), { consume: true });
    expect(first).toHaveLength(1);
    expect(first[0]!.ok).toBe(true);
    expect(first[0]!.result).toMatchObject({ sandbox: "box-a", sessions: 1 });
    expect(first[0]!.result!.turns_added).toBeGreaterThan(0);
    expect(first[0]!.result!.findings_added).toBe(bundle.detections.detections.length);
    // Consumed: moved to done/, nothing pending.
    expect(pendingImports(dataDir)).toEqual([]);
    expect(readdirSync(join(importsDir(dataDir), "done"))).toHaveLength(1);

    // The host lists its own session AND the sandbox's — whose transcript is
    // not on this disk, which would hide a host session.
    const sessions = host.sessions();
    expect(sessions.map((s) => s.id).sort()).toEqual([HOST_SESSION, `${SANDBOX_SESSION}@box-a`].sort());
    expect(sessions.find((s) => s.id === `${SANDBOX_SESSION}@box-a`)).toMatchObject({ sandbox: "box-a", source: "claude-code" });
    expect(sessions.find((s) => s.id === HOST_SESSION)!.sandbox).toBeUndefined();
    expect(host.search("release").map((t) => t.session_id)).toContain(`${SANDBOX_SESSION}@box-a`);

    // The Radar: shown, in the feed, and its place names the sandbox.
    const shown = host.shownFindings();
    const fromSandbox = shown.filter((f) => f.sandbox === "box-a");
    expect(shown.length).toBe(before + fromSandbox.length);
    expect(fromSandbox.length).toBe(bundle.detections.detections.length);
    const feed = radarFeedRows(radarRows(shown, hostHome), { hiddenBands: [], showFalsePositives: false });
    const sandboxCards = feed.filter((r) => r.sandbox === "box-a");
    expect(sandboxCards.length).toBeGreaterThan(0);
    for (const r of sandboxCards) {
      expect(r.place).toContain("sandbox box-a");
      expect(r.exposure_key).toContain("@sandbox:box-a");
    }
    // The host's own rows are untouched by the label.
    for (const r of feed.filter((x) => x.sandbox === undefined)) expect(r.place).not.toContain("sandbox");
    // VIEW RAW: the evidence stays in the sandbox, and says how to read it there.
    const reveal = host.revealFinding(fromSandbox[0]!.finding_id);
    expect(reveal).toEqual({ ok: false, error: expect.stringContaining("sbx exec box-a doorman findings show") });
    expect(JSON.stringify(shown)).not.toContain(TOKEN);

    // Pulled again: the same ids, so nothing is added and nothing rewritten.
    const store = (name: string) => readFileSync(join(hostHome, "store", name), "utf8");
    const turnsBefore = store("turns.jsonl");
    const findingsBefore = store("findings.jsonl");
    writeDropFile(dataDir, bundle, new Date());
    const second = drainImports(dataDir, (b) => host.importSandboxBundle(b), { consume: true });
    expect(second[0]!.result).toMatchObject({ turns_added: 0, findings_added: 0, findings_updated: 0 });
    expect(store("turns.jsonl")).toBe(turnsBefore);
    expect(store("findings.jsonl")).toBe(findingsBefore);
    host.stop();

    // A restart reads them back as sandbox items, still exempt from the rule.
    const again = await hostEngine();
    expect(again.sessions().some((s) => s.sandbox === "box-a")).toBe(true);
    expect(again.shownFindings().filter((f) => f.sandbox === "box-a")).toHaveLength(fromSandbox.length);
    again.stop();
  });

  it("keeps triage made on the host when the sandbox is pulled again", async () => {
    const bundle = await sandboxBundle();
    const host = await hostEngine();
    host.importSandboxBundle(bundle);
    const id = host.shownFindings().find((f) => f.sandbox === "box-a")!.finding_id;
    expect(host.setFindingStatus(id, "resolved")).toBe(true);
    host.importSandboxBundle(bundle);
    expect(host.shownFinding(id)!.status).toBe("resolved");
    host.stop();
  });

  it("leaves the files for the owner on a copy, and sets aside a broken one", async () => {
    const bundle = await sandboxBundle();
    const host = await hostEngine();
    const file = writeDropFile(dataDir, bundle, new Date());
    const copy = drainImports(dataDir, (b) => host.importSandboxBundle(b), { consume: false });
    expect(copy[0]!.ok).toBe(true);
    expect(pendingImports(dataDir)).toEqual([file]);

    writeFileSync(join(importsDir(dataDir), "sandbox-bad-1.json"), "{ not json");
    const unnamed = { ...bundle, sandbox: null };
    writeFileSync(join(importsDir(dataDir), "sandbox-bad-2.json"), JSON.stringify(unnamed));
    const owner = drainImports(dataDir, (b) => host.importSandboxBundle(b), { consume: true });
    expect(owner.map((o) => o.ok).sort()).toEqual([false, false, true]);
    expect(pendingImports(dataDir)).toEqual([]);
    expect(readdirSync(join(importsDir(dataDir), "rejected")).sort()).toEqual(["sandbox-bad-1.json", "sandbox-bad-2.json"]);
    expect(existsSync(join(importsDir(dataDir), "done", file.split("/").pop()!))).toBe(true);
    host.stop();
  });
});
