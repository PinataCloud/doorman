import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CaptureEngine } from "../main/capture.js";
import { findingContext } from "../main/ai-assistant.js";
import { defaultPolicy, type GuardPolicy } from "../main/guard/policy.js";
import {
  DETECTION_SCHEMA,
  DETECTION_SCHEMA_ID,
  DETECTION_SCHEMA_VERSION,
  DETECTIONS_EXPORT_SCHEMA_ID,
  buildDetectionsExport,
  toDetectionRecord,
  upgradeFindingRow,
  validateDetection,
  validateDetectionsExport,
} from "../main/lib/detection-schema.js";
import { EvidenceVault, sandboxVaultCrypto, type VaultCrypto } from "../main/lib/evidence-vault.js";
import { renderSchemaFiles } from "../main/lib/schema-files.js";
import { alignRedactedValues } from "../main/lib/reveal.js";
import { maskFindingRow, maskText, maskTurnText } from "../main/lib/masking.js";
import { accountForUnit } from "../main/lib/account.js";
import { TURN_TEXT_MAX_CHARS } from "../main/lib/turns.js";
import { LEDGER_EXPORT_SCHEMA_ID, buildLedgerExport, validateLedgerExport } from "../main/lib/ledger-export.js";
import type { LedgerTurn, SessionSummary } from "../main/lib/turns.js";
import {
  LOCAL_DETECTOR_LABELS,
  foldFindingLines,
  mergeFinding,
  mintFindingRow,
  ruleModeOf,
  type FindingRow,
} from "../main/lib/findings.js";

/**
 *: the detection schema is the ledger's contract, the export's shape
 * and Doorman AI's finding context; the evidence vault keeps the raw window
 * encrypted, and never in the clear.
 */

/**
 * EVERY field a stored row can carry, populated. `Required<…>` is the point:
 * add a field to FindingRow and this stops compiling until it is set here —
 * and then the validation below fails until the schema learns it too.
 */
const FULL_ROW: Required<Omit<FindingRow, "place" | "place_kind" | "exposure_key">> = {
  schema_version: DETECTION_SCHEMA_VERSION,
  finding_id: "0123456789abcdef",
  detector: "flow_secret_egress",
  severity: "critical",
  confidence: "medium",
  assist: { by: "second_opinion", model: "qwen3:1.7b", verdict: "confirmed", score: 0.9 },
  account: {
    by: "extractor",
    source_kind: "file",
    source_ref: ".env",
    name: "DB_PASSWORD",
    read_via: "cat",
    sink_tool: "curl",
    destination_host: "api.example.com",
    credential_family: "aws",
    family_noun: "AWS credential",
    gap: "4s",
    placeholder_signals: ["test_path"],
    sentence: "Read `.env`, then sent to `api.example.com` 4s later.",
    title: "`.env` read, then sent to `api.example.com`",
    so: "The credential may have left this Mac.",
    next: "Rotate it.",
  },
  key_name: ".env",
  excerpt: "curl -d [redacted:aws] https://api.example.com",
  occurrences: 1,
  tool_name: "Bash",
  target: "api.example.com",
  source: "claude-code",
  origin: "transcript",
  session_id: "s1",
  turn_id: "t2",
  source_turn_id: "t1",
  source_at: "2026-09-01T10:00:00.000Z",
  burned_usd: 0.42,
  burned_tokens: 4200,
  config_host: "Cursor",
  cwd: "/Users/dev/repo",
  status: "open",
  first_seen_at: "2026-09-01T10:00:04.000Z",
  last_seen_at: "2026-09-01T10:00:04.000Z",
  enforced: "excepted",
  exception: { pattern: "^\\.env$", detector: "dotenv_read", cwd_prefix: "/Users/dev", expires_at: "2026-10-01T00:00:00.000Z", note: "fixtures", origin: "manual" },
  resolution: "allowed",
  held_at: "2026-09-01T10:00:04.000Z",
  decided_at: "2026-09-01T10:00:09.000Z",
  decided_via: "panel",
  hold_ms: 5000,
  allow_scope: "project",
  detector_label: "Secret read, then network egress",
  rule_mode: "radar",
  app_version: "0.70.0",
  secrets: [{ label: "aws", length: 40, fingerprint: "0123456789abcdef", primary: true }],
};

/** A reversible stand-in for safeStorage: never plaintext on disk, so a test
 * can assert the value is absent from the file. */
const fakeKeychain = (available = true): VaultCrypto => ({
  isAvailable: () => available,
  encrypt: (plain) => Buffer.from(Buffer.from(plain, "utf8").map((b) => b ^ 0x5a)),
  decrypt: (cipher) => Buffer.from(cipher.map((b) => b ^ 0x5a)).toString("utf8"),
});

describe("detection schema", () => {
  it("accepts a row carrying every field FindingRow has", () => {
    expect(validateDetection(FULL_ROW)).toEqual([]);
  });

  it("accepts what mintFindingRow produces, and stamps the version", () => {
    const row = mintFindingRow(
      { detector: "dotenv_read", severity: "high", key_name: ".env", excerpt: "cat .env", occurrences: 1 },
      { source: "claude-code", origin: "transcript", session_id: "s1", at: "2026-09-01T10:00:00.000Z" },
    );
    expect(row.schema_version).toBe(DETECTION_SCHEMA_VERSION);
    expect(validateDetection(row)).toEqual([]);
  });

  it("refuses unknown fields, wrong enums, bad instants and a raw-looking secret entry", () => {
    const paths = (value: unknown) => validateDetection(value).map((p) => p.path);
    expect(paths({ ...FULL_ROW, surprise: 1 })).toContain("/surprise");
    expect(paths({ ...FULL_ROW, severity: "severe" })).toContain("/severity");
    expect(paths({ ...FULL_ROW, rule_mode: "loud" })).toContain("/rule_mode");
    expect(paths({ ...FULL_ROW, first_seen_at: "yesterday" })).toContain("/first_seen_at");
    // A secrets[] entry is a fingerprint: carrying the value is a schema error.
    expect(paths({ ...FULL_ROW, secrets: [{ label: "aws", length: 3, fingerprint: "0123456789abcdef", value: "abc" }] })).toContain(
      "/secrets/0/value",
    );
    const { finding_id: _id, ...noId } = FULL_ROW;
    expect(paths(noId)).toContain("/finding_id");
  });

  it("names every shipped detector id with the detector pattern", () => {
    const pattern = new RegExp(DETECTION_SCHEMA.properties!.detector!.pattern!, "u");
    for (const id of Object.keys(LOCAL_DETECTOR_LABELS)) expect(id).toMatch(pattern);
    expect("custom:no-prod-db").toMatch(pattern);
  });

  it("upgrades a pre-schema ledger line on read and leaves a newer build's row alone", () => {
    const { schema_version: _v, rule_mode: _m, app_version: _a, secrets: _s, ...old } = FULL_ROW;
    const folded = foldFindingLines([JSON.stringify(old), "not json", JSON.stringify({ no: "id" })]);
    expect([...folded.keys()]).toEqual([FULL_ROW.finding_id]);
    expect(folded.get(FULL_ROW.finding_id)!.schema_version).toBe(DETECTION_SCHEMA_VERSION);
    expect(upgradeFindingRow({ ...old, schema_version: 99 })!.schema_version).toBe(99);
  });

  it("merge keeps the level, build and fingerprints of the newest sighting that had them", () => {
    const base = mintFindingRow(
      { detector: "dotenv_read", severity: "high", key_name: ".env", excerpt: "cat .env", occurrences: 1 },
      { source: "claude-code", origin: "transcript", session_id: "s1", at: "2026-09-01T10:00:00.000Z", rule_mode: "observe", app_version: "0.69.0", secrets: FULL_ROW.secrets },
    );
    const later = mintFindingRow(
      { detector: "dotenv_read", severity: "high", key_name: ".env", excerpt: "cat .env", occurrences: 1 },
      { source: "claude-code", origin: "guard", session_id: "s1", at: "2026-09-02T10:00:00.000Z", rule_mode: "ask", app_version: "0.70.0" },
    );
    const merged = mergeFinding(base, later);
    expect(merged.rule_mode).toBe("ask");
    expect(merged.app_version).toBe("0.70.0");
    expect(merged.secrets).toEqual(FULL_ROW.secrets);
    expect(validateDetection(merged)).toEqual([]);
  });

  it("reads a rule's level off the policy: guard mode, off, custom, radar-only", () => {
    const policy: GuardPolicy = {
      ...defaultPolicy(),
      modes: { dotenv_read: "block" },
      disabled: ["env_dump"],
      custom_rules: [{ id: "no-prod", label: "No prod", severity: "high", mode: "warn", when: { tool: "Bash" } }],
    };
    expect(ruleModeOf("dotenv_read", policy)).toBe("block");
    expect(ruleModeOf("env_dump", policy)).toBe("off");
    expect(ruleModeOf("destructive_command", { ...policy, modes: {} })).toBe("observe");
    expect(ruleModeOf("custom:no-prod", policy)).toBe("warn");
    expect(ruleModeOf("custom:deleted", policy)).toBeUndefined();
    expect(ruleModeOf("flow_secret_egress", policy)).toBe("radar");
    // Scans tool OUTPUT; the PreToolUse guard can never enforce it.
    expect(ruleModeOf("injected_instruction", policy)).toBe("radar");
  });

  it("builds an export that validates, drops snapshot-only fields and lists each rule once", () => {
    const shown = { ...FULL_ROW, place: "/Users/dev/repo", place_kind: "project" as const, exposure_key: "x" };
    const bundle = buildDetectionsExport({
      rows: [shown, { ...FULL_ROW, finding_id: "fedcba9876543210", detector: "dotenv_read", detector_label: undefined as never }],
      app_version: "0.70.0",
      generated_at: new Date("2026-09-28T12:00:00.000Z"),
      labelOf: (id) => `label ${id}`,
      modeOf: (id) => (id === "dotenv_read" ? "ask" : "radar"),
    });
    expect(validateDetectionsExport(bundle)).toEqual([]);
    // The FILE names its own schema, not the per-record one.
    expect(bundle.schema).toBe(DETECTIONS_EXPORT_SCHEMA_ID);
    expect(bundle.detections[0]).not.toHaveProperty("place");
    expect(bundle.detectors).toEqual([
      { id: "dotenv_read", label: "label dotenv_read", mode: "ask" },
      { id: "flow_secret_egress", label: "Secret read, then network egress", mode: "radar" },
    ]);
  });

  it("the committed schema files are what the code generates", () => {
    // Regenerate with: npx vite-node scripts/make-detection-schema.ts
    for (const [name, body] of Object.entries(renderSchemaFiles())) {
      const path = join(__dirname, "..", "schemas", name);
      expect(readFileSync(path, "utf8"), `${name} is stale`).toBe(body);
    }
  });

  it("hands Doorman AI the masked record, with fingerprints and never a value", () => {
    const text = findingContext(FULL_ROW, undefined, {}).text;
    expect(text).toContain(DETECTION_SCHEMA_ID);
    expect(text).toContain("Rule mode when last seen: radar");
    expect(text).toContain("fp 0123456789abcdef");
    const json = text.slice(text.indexOf("{", text.indexOf(DETECTION_SCHEMA_ID)));
    expect(JSON.parse(json)).toEqual(toDetectionRecord(FULL_ROW));
  });
});

describe("evidence vault", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "doorman-vault-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const evidence = { raw: "export TOKEN=ghp_SECRETVALUE", truncated: false, at: "2026-09-01T10:00:00.000Z", secrets: [{ label: "github", value: "ghp_SECRETVALUE" }] };

  it("keeps evidence encrypted, owner-only, and reads it back", () => {
    const vault = new EvidenceVault(dir, fakeKeychain());
    expect(vault.put("f1", "export TOKEN=[redacted:github]", evidence)).toBe(true);
    const file = join(dir, "evidence-vault.jsonl");
    expect(readFileSync(file, "utf8")).not.toContain("ghp_SECRETVALUE");
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const back = new EvidenceVault(dir, fakeKeychain()).get("f1", "export TOKEN=[redacted:github]");
    expect(back?.raw).toBe(evidence.raw);
    expect(back?.secrets).toEqual(evidence.secrets);
  });

  /** A keychain that counts every call — each one is a potential macOS prompt. */
  const countingKeychain = (behaviour: "allow" | "deny" | "unavailable" | "fail-later") => {
    const calls = { isAvailable: 0, encrypt: 0, decrypt: 0 };
    const base = fakeKeychain();
    let encrypts = 0;
    const crypto: VaultCrypto = {
      isAvailable: () => {
        calls.isAvailable += 1;
        return behaviour !== "unavailable";
      },
      encrypt: (plain) => {
        calls.encrypt += 1;
        encrypts += 1;
        if (behaviour === "deny") throw new Error("User canceled the operation.");
        if (behaviour === "fail-later" && encrypts > 1) throw new Error("keychain locked");
        return base.encrypt(plain);
      },
      decrypt: (cipher) => {
        calls.decrypt += 1;
        return base.decrypt(cipher);
      },
    };
    return { crypto, calls };
  };

  it("never touches the keychain until a value needs keeping", () => {
    const { crypto, calls } = countingKeychain("allow");
    const vault = new EvidenceVault(dir, crypto);
    vault.has("f1", "a");
    vault.get("f1", "a");
    vault.prune(new Set(["f1"]));
    vault.size();
    expect(calls).toEqual({ isAvailable: 0, encrypt: 0, decrypt: 0 });
  });

  it("asks the keychain ONCE per run, and a refusal is remembered — no dialog per detection", () => {
    const denied = countingKeychain("deny");
    const vault = new EvidenceVault(dir, denied.crypto);
    for (let i = 0; i < 20; i++) vault.put(`f${i}`, "a", evidence);
    vault.fingerprints(evidence.secrets);
    expect(denied.calls.isAvailable).toBe(1);
    expect(denied.calls.encrypt).toBe(1);
    expect(existsSync(join(dir, "evidence-vault.jsonl"))).toBe(false);

    const missing = countingKeychain("unavailable");
    const none = new EvidenceVault(dir, missing.crypto);
    for (let i = 0; i < 20; i++) none.put(`f${i}`, "a", evidence);
    expect(missing.calls).toEqual({ isAvailable: 1, encrypt: 0, decrypt: 0 });
  });

  it("a keychain that stops answering mid-run stops being asked", () => {
    const later = countingKeychain("fail-later");
    const vault = new EvidenceVault(dir, later.crypto);
    // The unlock round-trip is the first encrypt; the first put is the second, and fails.
    expect(vault.put("f1", "a", evidence)).toBe(false);
    for (let i = 2; i < 10; i++) vault.put(`f${i}`, "a", evidence);
    expect(later.calls.encrypt).toBe(2);
    expect(later.calls.isAvailable).toBe(1);
  });

  it("keys by SIGHTING: idempotent per excerpt, several sightings per finding, each read back exactly", () => {
    const vault = new EvidenceVault(dir, fakeKeychain());
    vault.put("f1", "a", evidence);
    expect(vault.put("f1", "a", evidence)).toBe(false);
    expect(vault.put("f1", "b", { ...evidence, raw: "newer" })).toBe(true);
    // Re-scans alternate between the two sightings: nothing is re-appended.
    for (let i = 0; i < 3; i++) {
      expect(vault.put("f1", "a", evidence)).toBe(false);
      expect(vault.put("f1", "b", { ...evidence, raw: "newer" })).toBe(false);
    }
    expect(readFileSync(join(dir, "evidence-vault.jsonl"), "utf8").trim().split("\n")).toHaveLength(2);
    // Reveal asks for the card's own excerpt — never another sighting's window.
    expect(vault.get("f1", "a")?.raw).toBe(evidence.raw);
    expect(vault.get("f1", "b")?.raw).toBe("newer");
    expect(vault.get("f1", "c")).toBeUndefined();
  });

  it("caps sightings per finding, newest kept", () => {
    const vault = new EvidenceVault(dir, fakeKeychain());
    for (let i = 0; i < 12; i++) vault.put("f1", `x${i}`, evidence, `2026-09-01T10:00:${String(i).padStart(2, "0")}.000Z`);
    expect(vault.size()).toBe(8);
    expect(vault.has("f1", "x0")).toBe(false);
    expect(vault.has("f1", "x11")).toBe(true);
  });

  it("keeps the account with the evidence", () => {
    const vault = new EvidenceVault(dir, fakeKeychain());
    const account = { ...FULL_ROW.account };
    vault.put("f1", "a", { ...evidence, account });
    expect(new EvidenceVault(dir, fakeKeychain()).get("f1", "a")?.account).toEqual(account);
  });

  it("stores nothing at all when the keychain can't encrypt", () => {
    const vault = new EvidenceVault(dir, fakeKeychain(false));
    expect(vault.put("f1", "a", evidence)).toBe(false);
    expect(vault.fingerprints(evidence.secrets)).toEqual([]);
    expect(existsSync(join(dir, "evidence-vault.jsonl"))).toBe(false);
    expect(existsSync(join(dir, "evidence-vault.key"))).toBe(false);
  });

  it("prune drops what left the ledger and what fell out of the retention window", () => {
    const vault = new EvidenceVault(dir, fakeKeychain());
    vault.put("f1", "old", evidence, "2026-08-01T00:00:00.000Z");
    vault.put("f1", "new", evidence, "2026-09-20T00:00:00.000Z");
    vault.put("f2", "a", evidence, "2026-09-20T00:00:00.000Z");
    expect(vault.prune(new Set(["f1"]), "2026-09-01T00:00:00.000Z")).toBe(true);
    const lines = readFileSync(join(dir, "evidence-vault.jsonl"), "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    const reopened = new EvidenceVault(dir, fakeKeychain());
    expect(reopened.get("f2", "a")).toBeUndefined();
    expect(reopened.get("f1", "old")).toBeUndefined();
    expect(reopened.get("f1", "new")?.raw).toBe(evidence.raw);
    // Nothing to drop and nothing superseded: the file is left alone.
    expect(reopened.prune(new Set(["f1"]))).toBe(false);
  });

  it("gives no fingerprint to a value that is itself a literal placeholder", () => {
    const vault = new EvidenceVault(dir, fakeKeychain());
    expect(vault.fingerprints([{ label: "", value: "[redacted]" }, { label: "aws", value: " [redacted:aws] " }])).toEqual([]);
    expect(vault.fingerprints([{ label: "", value: "[redacted]" }, { label: "github", value: "ghp_REAL" }])).toHaveLength(1);
  });

  it("replaces a fingerprint key the keychain can no longer open, instead of stopping for good", () => {
    new EvidenceVault(dir, fakeKeychain()).fingerprints([{ label: "github", value: "ghp_x" }]);
    writeFileSync(join(dir, "evidence-vault.key"), Buffer.from("not decryptable by this keychain"));
    const reset: VaultCrypto = { ...fakeKeychain(), decrypt: () => { throw new Error("keychain reset"); } };
    const fresh = new EvidenceVault(dir, { ...reset, decrypt: (c) => { if (c.toString().includes("not decryptable")) throw new Error("reset"); return fakeKeychain().decrypt(c); } });
    expect(fresh.fingerprints([{ label: "github", value: "ghp_x" }])).toHaveLength(1);
    expect(readdirSync(dir).some((f) => f.startsWith("evidence-vault.key.unreadable-"))).toBe(true);
  });

  it("fingerprints are stable per install, keyed (not a bare hash) and value-free", () => {
    const a = new EvidenceVault(dir, fakeKeychain()).fingerprints([{ label: "github", value: "ghp_SECRETVALUE", primary: true }]);
    const again = new EvidenceVault(dir, fakeKeychain()).fingerprints([{ label: "github", value: "ghp_SECRETVALUE" }]);
    expect(a[0]).toMatchObject({ label: "github", length: 15, primary: true });
    expect(a[0]!.fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(again[0]!.fingerprint).toBe(a[0]!.fingerprint);
    const other = mkdtempSync(join(tmpdir(), "doorman-vault-other-"));
    try {
      const elsewhere = new EvidenceVault(other, fakeKeychain()).fingerprints([{ label: "github", value: "ghp_SECRETVALUE" }]);
      expect(elsewhere[0]!.fingerprint).not.toBe(a[0]!.fingerprint);
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
    expect(readFileSync(join(dir, "evidence-vault.key")).toString("utf8")).not.toMatch(/^[A-Za-z0-9+/=]{40,}$/);
  });
});

describe("capture engine × vault", () => {
  const SESSION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  const TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2";
  let root: string;
  let projects: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-capture-vault-"));
    projects = join(root, "claude", "projects", "-Users-dev-repo");
    mkdirSync(projects, { recursive: true });
    mkdirSync(join(root, "codex", "sessions"), { recursive: true });
    writeFileSync(
      join(projects, `${SESSION}.jsonl`),
      [
        JSON.stringify({ type: "user", uuid: "p1", timestamp: "2026-09-01T10:00:00.000Z", sessionId: SESSION, cwd: "/Users/dev/repo", message: { role: "user", content: "push it" } }),
        JSON.stringify({
          type: "assistant",
          timestamp: "2026-09-01T10:00:05.000Z",
          sessionId: SESSION,
          cwd: "/Users/dev/repo",
          message: {
            id: "msg_1",
            model: "claude-opus-5",
            role: "assistant",
            content: [{ type: "tool_use", name: "Bash", input: { command: `git push https://x:${TOKEN}@github.com/acme/app.git` } }],
            usage: { input_tokens: 10, output_tokens: 5, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
          },
        }),
      ].join("\n"),
    );
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  let policy: GuardPolicy = defaultPolicy();
  let retention = 0;
  beforeEach(() => {
    policy = defaultPolicy();
    retention = 0;
  });
  const engineFor = (vault: EvidenceVault | undefined) =>
    new CaptureEngine({
      storeDir: join(root, "store"),
      claudeProjectsDir: join(root, "claude", "projects"),
      codexSessionsDir: join(root, "codex", "sessions"),
      home: root,
      policy: () => policy,
      retentionDays: () => retention,
      onUpdate: () => {},
      onNewFindings: () => {},
      log: () => {},
      ...(vault ? { vault } : {}),
      appVersion: "0.70.0",
    });

  it("records level, build and fingerprints; the ledger stays masked and schema-valid; Reveal survives the transcript", async () => {
    const storeDir = join(root, "store");
    mkdirSync(storeDir, { recursive: true });
    const vault = new EvidenceVault(storeDir, fakeKeychain());
    const engine = engineFor(vault);
    await engine.start();
    engine.stop?.();
    const row = [...engine.ledger.values()].find((r) => r.secrets && r.secrets.length > 0);
    expect(row, "a credential row with fingerprints").toBeDefined();
    expect(row!.app_version).toBe("0.70.0");
    expect(row!.rule_mode).toBe(ruleModeOf(row!.detector, defaultPolicy()));
    expect(validateDetection(row)).toEqual([]);

    const ledgerText = readFileSync(join(storeDir, "findings.jsonl"), "utf8");
    expect(ledgerText).not.toContain(TOKEN);
    expect(readFileSync(join(storeDir, "evidence-vault.jsonl"), "utf8")).not.toContain(TOKEN);

    // The transcript goes away; the evidence doesn't.
    rmSync(join(projects, `${SESSION}.jsonl`));
    const revealed = engine.revealFinding(row!.finding_id);
    expect(revealed.ok).toBe(true);
    if (revealed.ok) {
      expect(revealed.evidence_source).toBe("vault");
      // The URL's whole userinfo is the redacted value (`x:<token>`).
      expect(revealed.secrets.some((s) => s.value.includes(TOKEN))).toBe(true);
    }
  });

  it("a re-scan of an OLD sighting keeps the rule mode it fired under", async () => {
    const storeDir = join(root, "store");
    mkdirSync(storeDir, { recursive: true });
    policy = { ...defaultPolicy(), modes: { ...defaultPolicy().modes, credential_in_tool_arg: "block" } };
    const engine = engineFor(new EvidenceVault(storeDir, fakeKeychain()));
    await engine.start();
    engine.stop?.();
    const before = [...engine.ledger.values()].find((r) => r.detector === "credential_in_tool_arg");
    expect(before?.rule_mode).toBe("block");
    // The person relaxes the rule; the transcript grows (an unrelated line),
    // so the whole file — the old call included — is re-scanned.
    policy = { ...policy, modes: { ...policy.modes, credential_in_tool_arg: "observe" } };
    appendFileSync(join(projects, `${SESSION}.jsonl`), "\n" + JSON.stringify({ type: "user", uuid: "p2", timestamp: "2026-09-01T10:01:00.000Z", sessionId: SESSION, message: { role: "user", content: "thanks" } }));
    const again = engineFor(new EvidenceVault(storeDir, fakeKeychain()));
    await again.start();
    again.stop?.();
    expect(again.ledger.get(before!.finding_id)?.rule_mode).toBe("block");
  });

  it("the vault is pruned to the retention window even when no turn was pruned", async () => {
    const storeDir = join(root, "store");
    mkdirSync(storeDir, { recursive: true });
    const engine = engineFor(new EvidenceVault(storeDir, fakeKeychain()));
    await engine.start();
    engine.stop?.();
    expect(new EvidenceVault(storeDir, fakeKeychain()).size()).toBeGreaterThan(0);
    // A 1-day window: the fixture's 2026-09-01 sighting is outside it. The
    // turns go too, but the point is the vault goes with them on boot.
    retention = 1;
    const later = engineFor(new EvidenceVault(storeDir, fakeKeychain()));
    (later as unknown as { load(): void }).load();
    expect(new EvidenceVault(storeDir, fakeKeychain()).size()).toBe(0);
  });

  it("without a vault, nothing is kept and Reveal still reads the transcript", async () => {
    const engine = engineFor(undefined);
    await engine.start();
    engine.stop?.();
    const row = [...engine.ledger.values()].find((r) => r.detector === "credential_in_tool_arg") ?? [...engine.ledger.values()][0];
    expect(row).toBeDefined();
    expect(row!.secrets).toBeUndefined();
    expect(existsSync(join(root, "store", "evidence-vault.jsonl"))).toBe(false);
    const revealed = engine.revealFinding(row!.finding_id);
    expect(revealed.ok && revealed.evidence_source).toBe("transcript");
  });
});

describe("ledger export", () => {
  const SESSION_ROW: Required<Omit<SessionSummary, "task">> & { task: SessionSummary["task"] } = {
    id: "s1",
    source: "claude-code",
    title: "Rotate the keys",
    title_origin: "auto_summary",
    cost: 1.25,
    cost_unknown_turns: 0,
    input_tokens: 10,
    output_tokens: 5,
    cache_read_tokens: 0,
    cache_write_tokens: 0,
    turns: 2,
    prompts: 1,
    models: ["claude-opus-5"],
    started_at: "2026-09-01T10:00:00.000Z",
    ended_at: "2026-09-01T10:00:05.000Z",
    cwd: "/Users/dev/repo",
    git_branch: "main",
    task: "coding" as SessionSummary["task"],
    covered_cost: 1.25,
    overage_cost: 0,
    billed_cost: 0,
    unknown_cost: 0,
    covered_tokens: 15,
    overage_tokens: 0,
    billed_tokens: 0,
    unknown_tokens: 0,
    alerts: 1,
    last_role: "assistant",
    last_turn_tools: 1,
    resume_command: "claude --resume s1",
  };
  const TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2";
  const TURNS: Required<LedgerTurn>[] = [
    {
      id: "t1",
      source: "claude-code",
      session_id: "s1",
      role: "user",
      at: "2026-09-01T10:00:00.000Z",
      model: "claude-opus-5",
      usage: { input_tokens: 10, output_tokens: 5, cache_read_tokens: 0, cache_write_tokens: 0, cache_write_1h_tokens: 0, web_search_requests: 0 },
      cost: 1.25,
      cost_unknown: false,
      reported_cost: 1.25,
      usage_incomplete: false,
      settlement: "subscription",
      text: `use GITHUB_TOKEN=${TOKEN} to push`,
      tools: ["Bash"],
      cwd: "/Users/dev/repo",
      git_branch: "main",
    },
  ];

  it("validates, redacts turn text, fingerprints what it removed and names the session's detections", () => {
    const dir = mkdtempSync(join(tmpdir(), "doorman-ledger-export-"));
    try {
      const vault = new EvidenceVault(dir, fakeKeychain());
      const bundle = buildLedgerExport({
        sessions: [SESSION_ROW as SessionSummary],
        turnsOf: () => TURNS,
        detectionIdsOf: () => ["0123456789abcdef"],
        mask: maskTurnText,
        fingerprintsOf: (raw, masked) => vault.fingerprints(alignRedactedValues(raw, masked)),
        app_version: "0.70.0",
        generated_at: new Date("2026-09-28T12:00:00.000Z"),
      });
      expect(validateLedgerExport(bundle)).toEqual([]);
      expect(bundle.schema).toBe(LEDGER_EXPORT_SCHEMA_ID);
      expect(JSON.stringify(bundle)).not.toContain(TOKEN);
      const turn = bundle.sessions[0]!.items[0]!;
      expect(turn.text_redacted).toBe(true);
      expect(turn.text).toContain("[redacted");
      expect(turn.secrets?.[0]?.fingerprint).toMatch(/^[0-9a-f]{16}$/);
      expect(bundle.sessions[0]!.detection_ids).toEqual(["0123456789abcdef"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a turn field the schema doesn't know", () => {
    const bad = { schema: LEDGER_EXPORT_SCHEMA_ID, schema_version: 1, generated_at: "2026-09-28T12:00:00.000Z", app_version: "x", sessions: [{ ...SESSION_ROW, detection_ids: [], items: [{ ...TURNS[0], raw: "x" }] }] };
    expect(validateLedgerExport(bad).map((p) => p.path)).toContain("/sessions/0/items/0/raw");
  });
});

describe("dev-sandbox cipher", () => {
  it("round-trips, keeps its key in the fixture (0600), and never writes the value in the clear", () => {
    const dir = mkdtempSync(join(tmpdir(), "doorman-sandbox-cipher-"));
    try {
      const vault = new EvidenceVault(dir, sandboxVaultCrypto(dir));
      vault.put("f1", "a", { raw: "SECRET-VALUE-123", truncated: false, at: "2026-09-01T10:00:00.000Z", secrets: [] });
      expect(readFileSync(join(dir, "evidence-vault.jsonl"), "utf8")).not.toContain("SECRET-VALUE-123");
      expect(statSync(join(dir, "evidence-vault.sandbox-key")).mode & 0o777).toBe(0o600);
      expect(new EvidenceVault(dir, sandboxVaultCrypto(dir)).get("f1", "a")?.raw).toBe("SECRET-VALUE-123");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("masking — nothing a record or an export carries holds a value (review fixes)", () => {
  const SENDGRID = "SG." + "aBcDeFgHiJkLmNoPqRsTuV" + "." + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefg";
  const STRIPE = "sk_live_" + "q7Lm2Xv9Pz4Rk8Tn3Wb6";

  it("the account never quotes a dotted credential as the source file", () => {
    const raw = JSON.stringify({ command: `SENDGRID=${SENDGRID} curl -X POST https://api.sendgrid.com/v3/mail/send` });
    const account = accountForUnit({ detector: "credential_in_tool_arg", key_name: "sendgrid" }, { kind: "tool_call", raw, tool_name: "Bash" }, [
      { label: "sendgrid", value: SENDGRID },
    ]);
    expect(JSON.stringify(account ?? {})).not.toContain(SENDGRID);
    expect(JSON.stringify(account ?? {})).not.toContain("aBcDeFgHiJkLmNoPqRsTuV");
  });

  it("a Bash target that begins with an env assignment is masked at mint, and on read for old rows", () => {
    const row = mintFindingRow(
      { detector: "credential_in_tool_arg", severity: "high", key_name: "stripe", excerpt: "[redacted:stripe] node charge.js", occurrences: 1, tool_name: "Bash", target: `STRIPE_KEY=${STRIPE}` },
      { source: "claude-code", origin: "transcript", session_id: "s1", at: "2026-09-01T10:00:00.000Z" },
    );
    expect(row.target).toBe("STRIPE_KEY=[redacted:stripe]");
    // An older build's stored line with the raw target is masked on read…
    const legacy = JSON.stringify({ ...row, target: `STRIPE_KEY=${STRIPE}`, schema_version: undefined });
    const stats = { upgraded: 0 };
    const folded = foldFindingLines([legacy], stats);
    expect(folded.get(row.finding_id)!.target).not.toContain(STRIPE);
    expect(stats.upgraded).toBe(1);
    // …and the export / AI choke point masks whatever reaches it regardless.
    expect(JSON.stringify(toDetectionRecord({ ...row, target: `STRIPE_KEY=${STRIPE}` }))).not.toContain(STRIPE);
    expect(findingContext({ ...row, target: `STRIPE_KEY=${STRIPE}` }, undefined, {}).text).not.toContain(STRIPE);
  });

  it("masks what only the detectors know: cards, IBANs, SSNs, wallet addresses, high-entropy tokens", () => {
    const text = "card 4111 1111 1111 1111, iban DE89370400440532013000, ssn 123-45-6789, token Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd5Hf7Gj0Aa";
    const masked = maskText(text);
    for (const value of ["4111 1111 1111 1111", "DE89370400440532013000", "123-45-6789", "Zx9Qm2Lp8Rt4Vw6Yb1Nc3Kd5Hf7Gj0Aa"]) expect(masked).not.toContain(value);
    // Still a pure replacement view: every hidden value is recoverable.
    expect(alignRedactedValues(text, masked).map((s) => s.value)).toContain("4111 1111 1111 1111");
  });

  it("a turn cut by the length cap masks the unterminated key block and the cut token", () => {
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ".repeat(40);
    const text = ("x".repeat(3000) + " here is my key\n" + pem).slice(0, TURN_TEXT_MAX_CHARS);
    const masked = maskTurnText(text);
    expect(masked).not.toContain("b3BlbnNzaC1rZXkt");
    // A secret the cap cut to 20 characters matches no pattern any more; the
    // cut token is masked because it is the cut token.
    const cut = ("y ".repeat(1990) + "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY").slice(0, TURN_TEXT_MAX_CHARS);
    expect(maskTurnText(cut)).not.toContain("wJalrXUtnFEMIK7MDENG");
    expect(maskTurnText(cut).endsWith("[redacted]")).toBe(true);
    // Under the cap nothing extra is masked.
    expect(maskTurnText("hello world")).toBe("hello world");
  });

  it("the validator does not let prototype keys pass as declared fields", () => {
    expect(validateDetection({ ...FULL_ROW, constructor: "x" }).map((p) => p.path)).toContain("/constructor");
    expect(validateDetection({ ...FULL_ROW, toString: "x" }).map((p) => p.path)).toContain("/toString");
  });

  it("maskFindingRow leaves ordinary paths, hosts and names untouched", () => {
    const masked = maskFindingRow(FULL_ROW);
    expect(masked.target).toBe(FULL_ROW.target);
    expect(masked.cwd).toBe(FULL_ROW.cwd);
    expect(masked.account).toEqual(FULL_ROW.account);
  });
});
