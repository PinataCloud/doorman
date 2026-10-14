import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CaptureEngine } from "../main/capture.js";
import { findingContext } from "../main/ai-assistant.js";
import { defaultPolicy } from "../main/guard/policy.js";
import { redact } from "../main/guard/redact.js";
import { detectSecurityFindings } from "../main/guard/security-detect.js";
import type { DetectUnit } from "../main/lib/cc-transcript.js";
import { toDetectionRecord } from "../main/lib/detection-schema.js";
import { EvidenceVault, vaultFileNames, type VaultCrypto } from "../main/lib/evidence-vault.js";
import { foldFindingLines, mergeFinding, mintFindingRow, type FindingRow } from "../main/lib/findings.js";
import { maskExcerpt } from "../main/lib/masking.js";
import { matchingFinding, revealEvidenceForFinding } from "../main/lib/reveal.js";

/**
 * Regression tests for the findings-pipeline review (2026-09-29): excerpt
 * masking, vault blobs a reset keychain can't open, per-build vault files,
 * newest-sighting merges, and Reveal never keeping a near match.
 */

/** A keychain whose key is `byte` — two different bytes are two builds. */
const keychain = (byte = 0x5a): VaultCrypto => ({
  isAvailable: () => true,
  encrypt: (plain) => Buffer.concat([Buffer.from([byte]), Buffer.from(Buffer.from(plain, "utf8").map((b) => b ^ byte))]),
  decrypt: (cipher) => {
    if (cipher[0] !== byte) throw new Error("Error while decrypting the ciphertext provided to safeStorage.decryptString.");
    return Buffer.from(cipher.subarray(1).map((b) => b ^ byte)).toString("utf8");
  },
});

const IBAN = "DE89370400440532013000";
const SSN = "123-45-6789";
const CARD = "4111 1111 1111 1111";

describe("excerpt masking — every detector's values, not only the one that fired", () => {
  it("masks the neighbours a detector quoted in the clear, keeps its placeholders verbatim, and is idempotent", () => {
    const excerpt = `card [redacted:credit_card], iban ${IBAN}, ssn ${SSN}; KEY=[redacted:aws]`;
    const masked = maskExcerpt(excerpt);
    expect(masked).not.toContain(IBAN);
    expect(masked).not.toContain(SSN);
    expect(masked).toContain("card [redacted:credit_card]");
    expect(masked).toContain("KEY=[redacted:aws]");
    expect(maskExcerpt(masked)).toBe(masked);
  });

  it("a minted row, a legacy ledger line, the export and Doorman AI all carry the masked excerpt", () => {
    const row = mintFindingRow(
      { detector: "pii_exposure", severity: "high", key_name: "credit card", excerpt: `pay with [redacted] then ssn ${SSN} iban ${IBAN}`, occurrences: 1 },
      { source: "claude-code", origin: "transcript", session_id: "s1", at: "2026-09-01T10:00:00.000Z" },
    );
    expect(row.excerpt).not.toContain(SSN);
    expect(row.excerpt).not.toContain(IBAN);
    const legacy = JSON.stringify({ ...row, excerpt: `ssn ${SSN}`, schema_version: undefined });
    expect(foldFindingLines([legacy]).get(row.finding_id)!.excerpt).not.toContain(SSN);
    const raw = { ...row, excerpt: `ssn ${SSN} iban ${IBAN}` };
    expect(JSON.stringify(toDetectionRecord(raw))).not.toContain(SSN);
    const ai = findingContext(raw, undefined, {}).text;
    expect(ai).not.toContain(SSN);
    expect(ai).not.toContain(IBAN);
  });

  it("Reveal still finds its unit EXACTLY from a masked excerpt", () => {
    const text = `charge ${CARD} for the order, customer ssn ${SSN}, iban ${IBAN}`;
    const unit: DetectUnit = { kind: "prompt", raw: text, session_id: "s1", turn_id: "t1", at: "2026-09-01T10:00:00.000Z" };
    const findings = detectSecurityFindings({ kind: "prompt", text: redact(text) });
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      const row = mintFindingRow(finding, { source: "claude-code", origin: "transcript", session_id: "s1", turn_id: "t1", at: unit.at });
      for (const value of [CARD, SSN, IBAN]) expect(row.excerpt).not.toContain(value);
      const scored = revealEvidenceForFinding(row, [unit]);
      expect(scored?.exact, `${finding.detector} reveals exactly`).toBe(true);
      expect(scored?.evidence.raw).toContain(CARD);
    }
  });
});

describe("evidence vault — blobs a reset keychain can't open", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "doorman-vault-reset-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const evidence = { raw: "export TOKEN=ghp_SECRETVALUE", truncated: false, at: "2026-09-01T10:00:00.000Z", secrets: [] };

  it("drops a stale blob on read so the sighting can be kept again, logging once", () => {
    new EvidenceVault(dir, keychain(0x11)).put("f1", "a", evidence);
    new EvidenceVault(dir, keychain(0x11)).put("f2", "b", evidence);
    const log = vi.fn();
    const reset = new EvidenceVault(dir, keychain(0x22), log);
    expect(reset.get("f1", "a")).toBeUndefined();
    expect(reset.get("f2", "b")).toBeUndefined();
    expect(log).toHaveBeenCalledTimes(1);
    expect(reset.has("f1", "a")).toBe(false);
    expect(reset.put("f1", "a", evidence)).toBe(true);
    expect(reset.get("f1", "a")?.raw).toBe(evidence.raw);
    // The dead line leaves the file at the next compaction.
    expect(reset.prune(new Set(["f1", "f2"]))).toBe(true);
    expect(new EvidenceVault(dir, keychain(0x22)).size()).toBe(1);
  });

  it("a keychain that stops answering altogether locks the vault instead of dropping good evidence", () => {
    new EvidenceVault(dir, keychain(0x11)).put("f1", "a", evidence);
    let dead = false;
    const base = keychain(0x11);
    const flaky: VaultCrypto = {
      isAvailable: () => true,
      encrypt: (p) => {
        if (dead) throw new Error("keychain locked");
        return base.encrypt(p);
      },
      decrypt: (c) => {
        if (dead) throw new Error("keychain locked");
        return base.decrypt(c);
      },
    };
    const vault = new EvidenceVault(dir, flaky);
    expect(vault.available()).toBe(true);
    dead = true;
    expect(vault.get("f1", "a")).toBeUndefined();
    expect(vault.has("f1", "a")).toBe(true);
  });
});

describe("evidence vault — per-build files", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "doorman-vault-flavour-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const secret = [{ label: "github", value: "ghp_SAMEVALUE" }];

  it("alternating packaged and dev runs keep stable fingerprints and never set each other's key aside", () => {
    const packaged = () => new EvidenceVault(dir, keychain(0x11));
    const dev = () => new EvidenceVault(dir, keychain(0x22), () => {}, { flavour: "dev" });
    const p1 = packaged().fingerprints(secret)[0]!.fingerprint;
    const d1 = dev().fingerprints(secret)[0]!.fingerprint;
    const p2 = packaged().fingerprints(secret)[0]!.fingerprint;
    const d2 = dev().fingerprints(secret)[0]!.fingerprint;
    expect(p2).toBe(p1);
    expect(d2).toBe(d1);
    expect(readdirSync(dir).filter((f) => f.includes("unreadable"))).toEqual([]);
    expect(existsSync(join(dir, vaultFileNames().key))).toBe(true);
    expect(existsSync(join(dir, vaultFileNames("dev").key))).toBe(true);
    expect(vaultFileNames("dev")).toEqual({ vault: "evidence-vault.dev.jsonl", key: "evidence-vault.dev.key" });
  });

  it("a key set aside twice in the same millisecond keeps both copies", () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
    try {
      new EvidenceVault(dir, keychain(0x11)).fingerprints(secret);
      new EvidenceVault(dir, keychain(0x22)).fingerprints(secret);
      new EvidenceVault(dir, keychain(0x33)).fingerprints(secret);
      expect(readdirSync(dir).filter((f) => f.includes(".unreadable-")).length).toBe(2);
    } finally {
      now.mockRestore();
    }
  });
});

describe("mergeFinding — the newest sighting's fields travel together", () => {
  const base = (at: string, over: Partial<FindingRow>): FindingRow => ({
    ...mintFindingRow(
      { detector: "credential_in_tool_arg", severity: "high", key_name: "github", excerpt: "x", occurrences: 1 },
      { source: "claude-code", origin: "transcript", session_id: "s1", at },
    ),
    ...over,
  });

  it("an OLDER sighting arriving late only fills gaps", () => {
    const newer = base("2026-09-02T10:00:00.000Z", { excerpt: "newer", severity: "high", turn_id: "t2", rule_mode: "block", secrets: [{ label: "github", length: 10, fingerprint: "NEWFP" }] });
    const older = base("2026-09-01T10:00:00.000Z", { excerpt: "older", severity: "medium", turn_id: "t1", rule_mode: "observe", secrets: [{ label: "github", length: 10, fingerprint: "OLDFP" }], occurrences: 3 });
    const merged = mergeFinding(newer, older);
    expect(merged).toMatchObject({ excerpt: "newer", severity: "high", turn_id: "t2", rule_mode: "block" });
    expect(merged.secrets![0]!.fingerprint).toBe("NEWFP");
    expect(merged.first_seen_at).toBe("2026-09-01T10:00:00.000Z");
    expect(merged.last_seen_at).toBe("2026-09-02T10:00:00.000Z");
    expect(merged.occurrences).toBe(3);
  });

  it("a NEWER sighting replaces them, turn included", () => {
    const older = base("2026-09-01T10:00:00.000Z", { excerpt: "older", turn_id: "t1" });
    const newer = base("2026-09-02T10:00:00.000Z", { excerpt: "newer", severity: "critical", turn_id: "t2" });
    expect(mergeFinding(older, newer)).toMatchObject({ excerpt: "newer", severity: "critical", turn_id: "t2" });
  });
});

describe("Reveal — never another sighting's value", () => {
  const TOKEN_A = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
  const TOKEN_B = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2";
  const call = (turn: string, token: string, at: string): DetectUnit => ({
    kind: "tool_call",
    raw: JSON.stringify({ command: `git push https://x:${token}@github.com/acme/${turn}.git` }),
    tool_name: "Bash",
    target: "git",
    session_id: "s1",
    turn_id: turn,
    at,
  });
  const units = [call("t1", TOKEN_A, "2026-09-01T10:00:00.000Z"), call("t2", TOKEN_B, "2026-09-01T10:05:00.000Z")];
  const rowFor = (unit: DetectUnit, over: Partial<FindingRow> = {}): FindingRow => {
    const found = matchingFinding(unit, { detector: "credential_in_tool_arg", key_name: undefined } as unknown as FindingRow) ??
      detectSecurityFindings({ kind: "tool_call", text: redact(unit.raw), raw_text: unit.raw, tool_name: unit.tool_name, target: unit.target })[0]!;
    return { ...mintFindingRow(found, { source: "claude-code", origin: "transcript", session_id: "s1", turn_id: unit.turn_id, at: unit.at }), ...over };
  };

  it("the card's own excerpt is an exact match", () => {
    const scored = revealEvidenceForFinding(rowFor(units[1]!), units);
    expect(scored?.exact).toBe(true);
    expect(scored?.evidence.raw).toContain(TOKEN_B);
  });

  it("a drifted excerpt with nothing tying it to one of several reproductions reveals nothing", () => {
    const row = rowFor(units[1]!, { excerpt: "an excerpt an older build wrote", turn_id: undefined });
    expect(revealEvidenceForFinding(row, units)).toBeUndefined();
    // With one reproduction there is nothing else it could be — shown, not exact.
    const lone = revealEvidenceForFinding(row, [units[1]!]);
    expect(lone?.exact).toBe(false);
    expect(lone?.evidence.raw).toContain(TOKEN_B);
  });
});

describe("capture engine — Reveal keeps only exact evidence; the ledger is owner-only", () => {
  const SESSION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  const TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2";
  let root: string;
  let projects: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-pipeline-"));
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
  const engineFor = (vault: EvidenceVault) =>
    new CaptureEngine({
      storeDir: join(root, "store"),
      claudeProjectsDir: join(root, "claude", "projects"),
      codexSessionsDir: join(root, "codex", "sessions"),
      home: root,
      policy: () => defaultPolicy(),
      retentionDays: () => 0,
      onUpdate: () => {},
      onNewFindings: () => {},
      log: () => {},
      vault,
      appVersion: "0.70.0",
    });

  it("a near-match Reveal is shown but not kept; an exact one is kept", async () => {
    const storeDir = join(root, "store");
    mkdirSync(storeDir, { recursive: true });
    const vault = new EvidenceVault(storeDir, keychain());
    const engine = engineFor(vault);
    await engine.start();
    engine.stop?.();
    const row = [...engine.ledger.values()].find((r) => r.detector === "credential_in_tool_arg")!;
    expect(row).toBeDefined();
    const exactExcerpt = row.excerpt;
    vault.prune(new Set());
    expect(vault.size()).toBe(0);

    row.excerpt = "an excerpt an older build wrote";
    const near = engine.revealFinding(row.finding_id);
    expect(near.ok && near.evidence_source).toBe("transcript");
    expect(vault.size()).toBe(0);

    row.excerpt = exactExcerpt;
    const exact = engine.revealFinding(row.finding_id);
    expect(exact.ok && exact.evidence_source).toBe("transcript");
    expect(vault.size()).toBe(1);
  });

  it("writes the ledger files owner-only, and tightens ones an older build left world-readable", async () => {
    const storeDir = join(root, "store");
    mkdirSync(storeDir, { recursive: true });
    writeFileSync(join(storeDir, "cursors.json"), "{}\n");
    chmodSync(join(storeDir, "cursors.json"), 0o644);
    const engine = engineFor(new EvidenceVault(storeDir, keychain()));
    await engine.start();
    engine.stop?.();
    for (const name of ["findings.jsonl", "turns.jsonl", "cursors.json"]) {
      expect(statSync(join(storeDir, name)).mode & 0o777, name).toBe(0o600);
    }
  });
});
