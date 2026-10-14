/**
 * The evidence vault — the raw window behind a detection, kept so a
 * Reveal still works after the transcript it came from is rotated, compacted
 * or deleted, and so "what exactly was reported" has an answer that does not
 * depend on re-running today's detectors over yesterday's file.
 *
 * The ledger's invariant holds: a finding row is masked, and so is
 * everything built from it (the export, the report, Doorman AI's context).
 * The raw values live HERE, and only here, encrypted with the OS keychain
 * (Electron `safeStorage` — on macOS a Keychain item only this app can read).
 * When the keychain cannot encrypt (no keyring on a Linux box, a test), the
 * vault stores nothing at all: a plaintext copy of every secret the app ever
 * caught is the one thing this file must never become. Reveal then falls back
 * to re-reading the transcript, exactly as before the vault existed.
 *
 * Layout: <store>/evidence-vault.jsonl (a dev build: evidence-vault.dev.jsonl —
 * see vaultFileNames), mode 0600, one line per sighting —
 *   { finding_id, excerpt, at, blob }   blob = base64(encrypt(JSON(evidence)))
 * `excerpt` is the row's MASKED excerpt, kept in the clear so a re-scan can tell
 * a sighting it already holds from a new one without decrypting anything.
 * Keyed by SIGHTING (finding id + excerpt), a few per finding; append-only,
 * compacted against the ledger and the retention window (`prune`).
 *
 * Fingerprints: the export and the AI get a `secrets[]` fingerprint per value
 * (label, length, HMAC-SHA256 prefix). The HMAC key is random per install and
 * sits beside the vault, encrypted the same way — so a fingerprint correlates
 * sightings on this Mac but cannot be brute-forced from an exported file.
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import { appendFileSync, chmodSync, existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { SecretFingerprint } from "./findings.js";
import type { RawEvidence, RedactedSecret } from "./reveal.js";

/** The keychain, as the vault needs it — `safeStorage` in the app. */
export interface VaultCrypto {
  isAvailable(): boolean;
  encrypt(plain: string): Buffer;
  decrypt(cipher: Buffer): string;
}

/** What the vault keeps for one SIGHTING: the reveal payload as it stood when
 * the detection fired. */
export type VaultedEvidence = RawEvidence & { vaulted_at: string };

interface VaultLine {
  finding_id: string;
  /** The row's MASKED excerpt at that sighting — half of the entry's key. */
  excerpt: string;
  /** When the sighting happened — what retention prunes on. */
  at: string;
  blob: string;
}

/**
 * The vault's files, per BUILD FLAVOUR. safeStorage's key lives in the
 * "<app name> Safe Storage" Keychain item, and an unpackaged run is named
 * "Doorman Dev" (index.ts) so it doesn't fight the signed app over one item
 * — which makes the two keys different. Sharing one vault file and one HMAC
 * key file across them meant each build found the other's key unreadable,
 * set it aside and minted its own on every alternation (fingerprints of one
 * value changed each time), and filled the vault with blobs the other could
 * not open. So a flavour other than the default gets its own pair.
 */
export function vaultFileNames(flavour?: string): { vault: string; key: string } {
  const tag = flavour ? `.${flavour.replace(/[^a-z0-9_-]/gi, "")}` : "";
  return { vault: `evidence-vault${tag}.jsonl`, key: `evidence-vault${tag}.key` };
}
/** Sightings kept per finding. One finding id spans a session's every sighting
 * of the same detector + key (a session's `unrecognized_secret` rows share one),
 * and each sighting's excerpt differs — so the vault keeps several, newest
 * first, rather than one that each re-scan would overwrite in turn. */
export const VAULT_SIGHTINGS_PER_FINDING = 8;

const entryKey = (findingId: string, excerpt: string) => `${findingId}\u0000${excerpt}`;
const isPlaceholderText = (value: string) => /^\[redacted(?::[a-z0-9_]+)?\]$/.test(value.trim());

export class EvidenceVault {
  /** (finding id, excerpt) → its newest line. */
  private readonly lines = new Map<string, VaultLine>();
  /** Lines in the FILE, superseded ones included — when it exceeds the map, a
   * compaction has something to squeeze out. */
  private fileLines = 0;
  private loaded = false;
  private hmacKey: Buffer | undefined;
  /** The key could not be read or made this run; don't retry on every row. */
  private keyFailed = false;
  /** An undecryptable blob was already reported this run. */
  private staleLogged = false;
  private readonly names: { vault: string; key: string };

  constructor(
    private readonly dir: string,
    private readonly crypto: VaultCrypto,
    private readonly log: (message: string) => void = () => {},
    options: { flavour?: string } = {},
  ) {
    this.names = vaultFileNames(options.flavour);
  }

  private get file(): string {
    return join(this.dir, this.names.vault);
  }

  /** The answer to "can this run keep values?", once asked (see available). */
  private unlocked: boolean | undefined;

  /**
   * Whether values can be kept at all — decided ONCE per run, the first time a
   * value actually needs keeping, and remembered either way.
   *
   * On macOS every safeStorage call is a Keychain read (isEncryptionAvailable
   * included), and when the "<app> Safe Storage" item was created by another
   * build — a dev run, an older signature — each read the Keychain refuses
   * silently becomes a password dialog (two, in fact: macOS asks to "use" and
   * then to "access" the item). Asking lazily keeps a launch with nothing to
   * keep from prompting at all; remembering a refusal keeps a Cancel from
   * turning into a dialog per detection. The round-trip proves the key works,
   * so a later encrypt is not the first thing to find out it doesn't.
   */
  available(): boolean {
    if (this.unlocked !== undefined) return this.unlocked;
    try {
      if (!this.crypto.isAvailable()) {
        this.unlocked = false;
      } else {
        const probe = "doorman-evidence-vault";
        this.unlocked = this.crypto.decrypt(this.crypto.encrypt(probe)) === probe;
      }
    } catch (err) {
      this.log(`evidence vault: keychain refused or unavailable (${String(err)})`);
      this.unlocked = false;
    }
    if (!this.unlocked) this.log("evidence vault: nothing will be kept this run; Reveal reads transcripts");
    return this.unlocked;
  }

  /** A keychain call failed after unlocking (the item was reset or locked
   * mid-run): stop asking for the rest of the run. */
  private lock(err: unknown): void {
    this.log(`evidence vault: keychain stopped answering (${String(err)}); nothing more is kept this run`);
    this.unlocked = false;
  }

  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    let text: string;
    try {
      text = readFileSync(this.file, "utf8");
    } catch {
      return;
    }
    for (const raw of text.split("\n")) {
      if (raw.trim() === "") continue;
      this.fileLines += 1;
      try {
        const line = JSON.parse(raw) as VaultLine;
        if (line && typeof line.finding_id === "string" && typeof line.blob === "string" && typeof line.excerpt === "string") {
          this.lines.set(entryKey(line.finding_id, line.excerpt), line);
        }
      } catch {
        // a torn line; compaction drops it
      }
    }
  }

  /** Whether this sighting (finding + excerpt) is kept; with no excerpt,
   * whether any sighting of the finding is. */
  has(findingId: string, excerpt?: string): boolean {
    this.load();
    if (excerpt !== undefined) return this.lines.has(entryKey(findingId, excerpt));
    for (const line of this.lines.values()) if (line.finding_id === findingId) return true;
    return false;
  }

  /** Keep the evidence for one sighting. Idempotent: a whole-file re-scan
   * re-mints every row, and a sighting already kept is not re-encrypted or
   * re-appended. */
  put(findingId: string, excerpt: string, evidence: RawEvidence, at: string = new Date().toISOString()): boolean {
    if (!this.available()) return false;
    this.load();
    if (this.has(findingId, excerpt)) return false;
    const payload: VaultedEvidence = { ...evidence, vaulted_at: at };
    let blob: string;
    try {
      blob = this.crypto.encrypt(JSON.stringify(payload)).toString("base64");
    } catch (err) {
      this.lock(err);
      return false;
    }
    const line: VaultLine = { finding_id: findingId, excerpt, at, blob };
    try {
      const fresh = !existsSync(this.file);
      appendFileSync(this.file, `${JSON.stringify(line)}\n`, { mode: 0o600 });
      if (fresh) chmodSync(this.file, 0o600);
    } catch (err) {
      this.log(`evidence vault: couldn't write: ${String(err)}`);
      return false;
    }
    this.fileLines += 1;
    this.lines.set(entryKey(findingId, excerpt), line);
    this.capSightings(findingId);
    return true;
  }

  /** Drop a finding's oldest sightings past the cap (in memory; the file loses
   * them at the next compaction). */
  private capSightings(findingId: string): void {
    const mine = [...this.lines.entries()].filter(([, l]) => l.finding_id === findingId);
    if (mine.length <= VAULT_SIGHTINGS_PER_FINDING) return;
    mine.sort((a, b) => b[1].at.localeCompare(a[1].at));
    for (const [key] of mine.slice(VAULT_SIGHTINGS_PER_FINDING)) this.lines.delete(key);
  }

  /**
   * The evidence kept for the sighting whose excerpt IS `excerpt`, decrypted —
   * for Reveal only. Exact on purpose: the card shows one sighting's excerpt,
   * and another sighting's window would put a different credential in place
   * under it. No match → undefined, and Reveal reads the transcript instead.
   */
  get(findingId: string, excerpt: string): VaultedEvidence | undefined {
    this.load();
    const line = this.lines.get(entryKey(findingId, excerpt));
    if (!line || !this.available()) return undefined;
    let plain: string;
    try {
      plain = this.crypto.decrypt(Buffer.from(line.blob, "base64"));
    } catch (err) {
      // Either the keychain stopped answering (then nothing decrypts — lock)
      // or this blob was sealed by a key the keychain no longer holds (a
      // reset Safe Storage item, a restore onto another Mac). The probe tells
      // them apart. A stale blob is DROPPED, not kept: while it sat in the map
      // `has()` stayed true, so neither a re-scan nor the Reveal fallback could
      // ever store the sighting again, and Reveal died with the transcript.
      if (!this.probe()) {
        this.lock(err);
        return undefined;
      }
      this.drop(line, err);
      return undefined;
    }
    try {
      const parsed = JSON.parse(plain) as VaultedEvidence;
      if (parsed && typeof parsed.raw === "string") return parsed;
    } catch {
      // fall through: an unparseable payload is as dead as an unreadable one
    }
    this.drop(line, "unreadable payload");
    return undefined;
  }

  /** Does the keychain still round-trip right now? */
  private probe(): boolean {
    try {
      const probe = "doorman-evidence-vault";
      return this.crypto.decrypt(this.crypto.encrypt(probe)) === probe;
    } catch {
      return false;
    }
  }

  /** Forget a dead line (the file loses it at the next compaction). */
  private drop(line: VaultLine, why: unknown): void {
    this.lines.delete(entryKey(line.finding_id, line.excerpt));
    if (this.staleLogged) return;
    this.staleLogged = true;
    this.log(`evidence vault: dropping evidence this keychain can't open (${String(why)}); it is re-kept on the next Reveal or scan`);
  }

  /**
   * Compact: keep only sightings of findings still in `keep`, and — with a
   * retention window — only those at or after `cutoffIso`, so a kept value
   * never outlives the turns the person asked the app to forget. Rewrites the
   * file whenever that dropped anything or the file carries superseded or torn
   * lines; otherwise touches nothing. Returns whether it rewrote.
   */
  prune(keep: ReadonlySet<string>, cutoffIso?: string): boolean {
    this.load();
    for (const [key, line] of [...this.lines.entries()]) {
      if (!keep.has(line.finding_id) || (cutoffIso !== undefined && line.at < cutoffIso)) this.lines.delete(key);
    }
    if (this.fileLines === this.lines.size) return false;
    this.rewrite();
    return true;
  }

  size(): number {
    this.load();
    return this.lines.size;
  }

  private rewrite(): void {
    try {
      const body = [...this.lines.values()].map((l) => JSON.stringify(l)).join("\n");
      writeFileSync(this.file, body === "" ? "" : `${body}\n`, { mode: 0o600 });
      chmodSync(this.file, 0o600);
      this.fileLines = this.lines.size;
    } catch (err) {
      this.log(`evidence vault: couldn't compact: ${String(err)}`);
    }
  }

  // ── Fingerprints ──────────────────────────────────────────────────────────

  /** The per-install HMAC key, created on first use. Undefined when the
   * keychain can't protect it — then there are no fingerprints either, since
   * a key stored in the clear would make them brute-forceable after all. A key
   * file the keychain can no longer open (a reset, a restore onto another Mac)
   * is set aside and replaced: fingerprints restart, rather than stopping for
   * good. */
  private key(): Buffer | undefined {
    if (this.hmacKey) return this.hmacKey;
    if (this.keyFailed || !this.available()) return undefined;
    const path = join(this.dir, this.names.key);
    if (existsSync(path)) {
      try {
        const key = Buffer.from(this.crypto.decrypt(readFileSync(path)), "base64");
        if (key.length === 32) {
          this.hmacKey = key;
          return key;
        }
        throw new Error(`key is ${key.length} bytes`);
      } catch (err) {
        this.log(`evidence vault: fingerprint key unreadable (${String(err)}); starting a new one`);
        try {
          renameSync(path, setAsidePath(path));
        } catch {
          // fall through: the write below replaces it
        }
      }
    }
    try {
      const fresh = randomBytes(32);
      writeFileSync(path, this.crypto.encrypt(fresh.toString("base64")), { mode: 0o600 });
      this.hmacKey = fresh;
      return fresh;
    } catch (err) {
      this.keyFailed = true;
      this.lock(err);
      return undefined;
    }
  }

  /** Fingerprints of real values only: a "value" that is itself a literal
   * placeholder (text that was already masked when the agent wrote it) has
   * nothing behind it, and fingerprinting it would make every such finding look
   * like the same leaked secret. */
  fingerprints(secrets: readonly RedactedSecret[]): SecretFingerprint[] {
    const real = secrets.filter((s) => s.value !== "" && !isPlaceholderText(s.value));
    if (real.length === 0) return [];
    const key = this.key();
    if (!key) return [];
    return real.map((s) => fingerprintSecret(key, s));
  }
}

/** Where an unreadable key file is moved — never onto an earlier one. */
function setAsidePath(path: string): string {
  const base = `${path}.unreadable-${Date.now()}`;
  let candidate = base;
  for (let n = 1; existsSync(candidate); n++) candidate = `${base}-${n}`;
  return candidate;
}

export function fingerprintSecret(key: Buffer, secret: RedactedSecret): SecretFingerprint {
  return {
    label: secret.label,
    length: secret.value.length,
    fingerprint: createHmac("sha256", key).update(secret.value).digest("hex").slice(0, 16),
    ...(secret.primary ? { primary: true } : {}),
  };
}

/**
 * The DEV SANDBOX's stand-in for the keychain — scripts/dev-sandbox.mjs only.
 *
 * The sandbox redirects HOME, and macOS looks for the login keychain under
 * it: `safeStorage` then reports no encryption and, worse, raises the system's
 * "A keychain cannot be found" dialog on every boot. So a sandbox (and only a
 * sandbox — index.ts gates this on DOORMAN_APPDATA_DIR *and* a redirected
 * HOME) encrypts with AES-256-GCM under a random key kept in the fixture's own
 * store. That is not a keychain, and says so: the key sits beside the data,
 * inside a throwaway directory whose linked transcripts already hold the same
 * values in the clear. It exists so the vault can be SEEN working in a dev run,
 * never as a fallback for a real install.
 */
export function sandboxVaultCrypto(dir: string): VaultCrypto {
  const path = join(dir, "evidence-vault.sandbox-key");
  let key: Buffer | undefined;
  const keyOf = (): Buffer => {
    if (key) return key;
    if (existsSync(path)) key = readFileSync(path);
    else {
      key = randomBytes(32);
      writeFileSync(path, key, { mode: 0o600 });
    }
    return key;
  };
  return {
    isAvailable: () => true,
    encrypt: (plain) => {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", keyOf(), iv);
      const body = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), body]);
    },
    decrypt: (blob) => {
      const decipher = createDecipheriv("aes-256-gcm", keyOf(), blob.subarray(0, 12));
      decipher.setAuthTag(blob.subarray(12, 28));
      return Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]).toString("utf8");
    },
  };
}
