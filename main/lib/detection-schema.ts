/**
 * The detection record — ONE JSON Schema for what the Security Radar knows
 * about a finding. It is the contract behind three things that used
 * to agree only by convention:
 *
 *  · the ledger: every row capture.ts appends to findings.jsonl is checked
 *    against it, and rows written before the schema existed are upgraded on
 *    read (`upgradeFindingRow`);
 *  · the export: "Export detections" writes a bundle that validates against
 *    `DETECTIONS_EXPORT_SCHEMA`, so a security team's tooling can rely on the
 *    shape rather than reverse-engineer it;
 *  · Doorman AI: the finding context carries this record, so the model sees
 *    the same fields a person exports.
 *
 * The schema is DATA that the validator below interprets — there is no
 * second, hand-maintained list of fields to drift from it. The committed copies
 * under schemas/ are generated from these objects (lib/schema-files.ts;
 * a test fails when they differ), for readers who never open TypeScript.
 *
 * What the record never holds: a raw value. The excerpt is masked before it is
 * minted (guard/security-detect.ts), and a redacted secret appears only as a
 * `secrets[]` fingerprint — family, length, a keyed hash. The value itself,
 * when kept at all, lives in the Keychain-encrypted evidence vault
 * (lib/evidence-vault.ts), which nothing here reads.
 */

import type { FindingRow } from "./findings.js";
import { maskFindingRow } from "./masking.js";

export const DETECTION_SCHEMA_VERSION = 1;
export const DETECTION_SCHEMA_ID = "urn:doorman:schemas:detection.v1";
export const DETECTIONS_EXPORT_SCHEMA_ID = "urn:doorman:schemas:detections-export.v1";

/** The subset of JSON Schema (2020-12) the validator understands. */
export interface JsonSchema {
  $schema?: string;
  $id?: string;
  $ref?: string;
  $defs?: Record<string, JsonSchema>;
  title?: string;
  description?: string;
  type?: JsonType | JsonType[];
  enum?: readonly (string | number | boolean | null)[];
  const?: string | number | boolean | null;
  properties?: Record<string, JsonSchema>;
  required?: readonly string[];
  additionalProperties?: boolean;
  items?: JsonSchema;
  pattern?: string;
  format?: "date-time";
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
}
type JsonType = "string" | "number" | "integer" | "boolean" | "object" | "array" | "null";

const SEVERITY = ["critical", "high", "medium", "low"] as const;
const ENFORCEMENT_MODE = ["observe", "warn", "ask", "block"] as const;

const str = (description: string, extra: Partial<JsonSchema> = {}): JsonSchema => ({ type: "string", description, ...extra });
const time = (description: string): JsonSchema => ({ type: "string", format: "date-time", description });

/**
 * One redacted value, as a fingerprint. Enough to say "the same AWS key showed
 * up in three sessions" or "this is a 40-character GitHub token" without the
 * value: the hash is an HMAC under a key that never leaves this Mac, so it
 * cannot be brute-forced from an export the way a bare SHA-256 of a short
 * password could.
 */
const SECRET_FINGERPRINT: JsonSchema = {
  type: "object",
  description: "A value redaction removed from the evidence, as a fingerprint — never the value.",
  required: ["label", "length", "fingerprint"],
  additionalProperties: false,
  properties: {
    label: str("The redaction family (`aws`, `github`, `credentials`); empty for an anonymous value."),
    length: { type: "integer", minimum: 0, description: "Characters in the value." },
    fingerprint: str("HMAC-SHA256 of the value under this machine's vault key, first 16 hex characters.", {
      pattern: "^[0-9a-f]{16}$",
    }),
    primary: { type: "boolean", description: "The value this detection is about, when the evidence held several." },
  },
};

const ACCOUNT: JsonSchema = {
  type: "object",
  description: "What happened, in quotable fields and a sentence (lib/account.ts). Paths, command words and hosts — never a value.",
  required: ["by", "source_kind", "placeholder_signals", "sentence", "title", "so", "next"],
  additionalProperties: false,
  properties: {
    by: { type: "string", enum: ["extractor", "local_reader"] },
    source_kind: { type: "string", enum: ["file", "env", "prompt", "secret_manager", "tool_output", "unknown"] },
    source_ref: str("The file the value came from."),
    name: str("The secret-shaped name a value was assigned to."),
    read_via: str("The command or tool that read it."),
    sink_tool: str("The command or tool that carried it out."),
    destination_host: str("The host it was sent to."),
    credential_family: str("The redaction family of the value."),
    output: {
      type: "string",
      enum: ["agent", "local"],
      description: "For a secret read: printed back to the agent (`agent`), or used without being printed (`local`).",
    },
    family_noun: str("The family in words."),
    gap: str("Time between a flow's two ends."),
    placeholder_signals: {
      type: "array",
      items: { type: "string", enum: ["test_path", "doc_example", "synthetic_value", "named_as_example"] },
    },
    sentence: str("The card's sentence."),
    title: str("The card's headline."),
    so: str("The consequence, in one line."),
    next: str("What to do, in one line."),
  },
};

/** The ledger row. Property order follows FindingRow. */
export const DETECTION_SCHEMA: JsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: DETECTION_SCHEMA_ID,
  title: "Doorman detection",
  description:
    "One Security Radar finding on this computer: which rule fired, how sure it was, the mode it was in, what enforcement did, when, where, and the masked evidence.",
  type: "object",
  required: [
    "schema_version",
    "finding_id",
    "detector",
    "severity",
    "excerpt",
    "occurrences",
    "source",
    "origin",
    "status",
    "first_seen_at",
    "last_seen_at",
  ],
  additionalProperties: false,
  properties: {
    schema_version: { const: DETECTION_SCHEMA_VERSION, description: "This schema's version." },
    finding_id: str("Stable identity: a hash of detector + session + key name.", { minLength: 1 }),
    detector: str("The rule that fired: a shipped detector id, or `custom:<id>` for the person's own rule.", {
      pattern: "^(custom:[a-z0-9][a-z0-9_-]{0,47}|[a-z][a-z0-9_]*)$",
    }),
    detector_label: str("A custom rule's label at the time it fired."),
    severity: { type: "string", enum: SEVERITY, description: "How bad it is if real." },
    confidence: {
      type: "string",
      enum: ["high", "medium", "low"],
      description: "How sure the rule (or a model's second look) was. Absent means high.",
    },
    rule_mode: {
      type: "string",
      enum: [...ENFORCEMENT_MODE, "off", "radar"],
      description:
        "The rule's enforcement level when this was last seen: observe/warn/ask/block, `off` (disabled), or `radar` (a Radar-only rule the guard never enforces).",
    },
    app_version: str("The app version that last recorded this row — which build of the detectors fired."),
    assist: {
      type: "object",
      description: "A model's second look at the rule's hit.",
      required: ["by", "model", "verdict"],
      additionalProperties: false,
      properties: {
        by: { type: "string", enum: ["injection_classifier", "second_opinion"] },
        model: str("The model's name."),
        verdict: { type: "string", enum: ["stood_down", "confirmed", "unsure"] },
        score: { type: "number", minimum: 0, maximum: 1 },
      },
    },
    account: ACCOUNT,
    key_name: str("The exposed or matched name (a file, a variable, a credential family)."),
    excerpt: str("Masked context around the match; redacted values read `[redacted:<family>]`."),
    secrets: {
      type: "array",
      description: "The values redacted from the evidence, as fingerprints.",
      items: SECRET_FINGERPRINT,
    },
    occurrences: { type: "integer", minimum: 0, description: "Times it matched in the newest sighting." },
    tool_name: str("The tool the agent called."),
    target: str("The file, command target or host the call named."),
    source: str("The capture rail or guarded host (`claude-code`, `codex`, …).", { minLength: 1 }),
    origin: {
      type: "string",
      enum: ["transcript", "guard", "config", "gateway", "integrity"],
      description: "How it was detected: a transcript scan, the pre-tool-use guard, an MCP config file, the MCP gateway, or the guard-integrity check.",
    },
    session_id: str("The agent session it happened in."),
    turn_id: str("The ledger turn it sits under."),
    source_turn_id: str("Session-flow rows: the turn where the flow began."),
    source_at: time("Session-flow rows: when the flow began."),
    burned_usd: { type: "number", minimum: 0, description: "agent_loop only: what the repeated turns cost, priced on this computer (an estimate; the app shows tokens instead)." },
    burned_tokens: { type: "integer", minimum: 0, description: "agent_loop only: input+output tokens the repeated turns burned — the figure the app shows." },
    config_host: str("Config rows: the app whose config file this is."),
    cwd: str("The call's working directory."),
    status: {
      type: "string",
      enum: ["open", "resolved", "false_positive", "accepted_risk"],
      description: "Triage state.",
    },
    first_seen_at: time("First sighting."),
    last_seen_at: time("Newest sighting."),
    enforced: {
      type: "string",
      enum: ["ask", "deny", "warn", "excepted"],
      description: "What the guard did: held, refused, warned, or let it through under an exception. Absent means observed.",
    },
    exception: {
      type: "object",
      description: "The scoped ignore rule that let an `excepted` call through, as it stood then.",
      required: ["pattern"],
      additionalProperties: false,
      properties: {
        pattern: str("The rule's pattern."),
        detector: str("The detector it is limited to."),
        cwd_prefix: str("The directory it is limited to."),
        expires_at: time("When it lapses."),
        note: str("Why it exists."),
        origin: { type: "string", enum: ["approval", "manual"] },
      },
    },
    resolution: {
      type: "string",
      enum: ["allowed", "denied", "timeout", "unattended", "unavailable"],
      description: "How a held call ended.",
    },
    held_at: time("When the hold was raised."),
    decided_at: time("When it was answered."),
    decided_via: {
      type: "string",
      enum: ["panel", "window", "notification", "editor", "terminal", "timeout", "app-absent"],
      description: "Which surface answered it.",
    },
    hold_ms: { type: "number", minimum: 0, description: "Milliseconds from hold to decision." },
    allow_scope: { type: "string", enum: ["project"], description: "The person allowed it for this project." },
  },
};

/** The file "Export detections" writes. */
export const DETECTIONS_EXPORT_SCHEMA: JsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: DETECTIONS_EXPORT_SCHEMA_ID,
  title: "Doorman detections export",
  description: "Every detection the Security Radar shows on this computer, with the rules that raised them. Masked: no raw values.",
  type: "object",
  required: ["schema", "schema_version", "generated_at", "app_version", "detectors", "detections"],
  additionalProperties: false,
  properties: {
    schema: { const: DETECTIONS_EXPORT_SCHEMA_ID, description: "This file's own schema." },
    schema_version: { const: DETECTION_SCHEMA_VERSION },
    generated_at: time("When the file was written."),
    app_version: str("The app that wrote it."),
    detectors: {
      type: "array",
      description: "Each rule that appears in `detections`, with its label and current mode.",
      items: {
        type: "object",
        required: ["id", "label"],
        additionalProperties: false,
        properties: {
          id: str("Detector id."),
          label: str("Human label."),
          mode: { type: "string", enum: [...ENFORCEMENT_MODE, "off", "radar"] },
        },
      },
    },
    detections: { type: "array", items: { $ref: "#/$defs/detection" } },
  },
  $defs: { detection: { ...DETECTION_SCHEMA, $schema: undefined, $id: undefined } },
};

// ── Validation ─────────────────────────────────────────────────────────────────

export interface SchemaProblem {
  /** JSON pointer to the offending value (`/secrets/0/length`). */
  path: string;
  message: string;
}

function typeOf(value: unknown): JsonType {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  return typeof value as JsonType;
}

function typeMatches(actual: JsonType, wanted: JsonType): boolean {
  return actual === wanted || (wanted === "number" && actual === "integer");
}

const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * Validate `value` against `schema` — the keywords `JsonSchema` declares,
 * nothing else. `root` resolves `#/$defs/…` references.
 */
export function validateSchema(schema: JsonSchema, value: unknown, root: JsonSchema = schema, path = ""): SchemaProblem[] {
  if (schema.$ref) {
    const name = /^#\/\$defs\/(.+)$/.exec(schema.$ref)?.[1];
    const target = name && root.$defs && Object.hasOwn(root.$defs, name) ? root.$defs[name] : undefined;
    if (!target) return [{ path, message: `unresolvable $ref ${schema.$ref}` }];
    return validateSchema(target, value, root, path);
  }
  const problems: SchemaProblem[] = [];
  const at = path || "/";
  if (schema.const !== undefined && value !== schema.const) {
    problems.push({ path: at, message: `must be ${JSON.stringify(schema.const)}` });
    return problems;
  }
  if (schema.enum && !schema.enum.includes(value as never)) {
    problems.push({ path: at, message: `must be one of ${schema.enum.join(", ")}` });
    return problems;
  }
  const actual = typeOf(value);
  if (schema.type) {
    const wanted = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!wanted.some((t) => typeMatches(actual, t))) {
      problems.push({ path: at, message: `must be ${wanted.join(" or ")}, got ${actual}` });
      return problems;
    }
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) problems.push({ path: at, message: `shorter than ${schema.minLength}` });
    if (schema.maxLength !== undefined && value.length > schema.maxLength) problems.push({ path: at, message: `longer than ${schema.maxLength}` });
    if (schema.pattern && !new RegExp(schema.pattern, "u").test(value)) problems.push({ path: at, message: `does not match ${schema.pattern}` });
    if (schema.format === "date-time" && (!ISO_INSTANT.test(value) || !Number.isFinite(Date.parse(value)))) {
      problems.push({ path: at, message: "must be an ISO 8601 date-time" });
    }
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) problems.push({ path: at, message: "must be finite" });
    if (schema.minimum !== undefined && value < schema.minimum) problems.push({ path: at, message: `below ${schema.minimum}` });
    if (schema.maximum !== undefined && value > schema.maximum) problems.push({ path: at, message: `above ${schema.maximum}` });
  }
  if (actual === "array" && schema.items) {
    (value as unknown[]).forEach((item, i) => problems.push(...validateSchema(schema.items!, item, root, `${path}/${i}`)));
  }
  if (actual === "object") {
    const obj = value as Record<string, unknown>;
    for (const key of schema.required ?? []) {
      if (obj[key] === undefined) problems.push({ path: `${path}/${key}`, message: "is required" });
    }
    for (const [key, child] of Object.entries(obj)) {
      // JSON drops undefined; so does the check.
      if (child === undefined) continue;
      // Own properties only: `constructor`, `toString`… are on every object's
      // prototype and must not pass as declared fields.
      const sub = schema.properties && Object.hasOwn(schema.properties, key) ? schema.properties[key] : undefined;
      if (sub) problems.push(...validateSchema(sub, child, root, `${path}/${key}`));
      else if (schema.additionalProperties === false) problems.push({ path: `${path}/${key}`, message: "is not a known field" });
    }
  }
  return problems;
}

export function validateDetection(value: unknown): SchemaProblem[] {
  return validateSchema(DETECTION_SCHEMA, value);
}

export function validateDetectionsExport(value: unknown): SchemaProblem[] {
  return validateSchema(DETECTIONS_EXPORT_SCHEMA, value);
}

/** The fields main stamps on a SNAPSHOT copy of a row (lib/exposures.ts) —
 * never stored, so never part of the record. */
const SNAPSHOT_ONLY = ["place", "place_kind", "exposure_key"] as const;

/**
 * A ledger line → a current-version row. Rows written before carry no
 * `schema_version`; every field they do carry is already in v1, so the upgrade
 * is the stamp. A line that is not a row at all (no id) is refused — the fold
 * skips it as it always has.
 */
export function upgradeFindingRow(raw: unknown): FindingRow | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const row = raw as Record<string, unknown>;
  if (typeof row.finding_id !== "string") return undefined;
  const version = row.schema_version;
  if (version !== undefined && (typeof version !== "number" || version > DETECTION_SCHEMA_VERSION)) {
    // Written by a NEWER app (a downgrade). Keep it — the fields this build
    // knows still read — but it is that build's record, not ours to restamp.
    return maskFindingRow(row as unknown as FindingRow);
  }
  // Rows from before the masking rule (lib/masking.ts) could carry a value in
  // their target or account quotes; reading one masks it.
  return maskFindingRow({ ...(row as unknown as FindingRow), schema_version: DETECTION_SCHEMA_VERSION });
}

/** A row as the record: current version, snapshot-only fields dropped, and
 * every free-text field masked once more — this is the choke point for the
 * export and Doorman AI, so it does not trust the row to be clean. */
export function toDetectionRecord(row: FindingRow): FindingRow {
  const out: Record<string, unknown> = { ...maskFindingRow(row), schema_version: DETECTION_SCHEMA_VERSION };
  for (const key of SNAPSHOT_ONLY) delete out[key];
  return out as unknown as FindingRow;
}

export interface DetectionsExport {
  schema: typeof DETECTIONS_EXPORT_SCHEMA_ID;
  schema_version: typeof DETECTION_SCHEMA_VERSION;
  generated_at: string;
  app_version: string;
  detectors: Array<{ id: string; label: string; mode?: NonNullable<FindingRow["rule_mode"]> }>;
  detections: FindingRow[];
}

export function buildDetectionsExport(inputs: {
  rows: readonly FindingRow[];
  app_version: string;
  generated_at: Date;
  labelOf: (detector: string) => string;
  modeOf: (detector: string) => FindingRow["rule_mode"];
}): DetectionsExport {
  const detections = inputs.rows
    .map(toDetectionRecord)
    .sort((a, b) => b.last_seen_at.localeCompare(a.last_seen_at) || a.finding_id.localeCompare(b.finding_id));
  const ids = [...new Set(detections.map((d) => d.detector))].sort();
  return {
    schema: DETECTIONS_EXPORT_SCHEMA_ID,
    schema_version: DETECTION_SCHEMA_VERSION,
    generated_at: inputs.generated_at.toISOString(),
    app_version: inputs.app_version,
    detectors: ids.map((id) => {
      const mode = inputs.modeOf(id);
      const recorded = detections.find((d) => d.detector === id && d.detector_label)?.detector_label;
      return { id, label: recorded ?? inputs.labelOf(id), ...(mode === undefined ? {} : { mode }) };
    }),
    detections,
  };
}
