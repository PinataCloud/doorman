/**
 * The Event Ledger export — sessions and their turns as one JSON
 * document with a published schema, the ledger's counterpart to the
 * detections export (lib/detection-schema.ts), validated by the same
 * interpreter.
 *
 * Masked like everything that leaves the app through a save dialog: turn text
 * goes through lib/masking.ts maskTurnText — redact(), the detectors' own
 * masks (cards, IBANs, wallet values, high-entropy tokens), and the tail a
 * length cap cut through — and each value removed rides as a fingerprint
 * (label, length, keyed HMAC) — the SAME fingerprint the detection rows carry,
 * so "this turn held the key that detection is about" is answerable from the
 * two files without either one holding the key. Sessions name the detections
 * anchored to them by id rather than embedding them: the detections export is
 * that record's one home.
 */

import type { LedgerTurn, SessionSummary } from "./turns.js";
import type { SecretFingerprint } from "./findings.js";
import { DETECTION_SCHEMA_VERSION, validateSchema, type JsonSchema, type SchemaProblem } from "./detection-schema.js";

export const LEDGER_EXPORT_SCHEMA_ID = "urn:doorman:schemas:ledger-export.v1";

const str = (description: string, extra: Partial<JsonSchema> = {}): JsonSchema => ({ type: "string", description, ...extra });
const time = (description: string): JsonSchema => ({ type: "string", format: "date-time", description });
const count = (description: string): JsonSchema => ({ type: "integer", minimum: 0, description });
const usd = (description: string): JsonSchema => ({ type: "number", minimum: 0, description });

const FINGERPRINT: JsonSchema = {
  type: "object",
  required: ["label", "length", "fingerprint"],
  additionalProperties: false,
  properties: {
    label: str("The redaction family; empty for an anonymous value."),
    length: count("Characters in the value."),
    fingerprint: str("HMAC-SHA256 under this machine's vault key, 16 hex characters — matches the detections export.", {
      pattern: "^[0-9a-f]{16}$",
    }),
    primary: { type: "boolean" },
  },
};

const TURN: JsonSchema = {
  type: "object",
  description: "One prompt or model turn.",
  required: ["id", "source", "session_id", "role", "at"],
  additionalProperties: false,
  properties: {
    id: str("Stable turn id.", { minLength: 1 }),
    source: str("The capture rail.", { minLength: 1 }),
    session_id: str("The session it belongs to."),
    role: { type: "string", enum: ["user", "assistant"] },
    at: time("When it happened."),
    model: str("The model that answered."),
    usage: {
      type: "object",
      required: ["input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "cache_write_1h_tokens", "web_search_requests"],
      additionalProperties: false,
      properties: {
        input_tokens: count("Input tokens."),
        output_tokens: count("Output tokens."),
        cache_read_tokens: count("Cache-read tokens."),
        cache_write_tokens: count("Cache-write tokens."),
        cache_write_1h_tokens: count("Of which 1-hour-TTL cache writes."),
        web_search_requests: count("Web searches."),
      },
    },
    cost: usd("USD from the local pricing table; absent when the model is unpriced."),
    cost_unknown: { type: "boolean" },
    reported_cost: usd("A provider-reported charge."),
    usage_incomplete: { type: "boolean" },
    settlement: { type: "string", enum: ["subscription", "credits", "billed", "unknown"] },
    text: str("The turn's text, redacted: a removed value reads `[redacted:<family>]`."),
    text_redacted: { type: "boolean", description: "Redaction changed this turn's text." },
    secrets: { type: "array", items: FINGERPRINT, description: "The values redaction removed, as fingerprints." },
    tools: { type: "array", items: { type: "string" } },
    cwd: str("Working directory."),
    git_branch: str("Git branch."),
  },
};

const SESSION: JsonSchema = {
  type: "object",
  description: "One agent session, as the Event Ledger shows it.",
  required: ["id", "source", "cost", "turns", "prompts", "started_at", "ended_at", "detection_ids", "items"],
  additionalProperties: false,
  properties: {
    id: str("Session id.", { minLength: 1 }),
    source: str("The capture rail."),
    title: str("The session's title."),
    title_origin: { type: "string", enum: ["auto_prompt", "auto_summary"] },
    cost: usd("Priced USD across the session."),
    cost_unknown_turns: count("Turns with an unpriced model."),
    input_tokens: count("Input tokens."),
    output_tokens: count("Output tokens."),
    cache_read_tokens: count("Cache-read tokens."),
    cache_write_tokens: count("Cache-write tokens."),
    turns: count("Turns in the session."),
    prompts: count("Prompts in the session."),
    models: { type: "array", items: { type: "string" } },
    started_at: time("First turn."),
    ended_at: time("Newest turn."),
    cwd: str("Working directory."),
    git_branch: str("Git branch."),
    task: str("The use-case classification."),
    covered_cost: usd("Plan-covered USD."),
    overage_cost: usd("Credits USD."),
    billed_cost: usd("API-metered USD."),
    unknown_cost: usd("Unattributed USD."),
    covered_tokens: count("Plan-covered input+output tokens."),
    overage_tokens: count("Input+output tokens settled on API credits."),
    billed_tokens: count("Input+output tokens metered to an API key."),
    unknown_tokens: count("Unattributed input+output tokens."),
    alerts: count("Open detections anchored here."),
    last_role: { type: "string", enum: ["user", "assistant"] },
    last_turn_tools: count("Tool calls in the newest turn."),
    resume_command: str("The host's resume command."),
    detection_ids: {
      type: "array",
      items: { type: "string" },
      description: "`finding_id`s of the detections anchored to this session — the records are in the detections export.",
    },
    items: { type: "array", items: { $ref: "#/$defs/turn" }, description: "The session's turns, oldest first." },
  },
};

export const LEDGER_EXPORT_SCHEMA: JsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: LEDGER_EXPORT_SCHEMA_ID,
  title: "Doorman Event Ledger export",
  description: "Agent sessions and their turns on this Mac. Masked: turn text is redacted and removed values appear as fingerprints.",
  type: "object",
  required: ["schema", "schema_version", "generated_at", "app_version", "sessions"],
  additionalProperties: false,
  properties: {
    schema: { const: LEDGER_EXPORT_SCHEMA_ID },
    schema_version: { const: DETECTION_SCHEMA_VERSION },
    generated_at: time("When the file was written."),
    app_version: str("The app that wrote it."),
    sessions: { type: "array", items: { $ref: "#/$defs/session" } },
  },
  $defs: { turn: TURN, session: SESSION },
};

export type ExportedTurn = LedgerTurn & { text_redacted?: boolean; secrets?: SecretFingerprint[] };
export type ExportedSession = Omit<SessionSummary, "task"> & { task?: string; detection_ids: string[]; items: ExportedTurn[] };

export interface LedgerExport {
  schema: typeof LEDGER_EXPORT_SCHEMA_ID;
  schema_version: typeof DETECTION_SCHEMA_VERSION;
  generated_at: string;
  app_version: string;
  sessions: ExportedSession[];
}

export function buildLedgerExport(inputs: {
  sessions: readonly SessionSummary[];
  turnsOf: (sessionId: string) => readonly LedgerTurn[];
  detectionIdsOf: (sessionId: string) => readonly string[];
  /** lib/masking.ts maskTurnText — injected so this module stays free of the
   * redactor's and the detectors' tables. */
  mask: (text: string) => string;
  /** Fingerprints of what `mask` removed from a RAW text (given both halves). */
  fingerprintsOf: (raw: string, masked: string) => SecretFingerprint[];
  app_version: string;
  generated_at: Date;
}): LedgerExport {
  const sessions = inputs.sessions.map((session): ExportedSession => {
    const items = inputs.turnsOf(session.id).map((turn): ExportedTurn => {
      if (typeof turn.text !== "string" || turn.text === "") return { ...turn };
      const masked = inputs.mask(turn.text);
      if (masked === turn.text) return { ...turn };
      const secrets = inputs.fingerprintsOf(turn.text, masked);
      return { ...turn, text: masked, text_redacted: true, ...(secrets.length > 0 ? { secrets } : {}) };
    });
    // An auto_prompt title IS the first prompt's text — masked like it.
    const title = session.title === undefined ? {} : { title: inputs.mask(session.title) };
    return { ...session, ...title, detection_ids: [...inputs.detectionIdsOf(session.id)], items };
  });
  return {
    schema: LEDGER_EXPORT_SCHEMA_ID,
    schema_version: DETECTION_SCHEMA_VERSION,
    generated_at: inputs.generated_at.toISOString(),
    app_version: inputs.app_version,
    sessions,
  };
}

export function validateLedgerExport(value: unknown): SchemaProblem[] {
  return validateSchema(LEDGER_EXPORT_SCHEMA, value);
}
