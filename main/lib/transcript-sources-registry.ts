/**
 * The transcript-source REGISTRY — the one list of hosts whose sessions the
 * capture engine reads from disk beyond the two it was born with.
 *
 * The contract each entry satisfies is `transcript-sources.ts`; the engine
 * (capture.ts) iterates THIS array instead of naming hosts, so registering a
 * descriptor is the whole of "Cursor shows up in the ledger": backfill, watch,
 * cursors, detection, the coverage card's Captured row, the per-source stats
 * on CaptureStatus.
 *
 * Claude Code and Codex are deliberately NOT here. Their parsers are wired
 * into the engine directly (`lib/cc-transcript.ts`, `lib/codex-rollout.ts`)
 * and predate the seam; adding them here would make the engine read the same
 * tree twice. `sourceLabel` covers them so a caller can name any TurnSource
 * without caring which side of that line it falls on.
 *
 * The last two entries are apps rather than agent CLIs, and their ids are their
 * SHADOW-AI CATALOG ids (lib/shadow-ai.ts) — no guard adapter can reach either,
 * so there is no guard-host id to match instead, and the coverage map joins the
 * registry to the catalog on that one string.
 */

import type { TranscriptSourceDescriptor } from "./transcript-sources.js";
import type { TurnSource } from "./turns.js";

/* ---- registered transcript sources -------------------------------------
 *
 * ONE line per host, and nothing else: a descriptor is pure over `SourceIo`,
 * so a parser lands here as an import plus an array entry. When the three
 * parsers merge, this block becomes:
 *
 *   import { cursorSource } from "./cursor-transcript.js";
 *   import { geminiSource } from "./gemini-transcript.js";
 *   import { copilotSource } from "./copilot-transcript.js";
 *
 * ...with `cursorSource, geminiSource, copilotSource` appended to the array
 * below. Order is display order (the ledger's rail chips, the coverage card),
 * not precedence — nothing here depends on it.
 *
 * ---- BEGIN registered sources ---- */
import { cursorSource } from "./cursor-transcript.js";
import { geminiSource } from "./gemini-transcript.js";
import { copilotSource } from "./copilot-transcript.js";
import { claudeDesktopSource } from "./claude-desktop-transcript.js";
import { vscodeCopilotSource } from "./vscode-copilot-transcript.js";
// 2026-09-06 — the autonomous
// agent frameworks and the next CLIs, each with its own native session record.
import { hermesSource } from "./hermes-transcript.js";
import { gooseSource } from "./goose-transcript.js";
import { qwenSource } from "./qwen-transcript.js";
import { openclawSource } from "./openclaw-transcript.js";
import { grokSource } from "./grok-transcript.js";

export const TRANSCRIPT_SOURCES: readonly TranscriptSourceDescriptor[] = [
  cursorSource,
  geminiSource,
  copilotSource,
  claudeDesktopSource,
  vscodeCopilotSource,
  hermesSource,
  gooseSource,
  qwenSource,
  openclawSource,
  grokSource,
];

/* ---- END registered sources ---- */

/** The descriptor for a source id, or undefined when nothing is registered. */
export function sourceById(
  id: string,
  registry: readonly TranscriptSourceDescriptor[] = TRANSCRIPT_SOURCES,
): TranscriptSourceDescriptor | undefined {
  return registry.find((source) => source.id === id);
}

/** The two hosts the engine reads without a descriptor — see the header. */
const BUILT_IN_LABELS: Readonly<Record<string, string>> = {
  "claude-code": "Claude Code",
  codex: "Codex",
};

/**
 * A human label for any TurnSource: the registry's when one is registered, the
 * built-in name for the two native rails, and the id itself as the last
 * resort — a stored turn from a host whose descriptor was removed still has to
 * render as something, and its own id is the honest answer.
 */
export function sourceLabel(
  id: TurnSource,
  registry: readonly TranscriptSourceDescriptor[] = TRANSCRIPT_SOURCES,
): string {
  return sourceById(id, registry)?.label ?? BUILT_IN_LABELS[id] ?? id;
}

/** Every source the ledger can hold, in display order: the two native rails
 * first (they are the oldest and the most populated), then the registry. */
export function allSourceLabels(
  registry: readonly TranscriptSourceDescriptor[] = TRANSCRIPT_SOURCES,
): Array<{ id: TurnSource; label: string }> {
  return [
    { id: "claude-code" as TurnSource, label: BUILT_IN_LABELS["claude-code"]! },
    { id: "codex" as TurnSource, label: BUILT_IN_LABELS["codex"]! },
    ...registry.map((source) => ({ id: source.id, label: source.label })),
  ];
}
