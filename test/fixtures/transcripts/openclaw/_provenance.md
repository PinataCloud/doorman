# OpenClaw session fixtures — provenance

## Recorded live

`agents/main/sessions/doorman-e2e-1.jsonl` is a **real recording**, written by
OpenClaw **2026.3.8 (3caab92)** on 2026-09-08 during the guard's end-to-end
test: two `openclaw agent --local --session-id …` turns (Claude Opus 4.6 through
the stored Anthropic profile) under a throwaway `OPENCLAW_STATE_DIR` with the
doorman-guard plugin installed by the app's own installer. The first turn asked
for two `exec` calls, one of which a block-mode custom rule denied; the second
asked for `write` → `read` → `edit` → a denied `exec`. Both turns landed in this
one file (OpenClaw kept appending to the agent's existing session despite the
second `--session-id`). The **only** edit is the home directory in `cwd`
(`/Users/dev/` → `/Users/dev/`). Exercises: the v3 header, `model_change`,
`thinking_level_change` and `custom` entries, parallel `toolCall`s, `thinking`
parts, host `usage.cost` on every assistant message, and the tool-result shape a
guard deny takes on this host (`details.error` = our reason, `isError: false`).

## Synthetic

Every other file here is **synthetic**: prompts, replies, tool arguments, paths,
session ids and entry ids are invented. No OpenClaw session existed on the
machine these were written on (`~/.openclaw/agents/main/sessions/` was empty).

What is **not** invented is the shape. OpenClaw writes sessions through the pi
coding agent's `SessionManager` (session file version 3), read on
**2026-09-06** from the OpenClaw **2026.3.8 (3caab92)** install on this Mac:
`node_modules/@mariozechner/pi-coding-agent/dist/core/session-manager.js`
(entry types, `id`/`parentId`, the `<ts>_<uuid>.jsonl` name) and
`@mariozechner/pi-ai/dist/types.d.ts` (`Usage`, `UserMessage`,
`AssistantMessage`, `ToolResultMessage`). The flat legacy line in
`legacy-flat.jsonl` mirrors the older shape quoted in OpenClaw's own issue
tracker and docs (docs.openclaw.ai/reference/token-use). The live recording
above confirmed the shape line for line.

| Fixture | Exercises |
|---|---|
| `2026-09-06T10-00-00-000Z_3f7a9c12-5b4e-4d8a-9c1e-7b2d4f6a8e01.jsonl` | header with `cwd`, `session_info` title, user → assistant (toolCall, host cost) → toolResult → assistant (no host cost, OpenRouter `vendor/model`), an `error` line with zero usage, a `compaction` entry |
| `work/sessions/9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d.jsonl` | the older `<uuid>.jsonl` name, an unpriceable custom-provider model (`cost_unknown`), a half-written last line |
| `main/sessions/legacy-flat.jsonl` | v1 flat lines with epoch-ms `timestamp` and no entry ids |
| `main/sessions/sessions.json` | the index — must be skipped |
