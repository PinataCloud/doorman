# Hermes Agent state.db fixture — provenance

`state-rows.json` is a **real recording**: every column of the `sessions` and
`messages` tables (plus `session_model_usage`, for reference — the reader does
not query it) as Hermes Agent **0.21.1** (NousResearch/hermes-agent `main`,
editable install in a throwaway venv) wrote them to a throwaway
`HERMES_HOME/state.db` on 2026-09-08, during the guard's end-to-end test: two
headless `hermes -z` turns (anthropic/claude-haiku-4.5 through OpenRouter) with
the Doorman shell hook installed by the app's own installer. The first asked
for two `terminal` calls, one denied by a block-mode custom rule; the second for
`write_file` → `read_file` → `patch` → a denied `terminal`. Values are
verbatim except scratch paths, rewritten to `/Users/dev/projects/api` (the
second session's cwd) and `/Users/dev` (the home).

What it pins that the docs could not: the real column list (58 session
columns, 24 message columns — the reader discovers what it needs through
`pragma_table_info`), `actual_cost_usd` NULL with `estimated_cost_usd` set and
`cost_status = "estimated"`, `reasoning_tokens` counted separately, the
`tool_calls` JSON shape (`id`/`call_id`/`response_item_id`/`function{name,
arguments}`), tool rows whose `content` is a JSON object, and the exact shape a
guard deny takes on this host: a `tool` row with `{"error": "Doorman flagged
this tool call: …"}`.

The unit suite in `test/hermes-transcript.test.ts` otherwise fabricates
its databases in-test from the documented schema; the "against a real state.db"
suite rebuilds this fixture into a real SQLite file so the reader runs against
the genuine, wider schema.
