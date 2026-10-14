# Gemini CLI session fixtures — provenance

Every file here is **synthetic**. The prompts, assistant replies, tool
arguments, tool output, paths, session ids and message ids are invented; no
real Gemini CLI recording was available on the machine these were written on
(`~/.gemini` held only `GEMINI.md`, `settings.json` and Google's separate
Antigravity IDE state — there was no `~/.gemini/tmp` at all).

What is **not** invented is the shape. Each record mirrors the upstream types
and the writer that produces them, read at
`raw.githubusercontent.com/google-gemini/gemini-cli/main/…` on **2026-09-06**,
at `main` commit **85aca163f6c73ac6ce380b5447359146b8adcae4** (latest release
at the time: **v0.58.0**):

| Fixture detail | Upstream source |
| --- | --- |
| `ConversationRecord`, `MessageRecord`, `TokensSummary`, `ToolCallRecord`, `SESSION_FILE_PREFIX = 'session-'` | `packages/core/src/services/chatRecordingTypes.ts` |
| the append-log lines (metadata, message upsert, `$set`, `$rewindTo`), the `session-<YYYY-MM-DDTHH-mm>-<id8>.jsonl` filename, the subagent `chats/<parentSessionId>/<sessionId>.jsonl` nesting, the legacy whole-file `.json` record | `packages/core/src/services/chatRecordingService.ts` |
| `GEMINI_DIR = '.gemini'`, `GEMINI_CLI_HOME` | `packages/core/src/utils/paths.ts` |
| `TMP_DIR_NAME = 'tmp'`, `getProjectTempDir()`, `chats/` | `packages/core/src/config/storage.ts` |
| `PROJECT_ROOT_FILE = '.project_root'` and the project-id slug | `packages/core/src/config/projectRegistry.ts` |
| `isIgnoredUserContent` (`/`, `?`, `<session_context>`, `<hook_context>`) | `packages/core/src/utils/sessionUtils.ts` |
| the model ids (`gemini-2.5-pro` priced, `gemini-3-pro-preview` not) | `packages/core/src/config/models.ts` |
| tool names `read_file` / `write_file` / `run_shell_command` and their `file_path` / `command` arguments | `packages/core/src/tools/{read-file,write-file,shell}.ts` |

## The tree

```
tmp/
  doorman-loop/                       one project's temp dir (the slug form)
    .project_root                      absolute project root -> a turn's cwd
    chats/
      session-2026-09-05T14-32-9f3c1a2b.jsonl   the append log, with a $rewindTo
      session-2026-09-05T09-10-4b8e77c0.json    the LEGACY whole-file record
      session-2026-09-05T15-00-c0ffee11.jsonl   a half-written trailing line
      session-2026-09-05T14-32-9f3c1a2b.jsonl.tmp-4242   writer scratch, ignored
      notes.txt                                          not a session, ignored
      9f3c1a2b-4d5e-4f60-9a1b-2c3d4e5f6071/     subagents of that session
        7a1b2c3d-4e5f-4061-8a2b-3c4d5e6f7081.jsonl
  antigravity/                         see below
```

`tmp/antigravity/` is deliberately **not** where the real Antigravity IDE keeps
its state — upstream puts that at `~/.gemini/antigravity`, a sibling of `tmp`
rather than a project inside it. It sits here so the "skip `antigravity`" guard
in `discover` is exercised: the guard exists so a root pointed one level too
high can never ingest another product's files.
