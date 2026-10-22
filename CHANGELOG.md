# Changelog

What changed for the people using Doorman, newest first. The desktop app and the
CLI (`@pinata/doorman` on npm) are released separately: each release is one
`## App <version> — <YYYY-MM-DD>` or `## CLI <version> — <YYYY-MM-DD>` section,
with `### New`, `### Changed` and `### Fixed` lists of one-line bullets.
`scripts/release-notes.mjs` and `doorman changelog` read these headings, and a
release without its section fails before it builds. Work not yet released sits
under `## Unreleased`; a release renames its part of it.

## Unreleased

### Fixed
- `doorman gateway route`/`unroute`, `doorman mcp recognize`/`forget` and `doorman mcp server install`/`uninstall` work while `doorman watch` runs; watch only keeps the transcript store to itself, and an answer it saves no longer writes over a setting changed meanwhile.
- `doorman gateway route`/`unroute` work while the app runs (the app follows the config change); `doorman mcp recognize` while the app runs says to quit the app instead of pointing at a control the app doesn't show.
- The app takes the home directory from `$HOME`, as the guard and the CLI do; a run with a redirected `HOME` no longer reads or writes MCP configs in the account's real home, and a sandboxed run refuses any write that would land outside its own home.
- The transcript store is rewritten through a temporary file after a retention prune, so a reader never sees half a file.
- Registering Doorman's MCP server (Settings → Agents can ask Doorman, `doorman mcp server install`) no longer replaces an agent's MCP config it can't read, a server of your own named `doorman`, or a server list that isn't an object: that config is skipped with a message saying how to fix it, and the other agents still get the server.
- Registering edits each MCP config in place — comments, trailing commas, indentation and key order kept — so VS Code `mcp.json` files with comments are accepted, and unregistering gives the file back byte for byte (a file Doorman created is removed). The `.doorman.bak` beside it keeps the original from before Doorman's first edit, with the original's permissions.
- MCP configs that are symlinks are written through the link; read-only ones are refused, not replaced.
- Registering no longer creates stable VS Code's `mcp.json` on a machine with only Insiders, no longer fails on a `.DS_Store` in VS Code's profiles folder, and finds Copilot CLI under `$COPILOT_HOME`. Fields you add to Doorman's entry are kept.
- `doorman mcp` lists servers from configs with comments, trailing commas or a byte-order mark (Cursor, Zed, Windsurf, VS Code) and under `$COPILOT_HOME`; its recognized count adds up; a name in another Unicode spelling matches; and it no longer shows MCP rule counts the app hides.
- `doorman mcp recognize` warns when no server by that name is configured or seen; `doorman mcp forget a…` says when the name fits several servers; `doorman mcp server status` shows a config it can't read as unreadable, with the reason.
- A failed `doorman mcp server install` lists each failing config on its own line, prints `--json` on stdout, and only turns the setting on when the server landed somewhere.
- The MCP config watcher keeps seeing changes after an editor saves by renaming a new file over the old one.
- The guard no longer holds or denies an agent's calls to Doorman's own MCP tools (`doorman_check_tool_call` and the other three, which only read), so "check before you run" works; the tools are marked read-only, so Codex with `approval_policy=never` runs them.
- `doorman_explain_last_block` lists one entry per call with how it ended (allowed, denied, timed out, handed to the agent's own prompt), shows the calling agent's own session first and says when entries come from other sessions, matches `/tmp` and `/private/tmp` and a trailing slash, skips a malformed record, and prints tool names on one line.
- `doorman_status` and `doorman_check_tool_call` say when the guard is not installed in any agent, name pack and custom rules, report an unreadable policy file, name `doorman watch` when it answers, and an allow no longer reads as a safety clearance.
- Doorman's MCP server answers every request before it exits at end of input, never answers a notification, offers its own protocol version for one it doesn't speak, echoes very large request ids exactly, caps a message at 8 MB and exits quietly when its reader goes away.
- The MCP gateway passes tool-call arguments through byte for byte: a non-ASCII character split across two writes is no longer turned into `�`, and a last message the agent ends without a newline is forwarded.
- The MCP gateway hands over everything a server wrote before it exited (a large last reply was cut off), answers calls still in flight with an error when the server dies, survives an agent or server that closes its end of the pipe, and stops a server that ignores SIGTERM instead of leaving it running.
- The gateway's records (`observed.jsonl`, `calls.jsonl`) mask secrets in tool descriptions, schemas and results and are readable only by you; `observed.jsonl` grows only when a tool changes, not with every session.
- `doorman gateway route`/`unroute` change only the server's own entry — comments, tabs, escapes and large numbers stay as written, numeric arguments are kept, and unrouting gives the file back byte for byte; `.doorman.bak` keeps the file from before Doorman's first edit, with its permissions.
- `doorman gateway route` routes VS Code (`servers`, commented `mcp.json`) and Zed (`context_servers`) servers, a server named `--`, and, with `--project <dir>`, a project's server in `~/.claude.json` that shares its name with a user-level one.
- `doorman gateway route` says what the gateway does in this build — it records the tools a server advertises and the calls it answers — instead of promising to hold risky calls; `doorman gateway observed` no longer names or counts MCP rules the app hides.
- `doorman gateway calls` shows a refused, unattended or failed hold as such (not "ok"), shows a held call and its result as one row, and says "timed out after 60s".
- When MCP gateway permissions come back, a call can't slip past them in a JSON-RPC batch or with an unusual id, a refusal is never written into the middle of a server's reply, and a held call the agent cancelled or stopped waiting for is not run when approved later.

## CLI 0.7.0 — 2026-10-21

### New
- `doorman completion <zsh|bash|fish>`: Tab completion for every command, subcommand and flag, and exposure ids.
- `doorman changelog [--since <version>] [--all]`, and `doorman update` shows what changed after installing.
- `doorman watch` shows the agents running on this machine now (held · working · waiting for you · quiet), on macOS and Linux.
- `doorman findings resolve` marks exposures resolved, as the app's button does; `review` still works.

### Changed
- `doorman findings` and `findings show` name the project the way the app does ("acme-api"), the agent by name, and how a held call ended ("Held — denied by you after 9s"); a command excerpt reads as the command.
- `doorman analytics` counts outcomes the way the app does: Stopped (blocked or denied), Allowed, Warned, Observed, with held calls and the median time to decide; the `items` row is gone.

## App 0.7.0 — 2026-10-21

### New
- Overview: a ring around your level's shield shows how protected you are ("Protected · Balanced"), your live agents appear as pills (a held one counts down), and the open-exposure count takes you to the Radar.
- Held calls: a ring on Deny drains with the hold window, in step with the countdown, in the overlay and the floating panel.
- Radar: an "All clear" state when nothing is left to review.
- Analytics: headline figures count up, and "Stopped by the guard" shows one ◆ per stopped exposure.
- Guardrails: a shield per level that you click to change it, and each rule family shows its Observe / Warn / Ask / Block mode at a glance.
- Trace a secret: a "Where it went" route (way in → agent → provider, and the files an agent wrote it to), drawn only from what the trace found.
- Event Ledger: a strip with one bar per turn (height = tokens, a red notch = an exposure) that jumps to the turn, in place of the tokens-per-turn sparkline.
- Usage: a weekday × hour punchcard of the time you spent with your agents.

### Changed
- The "Protective" level is now called "Balanced" everywhere. Your setting carries over as it is.
- The tray menu no longer has Ask Doorman AI: it opens with Open Doorman, then Trace a Secret. Doorman AI is still in the app menu and the window.

## CLI 0.6.0 — 2026-10-21

### New
- `doorman status` on a terminal: a ● PROTECTED badge beside the mark with your level and agent dots, a severity bar, and a 14-day exposure sparkline.
- `doorman usage`: heat strips for time and tokens per day.
- `doorman trace`: a Route section (way in → agent → provider, files written, MCP servers).
- `doorman findings` and `doorman status` say "All clear" when nothing is open.
- `doorman policy level balanced` sets the Balanced level (`protective` still works).

### Changed
- The level once called "Protective" reads "balanced" in text output; `--json` keeps its id, `protective`.
- The new visuals appear on decorated terminals only: piped output, `NO_COLOR`, ASCII mode and `--json` are unchanged.

### Fixed
- `doorman watch` no longer redraws in place on a `TERM=dumb` terminal.

## App 0.6.0 — 2026-10-21

### New
- One-click triage on the Radar: Resolved, False positive or Accept risk, and Reopen to undo. The next exposure opens and stays in view.
- Protection switches and wallets moved from Settings to Guardrails, where each rule also shows its last 14 days of activity.
- The approval panel and overlay share one set of buttons: Esc denies, ⌘↩ (Ctrl+Enter) allows once, "stop holding" asks you to confirm, and rules are shown by name.
- Onboarding is three steps, including the notification permission.
- Deleting a rule, an exception or a saved set asks you to confirm.

### Changed
- One vocabulary everywhere: exposures (what you review), sightings (each time one was seen) and sessions; rule modes Observe / Warn / Ask / Block; outcomes Blocked, Denied, Allowed, Warned and Observed.
- Honest counts: Usage and the Ledger count open exposures, not raw detections, and a held call you allowed no longer counts as stopped. A hold you denied reads "held, then denied", not "Blocked".
- Severity follows where a secret went: high when a credential value reached the model, medium when a read was printed back to the agent or a value went to a host without passing through it, low when it stayed on this computer. Cards say which.
- Radar rows show the place, agent and outcome; rarely used filters moved under "More filters".

### Fixed
- Windows: a left-click on the tray icon opens the window, and a right-click shows the menu.
- Linux: the tray menu opens, and a click opens the window.
- Windows and Linux: Continue in Terminal and Open Notification settings work, macOS-only buttons and menu items are hidden, and the scrollbar at the window's edge takes clicks again.

## CLI 0.5.0 — 2026-10-21

### New
- `doorman sbx watch`: one terminal on the host answers held calls from every running Docker Sandbox, including ones that start later, with the same card and keys as `doorman watch`.
- `doorman sbx ls`: running sandboxes with their Doorman version, guard, who answers held calls, and open exposures.
- `doorman sbx pull`: brings a sandbox's findings home, masked again. Whoever owns the data takes them in, and pulling again keeps your triage.
- `doorman export bundle`, `doorman watch --stdio` (newline-delimited JSON, for sandbox hosts), and `--no-color` and `--quiet` on every command.
- The approval card wraps the whole preview, names the call after its risky part (`curl → webhook.site`), shows the agent's own description, and `[v]` shows a call that was cut short.

### Changed
- Tables never cut IDs or names: low-value columns go first, and narrow terminals print rows as records. Help wraps instead of truncating, and piped output is never cut.
- One vocabulary: exposures and sightings, guard on/off, hooks installed/missing; times are local.
- `--reveal` is now `--evidence`.
- In a sandbox, the guard tells the agent to run `sbx exec -it <name> doorman watch`, and `doorman status` and `doorman doctor` say who answers held calls.

### Fixed
- A `doorman watch` left behind by a closed `sbx exec -it` no longer holds calls forever: a new watch takes over after 10 idle minutes, or at once with `--replace`.
- `doorman doctor` no longer fails a fresh install over the VS Code companion, and its `--json` matches its text.
- A model download the sandbox policy blocks says so, with the command that allows it, instead of "downloading", and isn't retried in the background.

## Earlier releases

App 0.5.4 and CLI 0.4.1 and everything before them: see the release notes at
https://github.com/PinataCloud/doorman/releases and the git history.
