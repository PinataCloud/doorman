# Changelog

What changed for the people using Doorman, newest first. The desktop app and the
CLI (`@pinata/doorman` on npm) are released separately: each release is one
`## App <version> — <YYYY-MM-DD>` or `## CLI <version> — <YYYY-MM-DD>` section,
with `### New`, `### Changed` and `### Fixed` lists of one-line bullets.
`scripts/release-notes.mjs` and `doorman changelog` read these headings, and a
release without its section fails before it builds. Work not yet released sits
under `## Unreleased`; a release renames its part of it.

## Unreleased

### CLI
- New `doorman completion <zsh|bash|fish>`: Tab completion for every command, subcommand and flag, and exposure ids.
- New `doorman changelog [--since <version>] [--all]`, and `doorman update` shows what changed after installing.
- `doorman watch` shows the agents running on this machine now (held · working · waiting for you · quiet), on macOS and Linux.
- `doorman findings resolve` marks exposures resolved, as the app's button does; `review` still works.
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
