# Doorman for VS Code

The editor half of the Doorman desktop app: today's
agent token usage and the Security Guard's state in the status bar, held tool calls
answered where your hands already are, and one honest report back to the app
about whether the guard can run in this window at all.

The app installs it for you — it is on by default, with the switch under
**Integrations → Doorman in VS Code** — rather than you installing it by hand:
the app ships the copy that matches its own file format and keeps it current.

## What it does

- **Status bar.** The Doorman mark with the number of open detections beside
  it — the same "things to decide" count the app's own badge carries. Hover for
  today's tokens, whether the Security Guard is armed and how many agents are
  running. Greyed out when the app isn't running, so a number is never stale
  without saying so; a warning background when the guard is off. **Click it**:
  if the guard is holding a call, you review it right here; otherwise the app
  comes to the front on its Security Radar (or the Overview when there is
  nothing to review).
- **Ask here.** When the guard holds an agent's tool call, the question appears
  in this window as well as in the app. Allow, Deny, or open the details —
  what the agent was about to do, which rules fired, in which directory. A
  second status-bar item stays lit with the count of held calls until each is
  decided, because a notification can be dismissed or missed while the guard
  waits; a critical hold asks modally.
- **Tells the app about this window.** Whether the window is trusted (VS Code
  runs no hooks in Restricted Mode — the guard included), its folders, and
  the values of `chat.useHooks`, `chat.hookFilesLocations` and
  `chat.mcp.access` that actually apply here after any enterprise policy.
  The app's setup check uses that instead of guessing from settings files.
- **Commands.** `Doorman: Show status`, `Doorman: Review held tool calls`,
  `Doorman: Open the app`.

## What it does not do

It opens no socket and makes no network request. Everything it shows is read
from the files the app writes in your own user directory. It writes two things
there: your answer to a held call — which the app then applies, so a decision
made here is recorded exactly like one made in the app — and the report about
this window described above, removed when the window closes.

It reads nothing from your workspace beyond the folder paths, which is why it
works in an untrusted window.

## Settings

| Setting | Default | |
| --- | --- | --- |
| `doorman.statusBar` | `true` | Show the status-bar item. |
| `doorman.askInEditor` | `true` | Ask here when the guard holds a call. |
| `doorman.userDataPath` | _(empty)_ | Where the app keeps its data. Empty means the platform's usual place: `~/Library/Application Support/Doorman` on macOS, `%APPDATA%\Doorman` on Windows, `~/.config/Doorman` on Linux. |

## A note on VS Code's own settings

The guard reaches VS Code's agent mode through the hooks VS Code loads from
`~/.copilot/hooks`. Two settings can switch that off without anything looking
broken — `chat.useHooks`, and the `~/.copilot/hooks` entry in
`chat.hookFilesLocations` — and VS Code skips every hook in a workspace opened
in Restricted Mode. The app's setup check reports all three, and with this
extension installed it reports them for the windows you actually have open.
