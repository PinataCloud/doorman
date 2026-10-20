# Doorman CLI

Doorman watches what your AI coding agents read and run, flags the secrets
they expose, and can hold a risky tool call until you answer. This is Doorman
from the terminal: the same detectors, guard and policy as the
[Doorman desktop app](https://github.com/PinataCloud/doorman), with nothing
sent anywhere.

```sh
npm install -g @pinata/doorman   # Node 22 or later
doorman status
```

## What it does

| Command | What it does |
| --- | --- |
| `doorman status` | Where Doorman keeps its data, what it guards, what needs review |
| `doorman scan` | Read new agent transcripts (Claude Code, Codex, Cursor, Copilot, Gemini and more) and report new findings |
| `doorman findings` | Open exposures, grouped like the app's Security Radar; `show`, `review`, `reopen`, `false-positive`, `accept-risk` |
| `doorman sessions`, `session <id>`, `search <query>` | The Event Ledger: sessions, turns and search, always masked |
| `doorman usage`, `doorman analytics` | Tokens and time spent with AI; what each rule found |
| `doorman report`, `doorman export detections\|ledger` | The security report (Markdown) and schema-valid JSON exports |
| `doorman trace` | Trace a secret: where a value went, read from stdin and never echoed |
| `doorman guard install\|uninstall\|status` | The PreToolUse hook that watches, holds or blocks each agent's tool calls |
| `doorman watch` | Answer held tool calls in this terminal while the desktop app is closed |
| `doorman policy`, `rules`, `packs`, `exceptions`, `custom-rules` | The policy the guard enforces, rule by rule |
| `doorman mcp`, `doorman gateway` | MCP servers on this machine, Doorman's own MCP server, and the MCP gateway |
| `doorman editor` | The VS Code companion |
| `doorman doctor` | Check the guard, MCP and editor wiring, and repair it |
| `doorman model` | The on-device injection classifier ([Llama-Doorman-22M](https://huggingface.co/PinataCloud/Llama-Doorman-22M)): status, download, check text |
| `doorman config` | Settings shared with the app (retention, confidence bands and more) |
| `doorman update` | Install a newer Doorman CLI with npm; `--check` only says whether one is out |

Every command takes `--json` for machine-readable output and `--help` for its
options.

## Shared with the desktop app

The CLI uses the desktop app's own data directory (macOS:
`~/Library/Application Support/Doorman`, Linux: `~/.config/Doorman`,
Windows: `%APPDATA%\Doorman`; `DOORMAN_APPDATA_DIR` overrides), so the CLI and
the app see one store, one policy and one guard.

Only one of them changes things at a time, and they can run side by side or
one after the other without stepping on each other:

- While the app (or `doorman watch`) is running, read commands work on a copy
  of the store, and commands that change the policy, hooks, settings or the
  classifier model ask you to make the change in the app or quit it first.
- When the app starts while a command is writing, it waits for that command,
  and a long scan stops at its next file and leaves the rest to the app.
  `doorman watch` hands over to a starting app by itself.
- Two `doorman` commands at once: the second reads a copy, or asks you to run
  its change again when the first one finishes.
- One classifier download at a time: whichever of the two starts second waits
  for the other's download and uses it.
- The app and the CLI update separately, so they may be different versions.
  Each keeps the classifier weights it pins in its own folder, neither replaces
  a newer version's guard with an older one or reports it as tampered, and
  neither drops settings the other added.

The app keeps the raw evidence behind each finding encrypted in the macOS
Keychain. The CLI doesn't open it, so `doorman findings show --reveal` reads
the masked evidence back from the transcripts instead.

## Docker Sandboxes

To run a coding agent in a [Docker Sandbox](https://docs.docker.com/ai/sandboxes/)
with Doorman guarding it, add the
[Doorman kit](https://github.com/PinataCloud/doorman/tree/main/integrations/sbx-kit)
(kits are experimental in `sbx`). It works with the `sbx` agents `claude`,
`codex`, `copilot`, `cursor`, `droid`, `gemini` and `opencode`. `sbx` only
accepts kits from sources you allow, so allow this one once (keep any sources
you already allow in the list), then start the agent (Claude Code here):

```sh
sbx settings set kit.allowedSources '["docker.io/","git+https://github.com/PinataCloud/doorman.git"]'
sbx run --name my-project claude ~/my-project --kit "git+https://github.com/PinataCloud/doorman.git#dir=integrations/sbx-kit"
```

The kit installs the CLI, runs `doorman guard install` and lets the sandbox
download the classifier from Hugging Face. By hand, for a sandbox named
`my-project`:

```sh
sbx create --name my-project claude ~/my-project
sbx exec my-project npm install -g @pinata/doorman
sbx exec my-project doorman guard install
sbx policy allow network --sandbox my-project "huggingface.co,**.hf.co"
```

The desktop app can't run inside a sandbox. Answer held calls from the host
with `sbx exec -it my-project doorman watch`. With nobody watching, Claude
Code, Copilot CLI, Cursor and Factory Droid ask in their own prompt; the
others deny the call.

## Updates

Like the app, the CLI looks for a newer version on its own: at most once a
day it asks the npm registry for the latest `@pinata/doorman`, and when one is
out it says so on stderr after the command's output. `doorman status` shows it
too. `doorman update` installs it with `npm install --global`; a copy run
through npx or installed in a project tells you the command to run there
instead.

The check never delays a command by more than a moment, and an offline machine
asks once a day. It is off under CI and when stderr is not a terminal, so
scripts never see the notice. Set `DOORMAN_NO_UPDATE_CHECK=1` (or
`NO_UPDATE_NOTIFIER=1`) to turn it off.

## Privacy

Doorman reads the agents' transcript files on this machine and stores what it
finds under its data directory. It has no account, no server and no telemetry.
It makes two requests on its own, and neither carries anything about you or
your machine: the daily update check above, and the injection-classifier
model, from Hugging Face with every file pinned by sha256. Like the app, the
CLI fetches the model on its own: the first command that finds it missing
starts the download in the background (about 96 MB) and carries on, and
`doorman model` shows its progress. Set `DOORMAN_INJECTION_CLASSIFIER=off` to
turn the classifier, and with it the download, off.

## License

Apache-2.0. The classifier model weights are licensed separately under the
Llama 4 Community License. Built with Llama. Built by [Pinata](https://pinata.cloud).
