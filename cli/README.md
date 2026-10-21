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
| `doorman status` | The dashboard: guard, agents, model, what needs review, and the next thing to do |
| `doorman scan` | Read new agent transcripts (Claude Code, Codex, Cursor, Copilot, Gemini and more) and report new findings |
| `doorman findings` | Open exposures, grouped like the app's Security Radar; `show`, `resolve`, `reopen`, `false-positive`, `accept-risk` (`review` still works for `resolve`) |
| `doorman sessions`, `session <id>`, `search <query>` | The Event Ledger: sessions, turns and search, always masked |
| `doorman usage`, `doorman analytics` | Tokens and time spent with AI; what each rule found |
| `doorman report`, `doorman export detections\|ledger\|bundle` | The security report (Markdown) and schema-valid JSON exports (`bundle`: both, for `doorman sbx pull`) |
| `doorman trace` | Trace a secret: where a value went, read from stdin and never echoed |
| `doorman guard install\|uninstall\|status` | The PreToolUse hook that watches, holds or blocks each agent's tool calls |
| `doorman watch` | Answer held tool calls in this terminal while the desktop app is closed; on macOS and Linux its bottom line counts the agents running now (held · working · waiting for you · quiet) |
| `doorman sbx ls\|watch\|pull` | From your computer, Docker Sandboxes running Doorman: list them, answer all their held calls in one terminal, bring their findings here |
| `doorman policy`, `rules`, `packs`, `exceptions`, `custom-rules` | The policy the guard enforces, rule by rule |
| `doorman mcp`, `doorman gateway` | MCP servers on this machine, Doorman's own MCP server, and the MCP gateway |
| `doorman editor` | The VS Code companion |
| `doorman doctor` | Check the guard, MCP and editor wiring, and repair it |
| `doorman model` | The on-device injection classifier ([Llama-Doorman-22M](https://huggingface.co/PinataCloud/Llama-Doorman-22M)): status, download, check text |
| `doorman config` | Settings shared with the app (retention, confidence bands and more) |
| `doorman update` | Install a newer Doorman CLI with npm and show what changed; `--check` only says whether one is out |
| `doorman changelog` | What changed in each CLI release; `--since <version>` or `--all` |
| `doorman completion <zsh\|bash\|fish>` | Print a Tab-completion script: commands, subcommands, flags and exposure ids |

Every command takes `--json` for machine-readable output and `--help` for its
usage, options and examples. `doorman help` lists every command by group.

Tab completion: `doorman completion zsh > "${fpath[1]}/_doorman"`,
`source <(doorman completion bash)` in `~/.bashrc` (macOS's bash 3.2:
`eval "$(doorman completion bash)"`), or
`doorman completion fish > ~/.config/fish/completions/doorman.fish`.
`doorman completion --help` has the details.

### In the terminal

On a terminal, output has colour, status marks (✓ ! ✗) and, on `doorman`,
`doorman status` and `doorman watch`, the Doorman llama in ASCII. `doorman
status` adds a protection badge, a severity bar and a 14-day exposure
sparkline; `doorman usage` adds a heat strip per day; `doorman trace` draws
where the value went; and `doorman findings` says "All clear" when nothing is
open. Tables and long lines fit the terminal's width, and long work (a scan,
the model download) shows its progress on one line that redraws in place.

Everything else gets plain text with the same words and columns, nothing that
breaks `grep` or `awk`:

- Piped or redirected output, `NO_COLOR=1` and `TERM=dumb` are plain: no colour,
  no marks, no art. Progress prints a line now and then instead of redrawing.
- `--json` is only the JSON, on a terminal or not.
- Output is pure ASCII (marks `+ ! x`, `|` for `·`, `-` for dashes, `...`)
  with `DOORMAN_ASCII=1`, and on a terminal that may not show Unicode: the
  Linux console, a locale that isn't UTF-8, and Windows outside Windows
  Terminal, VS Code, ConEmu or mintty (the old `cmd` and PowerShell 5.1
  console). `DOORMAN_ASCII=0` turns Unicode back on. `--json` and the JSON
  exports stay as they are. The art is ASCII always.
- Long paths and URLs wrap only after a `/` or `\`.

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

The app keeps the raw evidence behind each sighting encrypted in the macOS
Keychain. The CLI doesn't open it, so `doorman findings show --evidence` reads
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

The kit installs the CLI (`--kit-arg doorman.version=<version>` pins it), runs
`doorman guard install`, puts the hook back at every start and lets the
sandbox download the classifier from Hugging Face. For a sandbox you already
have, add it with `sbx kit add my-project <kit>`. Don't install the CLI in a
sandbox by hand: `sbx kit add` and sandboxes created from templates reset the
agent's configuration, and a hand-installed hook is gone without a word. For
v3 workloads (`sbx run docker.io/docker/sbx-kit-claude:…`) use the v3 kit,
`#dir=integrations/sbx-kit/v3/doorman`, when you create the sandbox: a v3
sandbox takes no `sbx kit add`.

The desktop app can't run inside a sandbox, so the CLI on your computer works
with the sandboxes through `sbx`:

| Command (on your computer) | What it does |
| --- | --- |
| `doorman sbx ls` | Your sandboxes, and in each running one: Doorman's version (or not installed), guard on or off, who answers held calls, open exposures |
| `doorman sbx watch [--all \| <name>...] [--replace]` | Answer held calls from every sandbox in one terminal, each card headed with its sandbox's name; with no name (or `--all`), every running sandbox and each one that starts later |
| `doorman sbx pull [--all \| <name>...] [--remove-after] [--yes]` | Bring sandboxes' sightings and sessions to this computer's Doorman, where they read as "sandbox <name>"; `--remove-after` then removes each one (`sbx rm`), after asking |

`doorman sbx watch` runs `doorman watch --stdio` in each sandbox over
`sbx exec -i` (no terminal inside: when the host side goes, so does each
watch). A sandbox without Doorman, or with one too old for it, is named once
with what to do; so is one where a `doorman watch` already answers, unless
`--replace`. Without the CLI on your computer, answer one
sandbox with `sbx exec -it my-project doorman watch`. `sbx` agents run
without their own permission prompts, so allowing a call there runs it at
once. With nobody watching, Claude Code, Copilot CLI, Cursor and Factory Droid
ask in their own prompt; the others deny the call. Closing the host terminal
of an `sbx exec -it` watch doesn't stop it inside the sandbox: a new one takes
over once the old one has seen no key for 10 minutes, or at once with
`doorman watch --replace`. A watch stops by itself when a held call runs out
and no key was pressed since that call arrived nor for at least 60 seconds, so
the agents go back to their own prompt.

A download the sandbox's network policy blocks shows in `doorman model` and
`doorman status` as blocked, with the `sbx policy allow network` command to run
on your computer (approving the request in `sbx` lets only `huggingface.co`
through, not the CDN). Then run `doorman model download` in the sandbox.

Doorman's data stays inside the sandbox, and `sbx rm` deletes it.
`doorman sbx pull` runs `doorman export bundle --scan` in each sandbox and
drops the result in the `imports` folder of this computer's Doorman data;
whoever owns the data takes it in (the command itself, else the desktop app
at once, or the next `doorman` command once the app quits). Pulling again
adds only what is new. Without the CLI on your computer, export with
`sbx exec my-project doorman export detections --scan > detections.json` (or
`doorman report`). The kit's README has an `sbxenv.yaml` that pulls on
`sbx env rm`. Only local sandboxes are supported: the `doorman sbx` commands
don't see cloud sandboxes (`sbx --cloud`), and answering their held calls with
`sbx --cloud exec -it <name> doorman watch` is untested.

## Updates

Like the app, the CLI looks for a newer version on its own: at most once a
day it asks the npm registry for the latest `@pinata/doorman`, and when one is
out it says so on stderr after the command's output. `doorman status` shows it
too. `doorman update` installs it with `npm install --global`, then shows what
changed since your version (`doorman changelog` prints it any time); a copy run
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
CLI fetches the model on its own: the first command run in a terminal that
finds it missing starts the download in the background (about 96 MB) and
carries on, and `doorman model` shows its progress. Commands under CI or with
stderr redirected don't start it; `doorman model download` fetches it on
demand. Until it lands, injection findings come from the rules alone. If the
download fails, it retries on its own (not when a Docker Sandbox's network
policy blocked it: that waits for `doorman model download`) and the next
command run in a terminal says so once, with the reason. Set
`DOORMAN_INJECTION_CLASSIFIER=off` to turn the classifier, and with it the
download, off.

## License

Apache-2.0. The classifier model weights are licensed separately under the
Llama 4 Community License. Built with Llama. Built by [Pinata](https://pinata.cloud).
