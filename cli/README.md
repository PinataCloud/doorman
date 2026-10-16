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

Every command takes `--json` for machine-readable output and `--help` for its
options.

## Shared with the desktop app

The CLI uses the desktop app's own data directory (macOS:
`~/Library/Application Support/Doorman`, Linux: `~/.config/Doorman`,
Windows: `%APPDATA%\Doorman`; `DOORMAN_APPDATA_DIR` overrides), so the CLI and
the app see one store, one policy and one guard.

Only one of them changes things at a time. While the app (or `doorman watch`)
is running, read commands work on a copy of the store, and commands that change
the policy, hooks or settings ask you to make the change in the app or quit it
first.

The app keeps the raw evidence behind each finding encrypted in the macOS
Keychain. The CLI doesn't open it, so `doorman findings show --reveal` reads
the masked evidence back from the transcripts instead.

## Privacy

Doorman reads the agents' transcript files on this machine and stores what it
finds under its data directory. It has no account, no server and no telemetry.
The only downloads are the injection-classifier model (`doorman model
download`, from Hugging Face, every file pinned by sha256) and nothing else.

## License

Apache-2.0. The classifier model weights are licensed separately under the
Llama 4 Community License. Built with Llama. Built by [Pinata](https://pinata.cloud).
