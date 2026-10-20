# Doorman kit for Docker Sandboxes

A [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) mixin kit that
puts Doorman's guard in front of the coding agent a sandbox runs. When the
sandbox is created it:

- allows the sandbox to reach `huggingface.co` and `**.hf.co`, so Doorman can
  download its on-device injection classifier (model files redirect to CDN
  hosts such as `us.aws.cdn.hf.co`, which `*.hf.co` does not cover). The rules
  belong to this sandbox only; your global `sbx` policy is left alone.
- installs the Doorman CLI as the sandbox user: `npm install -g @pinata/doorman`.
- runs `doorman guard install`, which finds the sandbox's agent and adds its
  hook before the agent starts.

The install runs once, at creation. A stopped and restarted sandbox keeps the
CLI and the hooks. The classifier (about 96 MB) downloads in the background on
first use; `sbx exec <name> doorman model` shows its progress.

Kits are experimental in `sbx` (tested with 0.46.0): the file format and the
`sbx kit` commands may change.

## Agents

One kit for every agent below. Put the `sbx` agent name in the command.

| Agent         | `sbx` agent | Hook file                                |
| ------------- | ----------- | ---------------------------------------- |
| Claude Code   | `claude`    | `~/.claude/settings.json`                |
| Codex         | `codex`     | `~/.codex/hooks.json`                    |
| Copilot CLI   | `copilot`   | `~/.copilot/hooks/doorman.json`          |
| Cursor        | `cursor`    | `~/.cursor/hooks.json`                   |
| Factory Droid | `droid`     | `~/.factory/settings.json`               |
| Gemini CLI    | `gemini`    | `~/.gemini/settings.json`                |
| OpenCode      | `opencode`  | `~/.config/opencode/doorman-guard.json`, read by the plugin `~/.config/opencode/plugins/doorman-guard.js` |

From a checkout of this repository, start an agent in a guarded sandbox on
your project:

```sh
sbx run --name my-project claude ~/my-project --kit ./integrations/sbx-kit
sbx run --name my-project codex ~/my-project --kit ./integrations/sbx-kit
sbx run --name my-project copilot ~/my-project --kit ./integrations/sbx-kit
sbx run --name my-project cursor ~/my-project --kit ./integrations/sbx-kit
sbx run --name my-project droid ~/my-project --kit ./integrations/sbx-kit
sbx run --name my-project gemini ~/my-project --kit ./integrations/sbx-kit
sbx run --name my-project opencode ~/my-project --kit ./integrations/sbx-kit
```

`sbx exec my-project doorman guard status` shows the agent and its hook as
installed.

**Kiro CLI** (`kiro`): the kit installs the hook in `~/.kiro/hooks/doorman.json`,
but Kiro only runs it with its V3 engine (`kiro-cli --v3`, or
`kiro-cli settings chat.agentEngine v3`), which becomes the default in
kiro-cli 3.0. The `kiro` sandbox ships kiro-cli 2.32, whose default engine
skips the hook. The kit leaves Kiro's engine setting alone.

## More ways to start

`sbx` needs local kit paths to start with `./`, `../` or `/`. To create the
sandbox without attaching, then attach later:

```sh
sbx create --name my-project claude ~/my-project --kit ./integrations/sbx-kit
sbx run --name my-project
```

To add the kit to a sandbox you already have (`sbx` recreates its container and
keeps its workspace and agent history):

```sh
sbx kit add my-project ./integrations/sbx-kit
```

Without a checkout, reference the kit in this repository with `sbx`'s git
syntax, where `dir` is the kit's folder and `ref` (optional) a tag, branch or
commit. Quote it when it contains `&`. `sbx` only accepts kits from sources
you allow, so allow this one once (keep any sources you already allow in the
list):

```sh
sbx settings set kit.allowedSources '["docker.io/","git+https://github.com/PinataCloud/doorman.git"]'
sbx run --name my-project claude ~/my-project --kit "git+https://github.com/PinataCloud/doorman.git#dir=integrations/sbx-kit"
sbx run --name my-project claude ~/my-project --kit "git+https://github.com/PinataCloud/doorman.git#ref=main&dir=integrations/sbx-kit"
```

The git form is untested until this kit is merged into the repository.

Check the kit with `sbx kit validate ./integrations/sbx-kit`.

## Answering held calls

The desktop app can't run inside a sandbox. When the guard holds a call, answer
it from a second terminal on the host:

```sh
sbx exec -it my-project doorman watch
```

With nobody watching, Claude Code, Copilot CLI, Cursor and Factory Droid ask in
their own prompt; Codex, Gemini CLI and OpenCode deny the call.

## Without the kit

The same setup by hand, for a sandbox named `my-project` (any agent above in
place of `claude`):

```sh
sbx create --name my-project claude ~/my-project
sbx exec my-project npm install -g @pinata/doorman
sbx exec my-project doorman guard install
sbx policy allow network --sandbox my-project "huggingface.co,**.hf.co"
```

Then `sbx run --name my-project` starts the agent.
