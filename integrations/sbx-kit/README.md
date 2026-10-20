# Doorman kit for Docker Sandboxes

A [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) mixin kit that
puts Doorman's guard in front of the coding agent a sandbox runs. The kit is
the way to set Doorman up in a sandbox. When the sandbox is created it:

- allows the sandbox to reach `huggingface.co` and `**.hf.co`, so Doorman can
  download its on-device injection classifier (model files redirect to CDN
  hosts such as `us.aws.cdn.hf.co`, which `*.hf.co` does not cover). The rules
  belong to this sandbox only; your global `sbx` policy is left alone.
- installs the Doorman CLI as the sandbox user:
  `npm install -g @pinata/doorman@<version>` (the latest release unless you
  pin one, below).
- runs `doorman guard install`, which finds the sandbox's agent and adds its
  hook before the agent starts.

Then, at every start of the sandbox, it:

- puts the guard's hook back if it's gone (`doorman doctor --repair auto`).
  `sbx` manages the agent's settings file and can rewrite it, which drops the
  hook. A guard you turned off with `doorman guard uninstall` stays off.
- downloads the classifier (about 96 MB) in the background if it's missing.
  `sbx exec <name> doorman model` shows its progress.

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

To add the kit to a sandbox you already have:

```sh
sbx kit add my-project ./integrations/sbx-kit
```

`sbx kit add` recreates the sandbox. It keeps the workspace, packages and agent
history, but it writes the agent's configuration again. The same goes for a
sandbox created from a saved template (`sbx template save`), which doesn't keep
agent configuration. A hook you added by hand is gone after either one. With
the kit, its install commands run again on `sbx kit add` and its startup
commands put the hook back at every start. So use the kit rather than
installing Doorman by hand, and give `--kit` again when you create a sandbox
from a template.

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

To pin the CLI version the kit installs, pass the kit's `version` argument
(default `latest`):

```sh
sbx run --name my-project claude ~/my-project --kit ./integrations/sbx-kit --kit-arg doorman.version=0.4.1
```

Check the kit with `sbx kit validate ./integrations/sbx-kit`.

## Answering held calls

The desktop app can't run inside a sandbox, and the app on your computer can't
see the sandbox's data. When the guard holds a call, answer it from a second
terminal on the host:

```sh
sbx exec -it my-project doorman watch
```

Every `sbx` agent runs with its own permission prompts turned off, so allowing
a call in `doorman watch` runs it at once. With nobody watching, Claude Code,
Copilot CLI, Cursor and Factory Droid ask in their own prompt; Codex, Gemini
CLI and OpenCode deny the call. What the guard tells the agent names the same
`sbx exec` commands.

Closing the host terminal doesn't stop `doorman watch` inside the sandbox
(`sbx exec -it` sends it no hangup). Starting it again takes over on its own
once the old one's terminal has seen no key for 10 minutes. Before that it
refuses and prints `sbx exec -it my-project doorman watch --replace`, which
takes over at once. A watch stops by itself ("Nobody answered…") when a held
call runs out and no key was pressed since that call arrived nor for at least
60 seconds, so the agents go back to their own prompt instead of waiting on a
terminal nobody reads. Someone at the keyboard who lets a call time out keeps
their watch.

Only local sandboxes are supported. A cloud sandbox (`sbx --cloud`) has its
own network policy, separate from the local one: the kit's rule and the
`sbx policy allow network` command Doorman suggests apply to local sandboxes.
Doorman's messages also name the local `sbx exec` commands. Held calls in a
cloud sandbox are untested.

## The classifier download

If the sandbox's network policy blocks the download, `doorman model` and
`doorman status` say so and print the command to run on your computer:

```sh
sbx policy allow network --sandbox my-project "huggingface.co,**.hf.co"
```

Then run `sbx exec my-project doorman model download`. Doorman doesn't retry a
blocked download in the background, since nothing changes until you allow the
hosts. `sbx` also lists the blocked request as a pending approval. Approving it
allows only `huggingface.co`, not the CDN the model files come from, so use the
`sbx policy allow network` command.

## Keep the findings before removing a sandbox

Doorman's data lives inside the sandbox (`~/.config/Doorman`), not in your
workspace, and `sbx rm` deletes it. Export what Doorman found first:

```sh
sbx exec my-project doorman export detections --scan > my-project-detections.json
sbx exec my-project doorman report --scan > my-project-report.md
```

`doorman findings` lists the open exposures. `doorman export ledger` exports
the sessions.

With an [environment file](https://docs.docker.com/ai/sandboxes/configuration/environment-files/),
a host `preRemove` command can export the findings for you whenever the
sandbox is removed with `sbx env rm`. Plain `sbx rm` doesn't run lifecycle
commands. Put this `sbxenv.yaml` beside your project, outside the folders the
sandbox mounts:

```yaml
schemaVersion: "1"
name: my-project
agent: claude
workspace: ./my-project

kits:
  - source: git+https://github.com/PinataCloud/doorman.git#dir=integrations/sbx-kit
    args:
      version: latest

lifecycle:
  preRemove:
    - name: Export Doorman's findings
      command: mkdir -p doorman-exports && sbx exec "$SBX_SANDBOX_NAME" doorman export detections --scan > "doorman-exports/$SBX_SANDBOX_NAME-$(date +%Y%m%d-%H%M%S).json"
```

`sbx env run` starts it. `sbx env rm` writes
`doorman-exports/my-project-<time>.json` next to the file, then removes the
sandbox.
