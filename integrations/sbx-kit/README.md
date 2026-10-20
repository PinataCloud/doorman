# Doorman kit for Docker Sandboxes

A [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) mixin kit that
puts Doorman's guard in front of the coding agent a sandbox runs. The kit is
the way to set Doorman up in a sandbox. When the sandbox is created it:

- allows the sandbox to reach `huggingface.co` and `**.hf.co`, so Doorman can
  download its on-device injection classifier (model files redirect to CDN
  hosts such as `us.aws.cdn.hf.co`, which `*.hf.co` does not cover). The rules
  belong to this sandbox only; your global `sbx` policy is left alone.
- installs the Doorman CLI: `npm install -g @pinata/doorman@<version>` (the
  latest release unless you pin one, below).
- runs `doorman guard install`, which finds the sandbox's agent and adds its
  hook before the agent starts.

Then, at every start of the sandbox, it:

- puts the guard's hook back if it's gone (`doorman doctor --repair auto`).
  `sbx` manages the agent's settings file and can rewrite it, which drops the
  hook. A guard you turned off with `doorman guard uninstall` stays off.
- downloads the classifier (about 96 MB) in the background if it's missing.
  `sbx exec <name> doorman model` shows its progress.

The kit comes in both of `sbx`'s kit formats, with the same behaviour:

| Format | Folder | For sandboxes started with |
| --- | --- | --- |
| v2 | [`integrations/sbx-kit`](spec.yaml) | a built-in agent name: `sbx run claude …` |
| v3 | [`integrations/sbx-kit/v3/doorman`](v3/doorman/doorman.yaml) | a v3 workload: `sbx run docker.io/docker/sbx-kit-claude:… …` (sbx 0.45 or later) |

A sandbox takes kits of one format only, and the built-in agent names select
v2 ([Version compatibility](https://docs.docker.com/ai/sandboxes/customize/#version-compatibility)),
so use the v2 kit unless you run a v3 workload. Kits are experimental in `sbx`
(tested with 0.46.0): the file format and the `sbx kit` commands may change.

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

## v3 sandboxes

The v3 kit is for sandboxes that run a
[v3 workload](https://docs.docker.com/ai/sandboxes/customize/use-kits/#published-v3-workloads)
such as `docker.io/docker/sbx-kit-claude` (the agent `sbx ls` shows is then
`sbx-kit-claude`). Give the workload's image in place of the agent name:

```sh
sbx run --name my-project docker.io/docker/sbx-kit-claude:2.1.267 ~/my-project --kit ./integrations/sbx-kit/v3/doorman
sbx run --name my-project docker.io/docker/sbx-kit-codex:0.155.1 ~/my-project \
  --kit "git+https://github.com/PinataCloud/doorman.git#dir=integrations/sbx-kit/v3/doorman"
```

Pin the CLI with `--kit-arg doorman.version=0.4.1`, as with the v2 kit (the
prefix is the kit's folder name). The v3 kit installs the CLI as root into
`/usr/local` when the sandbox is created and takes `registry.npmjs.org` for
that step only; the CLI needs the Node.js 22 or later that Docker's workloads
ship.

What differs from v2, per the
[v3 docs](https://docs.docker.com/ai/sandboxes/customize/use-kits/#change-a-sandboxs-mixins):

- `sbx kit add` can't add a mixin to a v3 sandbox. Create the sandbox with
  `--kit`, or create a new one; the new sandbox doesn't keep the old one's
  Doorman data, so [pull it first](#keep-the-findings-before-removing-a-sandbox).
- `sbx kit validate` in sbx 0.46 refuses a v3 kit folder ("no kit builder
  configured"). `sbx kit inspect ./integrations/sbx-kit/v3/doorman` builds and
  shows it instead.
- The kit is declaration-only: no Dockerfile, nothing in its image but the
  descriptor. A version baked into the image would be stuck at whatever
  `latest` meant at the first build (the build is cached), and sbx 0.46 can't
  set a build-time argument on a folder or git kit.

## Published kits

Each kit release is on Docker Hub, which `sbx` accepts by default
(`kit.allowedSources` starts as `["docker.io/"]`):

```sh
# v2, with a built-in agent
sbx run --name my-project claude ~/my-project --kit docker.io/pinata/doorman-kit:<version>
# v3, with a v3 workload
sbx run --name my-project docker.io/docker/sbx-kit-claude:2.1.267 ~/my-project --kit docker.io/pinata/doorman-kit:<version>-v3
```

A published kit still installs the latest CLI unless you pin one; its handle
is the repository's last part, so the argument is
`--kit-arg doorman-kit.version=0.4.1`. Both are signed in GitHub Actions
(Sigstore, keyless). To check a signature:

```sh
sbx kit verify docker.io/pinata/doorman-kit:<version> \
  --certificate-identity "https://github.com/PinataCloud/doorman/.github/workflows/sbx-kit.yml@refs/tags/kit-v<version>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Answering held calls

The desktop app can't run inside a sandbox, and the app on your computer can't
see the sandbox's data. When the guard holds a call, answer it from a terminal
on your computer. With the Doorman CLI installed there
(`npm install -g @pinata/doorman`), one terminal answers every sandbox:

```sh
doorman sbx watch --all
```

It runs `doorman watch --stdio` in each running sandbox (`sbx exec -i`), picks
up sandboxes started later, and shows their held calls in one queue, oldest
first, each card headed with its sandbox's name. The keys are
`doorman watch`'s: `d` deny, `a` allow once, `p` allow and don't hold it in
this project for 30 days, `s` allow and stop asking (both apply in that
sandbox). `--all` is the default; name sandboxes to watch only those:
`doorman sbx watch my-project`. A sandbox without Doorman, or with a Doorman
too old for it, is named once with what to do, and the others carry on; so is
one where a `doorman watch` already answers, unless you add `--replace`.
Ctrl-C, or closing the terminal, ends the watch in every sandbox at once. It
needs a terminal, and sees local sandboxes only.

Without the CLI on your computer, answer one sandbox with `sbx` alone:

```sh
sbx exec -it my-project doorman watch
```

Every `sbx` agent runs with its own permission prompts turned off, so allowing
a call in `doorman watch` runs it at once. With nobody watching, Claude Code,
Copilot CLI, Cursor and Factory Droid ask in their own prompt; Codex, Gemini
CLI and OpenCode deny the call. What the guard tells the agent names the
`sbx exec` commands.

Closing the host terminal doesn't stop an `sbx exec -it … doorman watch`
inside the sandbox (`sbx exec -it` sends it no hangup). Starting it again
takes over on its own once the old one's terminal has seen no key for 10
minutes. Before that it refuses and prints
`sbx exec -it my-project doorman watch --replace`, which takes over at once.
A watch, `doorman sbx watch` included, stops by itself ("Nobody answered…")
when a held call runs out and no key was pressed since that call arrived nor
for at least 60 seconds, so the agents go back to their own prompt instead of
waiting on a terminal nobody reads. Someone at the keyboard who lets a call
time out keeps their watch.

`doorman sbx ls` lists your sandboxes and asks each running one's Doorman
(`doorman status --json`, all at once) for its version, whether the guard is
on, who answers held calls (nobody, the app, `doorman watch` or
`doorman sbx watch`) and how many exposures are open. A stopped sandbox isn't
asked, since `sbx exec` would start it.

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
workspace, and `sbx rm` deletes it. Bring it to the Doorman on your computer
first:

```sh
doorman sbx pull my-project
doorman sbx pull --all                       # every running sandbox
doorman sbx pull my-project --remove-after   # then `sbx rm` it, after asking
```

`doorman sbx pull` runs `doorman export bundle --scan` in each sandbox and
drops the result in the `imports` folder of your Doorman data. Whoever owns
the data takes it in: the command itself when nothing else runs, else the
desktop app (at once) or the next `doorman` command once the app quits. The
sightings and sessions then show in the app, `doorman findings` and
`doorman sessions` as "sandbox my-project". Pulling again adds only what is
new, and every value stays masked. `--remove-after` removes a sandbox only once
its bundle is written; it asks first, and `--yes` skips the question.

Without the CLI on your computer, export with `sbx` alone:

```sh
sbx exec my-project doorman export detections --scan > my-project-detections.json
sbx exec my-project doorman report --scan > my-project-report.md
```

With an [environment file](https://docs.docker.com/ai/sandboxes/configuration/environment-files/),
a host `preRemove` command can pull the findings for you whenever the sandbox
is removed with `sbx env rm`. Plain `sbx rm` doesn't run lifecycle commands.
Put this `sbxenv.yaml` beside your project:

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
    - name: Bring Doorman's findings to this computer
      command: doorman sbx pull "$SBX_SANDBOX_NAME"
```

`sbx env run` starts it. `sbx env rm` pulls the sandbox's findings into your
Doorman, then removes the sandbox.

## Cloud sandboxes

Doorman is tested in local sandboxes only. From the
[cloud docs](https://docs.docker.com/ai/sandboxes/cloud/local-vs-cloud/), for
a cloud sandbox (`sbx --cloud`):

- The kit can be added when the sandbox is created
  (`sbx --cloud create … --kit …`): its lifecycle commands are supported there,
  and its network rules partly ([capability support](https://docs.docker.com/ai/sandboxes/customize/author/capabilities/)).
  Cloud network policy is separate from your local one, so the
  `sbx policy allow network` command Doorman suggests doesn't apply; use the
  cloud policy commands.
- `doorman sbx watch`, `doorman sbx ls` and `doorman sbx pull` see local
  sandboxes only (`sbx ls` lists no cloud ones). Held calls in a cloud sandbox
  can only be answered with `sbx --cloud exec -it <name> doorman watch`, which
  is untested, and the guard's own messages name the local `sbx exec` command.
- Doorman's data stays in the cloud sandbox and goes when it does, including
  when its time-to-live runs out. `sbx --cloud exec <name> doorman export
  detections --scan > detections.json` exports it.

## Publishing the kit

Maintainers: the [`sbx-kit` workflow](../../.github/workflows/sbx-kit.yml)
publishes both kits when a `kit-v<x.y.z>` tag is pushed
(`git tag kit-v1.0.0 && git push origin kit-v1.0.0`), or from Run workflow for
an existing tag. It needs the secrets `DOCKERHUB_USERNAME` and
`DOCKERHUB_TOKEN` (a Docker Hub access token with write access to
`pinata/doorman-kit`). It installs `sbx` from Docker's apt repository, signs in
(`sbx login --password-stdin`; the kit commands refuse to run signed out), then:

1. validates the v2 kit (`sbx kit validate`) and builds the v3 kit with Buildx
   (the `docker/sandbox-kit:3` frontend validates its descriptor);
2. pushes the v2 kit with `sbx kit push --sign` to
   `docker.io/pinata/doorman-kit:<x.y.z>` (v1/v2 kits are OCI artifacts that
   only `sbx kit push` makes);
3. builds and pushes the v3 kit with
   `docker buildx build -f doorman.yaml --push` to
   `docker.io/pinata/doorman-kit:<x.y.z>-v3`, and signs it with `sbx kit sign`
   ([v3 kits are images built with Buildx](https://docs.docker.com/ai/sandboxes/customize/author/distribute/));
4. reads both back with `sbx kit inspect`.

A tag already on Docker Hub is left as it is. The kits install the CLI from
npm at sandbox creation, so a kit release is needed only when the kit changes,
not for each CLI release.

The same by hand, signed in to Docker Hub with push rights on the repository
(`sbx login`, `docker login`):

```sh
version=1.0.0
stage=$(mktemp -d) && cp integrations/sbx-kit/spec.yaml "$stage/"
sbx kit validate "$stage"
sbx kit push --sign "$stage" "docker.io/pinata/doorman-kit:$version"
docker buildx build integrations/sbx-kit/v3/doorman -f integrations/sbx-kit/v3/doorman/doorman.yaml \
  --platform linux/amd64,linux/arm64 --push -t "docker.io/pinata/doorman-kit:$version-v3"
sbx kit sign "docker.io/pinata/doorman-kit:$version-v3"
```

The v2 kit is pushed from a folder holding only `spec.yaml`: `sbx kit push`
packs the whole folder, which here also holds this README and the v3 kit.
Signing by hand opens a browser to sign in to Sigstore.
