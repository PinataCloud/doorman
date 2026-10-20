# Doorman kit for Docker Sandboxes

A [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) mixin kit that
turns a `claude` sandbox into one guarded by Doorman. When the sandbox is
created it:

- allows the sandbox to reach `huggingface.co` and `**.hf.co`, so Doorman can
  download its on-device injection classifier (model files redirect to CDN
  hosts such as `us.aws.cdn.hf.co`, which `*.hf.co` does not cover). The rules
  belong to this sandbox only; your global `sbx` policy is left alone.
- installs the Doorman CLI as the sandbox user: `npm install -g @pinata/doorman`.
- runs `doorman guard install`, so Claude Code's hooks are in place before the
  agent starts.

The install runs once, at creation. A stopped and restarted sandbox keeps the
CLI and the hooks. The classifier (about 96 MB) downloads in the background on
first use; `sbx exec <name> doorman model` shows its progress.

Kits are experimental in `sbx` (tested with 0.46.0): the file format and the
`sbx kit` commands may change.

## One command

From a checkout of this repository, start Claude Code in a guarded sandbox on
your project:

```sh
sbx run claude ~/my-project --kit ./integrations/sbx-kit
```

`sbx` needs local kit paths to start with `./`, `../` or `/`. To create the
sandbox without attaching, then attach later:

```sh
sbx create --name my-project claude ~/my-project --kit ./integrations/sbx-kit
sbx run --name my-project
```

To add the kit to a `claude` sandbox you already have (`sbx` recreates its
container and keeps its workspace and agent history):

```sh
sbx kit add my-project ./integrations/sbx-kit
```

Without a checkout, reference the kit in this repository with `sbx`'s git
syntax, where `dir` is the kit's folder and `ref` (optional) a tag, branch or
commit. Quote it when it contains `&`:

```sh
sbx run claude ~/my-project --kit "git+https://github.com/PinataCloud/doorman.git#dir=integrations/sbx-kit"
sbx run claude ~/my-project --kit "git+https://github.com/PinataCloud/doorman.git#ref=main&dir=integrations/sbx-kit"
```

The git form is untested until this kit is merged into the repository.

Check the kit with `sbx kit validate ./integrations/sbx-kit`.

## Answering held calls

The desktop app can't run inside a sandbox. When the guard holds a call, answer
it from a second terminal on the host:

```sh
sbx exec -it my-project doorman watch
```

With nobody watching, the held call goes to Claude Code's own permission
prompt.

## Without the kit

The same setup by hand, for a sandbox named `my-project`:

```sh
sbx create --name my-project claude ~/my-project
sbx exec my-project npm install -g @pinata/doorman
sbx exec my-project doorman guard install
sbx policy allow network --sandbox my-project "huggingface.co,**.hf.co"
```

Then `sbx run --name my-project` starts Claude Code.
