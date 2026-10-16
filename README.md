# Doorman

A local-first desktop app that watches the AI coding agents on this machine:
what they spend in tokens, what they touch, and what they try to send. It runs
on macOS (the primary target), with Linux (AppImage) and Windows (NSIS) builds
from the same source.

**Everything stays on the machine.** Doorman reads the agents' own transcript
files from disk and keeps its store under its own data directory. It has no
account, no server and no telemetry. The one thing it downloads is described
under [Network](#network).

## What it does

- **Usage graphs**: the last 7 or 30 days of input and output tokens per
  model, measured from the transcripts. Figures are token counts, never
  dollars: the vendored pricing table (`main/lib/pricing.ts`) still prices
  each turn internally, but an on-device estimate can't know how a turn was
  actually paid for.
- **Event Ledger**: sessions and their turns, with local full-text search,
  deterministic titles (the agent's own title, else the first prompt), and the
  subscription-vs-overage split where the agent records it (Codex plan
  windows).
- **Security Radar**: deterministic detectors (`main/guard/security-detect.ts`,
  with redaction first) run over every prompt, tool call and tool output,
  backfill included. Findings carry masked excerpts only and are grouped into
  *exposures*: one rule in one place (`main/lib/exposures.ts`). The Radar
  also has a **Trace a secret** view (`renderer/screens/radar-trace.jsx`).
- **Analytics and Rules**: per-rule counters over a chosen window, the
  detector catalog, rule packs, your own rules (with a dry-run editor) and the
  exceptions list. The families shown are narrowed by
  `main/guard/rule-scope.ts`.
- **The guard**: a PreToolUse hook that can watch, ask (hold the call until you
  answer in the app, a floating panel, a notification or VS Code), or block.
  Adapters live in `main/guard/hosts/`: Claude Code, Codex, Cursor, Gemini CLI,
  Copilot CLI, VS Code + Copilot, OpenCode, OpenClaw, Hermes Agent, Goose,
  Crush, Factory Droid, Kiro CLI, Kimi Code, Qwen Code and Grok Build.
- **MCP inventory and gateway**: the MCP servers configured on the machine,
  tool-poisoning findings, a personal "recognized" list, and an optional
  stdio gateway that scans live tool descriptions (`main/gateway/`).
- **Doorman's own MCP server** (`main/mcp/doorman-mcp.ts`): lets an agent ask
  the guard before acting, using four tools: `doorman_check_tool_call`,
  `doorman_explain_last_block`, `doorman_session_spend` and `doorman_status`.
  All four are answered from disk, so they work with the app closed.
- **VS Code companion** (`vscode-extension/`): shows today's token usage and
  the guard's state in the status bar, and lets you answer held calls in the
  editor. It is packaged into a `.vsix` at build time and installed through the
  editor's own `code` CLI.
- **"How to fix this?"**: beside a finding, this builds a prompt from the
  masked evidence (`main/ai-assistant.ts`) for you to copy into your own coding
  agent. The app sends nothing itself.
- **Setup health** (`main/lib/doctor.ts`): checks that the guard's hook entries,
  plugin files and bundle are in place, and that VS Code's settings let it run.
  It applies lossless repairs automatically and offers anything lossy as a
  click.

## Network

- **Injection-classifier model** (optional, on by default). When the
  classifier is on, the app downloads the model it needs into
  `<userData>/models/`, every file pinned by exact size and sha256
  (`main/lib/model-assets.ts`) and written only after it verifies. Two models
  can be selected in Settings → AI-delivered protection:
  - **Doorman (fine-tuned, recommended)**, the default: Llama Prompt Guard 2
    22M fine-tuned for tool output (int8 ONNX, about 96 MB with its
    tokenizer). It downloads from `DOORMAN_MODEL_BASE_URL` in
    `main/lib/model-sources.ts`, a pinned-revision Hugging Face URL that is
    **empty until the model is published**, or from
    `DOORMAN_INJECTION_CLASSIFIER_SOURCE` when that is set.
  - **Prompt Guard 2 (stock)**: Llama Prompt Guard 2 22M (ONNX, about 82 MB)
    from Hugging Face (`gravitee-io/Llama-Prompt-Guard-2-22M-onnx`, pinned to
    one commit).

  While the fine-tuned model has no download location, or its download or
  verification fails, the app downloads and runs the **stock** model in its
  place (never no model) and says so in Settings; it switches to the
  fine-tuned model by itself once that installs. So today the one download
  is the stock model from Hugging Face; once `DOORMAN_MODEL_BASE_URL` is set,
  the default download becomes the fine-tuned model from that URL. Both sets
  of weights are under the Llama 4 Community License, whose `LICENSE` and
  `NOTICE` files are downloaded and kept beside them. The ONNX Runtime WASM
  build that runs them ships inside the app (`scripts/stage-runtime.mjs`).
- **Second opinion** (optional, off by default). This is a local model the
  guard can ask before a credential hold. Its endpoint must be loopback.
- **Updates.** At start and hourly, `electron-updater` reads the latest
  release of the public `PinataCloud/doorman` repo on GitHub (the
  `publish` block in `electron-builder.yml`, baked into the app as
  `app-update.yml`). It sends no identifying data beyond a normal HTTPS
  request. A build without that file (`--dir`, a dev run) never checks.

## What it writes outside its own directory

The app writes outside `~/Library/Application Support/Doorman/` only when you
turn a feature on, and every write keeps a `.bak` beside the file:

- **The guard**: a PreToolUse entry in each present agent's user-level hook
  document, for example `~/.claude/settings.json`,
  `${CODEX_HOME:-~/.codex}/hooks.json`, `~/.copilot/hooks/doorman.json` and
  `~/.kiro/hooks/doorman.json`. Plugin hosts also get a plugin directory
  (`~/.openclaw/extensions/doorman-guard/`, Hermes's
  `plugins/doorman-guard/`). The entry runs
  `node "<userData>/doorman/guard/guard.js"`, so it survives app updates.
- **The MCP server**: an entry in each MCP host's config that points at
  `<userData>/doorman/mcp/doorman-mcp.js` (`main/mcp-install.ts`).
- **The VS Code extension** (`pinata.doorman`): installed through
  `code --install-extension`.

## Layout

- `main/`: the Electron main process, TypeScript compiled to CommonJS in
  `build/` (comments stripped by `removeComments`).
  - `main/lib/`: pure logic with no `electron` import, unit-tested.
  - `main/guard/`: the **self-contained** guard bundle, including
    `guard/hosts/`. It is compiled and copied to `<userData>/doorman/guard/`
    at install time. Nothing in it may import from outside the directory, and
    every module must be listed in `GUARD_FILES` (`main/enforcement.ts`). A
    module the copy misses throws in someone's session, and the host reads
    that as an errored hook and fails open. `policy.json`, `spool.jsonl`,
    `app.json` (the heartbeat) and `pending/` (held calls) live beside it.
- `renderer/`: no bundler in development. It uses vendored React + Babel
  (`assets/vendor/`) over the private `doorman://` scheme, with raw JSX
  compiled in-page and flat globals shared across scripts (loader order is
  `SCREENS` in `renderer/index.html`). **Packaged builds ship a precompiled
  renderer**: `scripts/build-renderer.mjs` concatenates the screens and runs
  one esbuild pass (JSX strip + minify) into `build/renderer/`. As a result
  the asar carries no raw source and no Babel, and the packaged CSP drops
  `unsafe-eval`. `renderer/tokens.css` holds the design tokens (fonts and
  palette).
- `assets/`: fonts, vendored React/Babel and the brand mark. These are
  served to the renderer under `_asset/` and shipped as `Resources/assets`.
- `vscode-extension/`: the editor companion.
- `schemas/`: committed JSON Schemas for the detection and ledger exports,
  generated from `main/lib/schema-files.ts` by
  `npx vite-node scripts/make-detection-schema.ts`. A test fails when they
  go stale.
- `test/`: Vitest. `test/fixtures/` holds recorded transcripts and hook
  payloads per agent.
- `docs/shipped-surface.md`: what the packaged app contains, and what a
  downloader can read from it.

Data lives under `~/Library/Application Support/Doorman/` (`%APPDATA%\Doorman`
on Windows, `~/.config/Doorman` on Linux): `store/` (the turn store,
findings, titles, cursors and the Keychain-encrypted evidence vault),
`prefs.json`, `models/` (one directory per downloaded model, each with a
`.verified.json` recording the sha256 every file was checked against) and
`doorman/` (the guard and MCP bundles).

## Develop

```
npm install
npm run dev              # compile + launch
DOORMAN_DEV=1 npm run dev   # + devtools, renderer console forwarded
npm run typecheck        # main + tests
npm test                 # vitest
npm run dev:sandbox      # throwaway home + profile, guard installable (see the script)
npm run compile && npm run probe   # drive the guard catalog through the shipped pipeline
```

Renderer edits need no compile: reload the window. Main-process edits need a
fresh `npm run dev`.

`npm run compile` runs the icon build, `brand` (`scripts/brand-dev-shell.mjs`),
`runtime` and `vsix` steps, then `tsc`. `brand` relabels the prebuilt
`node_modules/electron/dist/Electron.app`, so that an unpackaged run shows
**Doorman** with its mark instead of Electron. It sets the bundle name, the
icon and a separate `cloud.pinata.doorman.dev` identifier, and it leaves the
binary's name alone (the script explains why). Restart after the first branded
compile.

`DOORMAN_APPDATA_DIR=<dir>` redirects the profile into a sandbox. A sandboxed
run refuses to write hook documents in the real home.

### Environment settings

The injection classifier has one row in Settings → AI-delivered protection:
an on/off switch and a model dropdown (Doorman's fine-tuned model, the
default, or stock Prompt Guard 2). The stored choice is written only when it
is stock (`injection_classifier.model` in the policy); no value means the
fine-tuned model, so an install from before the dropdown existed moves to it.
The guard's credential second opinion has no Settings screen. Both can be set
in the environment the app is launched from (`main/lib/policy-env.ts`); an
environment value wins over Settings, and the control it pins shows read-only.
Values are laid over the stored prefs through the same clamps, and an unset or
unparseable value means "no opinion":

```
DOORMAN_INJECTION_CLASSIFIER=off                  # on | off (default on)
DOORMAN_INJECTION_CLASSIFIER_SUPPRESS_BELOW=0.35  # overrule threshold, clamped
DOORMAN_INJECTION_CLASSIFIER_MODEL=stock          # doorman-1 | stock (default doorman-1)
DOORMAN_INJECTION_CLASSIFIER_SOURCE=/path/to/package   # or https://host/prefix/; where doorman-1 comes from
DOORMAN_SECOND_OPINION=on                         # on | off (default off)
DOORMAN_SECOND_OPINION_ENDPOINT=http://127.0.0.1:11434/v1/chat/completions   # loopback only
DOORMAN_SECOND_OPINION_MODEL=qwen2.5:1.5b
DOORMAN_SECOND_OPINION_TIMEOUT_MS=3000
```

`DOORMAN_INJECTION_CLASSIFIER_SOURCE` overrides `DOORMAN_MODEL_BASE_URL`
(`main/lib/model-sources.ts`) for the fine-tuned model: an http(s) prefix the
file names are appended to, or a local directory holding the package. Either
way every file is verified against the pins in `main/lib/model-assets.ts`.

**Publishing the fine-tuned model** means setting that one constant,
`DOORMAN_MODEL_BASE_URL`, to its pinned-revision Hugging Face URL
(`https://huggingface.co/<org>/<repo>/resolve/<commit>/`). The pins do not
change. Installed apps then fetch it at their next launch and switch over.

A Finder launch inherits nothing from a shell. For a packaged app, use
`launchctl setenv …` and relaunch, or start it with `open -a Doorman --env …`.

## Build

```
npm run build        # macOS: dmg + zip, arm64 and x64
npm run build:linux  # AppImage, x64 and arm64 (static AppImage runtime, no libfuse2 needed)
npm run build:win    # one NSIS installer covering x64 and arm64, per-user, unsigned
```

Output goes to `dist/`. Packaging is configured in `electron-builder.yml`. Its
comments explain the `files` / `extraResources` split: the WASM runtime and the
`.vsix` ship once, as real files under `Resources/`.

**Signing (macOS).** The hardened runtime is on, with the entitlements in
`build-resources/entitlements.mac.plist`. `scripts/adhoc-sign.mjs` (the
`afterPack` hook) re-signs the bundle **ad-hoc** unless a "Developer ID
Application" identity is in the keychain. Without that step, arm64 builds
would carry an invalid linker signature and macOS would report them as
"damaged". Ad-hoc builds still need a one-time allow in System Settings →
Privacy & Security. With a Developer ID available, electron-builder signs
properly (`CSC_LINK` / `CSC_KEY_PASSWORD`, or the keychain), and it notarizes
when `APPLE_API_KEY`, `APPLE_API_KEY_ID` and `APPLE_API_ISSUER` are set.
Windows builds are unsigned.

## Releasing

`.github/workflows/release.yml` runs on a pushed `v*` tag: tests, then the Mac
(dmg + zip, x64 + arm64), Linux (AppImage) and Windows (NSIS) builds in
parallel, each launched once as a smoke test, then publishes every file to a
release on this repo, which is where installed apps look for updates.

```sh
npm version 0.2.0 --no-git-tag-version   # bumps package.json + lock
git commit -am "chore: release 0.2.0"
git tag v0.2.0 && git push origin main v0.2.0
```

The tag must match `package.json` or the run stops. Publishing uses the run's
own `GITHUB_TOKEN`; the only secrets the workflow reads are the optional Apple
signing and notary ones listed at the top of the file.
Unsigned Mac builds install with a one-time "Open Anyway", but macOS will not
apply an auto-update to them, so Mac auto-update needs the Developer ID.

Those secrets are set (2026-10-14): Mac releases are signed with the
**Developer ID Application: Pinata Technologies Inc (`GUFNBHK267`)** identity
and notarized through that team's App Store Connect API key (`W5X5576RG4`).
v0.1.0 predates them and is ad-hoc signed, so its installs cannot auto-update
and need one manual download of a signed release.

## Brand assets

Every brand asset derives from one master, `assets/doorman-logo.png`.
`scripts/make-brand.py` (Pillow + fontTools, needed only to regenerate; the
outputs are committed) writes:

- `assets/doorman-mark-512.png`
- `assets/doorman-app-icon.png`
- the menu-bar silhouette mask, `main/lib/tray-mask.ts`
- the VS Code status-bar glyph font, `vscode-extension/doorman-icons.woff`

`scripts/make-icons.mjs` then slices the `.icns` and the Linux/Windows PNG
from the app icon on every build.

**Fonts.** Hanken Grotesk ships under the SIL OFL (`assets/fonts/HankenGrotesk-OFL.txt`).
ABC Diatype (Variable, Mono and Extended) is a commercial typeface that is
currently included and shipped inside the app. Its licence for this product
needs to be confirmed before any build is distributed.
