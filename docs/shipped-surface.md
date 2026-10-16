# What a Doorman build ships

Everything in a released build is readable by anyone who downloads it: the DMG
and zip are plain containers, and `app.asar` is an unencrypted archive. This
file is the record of what ships and what a downloader can read from it — a
**security** record (what must never ship: secrets, customer data, internal
infrastructure) and a **licensing** record (every redistributed font and
dependency).

Update it in the same change whenever you:

1. add or remove a shipped file, asset, font or npm dependency;
2. change what packaging strips — `removeComments` in `tsconfig.json`,
   `scripts/build-renderer.mjs`, or the `files` / `extraResources` globs in
   `electron-builder.yml`;
3. add an IPC channel, an entitlement, or any network call (including a
   change of a model's download URL, e.g. `main/lib/model-sources.ts`);
4. move something between *deliberately shipped* and *must not ship*.

Audit the **built** app, never the source tree — packaging decides what ships,
and a source-level check misses a regression in it. The recipe is at the end.

Last audited: 2026-10-12, `Doorman.app` 0.1.0, macOS arm64 (`electron-builder
--mac dir --arm64`), 297 MB unpacked.

## Layout of the app

```
Doorman.app/Contents/
  Info.plist                 CFBundleIdentifier cloud.pinata.doorman, copyright "Pinata"
  Resources/
    app.asar                 327 files — see below
    icon.icns                from assets/doorman-app-icon.png
    assets/                  served to the renderer under the _asset/ prefix
      doorman-mark-512.png
      fonts/                 Hanken Grotesk, ABC Diatype (see Licensing)
      vendor/react.js, react-dom.js
    runtime/onnxruntime-web/ the WASM runtime the injection classifier runs on
    vscode/doorman.vsix      the VS Code companion, installed by path
```

Inside `app.asar`:

- `package.json` — name, version, description, author, the two runtime
  dependencies. No scripts or dev dependencies.
- `build/main/**` — the compiled main process, guard bundle, MCP server and
  gateway. Compiled with `removeComments`, so no source commentary ships.
- `renderer/` — `index.html`, `app.css`, `tokens.css` and one precompiled,
  comment-free `app.min.js` (`scripts/build-renderer.mjs`). The in-page JSX
  compiler (`assets/vendor/babel.js`) is a development-only file and is
  excluded; packaged builds also drop `unsafe-eval` from the page's CSP.
- `node_modules/` — the runtime dependencies listed under Licensing.

`build/` is deleted before every compile (`npm run clean`), so a module removed
from the source cannot linger in a build.

## Network

The app makes no request on its own except:

- **The injection-classifier model**, downloaded only when the classifier
  needs it and verified by size and sha256 against pins in
  `main/lib/model-assets.ts`. The default selection is Doorman's fine-tuned
  model (`doorman-1`), fetched from huggingface.co,
  `PinataCloud/Llama-Doorman-22M` at commit
  `4a43fec65a670e48835d8e8c85c705b4b0d1c907` (`DOORMAN_MODEL_BASE_URL` in
  `main/lib/model-sources.ts`; `DOORMAN_INJECTION_CLASSIFIER_SOURCE`
  overrides it). Whenever that download or its verification fails, the app
  fetches and runs stock Llama Prompt Guard 2 22M from huggingface.co
  (`gravitee-io/Llama-Prompt-Guard-2-22M-onnx`, pinned to one commit) in its
  place, and keeps retrying the fine-tuned model. Each model directory gets a `.verified.json` (file
  name to the sha256 it was verified against; hashes of public files only).
- **The second opinion**, off by default: a loopback-only call to a local
  OpenAI-compatible model server the person configures (`DOORMAN_SECOND_OPINION*`).
- **Auto-update**: `Resources/app-update.yml` (from the `publish` block in
  `electron-builder.yml`) points `electron-updater` at the public GitHub
  repo `PinataCloud/doorman`; it checks at start and hourly. A
  `--dir` build carries no such file and never checks.

The only URLs in first-party shipped code are `huggingface.co`, `127.0.0.1`,
and the JSON-schema `$schema` / `urn:doorman:schemas:*` identifiers; the
update feed's GitHub address lives in `app-update.yml`, outside `app.asar`.

## What it writes outside its own data directory

Covered in the README (*What it writes outside its own directory*): the guard's
hook entries and plugin directories, MCP server registrations, and the VS Code
extension — each only when its feature is on, each with a `.bak` beside the
file it changes.

## Must never ship — checked at the last audit

| Check | Result |
| --- | --- |
| Credentials, tokens, private keys, `.env` files | none |
| Any reference to the product's former name or its servers | none |
| Internal ticket ids, people's names, internal paths | none |
| Compiled leftovers of deleted modules | none (after the clean step) |
| Source maps (`*.map`) | excluded by `files` glob |
| Test files and fixtures | not in `files` |

## Licensing — everything redistributed

**npm runtime dependencies** (in `app.asar/node_modules`):

| Package | Licence |
| --- | --- |
| @huggingface/tokenizers 0.1.3 | Apache-2.0 |
| electron-updater 6.8.9 | MIT |
| builder-util-runtime 9.7.0 | MIT |
| debug 4.4.3, ms 2.1.3 | MIT |
| fs-extra 10.1.0, jsonfile 6.2.1, universalify 2.0.1 | MIT |
| graceful-fs 4.2.11, semver 7.7.4 | ISC |
| js-yaml 4.3.1 | MIT |
| argparse 2.0.1 | Python-2.0 |
| lazy-val 1.0.5, lodash.escaperegexp 4.1.2, lodash.isequal 4.5.0, tiny-typed-emitter 2.1.0 | MIT |
| sax 1.6.1 | BlueOak-1.0.0 |

**Bundled outside node_modules:**

| Item | Licence |
| --- | --- |
| Electron 43 (the runtime itself, with Chromium) | MIT + Chromium's bundled licences (`LICENSES.chromium.html` in the app) |
| onnxruntime-web 1.29.0 WASM runtime | MIT |
| React, React DOM (`assets/vendor`) | MIT |
| Hanken Grotesk | SIL Open Font License 1.1 (`assets/fonts/HankenGrotesk-OFL.txt` ships beside it) |
| **ABC Diatype, ABC Diatype Mono, ABC Diatype Extended** | **Commercial (Dinamo). Redistribution in an app needs a licence that covers it — confirm before any build is distributed, or replace the family.** |
| The Doorman mark and app icon | Pinata's own |

The classifier models are data the app downloads on demand, never part of the
bundle. Both (stock, and Doorman's fine-tune of it) are Llama derivatives under
the **Llama 4 Community License**: the pinned `LICENSE` and `NOTICE` files are
downloaded with the weights and kept beside them, the fine-tune's directory name
starts with "Llama", and the notice "Built with Llama" travels in each manifest.
The fine-tuned weights are redistributed from `PinataCloud/Llama-Doorman-22M`
on Hugging Face under the same terms.

## Keeping this doc honest

```sh
npm run compile && npm run renderer:min
npx electron-builder --mac dir --arm64 --publish never
A=dist/mac-arm64/Doorman.app; T=$(mktemp -d)
npx @electron/asar extract "$A/Contents/Resources/app.asar" "$T/asar"
unzip -oq "$A/Contents/Resources/vscode/doorman.vsix" -d "$T/vsix"
cp -R "$A/Contents/Resources/assets" "$T/assets"

find "$T/asar" -type f | wc -l                         # file count above
grep -rhoE "https?://[A-Za-z0-9.-]+" "$T/asar/build" "$T/asar/renderer" "$T/vsix/extension" | sort -u
grep -rliE "BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}" "$T/asar/build" "$T/asar/renderer"
plutil -p "$A/Contents/Info.plist" | grep -E "CFBundleIdentifier|Copyright"
```

The secret grep came back empty at the last audit. Should it ever match inside
`guard/redact.js` or `guard/security-detect.js`, check whether the hit is a
detector's regex for a key shape (expected) or a literal key (a finding).
