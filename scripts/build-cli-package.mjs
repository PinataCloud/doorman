#!/usr/bin/env node
/**
 * Assemble the `@pinata/doorman` npm package in dist/cli-package from a compiled
 * tree (`npm run compile` first). The CLI is the app's own main-process code
 * run under plain Node, so the package is build/main minus the Electron-only
 * modules, the ONNX runtime the classifier runs on, the VS Code companion the
 * `editor` command installs, and the licence files.
 *
 *   npm run cli:package            # compile + assemble
 *   (cd dist/cli-package && npm pack)
 *
 * It then proves the package stands alone: the bin runs, prints the manifest's
 * version, and loads no Electron-only module and no package it doesn't declare.
 */
import { execFileSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist", "cli-package");
const fail = (message) => {
  console.error(`build-cli-package: ${message}`);
  process.exit(1);
};

/** Main-process modules that import Electron (or exist only for the window). */
const ELECTRON_ONLY = new Set(["index.js", "preload.js", "tray.js", "menu.js", "approval-window.js", "notifications.js", "updater.js"]);

if (!existsSync(join(root, "build", "main", "cli", "index.js"))) fail("build/main/cli/index.js is missing; run `npm run compile` first");
const runtime = join(root, "build", "runtime", "onnxruntime-web");
if (!existsSync(runtime)) fail("build/runtime/onnxruntime-web is missing; run `npm run compile` first");
const vsix = join(root, "build", "vscode");
if (!existsSync(vsix) || !readdirSync(vsix).some((f) => f.endsWith(".vsix"))) fail("build/vscode/*.vsix is missing; run `npm run compile` first");

// Empty the folder rather than replace it: a container or editor that has
// dist/cli-package mounted keeps seeing the new contents (a removed and
// recreated directory leaves the mount pointing at the deleted one).
mkdirSync(out, { recursive: true });
for (const entry of readdirSync(out)) rmSync(join(out, entry), { recursive: true, force: true });

// Source maps stay out, as they do from the app (electron-builder `!**/*.map`):
// they would carry the source, comments included, that `removeComments` strips.
cpSync(join(root, "build", "main"), join(out, "build", "main"), {
  recursive: true,
  filter: (src) =>
    !src.endsWith(".map") && !(dirname(src) === join(root, "build", "main") && ELECTRON_ONLY.has(src.slice(dirname(src).length + 1))),
});
cpSync(runtime, join(out, "build", "runtime", "onnxruntime-web"), { recursive: true });
cpSync(vsix, join(out, "build", "vscode"), { recursive: true });
// CHANGELOG.md: what `doorman changelog` prints and `doorman update` shows
// after installing (main/cli/commands/changelog.ts).
for (const file of ["LICENSE", "NOTICE", "CHANGELOG.md"]) cpSync(join(root, file), join(out, file));
cpSync(join(root, "cli", "README.md"), join(out, "README.md"));

// The manifest, with runtime dependencies pinned to the versions the app is
// tested against, so the CLI and the app never run different tokenizers.
const manifest = JSON.parse(readFileSync(join(root, "cli", "package.json"), "utf8"));
const appManifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
for (const name of Object.keys(manifest.dependencies ?? {})) {
  const pinned = appManifest.dependencies?.[name];
  if (!pinned) fail(`cli/package.json depends on ${name}, which the app does not`);
  manifest.dependencies[name] = pinned;
}
writeFileSync(join(out, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
const bin = join(out, manifest.bin.doorman);
chmodSync(bin, 0o755);

// Stand-alone checks.
const version = execFileSync(process.execPath, [bin, "--version"], { encoding: "utf8" }).trim();
if (version !== manifest.version) fail(`the bin reports ${version}, the manifest says ${manifest.version}`);
// npm pack quietly leaves out what `files` doesn't list.
const listed = new Set(["package.json", ...manifest.files.map((f) => f.replace(/\/$/, ""))]);
const unlisted = readdirSync(out).filter((f) => !listed.has(f));
if (unlisted.length > 0) fail(`cli/package.json "files" leaves out ${unlisted.join(", ")}`);
const notes = JSON.parse(execFileSync(process.execPath, [bin, "changelog", "--json"], { encoding: "utf8", cwd: out }));
if (notes.versions?.[0]?.version !== manifest.version) fail(`the bundled CHANGELOG.md has no "## CLI ${manifest.version}" section`);
const loaded = JSON.parse(
  execFileSync(
    process.execPath,
    [
      "-e",
      `require(${JSON.stringify(bin)}); console.log(JSON.stringify(Object.keys(require.cache)))`,
    ],
    { encoding: "utf8", cwd: out },
  ),
);
const escaped = loaded.filter((p) => !p.startsWith(out));
if (escaped.length > 0) fail(`the bin loads files outside the package: ${escaped.join(", ")}`);
const electronOnly = loaded.filter((p) => dirname(p) === join(out, "build", "main") && ELECTRON_ONLY.has(p.slice(dirname(p).length + 1)));
if (electronOnly.length > 0) fail(`the bin loads Electron-only modules: ${electronOnly.join(", ")}`);

const size = execFileSync("du", ["-sh", out], { encoding: "utf8" }).split("\t")[0];
console.log(`${manifest.name}@${manifest.version} → dist/cli-package (${size}); bin "doorman" runs and loads ${loaded.length} files, none Electron-only`);
