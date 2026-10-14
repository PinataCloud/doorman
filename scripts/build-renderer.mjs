#!/usr/bin/env node
// Package-time renderer build: precompile the raw JSX the dev loop
// serves into one minified script, so the packaged app ships neither readable
// source + internal commentary nor babel-standalone.
//
//   node scripts/build-renderer.mjs   # writes build/renderer/
//
// Chained into `npm run build` and the CI release job — deliberately NOT into
// `compile`, so `npm run dev` keeps loading the raw per-file JSX through the
// in-page Babel loader untouched. electron-builder packs build/renderer/ into
// the asar AS `renderer/` (see electron-builder.yml), so `rendererRoot()` in
// main/index.ts needs no packaged-vs-dev branch.
//
// The screens are classic scripts sharing one top-level scope (the dev loader
// evals ONE concatenation), so there is no import graph to bundle — concatenate
// in the loader's order, then run exactly ONE esbuild pass over the result.
// One pass is what keeps identifier minification consistent across file
// boundaries: esbuild only renames a top-level binding when it can see every
// reference to it.
import { transform } from "esbuild";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const rendererDir = fileURLToPath(new URL("../renderer/", import.meta.url));
const outDir = fileURLToPath(new URL("../build/renderer/", import.meta.url));

// Line endings normalized on READ, once, rather than `\r?\n` sprinkled through
// the four patterns below. A Windows checkout has core.autocrlf on by default,
// so index.html arrives CRLF there and every `\n` in a pattern silently stops
// matching — which is exactly how the first Windows CI run failed, on
// `mustReplace` rather than on anything to do with Windows itself.
const html = readFileSync(join(rendererDir, "index.html"), "utf8").replace(/\r\n/g, "\n");

// The load order lives in index.html's inline loader — read it from there
// rather than duplicating the list, so adding a screen stays a one-file change.
const screensMatch = html.match(/var SCREENS = \[([^\]]*)\]/);
if (!screensMatch) throw new Error("index.html: couldn't find the SCREENS list");
const screens = [...screensMatch[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
if (screens.length === 0) throw new Error("index.html: SCREENS list is empty");

// A leading `;` per section guards ASI hazards at the join points — identical
// to what the dev loader's `compiled.join("\n;\n")` already does.
const concatenated = screens
  .map((file) => `;\n${readFileSync(join(rendererDir, file), "utf8")}`)
  .join("\n");

const js = await transform(concatenated, {
  loader: "jsx",
  minify: true,
  // JSX-stripping + minification only — never downlevel. The dev path ships
  // this same modern JS (Babel-standalone only strips JSX too), so a lower
  // target would be a behavior change disguised as a build step.
  target: "esnext",
  sourcemap: false,
  sourcefile: "renderer.concat.jsx",
});

// The packaged index.html: same document, with the in-page compiler replaced by
// the precompiled script. Three surgical edits, each asserted so a loader
// rewrite in index.html fails THIS build instead of silently shipping Babel:
//  1. drop the babel-standalone <script>,
//  2. replace the whole inline loader IIFE with one script tag,
//  3. drop 'unsafe-eval' from the CSP — nothing evals anymore.
function mustReplace(source, pattern, replacement, what) {
  const next = source.replace(pattern, replacement);
  if (next === source) throw new Error(`index.html: couldn't rewrite ${what}`);
  return next;
}
let packagedHtml = html;
packagedHtml = mustReplace(
  packagedHtml,
  /<script src="_asset\/vendor\/babel\.js"><\/script>\n/,
  "",
  "the babel script tag",
);
packagedHtml = mustReplace(
  packagedHtml,
  /<script>\n\(function \(\) \{[\s\S]*?\}\)\(\);\n<\/script>/,
  '<script src="app.min.js"></script>',
  "the JSX loader",
);
packagedHtml = mustReplace(packagedHtml, / 'unsafe-eval'/, "", "the CSP eval grant");

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "index.html"), packagedHtml);
writeFileSync(join(outDir, "app.min.js"), `${js.code}\n`);
for (const css of ["tokens.css", "app.css"]) {
  const minified = await transform(readFileSync(join(rendererDir, css), "utf8"), {
    loader: "css",
    minify: true,
  });
  writeFileSync(join(outDir, css), minified.code);
}

console.log(
  `[build-renderer] wrote ${outDir} (app.min.js ${js.code.length} bytes from ${screens.length} sources)`,
);
