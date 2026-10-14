import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Same guard as test/renderer.test.ts, pointed at the app:
 * Babel-in-the-browser means a .jsx typo is a blank window at runtime, the
 * ordered list in index.html IS the module graph, and nothing may reach the
 * network — this app's entire privacy story is "local", so a CDN reference is
 * both a leak and a blank screen offline.
 */

const rendererDir = new URL("../renderer/", import.meta.url);

function babelStandalone() {
  const vendor = new URL("../assets/vendor/babel.js", import.meta.url);
  const ctx: Record<string, unknown> = { console, setTimeout, clearTimeout };
  ctx.window = ctx;
  ctx.self = ctx;
  ctx.globalThis = ctx;
  return import("node:vm").then(({ createContext, runInContext }) => {
    createContext(ctx);
    runInContext(readFileSync(vendor, "utf8"), ctx as object, { filename: "babel.js" });
    return ctx.Babel as { transform(code: string, opts: unknown): unknown };
  });
}

function jsxFiles(dir: URL): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) out.push(...jsxFiles(new URL(`${entry.name}/`, dir)).map((f) => `${entry.name}/${f}`));
    else if (entry.name.endsWith(".jsx")) out.push(entry.name);
  }
  return out.sort();
}

describe("desktop renderer", () => {
  it("transpiles every .jsx through the same Babel the app loads", async () => {
    const babel = await babelStandalone();
    expect(babel, "vendored babel.js did not expose a Babel global").toBeTruthy();

    const files = jsxFiles(rendererDir);
    expect(files.length).toBeGreaterThan(4);
    for (const file of files) {
      const source = readFileSync(new URL(file, rendererDir), "utf8");
      expect(
        () => babel.transform(source, { presets: ["react"], filename: file }),
        `${file} is not valid JSX`,
      ).not.toThrow();
    }
  });

  it("loads exactly the files that exist, in one place", () => {
    const html = readFileSync(new URL("index.html", rendererDir), "utf8");
    const listed = [...html.matchAll(/"([\w./-]+\.jsx)"/g)].map((m) => m[1]!);
    expect(listed.length, "no .jsx entries found in index.html").toBeGreaterThan(4);
    expect(new Set(listed)).toEqual(new Set(jsxFiles(rendererDir)));
  });

  it("reaches no network at load time", () => {
    const html = readFileSync(new URL("index.html", rendererDir), "utf8");
    expect(html).not.toMatch(/src="https?:\/\//);
    expect(html).not.toMatch(/href="https?:\/\/[^"]*\.css/);
  });
});
