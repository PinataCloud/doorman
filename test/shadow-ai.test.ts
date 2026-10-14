import { describe, expect, it } from "vitest";
import {
  SHADOW_ACTIVE_DAYS,
  SHADOW_AI_CATALOG,
  SHADOW_AI_IDS,
  scanShadowAi,
} from "../main/lib/shadow-ai.js";

const DAY = 86_400_000;

describe("scanShadowAi", () => {
  it("marks a covered rail covered and an uncovered installed tool as outside the guard", () => {
    // Claude Code (.claude) and Cursor (/Applications/Cursor.app) present.
    const present = new Set([".claude", ".claude/projects", "/Applications/Cursor.app", ".cursor"]);
    const now = Date.parse("2026-09-02T00:00:00Z");
    const state = scanShadowAi(
      (p) => present.has(p),
      (paths) => (paths.some((p) => present.has(p)) ? now - DAY : undefined),
      now,
    );
    const byId = Object.fromEntries(state.tools.map((t) => [t.id, t]));
    expect(byId["claude-code"].installed).toBe(true);
    expect(byId["claude-code"].covered).toBe(true);
    expect(byId.cursor.installed).toBe(true);
    expect(byId.cursor.covered).toBe(false);
    // The headline: one uncovered installed tool (Cursor), and it is active.
    expect(state.uncovered_installed).toBe(1);
    expect(state.active_uncovered).toBe(1);
    // Not-installed tools report installed:false, no activity.
    expect(byId.ollama.installed).toBe(false);
    expect(byId.ollama.last_active_at).toBeUndefined();
  });

  it("counts an uncovered tool inactive when its newest mtime is beyond the window", () => {
    const present = new Set(["/Applications/ChatGPT.app"]);
    const now = Date.parse("2026-09-02T00:00:00Z");
    const stale = now - (SHADOW_ACTIVE_DAYS + 2) * DAY;
    const state = scanShadowAi(
      (p) => present.has(p),
      (paths) => (paths.length ? stale : undefined),
      now,
    );
    expect(state.uncovered_installed).toBe(1);
    // Installed but stale → not counted as active.
    expect(state.active_uncovered).toBe(0);
  });

  it("computes `covered` from where the guard is installed, not from the catalog", () => {
    // Cursor and Claude Code both on the machine; the guard is wired into
    // Claude Code only (its host id AND source are passed, as enforcement.ts
    // installedGuardHostIds returns both).
    const present = new Set([".claude", "/Applications/Cursor.app", ".cursor"]);
    const now = Date.parse("2026-09-02T00:00:00Z");
    const scan = (guarded: string[]) =>
      Object.fromEntries(
        scanShadowAi((p) => present.has(p), () => now - DAY, now, guarded).tools.map((t) => [t.id, t]),
      );

    const claudeOnly = scan(["claude", "claude-code"]);
    expect(claudeOnly["claude-code"].covered).toBe(true);
    expect(claudeOnly.cursor.covered).toBe(false);

    // Register + install the Cursor adapter and the same catalog entry flips,
    // with no edit to the catalog itself.
    const withCursor = scan(["claude", "claude-code", "cursor"]);
    expect(withCursor.cursor.covered).toBe(true);

    // A capture rail stays covered even with the guard uninstalled — its
    // transcripts are read either way.
    const noGuard = scan([]);
    expect(noGuard["claude-code"].covered).toBe(true);
    expect(noGuard.codex.covered).toBe(true);
    expect(noGuard.cursor.covered).toBe(false);
    // A tool no host adapter can ever reach is never covered.
    expect(scan(["chatgpt-desktop"])["chatgpt-desktop"].covered).toBe(false);
  });

  it("counts observation and prevention apart — a metered rail with no hook is not 'guarded' (review F5)", () => {
    // Claude Code, Codex and Cursor on the machine. Cursor is metered (its
    // transcript source is registered) and guardable, but the guard is wired
    // into Claude Code only.
    const present = new Set([".claude", ".codex", ".cursor", "/Applications/Cursor.app", "/Applications/ChatGPT.app"]);
    const now = Date.parse("2026-09-10T00:00:00Z");
    const scan = (guarded: string[]) =>
      scanShadowAi((p) => present.has(p), () => now - DAY, now, guarded, ["claude", "codex", "cursor"], ["cursor"]);

    const partial = scan(["claude", "claude-code"]);
    const byId = Object.fromEntries(partial.tools.map((t) => [t.id, t]));
    // The union still says Cursor is "covered" (its sessions are read)…
    expect(byId.cursor.covered).toBe(true);
    // …but the split counts say what is actually true: one guarded, two
    // metered-only rails (Codex, Cursor) whose tool calls run unchecked, both
    // reachable by Wire in — while the old actionable count saw nothing to do.
    expect(partial.guarded_installed).toBe(1);
    expect(partial.metered_unguarded).toBe(2);
    expect(partial.guardable_unguarded).toBe(2);
    expect(partial.guardable_uncovered).toBe(0);
    // ChatGPT Desktop: installed, neither metered nor guarded, no adapter.
    expect(partial.uncovered_installed).toBe(1);
    // Active-in-window, not guarded: Codex, Cursor, ChatGPT Desktop.
    expect(partial.active_unguarded).toBe(3);

    // Wire the guard into all three and the metered-only bucket empties.
    const full = scan(["claude", "claude-code", "codex", "cursor"]);
    expect(full.guarded_installed).toBe(3);
    expect(full.metered_unguarded).toBe(0);
    expect(full.guardable_unguarded).toBe(0);
    expect(full.active_unguarded).toBe(1);

    // Guard off everywhere: every installed adapter host is unguarded — the
    // Radar uses this number only while the guard is on (radar.jsx).
    const off = scan([]);
    expect(off.guarded_installed).toBe(0);
    expect(off.metered_unguarded).toBe(3);
    expect(off.guardable_unguarded).toBe(3);
  });

  it("finds nothing on a clean machine", () => {
    const state = scanShadowAi(() => false, () => undefined, Date.parse("2026-09-02T00:00:00Z"));
    expect(state.installed_count).toBe(0);
    expect(state.uncovered_installed).toBe(0);
    expect(state.tools.length).toBeGreaterThan(0); // catalog still enumerated
  });

  it("tells a guardable-but-uncovered tool it is one switch away, and a guarded one that it is guarded", () => {
    // Cursor and Copilot CLI on the machine; the registry knows cursor, gemini
    // and copilot; the guard is installed into none of them (switched off).
    const present = new Set([".claude", ".cursor", ".copilot/session-state", "/Applications/ChatGPT.app"]);
    const now = Date.parse("2026-09-05T00:00:00Z");
    const scan = (guarded: string[]) =>
      Object.fromEntries(
        scanShadowAi((p) => present.has(p), () => now - DAY, now, guarded, ["claude", "codex", "cursor", "gemini", "copilot"])
          .tools.map((t) => [t.id, t]),
      );
    const off = scan(["claude", "claude-code"]);
    expect(off.cursor.guardable).toBe(true);
    expect(off.cursor.covered).toBe(false);
    expect(off.cursor.note).toContain("One switch away");
    expect(off["copilot-cli"].guardable).toBe(true);
    expect(off["copilot-cli"].installed).toBe(true);
    // VS Code's agent hooks read the Copilot CLI's hook directory, so the row
    // is guardable through the `copilot` host (2026-09-08).
    expect(off["vscode-copilot"].guardable).toBe(true);
    expect(off["chatgpt-desktop"].guardable).toBe(false);
    expect(off["chatgpt-desktop"].note).not.toContain("One switch away");
    // Wired in: the note says guarded, and the row is covered.
    const on = scan(["claude", "claude-code", "cursor", "copilot"]);
    expect(on.cursor.covered).toBe(true);
    expect(on.cursor.note).toContain("Guarded");
    expect(on["copilot-cli"].covered).toBe(true);
    // Capture rails keep their own note whatever the guard does.
    expect(on["claude-code"].note).toContain("Captured and guarded");
  });

  it("computes `captured` from the transcript-source registry, the same way", () => {
    // Cursor and Gemini CLI on the machine, the guard installed nowhere.
    const present = new Set([".cursor", "/Applications/Cursor.app", ".gemini", ".claude"]);
    const now = Date.parse("2026-09-06T00:00:00Z");
    const scan = (capturedSources: string[]) =>
      Object.fromEntries(
        scanShadowAi((p) => present.has(p), () => now - DAY, now, [], ["cursor", "gemini"], capturedSources)
          .tools.map((t) => [t.id, t]),
      );

    // No parser registered yet: Cursor is inventory, not a rail.
    const none = scan([]);
    expect(none.cursor.captured).toBe(false);
    expect(none.cursor.covered).toBe(false);
    expect(none.cursor.note).toContain("One switch away");

    // A registered Cursor descriptor (its own id) makes the row Captured —
    // covered even with the guard switched off, because the transcripts are
    // read either way.
    const withCursor = scan(["cursor"]);
    expect(withCursor.cursor.captured).toBe(true);
    expect(withCursor.cursor.covered).toBe(true);
    expect(withCursor.cursor.note).toContain("Captured");
    // ...and only that row.
    expect(withCursor["gemini-cli"].captured).toBe(false);

    // A row is matched by its GUARD HOST id too, since the registry ids and the
    // guard host ids differ for the CLIs (`gemini-cli` vs `gemini`).
    const withGemini = scan(["gemini"]);
    expect(withGemini["gemini-cli"].captured).toBe(true);

    // The two native rails never depend on the registry.
    expect(scan([])["claude-code"].captured).toBe(true);
    expect(scan([]).codex.captured).toBe(true);
  });
});

describe("the catalog as policy vocabulary", () => {
  it("gives every entry a tool-specific path and a unique id", () => {
    const ids = SHADOW_AI_CATALOG.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(SHADOW_AI_IDS).toEqual([...ids].sort());
    for (const entry of SHADOW_AI_CATALOG) {
      expect(entry.present.length).toBeGreaterThan(0);
      expect(entry.note.trim()).not.toBe("");
      for (const path of entry.present) {
        // A shared directory would flag every Mac. Each path is either an app
        // bundle or something under the tool's own folder.
        expect(path).not.toBe("Library/Application Support");
        expect(path).not.toBe("/Applications");
      }
    }
  });

  it("keeps mainstream browsers OUT — presence there says nothing", () => {
    const paths = SHADOW_AI_CATALOG.flatMap((e) => e.present);
    for (const bundle of [
      "/Applications/Google Chrome.app",
      "/Applications/Safari.app",
      "/Applications/Microsoft Edge.app",
      "/Applications/Brave Browser.app",
    ]) {
      expect(paths).not.toContain(bundle);
    }
  });

  it("credits an app whose sessions another rail already carried", () => {
    const present = new Set(["/Applications/ChatGPT.app", ".codex"]);
    const now = Date.parse("2026-09-06T00:00:00Z");
    const scan = (captured: string[]) =>
      Object.fromEntries(
        scanShadowAi((p) => present.has(p), () => now - DAY, now, [], [], captured).tools.map((t) => [
          t.id,
          t,
        ]),
      );
    // No Codex Desktop rollouts read yet: the app is just installed.
    expect(scan([])["chatgpt-desktop"].covered).toBe(false);
    // One read, and the row can no longer claim we cannot see it.
    const withRollouts = scan(["chatgpt-desktop"]);
    expect(withRollouts["chatgpt-desktop"].captured).toBe(true);
    expect(withRollouts["chatgpt-desktop"].covered).toBe(true);
    // ...but the note must not promise a guard that has no adapter for it.
    expect(withRollouts["chatgpt-desktop"].note).not.toContain("while the guard is off");
    expect(withRollouts["chatgpt-desktop"].note).toContain("not something Doorman can hold");
  });
});
