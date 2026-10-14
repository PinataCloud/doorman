import { describe, expect, it } from "vitest";
import { userInfo } from "node:os";
import { hookWritesAllowed, homeIsRedirected, SANDBOX_READ_ONLY } from "../main/lib/sandbox.js";

/**
 * The one predicate every write into a foreign document is checked against
 * (main/lib/sandbox.ts). It has to hold two lines at once: never touch
 * the real account's hook documents from a scratch run, and still let a fully
 * redirected fixture install the guard — without which no rule can ever hold a
 * call, and enforcement cannot be tested anywhere but a real machine.
 */
describe("the sandbox's write predicate", () => {
  const real = userInfo().homedir;

  it("allows everything in a normal run", () => {
    expect(hookWritesAllowed({ HOME: real })).toBe(true);
    // No HOME at all is still a normal run: the sandbox flag is what gates.
    expect(hookWritesAllowed({})).toBe(true);
    // An EMPTY value is not a sandbox — the variable has to name a directory.
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "" })).toBe(true);
  });

  it("says why, in the message every refusal carries", () => {
    expect(SANDBOX_READ_ONLY).toMatch(/read-only/);
  });

  it("refuses a sandboxed run pointed at the REAL home", () => {
    // The 2026-09-06 incident exactly: a scratch profile, the real home, and a
    // boot re-merge that rewrote five hook documents to point into /tmp.
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "/tmp/box", HOME: real })).toBe(false);
    // …and with HOME absent, which resolves to the real home too.
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "/tmp/box" })).toBe(false);
  });

  it("allows a sandboxed run whose HOME is redirected too", () => {
    // Every hook path is resolved from homedir(), so under a redirected home
    // they all land inside the fixture — there is no foreign document to
    // damage, and the guard becomes installable and therefore testable.
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "/tmp/box", HOME: "/tmp/box/home" })).toBe(true);
  });

  it("does not mistake a trailing slash for a different home", () => {
    expect(homeIsRedirected({ HOME: real + "/" })).toBe(false);
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "/tmp/box", HOME: real + "/" })).toBe(false);
  });

  it("treats an unreadable home as NOT redirected — the end that writes nothing", () => {
    expect(homeIsRedirected({})).toBe(false);
    expect(homeIsRedirected({ HOME: "" })).toBe(false);
  });
});
