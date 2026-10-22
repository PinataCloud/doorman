import { spawn } from "node:child_process";
import { once } from "node:events";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { setTimeout as sleep } from "node:timers/promises";
import { afterEach, describe, expect, it } from "vitest";
import { runGateway, type GatewayRun } from "../main/gateway/mcp-gateway.js";
import { writeReply } from "../main/guard/handshake.js";

/**
 * The gateway as a process: a real stdio server (test/fixtures/fake-mcp-server.mjs)
 * behind `runGateway`, driven through in-memory pipes — and, for what only a
 * real process can show (exiting, EPIPE, signals), the compiled
 * build/main/gateway/mcp-gateway.js.
 *
 * Enforcement runs under the `permissionsShown` seam: `mcp_permission` is a
 * hidden rule in this build (guard/rule-scope.ts), and these tests hold the
 * dormant path to being safe for when it comes back.
 */

const FIXTURE = join(__dirname, "fixtures", "fake-mcp-server.mjs");
const BUILD = join(__dirname, "..", "build", "main");
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "doorman-gateway-"));
  dirs.push(dir);
  return dir;
}

async function waitFor<T>(probe: () => T | undefined | false, ms = 5_000): Promise<T> {
  const deadline = Date.now() + ms;
  for (;;) {
    const value = probe();
    if (value !== undefined && value !== false) return value;
    if (Date.now() > deadline) throw new Error("timed out waiting");
    // Polls a condition the code exposes no event for (a file, a pid).
    await sleep(10);
  }
}

/** A JSON-RPC response line, as these tests read it. */
interface Reply {
  id?: unknown;
  result?: { content?: { text?: string }[] };
  error?: { code?: number; message?: string };
}

interface Session {
  dir: string;
  gatewayDir: string;
  guardDir: string;
  log: string;
  input: PassThrough;
  run: GatewayRun;
  bytes(): Buffer;
  /** Every complete output line, parsed (a line that doesn't parse fails the test). */
  messages(): unknown[];
  reply(id: unknown): Promise<Reply>;
  send(message: unknown): void;
  received(): string;
}

function session(options: { dir?: string; env?: Record<string, string>; policy?: unknown; permissionsShown?: boolean } = {}): Session {
  const dir = options.dir ?? scratch();
  const gatewayDir = join(dir, "gateway");
  const guardDir = join(dir, "guard");
  mkdirSync(gatewayDir, { recursive: true });
  mkdirSync(guardDir, { recursive: true });
  if (options.policy) writeFileSync(join(guardDir, "policy.json"), JSON.stringify(options.policy));
  const log = join(dir, `server-${Date.now()}-${Math.random()}.log`);
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: Buffer[] = [];
  output.on("data", (c: Buffer) => chunks.push(c));
  const run = runGateway({
    args: { server: "fake", command: process.execPath, commandArgs: [FIXTURE] },
    gatewayDir,
    guardDir,
    input,
    output,
    env: { ...process.env, FAKE_LOG: log, ...options.env },
    ...(options.permissionsShown ? { permissionsShown: true } : {}),
    pollMs: 20,
    killGraceMs: 300,
  });
  const bytes = () => Buffer.concat(chunks);
  const messages = () =>
    bytes()
      .toString("utf8")
      .split("\n")
      .slice(0, -1)
      .map((line) => JSON.parse(line) as unknown);
  return {
    dir,
    gatewayDir,
    guardDir,
    log,
    input,
    run,
    bytes,
    messages,
    reply: (id) =>
      waitFor(() => messages().find((m): m is Reply => !!m && typeof m === "object" && !Array.isArray(m) && "id" in m && m.id === id)),
    send: (message) => input.write(typeof message === "string" ? message : `${JSON.stringify(message)}\n`),
    received: () => (existsSync(log) ? readFileSync(log, "utf8") : ""),
  };
}

const call = (id: unknown, name: string, args: Record<string, unknown> = {}) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const BLOCK_ACT = { mcp_permissions: { fake: { act: "block" } } };

describe("the gateway relays bytes, not decoded chunks", () => {
  it("delivers a character split across stdin chunks intact, byte for byte", async () => {
    const s = session();
    const line = Buffer.from(`${JSON.stringify(call(1, "echo", { text: `split 🦄 漢 ${"é".repeat(50_000)}` }))}\n`, "utf8");
    // One byte at a time around the emoji, then the rest in odd-sized chunks.
    const emoji = line.indexOf(Buffer.from("🦄"));
    for (let i = 0; i < emoji + 8; i++) s.input.write(line.subarray(i, i + 1));
    for (let i = emoji + 8; i < line.length; i += 4093) s.input.write(line.subarray(i, i + 4093));
    const reply = await s.reply(1);
    expect(reply.result?.content?.[0]?.text).toBe(`split 🦄 漢 ${"é".repeat(50_000)}`);
    expect(Buffer.from(s.received(), "utf8").equals(line)).toBe(true);
    s.input.end();
    await s.run.done;
  });

  it("forwards a last message the client ended with EOF instead of a newline", async () => {
    const s = session();
    s.send(JSON.stringify(call("last", "echo", { text: "no newline" })));
    s.input.end();
    expect(await s.run.done).toEqual({ code: 0 });
    expect(s.received()).toBe(JSON.stringify(call("last", "echo", { text: "no newline" })));
    expect(await s.reply("last")).toMatchObject({ result: { content: [{ text: "no newline" }] } });
  });
});

describe("the spools hold no secret", () => {
  it("masks tool descriptions and schemas, writes 0600, and records only versions not seen before", async () => {
    const dir = scratch();
    for (let n = 0; n < 2; n++) {
      const s = session({ dir, env: { FAKE_SECRET_TOOL: "1" } });
      s.send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
      await s.reply(1);
      s.send(call(2, "echo", { text: "token ghp_Zq8Lm2Vx7Rt4Kp9Wn3Bc6Hd1Fg5Js0Ye8Ua2X here" }));
      await s.reply(2);
      s.input.end();
      await s.run.done;
    }
    const observed = readFileSync(join(dir, "gateway", "observed.jsonl"), "utf8");
    const calls = readFileSync(join(dir, "gateway", "calls.jsonl"), "utf8");
    for (const spool of [observed, calls]) {
      expect(spool).not.toContain("ghp_Zq8Lm2Vx7Rt4");
      expect(spool).not.toContain("Qm9vZ3hYZk4yTjdV");
      expect(spool).toContain("[redacted");
    }
    // Three tools, listed by two sessions: three lines.
    expect(observed.trim().split("\n")).toHaveLength(3);
    expect(statSync(join(dir, "gateway", "observed.jsonl")).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, "gateway", "calls.jsonl")).mode & 0o777).toBe(0o600);
  });

  it("tightens a spool an older gateway left world-readable", async () => {
    const s = session();
    writeFileSync(join(s.gatewayDir, "calls.jsonl"), "", { mode: 0o644 });
    s.send(call(1, "echo", { text: "hi" }));
    await s.reply(1);
    s.input.end();
    await s.run.done;
    expect(statSync(join(s.gatewayDir, "calls.jsonl")).mode & 0o777).toBe(0o600);
  });
});

describe("dormant enforcement can't be bypassed (mcp_permission un-hidden in-test)", () => {
  it("decides on a tools/call whatever its id, echoing the id exactly", async () => {
    const s = session({ policy: BLOCK_ACT, permissionsShown: true });
    s.send('{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"send_email"}}\n');
    s.send('{"jsonrpc":"2.0","method":"tools/call","params":{"name":"send_email"}}\n');
    s.send('{"jsonrpc":"2.0","id":{"o":1},"method":"tools/call","params":{"name":"send_email"}}\n');
    s.send('{"jsonrpc":"2.0","id":true,"method":"tools/call","params":{"name":"send_email"}}\n');
    s.send('{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/call","params":{"name":"send_email"}}\n');
    s.send(call("after", "echo", { text: "still here" }));
    await s.reply("after");
    expect(s.received()).not.toContain("send_email");
    const text = s.bytes().toString("utf8");
    for (const id of ["null", '{"o":1}', "true", "9007199254740993"]) {
      expect(text).toContain(`{"jsonrpc":"2.0","id":${id},"error":{"code":-32001,"message":"Doorman blocked this call`);
    }
    s.input.end();
    await s.run.done;
  });

  it("answers a batch carrying a blocked call as a whole, and forwards none of it", async () => {
    const s = session({ policy: BLOCK_ACT, permissionsShown: true });
    s.send(`${JSON.stringify([call(7, "send_email"), { jsonrpc: "2.0", id: 8, method: "ping" }])}\n`);
    const found = await waitFor(() => s.messages().find((m) => Array.isArray(m)));
    // A batch response: an array of responses.
    const batch = found as Reply[];
    expect(batch.map((r) => r.id)).toEqual([7, 8]);
    expect(batch[0]!.error?.message).toContain("Doorman blocked this call");
    expect(batch[1]!.error?.message).toContain("Send the calls one at a time");
    // An allowed batch passes, and its results are recorded masked.
    s.send(`${JSON.stringify([call(9, "echo", { text: "a" }), call(10, "echo", { text: "b" })])}\n`);
    await waitFor(() => s.messages().filter((m) => Array.isArray(m)).length === 2);
    s.input.end();
    await s.run.done;
    expect(s.received()).not.toContain("send_email");
    const calls = readFileSync(join(s.gatewayDir, "calls.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(calls.filter((c) => c.tool === "echo").map((c) => c.excerpt)).toEqual(["batch echo", "batch echo"]);
  });

  it("never writes a refusal into the middle of a server line", async () => {
    const s = session({ policy: BLOCK_ACT, permissionsShown: true });
    s.send(call("half", "half_line"));
    await waitFor(() => s.bytes().length > 0);
    s.send(call("blocked", "send_email"));
    await s.reply("half");
    await s.reply("blocked");
    // messages() parses every line: a spliced one would have thrown.
    expect(s.messages()).toHaveLength(2);
    s.input.end();
    await s.run.done;
  });

  async function heldCall(s: Session, id: string): Promise<string> {
    // The app is "listening": a fresh heartbeat from a live pid.
    writeFileSync(join(s.guardDir, "app.json"), JSON.stringify({ at: new Date().toISOString(), pid: process.pid }));
    s.send(call(id, "send_email"));
    const file = await waitFor(() => (existsSync(join(s.guardDir, "pending")) ? readdirSync(join(s.guardDir, "pending")).find((f) => !f.includes("reply")) : undefined));
    return file.replace(/\.json$/, "");
  }

  it("does not forward a held call the agent cancelled, even when it is approved after", async () => {
    const s = session({ policy: { mcp_permissions: { fake: { act: "ask" } } }, permissionsShown: true });
    const exchange = await heldCall(s, "c1");
    s.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "c1", reason: "user" } });
    // The card is withdrawn…
    await waitFor(() => !existsSync(join(s.guardDir, "pending", `${exchange}.json`)));
    // …and an approval that lands anyway changes nothing.
    writeReply(s.guardDir, { id: exchange, verdict: "allow", at: new Date().toISOString() });
    await waitFor(() => existsSync(join(s.gatewayDir, "calls.jsonl")) && readFileSync(join(s.gatewayDir, "calls.jsonl"), "utf8").includes("cancelled"));
    s.send(call("after", "echo", { text: "x" }));
    await s.reply("after");
    expect(s.received()).not.toContain("send_email");
    expect(s.bytes().toString("utf8")).not.toContain('"id":"c1"');

    // Control: the same hold, approved and not cancelled, is forwarded.
    const second = await heldCall(s, "c2");
    writeReply(s.guardDir, { id: second, verdict: "allow", at: new Date().toISOString() });
    await s.reply("c2");
    expect(s.received()).toContain('"id":"c2"');
    s.input.end();
    await s.run.done;
  });

  it("ends a hold before a client that gives up silently (Codex) stops waiting, and refuses it", async () => {
    const codexHome = scratch();
    writeFileSync(join(codexHome, "config.toml"), '[mcp_servers.fake]\ncommand = "node"\ntool_timeout_sec = 3\n');
    const s = session({ policy: { mcp_permissions: { fake: { act: "ask" } } }, permissionsShown: true, env: { CODEX_HOME: codexHome } });
    s.send({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "codex-mcp-client", version: "0.162.0" } } });
    await s.reply(0);
    const started = Date.now();
    await heldCall(s, "slow");
    const refused = await s.reply("slow");
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(refused.error?.message).toContain("held for 1s");
    expect(s.received()).not.toContain("send_email");
    s.input.end();
    await s.run.done;
  });
});

describe("the end of a session", () => {
  it("answers in-flight requests with an error when the server dies", async () => {
    const s = session();
    s.send(call("doomed", "die"));
    const reply = await s.reply("doomed");
    expect(reply.error).toMatchObject({ code: -32000 });
    expect(reply.error?.message).toContain("exited before answering");
    expect(await s.run.done).toEqual({ code: 3 });
  });

  /** The compiled bundle, installed the way refreshGatewayBundle lays it out
   * (gateway/ beside guard/) in a scratch dir, so its spools land there. */
  const compiled = (env: Record<string, string> = {}, serverArgs = [FIXTURE]) => {
    const root = scratch();
    for (const part of ["gateway", "guard"]) cpSync(join(BUILD, part), join(root, part), { recursive: true });
    const gw = spawn(process.execPath, [join(root, "gateway", "mcp-gateway.js"), "--server", "fake", "--", process.execPath, ...serverArgs], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    let err = "";
    gw.stdout.on("data", (c: Buffer) => out.push(c));
    gw.stderr.on("data", (c: Buffer) => (err += c.toString()));
    const exited = once(gw, "close").then(([code, signal]) => ({ code: code as number | null, signal: signal as NodeJS.Signals | null }));
    return { gw, out: () => Buffer.concat(out), err: () => err, exited };
  };

  it("hands over everything a server wrote before it exited (compiled gateway)", async () => {
    const dir = scratch();
    const pidfile = join(dir, "pid");
    const g = compiled({ FAKE_PIDFILE: pidfile });
    // Not reading while the server writes and exits: what it wrote is then
    // still in the gateway's hands, and must reach us before the gateway
    // exits. A gateway that applies backpressure holds the server up instead,
    // so the wait is bounded (a real pipe filling up has no event to await).
    g.gw.stdout.pause();
    const pid = Number(await waitFor(() => existsSync(pidfile) && readFileSync(pidfile, "utf8")));
    g.gw.stdin.write(`${JSON.stringify(call(1, "big_then_exit", { bytes: 3_000_000 }))}\n`);
    await waitFor(() => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    }, 1_000).catch(() => undefined);
    g.gw.stdout.resume();
    expect(await g.exited).toEqual({ code: 0, signal: null });
    const reply = JSON.parse(g.out().toString("utf8")) as Reply;
    expect(reply.id).toBe(1);
    expect(reply.result?.content?.[0]?.text).toHaveLength(3_000_000);
  });

  it("survives a client that closed its end (EPIPE): no crash, and the server is stopped", async () => {
    const dir = scratch();
    const pidfile = join(dir, "pid");
    const g = compiled({ FAKE_PIDFILE: pidfile });
    await waitFor(() => existsSync(pidfile) && readFileSync(pidfile, "utf8"));
    g.gw.stdout.destroy();
    for (let i = 0; i < 200; i++) g.gw.stdin.write(`${JSON.stringify(call(i, "echo", { text: "x".repeat(10_000) }))}\n`);
    await g.exited;
    expect(g.err()).not.toContain("EPIPE");
    expect(g.err()).not.toContain("Error:");
    const pid = Number(readFileSync(pidfile, "utf8"));
    await waitFor(() => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    });
  });

  it("survives a burst of writes to a server that exits under it", async () => {
    const g = compiled({ FAKE_EXIT_NOW: "1" });
    // The gateway goes once its server has; writes racing that are the test's to lose.
    g.gw.stdin.on("error", () => {});
    for (let i = 0; i < 200; i++) g.gw.stdin.write(`${JSON.stringify(call(i, "echo", { text: "x".repeat(10_000) }))}\n`);
    expect((await g.exited).code).toBe(0);
    expect(g.err()).not.toContain("EPIPE");
    expect(g.err()).not.toContain("Error:");
  });

  it("takes a server that ignores SIGTERM down with it instead of orphaning it", async () => {
    const dir = scratch();
    const pidfile = join(dir, "pid");
    const g = compiled({ FAKE_PIDFILE: pidfile, FAKE_IGNORE_TERM: "1", FAKE_STAY: "1" });
    await waitFor(() => existsSync(pidfile) && readFileSync(pidfile, "utf8"));
    const pid = Number(readFileSync(pidfile, "utf8"));
    g.gw.kill("SIGTERM");
    const ended = await g.exited;
    expect(ended.signal).toBe("SIGTERM");
    expect(() => process.kill(pid, 0)).toThrow();
  });
});
