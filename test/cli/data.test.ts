import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CliCommand } from "../../main/cli/command.js";
import { COMMANDS } from "../../main/cli/commands/index.js";
import { dataCommands } from "../../main/cli/commands/data.js";
import type { CliEnvironment } from "../../main/cli/context.js";
import { main } from "../../main/cli/index.js";
import { guardDir } from "../../main/enforcement.js";
import { heartbeatPath } from "../../main/guard/handshake.js";

/**
 * The Radar, Ledger, Usage and Analytics commands against a real store built
 * from a transcript in a temp HOME: what a person would see and change, the
 * refusal while the app runs, and that no secret value ever prints.
 */

// Until the integrator lists them, put the slice's commands where `main` looks.
for (const command of dataCommands) {
  if (!COMMANDS.some((c) => c.name === command.name)) (COMMANDS as CliCommand[]).push(command);
}

/** The shapes these tests read back from `--json`. */
type Json = Record<string, unknown>;
interface Exposure {
  id: string;
  rule: string;
  status: string;
  severity: string;
  place: string;
  finding_ids: string[];
}
interface FindingsJson {
  open_exposures: number;
  exposures: Exposure[];
}
const envOf = (list: FindingsJson): Exposure | undefined => list.exposures.find((e) => e.rule === "env_dump");

const SESSION = "5e55a0b1-2c3d-4e5f-8a9b-0c1d2e3f4a5b";
/** Shaped like a GitHub token, random enough not to read as a placeholder. */
const TOKEN = "ghp_R8xK2mQ9vL4tZ7wN3pB6yH1jF5cD0sA2eG8u";

function minutesAgo(n: number): string {
  return new Date(Date.now() - n * 60_000).toISOString();
}

/** One Claude Code session: a prompt that pastes a token, a `printenv` call and a reply. */
function transcript(): string {
  const usage = { input_tokens: 1000, output_tokens: 200, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
  return [
    {
      type: "user",
      uuid: "prompt-1",
      timestamp: minutesAgo(30),
      sessionId: SESSION,
      cwd: "/Users/dev/app",
      message: { role: "user", content: `push the release with ${TOKEN} please` },
    },
    {
      type: "assistant",
      timestamp: minutesAgo(29),
      sessionId: SESSION,
      cwd: "/Users/dev/app",
      message: { id: "msg_1", model: "claude-opus-5", role: "assistant", content: [{ type: "tool_use", id: "tu_1", name: "Bash", input: { command: "printenv" } }], usage },
    },
    {
      type: "assistant",
      timestamp: minutesAgo(28),
      sessionId: SESSION,
      cwd: "/Users/dev/app",
      message: { id: "msg_2", model: "claude-opus-5", role: "assistant", content: [{ type: "text", text: "The release pipeline is pushed." }], usage },
    },
  ]
    .map((line) => JSON.stringify(line))
    .join("\n");
}

describe("doorman data commands", () => {
  let root: string;
  let home: string;
  let appData: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-cli-data-"));
    home = join(root, "home");
    appData = join(root, "appdata");
    const project = join(home, ".claude", "projects", "-Users-dev-app");
    mkdirSync(project, { recursive: true });
    mkdirSync(appData, { recursive: true });
    writeFileSync(join(project, `${SESSION}.jsonl`), `${transcript()}\n`);
    savedHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    rmSync(root, { recursive: true, force: true });
  });

  async function run(argv: string[], stdin: string = ""): Promise<{ code: number; out: string; err: string }> {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let out = "";
    let err = "";
    stdout.on("data", (c: Buffer) => (out += c.toString()));
    stderr.on("data", (c: Buffer) => (err += c.toString()));
    const io: CliEnvironment = {
      env: { HOME: home, DOORMAN_APPDATA_DIR: appData, NO_COLOR: "1" },
      home,
      platform: process.platform,
      version: "0.0.0-test",
      stdout,
      stderr,
      stdin: Readable.from([stdin]),
      now: () => Date.now(),
      verbose: false,
    };
    const code = await main(argv, io);
    return { code, out, err };
  }

  async function json<T = Json>(argv: string[]): Promise<T> {
    const r = await run([...argv, "--json"]);
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    return JSON.parse(r.out) as T;
  }

  /** Pretend the desktop app is running: a fresh heartbeat from another pid. */
  function appRunning(): void {
    const path = heartbeatPath(guardDir(join(appData, "Doorman")));
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, JSON.stringify({ at: new Date().toISOString(), pid: process.pid + 1, version: "9.9.9" }));
  }

  it("scan reports what was new, then nothing the second time", async () => {
    const first = await json<{ snapshot: boolean; sessions_added: number; turns_added: number; new_findings: number }>(["scan"]);
    expect(first).toMatchObject({ snapshot: false, sessions_added: 1 });
    expect(first.turns_added).toBeGreaterThan(0);
    expect(first.new_findings).toBeGreaterThan(0);
    const second = await json(["scan"]);
    expect(second).toMatchObject({ turns_added: 0, sessions_added: 0, new_findings: 0 });
    const text = await run(["scan"]);
    expect(text.out).toContain("No new findings.");
  });

  it("findings groups exposures like the Radar, filters, and never prints the token", async () => {
    await run(["scan"]);
    const list = await json<FindingsJson>(["findings"]);
    expect(list.open_exposures).toBeGreaterThanOrEqual(2);
    const rules = list.exposures.map((e) => e.rule);
    expect(rules).toContain("env_dump");
    expect(rules).toContain("credential_in_prompt");
    for (const e of list.exposures) {
      expect(e.status).toBe("open");
      expect(e.finding_ids).toContain(e.id);
      expect(e.place).toBeTruthy();
    }
    const onlyEnv = await json<FindingsJson>(["findings", "--rule", "env_dump"]);
    expect(onlyEnv.exposures.map((e) => e.rule)).toEqual(["env_dump"]);
    const critical = await json<FindingsJson>(["findings", "--severity", "critical"]);
    expect(critical.exposures.every((e) => e.severity === "critical")).toBe(true);
    const limited = await json<FindingsJson>(["findings", "--limit", "1"]);
    expect(limited.exposures).toHaveLength(1);
    const text = await run(["findings"]);
    expect(text.out).toContain("open exposure");
    expect(text.out).not.toContain(TOKEN);
    expect((await run(["findings", "--severity", "huge"])).code).toBe(2);
  });

  it("findings show tells the card's story, masked, and --reveal stays masked", async () => {
    await run(["scan"]);
    const list = await json<FindingsJson>(["findings", "--rule", "credential_in_prompt"]);
    const id = list.exposures[0]!.id;
    const shown = await run(["findings", "show", id.slice(0, 8), "--reveal"]);
    expect(shown.code).toBe(0);
    expect(shown.out).toContain("What");
    expect(shown.out).toContain("Action");
    expect(shown.out).toContain("Do next");
    expect(shown.out).toContain(id);
    expect(shown.out).not.toContain(TOKEN);
    const data = await json(["findings", "show", id, "--reveal"]);
    expect(data).toMatchObject({ finding: { finding_id: id } });
    expect(JSON.stringify(data)).not.toContain(TOKEN);
    expect((await run(["findings", "show", "nope"])).code).toBe(1);
  });

  it("review marks the whole exposure, --all shows it, reopen brings it back", async () => {
    await run(["scan"]);
    const env = envOf(await json<FindingsJson>(["findings"]))!;
    const reviewed = await json(["findings", "review", env.id]);
    expect(reviewed.updated).toBe(env.finding_ids.length);
    expect(envOf(await json<FindingsJson>(["findings"]))).toBeUndefined();
    expect(envOf(await json<FindingsJson>(["findings", "--all"]))?.status).toBe("resolved");
    await json(["findings", "reopen", env.id]);
    expect(envOf(await json<FindingsJson>(["findings"]))?.status).toBe("open");
    await json(["findings", "false-positive", env.id]);
    // Hidden from the feed like the Radar does, unless the person shows them.
    expect(envOf(await json<FindingsJson>(["findings", "--all"]))).toBeUndefined();
  });

  it("reads work on a copy while the app runs; triage refuses and changes nothing", async () => {
    await run(["scan"]);
    const env = envOf(await json<FindingsJson>(["findings"]))!;
    appRunning();
    expect(envOf(await json<FindingsJson>(["findings"]))).toBeDefined();
    expect(await json(["sessions"])).toMatchObject({ total: 1 });
    expect((await json<{ tokens: number }>(["usage"])).tokens).toBeGreaterThan(0);
    expect(await json(["scan"])).toMatchObject({ snapshot: true });
    const refused = await run(["findings", "review", env.id]);
    expect(refused.code).toBe(1);
    expect(refused.err).toContain("Doorman is running");
    rmSync(heartbeatPath(guardDir(join(appData, "Doorman"))));
    expect(envOf(await json<FindingsJson>(["findings"]))?.status).toBe("open");
  });

  it("sessions, session and search read like the Ledger, masked", async () => {
    await run(["scan"]);
    const sessions = await json<{ sessions: Array<{ id: string; alerts: number }> }>(["sessions"]);
    expect(sessions.sessions[0]).toMatchObject({ id: SESSION, source: "claude-code", tokens: 2400 });
    expect(sessions.sessions[0]!.alerts).toBeGreaterThan(0);
    expect(JSON.stringify(sessions)).not.toContain(TOKEN);
    expect(await json(["sessions", "--source", "codex"])).toMatchObject({ total: 0 });
    const one = await run(["session", SESSION.slice(0, 6)]);
    expect(one.code).toBe(0);
    expect(one.out).toContain("push the release with");
    expect(one.out).toContain("finding");
    expect(one.out).not.toContain(TOKEN);
    const detail = await json<{ turns: unknown[]; total_turns: number; findings: unknown[] }>(["session", SESSION]);
    expect(detail.turns.length).toBe(detail.total_turns);
    expect(detail.findings.length).toBeGreaterThan(0);
    const hits = await json<{ turns: unknown[] }>(["search", "release"]);
    expect(hits.turns.length).toBeGreaterThan(0);
    expect(JSON.stringify(hits)).not.toContain(TOKEN);
  });

  it("usage and analytics give the screens' numbers, tokens only", async () => {
    await run(["scan"]);
    const usage = await json(["usage", "--days", "30"]);
    expect(usage).toMatchObject({ days: 30, tokens: 2400, sessions: 1, by_model: [{ model: "claude-opus-5", tokens: 2400 }] });
    expect(JSON.stringify(usage)).not.toMatch(/cost|usd/);
    expect((await run(["usage", "--days", "9"])).code).toBe(2);
    const analytics = await json<{ days: number; exposures: number; window_sessions: number; rules: Array<{ detector: string }> }>(["analytics", "--days", "7"]);
    expect(analytics).toMatchObject({ days: 7, window_sessions: 1 });
    expect(analytics.exposures).toBeGreaterThanOrEqual(2);
    expect(analytics.rules.map((r) => r.detector)).toContain("env_dump");
    expect(JSON.stringify(analytics)).not.toContain("burned_usd");
  });

  it("report and exports write what the app's buttons write", async () => {
    await run(["scan"]);
    const md = await run(["report"]);
    expect(md.code).toBe(0);
    expect(md.out).toContain("# Doorman security report");
    expect(md.out).not.toContain(TOKEN);
    const reportFile = join(root, "report.json");
    expect(await json(["report", "--out", reportFile])).toMatchObject({ format: "json" });
    expect(JSON.parse(readFileSync(reportFile, "utf8"))).toHaveProperty("posture");
    const detections = await json<{ schema: string; detections: unknown[] }>(["export", "detections"]);
    expect(detections.schema).toBe("urn:doorman:schemas:detections-export.v1");
    expect(detections.detections.length).toBeGreaterThan(0);
    const out = join(root, "ledger.json");
    const written = await json(["export", "ledger", "--session", SESSION.slice(0, 8), "--out", out]);
    expect(written).toMatchObject({ count: 1, valid: true });
    const ledger = readFileSync(out, "utf8");
    expect(JSON.parse(ledger)).toHaveProperty("schema", "urn:doorman:schemas:ledger-export.v1");
    expect(ledger).not.toContain(TOKEN);
    expect((await run(["export", "ledger", "--session", "zzz"])).code).toBe(1);
  });

  it("trace reads the value from stdin and never prints it", async () => {
    await run(["scan"]);
    const r = await run(["trace"], `${TOKEN}\n`);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Secret trace");
    expect(r.out).not.toContain(TOKEN);
    const data = await run(["trace", "--json"], TOKEN);
    expect((JSON.parse(data.out) as { total: number }).total).toBeGreaterThan(0);
    expect(data.out).not.toContain(TOKEN);
    expect((await run(["trace", TOKEN])).code).toBe(2);
    expect((await run(["trace"], "short")).code).toBe(1);
    expect(existsSync(join(appData, "Doorman", "store"))).toBe(true);
  });
});
