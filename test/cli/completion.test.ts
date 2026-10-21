import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { COMMANDS } from "../../main/cli/commands/index.js";
import { completionScript, completionTree, SHELLS } from "../../main/cli/commands/completion.js";
import type { CliEnvironment } from "../../main/cli/context.js";
import { main } from "../../main/cli/index.js";

/**
 * `doorman completion`: scripts built from the registry (every command,
 * subcommand and documented flag), valid in their shell, completing as a
 * person would see it, and `--ids` listing the exposure ids `findings` does.
 */

const has = (shell: string) => spawnSync(shell, ["-c", "exit 0"]).status === 0;

/** The long flags `--help` documents for a command. */
const documented = (flags: readonly (readonly [string, string])[] | undefined) => [...new Set((flags ?? []).map(([f]) => /^--[\w-]+/.exec(f)![0]))];

/** Each line: what Tab offers after the words (the last one being typed). */
function bashCompletes(lines: readonly string[][]): string[] {
  const script = [
    // The ids callback, stubbed: the real one is tested below.
    `doorman() { [[ "$1 $2" == "completion --ids" ]] && printf 'abc123\\tcritical, A\\nabd999\\thigh, B\\n'; }`,
    completionScript("bash", COMMANDS),
    't() { COMP_WORDS=("$@"); COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 )); _doorman; echo "${COMPREPLY[*]}"; }',
    ...lines.map((words) => `t ${words.map((w) => `'${w}'`).join(" ")}`),
  ].join("\n");
  const r = spawnSync("bash", [], { input: script, encoding: "utf8" });
  expect(r.stderr).toBe("");
  return r.stdout.trimEnd().split("\n");
}

describe("doorman completion", () => {
  it("builds every command, subcommand and documented flag from the registry", () => {
    const nodes = new Map(completionTree(COMMANDS).map((n) => [n.at, n]));
    for (const command of COMMANDS) {
      const words = command.name.split(" ");
      const node = nodes.get(`doorman ${command.name}`);
      expect(node, command.name).toBeDefined();
      expect(nodes.get(["doorman", ...words.slice(0, -1)].join(" "))!.subs.map(([w]) => w), command.name).toContain(words[words.length - 1]);
      for (const flag of documented(command.flags)) expect(node!.flags.map((f) => f.name), command.name).toContain(flag);
      for (const shell of SHELLS) {
        const script = completionScript(shell, COMMANDS);
        expect(script, `${shell}: ${command.name}`).toContain(`'doorman ${command.name}'`);
        for (const flag of documented(command.flags)) expect(script, `${shell}: ${command.name} ${flag}`).toContain(flag);
      }
    }
    // The ids callback is internal: not offered.
    expect(nodes.get("doorman completion")!.flags.map((f) => f.name)).not.toContain("--ids");
  });

  it.skipIf(!has("bash"))("writes a bash script bash accepts and that completes", () => {
    expect(spawnSync("bash", ["-n"], { input: completionScript("bash", COMMANDS) }).status).toBe(0);
    const [top, sub, ids, prefixed, flags, format, shells, family] = bashCompletes([
      ["doorman", "fin"],
      ["doorman", "findings", ""],
      ["doorman", "findings", "show", ""],
      ["doorman", "findings", "review", "abc123", "abd"],
      ["doorman", "findings", "show", "--"],
      ["doorman", "report", "--format", ""],
      ["doorman", "completion", ""],
      ["doorman", "help", "gu"],
    ]);
    expect(top).toBe("findings");
    expect(sub!.split(" ")).toEqual(expect.arrayContaining(["show", "review", "reopen", "false-positive", "accept-risk"]));
    expect(ids).toBe("abc123 abd999");
    expect(prefixed).toBe("abd999");
    expect(flags!.split(" ")).toEqual(expect.arrayContaining(["--evidence", "--json", "--help"]));
    expect(format).toBe("md json");
    expect(shells).toBe("zsh bash fish");
    expect(family).toBe("guard");
  });

  it.skipIf(!has("zsh"))("writes a zsh script zsh accepts and that completes", () => {
    const script = completionScript("zsh", COMMANDS);
    expect(script.startsWith("#compdef doorman\n")).toBe(true);
    expect(spawnSync("zsh", ["-n"], { input: script }).status).toBe(0);
    // compsys's helpers stubbed to print what they were handed.
    const run = [
      `doorman() { [[ "$1 $2" == "completion --ids" ]] && printf 'ab:c\\tcritical, A\\n'; }`,
      '_describe() { print -r -- "${(Pj:|:)@[-1]}"; }',
      'compadd() { [[ $1 == -a ]] && print -r -- "${(Pj:|:)2}"; }',
      "_files() { print -r -- files; }",
      "_message() { print -r -- message; }",
      script,
      't() { words=("$@"); CURRENT=$#words; PREFIX=$words[-1]; _doorman; }',
      "t doorman findings ''",
      "t doorman findings show ''",
      "t doorman findings show --e",
      "t doorman report --out ''",
      "t doorman policy level ''",
    ].join("\n");
    const r = spawnSync("zsh", ["-f"], { input: run, encoding: "utf8" });
    expect(r.stderr).toBe("");
    const [sub, ids, flags, out, level] = r.stdout.trimEnd().split("\n");
    expect(sub).toMatch(/^show:One exposure in full/);
    expect(ids).toBe("ab\\:c:critical, A");
    expect(flags).toMatch(/^--evidence:/);
    expect(out).toBe("files");
    expect(level!.split("|").length).toBeGreaterThan(1);
  });

  it.skipIf(!has("fish"))("writes a fish script fish accepts", () => {
    expect(spawnSync("fish", ["--no-execute"], { input: completionScript("fish", COMMANDS) }).status).toBe(0);
  });
});

describe("doorman completion via the CLI", () => {
  let root: string;
  let home: string;
  let appData: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-cli-completion-"));
    home = join(root, "home");
    appData = join(root, "appdata");
    const project = join(home, ".claude", "projects", "-Users-dev-app");
    mkdirSync(project, { recursive: true });
    mkdirSync(appData, { recursive: true });
    const session = "5e55a0b1-2c3d-4e5f-8a9b-0c1d2e3f4a5c";
    const at = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
    const usage = { input_tokens: 1000, output_tokens: 200, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
    // A pasted token and a `printenv`: two exposures.
    const lines = [
      { type: "user", uuid: "prompt-1", timestamp: at(30), sessionId: session, cwd: "/Users/dev/app", message: { role: "user", content: "push it with ghp_R8xK2mQ9vL4tZ7wN3pB6yH1jF5cD0sA2eG8u please" } },
      {
        type: "assistant",
        timestamp: at(29),
        sessionId: session,
        cwd: "/Users/dev/app",
        message: { id: "msg_1", model: "claude-opus-5", role: "assistant", content: [{ type: "tool_use", id: "tu_1", name: "Bash", input: { command: "printenv" } }], usage },
      },
    ];
    writeFileSync(join(project, `${session}.jsonl`), `${lines.map((l) => JSON.stringify(l)).join("\n")}\n`);
    savedHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    rmSync(root, { recursive: true, force: true });
  });

  async function run(argv: string[]): Promise<{ code: number; out: string; err: string }> {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let out = "";
    let err = "";
    stdout.on("data", (c: Buffer) => (out += c.toString()));
    stderr.on("data", (c: Buffer) => (err += c.toString()));
    const io: CliEnvironment = {
      env: { HOME: home, DOORMAN_APPDATA_DIR: appData },
      home,
      platform: process.platform,
      version: "0.0.0-test",
      stdout,
      stderr,
      stdin: Readable.from([""]),
      now: () => Date.now(),
      verbose: false,
    };
    return { code: await main(argv, io), out, err };
  }

  it("prints the script as is, and refuses a shell it has none for", async () => {
    const zsh = await run(["completion", "zsh"]);
    expect(zsh).toEqual({ code: 0, out: `${completionScript("zsh", COMMANDS)}\n`, err: "" });
    expect((await run(["completion", "tcsh"])).code).toBe(2);
    expect((await run(["completion"])).code).toBe(2);
  });

  it("--ids lists the ids `findings` does, one per line, quietly", async () => {
    expect((await run(["scan", "--json"])).code).toBe(0);
    const listed = JSON.parse((await run(["findings", "--all", "--limit", "0", "--json"])).out) as { exposures: { id: string }[] };
    expect(listed.exposures.length).toBeGreaterThan(0);
    const ids = await run(["completion", "--ids"]);
    expect(ids.err).toBe("");
    expect(ids.code).toBe(0);
    const lines = ids.out.trimEnd().split("\n");
    for (const line of lines) expect(line).toMatch(/^[^\t\s]+\t\S/);
    expect(lines.map((l) => l.split("\t")[0]).sort()).toEqual(listed.exposures.map((e) => e.id).sort());
  });
});
