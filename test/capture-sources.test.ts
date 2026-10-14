import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CaptureEngine } from "../main/capture.js";
import { defaultPolicy } from "../main/guard/policy.js";
import type { LedgerTurn } from "../main/lib/turns.js";
import type {
  SourceIo,
  TranscriptParseResult,
  TranscriptSourceDescriptor,
} from "../main/lib/transcript-sources.js";

/**
 * The engine's REGISTRY side, driven by a fake descriptor rather than a real
 * editor: day-zero backfill, the size+mtime cursor, the full detection pipeline
 * under the descriptor's own source id, isolation of a parser that throws, and
 * the per-source rollup the snapshot is built from.
 *
 * The fake reads a directory of tiny JSON documents through the injected
 * `SourceIo`, which is exactly the shape the three real parsers have.
 */

const SESSION = "cur-session-1";

interface FakeDoc {
  turns: Array<Partial<LedgerTurn> & { id: string; role: "user" | "assistant" }>;
  /** A tool call to run the detectors over. */
  command?: string;
}

function fakeSource(over: Partial<TranscriptSourceDescriptor> = {}): TranscriptSourceDescriptor {
  return {
    id: "cursor",
    label: "Cursor",
    presencePaths: [".fakehost"],
    roots: (home) => [join(home, ".fakehost", "chats")],
    discover: (root, io) => io.listDir(root).filter((n) => n.endsWith(".json")).map((n) => join(root, n)),
    parse: (path, io): TranscriptParseResult => {
      const raw = io.readText(path);
      if (raw === undefined) return { turns: [], titles: [], detect: [] };
      const doc = JSON.parse(raw) as FakeDoc;
      const turns: LedgerTurn[] = doc.turns.map((t) => ({
        source: "cursor",
        session_id: SESSION,
        at: "2026-09-01T10:00:00.000Z",
        ...t,
      })) as LedgerTurn[];
      return {
        turns,
        titles: [],
        detect: doc.command
          ? [
              {
                kind: "tool_call",
                raw: JSON.stringify({ command: doc.command }),
                tool_name: "Bash",
                target: doc.command.split(" ")[0],
                session_id: SESSION,
                turn_id: doc.turns[0]?.id ?? "t1",
                at: "2026-09-01T10:00:00.000Z",
              },
            ]
          : [],
      };
    },
    sessionIdOf: () => SESSION,
    metered: true,
    ...over,
  };
}

describe("CaptureEngine over a registered transcript source", () => {
  let root: string;
  let home: string;
  let chats: string;
  let deps: ConstructorParameters<typeof CaptureEngine>[0];
  let logs: string[];

  const io = (): SourceIo => ({
    readText: (p) => {
      try {
        return readFileSync(p, "utf8");
      } catch {
        return undefined;
      }
    },
    listDir: (p) => {
      try {
        return readdirSync(p);
      } catch {
        return [];
      }
    },
    stat: (p) => {
      try {
        const st = statSync(p);
        return { size: st.size, mtimeMs: st.mtimeMs, isDirectory: st.isDirectory() };
      } catch {
        return undefined;
      }
    },
    querySqlite: () => {
      throw new Error("this fake host keeps JSON documents, not a database");
    },
  });

  const write = (name: string, doc: FakeDoc) =>
    writeFileSync(join(chats, name), JSON.stringify(doc));

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-src-"));
    home = join(root, "home");
    chats = join(home, ".fakehost", "chats");
    mkdirSync(chats, { recursive: true });
    mkdirSync(join(root, "claude", "projects"), { recursive: true });
    mkdirSync(join(root, "codex", "sessions"), { recursive: true });
    logs = [];
    deps = {
      storeDir: join(root, "store"),
      claudeProjectsDir: join(root, "claude", "projects"),
      codexSessionsDir: join(root, "codex", "sessions"),
      home,
      env: {},
      sources: [fakeSource()],
      sourceIo: io(),
      policy: () => defaultPolicy(),
      retentionDays: () => 0,
      onUpdate: () => {},
      onNewFindings: () => {},
      log: (m) => logs.push(m),
    };
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("backfills a registered source's documents and stores its turns under its own id", async () => {
    write("chat-1.json", {
      turns: [
        { id: "cur-1", role: "user", text: "rewrite the auth middleware" },
        {
          id: "cur-2",
          role: "assistant",
          model: "claude-opus-5",
          usage: {
            input_tokens: 100,
            output_tokens: 40,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            cache_write_1h_tokens: 0,
            web_search_requests: 0,
          },
        },
      ],
    });
    const engine = new CaptureEngine(deps);
    await engine.start();
    engine.stop();

    expect(engine.turns.get("cur-2")?.source).toBe("cursor");
    const session = engine.sessions().find((s) => s.id === SESSION);
    expect(session?.source).toBe("cursor");
    // The first prompt names the session, exactly as it does for the two
    // native rails — the descriptor doesn't have to supply a title.
    expect(session?.title).toBe("rewrite the auth middleware");
  });

  it("only re-parses a document when it changes, and converges when it does", async () => {
    let parses = 0;
    const counting = fakeSource();
    const source = { ...counting, parse: (p: string, i: SourceIo) => (parses++, counting.parse(p, i)) };
    deps.sources = [source];
    write("chat-1.json", { turns: [{ id: "cur-1", role: "assistant", model: "claude-opus-5" }] });

    const engine = new CaptureEngine(deps);
    await engine.start();
    expect(parses).toBe(1);

    // Untouched: the size+mtime cursor skips it.
    await engine.scan();
    expect(parses).toBe(1);

    // Appended: re-parsed WHOLE, and stable ids mean the old turn is not
    // duplicated while the new one lands.
    write("chat-1.json", {
      turns: [
        { id: "cur-1", role: "assistant", model: "claude-opus-5" },
        { id: "cur-2", role: "assistant", model: "claude-opus-5" },
      ],
    });
    await engine.scan();
    engine.stop();
    expect(parses).toBe(2);
    expect(engine.turns.size).toBe(2);
  });

  it("runs the detectors and the flow rules over a source's units, stamped with its rail", async () => {
    write("chat-1.json", {
      turns: [{ id: "cur-1", role: "assistant", model: "claude-opus-5" }],
      command: "printenv",
    });
    const engine = new CaptureEngine(deps);
    await engine.start();
    engine.stop();

    const row = [...engine.ledger.values()].find((r) => r.detector === "env_dump");
    expect(row).toBeDefined();
    expect(row?.source).toBe("cursor");
    expect(row?.session_id).toBe(SESSION);
    expect(row?.origin).toBe("transcript");
  });

  it("a parser that throws costs its own document and nothing else", async () => {
    const boom = fakeSource({
      parse: (path, io) => {
        if (path.endsWith("bad.json")) throw new Error("half-written row");
        return fakeSource().parse(path, io);
      },
    });
    deps.sources = [boom];
    write("bad.json", { turns: [] });
    write("good.json", { turns: [{ id: "cur-ok", role: "assistant", model: "claude-opus-5" }] });

    const engine = new CaptureEngine(deps);
    await engine.start();
    engine.stop();

    expect(engine.turns.has("cur-ok")).toBe(true);
    expect(logs.some((l) => l.includes("half-written row"))).toBe(true);
    // The engine is still watching, not dead.
    expect(engine.status).toBe("watching");
  });

  it("a source whose host is absent is neither read nor reported as present", async () => {
    deps.sources = [
      fakeSource({
        presencePaths: [".not-installed"],
        roots: (home) => [join(home, ".not-installed", "chats")],
      }),
    ];
    write("chat-1.json", { turns: [{ id: "cur-1", role: "assistant", model: "claude-opus-5" }] });
    const engine = new CaptureEngine(deps);
    await engine.start();
    engine.stop();

    expect(engine.presentSources()).toHaveLength(0);
    expect(engine.turns.size).toBe(0);
    expect(engine.sourceIndex().find((s) => s.id === "cursor")?.present).toBe(false);
  });

  // A host whose data directory is relocated by its own env var (Grok's
  // GROK_HOME) leaves no home-relative marker, so an existing ROOT counts as
  // presence too — otherwise the rail would read as not installed while the
  // engine had sessions in front of it.
  it("an existing root proves presence even when no presence path does", async () => {
    deps.sources = [fakeSource({ presencePaths: [".not-installed"] })];
    write("chat-1.json", { turns: [{ id: "cur-1", role: "assistant", model: "claude-opus-5" }] });
    const engine = new CaptureEngine(deps);
    await engine.start();
    engine.stop();

    expect(engine.presentSources()).toHaveLength(1);
    expect(engine.turns.has("cur-1")).toBe(true);
    expect(engine.sourceIndex().find((s) => s.id === "cursor")?.present).toBe(true);
  });

  it("reports every rail — the two native ones and the registry's — for the snapshot", async () => {
    const engine = new CaptureEngine(deps);
    await engine.start();
    engine.stop();
    expect(engine.sourceIndex().map((s) => s.id)).toEqual(["claude-code", "codex", "cursor"]);
    expect(engine.sourceIndex().find((s) => s.id === "cursor")).toMatchObject({
      label: "Cursor",
      present: true,
      metered: true,
    });
  });
});
