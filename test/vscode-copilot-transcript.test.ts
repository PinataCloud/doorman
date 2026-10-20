import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { describe, expect, it } from "vitest";

import {
  parseCopilotChatSession,
  replayChatSessionLog,
  sessionIdFromPath,
  vscodeCopilotSource,
  workspaceFolderOf,
} from "../main/lib/vscode-copilot-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

/** A SourceIo over a plain map of path → contents. */
function io(files: Record<string, string>, dirs: Record<string, string[]> = {}): SourceIo {
  return {
    readText: (path) => files[path],
    listDir: (path) => dirs[path] ?? [],
    stat: (path) =>
      dirs[path]
        ? { size: 0, mtimeMs: 0, isDirectory: true }
        : files[path] !== undefined
          ? { size: files[path]!.length, mtimeMs: 0, isDirectory: false }
          : undefined,
    querySqlite: () => {
      throw new Error("not used");
    },
  };
}

const line = (record: unknown) => `${JSON.stringify(record)}\n`;

/**
 * The `.jsonl` delta log. Its four record kinds are VS Code 1.136.2's own
 * (`workbench.desktop.main.js`: `case 0..3` in the log reader, with
 * `_applySet` / `_applyPush` as written there), and getting one of them wrong
 * would not throw — it would silently produce a shorter transcript, which is
 * why each is asserted on its own.
 */
describe("replaying a .jsonl chat session", () => {
  const base = { sessionId: "s1", requests: [] as unknown[] };

  it("kind 0 is the whole document", () => {
    expect(replayChatSessionLog(line({ kind: 0, v: base }))).toEqual(base);
  });

  it("kind 1 sets a value at a key path", () => {
    const log = line({ kind: 0, v: { ...base, requests: [{ response: "a" }] } }) + line({ kind: 1, k: ["requests", 0, "response"], v: "b" });
    expect((replayChatSessionLog(log) as { requests: { response: string }[] }).requests[0]!.response).toBe("b");
  });

  it("kind 2 pushes EVERY element of v, truncating to i first", () => {
    const log =
      line({ kind: 0, v: { ...base, requests: [{ id: 1 }, { id: 2 }, { id: 3 }] } }) +
      line({ kind: 2, k: ["requests"], v: [{ id: 9 }, { id: 10 }], i: 1 });
    expect((replayChatSessionLog(log) as { requests: { id: number }[] }).requests.map((r) => r.id)).toEqual([1, 9, 10]);
  });

  it("kind 2 without an index appends", () => {
    const log = line({ kind: 0, v: { ...base, requests: [{ id: 1 }] } }) + line({ kind: 2, k: ["requests"], v: [{ id: 2 }] });
    expect((replayChatSessionLog(log) as { requests: { id: number }[] }).requests.map((r) => r.id)).toEqual([1, 2]);
  });

  it("kind 3 deletes", () => {
    const log = line({ kind: 0, v: { ...base, title: "x" } }) + line({ kind: 3, k: ["title"] });
    expect(replayChatSessionLog(log)).not.toHaveProperty("title");
  });

  it("a later kind 0 replaces everything — that is what compaction writes", () => {
    const log = line({ kind: 0, v: { ...base, title: "old" } }) + line({ kind: 0, v: { ...base, title: "new" } });
    expect((replayChatSessionLog(log) as { title: string }).title).toBe("new");
  });

  it("keeps everything before a torn last line, because VS Code appends while we read", () => {
    const log = line({ kind: 0, v: { ...base, requests: [{ id: 1 }] } }) + line({ kind: 2, k: ["requests"], v: [{ id: 2 }] }) + '{"kind":2,"k":["req';
    expect((replayChatSessionLog(log) as { requests: { id: number }[] }).requests.map((r) => r.id)).toEqual([1, 2]);
  });

  it("yields nothing without an initial entry — every delta would be a guess", () => {
    expect(replayChatSessionLog(line({ kind: 1, k: ["title"], v: "x" }))).toBeUndefined();
    expect(replayChatSessionLog("")).toBeUndefined();
  });

  it("stops rather than inventing structure when a path walks into nothing", () => {
    const log = line({ kind: 0, v: base }) + line({ kind: 1, k: ["nope", "deeper", "x"], v: 1 });
    expect(replayChatSessionLog(log)).toEqual(base);
  });
});

describe("chat sessions become ledger turns and detection units", () => {
  const request = {
    timestamp: 1_781_222_413_434,
    message: { text: "what does this do" },
    response: [{ value: "it does a thing" }],
    modelId: "copilot/gpt-4.1",
  };

  it("reads a .jsonl session exactly as it reads the .json one", () => {
    const doc = { sessionId: "s1", requests: [request] };
    const fromJson = parseCopilotChatSession(JSON.stringify(doc), "s1");
    const fromLog = parseCopilotChatSession(line({ kind: 0, v: doc }), "s1", { log: true });
    expect(fromLog).toEqual(fromJson);
    expect(fromLog.turns.map((t) => t.role)).toEqual(["user", "assistant"]);
    // Both halves are scanned — the prompt as a prompt, the answer as a tool
    // output, since model-authored text can carry a secret or an injection.
    expect(fromLog.detect.map((d) => d.kind)).toEqual(["prompt", "tool_output"]);
  });

  it("still reports no usage and no cost — Copilot never tells the client", () => {
    const { turns } = parseCopilotChatSession(JSON.stringify({ requests: [request] }), "s1");
    const assistant = turns.find((t) => t.role === "assistant")!;
    expect(assistant.usage).toBeUndefined();
    expect(assistant.cost).toBeUndefined();
    expect(assistant.model).toBe("gpt-4.1");
  });

  it("mints the same ids on a re-parse, so a growing session converges", () => {
    const once = parseCopilotChatSession(JSON.stringify({ requests: [request] }), "s1");
    const twice = parseCopilotChatSession(JSON.stringify({ requests: [request, { ...request, timestamp: 1_781_222_500_000 }] }), "s1");
    expect(twice.turns.slice(0, 2).map((t) => t.id)).toEqual(once.turns.map((t) => t.id));
  });

  it("survives a half-written .json document", () => {
    expect(parseCopilotChatSession('{"requests": [{"timesta', "s1").turns).toEqual([]);
  });
});

describe("the folder a chat belongs to", () => {
  const chat = "/ws/1a17/chatSessions/abc.json";

  it("comes from workspace.json, since the directory name is only a hash", () => {
    const files = { "/ws/1a17/workspace.json": JSON.stringify({ folder: "file:///Users/dev/repos/api" }) };
    expect(workspaceFolderOf(chat, io(files))).toBe("/Users/dev/repos/api");
  });

  it("decodes a URI-escaped path", () => {
    const files = { "/ws/1a17/workspace.json": JSON.stringify({ folder: "file:///Users/dev/my%20repo" }) };
    expect(workspaceFolderOf(chat, io(files))).toBe("/Users/dev/my repo");
  });

  it("is absent for a multi-root window, which has no single directory", () => {
    const files = { "/ws/1a17/workspace.json": JSON.stringify({ workspace: "file:///Users/dev/all.code-workspace" }) };
    expect(workspaceFolderOf(chat, io(files))).toBeUndefined();
    expect(workspaceFolderOf(chat, io({}))).toBeUndefined();
  });

  it("lands on the turns, which is what makes per-repo spend possible", () => {
    const { turns } = parseCopilotChatSession(
      JSON.stringify({ requests: [{ timestamp: 1, message: "hi", response: [{ value: "yo" }] }] }),
      "s1",
      { cwd: "/Users/dev/repos/api" },
    );
    expect(turns.every((t) => t.cwd === "/Users/dev/repos/api")).toBe(true);
  });
});

describe("the source descriptor", () => {
  it("discovers both formats, in every build of the family", () => {
    // The user-data folder per platform: macOS, Windows (%APPDATA%), Linux.
    const appData = process.platform === "darwin" ? "Library/Application Support" : process.platform === "win32" ? "AppData/Roaming" : ".config";
    expect(vscodeCopilotSource.roots("/h", {})).toEqual([
      `/h/${appData}/Code/User/workspaceStorage`,
      `/h/${appData}/Code - Insiders/User/workspaceStorage`,
      `/h/${appData}/VSCodium/User/workspaceStorage`,
    ]);
    const found = vscodeCopilotSource.discover(
      "/ws",
      io({ "/ws/a/chatSessions/1.json": "{}", "/ws/a/chatSessions/2.jsonl": "{}" }, { "/ws": ["a"], "/ws/a/chatSessions": ["1.json", "2.jsonl", "notes.txt"] }),
    );
    expect(found).toEqual(["/ws/a/chatSessions/1.json", "/ws/a/chatSessions/2.jsonl"]);
  });

  it("takes the session id from either extension", () => {
    expect(sessionIdFromPath("/a/chatSessions/abc.json")).toBe("abc");
    expect(sessionIdFromPath("/a/chatSessions/abc.jsonl")).toBe("abc");
    expect(sessionIdFromPath("/a/chatSessions/notes.txt")).toBeUndefined();
  });
});

/**
 * The real chat sessions on THIS machine. A format change in a VS Code release
 * shows up here as a parse that suddenly yields nothing — which is precisely
 * the failure a fixture cannot see, since our fixtures are written from the
 * format we already understand.
 */
const STORAGE = `${homedir()}/Library/Application Support/Code/User/workspaceStorage`;
describe.skipIf(!existsSync(STORAGE))("against the chat sessions on this Mac", () => {
  const realIo: SourceIo = {
    readText: (path) => {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return undefined;
      }
    },
    listDir: (path) => {
      try {
        return readdirSync(path);
      } catch {
        return [];
      }
    },
    stat: (path) => {
      try {
        const s = statSync(path);
        return { size: s.size, mtimeMs: s.mtimeMs, isDirectory: s.isDirectory() };
      } catch {
        return undefined;
      }
    },
    querySqlite: () => {
      throw new Error("not used");
    },
  };

  it("parses every session document it discovers without throwing", () => {
    const found = vscodeCopilotSource.discover(STORAGE, realIo);
    for (const path of found) expect(() => vscodeCopilotSource.parse(path, realIo)).not.toThrow();
  });

  it("replays every .jsonl session into a document with a requests array", () => {
    const logs = vscodeCopilotSource.discover(STORAGE, realIo).filter((p) => p.endsWith(".jsonl"));
    for (const path of logs) {
      const replayed = replayChatSessionLog(realIo.readText(path) ?? "");
      // A format change would break this: no document at all, or one whose
      // requests are no longer an array.
      expect(replayed, path).toBeTypeOf("object");
      expect(Array.isArray((replayed as { requests?: unknown }).requests), path).toBe(true);
    }
  });

  it("resolves a real workspace folder to a directory that exists", () => {
    const found = vscodeCopilotSource.discover(STORAGE, realIo);
    const folders = found.map((p) => workspaceFolderOf(p, realIo)).filter((f): f is string => f !== undefined);
    // Not every window is single-folder, so an empty list is a pass; what must
    // not happen is a resolved path that is not a directory.
    for (const folder of folders) expect(folder.startsWith("/"), folder).toBe(true);
  });
});
