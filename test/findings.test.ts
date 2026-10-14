import { describe, expect, it } from "vitest";
import {
  foldFindingLines,
  mergeFinding,
  mintFindingRow,
  summarizeFindings,
  type FindingRow,
} from "../main/lib/findings.js";

const finding = {
  detector: "dotenv_read" as const,
  severity: "high" as const,
  key_name: ".env",
  excerpt: "cat .env",
  occurrences: 2,
};

const context = {
  source: "claude-code" as const,
  origin: "transcript" as const,
  session_id: "s1",
  turn_id: "t1",
  at: "2026-08-20T10:00:00.000Z",
};

describe("mintFindingRow", () => {
  it("mints the same id for the same (detector, session, key) — the upstream rule", () => {
    const a = mintFindingRow(finding, context);
    const b = mintFindingRow(finding, { ...context, origin: "guard", at: "2026-08-21T00:00:00.000Z" });
    expect(a.finding_id).toBe(b.finding_id);
    expect(a.finding_id).toMatch(/^[0-9a-f]{16}$/);
    const other = mintFindingRow(finding, { ...context, session_id: "s2" });
    expect(other.finding_id).not.toBe(a.finding_id);
  });
});

describe("mergeFinding", () => {
  it("is idempotent under re-scans: max occurrences, widened timestamps, status kept", () => {
    const base: FindingRow = { ...mintFindingRow(finding, context), status: "accepted_risk" };
    const rescan = mintFindingRow({ ...finding, occurrences: 2 }, context);
    const merged = mergeFinding(base, rescan);
    expect(merged.occurrences).toBe(2);
    expect(merged.status).toBe("accepted_risk");
    expect(mergeFinding(merged, rescan)).toEqual(merged);

    const later = mintFindingRow({ ...finding, occurrences: 5 }, { ...context, at: "2026-08-22T00:00:00.000Z" });
    const widened = mergeFinding(merged, later);
    expect(widened.occurrences).toBe(5);
    expect(widened.first_seen_at).toBe(context.at);
    expect(widened.last_seen_at).toBe("2026-08-22T00:00:00.000Z");
  });

  it("keeps a model's verdict across re-scans, and lets a newer verdict replace it", () => {
    const stoodDown = { by: "injection_classifier" as const, model: "Llama Prompt Guard 2", verdict: "stood_down" as const, score: 0.04 };
    const judged = mintFindingRow(finding, { ...context, assist: stoodDown });
    expect(judged.assist).toEqual(stoodDown);
    // A re-scan with the model gone (feature off, model removed) says nothing —
    // and erases nothing.
    const plain = mintFindingRow(finding, context);
    expect(plain.assist).toBeUndefined();
    expect(mergeFinding(judged, plain).assist).toEqual(stoodDown);
    // A later look wins.
    const confirmed = { ...stoodDown, verdict: "confirmed" as const, score: 0.9 };
    expect(mergeFinding(judged, mintFindingRow(finding, { ...context, assist: confirmed })).assist).toEqual(confirmed);
  });
});

describe("foldFindingLines", () => {
  it("last state per finding_id wins; malformed lines are skipped", () => {
    const row = mintFindingRow(finding, context);
    const resolved = { ...row, status: "resolved" as const };
    const fold = foldFindingLines([JSON.stringify(row), "garbage", JSON.stringify(resolved), ""]);
    expect(fold.size).toBe(1);
    expect(fold.get(row.finding_id)!.status).toBe("resolved");
  });
});

describe("summarizeFindings", () => {
  it("counts only open rows, by severity and detector, with affected sessions", () => {
    const open = mintFindingRow(finding, context);
    const other = mintFindingRow({ ...finding, detector: "env_dump", key_name: undefined }, { ...context, session_id: "s2" });
    const closed = { ...mintFindingRow(finding, { ...context, session_id: "s3" }), status: "resolved" as const };
    const summary = summarizeFindings([open, other, closed]);
    expect(summary.open).toBe(2);
    expect(summary.by_severity.high).toBe(2);
    expect(summary.by_detector.dotenv_read).toBe(1);
    expect(summary.by_detector.env_dump).toBe(1);
    expect(summary.affected_sessions).toBe(2);
    expect(summary.latest_detected_at).toBe(context.at);
  });
});
