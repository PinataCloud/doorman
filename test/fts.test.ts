import { describe, expect, it } from "vitest";
import { createIndex, indexDocument, searchIndex, tokenize } from "../main/lib/fts.js";

describe("tokenize", () => {
  it("lowercases, splits on non-word runs and drops single chars", () => {
    expect(tokenize("Fix the OAuth2 callback_url!")).toEqual(["fix", "the", "oauth2", "callback_url"]);
    expect(tokenize("a b c")).toEqual([]);
  });
});

describe("searchIndex", () => {
  it("ANDs terms with the trailing term as a prefix", () => {
    const index = createIndex();
    indexDocument(index, "t1", "fix the login bug in oauth");
    indexDocument(index, "t2", "login page styling");
    indexDocument(index, "t3", "unrelated content");

    expect([...searchIndex(index, "login")].sort()).toEqual(["t1", "t2"]);
    expect([...searchIndex(index, "login bu")]).toEqual(["t1"]); // prefix on the last term
    expect([...searchIndex(index, "login zzz")]).toEqual([]);
    expect([...searchIndex(index, "")]).toEqual([]);
  });

  it("is idempotent per document id", () => {
    const index = createIndex();
    indexDocument(index, "t1", "hello world");
    indexDocument(index, "t1", "completely different"); // re-index attempt ignored
    expect([...searchIndex(index, "different")]).toEqual([]);
    expect([...searchIndex(index, "hello")]).toEqual(["t1"]);
  });
});
