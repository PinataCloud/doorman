import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The app and the CLI each copy the compiled guard into the same folder and
 * tell their own bundle from the other's by its bytes. A Windows checkout with
 * core.autocrlf turned LF into CRLF, so the app's guard (built on Windows) held
 * CRs the CLI's didn't: each read the other's bundle as altered and replaced
 * it. .gitattributes pins LF for every checkout, so every build is the same.
 */
const root = join(__dirname, "..");

describe("line endings", () => {
  it("every tracked file checks out with LF, whatever core.autocrlf says", () => {
    const files = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
    const attrs = execFileSync("git", ["check-attr", "--stdin", "-z", "eol"], { cwd: root, input: files.join("\0"), encoding: "utf8" });
    // -z output: path, attribute, value, repeated.
    const fields = attrs.split("\0");
    const notLf: string[] = [];
    for (let i = 0; i + 2 < fields.length; i += 3) if (fields[i + 2] !== "lf") notLf.push(fields[i]!);
    expect(files.length).toBeGreaterThan(0);
    expect(notLf).toEqual([]);
  });

  it("the compiled guard bundle has no carriage returns", () => {
    const guard = join(root, "build", "main", "guard");
    const withCr = (readdirSync(guard, { recursive: true }) as string[])
      .filter((file) => file.endsWith(".js"))
      .filter((file) => readFileSync(join(guard, file)).includes(0x0d));
    expect(withCr).toEqual([]);
  });
});
