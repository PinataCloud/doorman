import { describe, expect, it } from "vitest";
import { isTranslocated } from "../main/lib/hook-health.js";

/**
 * A Gatekeeper-translocated launch runs from an ephemeral
 * /private/var/…/AppTranslocation/… mount that is gone after the app quits —
 * anything that records the app's path from there points at nothing later.
 */

const TRANSLOCATED_RUNTIME =
  "/private/var/folders/zh/ts5s/T/AppTranslocation/64E25B04-195A-4307-9CF5-068F2EA0C72E/d/Doorman.app/Contents/MacOS/Doorman";
const HEALTHY_RUNTIME = "/Applications/Doorman.app/Contents/MacOS/Doorman";

describe("isTranslocated", () => {
  it("recognises a Gatekeeper translocation mount and nothing else", () => {
    expect(isTranslocated(TRANSLOCATED_RUNTIME)).toBe(true);
    expect(isTranslocated(HEALTHY_RUNTIME)).toBe(false);
    expect(isTranslocated("/usr/local/bin/node")).toBe(false);
  });
});
