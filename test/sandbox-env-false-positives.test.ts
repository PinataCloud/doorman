import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { detectSecurityFindings } from "../main/guard/security-detect.js";

/**
 * Inside a Docker Sandbox (`sbx`) the environment carries the policy proxy's
 * public CA certificate as base64 (`PROXY_CA_CERT_B64`) and placeholder
 * credentials the proxy swaps for real ones. An agent running `env` there must
 * not raise a finding on any of it, or every sandbox session flags itself.
 */

// A real self-signed certificate (`openssl req -x509 -newkey rsa:2048 -nodes
// -subj /CN=test -days 1 | base64`): public material, safe to commit.
const CERT_B64 =
  "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNtakNDQVlJQ0NRQysyWW9yY0tHb3JUQU5CZ2txaGtpRzl3MEJBUXNGQURBUE1RMHdDd1lEVlFRRERBUjAKWlhOME1CNFhEVEkyTVRBeU1ERXpNREF5TmxvWERUSTJNVEF5TVRFek1EQXlObG93RHpFTk1Bc0dBMVVFQXd3RQpkR1Z6ZERDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTGg1a28zQlk1ZnFDODcrCmgzeEY1TXhpSUJPdDhCMGZGRWtXblVMTytWRnJZVzB1RGVia0lrb1VkU1VtaFJIOXF1VDNMQlRVTmVIM2hqNm4Kekp1bHBaekY4MkNTczRlS2ZwNklWbURPbnpGNCt2YkFpUHo3QythSC9BMmJMT1duMHJmbUdxQ0x4ejY2djlGegpRb29xV1c1OVhHRHlFTDF1a1oxUUxaNzZLdG5mNTQ1M1JwakZiOWNNQ1l6SkEzVThCSzJvWTd0QWdPNzNydXpxCkJQcXdWN0ZjcUNQdnNWeUFGRXpFMU9hL2picGl6OTJyS0hSdUZkTG0yTC9zTEVSUEh2RWF6Vk83VXVjbzF1VGwKZDBFRXdIa0RFNkhZSHV4U3U3SFphRGNIYnJ1bG1Mc3p1OFJ5eUdVUnJhY3JJSjd6UFhwWkt0bU12b3JwNWtXeApOZENLbzhzQ0F3RUFBVEFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBTnBTU0FsQ0RaQzdxeGRZa1phYW5SYnN1Clo4eklEZGFnYS9vd0h0am95N0dVS2w2dUxCMUMwVkZ1cWUrMEQ0UEFrY1lncENWQ3ZaSTVObU15WUtBT1VVZXcKRm9iVDJVa3hLRzR3VElzUFhyUnpqRmpBd2Z4Yi9EdmVmQ29FbWE1R3NQQU0xWjZSWkNQSy9JUWxmN1hlREFiTQp5TUVuSjJDblU1WldqY2U2b2o4QURBZHJRYWdDMEJEUWJRRng3MXZlSXJUTjRXZlA1YTFYdEE2Nzg0cElrRVJqCmU0bWw4RlBvdmRCUjlmNDFRYXltVE1pT0ZRRm5WU1RTQ1dPS1U2dGd5R1IxYzFaMXVtU3JnVWswKzF2aFR3WGsKNGlpODFSaTh5Q1F1K08xbXhhM3NzZHVGdndTR1ozT2FNeUZzTFdNanNOUjRNS1dCOVFQZUJveWw0S3V1dFE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==";

/** What `env` prints inside a sandbox, trimmed to the variables that matter. */
const SANDBOX_ENV = [
  "SANDBOX_NAME=doorman",
  "SANDBOX_ID=3f6c1d2e-8a4b-4c7d-9e0f-1a2b3c4d5e6f",
  "WORKSPACE_DIR=/Users/lucas/repos/pinata/doorman",
  "HTTPS_PROXY=http://gateway.docker.internal:3128",
  "NODE_USE_ENV_PROXY=1",
  "GH_TOKEN=gho_sbxproxymanaged000000000000000000000",
  "ANTHROPIC_API_KEY=proxy-managed",
  `PROXY_CA_CERT_B64=${CERT_B64}`,
  "HOME=/home/agent",
  "USER=agent",
  "WAYLAND_DISPLAY=wayland-0",
  "",
].join("\n");

const envOutput = (text: string) => detectSecurityFindings({ kind: "tool_output", text, tool_name: "Bash", target: "env" });

describe("env inside a Docker Sandbox", () => {
  it("raises nothing for the proxy CA certificate or the placeholder credentials", () => {
    expect(envOutput(SANDBOX_ENV)).toEqual([]);
  });

  it("raises nothing when base64 wrapped the certificate at 76 columns", () => {
    const wrapped = CERT_B64.replace(/(.{76})/g, "$1\n");
    expect(envOutput(`PROXY_CA_CERT_B64=\n${wrapped}\nHOME=/home/agent\n`)).toEqual([]);
  });

  it("raises nothing for a public key carried as base64", () => {
    const { publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    expect(envOutput(`SIGNING_PUBKEY_B64=${Buffer.from(publicKey).toString("base64")}\n`)).toEqual([]);
  });

  it("still flags a base64-encoded private key", () => {
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const detectors = envOutput(`DEPLOY_KEY_B64=${Buffer.from(privateKey).toString("base64")}\n`).map((f) => f.detector);
    expect(detectors).toContain("unrecognized_secret");
  });

  it("still flags an unknown token printed right after the certificate", () => {
    const token = "Zq8Lm2Xv9Kd4Rt7Yw1Pn5Hs3Jb6Fg0Cc";
    const wrapped = CERT_B64.replace(/(.{76})/g, "$1\n");
    const unwrapped = envOutput(`${SANDBOX_ENV}SESSION_SECRET=${token}\n`).map((f) => f.detector);
    const afterWrapped = envOutput(`PROXY_CA_CERT_B64=\n${wrapped}\n${token}\n`).map((f) => f.detector);
    expect(unwrapped).toContain("unrecognized_secret");
    expect(afterWrapped).toContain("unrecognized_secret");
  });

  it("judges padded base64 whole, not as NAME=value", () => {
    // `=` only ever appears as base64's trailing padding, so these are data,
    // and the part before the `=` is what gets judged.
    for (const padded of ["Zq8Lm2Xv9Kd4Rt7Yw1Pn5Hs3Jb6Fg0Cc=", "Zq8Lm2Xv9Kd4Rt7Yw1Pn5Hs3Jb6Fg0Cc=="]) {
      expect(envOutput(`${padded}\n`).map((f) => f.detector)).toContain("unrecognized_secret");
    }
  });
});
