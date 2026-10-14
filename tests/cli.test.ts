import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { describe, expect, it } from "vitest";

import { VERSION } from "../src/server.js";
import pkg from "../package.json" with { type: "json" };

const root = join(import.meta.dirname, "..");
const entry = ["--import", "tsx", join(root, "src/index.ts")];
const run = (args: string[], env: Record<string, string | undefined> = {}) =>
  spawnSync(process.execPath, [...entry, ...args], { cwd: root, encoding: "utf8", env: { PATH: process.env.PATH ?? "", ...env } as NodeJS.ProcessEnv, timeout: 30_000 });

describe("command line", () => {
  it("keeps the code version in sync with package.json", () => {
    expect(VERSION).toBe(pkg.version);
  });

  it("prints help and version on stdout", () => {
    const help = run(["--help"]);
    expect(help.status).toBe(0);
    expect(help.stdout).toContain("Usage:");
    expect(help.stdout).toContain("OPS_MCP_ALLOW_PRIVATE");
    expect(run(["--version"]).stdout.trim()).toBe(VERSION);
  });

  it("rejects unknown options", () => {
    const result = run(["--nope"]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/Unknown option/i);
  });

  it("refuses to serve HTTP without a strong token", () => {
    for (const env of [{}, { OPS_MCP_HTTP_TOKEN: "short" }]) {
      const result = run(["--http"], env);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("OPS_MCP_HTTP_TOKEN");
      expect(result.stdout).toBe("");
    }
  });

  it("rejects an invalid port and invalid configuration with clear messages", () => {
    expect(run(["--http", "--port", "99999"], { OPS_MCP_HTTP_TOKEN: "x".repeat(32) }).status).toBe(2);
    const bad = run([], { OPS_MCP_RATE_PER_MINUTE: "0" });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain("OPS_MCP_RATE_PER_MINUTE");
  });
});

describe("stdio server (the real process)", () => {
  it("speaks clean MCP on stdout, enforces policy and writes the audit log", async () => {
    const { mkdtemp, readFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const dir = await mkdtemp(join(tmpdir(), "ops-mcp-cli-"));
    const auditPath = join(dir, "audit.jsonl");

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: entry,
      cwd: root,
      env: { PATH: process.env.PATH ?? "", OPS_MCP_AUDIT_LOG: auditPath, OPS_MCP_RATE_PER_MINUTE: "30" },
      stderr: "pipe",
    });
    const stderr: string[] = [];
    transport.stderr?.on("data", (chunk) => stderr.push(String(chunk)));

    const client = new Client({ name: "cli-test", version: "1.0.0" });
    await client.connect(transport); // would fail if anything but JSON-RPC were written to stdout
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(8);

      const blocked = (await client.callTool({ name: "http_probe", arguments: { url: "http://127.0.0.1:8080/" } })) as { isError?: boolean; structuredContent?: Record<string, unknown> };
      expect(blocked.isError).toBe(true);
      expect(blocked.structuredContent?.error).toBe("policy_blocked_address");

      const dns = (await client.callTool({ name: "dns_lookup", arguments: { name: "intranet.corp" } })) as { structuredContent?: Record<string, unknown> };
      expect(dns.structuredContent?.error).toBe("policy_internal_name");
    } finally {
      await client.close();
    }

    expect(stderr.join("")).toContain("stdio server ready");
    expect(stderr.join("")).not.toContain("PRIVATE TARGETS ALLOWED");

    const lines = (await readFile(auditPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    expect(lines.map((l) => [l.tool, l.ok])).toEqual([["http_probe", false], ["dns_lookup", false]]);
  }, 60_000);
});
