#!/usr/bin/env node
/**
 * claude-ops-mcp entry point.
 *
 *   claude-ops-mcp                          stdio (for Claude Code / Claude Desktop)
 *   claude-ops-mcp --http [--port 3333]     Streamable HTTP (needs OPS_MCP_HTTP_TOKEN)
 *
 * stdout is reserved for the protocol in stdio mode, so everything human-readable goes to stderr.
 */

import { parseArgs } from "node:util";

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { loadConfig } from "./config.js";
import { createHttpServer } from "./http.js";
import { createRuntime } from "./runtime.js";
import { VERSION, createOpsServer } from "./server.js";

const HELP = `claude-ops-mcp ${VERSION}: read-only network diagnostics for Claude

Usage:
  claude-ops-mcp [--http] [--host 127.0.0.1] [--port 3333]

Options:
  --http          Serve Streamable HTTP at /mcp instead of stdio (requires OPS_MCP_HTTP_TOKEN)
  --host <addr>   Bind address for --http (default 127.0.0.1)
  --port <n>      Port for --http (default 3333)
  -h, --help      Show this help
  -v, --version   Show the version

Environment (all optional):
  OPS_MCP_ALLOW_PRIVATE=1        allow loopback/private targets (off by default: SSRF protection)
  OPS_MCP_ALLOW_HOSTS=a.com,*.b.com   only these hosts may be probed
  OPS_MCP_DENY_HOSTS=...         hosts that must never be probed
  OPS_MCP_ALLOWED_PORTS=80,443,8080,8443 | any
  OPS_MCP_RATE_PER_MINUTE=60     tool calls per minute
  OPS_MCP_MAX_CONCURRENT=4       simultaneous tool calls
  OPS_MCP_TIMEOUT_MS=10000       per-request timeout
  OPS_MCP_MAX_BODY_BYTES=1000000 max bytes read from any response
  OPS_MCP_MAX_REDIRECTS=10
  OPS_MCP_MAX_SITEMAP_CHECKS=100
  OPS_MCP_AUDIT_LOG=/path/audit.jsonl   JSONL audit log of every call
  OPS_MCP_HTTP_TOKEN=...         bearer token for --http (16+ characters)
  OPS_MCP_HTTP_ALLOWED_HOSTS=ops.example.com   extra Host header values for --http
`;

const log = (message: string) => process.stderr.write(`[claude-ops-mcp] ${message}\n`);

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      http: { type: "boolean", default: false },
      host: { type: "string", default: "127.0.0.1" },
      port: { type: "string", default: "3333" },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
    strict: true,
  });

  if (values.help) return void process.stdout.write(HELP);
  if (values.version) return void process.stdout.write(`${VERSION}\n`);

  const config = loadConfig();
  const runtime = createRuntime(config);

  const shutdown = async (signal: string) => {
    log(`${signal} received, shutting down`);
    await runtime.audit.flush();
    process.exit(0);
  };
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));

  if (!values.http) {
    const server = createOpsServer(runtime);
    await server.connect(new StdioServerTransport());
    log(`stdio server ready (v${VERSION})${config.allowPrivateTargets ? "; PRIVATE TARGETS ALLOWED" : ""}`);
    return;
  }

  const token = process.env.OPS_MCP_HTTP_TOKEN ?? "";
  if (token.length < 16) {
    log("OPS_MCP_HTTP_TOKEN must be set to a secret of at least 16 characters to use --http. Generate one with: openssl rand -hex 32");
    process.exit(2);
  }
  const port = Number(values.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    log(`Invalid --port "${values.port}"`);
    process.exit(2);
  }
  const host = values.host as string;
  const allowedHosts = [host, ...(process.env.OPS_MCP_HTTP_ALLOWED_HOSTS ?? "").split(",").map((h) => h.trim()).filter(Boolean)];
  const server = createHttpServer(runtime, { token, allowedHosts });
  await new Promise<void>((resolve) => server.listen(port, host, resolve));
  log(`HTTP server listening on http://${host}:${port}/mcp (v${VERSION})`);
  if (!["127.0.0.1", "::1", "localhost"].includes(host)) {
    log("WARNING: bound to a non-loopback address. This server speaks plain HTTP: put it behind a TLS-terminating reverse proxy.");
  }
}

main().catch((error: unknown) => {
  log(`fatal: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
