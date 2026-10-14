/**
 * Streamable HTTP transport, stateless: every request gets a fresh MCP server instance, so there
 * are no sessions to hijack or leak. Protections:
 *   - Bearer token (constant-time comparison) on /mcp
 *   - Host-header allow-list against DNS rebinding
 *   - 1 MB request body cap, POST only
 *   - no CORS headers, so browsers can't call it from arbitrary pages
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { type IncomingMessage, type Server, type ServerResponse, createServer } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import type { Runtime } from "./runtime.js";
import { VERSION, createOpsServer } from "./server.js";

export const MAX_REQUEST_BYTES = 1_000_000;

export interface HttpOptions {
  token: string;
  /** Host names (without port) accepted in the Host header, in addition to loopback names. */
  allowedHosts?: string[];
}

const digest = (value: string) => createHash("sha256").update(value).digest();

export function tokenMatches(provided: string | undefined, expected: string): boolean {
  if (!provided) return false;
  const match = /^Bearer\s+(.+)$/i.exec(provided.trim());
  if (!match) return false;
  return timingSafeEqual(digest(match[1]!), digest(expected));
}

export function hostAllowed(hostHeader: string | undefined, allowed: Set<string>): boolean {
  if (!hostHeader) return false;
  const host = hostHeader.startsWith("[") ? hostHeader.slice(0, hostHeader.indexOf("]") + 1) : hostHeader.split(":")[0]!;
  return allowed.has(host.toLowerCase());
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(payload), "cache-control": "no-store", ...headers });
  res.end(payload);
}

const rpcError = (code: number, message: string) => ({ jsonrpc: "2.0", error: { code, message }, id: null });

async function readJson(req: IncomingMessage): Promise<{ ok: true; body: unknown } | { ok: false; status: number; message: string }> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_REQUEST_BYTES) return { ok: false, status: 413, message: "Request body too large" };
    chunks.push(chunk as Buffer);
  }
  try {
    return { ok: true, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) };
  } catch {
    return { ok: false, status: 400, message: "Request body is not valid JSON" };
  }
}

export function createHttpServer(runtime: Runtime, options: HttpOptions): Server {
  const allowedHosts = new Set(["localhost", "127.0.0.1", "[::1]", ...(options.allowedHosts ?? []).map((h) => h.toLowerCase())]);

  return createServer(async (req, res) => {
    try {
      const path = new URL(req.url ?? "/", "http://placeholder").pathname;

      if (path === "/healthz" && req.method === "GET") return send(res, 200, { status: "ok", version: VERSION });

      if (!hostAllowed(req.headers.host, allowedHosts)) {
        return send(res, 403, rpcError(-32000, "Host not allowed. Set OPS_MCP_HTTP_ALLOWED_HOSTS to the public host name."));
      }
      if (path !== "/mcp") return send(res, 404, rpcError(-32000, "Not found"));
      if (!tokenMatches(req.headers.authorization, options.token)) {
        return send(res, 401, rpcError(-32001, "Unauthorized"), { "www-authenticate": 'Bearer realm="claude-ops-mcp"' });
      }
      if (req.method !== "POST") return send(res, 405, rpcError(-32000, "Method not allowed"), { allow: "POST" });

      const parsed = await readJson(req);
      if (!parsed.ok) return send(res, parsed.status, rpcError(-32700, parsed.message));

      const server = createOpsServer(runtime);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, parsed.body);
    } catch (error) {
      process.stderr.write(`[claude-ops-mcp] http error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
      if (!res.headersSent) send(res, 500, rpcError(-32603, "Internal server error"));
      else res.end();
    }
  });
}
