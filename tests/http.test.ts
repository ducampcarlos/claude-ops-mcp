import { request, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { MAX_REQUEST_BYTES, createHttpServer, hostAllowed, tokenMatches } from "../src/http.js";
import { AuditLog } from "../src/security/audit.js";
import { createRuntime } from "../src/runtime.js";
import { FakeDns, fakeLookup, startServer, testConfig, type TestServer } from "./helpers.js";

const TOKEN = "t".repeat(40);

let http: Server;
let base: string;
let target: TestServer | undefined;

beforeEach(async () => {
  const runtime = createRuntime(testConfig(), {
    lookup: fakeLookup().lookup,
    dns: new FakeDns({}),
    connectAddress: () => "127.0.0.1",
    audit: new AuditLog(undefined),
  });
  http = createHttpServer(runtime, { token: TOKEN, allowedHosts: ["ops.example.org"] });
  await new Promise<void>((resolve) => http.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => {
    http.closeAllConnections();
    http.close(() => resolve());
  });
  await target?.close();
  target = undefined;
});

const rpc = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
const post = (path: string, init: { token?: string | null; body?: string; host?: string; method?: string } = {}) =>
  new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
    const url = new URL(base + path);
    const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream" };
    if (init.token !== null) headers.authorization = `Bearer ${init.token ?? TOKEN}`;
    if (init.host) headers.host = init.host;
    const req = request({ hostname: url.hostname, port: url.port, path: url.pathname, method: init.method ?? "POST", headers }, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end(init.body ?? JSON.stringify(rpc));
  });

describe("authentication and routing", () => {
  it("serves /healthz without authentication", async () => {
    const r = await post("/healthz", { token: null, method: "GET", body: "" });
    expect(r.status).toBe(200);
    expect(JSON.parse(r.body)).toMatchObject({ status: "ok" });
  });

  it("rejects missing, malformed and wrong tokens with 401", async () => {
    for (const token of [null, "", "wrong-token", TOKEN.slice(0, -1), `${TOKEN}x`]) {
      const r = await post("/mcp", { token });
      expect(r.status, String(token)).toBe(401);
      expect(r.headers["www-authenticate"]).toMatch(/Bearer/);
      expect(r.body).not.toContain(TOKEN);
    }
  });

  it("only accepts the Bearer scheme", () => {
    expect(tokenMatches(`Bearer ${TOKEN}`, TOKEN)).toBe(true);
    expect(tokenMatches(`bearer ${TOKEN}`, TOKEN)).toBe(true);
    expect(tokenMatches(TOKEN, TOKEN)).toBe(false);
    expect(tokenMatches(`Basic ${TOKEN}`, TOKEN)).toBe(false);
    expect(tokenMatches(undefined, TOKEN)).toBe(false);
  });

  it("rejects unexpected Host headers (DNS rebinding) even with a valid token", async () => {
    for (const host of ["evil.example.com", "evil.example.com:3333", "127.0.0.1.evil.com"]) {
      const r = await post("/mcp", { host });
      expect(r.status, host).toBe(403);
    }
    expect((await post("/mcp", { host: "ops.example.org:443" })).status).toBe(200);
    expect((await post("/mcp", { host: "localhost:3333" })).status).toBe(200);
  });

  it("parses Host headers including IPv6 literals", () => {
    const allowed = new Set(["localhost", "[::1]"]);
    expect(hostAllowed("[::1]:3333", allowed)).toBe(true);
    expect(hostAllowed("LOCALHOST", allowed)).toBe(true);
    expect(hostAllowed(undefined, allowed)).toBe(false);
    expect(hostAllowed("[::2]", allowed)).toBe(false);
  });

  it("is POST-only and only serves /mcp", async () => {
    const get = await post("/mcp", { method: "GET", body: "" });
    expect(get.status).toBe(405);
    expect(get.headers.allow).toBe("POST");
    expect((await post("/mcp", { method: "DELETE", body: "" })).status).toBe(405);
    expect((await post("/other")).status).toBe(404);
    expect((await post("/")).status).toBe(404);
  });

  it("adds no CORS headers, so web pages cannot call it", async () => {
    const r = await post("/mcp");
    expect(Object.keys(r.headers).filter((h) => h.startsWith("access-control-"))).toEqual([]);
  });

  it("validates the request body", async () => {
    expect((await post("/mcp", { body: "{not json" })).status).toBe(400);
    const big = await post("/mcp", { body: JSON.stringify({ ...rpc, padding: "x".repeat(MAX_REQUEST_BYTES + 10) }) }).catch((e: NodeJS.ErrnoException) => e);
    // The server may close the socket as soon as the limit is hit, which surfaces as a reset.
    if (big instanceof Error) expect(["ECONNRESET", "EPIPE"]).toContain((big as NodeJS.ErrnoException).code);
    else expect(big.status).toBe(413);
  });
});

describe("MCP over HTTP", () => {
  const connect = async () => {
    const client = new Client({ name: "http-test", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } });
    await client.connect(transport);
    return client;
  };

  it("lists tools and runs a probe end to end", async () => {
    target = await startServer((_req, res) => void res.writeHead(200, { "content-type": "text/html" }).end("<title>over http</title>"));
    const client = await connect();
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(8);
      const result = (await client.callTool({ name: "http_probe", arguments: { url: `http://public.test:${target.port}/` } })) as { structuredContent?: Record<string, unknown> };
      expect(result.structuredContent).toMatchObject({ status: 200, title: "over http" });
    } finally {
      await client.close();
    }
  });

  it("is stateless: independent clients work concurrently and no session id is issued", async () => {
    const [a, b] = await Promise.all([connect(), connect()]);
    try {
      const [ta, tb] = await Promise.all([a.listTools(), b.listTools()]);
      expect(ta.tools.length).toBe(tb.tools.length);
      const raw = await post("/mcp");
      expect(raw.headers["mcp-session-id"]).toBeUndefined();
    } finally {
      await Promise.all([a.close(), b.close()]);
    }
  });

  it("enforces policy over HTTP exactly as over stdio", async () => {
    const client = await connect();
    try {
      const result = (await client.callTool({ name: "http_probe", arguments: { url: "http://169.254.169.254/latest/meta-data/" } })) as { isError?: boolean; structuredContent?: Record<string, unknown> };
      expect(result.isError).toBe(true);
      expect(result.structuredContent?.error).toBe("policy_blocked_address");
    } finally {
      await client.close();
    }
  });
});
