/**
 * Runtime configuration. Everything has a safe default; every relaxation is an explicit,
 * named opt-in (OPS_MCP_*). Nothing here is ever read from tool arguments, so a model (or a
 * prompt injection) can never loosen the limits.
 */

export interface Config {
  /** Allow targets that resolve to loopback / private / link-local ranges. Off by default (SSRF). */
  allowPrivateTargets: boolean;
  /** If non-empty, ONLY these hosts (exact or `*.example.com`) may be probed. */
  allowHosts: string[];
  /** Hosts that must never be probed (exact or `*.example.com`). Evaluated before allowHosts. */
  denyHosts: string[];
  /** TCP ports tools may connect to, or "any". */
  allowedPorts: number[] | "any";
  /** Token-bucket size: tool calls per minute across the whole server. */
  requestsPerMinute: number;
  /** Tool calls running at the same time. */
  maxConcurrentCalls: number;
  /** Per-request network timeout. */
  timeoutMs: number;
  /** Max bytes read from any HTTP response body. */
  maxBodyBytes: number;
  /** Max redirects followed per request. */
  maxRedirects: number;
  /** Max URLs a sitemap audit will actually request. */
  maxSitemapChecks: number;
  /** JSONL audit log path (stdout is reserved for the protocol, so never log there). */
  auditLogPath: string | undefined;
  userAgent: string;
}

export const DEFAULT_PORTS = [80, 443, 8080, 8443];

export const DEFAULTS: Config = {
  allowPrivateTargets: false,
  allowHosts: [],
  denyHosts: [],
  allowedPorts: DEFAULT_PORTS,
  requestsPerMinute: 60,
  maxConcurrentCalls: 4,
  timeoutMs: 10_000,
  maxBodyBytes: 1_000_000,
  maxRedirects: 10,
  maxSitemapChecks: 100,
  auditLogPath: undefined,
  userAgent: "claude-ops-mcp/0.1 (+https://github.com/ducampcarlos/claude-ops-mcp; read-only diagnostics)",
};

type Env = Record<string, string | undefined>;

function bool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === "") return fallback;
  return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}

function list(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function positiveInt(name: string, value: string | undefined, fallback: number, max: number): number {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > max) {
    throw new Error(`${name} must be an integer between 1 and ${max} (got "${value}")`);
  }
  return parsed;
}

function ports(value: string | undefined): number[] | "any" {
  if (value === undefined || value === "") return DEFAULT_PORTS;
  if (value.trim().toLowerCase() === "any") return "any";
  return list(value).map((item) => {
    const port = Number(item);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`OPS_MCP_ALLOWED_PORTS contains an invalid port "${item}"`);
    }
    return port;
  });
}

export function loadConfig(env: Env = process.env): Config {
  return {
    allowPrivateTargets: bool(env.OPS_MCP_ALLOW_PRIVATE, DEFAULTS.allowPrivateTargets),
    allowHosts: list(env.OPS_MCP_ALLOW_HOSTS),
    denyHosts: list(env.OPS_MCP_DENY_HOSTS),
    allowedPorts: ports(env.OPS_MCP_ALLOWED_PORTS),
    requestsPerMinute: positiveInt("OPS_MCP_RATE_PER_MINUTE", env.OPS_MCP_RATE_PER_MINUTE, DEFAULTS.requestsPerMinute, 10_000),
    maxConcurrentCalls: positiveInt("OPS_MCP_MAX_CONCURRENT", env.OPS_MCP_MAX_CONCURRENT, DEFAULTS.maxConcurrentCalls, 64),
    timeoutMs: positiveInt("OPS_MCP_TIMEOUT_MS", env.OPS_MCP_TIMEOUT_MS, DEFAULTS.timeoutMs, 120_000),
    maxBodyBytes: positiveInt("OPS_MCP_MAX_BODY_BYTES", env.OPS_MCP_MAX_BODY_BYTES, DEFAULTS.maxBodyBytes, 50_000_000),
    maxRedirects: positiveInt("OPS_MCP_MAX_REDIRECTS", env.OPS_MCP_MAX_REDIRECTS, DEFAULTS.maxRedirects, 30),
    maxSitemapChecks: positiveInt("OPS_MCP_MAX_SITEMAP_CHECKS", env.OPS_MCP_MAX_SITEMAP_CHECKS, DEFAULTS.maxSitemapChecks, 1000),
    auditLogPath: env.OPS_MCP_AUDIT_LOG?.trim() || undefined,
    userAgent: DEFAULTS.userAgent,
  };
}
