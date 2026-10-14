/**
 * SSRF-safe HTTP client used by every HTTP-based tool.
 *
 *  - Each hop is validated by the TargetPolicy BEFORE any connection is made.
 *  - The TCP connection goes to the address the policy validated, not to whatever the name
 *    resolves to a moment later (closes the DNS-rebinding window).
 *  - Redirects are followed manually, so every Location is re-validated, loops are detected and
 *    the chain is recorded.
 *  - Bodies are read up to a byte cap, then the socket is destroyed.
 *  - GET/HEAD only. No request bodies, no cookies, no credentials.
 */

import type { LookupFunction } from "node:net";
import { isIP } from "node:net";

import { Agent, request } from "undici";

import type { Config } from "../config.js";
import { PolicyError, TargetPolicy, parseHttpUrl } from "../security/policy.js";

export interface HttpDeps {
  config: Config;
  policy: TargetPolicy;
  /** Test hook: maps a validated address to the address actually dialled. */
  connectAddress?: (validatedAddress: string) => string;
}

export interface HttpOptions {
  method?: "GET" | "HEAD";
  followRedirects?: boolean;
  maxBodyBytes?: number;
  timeoutMs?: number;
  /** Fetch even if the TLS certificate is invalid (diagnostics only; still read-only). */
  allowInvalidCert?: boolean;
  headers?: Record<string, string>;
}

export interface Hop {
  url: string;
  status: number;
  location?: string;
  address: string;
  ms: number;
}

export type HeaderMap = Record<string, string | string[]>;

export interface HttpResult {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  headers: HeaderMap;
  /** One entry per response received, including the final one. */
  chain: Hop[];
  redirects: number;
  loop: boolean;
  tooManyRedirects: boolean;
  /** A redirect (or later hop) the policy or network stopped, with the reason. */
  stoppedAt?: { url: string; reason: string };
  body: string;
  bodyBytes: number;
  truncated: boolean;
  /** Milliseconds until the first response headers of the FINAL hop. */
  ttfbMs: number;
  /** Milliseconds for the whole chain, including body reads. */
  totalMs: number;
  /** Address the final hop connected to. */
  address: string;
}

export class HttpError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function describeNetworkError(error: unknown): Error {
  if (error instanceof HttpError || error instanceof PolicyError) return error;
  const err = error as NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException };
  const code = err.code ?? err.cause?.code ?? err.name ?? "ERR_UNKNOWN";
  const hints: Record<string, string> = {
    ECONNREFUSED: "connection refused (nothing is listening on that port)",
    ECONNRESET: "connection reset by the server",
    ETIMEDOUT: "connection timed out",
    UND_ERR_CONNECT_TIMEOUT: "connection timed out",
    UND_ERR_HEADERS_TIMEOUT: "timed out waiting for response headers",
    UND_ERR_BODY_TIMEOUT: "timed out reading the response body",
    TimeoutError: "the request timed out",
    AbortError: "the request was aborted (timeout)",
    CERT_HAS_EXPIRED: "the TLS certificate has expired",
    DEPTH_ZERO_SELF_SIGNED_CERT: "the server presented a self-signed certificate",
    SELF_SIGNED_CERT_IN_CHAIN: "the certificate chain contains a self-signed certificate",
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: "the server did not send its intermediate certificate(s)",
    UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "the certificate issuer is not trusted",
    ERR_TLS_CERT_ALTNAME_INVALID: "the certificate does not match the host name",
    EPROTO: "TLS/protocol error",
    ERR_SSL_WRONG_VERSION_NUMBER: "the server did not speak TLS on this port",
  };
  const detail = hints[code] ?? err.cause?.message ?? err.message ?? "unknown network error";
  return new HttpError(code, `Request failed: ${detail}`);
}

function pinnedLookup(addresses: string[]): LookupFunction {
  const all = addresses.map((address) => ({ address, family: isIP(address) }));
  return (_hostname, options, callback) => {
    const opts = typeof options === "object" && options !== null ? options : {};
    const family = opts.family === 4 || (opts.family as unknown) === "IPv4" ? 4 : opts.family === 6 || (opts.family as unknown) === "IPv6" ? 6 : 0;
    const matching = family === 0 ? all : all.filter((entry) => entry.family === family);
    const list = matching.length > 0 ? matching : all;
    if (opts.all) {
      (callback as unknown as (error: null, addresses: typeof list) => void)(null, list);
    } else {
      callback(null, list[0]!.address, list[0]!.family);
    }
  };
}

async function readBody(
  body: AsyncIterable<unknown> & { destroy(error?: Error): unknown },
  maxBytes: number,
): Promise<{ text: string; bytes: number; truncated: boolean }> {
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  for await (const chunk of body) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    if (total + buffer.length > maxBytes) {
      chunks.push(buffer.subarray(0, maxBytes - total));
      total = maxBytes;
      truncated = true;
      body.destroy();
      break;
    }
    chunks.push(buffer);
    total += buffer.length;
  }
  return { text: Buffer.concat(chunks).toString("utf8"), bytes: total, truncated };
}

export async function fetchSafe(deps: HttpDeps, startUrl: string, options: HttpOptions = {}): Promise<HttpResult> {
  const { config, policy } = deps;
  const method = options.method ?? "GET";
  const follow = options.followRedirects ?? true;
  const maxBody = Math.min(options.maxBodyBytes ?? config.maxBodyBytes, config.maxBodyBytes);
  const timeoutMs = Math.min(options.timeoutMs ?? config.timeoutMs, config.timeoutMs);
  const deadline = AbortSignal.timeout(timeoutMs * 2 + 1_000); // whole-chain safety net

  const chain: Hop[] = [];
  const seen = new Set<string>();
  const started = performance.now();
  let current = startUrl;
  let loop = false;
  let tooMany = false;
  let stoppedAt: HttpResult["stoppedAt"];
  let last: { status: number; headers: HeaderMap; body: string; bytes: number; truncated: boolean; ttfb: number; address: string } | undefined;

  for (let hop = 0; hop <= config.maxRedirects; hop++) {
    let parsed;
    let target;
    try {
      parsed = parseHttpUrl(current);
      target = await policy.resolve(parsed.hostname, parsed.port);
    } catch (error) {
      if (hop === 0) throw error;
      stoppedAt = { url: current, reason: error instanceof Error ? error.message : String(error) };
      break;
    }

    const key = parsed.url.href;
    if (seen.has(key)) {
      loop = true;
      stoppedAt = { url: current, reason: "redirect loop: this URL was already visited" };
      break;
    }
    seen.add(key);

    const dialled = deps.connectAddress ? target.addresses.map(deps.connectAddress) : target.addresses;
    const agent = new Agent({
      connect: {
        lookup: pinnedLookup(dialled),
        timeout: timeoutMs,
        rejectUnauthorized: !options.allowInvalidCert,
      },
      pipelining: 0,
      keepAliveTimeout: 1,
      keepAliveMaxTimeout: 1,
    });

    const hopStart = performance.now();
    try {
      const response = await request(parsed.url, {
        method,
        dispatcher: agent,
        signal: AbortSignal.any([deadline, AbortSignal.timeout(timeoutMs)]),
        headersTimeout: timeoutMs,
        bodyTimeout: timeoutMs,
        headers: {
          "user-agent": config.userAgent,
          accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "accept-encoding": "identity",
          ...options.headers,
        },
      });
      const ttfb = performance.now() - hopStart;
      const headers = response.headers as HeaderMap;
      // Destroying a body we don't need (redirects, HEAD) or have read enough of makes undici emit
      // an AbortError. With no listener that is an uncaught exception that would kill the server.
      response.body.on("error", () => undefined);

      let bodyInfo = { text: "", bytes: 0, truncated: false };
      const location = typeof headers.location === "string" ? headers.location : undefined;
      const isRedirect = REDIRECT_STATUSES.has(response.statusCode) && location !== undefined;
      if (method === "GET" && !(isRedirect && follow)) {
        bodyInfo = await readBody(response.body, maxBody);
      } else {
        // Discard (at most a little of) the body without buffering it.
        await response.body.dump({ limit: 64 * 1024 }).catch(() => undefined);
      }

      chain.push({
        url: parsed.url.href,
        status: response.statusCode,
        location,
        address: target.addresses[0]!,
        ms: Math.round(performance.now() - hopStart),
      });
      last = {
        status: response.statusCode,
        headers,
        body: bodyInfo.text,
        bytes: bodyInfo.bytes,
        truncated: bodyInfo.truncated,
        ttfb,
        address: target.addresses[0]!,
      };

      if (!isRedirect || !follow) break;
      try {
        current = new URL(location, parsed.url).href;
      } catch {
        stoppedAt = { url: location, reason: "the Location header is not a valid URL" };
        break;
      }
      if (hop === config.maxRedirects) tooMany = true;
    } catch (error) {
      if (hop === 0) throw describeNetworkError(error);
      stoppedAt = { url: current, reason: describeNetworkError(error).message };
      break;
    } finally {
      await agent.destroy().catch(() => undefined);
    }
  }

  if (!last) {
    // Only reachable when hop 0 produced no response without throwing, which cannot happen,
    // but keep the type checker (and future refactors) honest.
    throw new HttpError("NO_RESPONSE", "No response received");
  }

  const finalHop = chain[chain.length - 1]!;
  return {
    requestedUrl: startUrl,
    finalUrl: finalHop.url,
    status: last.status,
    headers: last.headers,
    chain,
    redirects: Math.max(0, chain.length - 1),
    loop,
    tooManyRedirects: tooMany,
    stoppedAt,
    body: last.body,
    bodyBytes: last.bytes,
    truncated: last.truncated,
    ttfbMs: Math.round(last.ttfb),
    totalMs: Math.round(performance.now() - started),
    address: last.address,
  };
}

/** Case-insensitive single-value header lookup. */
export function header(headers: HeaderMap, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value.join(", ") : value;
}
