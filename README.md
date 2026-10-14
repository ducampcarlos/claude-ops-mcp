# claude-ops-mcp

[![CI](https://github.com/ducampcarlos/claude-ops-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ducampcarlos/claude-ops-mcp/actions/workflows/ci.yml)
![Node](https://img.shields.io/badge/node-%E2%89%A522.19-339933)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**A safe, read-only [MCP](https://modelcontextprotocol.io) server that gives Claude eyes on your servers and websites.**
Ask *"why does mail from my domain land in spam?"*, *"is the certificate about to expire?"* or *"what broke in the sitemap after the migration?"* and Claude runs real checks (TLS, HTTP, DNS, email authentication, sitemaps) and answers from facts, with concrete fixes.

It started as the manual checklist behind real hosting, migration and security-review work, turned into tools an AI can call without being able to hurt anything.

## Tools

| Tool | What it answers |
| --- | --- |
| `tls_inspect` | Certificate chain, expiry, host-name match, trust, key strength, negotiated protocol, and optionally which TLS versions the server accepts (flags TLS 1.0/1.1). Spots incomplete chains and self-signed certificates. |
| `cert_expiry` | Which of up to 10 hosts need renewal soonest. |
| `http_probe` | Status, redirect chain, timings, headers, size, page title. Never returns the response body. |
| `redirect_chain` | Hop-by-hop redirects, loops, long chains, http→https upgrade, and whether `http`/`https` and `www`/non-`www` all converge on one URL. |
| `security_headers` | HSTS, CSP, clickjacking, nosniff, referrer policy, CORS, cookie flags (names only, never values), technology disclosure. Score and grade. |
| `dns_lookup` | A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, SRV, with NXDOMAIN and CNAME-with-MX detection. |
| `mail_auth` | MX health, SPF (including the 10-lookup limit), DKIM, DMARC strength, MTA-STS (record **and** policy file), TLS-RPT. |
| `sitemap_audit` | Finds the sitemap, samples its URLs and reports 4xx/5xx, redirects, `noindex`, missing titles, canonical mismatches and URLs blocked by `robots.txt`. |

Four ready-made prompts are included too: `site_health_review`, `migration_check`, `mail_deliverability` and `cert_renewal_sweep`.

Every result carries **findings** with a stable ID (`tls.expired`, `spf.too_many_lookups`, `sitemap.noindex`, ...), a severity (`info | low | medium | high`) and a concrete fix, plus a 0-100 score and an A-F grade, both as readable text for Claude and as structured JSON.

### What it looks like

Output from the real server against a deliberately flawed local demo site:

```text
Security headers for http://localhost:8080/ (HTTP 200)

Score: 30/100 (grade F)

- [HIGH] headers.no_https: The page was served over plain HTTP.
  Fix: Serve everything over HTTPS and redirect HTTP to HTTPS.
- [MEDIUM] headers.csp_missing: Content-Security-Policy is not set.
  Fix: Start with `default-src 'self'` and relax per resource type; it is the main defence against XSS.
- [MEDIUM] headers.cookie_not_httponly: Cookie `PHPSESSID` has no HttpOnly flag, so scripts can read it.
  Fix: Add `HttpOnly` unless JavaScript genuinely needs the cookie.
- [LOW] headers.server_version: The Server header reveals a version (nginx/1.18.0).
  Fix: Hide the version (nginx: `server_tokens off`; Apache: `ServerTokens Prod`).
  ...
```

```text
Sitemap audit for http://localhost:8080/
URLs: 8 listed, 8 unique
Checked 8 sampled URL(s): 3 fine, 5 with problems.

Problem URLs:
  301 http://localhost:8080/old-page  [redirected] 301 /about
  200 http://localhost:8080/draft  [noindex]
  404 http://localhost:8080/missing  [broken]
  500 http://localhost:8080/api/report  [broken]
  200 http://localhost:8080/admin/login  [blocked_by_robots]

- [HIGH] sitemap.server_errors: 1 of 8 sampled URLs return a 5xx error (e.g. http://localhost:8080/api/report).
- [HIGH] sitemap.noindex: 1 of 8 sampled URLs are marked noindex yet listed in the sitemap (e.g. http://localhost:8080/draft).
- [HIGH] sitemap.blocked_by_robots: 1 of 8 sampled URLs are blocked by robots.txt for Googlebot (e.g. http://localhost:8080/admin/login).
  ...
```

## Install

Requires **Node 22.19 or newer**.

```bash
git clone https://github.com/ducampcarlos/claude-ops-mcp.git
cd claude-ops-mcp
npm ci && npm run build
```

### Claude Code

```bash
claude mcp add ops -- node /absolute/path/to/claude-ops-mcp/dist/index.js
claude mcp list          # should show: ops ... Connected
```

With options (see [Configuration](#configuration)):

```bash
claude mcp add ops \
  -e OPS_MCP_AUDIT_LOG=$HOME/.claude-ops-mcp/audit.jsonl \
  -e OPS_MCP_ALLOW_HOSTS='*.example.com,example.com' \
  -- node /absolute/path/to/claude-ops-mcp/dist/index.js
```

### Claude Desktop (or any client that reads `mcpServers`)

```json
{
  "mcpServers": {
    "ops": {
      "command": "node",
      "args": ["/absolute/path/to/claude-ops-mcp/dist/index.js"],
      "env": { "OPS_MCP_AUDIT_LOG": "/home/you/.claude-ops-mcp/audit.jsonl" }
    }
  }
}
```

### Streamable HTTP (shared or remote use)

```bash
export OPS_MCP_HTTP_TOKEN=$(openssl rand -hex 32)
node dist/index.js --http --port 3333          # listens on 127.0.0.1 by default

claude mcp add --transport http ops http://127.0.0.1:3333/mcp \
  --header "Authorization: Bearer $OPS_MCP_HTTP_TOKEN"
```

The HTTP server is stateless, requires the token, validates the `Host` header (DNS-rebinding protection), accepts only `POST /mcp` with bodies up to 1 MB and sends no CORS headers. It speaks plain HTTP: if you bind it beyond loopback, put a TLS-terminating reverse proxy in front and set `OPS_MCP_HTTP_ALLOWED_HOSTS` to the public host name.

### Docker

```bash
docker build -t claude-ops-mcp .
docker run --rm -i claude-ops-mcp                                   # stdio
docker run --rm -p 127.0.0.1:3333:3333 -e OPS_MCP_HTTP_TOKEN=... claude-ops-mcp --http --host 0.0.0.0
```

## Security model

An MCP server that can make network requests on behalf of an AI is a textbook SSRF risk, so the safety properties are the product. Full details in [docs/security.md](docs/security.md); the short version:

- **Read-only by construction.** GET/HEAD only, TLS handshakes only, DNS queries only. No request bodies, no cookies, no credentials, no payloads, no port scanning. Every tool is annotated `readOnlyHint`.
- **SSRF protection.** Private, loopback, link-local (cloud metadata `169.254.169.254`), CGNAT, multicast, documentation and reserved ranges are refused, including IPv6 forms that embed an IPv4 address (`::ffff:127.0.0.1`, NAT64, 6to4) and numeric tricks like `http://2130706433/`.
- **DNS-rebinding safe.** Names are resolved once, **every** returned address must be public, and the connection is then pinned to the validated address, so the name cannot change its answer between check and connect.
- **Redirects are re-validated hop by hop.** A public site cannot bounce the server to an internal address.
- **Limits you control, not the model.** Port allow-list, allow/deny host lists, rate limit, concurrency cap, per-request timeout, response size cap. They come from the environment, never from tool arguments, so a prompt injection cannot loosen them.
- **Untrusted output is handled as untrusted.** Page bodies are never returned, cookie values are never read into the output, page titles are length-limited and labelled, and the server's instructions tell the model to treat probed content as data.
- **Audit log.** Optional JSONL record of every call (tool, target without query string, outcome, duration), never bodies or headers.
- **No stack traces to the model.** Unexpected errors are logged for the operator and reported to the model as a short generic message.

```
 Claude ──MCP──▶ transport (stdio | HTTP+token+Host check)
                      │
                tool wrapper: rate limit → concurrency cap → audit → error mapping
                      │
        ┌─────────────┼───────────────┐
     tls/http/dns tools …        analyzers (headers, SPF/DMARC, sitemap, robots)
        │                              │
   TargetPolicy (rules, ports, DNS resolve, every address public?)
        │
   pinned connection (undici Agent / tls.connect to the validated IP)
```

> Use it only on systems you own or are authorised to test. It is a diagnostics tool, not a penetration tester.

## Configuration

All settings are environment variables. Defaults are the safe choice.

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPS_MCP_ALLOW_PRIVATE` | off | Allow loopback/private targets (for testing your own internal systems). |
| `OPS_MCP_ALLOW_HOSTS` | *(any public host)* | Comma-separated hosts (`example.com`, `*.example.com`) that are the **only** ones allowed. |
| `OPS_MCP_DENY_HOSTS` | *(none)* | Hosts that must never be probed. Evaluated first. |
| `OPS_MCP_ALLOWED_PORTS` | `80,443,8080,8443` | Allowed target ports, or `any`. |
| `OPS_MCP_RATE_PER_MINUTE` | `60` | Tool calls per minute (token bucket). |
| `OPS_MCP_MAX_CONCURRENT` | `4` | Simultaneous tool calls. |
| `OPS_MCP_TIMEOUT_MS` | `10000` | Per-request network timeout. |
| `OPS_MCP_MAX_BODY_BYTES` | `1000000` | Maximum bytes read from any response. |
| `OPS_MCP_MAX_REDIRECTS` | `10` | Redirects followed per request. |
| `OPS_MCP_MAX_SITEMAP_CHECKS` | `100` | Maximum URLs a sitemap audit requests. |
| `OPS_MCP_AUDIT_LOG` | *(off)* | Path of the JSONL audit log. |
| `OPS_MCP_HTTP_TOKEN` | *(required for `--http`)* | Bearer token, 16+ characters. |
| `OPS_MCP_HTTP_ALLOWED_HOSTS` | *(loopback only)* | Extra `Host` values accepted in HTTP mode. |

Invalid values stop the server at start-up with a clear message instead of silently falling back.

## Things to know

- **DKIM selectors can't be listed in DNS.** `mail_auth` probes ~24 common ones plus any you pass; "not found" means "not found among those".
- **DMARC organisational domain** is found by walking up labels without the Public Suffix List, which is right for `example.com` but approximate for `example.co.uk`.
- **TLS checks use Node's OpenSSL and the system trust store.** An internal CA is reported as untrusted, correctly, unless it is in the store.
- **Sitemaps** are read up to the response size cap; gzip (`.xml.gz`) sitemaps are not read.
- **Not covered:** STARTTLS on port 25/587, IPv6-only SAN matching edge cases, HTTP/2-specific checks, vulnerability scanning.

## Development

```bash
npm ci
npm test            # 242 tests, no network access needed
npm run typecheck
npm run build
```

Tests never touch the internet. They spin up real local HTTP and TLS servers with generated certificates (expired, self-signed, wrong host, incomplete chain, weak key, legacy protocols), drive the server through a real MCP client (in memory, over HTTP and as a real stdio subprocess), and include the security regressions that matter most: SSRF ranges, redirect re-validation, rebinding, secret redaction and the audit log.

```
src/security/   ip classification, target policy, rate limit, concurrency gate, audit log
src/net/        pinned HTTP client, TLS inspection, DNS client, HTML helpers
src/checks/     headers, mail authentication, sitemap, robots, redirects (pure analysis)
src/tools/      the MCP tools and the wrapper that applies limits, audit and error mapping
src/            server, HTTP transport, CLI entry point
```

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Carlos Ducamp.
