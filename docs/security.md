# Security model and threat model

`claude-ops-mcp` lets an AI model make network requests. That is the definition of a server-side request forgery (SSRF) risk, so this document states what is defended, how, and what is out of scope.

## Who is the attacker?

1. **A malicious or compromised website** that the model is asked to probe. It controls responses, redirects, DNS and content.
2. **A prompt injection** inside that content (a page title, a header, a TXT record) trying to make the model call tools against internal systems or reveal data.
3. **A confused or over-eager model** asked to "check everything".
4. **A network attacker** against the optional HTTP transport.

The operator (who sets environment variables) is trusted. Tool arguments are **not** trusted.

## Defences

### SSRF and internal-network access

| Attack | Defence | Where |
| --- | --- | --- |
| `http://169.254.169.254/` (cloud metadata), `http://localhost`, `http://10.x` | All special-purpose ranges are refused after resolution | `security/ip.ts`, `security/policy.ts` |
| `http://2130706433/`, `http://0x7f.1/` | The URL parser canonicalises numeric forms before the check | `security/policy.ts` |
| `::ffff:127.0.0.1`, `64:ff9b::7f00:1`, `2002:7f00:1::` | IPv6 addresses embedding IPv4 are judged by the embedded address | `security/ip.ts` |
| A name with one public and one private record | Every address returned must be public | `security/policy.ts` |
| **DNS rebinding** (public at check time, private at connect time) | The name is resolved once; the socket is connected to the validated address, not the name | `net/safe-http.ts`, `net/tls-inspect.ts` |
| Public site redirects to an internal address | Each redirect hop is re-validated before any connection | `net/safe-http.ts` |
| Internal-looking names (`*.local`, `*.internal`, `*.corp`, `localhost`) | Refused before any DNS query | `security/policy.ts` |
| Using the tool as a port scanner | Port allow-list (`80,443,8080,8443` by default); no raw TCP tool exists | `config.ts`, `security/policy.ts` |
| `file://`, `gopher://`, credentials in URLs | Only `http(s)`; `user:pass@` is rejected | `security/policy.ts` |
| Using a hostile sitemap to scan third parties | Only URLs on the sitemap's own host are requested | `checks/sitemap.ts` |
| Using `dns_lookup` to read internal zones | Same name rules as network tools; IP literals refused | `tools/dns.ts` |

### Data exposure to the model

- Response **bodies are never returned**. Only derived facts (status, timings, title, robots meta).
- **Cookie values are never read into any output**, only names and attributes.
- Titles are length-limited and labelled "untrusted page content". Tool descriptions and the server instructions tell the model that probed content is data, not instructions.
- Unexpected exceptions are **not** echoed to the model (they can contain paths or internals). The operator sees them on stderr.
- The audit log stores the target **without query string or fragment**, never bodies or headers.

### Resource abuse

| Limit | Default | Notes |
| --- | --- | --- |
| Calls per minute | 60 | token bucket, whole server |
| Concurrent calls | 4 | extra calls are refused, not queued |
| Per-request timeout | 10 s | plus a whole-chain deadline |
| Response size | 1 MB | the socket is destroyed after the cap |
| Redirects | 10 | loops detected |
| Sitemap URLs requested | 100 (default sample 25), concurrency 4 | |

All limits come from the environment, so no tool argument can raise them. Per-call arguments can only **lower** the response size and timeout.

### HTTP transport

- Bearer token, compared in constant time (SHA-256 digests with `timingSafeEqual`).
- `Host` header allow-list (loopback by default) against DNS rebinding of the server itself.
- `POST /mcp` only, 1 MB body cap, JSON validated, **stateless** (no sessions to hijack).
- No CORS headers, so browsers cannot call it from arbitrary pages.
- Binds to `127.0.0.1` by default. Plain HTTP: terminate TLS in a reverse proxy if you expose it.

## Residual risks and non-goals

- **The operator can weaken it** (`OPS_MCP_ALLOW_PRIVATE=1`, `OPS_MCP_ALLOWED_PORTS=any`). That is deliberate and logged at start-up, but it is the operator's call.
- **Timing and existence side channels.** A refused request is distinguishable from a failed one, and response timings are returned. This reveals nothing about internal hosts because internal targets are refused before any packet is sent.
- **Public targets still receive requests.** The tool identifies itself with a `User-Agent` but cannot verify that you are authorised to probe a site. Use it on systems you own or may test.
- **Resolver trust.** DNS answers come from the system resolver. A compromised resolver can lie about public names; pinning protects against rebinding, not against a hostile resolver.
- **Not a penetration test.** It performs hygiene checks only. It does not exploit, fuzz, brute-force or scan.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a public issue.
