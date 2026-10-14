import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { Finding } from "../findings.js";
import { type TlsResult, inspectTls } from "../net/tls-inspect.js";
import type { Runtime } from "../runtime.js";
import { registerTool } from "./define.js";

const host = z.string().min(1).max(253).describe("Host name to inspect, e.g. example.com (no scheme, no port, no path).");
const port = z.number().int().min(1).max(65535).default(443).describe("TCP port with implicit TLS. Default 443. Mail ports 465/993/995 work too.");

function summarize(result: TlsResult): string {
  const leaf = result.chain[0];
  const lines = [`TLS inspection of ${result.host}:${result.port} (${result.address})`];
  if (leaf) {
    lines.push(`Certificate: ${leaf.subject}`);
    lines.push(`Issuer: ${leaf.issuer}`);
    lines.push(`Valid: ${leaf.validFrom} to ${leaf.validTo} (${leaf.daysRemaining} days remaining)`);
    lines.push(`Covers: ${leaf.subjectAltNames.join(", ") || "(no SAN)"}`);
    lines.push(`Key: ${leaf.keyType}${leaf.keyBits ? ` ${leaf.keyBits}-bit` : ""}${leaf.curve ? ` ${leaf.curve}` : ""}`);
  }
  lines.push(`Chain: ${result.chain.map((c) => c.subject).join(" ← ")}`);
  lines.push(`Negotiated: ${result.protocol ?? "?"}, ${result.cipher ?? "?"}${result.alpn ? `, ALPN ${result.alpn}` : ""}; handshake ${result.handshakeMs} ms`);
  if (result.supportedProtocols) {
    lines.push(
      `Protocol support: ${Object.entries(result.supportedProtocols)
        .map(([version, supported]) => `${version} ${supported ? "yes" : "no"}`)
        .join(", ")}`,
    );
  }
  return lines.join("\n");
}

export function registerTlsTools(server: McpServer, runtime: Runtime): void {
  registerTool(server, runtime, {
    name: "tls_inspect",
    title: "Inspect TLS certificate",
    description:
      "Performs a TLS handshake against host:port and reports the certificate chain, expiry, host-name match, trust, key strength, negotiated protocol and (optionally) which TLS versions the server accepts. Use it for expired or soon-to-expire certificates, 'certificate not trusted' errors, incomplete chains and legacy protocol audits. Only the handshake happens; no application data is sent.",
    inputSchema: {
      host,
      port,
      check_protocols: z.boolean().default(false).describe("Also probe TLS 1.0, 1.1, 1.2 and 1.3 individually (4 extra handshakes)."),
    },
    target: ({ host, port }) => `${host}:${port}`,
    async run({ host, port, check_protocols }, runtime) {
      const result = await inspectTls(runtime.tls, host, port, { checkProtocols: check_protocols });
      const { findings, ...data } = result;
      return { summary: summarize(result), data, findings };
    },
  });

  registerTool(server, runtime, {
    name: "cert_expiry",
    title: "Check certificate expiry for several hosts",
    description:
      "Checks the certificate expiry of up to 10 hosts at once and lists them soonest-expiring first. Ideal for a quick 'which of my domains need renewal?' sweep.",
    inputSchema: {
      hosts: z.array(host).min(1).max(10).describe("Up to 10 host names."),
      port,
    },
    target: ({ hosts, port }) => `${hosts.join(",")}:${port}`,
    async run({ hosts, port }, runtime) {
      const unique = [...new Set(hosts.map((h) => h.trim().toLowerCase()))];
      const rows = await Promise.all(
        unique.map(async (name) => {
          try {
            const result = await inspectTls(runtime.tls, name, port);
            const leaf = result.chain[0];
            return { host: name, ok: true as const, daysRemaining: leaf?.daysRemaining ?? null, validTo: leaf?.validTo ?? null, issuer: leaf?.issuer ?? null, findings: result.findings };
          } catch (error) {
            return { host: name, ok: false as const, error: error instanceof Error ? error.message : String(error), findings: [] as Finding[] };
          }
        }),
      );
      rows.sort((a, b) => (a.ok ? (a.daysRemaining ?? 1e9) : -1e9) - (b.ok ? (b.daysRemaining ?? 1e9) : -1e9));

      const lines = rows.map((row) =>
        row.ok ? `${String(row.daysRemaining).padStart(5)} days  ${row.host}  (until ${row.validTo?.slice(0, 10)}, ${row.issuer})` : `  ERROR      ${row.host}  ${row.error}`,
      );
      const findings: Finding[] = rows.flatMap((row) =>
        row.ok
          ? row.findings.filter((f) => !f.ok).map((f) => ({ ...f, message: `${row.host}: ${f.message}` }))
          : [{ id: "tls.unreachable", severity: "high" as const, message: `${row.host}: ${row.error}`, remediation: "Check the host name, port and that TLS is served there." }],
      );
      return {
        summary: `Certificate expiry (soonest first):\n${lines.join("\n")}`,
        data: { results: rows.map(({ findings: _f, ...rest }) => rest) },
        findings,
      };
    },
  });
}
