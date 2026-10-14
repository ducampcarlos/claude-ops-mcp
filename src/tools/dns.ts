import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { isIP } from "node:net";
import { z } from "zod";

import { auditMailAuth, COMMON_DKIM_SELECTORS } from "../checks/mail-auth.js";
import { type Finding, issue } from "../findings.js";
import { type DnsValue, type RecordType } from "../net/dns.js";
import { classifyAddress } from "../security/ip.js";
import { PolicyError, normalizeHostname } from "../security/policy.js";
import type { Runtime } from "../runtime.js";
import { registerTool } from "./define.js";

const QUERYABLE = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "SRV"] as const satisfies readonly RecordType[];

function formatValue(value: DnsValue): string {
  if (typeof value === "string") return value;
  if ("exchange" in value) return `${value.priority} ${value.exchange || "."}`;
  if ("tag" in value) return `${value.critical ? "critical " : ""}${value.tag} ${JSON.stringify(value.value)}`;
  if ("nsname" in value) return `${value.nsname} ${value.hostmaster} serial=${value.serial} refresh=${value.refresh} retry=${value.retry} expire=${value.expire} minttl=${value.minttl}`;
  return `${value.priority} ${value.weight} ${value.port} ${value.name}`;
}

/** Resolve a user-supplied DNS name, applying the same deny/allow/internal-name rules as network tools. */
function dnsName(runtime: Runtime, input: string): string {
  const name = normalizeHostname(input);
  if (isIP(name) !== 0) throw new PolicyError("invalid_target", "Pass a DNS name, not an IP address.");
  runtime.policy.checkName(name);
  return name;
}

export function registerDnsTools(server: McpServer, runtime: Runtime): void {
  registerTool(server, runtime, {
    name: "dns_lookup",
    title: "DNS lookup",
    description:
      "Looks up DNS records (A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, SRV) for a name using the server's resolver. Use it to check propagation, verify records after a change or investigate mail routing. For SPF/DKIM/DMARC use mail_auth instead, which interprets them.",
    inputSchema: {
      name: z.string().min(1).max(253).describe("DNS name, e.g. example.com or _dmarc.example.com."),
      types: z.array(z.enum(QUERYABLE)).min(1).max(9).default(["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"]).describe("Record types to query."),
    },
    target: ({ name }) => name,
    async run({ name, types }, runtime) {
      const host = dnsName(runtime, name);
      const wanted = [...new Set(types)] as RecordType[];
      const answers = await Promise.all(wanted.map(async (type) => ({ type, response: await runtime.dns.resolve(host, type) })));

      const lines = [`DNS records for ${host}:`];
      const findings: Finding[] = [];
      const data: Record<string, unknown> = {};
      for (const { type, response } of answers) {
        data[type] = response.records.map(formatValue);
        if (response.status === "ok") {
          for (const record of response.records) lines.push(`  ${type.padEnd(5)} ${formatValue(record)}`);
        } else if (response.status === "error") {
          lines.push(`  ${type.padEnd(5)} (lookup failed: ${response.error})`);
          findings.push(issue(`dns.lookup_failed.${type.toLowerCase()}`, "low", `The ${type} lookup for ${host} failed (${response.error}).`, "Retry; persistent failures usually mean the zone's nameservers are unreachable."));
        }
      }
      if (answers.every(({ response }) => response.status === "nxdomain")) {
        lines.push("  The name does not exist (NXDOMAIN).");
        findings.push(issue("dns.nxdomain", "medium", `${host} does not exist.`, "Check the spelling, and that the record was created in the right zone."));
      } else if (answers.every(({ response }) => response.records.length === 0 && response.status !== "error")) {
        lines.push("  The name exists but has none of the requested record types.");
      }
      for (const { type, response } of answers) {
        if (type === "A" || type === "AAAA") {
          for (const record of response.records) {
            const verdict = classifyAddress(String(record));
            if (!verdict.public) findings.push(issue("dns.private_address", "info", `${host} ${type} points to ${record}, which is ${verdict.reason}.`, "Expected for internal names; unexpected for a public site (split-horizon DNS or a stale record)."));
          }
        }
        if (type === "CNAME" && response.records.length > 0 && answers.some((a) => a.type === "MX" && a.response.records.length > 0)) {
          findings.push(issue("dns.cname_with_mx", "medium", `${host} has a CNAME and MX records; a CNAME cannot coexist with other record types (RFC 1034).`, "Replace the CNAME with A/AAAA records, or move the MX to a name without a CNAME."));
        }
      }
      return { summary: lines.join("\n"), data: { name: host, records: data }, findings };
    },
  });

  registerTool(server, runtime, {
    name: "mail_auth",
    title: "Audit email authentication",
    description:
      "Audits a domain's email authentication from public DNS: MX health, SPF (including the 10-lookup limit), DKIM (probes common selectors plus any you give), DMARC policy strength, MTA-STS (record and policy file) and TLS-RPT. Returns a score with fixes. Use it for 'mail goes to spam', spoofing concerns and after mail-server migrations. It never connects to a mail server.",
    inputSchema: {
      domain: z.string().min(1).max(253).describe("Domain to audit, e.g. example.com."),
      dkim_selectors: z
        .array(z.string().regex(/^[a-z0-9._-]{1,63}$/i, "invalid DKIM selector"))
        .max(10)
        .default([])
        .describe(`Extra DKIM selectors to probe (from the s= tag of a real DKIM-Signature header). Already probed: ${COMMON_DKIM_SELECTORS.slice(0, 8).join(", ")}, ...`),
      check_mta_sts_policy: z.boolean().default(true).describe("Fetch https://mta-sts.<domain>/.well-known/mta-sts.txt and validate it."),
    },
    target: ({ domain }) => domain,
    async run({ domain, dkim_selectors, check_mta_sts_policy }, runtime) {
      const name = dnsName(runtime, domain);
      const result = await auditMailAuth(runtime.dns, runtime.http, name, { dkimSelectors: dkim_selectors, fetchMtaSts: check_mta_sts_policy });
      const lines = [
        `Email authentication for ${name}`,
        `MX: ${result.mx.length ? result.mx.map((m) => `${m.priority} ${m.exchange || "."}`).join(", ") : "none"}`,
        `SPF: ${result.spf ? `${result.spf.record} (${result.spf.lookups}/10 lookups)` : "none"}`,
        `DKIM: ${result.dkim.found.length ? `selectors ${result.dkim.found.join(", ")}` : `none found (probed ${result.dkim.probed})`}`,
        `DMARC: ${result.dmarc ? result.dmarc.record : "none"}`,
        `MTA-STS: ${result.mtaSts ? (result.mtaSts.policy ? `mode ${result.mtaSts.policy.mode ?? "?"}` : "record only") : "none"}`,
      ];
      const { findings, ...data } = result;
      return { summary: lines.join("\n"), data, findings };
    },
  });
}
