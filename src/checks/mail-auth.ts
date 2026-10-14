/**
 * Email authentication audit: MX, SPF, DKIM, DMARC, MTA-STS (including the policy file) and TLS-RPT.
 * Reads public DNS and one HTTPS file; never talks to a mail server.
 */

import { type DnsClient, hasAddress, mxRecords, txtRecords } from "../net/dns.js";
import { type HttpDeps, fetchSafe } from "../net/safe-http.js";
import { type Finding, good, issue } from "../findings.js";

export const COMMON_DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim", "smtp",
  "mandrill", "mxvault", "everlytickey1", "cm", "zoho", "sendgrid", "mailgun", "amazonses", "protonmail", "fm1", "fm2", "fm3",
]; // fmt: skip

const MAX_SPF_LOOKUPS = 10;

export interface MailAuthOptions {
  dkimSelectors?: string[];
  /** Fetch and validate the MTA-STS policy file over HTTPS. */
  fetchMtaSts?: boolean;
}

export interface MailAuthResult {
  domain: string;
  spf?: { record: string; lookups: number };
  dmarc?: { record: string; domain: string; tags: Record<string, string> };
  dkim: { found: string[]; revoked: string[]; probed: number };
  mx: { priority: number; exchange: string }[];
  mtaSts?: { record: string; policy?: { mode?: string; maxAge?: number; mx: string[] } };
  findings: Finding[];
}

// ---------------------------------------------------------------------------------------------
// SPF
// ---------------------------------------------------------------------------------------------

const spfRecordsOf = async (dns: DnsClient, domain: string) =>
  (await txtRecords(dns, domain)).filter((txt) => /^v=spf1(\s|$)/i.test(txt));

/** Count terms that cost a DNS lookup, following include: and redirect= (loop-safe, capped). */
export async function countSpfLookups(dns: DnsClient, record: string, seen = new Set<string>(), budget = { calls: 0 }): Promise<number> {
  let total = 0;
  for (const raw of record.split(/\s+/).slice(1)) {
    const term = raw.replace(/^[+\-~?]/, "").toLowerCase();
    const name = term.split(/[:=/]/)[0]!;
    if (["include", "a", "mx", "ptr", "exists", "redirect"].includes(name)) total += 1;
    const separator = term.search(/[:=]/);
    if ((name === "include" || name === "redirect") && separator > 0) {
      const target = term.slice(separator + 1);
      if (target && !seen.has(target) && budget.calls < 30) {
        seen.add(target);
        budget.calls += 1;
        for (const child of await spfRecordsOf(dns, target)) total += await countSpfLookups(dns, child, seen, budget);
      }
    }
  }
  return total;
}

async function checkSpf(dns: DnsClient, domain: string, result: MailAuthResult): Promise<Finding[]> {
  const records = await spfRecordsOf(dns, domain);
  if (records.length === 0) {
    return [issue("spf.missing", "high", "No SPF record is published.", "Publish a TXT record such as `v=spf1 include:<your-provider> -all`.")];
  }
  if (records.length > 1) {
    return [issue("spf.multiple", "high", `${records.length} SPF records found; receivers treat this as a permanent error.`, "Merge them into a single `v=spf1` TXT record.")];
  }
  const record = records[0]!;
  const findings: Finding[] = [good("spf.present", "A single SPF record is published.")];
  const terms = record.toLowerCase().split(/\s+/).slice(1);
  const all = terms.find((term) => term.replace(/^[+\-~?]/, "") === "all");

  if (all === undefined && !terms.some((term) => term.startsWith("redirect="))) {
    findings.push(issue("spf.no_all", "medium", "The SPF record has no terminating `all` mechanism.", "End it with `-all` (or `~all` while rolling out)."));
  } else if (all === "all" || all === "+all") {
    findings.push(issue("spf.pass_all", "high", "`+all` authorises every server on the internet to send as this domain.", "Replace it with `-all` or `~all`."));
  } else if (all === "?all") {
    findings.push(issue("spf.neutral_all", "medium", "`?all` says nothing about unlisted senders.", "Use `~all`, then `-all` once every sender is listed."));
  } else if (all === "~all") {
    findings.push(issue("spf.softfail", "low", "`~all` (softfail) is fine while rolling out but weaker than `-all`.", "Move to `-all` once all legitimate senders are covered."));
  } else if (all === "-all") {
    findings.push(good("spf.hardfail", "SPF ends in `-all`."));
  }
  if (terms.some((term) => term.replace(/^[+\-~?]/, "").startsWith("ptr"))) {
    findings.push(issue("spf.ptr", "low", "The `ptr` mechanism is deprecated (RFC 7208 §5.5).", "Use explicit `ip4:`/`ip6:`/`include:` terms."));
  }
  const lookups = await countSpfLookups(dns, record);
  result.spf = { record, lookups };
  findings.push(
    lookups > MAX_SPF_LOOKUPS
      ? issue("spf.too_many_lookups", "high", `SPF needs ${lookups} DNS lookups; the limit is ${MAX_SPF_LOOKUPS}, beyond which receivers return a permanent error.`, "Flatten includes or remove providers you no longer use.")
      : good("spf.lookups", `SPF uses ${lookups} of ${MAX_SPF_LOOKUPS} allowed DNS lookups.`),
  );
  return findings;
}

// ---------------------------------------------------------------------------------------------
// DMARC
// ---------------------------------------------------------------------------------------------

export function parseTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) tags[part.slice(0, index).trim().toLowerCase()] = part.slice(index + 1).trim();
  }
  return tags;
}

async function findDmarc(dns: DnsClient, domain: string): Promise<{ domain: string; records: string[] } | undefined> {
  // DMARC falls back to the organisational domain. Without the Public Suffix List we walk up while
  // at least two labels remain, which is right for example.com and sub.example.com.
  const labels = domain.split(".");
  for (let i = 0; i <= labels.length - 2; i++) {
    const candidate = labels.slice(i).join(".");
    const records = (await txtRecords(dns, `_dmarc.${candidate}`)).filter((txt) => /^v=dmarc1\b/i.test(txt));
    if (records.length > 0) return { domain: candidate, records };
  }
  return undefined;
}

async function checkDmarc(dns: DnsClient, domain: string, result: MailAuthResult): Promise<Finding[]> {
  const found = await findDmarc(dns, domain);
  if (!found) {
    return [issue("dmarc.missing", "high", "No DMARC record is published.", `Publish \`_dmarc\` TXT \`v=DMARC1; p=none; rua=mailto:dmarc@${domain}\` and tighten the policy as reports come in.`)];
  }
  if (found.records.length > 1) {
    return [issue("dmarc.multiple", "high", "Multiple DMARC records found; receivers ignore all of them.", "Keep exactly one `v=DMARC1` TXT record.")];
  }
  const record = found.records[0]!;
  const tags = parseTags(record);
  result.dmarc = { record, domain: found.domain, tags };
  const findings: Finding[] = [
    good("dmarc.present", found.domain === domain ? "A DMARC record is published." : `DMARC is inherited from ${found.domain}.`),
  ];

  const policy = (tags.p ?? "").toLowerCase();
  if (policy === "reject") findings.push(good("dmarc.reject", "Policy is `p=reject`."));
  else if (policy === "quarantine") findings.push(issue("dmarc.quarantine", "low", "Policy is `p=quarantine`.", "Consider `p=reject` once reports show no legitimate failures."));
  else if (policy === "none") findings.push(issue("dmarc.monitor_only", "medium", "Policy is `p=none`: spoofed mail is still delivered.", "Use the aggregate reports to fix senders, then move to quarantine or reject."));
  else findings.push(issue("dmarc.invalid_policy", "high", `Missing or invalid \`p=\` tag (${JSON.stringify(policy)}).`, "Set `p=none`, `p=quarantine` or `p=reject`."));

  const pct = tags.pct;
  if (pct !== undefined && /^\d+$/.test(pct) && Number(pct) < 100 && (policy === "quarantine" || policy === "reject")) {
    findings.push(issue("dmarc.partial", "low", `The policy applies to only ${pct}% of messages.`, "Raise `pct` to 100 once you are confident."));
  }
  if (!tags.rua) findings.push(issue("dmarc.no_rua", "low", "No `rua=` address, so you receive no aggregate reports.", "Add `rua=mailto:<mailbox>` to see who sends as your domain."));
  if ((tags.sp ?? "").toLowerCase() === "none" && (policy === "quarantine" || policy === "reject")) {
    findings.push(issue("dmarc.weak_subdomain_policy", "medium", "Subdomain policy `sp=none` undermines the main policy.", "Remove `sp=` or match it to `p=`."));
  }
  return findings;
}

// ---------------------------------------------------------------------------------------------
// DKIM
// ---------------------------------------------------------------------------------------------

async function checkDkim(dns: DnsClient, domain: string, extra: string[], result: MailAuthResult): Promise<Finding[]> {
  const selectors = [...new Set([...extra.map((s) => s.toLowerCase()), ...COMMON_DKIM_SELECTORS])];
  const found: string[] = [];
  const revoked: string[] = [];

  const queue = [...selectors];
  const worker = async () => {
    for (let selector = queue.shift(); selector !== undefined; selector = queue.shift()) {
      const records = await txtRecords(dns, `${selector}._domainkey.${domain}`);
      for (const record of records) {
        const tags = parseTags(record);
        if (!("p" in tags)) continue;
        (tags.p ? found : revoked).push(selector);
        break;
      }
    }
  };
  await Promise.all(Array.from({ length: 8 }, worker));
  found.sort();
  revoked.sort();
  result.dkim = { found, revoked, probed: selectors.length };

  const findings: Finding[] = [];
  findings.push(
    found.length > 0
      ? good("dkim.found", `DKIM key found for selector(s): ${found.join(", ")}.`)
      : issue("dkim.not_found", "medium", `No DKIM key found among ${selectors.length} common selectors. DKIM selectors cannot be listed, so a custom one may exist.`, "Enable DKIM signing at your mail provider, or pass the selector from the DKIM-Signature header (s=...) of a real email."),
  );
  if (revoked.length > 0) {
    findings.push(issue("dkim.revoked", "low", `Revoked (empty \`p=\`) key for selector(s): ${revoked.join(", ")}.`, "Delete DNS records for selectors you no longer use."));
  }
  return findings;
}

// ---------------------------------------------------------------------------------------------
// MX
// ---------------------------------------------------------------------------------------------

async function checkMx(dns: DnsClient, domain: string, result: MailAuthResult): Promise<Finding[]> {
  const records = await mxRecords(dns, domain);
  result.mx = records;
  if (records.length === 0) {
    return [issue("mx.missing", "medium", "No MX records: the domain cannot receive email.", "Add MX records for your mail provider (or publish a null MX `0 .` if this is a send-only domain).")];
  }
  if (records.length === 1 && (records[0]!.exchange === "" || records[0]!.exchange === ".")) {
    return [good("mx.null", "A null MX is published (the domain accepts no mail).")];
  }
  const findings: Finding[] = [good("mx.present", `${records.length} MX record(s) published.`)];
  const checks = await Promise.all(records.map(async (mx) => ({ mx, ok: await hasAddress(dns, mx.exchange) })));
  const broken = checks.filter((c) => !c.ok).map((c) => c.mx.exchange);
  if (broken.length > 0) {
    findings.push(issue("mx.unresolvable", "high", `MX host(s) without A/AAAA records: ${broken.join(", ")}.`, "Fix or remove those MX entries; senders will retry and eventually bounce."));
  }
  if (records.length === 1) {
    findings.push(issue("mx.single", "low", "Only one MX host: mail queues up if it is down.", "Add a secondary MX (or confirm your provider already load-balances)."));
  }
  return findings;
}

// ---------------------------------------------------------------------------------------------
// MTA-STS and TLS-RPT
// ---------------------------------------------------------------------------------------------

export function parseMtaStsPolicy(text: string): { version?: string; mode?: string; maxAge?: number; mx: string[] } {
  const policy: { version?: string; mode?: string; maxAge?: number; mx: string[] } = { mx: [] };
  for (const line of text.split(/\r?\n/)) {
    const index = line.indexOf(":");
    if (index < 0) continue;
    const key = line.slice(0, index).trim().toLowerCase();
    const value = line.slice(index + 1).trim();
    if (key === "version") policy.version = value;
    else if (key === "mode") policy.mode = value.toLowerCase();
    else if (key === "max_age") policy.maxAge = Number(value);
    else if (key === "mx") policy.mx.push(value.toLowerCase());
  }
  return policy;
}

export function mxMatchesPattern(host: string, pattern: string): boolean {
  if (pattern.startsWith("*.")) return host.endsWith(pattern.slice(1)) && host.split(".").length === pattern.split(".").length;
  return host === pattern;
}

async function checkMtaSts(dns: DnsClient, http: HttpDeps | undefined, domain: string, fetchPolicy: boolean, result: MailAuthResult): Promise<Finding[]> {
  const findings: Finding[] = [];
  const records = (await txtRecords(dns, `_mta-sts.${domain}`)).filter((txt) => /^v=stsv1\b/i.test(txt));
  if (records.length === 0) {
    findings.push(issue("mta_sts.missing", "low", "No MTA-STS record, so inbound SMTP TLS can be downgraded by an attacker in the path.", "Publish `_mta-sts` TXT `v=STSv1; id=<timestamp>` and host the policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt`."));
  } else {
    result.mtaSts = { record: records[0]! };
    findings.push(good("mta_sts.present", "An MTA-STS record is published."));
    if (fetchPolicy && http) {
      try {
        const response = await fetchSafe(http, `https://mta-sts.${domain}/.well-known/mta-sts.txt`, { followRedirects: false, maxBodyBytes: 64 * 1024 });
        if (response.status !== 200) {
          findings.push(issue("mta_sts.policy_unreachable", "high", `The policy file returned HTTP ${response.status}; senders will ignore MTA-STS.`, "Serve `/.well-known/mta-sts.txt` with HTTP 200 and no redirects on mta-sts.<domain>."));
        } else {
          const policy = parseMtaStsPolicy(response.body);
          result.mtaSts.policy = { mode: policy.mode, maxAge: policy.maxAge, mx: policy.mx };
          if (policy.version !== "STSv1") findings.push(issue("mta_sts.policy_invalid", "high", "The policy file is missing `version: STSv1`.", "Fix the policy syntax."));
          if (policy.mode === "enforce") findings.push(good("mta_sts.enforce", "MTA-STS mode is `enforce`."));
          else if (policy.mode === "testing") findings.push(issue("mta_sts.testing", "low", "MTA-STS mode is `testing`: failures are reported but mail is still delivered insecurely.", "Switch to `mode: enforce` after reviewing TLS-RPT reports."));
          else findings.push(issue("mta_sts.mode_none", "medium", `MTA-STS mode is ${JSON.stringify(policy.mode ?? "missing")}.`, "Use `enforce` (or `testing` while rolling out)."));
          if (policy.maxAge !== undefined && policy.maxAge < 86_400) {
            findings.push(issue("mta_sts.short_max_age", "low", `max_age is ${policy.maxAge}s; senders cache the policy for too short a time.`, "Use at least 86400 (a day); 604800 or more once stable."));
          }
          const mx = await mxRecords(dns, domain);
          const uncovered = mx.filter((record) => record.exchange && !policy.mx.some((pattern) => mxMatchesPattern(record.exchange, pattern)));
          if (uncovered.length > 0) {
            findings.push(issue("mta_sts.mx_mismatch", "high", `MX host(s) not covered by the policy: ${uncovered.map((r) => r.exchange).join(", ")}. In enforce mode senders will refuse to deliver to them.`, "Add the missing hosts as `mx:` lines in the policy file."));
          }
        }
      } catch (error) {
        findings.push(issue("mta_sts.policy_unreachable", "high", `Could not fetch the policy file: ${error instanceof Error ? error.message : String(error)}`, "Host `https://mta-sts.<domain>/.well-known/mta-sts.txt` with a valid certificate."));
      }
    }
  }
  const tlsRpt = (await txtRecords(dns, `_smtp._tls.${domain}`)).some((txt) => /^v=tlsrptv1\b/i.test(txt));
  findings.push(
    tlsRpt
      ? good("tls_rpt.present", "A TLS-RPT record is published.")
      : issue("tls_rpt.missing", "info", "No TLS-RPT record, so you get no reports about TLS delivery failures.", "Publish `_smtp._tls` TXT `v=TLSRPTv1; rua=mailto:<mailbox>`."),
  );
  return findings;
}

// ---------------------------------------------------------------------------------------------

export async function auditMailAuth(
  dns: DnsClient,
  http: HttpDeps | undefined,
  domain: string,
  options: MailAuthOptions = {},
): Promise<MailAuthResult> {
  const result: MailAuthResult = { domain, dkim: { found: [], revoked: [], probed: 0 }, mx: [], findings: [] };
  const [mx, spf, dkim, dmarc, mtaSts] = await Promise.all([
    checkMx(dns, domain, result),
    checkSpf(dns, domain, result),
    checkDkim(dns, domain, options.dkimSelectors ?? [], result),
    checkDmarc(dns, domain, result),
    checkMtaSts(dns, http, domain, options.fetchMtaSts ?? true, result),
  ]);
  result.findings = [...mx, ...spf, ...dkim, ...dmarc, ...mtaSts];
  return result;
}
