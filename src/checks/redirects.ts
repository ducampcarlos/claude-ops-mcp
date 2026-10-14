/** Redirect analysis for one URL, and consistency across the http/https and www/non-www variants. */

import { type Finding, good, issue } from "../findings.js";
import { type HttpDeps, type HttpResult, fetchSafe } from "../net/safe-http.js";
import { parseHttpUrl } from "../security/policy.js";

export interface VariantResult {
  start: string;
  finalUrl?: string;
  finalStatus?: number;
  hops: number;
  error?: string;
}

export interface RedirectAnalysis {
  primary: Pick<HttpResult, "requestedUrl" | "finalUrl" | "status" | "chain" | "loop" | "tooManyRedirects" | "stoppedAt">;
  variants: VariantResult[];
  findings: Finding[];
}

async function follow(deps: HttpDeps, url: string): Promise<HttpResult> {
  return fetchSafe(deps, url, { followRedirects: true, maxBodyBytes: 1024 });
}

export function analyzeChain(result: Pick<HttpResult, "chain" | "loop" | "tooManyRedirects" | "stoppedAt" | "status" | "finalUrl">): Finding[] {
  const findings: Finding[] = [];
  const hops = result.chain.length - 1;

  if (result.loop) findings.push(issue("redirect.loop", "high", `Redirect loop detected: ${result.stoppedAt?.reason ?? ""}`, "Fix the rewrite rules; the loop usually comes from conflicting http→https and www rules."));
  if (result.tooManyRedirects) findings.push(issue("redirect.too_many", "high", `More than ${hops} redirects in a row.`, "Collapse the chain into a single redirect."));
  if (result.stoppedAt && !result.loop) findings.push(issue("redirect.stopped", "high", `The chain was stopped at ${result.stoppedAt.url}: ${result.stoppedAt.reason}`, "Make sure every redirect target is reachable."));
  if (!result.loop && !result.tooManyRedirects && hops > 2) findings.push(issue("redirect.long_chain", "low", `${hops} redirects before the final page (${result.chain.map((h) => h.status).join(" → ")}).`, "Redirect straight to the final URL; every extra hop adds latency and loses SEO signals."));
  if (result.status >= 400) findings.push(issue("redirect.final_error", "high", `The final URL ${result.finalUrl} returns HTTP ${result.status}.`, "Fix the destination or the redirect target."));
  if (hops > 0 && result.chain.slice(0, -1).some((h) => h.status === 302 || h.status === 307)) {
    findings.push(issue("redirect.temporary", "low", "A redirect uses a temporary status (302/307). Search engines may keep indexing the old URL.", "Use 301/308 for permanent moves."));
  }
  if (hops > 0 && result.chain.slice(0, -1).some((h) => h.status === 301 || h.status === 308) && !result.loop && result.status < 400 && findings.length === 0) {
    findings.push(good("redirect.clean", `${hops} permanent redirect(s) reaching ${result.finalUrl}.`));
  }
  if (hops === 0 && result.status < 400) findings.push(good("redirect.none", `No redirect; the URL answers directly with HTTP ${result.status}.`));
  return findings;
}

export async function analyzeRedirects(deps: HttpDeps, input: string, checkVariants = true): Promise<RedirectAnalysis> {
  const start = parseHttpUrl(input);
  const primary = await follow(deps, start.url.href);
  const findings = analyzeChain(primary);

  const variants: VariantResult[] = [];
  if (checkVariants && !/^\d+\.\d+\.\d+\.\d+$/.test(start.hostname) && !start.hostname.includes(":")) {
    const bare = start.hostname.replace(/^www\./, "");
    const port = start.url.port ? `:${start.url.port}` : "";
    const candidates = [`http://${bare}${port}/`, `http://www.${bare}${port}/`, `https://${bare}${port}/`, `https://www.${bare}${port}/`];
    for (const candidate of candidates) {
      try {
        const result = await follow(deps, candidate);
        variants.push({ start: candidate, finalUrl: result.finalUrl, finalStatus: result.status, hops: result.chain.length - 1 });
      } catch (error) {
        variants.push({ start: candidate, hops: 0, error: error instanceof Error ? error.message : String(error) });
      }
    }

    const reachable = variants.filter((v) => v.finalUrl && (v.finalStatus ?? 0) < 400);
    const httpVariants = reachable.filter((v) => v.start.startsWith("http://"));
    const notUpgraded = httpVariants.filter((v) => v.finalUrl!.startsWith("http://"));
    if (notUpgraded.length > 0) {
      findings.push(issue("redirect.http_not_upgraded", "high", `Plain-HTTP variant(s) do not redirect to HTTPS: ${notUpgraded.map((v) => v.start).join(", ")}.`, "Add a site-wide 301 from http:// to https://."));
    }
    const finals = new Set(reachable.map((v) => v.finalUrl!.replace(/\/$/, "")));
    if (finals.size > 1) {
      findings.push(issue("redirect.variants_diverge", "medium", `The http/https and www/non-www variants end on different URLs: ${[...finals].join(", ")}.`, "Pick one canonical host and redirect every other variant to it."));
    } else if (finals.size === 1 && notUpgraded.length === 0 && reachable.length === variants.length) {
      findings.push(good("redirect.variants_converge", `All four http/https and www/non-www variants converge on ${[...finals][0]}.`));
    }
    const unreachable = variants.filter((v) => v.error);
    if (unreachable.length > 0) {
      findings.push(issue("redirect.variant_unreachable", "low", `Variant(s) not reachable: ${unreachable.map((v) => `${v.start} (${v.error})`).join("; ")}.`, "Make sure the apex and www both resolve and serve (or redirect) correctly."));
    }
  }

  return {
    primary: {
      requestedUrl: primary.requestedUrl,
      finalUrl: primary.finalUrl,
      status: primary.status,
      chain: primary.chain,
      loop: primary.loop,
      tooManyRedirects: primary.tooManyRedirects,
      stoppedAt: primary.stoppedAt,
    },
    variants,
    findings,
  };
}
