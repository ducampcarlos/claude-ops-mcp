/**
 * Sitemap audit: discover the sitemap, sample its URLs and check what a search engine would see.
 *
 * Only URLs on the SAME HOST as the sitemap are requested, so a hostile sitemap cannot turn the
 * tool into a scanner for third-party sites. Everything else is counted but never fetched.
 */

import { type Finding, good, issue } from "../findings.js";
import { extractCanonical, extractMetaRobots, extractTitle, hasNoindex } from "../net/html.js";
import { type HttpDeps, fetchSafe, header } from "../net/safe-http.js";
import { parseHttpUrl } from "../security/policy.js";
import { type Robots, parseRobots } from "./robots.js";

const MAX_URLS_PARSED = 50_000;
const MAX_CHILD_SITEMAPS = 10;
const MAX_LISTED_PROBLEMS = 50;
const CONCURRENCY = 4;

export interface SitemapOptions {
  /** URLs to request (evenly sampled). */
  sample?: number;
}

export type UrlProblem =
  | "broken"
  | "redirected"
  | "noindex"
  | "no_title"
  | "canonical_mismatch"
  | "blocked_by_robots"
  | "unreachable";

export interface UrlCheck {
  url: string;
  status?: number;
  problems: UrlProblem[];
  detail?: string;
}

export interface SitemapResult {
  sitemaps: string[];
  totalUrls: number;
  uniqueUrls: number;
  duplicateUrls: number;
  offHostUrls: number;
  mixedSchemeUrls: number;
  checked: number;
  ok: number;
  /** Problem URLs only, capped. */
  problems: UrlCheck[];
  robotsFetched: boolean;
  findings: Finding[];
}

export function parseSitemapXml(xml: string): { kind: "index" | "urlset" | "unknown"; locs: string[]; truncated: boolean } {
  const kind = /<sitemapindex[\s>]/i.test(xml) ? "index" : /<urlset[\s>]/i.test(xml) ? "urlset" : "unknown";
  const locs: string[] = [];
  const pattern = /<loc>\s*(?:<!\[CDATA\[([\s\S]*?)\]\]>|([^<]*?))\s*<\/loc>/gi;
  let truncated = false;
  for (let match = pattern.exec(xml); match; match = pattern.exec(xml)) {
    if (locs.length >= MAX_URLS_PARSED) {
      truncated = true;
      break;
    }
    const raw = (match[1] ?? match[2] ?? "").trim();
    if (raw) locs.push(raw.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'"));
  }
  return { kind, locs, truncated };
}

const bareHost = (host: string) => host.replace(/^www\./, "");

function sample<T>(items: T[], count: number): T[] {
  if (items.length <= count) return items;
  // Evenly spaced and deterministic, so repeated audits compare like with like.
  return Array.from({ length: count }, (_, i) => items[Math.floor((i * items.length) / count)]!);
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const index = next++;
        results[index] = await fn(items[index]!);
      }
    }),
  );
  return results;
}

async function fetchText(deps: HttpDeps, url: string): Promise<{ status: number; body: string; truncated: boolean } | undefined> {
  try {
    const response = await fetchSafe(deps, url, { maxBodyBytes: deps.config.maxBodyBytes });
    return { status: response.status, body: response.body, truncated: response.truncated };
  } catch {
    return undefined;
  }
}

export async function auditSitemap(deps: HttpDeps, input: string, options: SitemapOptions = {}): Promise<SitemapResult> {
  const start = parseHttpUrl(input);
  const origin = start.url.origin;
  const findings: Finding[] = [];
  const sitemapUrls: string[] = [];
  let robots: Robots | undefined;
  let robotsFetched = false;

  // --- Discover -------------------------------------------------------------------------------
  const robotsResponse = await fetchText(deps, `${origin}/robots.txt`);
  if (robotsResponse && robotsResponse.status === 200) {
    robots = parseRobots(robotsResponse.body);
    robotsFetched = true;
  }

  if (/\.xml$/i.test(start.url.pathname)) {
    sitemapUrls.push(start.url.href);
  } else if (robots && robots.sitemaps.length > 0) {
    sitemapUrls.push(...robots.sitemaps.slice(0, 5));
  } else {
    sitemapUrls.push(`${origin}/sitemap.xml`, `${origin}/sitemap_index.xml`);
  }

  // --- Fetch and parse (follow one level of index files) -----------------------------------------
  const fetched: string[] = [];
  const locs: string[] = [];
  const queue = [...sitemapUrls];
  let childCount = 0;
  let truncatedAny = false;
  const gzip = queue.filter((url) => /\.gz$/i.test(url));
  for (let url = queue.shift(); url !== undefined; url = queue.shift()) {
    if (/\.gz$/i.test(url)) continue;
    const response = await fetchText(deps, url);
    if (!response) {
      if (fetched.length === 0 && queue.length === 0) break;
      continue;
    }
    if (response.status !== 200) continue;
    fetched.push(url);
    if (response.truncated) truncatedAny = true;
    const parsed = parseSitemapXml(response.body);
    if (parsed.kind === "index") {
      for (const child of parsed.locs) {
        if (childCount >= MAX_CHILD_SITEMAPS) break;
        childCount += 1;
        queue.push(child);
      }
    } else if (parsed.kind === "urlset") {
      locs.push(...parsed.locs);
      if (parsed.truncated) truncatedAny = true;
    }
  }

  if (gzip.length > 0 && fetched.length === 0) {
    findings.push(issue("sitemap.gzip_unsupported", "info", "Compressed (.gz) sitemaps are not read by this tool.", "Point the audit at an uncompressed sitemap URL."));
  }
  if (fetched.length === 0) {
    findings.push(issue("sitemap.not_found", "high", `No sitemap found (tried ${sitemapUrls.join(", ")}).`, "Publish /sitemap.xml and reference it from robots.txt (`Sitemap: https://example.com/sitemap.xml`)."));
    return { sitemaps: [], totalUrls: 0, uniqueUrls: 0, duplicateUrls: 0, offHostUrls: 0, mixedSchemeUrls: 0, checked: 0, ok: 0, problems: [], robotsFetched, findings };
  }
  if (!robots || robots.sitemaps.length === 0) {
    findings.push(issue("sitemap.not_in_robots", "low", "The sitemap is not referenced from robots.txt.", "Add `Sitemap: <absolute URL>` to robots.txt."));
  }
  if (truncatedAny) {
    findings.push(issue("sitemap.truncated", "low", "A sitemap was larger than the byte cap and only part of it was read. Counts may be understated.", "Raise OPS_MCP_MAX_BODY_BYTES, or audit the child sitemaps one by one."));
  }
  if (locs.length === 0) {
    findings.push(issue("sitemap.empty", "high", "The sitemap contains no URLs.", "Check how the sitemap is generated."));
  }

  // --- Static analysis ---------------------------------------------------------------------------
  const unique = [...new Set(locs)];
  const duplicates = locs.length - unique.length;
  const sitemapHost = bareHost(start.hostname);
  const sameHost: string[] = [];
  let offHost = 0;
  let mixedScheme = 0;
  for (const loc of unique) {
    let parsed;
    try {
      parsed = parseHttpUrl(loc);
    } catch {
      offHost += 1;
      continue;
    }
    if (bareHost(parsed.hostname) !== sitemapHost) {
      offHost += 1;
      continue;
    }
    if (parsed.url.protocol !== start.url.protocol) mixedScheme += 1;
    sameHost.push(parsed.url.href);
  }

  if (duplicates > 0) findings.push(issue("sitemap.duplicates", "low", `${duplicates} duplicate URL entr${duplicates === 1 ? "y" : "ies"} in the sitemap.`, "List every URL once."));
  if (offHost > 0) findings.push(issue("sitemap.off_host", "low", `${offHost} URL(s) point to other hosts. They were not requested. Sitemaps may only list URLs on their own host.`, "Remove them or move them to their own host's sitemap."));
  if (mixedScheme > 0) findings.push(issue("sitemap.mixed_scheme", "medium", `${mixedScheme} URL(s) use a different scheme (http/https) than the sitemap itself.`, "List only the canonical https URLs."));
  if (unique.length > 50_000) findings.push(issue("sitemap.too_large", "medium", `${unique.length} URLs; the limit per sitemap file is 50,000.`, "Split into several sitemaps behind a sitemap index."));

  // --- Dynamic checks on a sample --------------------------------------------------------------
  const budget = Math.min(options.sample ?? 25, deps.config.maxSitemapChecks);
  const toCheck = sample(sameHost, Math.max(0, budget));
  const results = await mapLimit(toCheck, CONCURRENCY, (url) => checkUrl(deps, url, robots));

  const bad = results.filter((r) => r.problems.length > 0);
  const count = (problem: UrlProblem) => results.filter((r) => r.problems.includes(problem));
  const label = (urls: UrlCheck[]) => `${urls.length} of ${results.length} sampled URLs`;

  const server = results.filter((r) => r.status !== undefined && r.status >= 500);
  const client = results.filter((r) => r.status !== undefined && r.status >= 400 && r.status < 500);
  if (server.length > 0) findings.push(issue("sitemap.server_errors", "high", `${label(server)} return a 5xx error (e.g. ${server[0]!.url}).`, "Fix the failing pages or remove them from the sitemap; Google drops sitemaps full of errors."));
  if (client.length > 0) findings.push(issue("sitemap.not_found_urls", "medium", `${label(client)} return a 4xx error (e.g. ${client[0]!.url} → ${client[0]!.status}).`, "Remove dead URLs from the sitemap (or fix the slugs the generator produces)."));
  if (count("unreachable").length > 0) findings.push(issue("sitemap.unreachable", "medium", `${label(count("unreachable"))} could not be fetched (e.g. ${count("unreachable")[0]!.url}: ${count("unreachable")[0]!.detail}).`, "Check the host and TLS configuration."));
  if (count("redirected").length > 0) findings.push(issue("sitemap.redirects", "medium", `${label(count("redirected"))} redirect elsewhere (e.g. ${count("redirected")[0]!.url} → ${count("redirected")[0]!.detail}).`, "List the final destination URLs, not the redirecting ones."));
  if (count("noindex").length > 0) findings.push(issue("sitemap.noindex", "high", `${label(count("noindex"))} are marked noindex yet listed in the sitemap (e.g. ${count("noindex")[0]!.url}).`, "Either remove the noindex or remove the URLs from the sitemap; they send contradictory signals."));
  if (count("blocked_by_robots").length > 0) findings.push(issue("sitemap.blocked_by_robots", "high", `${label(count("blocked_by_robots"))} are blocked by robots.txt for Googlebot (e.g. ${count("blocked_by_robots")[0]!.url}).`, "Unblock them in robots.txt or remove them from the sitemap."));
  if (count("canonical_mismatch").length > 0) findings.push(issue("sitemap.canonical_mismatch", "medium", `${label(count("canonical_mismatch"))} declare a canonical URL different from the one listed (e.g. ${count("canonical_mismatch")[0]!.url} → ${count("canonical_mismatch")[0]!.detail}).`, "List the canonical URLs only."));
  if (count("no_title").length > 0) findings.push(issue("sitemap.no_title", "low", `${label(count("no_title"))} have no <title> (e.g. ${count("no_title")[0]!.url}).`, "Give every indexable page a unique title."));
  if (results.length > 0 && bad.length === 0) findings.push(good("sitemap.healthy", `All ${results.length} sampled URLs returned 200 with a title, no noindex, no redirect and no robots block.`));

  return {
    sitemaps: fetched,
    totalUrls: locs.length,
    uniqueUrls: unique.length,
    duplicateUrls: duplicates,
    offHostUrls: offHost,
    mixedSchemeUrls: mixedScheme,
    checked: results.length,
    ok: results.length - bad.length,
    problems: bad.slice(0, MAX_LISTED_PROBLEMS),
    robotsFetched,
    findings,
  };
}

async function checkUrl(deps: HttpDeps, url: string, robots: Robots | undefined): Promise<UrlCheck> {
  const problems: UrlProblem[] = [];
  const parsed = new URL(url);
  if (robots && !robots.isAllowed("googlebot", parsed.pathname + parsed.search)) problems.push("blocked_by_robots");

  let response;
  try {
    response = await fetchSafe(deps, url, { followRedirects: false, maxBodyBytes: 256 * 1024 });
  } catch (error) {
    return { url, problems: [...problems, "unreachable"], detail: error instanceof Error ? error.message : String(error) };
  }

  const check: UrlCheck = { url, status: response.status, problems };
  if (response.status >= 300 && response.status < 400) {
    problems.push("redirected");
    check.detail = `${response.status} ${header(response.headers, "location") ?? "(no Location)"}`;
  } else if (response.status >= 400) {
    problems.push("broken");
  } else if (response.status >= 200) {
    const type = header(response.headers, "content-type") ?? "";
    const isHtml = /html/i.test(type) || type === "";
    if (hasNoindex(header(response.headers, "x-robots-tag"))) problems.push("noindex");
    if (isHtml) {
      const robotsMeta = extractMetaRobots(response.body);
      if (hasNoindex(robotsMeta) && !problems.includes("noindex")) problems.push("noindex");
      if (!extractTitle(response.body)) problems.push("no_title");
      const canonical = extractCanonical(response.body);
      if (canonical) {
        try {
          const resolved = new URL(canonical, url);
          const normalise = (u: URL) => `${bareHost(u.hostname)}${u.pathname.replace(/\/$/, "")}${u.search}`;
          if (normalise(resolved) !== normalise(parsed)) {
            problems.push("canonical_mismatch");
            check.detail = resolved.href;
          }
        } catch {
          /* an invalid canonical is its own problem, but not one this audit scores */
        }
      }
    }
  }
  return check;
}
