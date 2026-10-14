import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { analyzeHeaders } from "../checks/security-headers.js";
import { analyzeRedirects } from "../checks/redirects.js";
import { auditSitemap } from "../checks/sitemap.js";
import { extractMetaRobots, extractTitle } from "../net/html.js";
import { type HeaderMap, fetchSafe, header } from "../net/safe-http.js";
import type { Runtime } from "../runtime.js";
import { auditTarget, registerTool } from "./define.js";

const url = z.string().min(1).max(2048).describe("Absolute http(s) URL, e.g. https://example.com/. Credentials in URLs are rejected.");

/** Headers worth showing; set-cookie is reduced to cookie NAMES so values never reach the model. */
const SHOWN = ["content-type", "content-length", "content-encoding", "server", "date", "last-modified", "etag", "cache-control", "age", "expires", "vary", "location", "via", "x-cache", "cf-cache-status", "x-served-by", "x-robots-tag", "alt-svc", "link"];

function publicHeaders(headers: HeaderMap): Record<string, string> {
  const shown: Record<string, string> = {};
  for (const name of SHOWN) {
    const value = header(headers, name);
    if (value !== undefined) shown[name] = value.slice(0, 300);
  }
  const cookies = headers["set-cookie"];
  const list = Array.isArray(cookies) ? cookies : cookies ? [cookies] : [];
  if (list.length > 0) shown["set-cookie"] = `${list.length} cookie(s): ${list.map((c) => c.split("=")[0]).join(", ")} (values hidden)`;
  return shown;
}

const clip = (text: string | undefined, max = 200) => (text && text.length > max ? `${text.slice(0, max)}…` : text);

export function registerWebTools(server: McpServer, runtime: Runtime): void {
  registerTool(server, runtime, {
    name: "http_probe",
    title: "Probe an HTTP(S) URL",
    description:
      "Makes one GET or HEAD request and reports status, redirect chain, timings, headers, size, page title and robots meta. Use it to answer 'is this URL up, where does it redirect, how fast is it?'. The response body is NOT returned.",
    inputSchema: {
      url,
      method: z.enum(["GET", "HEAD"]).default("GET"),
      follow_redirects: z.boolean().default(true).describe("Follow redirects (every hop is re-validated). Set false to see the first response only."),
      allow_invalid_cert: z.boolean().default(false).describe("Still fetch if the TLS certificate is invalid (use tls_inspect to diagnose the certificate itself)."),
    },
    target: ({ url }) => auditTarget(url),
    async run({ url, method, follow_redirects, allow_invalid_cert }, runtime) {
      const result = await fetchSafe(runtime.http, url, { method, followRedirects: follow_redirects, allowInvalidCert: allow_invalid_cert, maxBodyBytes: 512 * 1024 });
      const type = header(result.headers, "content-type") ?? "";
      const html = /html/i.test(type) && method === "GET";
      const title = html ? extractTitle(result.body) : undefined;
      const robots = html ? extractMetaRobots(result.body) : undefined;

      const lines = [
        `${method} ${result.requestedUrl} → HTTP ${result.status}${result.finalUrl !== result.requestedUrl ? ` (final URL ${result.finalUrl})` : ""}`,
        `Redirects: ${result.redirects}${result.chain.length > 1 ? ` (${result.chain.map((h) => h.status).join(" → ")})` : ""}`,
        `Timing: first byte ${result.ttfbMs} ms, total ${result.totalMs} ms; server address ${result.address}`,
        `Type: ${type || "(none)"}; body read: ${result.bodyBytes} bytes${result.truncated ? " (truncated at cap)" : ""}`,
      ];
      if (title) lines.push(`Title (untrusted page content): ${clip(title)}`);
      if (robots) lines.push(`Meta robots: ${clip(robots, 100)}`);
      if (result.loop) lines.push("Redirect loop detected.");
      if (result.stoppedAt) lines.push(`Stopped at ${result.stoppedAt.url}: ${result.stoppedAt.reason}`);

      return {
        summary: lines.join("\n"),
        data: {
          requested_url: result.requestedUrl,
          final_url: result.finalUrl,
          status: result.status,
          chain: result.chain,
          loop: result.loop,
          stopped_at: result.stoppedAt ?? null,
          ttfb_ms: result.ttfbMs,
          total_ms: result.totalMs,
          body_bytes: result.bodyBytes,
          body_truncated: result.truncated,
          address: result.address,
          title: clip(title) ?? null,
          meta_robots: clip(robots, 100) ?? null,
          headers: publicHeaders(result.headers),
        },
      };
    },
  });

  registerTool(server, runtime, {
    name: "redirect_chain",
    title: "Analyze redirects",
    description:
      "Follows the redirect chain of a URL hop by hop and checks http→https upgrade and that the http/https and www/non-www variants all converge on one canonical URL. Use it after a migration or when pages 'redirect too many times'.",
    inputSchema: {
      url,
      check_variants: z.boolean().default(true).describe("Also test http://, https://, www. and non-www variants of the host (4 extra requests)."),
    },
    target: ({ url }) => auditTarget(url),
    async run({ url, check_variants }, runtime) {
      const result = await analyzeRedirects(runtime.http, url, check_variants);
      const chain = result.primary.chain.map((hop) => `${hop.status} ${hop.url}${hop.location ? ` → ${hop.location}` : ""}`);
      const lines = [`Redirect chain for ${result.primary.requestedUrl}:`, ...chain.map((line) => `  ${line}`)];
      if (result.variants.length > 0) {
        lines.push("", "Variants:");
        for (const v of result.variants) lines.push(`  ${v.start} → ${v.error ? `ERROR ${v.error}` : `${v.finalUrl} (HTTP ${v.finalStatus}, ${v.hops} hop(s))`}`);
      }
      return { summary: lines.join("\n"), data: { primary: result.primary, variants: result.variants }, findings: result.findings };
    },
  });

  registerTool(server, runtime, {
    name: "security_headers",
    title: "Audit HTTP security headers",
    description:
      "Fetches a URL (following redirects) and audits its security headers: HSTS, CSP, clickjacking, nosniff, referrer policy, CORS, cookie flags (names only, never values) and technology disclosure. Returns a score and grade with concrete fixes. This is a header check, not a penetration test.",
    inputSchema: { url },
    target: ({ url }) => auditTarget(url),
    async run({ url }, runtime) {
      const result = await fetchSafe(runtime.http, url, { maxBodyBytes: 1024 });
      const analysis = analyzeHeaders(result.headers, result.finalUrl);
      return {
        summary: `Security headers for ${result.finalUrl} (HTTP ${result.status}${result.redirects ? `, after ${result.redirects} redirect(s)` : ""})`,
        data: { final_url: result.finalUrl, status: result.status, https: analysis.https, present_headers: analysis.present, cookies: analysis.cookies },
        findings: analysis.findings,
      };
    },
  });

  registerTool(server, runtime, {
    name: "sitemap_audit",
    title: "Audit a sitemap",
    description:
      "Finds a site's sitemap (robots.txt, /sitemap.xml, sitemap indexes), then checks a sample of its URLs the way a search engine would: HTTP errors (4xx/5xx), redirects, noindex, missing <title>, canonical mismatches and URLs blocked by robots.txt. Only URLs on the sitemap's own host are requested. Ideal after a migration or when Search Console reports 'submitted URL' errors.",
    inputSchema: {
      url: url.describe("Site root (https://example.com/) or the sitemap URL itself."),
      sample: z.number().int().min(1).max(100).default(25).describe("How many URLs to request, evenly spread across the sitemap. Capped by the server."),
    },
    target: ({ url }) => auditTarget(url),
    async run({ url, sample }, runtime) {
      const result = await auditSitemap(runtime.http, url, { sample });
      const lines = [
        `Sitemap audit for ${url}`,
        `Sitemaps read: ${result.sitemaps.length ? result.sitemaps.join(", ") : "none"}`,
        `URLs: ${result.totalUrls} listed, ${result.uniqueUrls} unique${result.offHostUrls ? `, ${result.offHostUrls} on other hosts (not requested)` : ""}`,
        `Checked ${result.checked} sampled URL(s): ${result.ok} fine, ${result.checked - result.ok} with problems.`,
      ];
      if (result.problems.length > 0) {
        lines.push("", "Problem URLs:");
        for (const p of result.problems.slice(0, 25)) lines.push(`  ${p.status ?? "ERR"} ${p.url}  [${p.problems.join(", ")}]${p.detail ? ` ${clip(p.detail, 120)}` : ""}`);
        if (result.problems.length > 25) lines.push(`  … and ${result.problems.length - 25} more in the structured data`);
      }
      const { findings, ...data } = result;
      return { summary: lines.join("\n"), data, findings };
    },
  });
}
