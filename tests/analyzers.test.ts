import { describe, expect, it } from "vitest";

import { parseRobots } from "../src/checks/robots.js";
import { analyzeChain } from "../src/checks/redirects.js";
import { analyzeHeaders, parseCsp, parseSetCookie } from "../src/checks/security-headers.js";
import { parseSitemapXml } from "../src/checks/sitemap.js";
import { renderFindings, score, sortFindings, worstSeverity, good, issue } from "../src/findings.js";

const byId = (findings: { id: string }[], id: string) => findings.find((f) => f.id === id);
const issueIds = (findings: { id: string; ok?: boolean }[]) => findings.filter((f) => !f.ok).map((f) => f.id);

describe("findings", () => {
  it("scores and grades", () => {
    expect(score([good("a", "x")])).toEqual({ score: 100, grade: "A" });
    expect(score([issue("a", "high", "x")])).toEqual({ score: 75, grade: "B" });
    expect(score([issue("a", "high", "x"), issue("b", "medium", "y"), issue("c", "low", "z")])).toEqual({ score: 62, grade: "C" });
    expect(score(Array.from({ length: 5 }, (_, i) => issue(`h${i}`, "high", "x")))).toEqual({ score: 0, grade: "F" });
    expect(score([issue("i", "info", "x")]).score).toBe(100);
  });

  it("finds the worst severity among problems only", () => {
    expect(worstSeverity([good("a", "x"), issue("b", "low", "y"), issue("c", "medium", "z")])).toBe("medium");
    expect(worstSeverity([good("a", "x")])).toBeUndefined();
  });

  it("sorts problems first, worst first, and renders fixes only for problems", () => {
    const sorted = sortFindings([good("ok", "fine"), issue("low", "low", "l", "fix low"), issue("high", "high", "h", "fix high")]);
    expect(sorted.map((f) => f.id)).toEqual(["high", "low", "ok"]);
    const text = renderFindings(sorted);
    expect(text).toContain("[HIGH] high: h");
    expect(text).toContain("Fix: fix high");
    expect(text).toContain("[OK] ok: fine");
    expect(text).not.toMatch(/Fix:.*fine/);
  });
});

describe("analyzeHeaders", () => {
  const strong = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
  };

  it("has no issues for a well configured HTTPS site", () => {
    const result = analyzeHeaders(strong, "https://example.test/");
    expect(issueIds(result.findings)).toEqual([]);
    expect(score(result.findings).grade).toBe("A");
    expect(result.present["strict-transport-security"]).toContain("max-age=63072000");
  });

  it("flags everything missing on a bare response", () => {
    const result = analyzeHeaders({}, "https://example.test/");
    expect(issueIds(result.findings)).toEqual(
      expect.arrayContaining(["headers.hsts_missing", "headers.csp_missing", "headers.nosniff_missing", "headers.clickjacking", "headers.referrer_missing"]),
    );
    expect(byId(result.findings, "headers.hsts_missing")).toMatchObject({ severity: "medium" });
  });

  it("flags plain HTTP and does not demand HSTS there", () => {
    const result = analyzeHeaders({}, "http://example.test/");
    expect(byId(result.findings, "headers.no_https")).toMatchObject({ severity: "high" });
    expect(byId(result.findings, "headers.hsts_missing")).toBeUndefined();
  });

  it("evaluates HSTS strength", () => {
    expect(byId(analyzeHeaders({ ...strong, "strict-transport-security": "max-age=300" }, "https://x/").findings, "headers.hsts_short")).toBeDefined();
    expect(byId(analyzeHeaders({ ...strong, "strict-transport-security": "max-age=31536000" }, "https://x/").findings, "headers.hsts_no_subdomains")).toBeDefined();
  });

  it("detects weak CSPs", () => {
    const weak = (csp: string) => analyzeHeaders({ ...strong, "content-security-policy": csp }, "https://x/").findings;
    expect(byId(weak("default-src 'self'; script-src 'self' 'unsafe-inline'"), "headers.csp_weak")).toBeDefined();
    expect(byId(weak("script-src 'self' 'unsafe-eval'"), "headers.csp_weak")).toBeDefined();
    expect(byId(weak("script-src *"), "headers.csp_weak")).toBeDefined();
    expect(byId(weak("img-src 'self'"), "headers.csp_weak")).toBeDefined(); // no script-src/default-src at all
    expect(byId(weak("script-src 'self' 'unsafe-inline' 'nonce-xyz'"), "headers.csp_weak")).toBeUndefined(); // nonce neutralises it
    expect(byId(weak("default-src 'none'; frame-ancestors 'self'"), "headers.csp_object_src")).toBeUndefined();
  });

  it("notes report-only CSP", () => {
    const result = analyzeHeaders({ "content-security-policy-report-only": "default-src 'self'" }, "https://x/");
    expect(byId(result.findings, "headers.csp_report_only")).toMatchObject({ severity: "low" });
    expect(byId(result.findings, "headers.csp_missing")).toBeUndefined();
  });

  it("accepts X-Frame-Options or frame-ancestors for clickjacking protection", () => {
    expect(byId(analyzeHeaders({ "x-frame-options": "DENY" }, "https://x/").findings, "headers.clickjacking")).toBeUndefined();
    expect(byId(analyzeHeaders({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'" }, "https://x/").findings, "headers.clickjacking")).toBeUndefined();
  });

  it("flags a leaky referrer policy and information disclosure", () => {
    const result = analyzeHeaders({ ...strong, "referrer-policy": "unsafe-url", server: "nginx/1.18.0", "x-powered-by": "PHP/7.4.3" }, "https://x/");
    expect(issueIds(result.findings)).toEqual(expect.arrayContaining(["headers.referrer_weak", "headers.server_version", "headers.x_powered_by"]));
    expect(byId(analyzeHeaders({ ...strong, server: "nginx" }, "https://x/").findings, "headers.server_version")).toBeUndefined();
  });

  it("flags dangerous CORS", () => {
    const worst = analyzeHeaders({ ...strong, "access-control-allow-origin": "*", "access-control-allow-credentials": "true" }, "https://x/");
    expect(byId(worst.findings, "headers.cors_wildcard_credentials")).toMatchObject({ severity: "high" });
    const mild = analyzeHeaders({ ...strong, "access-control-allow-origin": "*" }, "https://x/");
    expect(byId(mild.findings, "headers.cors_wildcard")).toMatchObject({ severity: "info" });
  });

  it("audits cookies without ever exposing their values", () => {
    const result = analyzeHeaders(
      { ...strong, "set-cookie": ["sessionid=SUPERSECRET123; Path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax", "x=1; SameSite=None"] },
      "https://x/",
    );
    const ids = issueIds(result.findings);
    expect(ids).toEqual(expect.arrayContaining(["headers.cookie_not_secure", "headers.cookie_not_httponly", "headers.cookie_no_samesite", "headers.cookie_samesite_none_insecure"]));
    expect(byId(result.findings, "headers.cookie_not_secure")).toMatchObject({ severity: "high" }); // session-like name
    expect(JSON.stringify(result)).not.toContain("SUPERSECRET123");
    expect(result.cookies.map((c) => c.name)).toEqual(["sessionid", "theme", "x"]);
  });

  it("parses cookies and CSP", () => {
    expect(parseSetCookie("__Host-id=abc; Secure; HttpOnly; SameSite=Strict; Path=/")).toEqual({ name: "__Host-id", secure: true, httpOnly: true, sameSite: "strict", hasPrefix: true });
    expect(parseCsp("default-src 'self'; img-src * data:;")).toEqual({ "default-src": ["'self'"], "img-src": ["*", "data:"] });
  });
});

describe("robots.txt", () => {
  const robots = parseRobots(`
    # comment
    User-agent: *
    Disallow: /private
    Disallow: /*.pdf$
    Allow: /private/public
    Disallow:

    User-agent: googlebot
    User-agent: bingbot
    Disallow: /g-only/
    Sitemap: https://example.test/sitemap.xml
    Sitemap: https://example.test/news.xml
  `);

  it("collects sitemaps", () => {
    expect(robots.sitemaps).toEqual(["https://example.test/sitemap.xml", "https://example.test/news.xml"]);
  });

  it("applies the * group to other crawlers with longest-match-wins", () => {
    expect(robots.isAllowed("somebot", "/")).toBe(true);
    expect(robots.isAllowed("somebot", "/private")).toBe(false);
    expect(robots.isAllowed("somebot", "/private/secret")).toBe(false);
    expect(robots.isAllowed("somebot", "/private/public")).toBe(true);
    expect(robots.isAllowed("somebot", "/docs/file.pdf")).toBe(false);
    expect(robots.isAllowed("somebot", "/docs/file.pdf?x=1")).toBe(true); // `$` anchors the end
    expect(robots.isAllowed("somebot", "/g-only/x")).toBe(true);
  });

  it("uses the most specific user-agent group and shares groups across stacked agents", () => {
    expect(robots.isAllowed("Googlebot/2.1", "/g-only/x")).toBe(false);
    expect(robots.isAllowed("Googlebot/2.1", "/private")).toBe(true); // the googlebot group has no /private rule
    expect(robots.isAllowed("bingbot", "/g-only/")).toBe(false);
  });

  it("allows everything when there are no rules, and ties go to Allow", () => {
    expect(parseRobots("").isAllowed("x", "/anything")).toBe(true);
    expect(parseRobots("User-agent: *\nDisallow: /a\nAllow: /a").isAllowed("x", "/a")).toBe(true);
  });

  it("survives hostile input", () => {
    const started = Date.now();
    const hostile = parseRobots("User-agent: *\n" + "Disallow: /" + "*a".repeat(200) + "\n".repeat(3) + "x:".repeat(10_000));
    hostile.isAllowed("x", "/" + "a".repeat(5000));
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe("parseSitemapXml", () => {
  it("reads urlsets, CDATA and entities", () => {
    const xml = `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://e.test/a?x=1&amp;y=2</loc></url>
      <url><loc> https://e.test/b </loc><lastmod>2026-01-01</lastmod></url>
      <url><loc><![CDATA[https://e.test/c?q=a&b]]></loc></url>
    </urlset>`;
    expect(parseSitemapXml(xml)).toEqual({ kind: "urlset", locs: ["https://e.test/a?x=1&y=2", "https://e.test/b", "https://e.test/c?q=a&b"], truncated: false });
  });

  it("recognises sitemap indexes and unknown documents", () => {
    expect(parseSitemapXml("<sitemapindex><sitemap><loc>https://e.test/1.xml</loc></sitemap></sitemapindex>")).toMatchObject({ kind: "index", locs: ["https://e.test/1.xml"] });
    expect(parseSitemapXml("<html><body>Not found</body></html>")).toMatchObject({ kind: "unknown", locs: [] });
  });

  it("caps the number of parsed URLs", () => {
    const xml = "<urlset>" + "<url><loc>https://e.test/x</loc></url>".repeat(50_100) + "</urlset>";
    const parsed = parseSitemapXml(xml);
    expect(parsed.locs).toHaveLength(50_000);
    expect(parsed.truncated).toBe(true);
  });
});

describe("analyzeChain", () => {
  const hop = (status: number, url = "https://e.test/") => ({ url, status, address: "1.2.3.4", ms: 1 });
  const base = { loop: false, tooManyRedirects: false, stoppedAt: undefined, status: 200, finalUrl: "https://e.test/" };

  it("is happy with one permanent redirect", () => {
    const findings = analyzeChain({ ...base, chain: [hop(301, "http://e.test/"), hop(200)] });
    expect(issueIds(findings)).toEqual([]);
    expect(byId(findings, "redirect.clean")).toBeDefined();
  });

  it("flags long chains, temporary redirects, loops and dead ends", () => {
    expect(byId(analyzeChain({ ...base, chain: [hop(301), hop(301), hop(301), hop(200)] }), "redirect.long_chain")).toBeDefined();
    expect(byId(analyzeChain({ ...base, chain: [hop(302), hop(200)] }), "redirect.temporary")).toBeDefined();
    expect(byId(analyzeChain({ ...base, loop: true, stoppedAt: { url: "x", reason: "redirect loop" }, status: 302, chain: [hop(302), hop(302)] }), "redirect.loop")).toMatchObject({ severity: "high" });
    expect(byId(analyzeChain({ ...base, status: 404, chain: [hop(301), hop(404)] }), "redirect.final_error")).toMatchObject({ severity: "high" });
    expect(byId(analyzeChain({ ...base, stoppedAt: { url: "http://10.0.0.1/", reason: "blocked" }, chain: [hop(302)], status: 302 }), "redirect.stopped")).toBeDefined();
  });

  it("notes when there is no redirect at all", () => {
    expect(byId(analyzeChain({ ...base, chain: [hop(200)] }), "redirect.none")).toBeDefined();
  });
});
