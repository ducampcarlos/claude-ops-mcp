import { afterEach, describe, expect, it } from "vitest";

import { analyzeRedirects } from "../src/checks/redirects.js";
import { auditSitemap } from "../src/checks/sitemap.js";
import { makeDeps, startServer, type Handler, type TestServer } from "./helpers.js";

let server: TestServer | undefined;
afterEach(async () => {
  await server?.close();
  server = undefined;
});

const page = (title: string | null, extra = "") =>
  `<!doctype html><html><head>${title === null ? "" : `<title>${title}</title>`}${extra}</head><body>hi</body></html>`;

const urlset = (urls: string[]) =>
  `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map((u) => `<url><loc>${u}</loc></url>`).join("")}</urlset>`;

const ids = (findings: { id: string; ok?: boolean }[], onlyIssues = true) => findings.filter((f) => !onlyIssues || !f.ok).map((f) => f.id);
const find = <T extends { id: string }>(findings: T[], id: string): T | undefined => findings.find((f) => f.id === id);

/** A site that has every defect the real-world audits turned up (robots.txt and the sitemap are served by the test). */
function messySite(hosts: string[]): Handler {
  return (req, res) => {
    hosts.push(String(req.headers.host));
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const html = (body: string, headers: Record<string, string> = {}) =>
      void res.writeHead(200, { "content-type": "text/html", ...headers }).end(body);
    switch (path) {
      case "/ok":
        return html(page("Fine page"));
      case "/broken":
        return void res.writeHead(500).end("boom");
      case "/gone":
        return void res.writeHead(404).end("nope");
      case "/moved":
        return void res.writeHead(301, { location: "/ok" }).end();
      case "/noindex-meta":
        return html(page("Hidden", '<meta name="robots" content="noindex, follow">'));
      case "/noindex-header":
        return html(page("Hidden too"), { "x-robots-tag": "noindex" });
      case "/notitle":
        return html(page(null));
      case "/canon":
        return html(page("Canon", '<link rel="canonical" href="/somewhere-else">'));
      case "/private":
        return html(page("Private"));
      default:
        return void res.writeHead(404).end();
    }
  };
}

describe("auditSitemap", () => {
  it("finds every kind of defect in a messy site", async () => {
    const hosts: string[] = [];
    const site = messySite(hosts);
    let port = 0;
    server = await startServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      const b = `http://public.test:${port}`;
      if (path === "/robots.txt") {
        return void res.writeHead(200).end(`User-agent: *\nDisallow: /private\nSitemap: ${b}/sitemap.xml\n`);
      }
      if (path === "/sitemap.xml") {
        return void res.writeHead(200, { "content-type": "application/xml" }).end(
          urlset([
            `${b}/ok`, `${b}/ok`, `${b}/broken`, `${b}/gone`, `${b}/moved`, `${b}/noindex-meta`, `${b}/noindex-header`,
            `${b}/notitle`, `${b}/canon`, `${b}/private`, "http://other.test/x", `https://public.test:${port}/ok`,
          ]),
        );
      }
      site(req, res);
    });
    port = server.port;

    const { deps } = makeDeps();
    const result = await auditSitemap(deps, `http://public.test:${port}/`);

    expect(result.robotsFetched).toBe(true);
    expect(result.sitemaps).toEqual([`http://public.test:${port}/sitemap.xml`]);
    expect(result.totalUrls).toBe(12);
    expect(result.uniqueUrls).toBe(11);
    expect(result.duplicateUrls).toBe(1);
    expect(result.offHostUrls).toBe(1);
    expect(result.mixedSchemeUrls).toBe(1);

    const issues = ids(result.findings);
    expect(issues).toEqual(
      expect.arrayContaining([
        "sitemap.server_errors", "sitemap.not_found_urls", "sitemap.redirects", "sitemap.noindex",
        "sitemap.no_title", "sitemap.canonical_mismatch", "sitemap.blocked_by_robots", "sitemap.duplicates",
        "sitemap.off_host", "sitemap.mixed_scheme", "sitemap.unreachable",
      ]),
    );
    expect(find(result.findings, "sitemap.server_errors")).toMatchObject({ severity: "high" });
    expect(find(result.findings, "sitemap.noindex")!.message).toMatch(/2 of \d+ sampled URLs/);
    expect(find(result.findings, "sitemap.noindex")).toMatchObject({ severity: "high" });
    expect(find(result.findings, "sitemap.blocked_by_robots")!.message).toContain("/private");
    expect(find(result.findings, "sitemap.redirects")!.message).toContain("301 /ok");
    expect(find(result.findings, "sitemap.canonical_mismatch")!.message).toContain("/somewhere-else");

    // Only the clean URL is OK; problem URLs are listed with their reasons.
    expect(result.ok).toBe(1);
    const byUrl = Object.fromEntries(result.problems.map((p) => [new URL(p.url).pathname, p.problems]));
    expect(byUrl["/broken"]).toEqual(["broken"]);
    expect(byUrl["/private"]).toContain("blocked_by_robots");
    expect(byUrl["/notitle"]).toEqual(["no_title"]);

    // Third-party hosts are never contacted.
    expect(hosts.some((h) => h.includes("other.test"))).toBe(false);
  });

  it("reports a healthy site as healthy", async () => {
    let port = 0;
    server = await startServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      if (path === "/robots.txt") return void res.writeHead(200).end(`Sitemap: http://public.test:${port}/sitemap.xml\n`);
      if (path === "/sitemap.xml") return void res.writeHead(200).end(urlset(["a", "b", "c"].map((n) => `http://public.test:${port}/${n}`)));
      res.writeHead(200, { "content-type": "text/html" }).end(page(`Page ${path}`));
    });
    port = server.port;
    const { deps } = makeDeps();
    const result = await auditSitemap(deps, `http://public.test:${port}`);
    expect(ids(result.findings)).toEqual([]);
    expect(find(result.findings, "sitemap.healthy")).toBeDefined();
    expect(result).toMatchObject({ checked: 3, ok: 3 });
  });

  it("follows a sitemap index into its children", async () => {
    let port = 0;
    server = await startServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      const b = `http://public.test:${port}`;
      if (path === "/sitemap.xml") return void res.writeHead(200).end(`<sitemapindex><sitemap><loc>${b}/s1.xml</loc></sitemap><sitemap><loc>${b}/s2.xml</loc></sitemap></sitemapindex>`);
      if (path === "/s1.xml") return void res.writeHead(200).end(urlset([`${b}/a`, `${b}/b`]));
      if (path === "/s2.xml") return void res.writeHead(200).end(urlset([`${b}/c`]));
      if (path === "/robots.txt") return void res.writeHead(404).end();
      res.writeHead(200, { "content-type": "text/html" }).end(page("ok"));
    });
    port = server.port;
    const { deps } = makeDeps();
    const result = await auditSitemap(deps, `http://public.test:${port}/sitemap.xml`);
    expect(result.sitemaps).toHaveLength(3);
    expect(result.totalUrls).toBe(3);
    expect(ids(result.findings)).toEqual(["sitemap.not_in_robots"]);
  });

  it("reports a missing sitemap and an empty one", async () => {
    server = await startServer((_req, res) => void res.writeHead(404).end());
    const { deps } = makeDeps();
    const missing = await auditSitemap(deps, `http://public.test:${server.port}/`);
    expect(find(missing.findings, "sitemap.not_found")).toMatchObject({ severity: "high" });
    await server.close();

    server = await startServer((req, res) => void res.writeHead(req.url === "/sitemap.xml" ? 200 : 404).end(req.url === "/sitemap.xml" ? "<urlset></urlset>" : ""));
    const empty = await auditSitemap(deps, `http://public.test:${server.port}/`);
    expect(find(empty.findings, "sitemap.empty")).toMatchObject({ severity: "high" });
  });

  it("samples evenly, respects the cap and never exceeds the concurrency limit", async () => {
    let port = 0;
    let inFlight = 0;
    let peak = 0;
    const requested: string[] = [];
    server = await startServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      const b = `http://public.test:${port}`;
      if (path === "/sitemap.xml") return void res.writeHead(200).end(urlset(Array.from({ length: 200 }, (_, i) => `${b}/p${i}`)));
      if (path === "/robots.txt") return void res.writeHead(404).end();
      requested.push(path);
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      setTimeout(() => {
        inFlight -= 1;
        res.writeHead(200, { "content-type": "text/html" }).end(page("t"));
      }, 30);
    });
    port = server.port;

    const { deps } = makeDeps({ maxSitemapChecks: 20 });
    const result = await auditSitemap(deps, `http://public.test:${port}/sitemap.xml`, { sample: 500 });
    expect(result.checked).toBe(20); // the server-wide cap beats the request
    expect(result.uniqueUrls).toBe(200);
    expect(peak).toBeLessThanOrEqual(4);
    expect(requested).toHaveLength(20);
    expect(requested[0]).toBe("/p0");
    expect(requested).toContain("/p100"); // spread across the whole list, not just the first 20
    expect(requested).not.toContain("/p19");

    const small = await auditSitemap(makeDeps({ maxSitemapChecks: 20 }).deps, `http://public.test:${port}/sitemap.xml`, { sample: 5 });
    expect(small.checked).toBe(5);
  });
});

describe("analyzeRedirects", () => {
  it("detects an HTTP site that never upgrades and variants that diverge", async () => {
    server = await startServer((req, res) => {
      const host = String(req.headers.host).split(":")[0];
      if (host === "www.public.test") return void res.writeHead(301, { location: `http://public.test:${req.socket.localPort}/` }).end();
      res.writeHead(200, { "content-type": "text/html" }).end("ok");
    });
    const { deps } = makeDeps({}, { "public.test": ["93.184.216.34"], "www.public.test": ["93.184.216.35"] });
    const result = await analyzeRedirects(deps, `http://www.public.test:${server.port}/`);

    expect(result.primary.chain.map((h) => h.status)).toEqual([301, 200]);
    expect(result.variants).toHaveLength(4);
    const issues = ids(result.findings);
    expect(issues).toContain("redirect.http_not_upgraded"); // the https variants can't connect on the plain test server, the http ones stay http
    expect(find(result.findings, "redirect.http_not_upgraded")).toMatchObject({ severity: "high" });
    expect(issues).toContain("redirect.variant_unreachable"); // https variants against a plain-HTTP server
  });

  it("reports a loop in the primary URL", async () => {
    server = await startServer((req, res) => void res.writeHead(302, { location: req.url === "/a" ? "/b" : "/a" }).end());
    const { deps } = makeDeps();
    const result = await analyzeRedirects(deps, `http://public.test:${server.port}/a`, false);
    expect(ids(result.findings)).toContain("redirect.loop");
    expect(result.primary.loop).toBe(true);
    expect(result.variants).toEqual([]);
  });

  it("does not check variants for IP literals", async () => {
    server = await startServer((_req, res) => void res.writeHead(200).end("ok"));
    const { deps } = makeDeps({ allowPrivateTargets: true });
    const result = await analyzeRedirects(deps, `http://127.0.0.1:${server.port}/`);
    expect(result.variants).toEqual([]);
    expect(find(result.findings, "redirect.none")).toBeDefined();
  });

  it("refuses a private first hop", async () => {
    const { deps } = makeDeps();
    await expect(analyzeRedirects(deps, "http://internal.test/")).rejects.toMatchObject({ code: "blocked_address" });
  });
});
