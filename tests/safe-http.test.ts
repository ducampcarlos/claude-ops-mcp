import { afterEach, describe, expect, it } from "vitest";

import { header, fetchSafe } from "../src/net/safe-http.js";
import { extractCanonical, extractMetaRobots, extractTitle, hasNoindex } from "../src/net/html.js";
import { makeDeps, startServer, url, type TestServer } from "./helpers.js";

let server: TestServer | undefined;
afterEach(async () => {
  await server?.close();
  server = undefined;
});

describe("fetchSafe", () => {
  it("fetches a page through the pinned address and reports timings", async () => {
    server = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html", "x-test": "yes" });
      res.end("<title>Hello</title>");
    });
    const { deps, dns, dialled } = makeDeps();
    const result = await fetchSafe(deps, url("public.test", server.port));
    expect(result.status).toBe(200);
    expect(result.body).toBe("<title>Hello</title>");
    expect(header(result.headers, "X-Test")).toBe("yes");
    expect(result.chain).toHaveLength(1);
    expect(result.address).toBe("93.184.216.34"); // the validated address, not 127.0.0.1
    expect(dialled).toEqual(["93.184.216.34"]);
    expect(dns.calls).toEqual(["public.test"]); // resolved once, then pinned
    expect(result.ttfbMs).toBeGreaterThanOrEqual(0);
    expect(result.totalMs).toBeGreaterThanOrEqual(result.ttfbMs);
  });

  it("sends an identifiable user agent and refuses compression", async () => {
    let seen: Record<string, string | string[] | undefined> = {};
    server = await startServer((req, res) => {
      seen = req.headers;
      res.end("ok");
    });
    const { deps } = makeDeps();
    await fetchSafe(deps, url("public.test", server.port));
    expect(seen["user-agent"]).toMatch(/claude-ops-mcp/);
    expect(seen["accept-encoding"]).toBe("identity");
    expect(seen.cookie).toBeUndefined();
    expect(seen.authorization).toBeUndefined();
  });

  it("HEAD requests return no body", async () => {
    let method = "";
    server = await startServer((req, res) => {
      method = req.method ?? "";
      res.writeHead(200, { "content-length": "5" });
      res.end(req.method === "HEAD" ? undefined : "hello");
    });
    const { deps } = makeDeps();
    const result = await fetchSafe(deps, url("public.test", server.port), { method: "HEAD" });
    expect(method).toBe("HEAD");
    expect(result.body).toBe("");
    expect(result.status).toBe(200);
  });

  it("follows a redirect chain and records every hop", async () => {
    server = await startServer((req, res) => {
      if (req.url === "/a") return void res.writeHead(301, { location: "/b" }).end();
      if (req.url === "/b") return void res.writeHead(302, { location: "/c" }).end();
      res.writeHead(200).end("done");
    });
    const { deps } = makeDeps();
    const result = await fetchSafe(deps, url("public.test", server.port, "/a"));
    expect(result.chain.map((hop) => hop.status)).toEqual([301, 302, 200]);
    expect(result.chain.map((hop) => new URL(hop.url).pathname)).toEqual(["/a", "/b", "/c"]);
    expect(result.redirects).toBe(2);
    expect(result.finalUrl).toBe(url("public.test", server.port, "/c"));
    expect(result.body).toBe("done");
  });

  it("can be told not to follow redirects", async () => {
    server = await startServer((_req, res) => void res.writeHead(301, { location: "/b" }).end());
    const { deps } = makeDeps();
    const result = await fetchSafe(deps, url("public.test", server.port, "/a"), { followRedirects: false });
    expect(result.status).toBe(301);
    expect(result.chain[0]?.location).toBe("/b");
    expect(result.redirects).toBe(0);
  });

  it("detects redirect loops", async () => {
    server = await startServer((req, res) => {
      res.writeHead(302, { location: req.url === "/a" ? "/b" : "/a" }).end();
    });
    const { deps } = makeDeps();
    const result = await fetchSafe(deps, url("public.test", server.port, "/a"));
    expect(result.loop).toBe(true);
    expect(result.stoppedAt?.reason).toMatch(/loop/);
    expect(result.chain).toHaveLength(2);
  });

  it("stops at maxRedirects", async () => {
    server = await startServer((req, res) => {
      const next = Number(req.url?.slice(1) ?? "0") + 1;
      res.writeHead(302, { location: `/${next}` }).end();
    });
    const { deps } = makeDeps({ maxRedirects: 3 });
    const result = await fetchSafe(deps, url("public.test", server.port, "/0"));
    expect(result.tooManyRedirects).toBe(true);
    expect(result.chain.length).toBe(4);
  });

  it("re-validates EVERY redirect: a public site cannot bounce us to cloud metadata", async () => {
    server = await startServer((_req, res) => {
      res.writeHead(302, { location: "http://meta.test/latest/meta-data/" }).end();
    });
    const { deps, dialled } = makeDeps();
    const result = await fetchSafe(deps, url("public.test", server.port));
    expect(result.status).toBe(302);
    expect(result.stoppedAt?.reason).toMatch(/169\.254\.169\.254/);
    expect(dialled).toEqual(["93.184.216.34"]); // never connected to the metadata address
  });

  it("blocks redirects to IP literals and internal names", async () => {
    for (const location of ["http://127.0.0.1:1/", "http://[::1]/", "http://2130706433/", "http://internal.test/", "http://localhost/"]) {
      server = await startServer((_req, res) => void res.writeHead(302, { location }).end());
      const { deps, dialled } = makeDeps();
      const result = await fetchSafe(deps, url("public.test", server.port));
      expect(result.stoppedAt, location).toBeDefined();
      expect(dialled, location).toHaveLength(1);
      await server.close();
      server = undefined;
    }
  });

  it("blocks redirects to non-http schemes and malformed locations", async () => {
    for (const location of ["file:///etc/passwd", "gopher://x/", "ftp://x/"]) {
      server = await startServer((_req, res) => void res.writeHead(302, { location }).end());
      const { deps } = makeDeps();
      const result = await fetchSafe(deps, url("public.test", server.port));
      expect(result.stoppedAt?.reason, location).toMatch(/http and https/);
      await server.close();
      server = undefined;
    }
  });

  it("refuses a first hop to a private target", async () => {
    const { deps } = makeDeps();
    await expect(fetchSafe(deps, "http://internal.test/")).rejects.toMatchObject({ code: "blocked_address" });
    await expect(fetchSafe(deps, "http://127.0.0.1:9/")).rejects.toMatchObject({ code: "blocked_address" });
    await expect(fetchSafe(deps, "http://rebind.test/")).rejects.toMatchObject({ code: "blocked_address" }); // one bad record is enough
  });

  it("caps the body and tears the connection down", async () => {
    let closedEarly = false;
    server = await startServer((req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      req.socket.on("close", () => (closedEarly = true));
      const chunk = Buffer.alloc(64 * 1024, "a");
      const timer = setInterval(() => {
        if (!res.write(chunk)) return;
      }, 1);
      res.on("close", () => clearInterval(timer));
    });
    const { deps } = makeDeps();
    const result = await fetchSafe(deps, url("public.test", server.port), { maxBodyBytes: 1000 });
    expect(result.truncated).toBe(true);
    expect(result.bodyBytes).toBe(1000);
    expect(result.body).toHaveLength(1000);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(closedEarly).toBe(true);
  });

  it("the server-wide cap wins over a larger per-call request", async () => {
    server = await startServer((_req, res) => void res.end("x".repeat(5000)));
    const { deps } = makeDeps({ maxBodyBytes: 100 });
    const result = await fetchSafe(deps, url("public.test", server.port), { maxBodyBytes: 1_000_000 });
    expect(result.bodyBytes).toBe(100);
    expect(result.truncated).toBe(true);
  });

  it("reports connection refused clearly", async () => {
    const closed = await startServer(() => undefined);
    const port = closed.port;
    await closed.close();
    const { deps } = makeDeps();
    await expect(fetchSafe(deps, url("public.test", port))).rejects.toThrow(/connection refused/);
  });

  it("times out on a server that never answers", async () => {
    server = await startServer(() => undefined); // accepts, never responds
    const { deps } = makeDeps({ timeoutMs: 300 });
    const started = Date.now();
    await expect(fetchSafe(deps, url("public.test", server.port))).rejects.toThrow(/timed out|aborted/);
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it("reports DNS failures", async () => {
    const { deps } = makeDeps();
    await expect(fetchSafe(deps, "http://nope.test/")).rejects.toMatchObject({ code: "dns_failure" });
  });

  it("does not accept credentials in URLs or odd schemes", async () => {
    const { deps } = makeDeps();
    await expect(fetchSafe(deps, "http://user:pw@public.test/")).rejects.toMatchObject({ code: "invalid_target" });
    await expect(fetchSafe(deps, "file:///etc/passwd")).rejects.toMatchObject({ code: "invalid_target" });
  });
});

describe("html helpers", () => {
  it("extracts and decodes the title", () => {
    expect(extractTitle("<html><head><TITLE>  A &amp; B\n  &#169; </title>")).toBe("A & B ©");
    expect(extractTitle("<title></title>")).toBeUndefined();
    expect(extractTitle("<p>no title</p>")).toBeUndefined();
  });

  it("reads robots and canonical in any attribute order and quote style", () => {
    const html = `<meta content="noindex, follow" name="robots"><link href='/x' rel="canonical">`;
    expect(extractMetaRobots(html)).toBe("noindex, follow");
    expect(extractCanonical(html)).toBe("/x");
    expect(extractMetaRobots(`<meta name=robots content=index>`)).toBe("index");
    expect(extractMetaRobots("<meta name='description' content='x'>")).toBeUndefined();
  });

  it("recognises noindex directives without matching look-alikes", () => {
    expect(hasNoindex("noindex")).toBe(true);
    expect(hasNoindex("index, NOFOLLOW, noindex")).toBe(true);
    expect(hasNoindex("none")).toBe(true);
    expect(hasNoindex("index, follow")).toBe(false);
    expect(hasNoindex("noindexed")).toBe(false);
    expect(hasNoindex(undefined)).toBe(false);
  });

  it("stays fast on hostile input", () => {
    const started = Date.now();
    extractTitle("<title>" + "a".repeat(2_000_000));
    extractMetaRobots("<meta " + "x ".repeat(200_000));
    extractCanonical("<link " + "rel=".repeat(100_000));
    expect(Date.now() - started).toBeLessThan(1_500);
  });
});
