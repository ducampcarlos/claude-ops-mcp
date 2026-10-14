import { afterEach, describe, expect, it } from "vitest";

import { auditMailAuth, countSpfLookups, mxMatchesPattern, parseMtaStsPolicy, parseTags } from "../src/checks/mail-auth.js";
import { score } from "../src/findings.js";
import { FakeDns, goodMailTable, makeDeps, startServer, type DnsTable, type TestServer } from "./helpers.js";

const ids = (findings: { id: string; ok?: boolean }[], issuesOnly = true) =>
  findings.filter((f) => !issuesOnly || !f.ok).map((f) => f.id);

const merge = (base: DnsTable, extra: DnsTable): DnsTable => {
  const out: DnsTable = {};
  for (const table of [base, extra]) {
    for (const [type, byName] of Object.entries(table) as [keyof DnsTable, Record<string, never>][]) {
      out[type] = { ...(out[type] ?? {}), ...byName };
    }
  }
  return out;
};

const audit = (table: DnsTable, domain = "example.test", options = {}) =>
  auditMailAuth(new FakeDns(table), undefined, domain, { fetchMtaSts: false, ...options });

describe("auditMailAuth: a well configured domain", () => {
  it("has no issues and scores 100", async () => {
    const result = await audit(goodMailTable());
    expect(ids(result.findings)).toEqual([]);
    expect(score(result.findings)).toEqual({ score: 100, grade: "A" });
    expect(result.spf).toMatchObject({ lookups: 0 });
    expect(result.dmarc?.tags.p).toBe("reject");
    expect(result.dkim).toMatchObject({ found: ["google"], revoked: [] });
    expect(result.mx.map((m) => m.exchange)).toEqual(["mx1.example.test", "mx2.example.test"]);
  });
});

describe("SPF", () => {
  const withSpf = (...records: string[]) => merge(goodMailTable(), { TXT: { "example.test": records } });

  it("reports a missing record", async () => {
    const table = goodMailTable();
    delete table.TXT!["example.test"];
    expect(ids((await audit(table)).findings)).toContain("spf.missing");
  });

  it("reports multiple records", async () => {
    expect(ids((await audit(withSpf("v=spf1 -all", "v=spf1 ~all"))).findings)).toContain("spf.multiple");
  });

  it.each([
    ["v=spf1 +all", "spf.pass_all", "high"],
    ["v=spf1 all", "spf.pass_all", "high"],
    ["v=spf1 ?all", "spf.neutral_all", "medium"],
    ["v=spf1 ~all", "spf.softfail", "low"],
    ["v=spf1 mx", "spf.no_all", "medium"],
    ["v=spf1 ptr -all", "spf.ptr", "low"],
  ])("%s -> %s", async (record, id, severity) => {
    const result = await audit(withSpf(record));
    expect(result.findings.find((f) => f.id === id)).toMatchObject({ severity });
  });

  it("counts lookups through nested includes and redirects", async () => {
    const dns = new FakeDns({
      TXT: {
        "a.test": ["v=spf1 include:b.test mx -all"],
        "b.test": ["v=spf1 include:c.test a -all"],
        "c.test": ["v=spf1 ip4:192.0.2.0/24 -all"],
        "r.test": ["v=spf1 redirect=c.test"],
      },
    });
    expect(await countSpfLookups(dns, "v=spf1 include:b.test mx -all")).toBe(4);
    expect(await countSpfLookups(dns, "v=spf1 redirect=c.test")).toBe(1);
    expect(await countSpfLookups(dns, "v=spf1 a:host.test mx:host.test a/24 -all")).toBe(3);
  });

  it("survives include loops", async () => {
    const dns = new FakeDns({ TXT: { "a.test": ["v=spf1 include:b.test -all"], "b.test": ["v=spf1 include:a.test -all"] } });
    expect(await countSpfLookups(dns, "v=spf1 include:a.test -all")).toBe(3);
  });

  it("flags more than 10 lookups", async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:i${i}.test`).join(" ");
    const result = await audit(withSpf(`v=spf1 ${includes} -all`));
    expect(result.findings.find((f) => f.id === "spf.too_many_lookups")).toMatchObject({ severity: "high" });
    expect(result.spf?.lookups).toBe(11);
  });
});

describe("DMARC", () => {
  const withDmarc = (...records: string[]) => merge(goodMailTable(), { TXT: { "_dmarc.example.test": records } });

  it("reports missing and multiple records", async () => {
    const table = goodMailTable();
    delete table.TXT!["_dmarc.example.test"];
    expect(ids((await audit(table)).findings)).toContain("dmarc.missing");
    expect(ids((await audit(withDmarc("v=DMARC1; p=none", "v=DMARC1; p=reject"))).findings)).toContain("dmarc.multiple");
  });

  it.each([
    ["v=DMARC1; p=none; rua=mailto:a@b.c", "dmarc.monitor_only", "medium"],
    ["v=DMARC1; p=quarantine; rua=mailto:a@b.c", "dmarc.quarantine", "low"],
    ["v=DMARC1; p=bogus; rua=mailto:a@b.c", "dmarc.invalid_policy", "high"],
    ["v=DMARC1; p=reject", "dmarc.no_rua", "low"],
    ["v=DMARC1; p=reject; pct=50; rua=mailto:a@b.c", "dmarc.partial", "low"],
    ["v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c", "dmarc.weak_subdomain_policy", "medium"],
  ])("%s -> %s", async (record, id, severity) => {
    const result = await audit(withDmarc(record));
    expect(result.findings.find((f) => f.id === id)).toMatchObject({ severity });
  });

  it("inherits from the organisational domain for subdomains", async () => {
    const result = await audit(goodMailTable("example.test"), "news.example.test");
    expect(result.dmarc?.domain).toBe("example.test");
    expect(result.findings.find((f) => f.id === "dmarc.present")!.message).toMatch(/inherited from example.test/);
  });

  it("parses tags tolerantly", () => {
    expect(parseTags("v=DMARC1 ; p = reject;rua=mailto:a@b.c; ;bad")).toEqual({ v: "DMARC1", p: "reject", rua: "mailto:a@b.c" });
  });
});

describe("DKIM", () => {
  it("finds custom selectors and reports revoked ones", async () => {
    const table = merge(goodMailTable(), {
      TXT: {
        "custom._domainkey.example.test": ["v=DKIM1; p=ABC"],
        "old._domainkey.example.test": ["v=DKIM1; p="],
      },
    });
    const result = await audit(table, "example.test", { dkimSelectors: ["Custom", "old"] });
    expect(result.dkim.found).toEqual(["custom", "google"]);
    expect(result.dkim.revoked).toEqual(["old"]);
    expect(ids(result.findings)).toContain("dkim.revoked");
  });

  it("reports when nothing is found and says how many selectors were probed", async () => {
    const table = goodMailTable();
    delete table.TXT!["google._domainkey.example.test"];
    const result = await audit(table);
    const finding = result.findings.find((f) => f.id === "dkim.not_found")!;
    expect(finding.severity).toBe("medium");
    expect(finding.message).toMatch(/among \d+ common selectors/);
  });

  it("ignores TXT records that are not DKIM keys", async () => {
    const table = merge(goodMailTable(), { TXT: { "google._domainkey.example.test": ["not a dkim record"] } });
    expect((await audit(table)).dkim.found).toEqual([]);
  });
});

describe("MX", () => {
  it("reports missing MX", async () => {
    const table = goodMailTable();
    delete table.MX;
    expect(ids((await audit(table)).findings)).toContain("mx.missing");
  });

  it("recognises a null MX", async () => {
    const table = merge(goodMailTable(), { MX: { "example.test": [{ priority: 0, exchange: "" }] } });
    const result = await audit(table);
    expect(ids(result.findings, false)).toContain("mx.null");
    expect(ids(result.findings)).not.toContain("mx.missing");
  });

  it("flags unresolvable and single MX hosts", async () => {
    const table = merge(goodMailTable(), { MX: { "example.test": [{ priority: 10, exchange: "ghost.example.test" }] } });
    const result = await audit(table);
    expect(ids(result.findings)).toEqual(expect.arrayContaining(["mx.unresolvable", "mx.single"]));
  });

  it("accepts MX hosts that only have AAAA records", async () => {
    const table = merge(goodMailTable(), {
      MX: { "example.test": [{ priority: 10, exchange: "v6.example.test" }, { priority: 20, exchange: "mx2.example.test" }] },
      AAAA: { "v6.example.test": ["2606:4700:4700::1111"] },
    });
    expect(ids((await audit(table)).findings)).toEqual([]);
  });
});

describe("MTA-STS and TLS-RPT (DNS only)", () => {
  it("flags missing records", async () => {
    const table = goodMailTable();
    delete table.TXT!["_mta-sts.example.test"];
    delete table.TXT!["_smtp._tls.example.test"];
    const result = await audit(table);
    expect(result.findings.find((f) => f.id === "mta_sts.missing")).toMatchObject({ severity: "low" });
    expect(result.findings.find((f) => f.id === "tls_rpt.missing")).toMatchObject({ severity: "info" });
  });
});

describe("MTA-STS policy file", () => {
  let server: TestServer | undefined;
  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  /** HTTPS is required by the spec, but our fake host maps to a plain local server; use allowInvalid path via http. */
  it("parses policy files", () => {
    expect(parseMtaStsPolicy("version: STSv1\r\nmode: Enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n")).toEqual({
      version: "STSv1",
      mode: "enforce",
      maxAge: 604800,
      mx: ["mail.example.com", "*.example.net"],
    });
  });

  it("matches MX wildcard patterns one label deep only", () => {
    expect(mxMatchesPattern("mail.example.com", "*.example.com")).toBe(true);
    expect(mxMatchesPattern("a.b.example.com", "*.example.com")).toBe(false);
    expect(mxMatchesPattern("example.com", "*.example.com")).toBe(false);
    expect(mxMatchesPattern("mail.example.com", "mail.example.com")).toBe(true);
  });

  it("reports an unreachable policy as a finding instead of failing the audit", async () => {
    const { deps } = makeDeps({}, { "mta-sts.example.test": ["93.184.216.34"] });
    // Nothing listens on 443 of 127.0.0.1 in the test, so the fetch fails.
    const result = await auditMailAuth(new FakeDns(goodMailTable()), deps, "example.test", { fetchMtaSts: true });
    expect(result.findings.find((f) => f.id === "mta_sts.policy_unreachable")).toMatchObject({ severity: "high" });
    expect(ids(result.findings)).not.toContain("mx.missing");
  });
});
