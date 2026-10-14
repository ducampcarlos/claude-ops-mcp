import * as tls from "node:tls";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { describeCertificate, evaluateTls, inspectTls } from "../src/net/tls-inspect.js";
import { TargetPolicy } from "../src/security/policy.js";
import { makeIdentity, startTlsServer, trustRoots, type Identity } from "./certs.js";
import { fakeLookup, testConfig } from "./helpers.js";

const deps = (overrides = {}) => {
  const config = testConfig(overrides);
  return {
    config,
    policy: new TargetPolicy(config, fakeLookup().lookup),
    connectAddress: () => "127.0.0.1",
  };
};

const ids = (findings: { id: string; ok?: boolean }[], onlyIssues = false) =>
  findings.filter((f) => !onlyIssues || !f.ok).map((f) => f.id);

let root: Identity;
let restoreTrust: () => void;
const closers: Array<() => Promise<void>> = [];

beforeAll(() => {
  root = makeIdentity({ cn: "Test Root CA", isCA: true, expiresInDays: 3650 });
  restoreTrust = trustRoots(root);
});
afterAll(() => restoreTrust());
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()));
});

async function serve(options: Parameters<typeof startTlsServer>[0]) {
  const server = await startTlsServer(options);
  closers.push(server.close);
  return server;
}

describe("inspectTls: healthy certificate", () => {
  it("reports a trusted, matching, TLS 1.3 certificate with no issues", async () => {
    const leaf = makeIdentity({ cn: "public.test", issuer: root, expiresInDays: 80 });
    const server = await serve({ leaf });
    const result = await inspectTls(deps(), "public.test", server.port);

    expect(result).toMatchObject({
      host: "public.test",
      port: server.port,
      address: "93.184.216.34",
      protocol: "TLSv1.3",
      authorized: true,
      authorizationError: null,
      hostnameMatches: true,
      alpn: "h2",
    });
    expect(result.chain[0]).toMatchObject({ subject: "CN=public.test", issuer: "CN=Test Root CA", selfSigned: false, keyType: "rsa", keyBits: 2048 });
    expect(result.chain[0]!.daysRemaining).toBeGreaterThanOrEqual(79);
    expect(result.chain[0]!.subjectAltNames).toEqual(["DNS:public.test"]);
    expect(ids(result.findings, true)).toEqual([]);
    expect(ids(result.findings)).toEqual(expect.arrayContaining(["tls.validity", "tls.trusted", "tls.protocol"]));
    expect(result.handshakeMs).toBeGreaterThanOrEqual(0);
  });

  it("sends the host name as SNI", async () => {
    let sni: string | undefined;
    const leaf = makeIdentity({ cn: "public.test", issuer: root });
    const server = await serve({ leaf, onServername: (name) => (sni = name) });
    await inspectTls(deps(), "Public.TEST.", server.port);
    expect(sni).toBe("public.test");
  });

  it("matches wildcard certificates", async () => {
    const leaf = makeIdentity({ cn: "*.public.test", sans: ["*.public.test"], issuer: root });
    const server = await serve({ leaf });
    const table = { "app.public.test": ["93.184.216.34"] };
    const config = testConfig();
    const result = await inspectTls(
      { config, policy: new TargetPolicy(config, fakeLookup(table).lookup), connectAddress: () => "127.0.0.1" },
      "app.public.test",
      server.port,
    );
    expect(result.hostnameMatches).toBe(true);
  });
});

describe("inspectTls: problems", () => {
  it("flags an expired certificate once (not also as untrusted)", async () => {
    const leaf = makeIdentity({ cn: "public.test", issuer: root, startsInDays: -100, expiresInDays: -3 });
    const server = await serve({ leaf });
    const result = await inspectTls(deps(), "public.test", server.port);
    expect(result.authorized).toBe(false);
    expect(result.authorizationError).toBe("CERT_HAS_EXPIRED");
    expect(result.chain[0]!.daysRemaining).toBeLessThan(0);
    const issues = ids(result.findings, true);
    expect(issues).toContain("tls.expired");
    expect(issues).not.toContain("tls.untrusted");
    expect(result.findings.find((f) => f.id === "tls.expired")).toMatchObject({ severity: "high" });
    expect(result.findings.find((f) => f.id === "tls.expired")!.message).toMatch(/expired \d+ day\(s\) ago/);
  });

  it.each([
    [3, "tls.expiring_critical", "high"],
    [7, "tls.expiring_critical", "high"],
    [10, "tls.expiring_soon", "medium"],
    [14, "tls.expiring_soon", "medium"],
    [25, "tls.expiring", "low"],
    [31, "tls.validity", undefined],
  ])("expiry in %i days is %s", async (days, expectedId, severity) => {
    const leaf = makeIdentity({ cn: "public.test", issuer: root, expiresInDays: days + 0.5 });
    const server = await serve({ leaf });
    const result = await inspectTls(deps(), "public.test", server.port);
    const finding = result.findings.find((f) => f.id === expectedId);
    expect(finding, JSON.stringify(result.findings)).toBeDefined();
    if (severity) expect(finding!.severity).toBe(severity);
  });

  it("flags a host name mismatch and lists what the certificate covers", async () => {
    const leaf = makeIdentity({ cn: "other.test", issuer: root });
    const server = await serve({ leaf });
    const result = await inspectTls(deps(), "public.test", server.port);
    expect(result.hostnameMatches).toBe(false);
    const finding = result.findings.find((f) => f.id === "tls.hostname_mismatch")!;
    expect(finding.severity).toBe("high");
    expect(finding.message).toContain("DNS:other.test");
    expect(ids(result.findings, true)).not.toContain("tls.untrusted");
  });

  it("flags a self-signed certificate", async () => {
    const leaf = makeIdentity({ cn: "public.test" });
    const server = await serve({ leaf });
    const result = await inspectTls(deps(), "public.test", server.port);
    expect(result.chain[0]!.selfSigned).toBe(true);
    expect(ids(result.findings, true)).toContain("tls.self_signed");
  });

  it("flags an incomplete chain (intermediate not sent)", async () => {
    const intermediate = makeIdentity({ cn: "Test Intermediate", isCA: true, issuer: root, expiresInDays: 1000 });
    const leaf = makeIdentity({ cn: "public.test", issuer: intermediate });

    const incomplete = await serve({ leaf });
    const bad = await inspectTls(deps(), "public.test", incomplete.port);
    expect(bad.authorizationError).toBe("UNABLE_TO_VERIFY_LEAF_SIGNATURE");
    expect(ids(bad.findings, true)).toContain("tls.incomplete_chain");

    const complete = await serve({ leaf, chain: [intermediate] });
    const good = await inspectTls(deps(), "public.test", complete.port);
    expect(good.authorized).toBe(true);
    expect(good.chain.map((c) => c.subject)).toEqual(["CN=public.test", "CN=Test Intermediate", "CN=Test Root CA"]);
    expect(ids(good.findings, true)).toEqual([]);
  });

  it("flags a weak RSA key", async () => {
    const leaf = makeIdentity({ cn: "public.test", issuer: root, keyBits: 1024 });
    // Newer OpenSSL (Node 24+) will not even load a 1024-bit key into a server at its default level.
    const server = await serve({ leaf, ciphers: "DEFAULT:@SECLEVEL=0" });
    const result = await inspectTls(deps(), "public.test", server.port);
    expect(result.chain[0]!.keyBits).toBe(1024);
    expect(ids(result.findings, true)).toContain("tls.weak_key");
  });

  it("reports several problems together, worst first", async () => {
    const leaf = makeIdentity({ cn: "other.test", startsInDays: -100, expiresInDays: -1, keyBits: 1024 });
    const server = await serve({ leaf, ciphers: "DEFAULT:@SECLEVEL=0" });
    const result = await inspectTls(deps(), "public.test", server.port);
    expect(ids(result.findings, true)).toEqual(expect.arrayContaining(["tls.expired", "tls.hostname_mismatch", "tls.weak_key"]));
  });
});

describe("inspectTls: protocol support", () => {
  it("detects TLS 1.2 + 1.3 and no legacy protocols on a modern server", async () => {
    const leaf = makeIdentity({ cn: "public.test", issuer: root });
    const server = await serve({ leaf });
    const result = await inspectTls(deps(), "public.test", server.port, { checkProtocols: true });
    expect(result.supportedProtocols).toEqual({ TLSv1: false, "TLSv1.1": false, "TLSv1.2": true, "TLSv1.3": true });
    expect(ids(result.findings, true)).toEqual([]);
  });

  it("notes a TLS 1.2-only server", async () => {
    const leaf = makeIdentity({ cn: "public.test", issuer: root });
    const server = await serve({ leaf, maxVersion: "TLSv1.2" });
    const result = await inspectTls(deps(), "public.test", server.port, { checkProtocols: true });
    expect(result.protocol).toBe("TLSv1.2");
    expect(result.supportedProtocols?.["TLSv1.3"]).toBe(false);
    expect(result.findings.find((f) => f.id === "tls.no_tls13")).toMatchObject({ severity: "low" });
  });

  it("detects a server that still accepts TLS 1.0/1.1", async () => {
    const leaf = makeIdentity({ cn: "public.test", issuer: root });
    const server = await serve({ leaf, minVersion: "TLSv1", ciphers: "ALL:@SECLEVEL=0" });
    const result = await inspectTls(deps(), "public.test", server.port, { checkProtocols: true });
    const supported = result.supportedProtocols!;
    expect(supported.TLSv1 || supported["TLSv1.1"]).toBe(true);
    expect(result.findings.find((f) => f.id === "tls.legacy_protocols")).toMatchObject({ severity: "medium" });
  });
});

describe("inspectTls: safety and errors", () => {
  it("never connects to private targets by default", async () => {
    const config = testConfig();
    const d = { config, policy: new TargetPolicy(config, fakeLookup().lookup) };
    await expect(inspectTls(d, "127.0.0.1", 443)).rejects.toMatchObject({ code: "blocked_address" });
    await expect(inspectTls(d, "internal.test", 443)).rejects.toMatchObject({ code: "blocked_address" });
    await expect(inspectTls(d, "169.254.169.254", 443)).rejects.toMatchObject({ code: "blocked_address" });
  });

  it("honours the port allow-list", async () => {
    const config = testConfig({ allowedPorts: [443] });
    const d = { config, policy: new TargetPolicy(config, fakeLookup().lookup) };
    await expect(inspectTls(d, "public.test", 22)).rejects.toMatchObject({ code: "port_not_allowed" });
  });

  it("rejects malformed hosts", async () => {
    await expect(inspectTls(deps(), "public.test/path", 443)).rejects.toMatchObject({ code: "invalid_target" });
    await expect(inspectTls(deps(), "a@b", 443)).rejects.toMatchObject({ code: "invalid_target" });
  });

  it("matches IP-literal hosts against IP SANs when private targets are allowed", async () => {
    const leaf = makeIdentity({ cn: "ip.test", sans: ["127.0.0.1"], issuer: root });
    const server = await serve({ leaf });
    const config = testConfig({ allowPrivateTargets: true });
    const d = { config, policy: new TargetPolicy(config, fakeLookup().lookup) };
    const result = await inspectTls(d, "127.0.0.1", server.port);
    expect(result.hostnameMatches).toBe(true);
    expect(result.address).toBe("127.0.0.1");
  });

  it("fails fast when the port is not TLS", async () => {
    const { startServer } = await import("./helpers.js");
    const plain = await startServer((_req, res) => res.end("hi"));
    try {
      await expect(inspectTls(deps({ timeoutMs: 2000 }), "public.test", plain.port)).rejects.toBeTruthy();
    } finally {
      await plain.close();
    }
  });

  it("times out on a silent server", async () => {
    const net = await import("node:net");
    const silent = net.createServer(() => undefined);
    await new Promise<void>((resolve) => silent.listen(0, "127.0.0.1", resolve));
    const port = (silent.address() as import("node:net").AddressInfo).port;
    try {
      const started = Date.now();
      await expect(inspectTls(deps({ timeoutMs: 300 }), "public.test", port)).rejects.toThrow(/timed out/);
      expect(Date.now() - started).toBeLessThan(2000);
    } finally {
      silent.close();
    }
  });
});

describe("pure helpers", () => {
  it("describeCertificate computes days remaining from the supplied clock", () => {
    const identity = makeIdentity({ cn: "x.test", expiresInDays: 10 });
    const raw = Buffer.from(identity.certPem.replace(/-----[A-Z ]+-----|\s/g, ""), "base64");
    const info = describeCertificate(raw, Date.now());
    expect(info.daysRemaining).toBeGreaterThanOrEqual(9);
    expect(info.daysRemaining).toBeLessThanOrEqual(10);
    const later = describeCertificate(raw, Date.now() + 20 * 86_400_000);
    expect(later.daysRemaining).toBeLessThan(0);
  });

  it("evaluateTls flags old negotiated protocols", () => {
    const findings = evaluateTls({ host: "x", protocol: "TLSv1.1", authorized: true, authorizationError: null, hostnameMatches: true, chain: [] });
    expect(findings.find((f) => f.id === "tls.old_protocol")).toMatchObject({ severity: "high" });
  });

  it("test environment can set default CAs (Node >= 22.19)", () => {
    expect(typeof tls.setDefaultCACertificates).toBe("function");
  });
});
