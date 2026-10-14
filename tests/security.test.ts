import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { DEFAULTS, loadConfig, type Config } from "../src/config.js";
import { AuditLog } from "../src/security/audit.js";
import { classifyAddress, isPublicAddress, parseIPv4, parseIPv6 } from "../src/security/ip.js";
import { ConcurrencyGate, RateLimiter } from "../src/security/limits.js";
import {
  PolicyError,
  TargetPolicy,
  matchesPattern,
  normalizeHostname,
  parseHttpUrl,
} from "../src/security/policy.js";

const config = (overrides: Partial<Config> = {}): Config => ({ ...DEFAULTS, ...overrides });

describe("IP parsing", () => {
  it("parses strict IPv4 and rejects ambiguous forms", () => {
    expect(parseIPv4("1.2.3.4")).toBe(16909060);
    for (const bad of ["1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.04", "a.b.c.d", ""]) {
      expect(parseIPv4(bad), bad).toBeNull();
    }
  });

  it("parses IPv6 in all its notations", () => {
    expect(parseIPv6("::")).toBe(0n);
    expect(parseIPv6("::1")).toBe(1n);
    expect(parseIPv6("2001:db8::1")).toBe(0x20010db8000000000000000000000001n);
    expect(parseIPv6("0:0:0:0:0:0:0:1")).toBe(1n);
    expect(parseIPv6("::ffff:127.0.0.1")).toBe(0xffff7f000001n);
    expect(parseIPv6("fe80::1%eth0")).toBe(0xfe800000000000000000000000000001n);
    for (const bad of ["1:2:3", "::1::2", "12345::", "g::1", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8:9"]) {
      expect(parseIPv6(bad), bad).toBeNull();
    }
  });
});

describe("address classification (SSRF)", () => {
  const blocked = [
    "127.0.0.1", "127.255.255.254", "0.0.0.0", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
    "192.168.1.1", "169.254.169.254", "169.254.0.1", "100.64.0.1", "100.127.255.255", "224.0.0.1",
    "255.255.255.255", "240.0.0.1", "198.18.0.1", "192.0.2.10", "198.51.100.7", "203.0.113.9",
    "::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1", "2001::1", "100::1",
    // IPv6 forms that embed an IPv4 address
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.1.2.3", "::ffff:169.254.169.254",
    "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "2002:a9fe:a9fe::1", "::127.0.0.1",
  ];
  const allowed = [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "172.15.255.255", "172.32.0.1", "100.63.255.255",
    "100.128.0.1", "169.253.1.1", "198.17.255.255", "198.20.0.1", "223.255.255.255",
    "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1",
  ];

  it.each(blocked)("blocks %s", (address) => {
    const verdict = classifyAddress(address);
    expect(verdict.public, address).toBe(false);
    expect(verdict.reason).toBeTruthy();
  });

  it.each(allowed)("allows %s", (address) => {
    expect(isPublicAddress(address), address).toBe(true);
  });

  it("never treats garbage as public", () => {
    for (const bad of ["", "localhost", "example.com", "1.2.3", "999.1.1.1", "::g"]) {
      expect(isPublicAddress(bad), bad).toBe(false);
    }
  });

  it("names the embedded address in the reason", () => {
    expect(classifyAddress("::ffff:169.254.169.254").reason).toMatch(/IPv4-mapped.*link-local/);
  });
});

describe("hostname and URL normalisation", () => {
  it("normalises case, trailing dot and numeric IPv4 shorthand", () => {
    expect(normalizeHostname("Example.COM.")).toBe("example.com");
    expect(normalizeHostname("2130706433")).toBe("127.0.0.1"); // decimal form of 127.0.0.1
    expect(normalizeHostname("0x7f.1")).toBe("127.0.0.1");
    expect(normalizeHostname("[::1]")).toBe("::1");
  });

  it.each(["", "  ", "a b.com", "evil.com/path", "user@evil.com", "evil.com?x=1", "evil.com#x", "host:8080", "a\\b.com"])(
    "rejects %j",
    (input) => {
      expect(() => normalizeHostname(input)).toThrowError(PolicyError);
    },
  );

  it("parses http(s) URLs and rejects the rest", () => {
    const parsed = parseHttpUrl("https://Example.com:8443/a?b=1");
    expect(parsed).toMatchObject({ hostname: "example.com", port: 8443 });
    expect(parseHttpUrl("http://example.com").port).toBe(80);
    expect(parseHttpUrl("https://example.com").port).toBe(443);
    for (const bad of ["ftp://example.com", "file:///etc/passwd", "gopher://x", "javascript:alert(1)", "not a url", "https://u:p@example.com/"]) {
      expect(() => parseHttpUrl(bad), bad).toThrowError(PolicyError);
    }
  });

  it("matches exact and wildcard patterns", () => {
    expect(matchesPattern("example.com", "example.com")).toBe(true);
    expect(matchesPattern("a.example.com", "*.example.com")).toBe(true);
    expect(matchesPattern("example.com", "*.example.com")).toBe(false);
    expect(matchesPattern("evilexample.com", "*.example.com")).toBe(false);
    expect(matchesPattern("a.example.com", "example.com")).toBe(false);
  });
});

describe("TargetPolicy", () => {
  const dns = (table: Record<string, string[]>) => async (host: string) => {
    const result = table[host];
    if (!result) throw Object.assign(new Error("nope"), { code: "ENOTFOUND" });
    return result;
  };

  const expectCode = async (promise: Promise<unknown>, code: string) => {
    await expect(promise).rejects.toMatchObject({ name: "PolicyError", code });
  };

  it("resolves a public host and returns the validated addresses", async () => {
    const policy = new TargetPolicy(config(), dns({ "example.com": ["93.184.216.34"] }));
    await expect(policy.resolve("example.com", 443)).resolves.toEqual({
      hostname: "example.com",
      port: 443,
      addresses: ["93.184.216.34"],
    });
  });

  it("blocks a name that resolves to a private address, even if only ONE record is private", async () => {
    const policy = new TargetPolicy(config(), dns({ "mixed.example": ["93.184.216.34", "10.0.0.5"] }));
    await expectCode(policy.resolve("mixed.example", 443), "blocked_address");
  });

  it("blocks the cloud metadata address and IP literals", async () => {
    const policy = new TargetPolicy(config(), dns({}));
    await expectCode(policy.resolve("169.254.169.254", 80), "blocked_address");
    await expectCode(policy.resolve("127.0.0.1", 80), "blocked_address");
    await expectCode(policy.resolve("::1", 443), "blocked_address");
    await expectCode(policy.resolve("::ffff:10.0.0.1", 443), "blocked_address");
  });

  it("blocks internal-looking names without a DNS lookup", async () => {
    const lookup = async () => {
      throw new Error("lookup must not run");
    };
    const policy = new TargetPolicy(config(), lookup);
    for (const host of ["localhost", "printer.local", "db.internal", "nas.lan", "x.corp"]) {
      await expectCode(policy.resolve(host, 443), "internal_name");
    }
  });

  it("enforces the port list", async () => {
    const policy = new TargetPolicy(config(), dns({ "example.com": ["93.184.216.34"] }));
    await expectCode(policy.resolve("example.com", 22), "port_not_allowed");
    await expectCode(policy.resolve("example.com", 6379), "port_not_allowed");
    await expect(policy.resolve("example.com", 8443)).resolves.toBeTruthy();
    const open = new TargetPolicy(config({ allowedPorts: "any" }), dns({ "example.com": ["93.184.216.34"] }));
    await expect(open.resolve("example.com", 22)).resolves.toBeTruthy();
  });

  it("applies deny before allow, and allow-list as an exclusive filter", async () => {
    const table = { "a.corp-site.com": ["93.184.216.34"], "b.other.com": ["93.184.216.35"], "bad.corp-site.com": ["93.184.216.36"] };
    const policy = new TargetPolicy(
      config({ allowHosts: ["*.corp-site.com"], denyHosts: ["bad.corp-site.com"] }),
      dns(table),
    );
    await expect(policy.resolve("a.corp-site.com", 443)).resolves.toBeTruthy();
    await expectCode(policy.resolve("bad.corp-site.com", 443), "denied_host");
    await expectCode(policy.resolve("b.other.com", 443), "not_allowed_host");
  });

  it("reports DNS failures clearly", async () => {
    const policy = new TargetPolicy(config(), dns({}));
    await expect(policy.resolve("nxdomain.example", 443)).rejects.toThrow(/Could not resolve nxdomain.example \(ENOTFOUND\)/);
    const empty = new TargetPolicy(config(), async () => []);
    await expectCode(empty.resolve("empty.example", 443), "dns_failure");
  });

  it("lets operators opt in to private targets", async () => {
    const policy = new TargetPolicy(config({ allowPrivateTargets: true, allowedPorts: "any" }), dns({}));
    await expect(policy.resolve("127.0.0.1", 3000)).resolves.toMatchObject({ addresses: ["127.0.0.1"] });
    await expect(policy.resolve("localhost", 3000)).rejects.toMatchObject({ code: "dns_failure" }); // allowed, just unresolvable here
  });
});

describe("config", () => {
  it("has safe defaults", () => {
    const c = loadConfig({});
    expect(c.allowPrivateTargets).toBe(false);
    expect(c.allowedPorts).toEqual([80, 443, 8080, 8443]);
    expect(c.requestsPerMinute).toBe(60);
  });

  it("parses overrides", () => {
    const c = loadConfig({
      OPS_MCP_ALLOW_PRIVATE: "true",
      OPS_MCP_ALLOW_HOSTS: "Example.com, *.Corp.io",
      OPS_MCP_DENY_HOSTS: "bad.example.com",
      OPS_MCP_ALLOWED_PORTS: "443, 9443",
      OPS_MCP_RATE_PER_MINUTE: "5",
      OPS_MCP_AUDIT_LOG: " /tmp/x.jsonl ",
    });
    expect(c).toMatchObject({
      allowPrivateTargets: true,
      allowHosts: ["example.com", "*.corp.io"],
      denyHosts: ["bad.example.com"],
      allowedPorts: [443, 9443],
      requestsPerMinute: 5,
      auditLogPath: "/tmp/x.jsonl",
    });
    expect(loadConfig({ OPS_MCP_ALLOWED_PORTS: "any" }).allowedPorts).toBe("any");
  });

  it("rejects nonsense instead of silently using a default", () => {
    expect(() => loadConfig({ OPS_MCP_RATE_PER_MINUTE: "0" })).toThrow(/OPS_MCP_RATE_PER_MINUTE/);
    expect(() => loadConfig({ OPS_MCP_TIMEOUT_MS: "abc" })).toThrow(/OPS_MCP_TIMEOUT_MS/);
    expect(() => loadConfig({ OPS_MCP_ALLOWED_PORTS: "443,99999" })).toThrow(/invalid port/);
  });
});

describe("limits", () => {
  it("token bucket allows a burst, then refills over time", () => {
    let now = 0;
    const limiter = new RateLimiter(6, () => now); // 6 per minute = 1 per 10s
    for (let i = 0; i < 6; i++) expect(limiter.tryConsume()).toEqual({ ok: true });
    expect(limiter.tryConsume()).toEqual({ ok: false, retryAfterMs: 10_000 });
    now += 5_000;
    expect(limiter.tryConsume()).toMatchObject({ ok: false, retryAfterMs: 5_000 });
    now += 5_000;
    expect(limiter.tryConsume()).toEqual({ ok: true });
    now += 10 * 60_000; // long idle never banks more than a full bucket
    for (let i = 0; i < 6; i++) expect(limiter.tryConsume()).toEqual({ ok: true });
    expect(limiter.tryConsume().ok).toBe(false);
  });

  it("concurrency gate refuses beyond the cap and release is idempotent", () => {
    const gate = new ConcurrencyGate(2);
    const a = gate.tryAcquire()!;
    const b = gate.tryAcquire()!;
    expect(gate.tryAcquire()).toBeNull();
    a();
    a(); // double release must not free a second slot
    expect(gate.inFlight).toBe(1);
    expect(gate.tryAcquire()).not.toBeNull();
    expect(gate.tryAcquire()).toBeNull();
    b();
  });
});

describe("audit log", () => {
  it("writes one JSON line per call and keeps order", async () => {
    const lines: string[] = [];
    const audit = new AuditLog((line) => void lines.push(line));
    audit.record({ tool: "tls_inspect", target: "example.com:443", ok: true, durationMs: 12.6 });
    audit.record({ tool: "http_probe", target: "https://x.test/", ok: false, durationMs: 3, error: "blocked" });
    await audit.flush();
    expect(lines).toHaveLength(2);
    const [first, second] = lines.map((line) => JSON.parse(line));
    expect(first).toMatchObject({ tool: "tls_inspect", target: "example.com:443", ok: true, durationMs: 13 });
    expect(second).toMatchObject({ tool: "http_probe", ok: false, error: "blocked" });
    expect(new Date(first.ts).toString()).not.toBe("Invalid Date");
  });

  it("truncates long values and survives a failing sink", async () => {
    const lines: string[] = [];
    let fail = true;
    const audit = new AuditLog((line) => {
      if (fail) throw new Error("disk full");
      lines.push(line);
    });
    audit.record({ tool: "t", ok: true, durationMs: 1 });
    await audit.flush();
    fail = false;
    audit.record({ tool: "t", target: "x".repeat(1000), ok: false, durationMs: 1, error: "e".repeat(1000) });
    await audit.flush();
    const entry = JSON.parse(lines[0]!);
    expect(entry.target).toHaveLength(300);
    expect(entry.error).toHaveLength(300);
  });

  it("appends to a file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ops-mcp-audit-"));
    const path = join(dir, "nested", "audit.jsonl");
    const audit = AuditLog.toFile(path);
    audit.record({ tool: "a", ok: true, durationMs: 1 });
    audit.record({ tool: "b", ok: true, durationMs: 1 });
    await audit.flush();
    const content = (await readFile(path, "utf8")).trim().split("\n");
    expect(content.map((line) => JSON.parse(line).tool)).toEqual(["a", "b"]);
  });

  it("is a no-op without a path", async () => {
    const audit = AuditLog.toFile(undefined);
    audit.record({ tool: "a", ok: true, durationMs: 1 });
    await expect(audit.flush()).resolves.toBeUndefined();
  });
});
