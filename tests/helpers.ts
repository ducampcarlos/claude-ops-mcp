import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { DEFAULTS, type Config } from "../src/config.js";
import type { HttpDeps } from "../src/net/safe-http.js";
import { TargetPolicy } from "../src/security/policy.js";

export type Handler = (req: IncomingMessage, res: ServerResponse) => void;

export interface TestServer {
  port: number;
  server: Server;
  close(): Promise<void>;
}

export async function startServer(handler: Handler): Promise<TestServer> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    server,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** Fake DNS: names map to PUBLIC-looking addresses (so the policy passes) or to chosen ones. */
export const FAKE_DNS: Record<string, string[]> = {
  "public.test": ["93.184.216.34"],
  "other.test": ["93.184.216.35"],
  "meta.test": ["169.254.169.254"],
  "internal.test": ["10.0.0.5"],
  "rebind.test": ["93.184.216.36", "127.0.0.1"],
};

export const fakeLookup = (table: Record<string, string[]> = FAKE_DNS) => {
  const calls: string[] = [];
  const lookup = async (host: string) => {
    calls.push(host);
    const result = table[host];
    if (!result) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    return result;
  };
  return { lookup, calls };
};

export const testConfig = (overrides: Partial<Config> = {}): Config => ({
  ...DEFAULTS,
  allowedPorts: "any",
  timeoutMs: 5_000,
  ...overrides,
});

/**
 * HttpDeps whose fake public addresses are dialled on 127.0.0.1, so tests exercise the real
 * policy + pinning code against a real local server.
 */
export function makeDeps(overrides: Partial<Config> = {}, table?: Record<string, string[]>) {
  const config = testConfig(overrides);
  const dns = fakeLookup(table);
  const dialled: string[] = [];
  const deps: HttpDeps = {
    config,
    policy: new TargetPolicy(config, dns.lookup),
    connectAddress: (address) => {
      dialled.push(address);
      return "127.0.0.1";
    },
  };
  return { deps, config, dns, dialled };
}

export const url = (host: string, port: number, path = "/") => `http://${host}:${port}${path}`;

// ---------------------------------------------------------------------------------------------
// In-memory DNS
// ---------------------------------------------------------------------------------------------

import type { DnsClient, DnsResponse, DnsValue, RecordType } from "../src/net/dns.js";

export type DnsTable = Partial<Record<RecordType, Record<string, DnsValue[]>>>;

/** A DnsClient backed by a table: `{ TXT: { "example.com": ["v=spf1 -all"] }, MX: {...} }`. */
export class FakeDns implements DnsClient {
  readonly queries: string[] = [];

  constructor(
    private readonly table: DnsTable = {},
    private readonly failing: Set<string> = new Set(),
  ) {}

  async resolve(name: string, type: RecordType): Promise<DnsResponse> {
    this.queries.push(`${type} ${name}`);
    if (this.failing.has(`${type} ${name}`)) return { status: "error", records: [], error: "ETIMEOUT" };
    const records = this.table[type]?.[name];
    if (!records) {
      const exists = Object.values(this.table).some((byName) => byName && name in byName);
      return { status: exists ? "nodata" : "nxdomain", records: [] };
    }
    return { status: "ok", records };
  }
}

/** A domain with everything configured properly. */
export const goodMailTable = (domain = "example.test"): DnsTable => ({
  MX: { [domain]: [{ priority: 10, exchange: `mx1.${domain}` }, { priority: 20, exchange: `mx2.${domain}` }] },
  A: { [`mx1.${domain}`]: ["93.184.216.34"], [`mx2.${domain}`]: ["93.184.216.35"] },
  TXT: {
    [domain]: ["v=spf1 ip4:93.184.216.0/24 -all"],
    [`_dmarc.${domain}`]: [`v=DMARC1; p=reject; rua=mailto:dmarc@${domain}`],
    [`google._domainkey.${domain}`]: ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
    [`_mta-sts.${domain}`]: ["v=STSv1; id=20260101"],
    [`_smtp._tls.${domain}`]: [`v=TLSRPTv1; rua=mailto:tls@${domain}`],
  },
});
