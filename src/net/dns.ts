/** DNS access behind a small interface so tools can be tested without a network. */

import { Resolver } from "node:dns/promises";

export type RecordType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT" | "CAA" | "SOA" | "SRV" | "PTR";

export const RECORD_TYPES: readonly RecordType[] = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "SRV", "PTR"];

export interface MxRecord {
  priority: number;
  exchange: string;
}
export interface CaaRecord {
  critical: boolean;
  tag: string;
  value: string;
}
export interface SoaRecord {
  nsname: string;
  hostmaster: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minttl: number;
}
export interface SrvRecord {
  priority: number;
  weight: number;
  port: number;
  name: string;
}

export type DnsValue = string | MxRecord | CaaRecord | SoaRecord | SrvRecord;

export interface DnsResponse {
  /** `nodata`: the name exists but has no records of this type. `nxdomain`: the name does not exist. */
  status: "ok" | "nodata" | "nxdomain" | "error";
  records: DnsValue[];
  error?: string;
}

export interface DnsClient {
  resolve(name: string, type: RecordType): Promise<DnsResponse>;
}

export class SystemDnsClient implements DnsClient {
  private readonly resolver: Resolver;

  constructor(timeoutMs = 5_000) {
    this.resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
  }

  async resolve(name: string, type: RecordType): Promise<DnsResponse> {
    try {
      return { status: "ok", records: await this.query(name, type) };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? "UNKNOWN";
      if (code === "ENODATA") return { status: "nodata", records: [] };
      if (code === "ENOTFOUND") return { status: "nxdomain", records: [] };
      return { status: "error", records: [], error: code };
    }
  }

  private async query(name: string, type: RecordType): Promise<DnsValue[]> {
    switch (type) {
      case "A":
        return this.resolver.resolve4(name);
      case "AAAA":
        return this.resolver.resolve6(name);
      case "CNAME":
        return this.resolver.resolveCname(name);
      case "NS":
        return this.resolver.resolveNs(name);
      case "PTR":
        return this.resolver.resolvePtr(name);
      case "TXT":
        return (await this.resolver.resolveTxt(name)).map((chunks) => chunks.join(""));
      case "MX":
        return (await this.resolver.resolveMx(name)).map((mx) => ({ priority: mx.priority, exchange: mx.exchange.toLowerCase() }));
      case "SRV":
        return (await this.resolver.resolveSrv(name)).map((srv) => ({ ...srv }));
      case "SOA": {
        const soa = await this.resolver.resolveSoa(name);
        return [{ ...soa }];
      }
      case "CAA":
        return (await this.resolver.resolveCaa(name)).map((caa) => {
          const fields = caa as unknown as Record<string, unknown>;
          const tag = (["issue", "issuewild", "iodef"] as const).find((key) => key in fields) ?? "unknown";
          return { critical: Number(fields.critical ?? 0) !== 0, tag, value: String(fields[tag] ?? "") };
        });
    }
  }
}

export async function txtRecords(dns: DnsClient, name: string): Promise<string[]> {
  return (await dns.resolve(name, "TXT")).records as string[];
}

export async function mxRecords(dns: DnsClient, name: string): Promise<MxRecord[]> {
  const records = (await dns.resolve(name, "MX")).records as MxRecord[];
  return [...records].sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange));
}

export async function hasAddress(dns: DnsClient, name: string): Promise<boolean> {
  const [a, aaaa] = await Promise.all([dns.resolve(name, "A"), dns.resolve(name, "AAAA")]);
  return a.records.length + aaaa.records.length > 0;
}
