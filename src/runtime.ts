/** Everything a tool needs, built once from the configuration. Tests inject fakes through `overrides`. */

import type { Config } from "./config.js";
import { type DnsClient, SystemDnsClient } from "./net/dns.js";
import type { HttpDeps } from "./net/safe-http.js";
import type { TlsDeps } from "./net/tls-inspect.js";
import { AuditLog } from "./security/audit.js";
import { ConcurrencyGate, type Clock, RateLimiter } from "./security/limits.js";
import { type Lookup, TargetPolicy } from "./security/policy.js";

export interface Runtime {
  config: Config;
  policy: TargetPolicy;
  dns: DnsClient;
  http: HttpDeps;
  tls: TlsDeps;
  audit: AuditLog;
  limiter: RateLimiter;
  gate: ConcurrencyGate;
}

export interface RuntimeOverrides {
  lookup?: Lookup;
  dns?: DnsClient;
  audit?: AuditLog;
  clock?: Clock;
  /** Test hook: maps a validated address to the address actually dialled. */
  connectAddress?: (validatedAddress: string) => string;
}

export function createRuntime(config: Config, overrides: RuntimeOverrides = {}): Runtime {
  const policy = new TargetPolicy(config, overrides.lookup);
  const connectAddress = overrides.connectAddress;
  return {
    config,
    policy,
    dns: overrides.dns ?? new SystemDnsClient(config.timeoutMs),
    http: { config, policy, connectAddress },
    tls: { config, policy, connectAddress },
    audit: overrides.audit ?? AuditLog.toFile(config.auditLogPath),
    limiter: new RateLimiter(config.requestsPerMinute, overrides.clock),
    gate: new ConcurrencyGate(config.maxConcurrentCalls),
  };
}
