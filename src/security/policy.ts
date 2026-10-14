/**
 * Target policy: decides whether a tool may connect to a host:port.
 *
 * Rules, in order:
 *   1. The hostname must be well-formed (no credentials, paths, ports or odd characters).
 *   2. Deny-list, then allow-list (when configured).
 *   3. The port must be allowed.
 *   4. Names that are obviously internal (.local, .internal, ...) are refused unless private
 *      targets are enabled.
 *   5. The name is resolved HERE and EVERY returned address must be public. The caller then
 *      connects to the validated address (not the name), which closes the DNS-rebinding gap
 *      between "check" and "connect".
 */

import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";

import type { Config } from "../config.js";
import { classifyAddress } from "./ip.js";

export type PolicyErrorCode =
  | "invalid_target"
  | "denied_host"
  | "not_allowed_host"
  | "port_not_allowed"
  | "internal_name"
  | "blocked_address"
  | "dns_failure";

export class PolicyError extends Error {
  constructor(
    public readonly code: PolicyErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PolicyError";
  }
}

/** Resolves a hostname to all of its addresses. Injected in tests. */
export type Lookup = (hostname: string) => Promise<string[]>;

export const systemLookup: Lookup = async (hostname) => {
  const results = await dnsLookup(hostname, { all: true, verbatim: true });
  return results.map((entry) => entry.address);
};

export interface ResolvedTarget {
  hostname: string;
  port: number;
  /** Validated addresses; connect to one of these, never to the name. */
  addresses: string[];
}

const INTERNAL_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".home.arpa", ".corp", ".intranet", ".private"];

export function matchesPattern(hostname: string, pattern: string): boolean {
  if (pattern.startsWith("*.")) return hostname.endsWith(pattern.slice(1)) && hostname.length > pattern.length - 1;
  return hostname === pattern;
}

/** Normalise a bare host (no scheme, no port). Throws PolicyError('invalid_target'). */
export function normalizeHostname(input: string): string {
  const raw = input.trim();
  if (!raw || raw.length > 255 || /[\s/\\@?#]/.test(raw)) {
    throw new PolicyError("invalid_target", `"${input.slice(0, 80)}" is not a valid host name`);
  }
  let url: URL;
  try {
    url = new URL(`http://${raw}`);
  } catch {
    throw new PolicyError("invalid_target", `"${input.slice(0, 80)}" is not a valid host name`);
  }
  if (url.port !== "") {
    throw new PolicyError("invalid_target", "Pass the port separately, not inside the host name");
  }
  // URL() canonicalises IPv4 shorthand/hex/octal (e.g. 2130706433 -> 127.0.0.1) and brackets IPv6.
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!host) throw new PolicyError("invalid_target", "Empty host name");
  return host;
}

export interface ParsedUrl {
  url: URL;
  hostname: string;
  port: number;
}

/** Parse and sanity-check an http(s) URL. Throws PolicyError('invalid_target'). */
export function parseHttpUrl(input: string): ParsedUrl {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new PolicyError("invalid_target", `"${input.slice(0, 120)}" is not a valid URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new PolicyError("invalid_target", `Only http and https URLs are supported (got ${url.protocol})`);
  }
  if (url.username || url.password) {
    throw new PolicyError("invalid_target", "URLs containing credentials are not allowed");
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  return { url, hostname, port };
}

export class TargetPolicy {
  constructor(
    private readonly config: Config,
    private readonly lookup: Lookup = systemLookup,
  ) {}

  /**
   * Check the name alone (deny/allow lists, internal-looking names) without touching the network.
   * Used directly by tools that only query DNS, so they cannot be used to read internal zones.
   */
  checkName(hostname: string): void {
    const { denyHosts, allowHosts, allowPrivateTargets } = this.config;

    if (denyHosts.some((pattern) => matchesPattern(hostname, pattern))) {
      throw new PolicyError("denied_host", `${hostname} is on the deny list`);
    }
    if (allowHosts.length > 0 && !allowHosts.some((pattern) => matchesPattern(hostname, pattern))) {
      throw new PolicyError("not_allowed_host", `${hostname} is not on the allow list`);
    }
    if (!allowPrivateTargets && isIP(hostname) === 0) {
      if (hostname === "localhost" || INTERNAL_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
        throw new PolicyError("internal_name", `${hostname} looks like an internal name`);
      }
    }
  }

  /** Check host rules and port without touching the network. */
  checkRules(hostname: string, port: number): void {
    this.checkName(hostname);
    const { allowedPorts } = this.config;
    if (allowedPorts !== "any" && !allowedPorts.includes(port)) {
      throw new PolicyError(
        "port_not_allowed",
        `Port ${port} is not allowed (allowed: ${allowedPorts.join(", ")}). Operators can change OPS_MCP_ALLOWED_PORTS.`,
      );
    }
  }

  /** Full check: rules, then DNS resolution with every address validated. */
  async resolve(hostname: string, port: number): Promise<ResolvedTarget> {
    this.checkRules(hostname, port);

    let addresses: string[];
    if (isIP(hostname) !== 0) {
      addresses = [hostname];
    } else {
      try {
        addresses = await this.lookup(hostname);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code ?? "unknown";
        throw new PolicyError("dns_failure", `Could not resolve ${hostname} (${code})`);
      }
      if (addresses.length === 0) throw new PolicyError("dns_failure", `${hostname} has no A/AAAA records`);
    }

    if (!this.config.allowPrivateTargets) {
      for (const address of addresses) {
        const verdict = classifyAddress(address);
        if (!verdict.public) {
          const subject = address === hostname ? hostname : `${hostname} resolves to ${address}, which`;
          throw new PolicyError(
            "blocked_address",
            `${subject} is ${verdict.reason}. Private and internal targets are blocked.`,
          );
        }
      }
    }
    return { hostname, port, addresses };
  }
}
