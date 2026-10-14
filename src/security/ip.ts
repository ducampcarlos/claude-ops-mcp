/**
 * IP address classification for SSRF protection.
 *
 * An address is "public" only if it is NOT in any special-purpose range (RFC 6890 and friends).
 * IPv6 addresses that embed an IPv4 address (IPv4-mapped, NAT64, 6to4) are judged by the embedded
 * IPv4 address, otherwise `::ffff:127.0.0.1` would sail through.
 */

import { isIP } from "node:net";

export interface Classification {
  public: boolean;
  /** Human-readable reason when not public. */
  reason?: string;
}

const NOT_PUBLIC = (reason: string): Classification => ({ public: false, reason });
const PUBLIC: Classification = { public: true };

export function parseIPv4(input: string): number | null {
  const parts = input.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null; // no leading zeros: they are octal in some parsers
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

export function parseIPv6(input: string): bigint | null {
  let text = input.split("%")[0]!.toLowerCase(); // drop zone id
  const tail = text.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (tail) {
    const v4 = parseIPv4(tail[1]!);
    if (v4 === null) return null;
    text = `${text.slice(0, -tail[1]!.length)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups: string[];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    groups = [...head, ...Array<string>(missing).fill("0"), ...rest];
  }
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(`0x${group}`);
  }
  return value;
}

type V4Range = [base: string, prefix: number, label: string];

const V4_BLOCKED: V4Range[] = [
  ["0.0.0.0", 8, "'this network' (0.0.0.0/8)"],
  ["10.0.0.0", 8, "private network (10.0.0.0/8)"],
  ["100.64.0.0", 10, "carrier-grade NAT (100.64.0.0/10)"],
  ["127.0.0.0", 8, "loopback (127.0.0.0/8)"],
  ["169.254.0.0", 16, "link-local / cloud metadata (169.254.0.0/16)"],
  ["172.16.0.0", 12, "private network (172.16.0.0/12)"],
  ["192.0.0.0", 24, "IETF protocol assignments (192.0.0.0/24)"],
  ["192.0.2.0", 24, "documentation range TEST-NET-1"],
  ["192.88.99.0", 24, "6to4 relay anycast (deprecated)"],
  ["192.168.0.0", 16, "private network (192.168.0.0/16)"],
  ["198.18.0.0", 15, "benchmarking range (198.18.0.0/15)"],
  ["198.51.100.0", 24, "documentation range TEST-NET-2"],
  ["203.0.113.0", 24, "documentation range TEST-NET-3"],
  ["224.0.0.0", 4, "multicast (224.0.0.0/4)"],
  ["240.0.0.0", 4, "reserved (240.0.0.0/4) and broadcast"],
];

function inV4(addr: number, base: string, prefix: number): boolean {
  const baseValue = parseIPv4(base)!;
  const shift = 32 - prefix;
  return Math.floor(addr / 2 ** shift) === Math.floor(baseValue / 2 ** shift);
}

export function classifyIPv4(addr: number): Classification {
  for (const [base, prefix, label] of V4_BLOCKED) {
    if (inV4(addr, base, prefix)) return NOT_PUBLIC(label);
  }
  return PUBLIC;
}

type V6Range = [base: string, prefix: number, label: string];

const V6_BLOCKED: V6Range[] = [
  ["::", 128, "unspecified address (::)"],
  ["::1", 128, "loopback (::1)"],
  ["100::", 64, "discard-only range (100::/64)"],
  ["2001::", 32, "Teredo tunnelling (2001::/32)"],
  ["2001:db8::", 32, "documentation range (2001:db8::/32)"],
  ["fc00::", 7, "unique local address (fc00::/7)"],
  ["fe80::", 10, "link-local (fe80::/10)"],
  ["fec0::", 10, "deprecated site-local (fec0::/10)"],
  ["ff00::", 8, "multicast (ff00::/8)"],
];

function inV6(addr: bigint, base: string, prefix: number): boolean {
  const baseValue = parseIPv6(base)!;
  const shift = BigInt(128 - prefix);
  return addr >> shift === baseValue >> shift;
}

export function classifyIPv6(addr: bigint): Classification {
  // IPv4-mapped (::ffff:0:0/96): judge the embedded IPv4 address.
  if (addr >> 32n === 0xffffn) return embedded(Number(addr & 0xffffffffn), "IPv4-mapped");
  // IPv4-compatible (::/96, deprecated) other than :: and ::1.
  if (addr >> 32n === 0n && addr > 1n) return embedded(Number(addr & 0xffffffffn), "IPv4-compatible");
  // NAT64 well-known prefix 64:ff9b::/96.
  if (addr >> 32n === 0x0064ff9b0000000000000000n) return embedded(Number(addr & 0xffffffffn), "NAT64");
  // 6to4 2002::/16 embeds the IPv4 address in bits 16..48.
  if (addr >> 112n === 0x2002n) return embedded(Number((addr >> 80n) & 0xffffffffn), "6to4");
  for (const [base, prefix, label] of V6_BLOCKED) {
    if (inV6(addr, base, prefix)) return NOT_PUBLIC(label);
  }
  return PUBLIC;
}

function embedded(v4: number, kind: string): Classification {
  const inner = classifyIPv4(v4);
  return inner.public ? PUBLIC : NOT_PUBLIC(`${kind} address embedding ${inner.reason}`);
}

/** Classify any textual IP address. Unparseable input is never public. */
export function classifyAddress(address: string): Classification {
  const family = isIP(address);
  if (family === 4) {
    const parsed = parseIPv4(address);
    return parsed === null ? NOT_PUBLIC("unparseable IPv4 address") : classifyIPv4(parsed);
  }
  if (family === 6) {
    const parsed = parseIPv6(address);
    return parsed === null ? NOT_PUBLIC("unparseable IPv6 address") : classifyIPv6(parsed);
  }
  return NOT_PUBLIC("not an IP address");
}

export function isPublicAddress(address: string): boolean {
  return classifyAddress(address).public;
}
