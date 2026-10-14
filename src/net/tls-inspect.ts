/**
 * TLS inspection: handshake, certificate chain and protocol support.
 *
 * Connects with rejectUnauthorized:false ON PURPOSE: the point is to look at broken
 * certificates, not to refuse to talk to them. Node still verifies the chain against the system
 * trust store and tells us the result in `authorized` / `authorizationError`.
 * Only the handshake happens: no application data is ever sent.
 */

import { X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import * as tls from "node:tls";

import type { Config } from "../config.js";
import { type Finding, good, issue } from "../findings.js";
import { TargetPolicy, normalizeHostname } from "../security/policy.js";

export interface TlsDeps {
  config: Config;
  policy: TargetPolicy;
  /** Test hook: maps a validated address to the address actually dialled. */
  connectAddress?: (validatedAddress: string) => string;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  subjectAltNames: string[];
  fingerprint256: string;
  selfSigned: boolean;
  isCA: boolean;
  keyType: string;
  keyBits?: number;
  curve?: string;
}

export type TlsVersion = "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";

export interface TlsResult {
  host: string;
  port: number;
  address: string;
  protocol: string | null;
  cipher: string | null;
  alpn: string | null;
  authorized: boolean;
  authorizationError: string | null;
  hostnameMatches: boolean;
  chain: CertInfo[];
  handshakeMs: number;
  /** Which protocol versions the server accepts (only when requested). */
  supportedProtocols?: Record<TlsVersion, boolean>;
  findings: Finding[];
}

const DAY_MS = 86_400_000;
const LEGACY_CIPHERS = "ALL:@SECLEVEL=0";

function firstLine(dn: string): string {
  // Node renders DNs as "CN=example.com\nO=Org"; keep it on one line.
  return dn.split("\n").join(", ");
}

export function describeCertificate(raw: Buffer, now = Date.now()): CertInfo {
  const cert = new X509Certificate(raw);
  const validTo = new Date(cert.validTo);
  const key = cert.publicKey;
  const details = key.asymmetricKeyDetails;
  return {
    subject: firstLine(cert.subject),
    issuer: firstLine(cert.issuer),
    serialNumber: cert.serialNumber,
    validFrom: new Date(cert.validFrom).toISOString(),
    validTo: validTo.toISOString(),
    daysRemaining: Math.floor((validTo.getTime() - now) / DAY_MS),
    subjectAltNames: cert.subjectAltName ? cert.subjectAltName.split(/,\s*/) : [],
    fingerprint256: cert.fingerprint256,
    // checkIssued() would also demand the keyCertSign usage, which server certificates lack.
    selfSigned: cert.subject === cert.issuer && cert.verify(cert.publicKey),
    isCA: cert.ca,
    keyType: key.asymmetricKeyType ?? "unknown",
    keyBits: details?.modulusLength,
    curve: details?.namedCurve,
  };
}

function connectOnce(
  options: tls.ConnectionOptions,
  timeoutMs: number,
): Promise<{ socket: tls.TLSSocket; ms: number }> {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const socket = tls.connect(options);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(Object.assign(new Error("TLS handshake timed out"), { code: "ETIMEDOUT" }));
    }, timeoutMs);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      resolve({ socket, ms: performance.now() - started });
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      socket.destroy();
      reject(error);
    });
  });
}

async function accepts(base: tls.ConnectionOptions, version: TlsVersion, timeoutMs: number): Promise<boolean> {
  const legacy = version === "TLSv1" || version === "TLSv1.1";
  try {
    const { socket } = await connectOnce(
      { ...base, minVersion: version, maxVersion: version, ...(legacy ? { ciphers: LEGACY_CIPHERS } : {}) },
      timeoutMs,
    );
    socket.destroy();
    return true;
  } catch {
    return false;
  }
}

function collectChain(socket: tls.TLSSocket): Buffer[] {
  const seen = new Set<string>();
  const raws: Buffer[] = [];
  let current: tls.DetailedPeerCertificate | undefined = socket.getPeerCertificate(true);
  while (current && current.raw && !seen.has(current.fingerprint256)) {
    seen.add(current.fingerprint256);
    raws.push(current.raw);
    const next: tls.DetailedPeerCertificate | undefined = current.issuerCertificate;
    current = next && next !== current ? next : undefined;
  }
  return raws;
}

export function evaluateTls(
  result: Pick<TlsResult, "host" | "protocol" | "authorized" | "authorizationError" | "hostnameMatches" | "chain" | "supportedProtocols">,
): Finding[] {
  const findings: Finding[] = [];
  const leaf = result.chain[0];

  if (leaf) {
    if (leaf.daysRemaining < 0) {
      findings.push(
        issue("tls.expired", "high", `The certificate expired ${-leaf.daysRemaining} day(s) ago (${leaf.validTo}).`, "Renew and deploy the certificate now; check why auto-renewal did not run."),
      );
    } else if (leaf.daysRemaining <= 7) {
      findings.push(issue("tls.expiring_critical", "high", `The certificate expires in ${leaf.daysRemaining} day(s) (${leaf.validTo}).`, "Renew immediately and verify the renewal job."));
    } else if (leaf.daysRemaining <= 14) {
      findings.push(issue("tls.expiring_soon", "medium", `The certificate expires in ${leaf.daysRemaining} days (${leaf.validTo}).`, "Renew now; most automated renewals start 30 days out."));
    } else if (leaf.daysRemaining <= 30) {
      findings.push(issue("tls.expiring", "low", `The certificate expires in ${leaf.daysRemaining} days (${leaf.validTo}).`, "Confirm automatic renewal is working."));
    } else {
      findings.push(good("tls.validity", `The certificate is valid for ${leaf.daysRemaining} more days (until ${leaf.validTo}).`));
    }

    if (leaf.keyType === "rsa" && leaf.keyBits !== undefined && leaf.keyBits < 2048) {
      findings.push(issue("tls.weak_key", "high", `The RSA key is only ${leaf.keyBits} bits.`, "Reissue with an RSA key of at least 2048 bits (or an ECDSA P-256 key)."));
    }
  }

  if (!result.hostnameMatches) {
    findings.push(
      issue(
        "tls.hostname_mismatch",
        "high",
        `The certificate is not valid for ${result.host}. It covers: ${leaf?.subjectAltNames.join(", ") || leaf?.subject || "unknown"}.`,
        "Issue a certificate that includes this host name in its Subject Alternative Names.",
      ),
    );
  }

  const error = result.authorizationError;
  if (!result.authorized && error && error !== "CERT_HAS_EXPIRED" && error !== "ERR_TLS_CERT_ALTNAME_INVALID") {
    if (error === "DEPTH_ZERO_SELF_SIGNED_CERT" || error === "SELF_SIGNED_CERT_IN_CHAIN") {
      findings.push(issue("tls.self_signed", "high", "The certificate is self-signed or its chain ends in an untrusted root.", "Use a certificate from a public CA (for example Let's Encrypt) for anything public."));
    } else if (error === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" || error === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY") {
      findings.push(issue("tls.incomplete_chain", "high", "The server does not send the intermediate certificate(s), so many clients (curl, Java, Python, mobile apps) will reject it even though some browsers cope.", "Serve the full chain: use fullchain.pem (not cert.pem) in the web server configuration."));
    } else {
      findings.push(issue("tls.untrusted", "high", `The certificate is not trusted (${error}).`, "Check the chain and the issuing CA."));
    }
  } else if (result.authorized) {
    findings.push(good("tls.trusted", "The certificate chain is trusted by the system store."));
  }

  if (result.protocol === "TLSv1.3") findings.push(good("tls.protocol", "Negotiated TLS 1.3."));
  else if (result.protocol === "TLSv1.2") findings.push(good("tls.protocol", "Negotiated TLS 1.2 (TLS 1.3 is not preferred by this server)."));
  else if (result.protocol) findings.push(issue("tls.old_protocol", "high", `Negotiated ${result.protocol}.`, "Disable protocols older than TLS 1.2."));

  const supported = result.supportedProtocols;
  if (supported) {
    if (supported.TLSv1 || supported["TLSv1.1"]) {
      const which = [supported.TLSv1 && "TLS 1.0", supported["TLSv1.1"] && "TLS 1.1"].filter(Boolean).join(" and ");
      findings.push(issue("tls.legacy_protocols", "medium", `The server still accepts ${which}.`, "Disable TLS 1.0 and 1.1 (deprecated by RFC 8996; PCI DSS forbids them)."));
    }
    if (!supported["TLSv1.3"]) {
      findings.push(issue("tls.no_tls13", "low", "The server does not support TLS 1.3.", "Enable TLS 1.3 (OpenSSL 1.1.1+, nginx 1.13+, Apache 2.4.36+)."));
    }
  }
  return findings;
}

export async function inspectTls(
  deps: TlsDeps,
  hostInput: string,
  port = 443,
  options: { checkProtocols?: boolean } = {},
): Promise<TlsResult> {
  const host = normalizeHostname(hostInput);
  const target = await deps.policy.resolve(host, port);
  const validated = target.addresses[0]!;
  const dial = deps.connectAddress ? deps.connectAddress(validated) : validated;
  const timeoutMs = deps.config.timeoutMs;
  const base: tls.ConnectionOptions = {
    host: dial,
    port,
    ...(isIP(host) === 0 ? { servername: host } : {}),
    rejectUnauthorized: false,
    ALPNProtocols: ["h2", "http/1.1"],
  };

  const { socket, ms } = await connectOnce(base, timeoutMs);
  try {
    const raws = collectChain(socket);
    const now = Date.now();
    const chain = raws.map((raw) => describeCertificate(raw, now));
    const leaf = raws[0] ? new X509Certificate(raws[0]) : undefined;
    const matches = leaf
      ? isIP(host) !== 0
        ? leaf.checkIP(host) !== undefined
        : leaf.checkHost(host) !== undefined
      : false;

    const result: TlsResult = {
      host,
      port,
      address: validated,
      protocol: socket.getProtocol(),
      cipher: socket.getCipher()?.name ?? null,
      alpn: typeof socket.alpnProtocol === "string" ? socket.alpnProtocol : null,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
      hostnameMatches: matches,
      chain,
      handshakeMs: Math.round(ms),
      findings: [],
    };

    if (options.checkProtocols) {
      const versions: TlsVersion[] = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"];
      const supported = {} as Record<TlsVersion, boolean>;
      for (const version of versions) supported[version] = await accepts(base, version, Math.min(timeoutMs, 5_000));
      result.supportedProtocols = supported;
    }
    result.findings = evaluateTls(result);
    return result;
  } finally {
    socket.destroy();
  }
}
