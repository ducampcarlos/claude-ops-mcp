/**
 * Test PKI: builds CA / intermediate / leaf certificates with arbitrary validity windows.
 *
 * Certificates are assembled as DER by hand and signed with node:crypto, so the test suite needs
 * no third-party crypto library. Node's own X509 parser and TLS stack then act as the validator.
 */

import { type KeyObject, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { isIP } from "node:net";
import * as tls from "node:tls";

// ---------------------------------------------------------------------------------------------
// Minimal DER encoder
// ---------------------------------------------------------------------------------------------

const der = (tag: number, content: Buffer): Buffer => {
  const length = content.length;
  const header =
    length < 0x80
      ? Buffer.from([tag, length])
      : length < 0x100
        ? Buffer.from([tag, 0x81, length])
        : Buffer.from([tag, 0x82, length >> 8, length & 0xff]);
  return Buffer.concat([header, content]);
};

const seq = (...parts: Buffer[]) => der(0x30, Buffer.concat(parts));
const set = (...parts: Buffer[]) => der(0x31, Buffer.concat(parts));
const octets = (content: Buffer) => der(0x04, content);
const boolean = (value: boolean) => der(0x01, Buffer.from([value ? 0xff : 0x00]));
const nul = () => Buffer.from([0x05, 0x00]);
const utf8 = (text: string) => der(0x0c, Buffer.from(text, "utf8"));

function integer(bytes: Buffer): Buffer {
  let body = bytes;
  while (body.length > 1 && body[0] === 0 && (body[1]! & 0x80) === 0) body = body.subarray(1);
  if ((body[0]! & 0x80) !== 0) body = Buffer.concat([Buffer.from([0]), body]);
  return der(0x02, body);
}

function oid(dotted: string): Buffer {
  const parts = dotted.split(".").map(Number);
  const bytes = [parts[0]! * 40 + parts[1]!];
  for (const part of parts.slice(2)) {
    const chunk = [part & 0x7f];
    for (let rest = part >> 7; rest > 0; rest >>= 7) chunk.unshift((rest & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return der(0x06, Buffer.from(bytes));
}

function bitString(bytes: Buffer, unusedBits = 0): Buffer {
  return der(0x03, Buffer.concat([Buffer.from([unusedBits]), bytes]));
}

function time(date: Date): Buffer {
  const pad = (n: number) => String(n).padStart(2, "0");
  const year = date.getUTCFullYear();
  const body = `${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return year < 2050 ? der(0x17, Buffer.from(`${pad(year % 100)}${body}`)) : der(0x18, Buffer.from(`${year}${body}`));
}

function ipBytes(address: string): Buffer {
  if (isIP(address) === 4) return Buffer.from(address.split(".").map(Number));
  throw new Error(`Only IPv4 SANs are supported in the test PKI (got ${address})`);
}

const OID = {
  sha256WithRSA: "1.2.840.113549.1.1.11",
  commonName: "2.5.4.3",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  serverAuth: "1.3.6.1.5.5.7.3.1",
  subjectAltName: "2.5.29.17",
} as const;

const extension = (id: string, critical: boolean, value: Buffer) =>
  seq(oid(id), ...(critical ? [boolean(true)] : []), octets(value));

// ---------------------------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------------------------

export interface Identity {
  certPem: string;
  keyPem: string;
  /** DER of the subject Name, reused as the issuer Name of certificates this identity signs. */
  nameDer: Buffer;
  privateKey: KeyObject;
}

export interface CertOptions {
  cn: string;
  /** Subject alternative names (DNS names or IPv4 addresses). Defaults to [cn]. */
  sans?: string[];
  /** Days from now. Negative = in the past. */
  startsInDays?: number;
  expiresInDays?: number;
  keyBits?: number;
  isCA?: boolean;
  issuer?: Identity;
}

const DAY = 86_400_000;
const keyCache = new Map<number, { privateKey: KeyObject; privatePem: string; spki: Buffer }>();

function rsaKey(bits: number) {
  let entry = keyCache.get(bits);
  if (!entry) {
    // Native key generation: far faster than any pure-JS implementation.
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
    entry = {
      privateKey,
      privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      spki: publicKey.export({ type: "spki", format: "der" }) as Buffer,
    };
    keyCache.set(bits, entry);
  }
  return entry;
}

// 64-column lines with no trailing blank line, even when the length is an exact multiple of 64.
const toPem = (derBytes: Buffer) =>
  `-----BEGIN CERTIFICATE-----\n${derBytes.toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;

export function makeIdentity(options: CertOptions): Identity {
  const { cn, sans = [cn], startsInDays = -1, expiresInDays = 90, keyBits = 2048, isCA = false, issuer } = options;
  const key = rsaKey(keyBits);
  const now = Date.now();

  const name = seq(set(seq(oid(OID.commonName), utf8(cn))));
  const signatureAlgorithm = seq(oid(OID.sha256WithRSA), nul());

  const extensions = [extension(OID.basicConstraints, true, seq(...(isCA ? [boolean(true)] : [])))];
  if (isCA) {
    // keyCertSign (bit 5) + cRLSign (bit 6)
    extensions.push(extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)));
  } else {
    // digitalSignature (bit 0) + keyEncipherment (bit 2)
    extensions.push(extension(OID.keyUsage, true, bitString(Buffer.from([0xa0]), 5)));
    extensions.push(extension(OID.extKeyUsage, false, seq(oid(OID.serverAuth))));
    const names = sans.map((value) => (isIP(value) ? der(0x87, ipBytes(value)) : der(0x82, Buffer.from(value, "ascii"))));
    extensions.push(extension(OID.subjectAltName, false, seq(...names)));
  }

  const serial = randomBytes(8);
  serial[0]! &= 0x7f;
  const tbs = seq(
    der(0xa0, integer(Buffer.from([2]))), // version: v3
    integer(serial),
    signatureAlgorithm,
    issuer ? issuer.nameDer : name,
    seq(time(new Date(now + startsInDays * DAY)), time(new Date(now + expiresInDays * DAY))),
    name,
    key.spki,
    der(0xa3, seq(...extensions)),
  );
  const signature = sign("sha256", tbs, issuer ? issuer.privateKey : key.privateKey);
  const certificate = seq(tbs, signatureAlgorithm, bitString(signature));

  return { certPem: toPem(certificate), keyPem: key.privatePem, nameDer: name, privateKey: createPrivateKey(key.privatePem) };
}

/** Make Node trust the given roots (in addition to the normal store) for this process. */
export function trustRoots(...roots: Identity[]): () => void {
  const original = tls.getCACertificates("default");
  tls.setDefaultCACertificates([...original, ...roots.map((root) => root.certPem)]);
  return () => tls.setDefaultCACertificates(original);
}

// ---------------------------------------------------------------------------------------------
// TLS test server
// ---------------------------------------------------------------------------------------------

export interface TlsTestServerOptions {
  leaf: Identity;
  /** Certificates to send after the leaf (e.g. the intermediate). */
  chain?: Identity[];
  minVersion?: tls.SecureVersion;
  maxVersion?: tls.SecureVersion;
  ciphers?: string;
  onServername?: (name: string | undefined) => void;
}

export async function startTlsServer(options: TlsTestServerOptions): Promise<{ port: number; close(): Promise<void> }> {
  const material = {
    key: options.leaf.keyPem,
    cert: [options.leaf.certPem, ...(options.chain ?? []).map((c) => c.certPem)].join("\n"),
    minVersion: options.minVersion,
    maxVersion: options.maxVersion,
    ciphers: options.ciphers,
  };
  const context = tls.createSecureContext(material);
  const server = tls.createServer({
    ...material,
    ALPNProtocols: ["h2", "http/1.1"],
    // Node only exposes the requested SNI name when an SNICallback is installed.
    SNICallback: (name, callback) => {
      options.onServername?.(name);
      callback(null, context);
    },
  });
  server.on("secureConnection", (socket) => {
    socket.on("error", () => undefined);
    socket.end();
  });
  server.on("tlsClientError", () => undefined);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as import("node:net").AddressInfo).port;
  return {
    port,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

void createPublicKey; // (kept available for tests that need to inspect keys)
