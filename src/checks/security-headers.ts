/**
 * Security-header analysis. Pure: takes the response headers, returns findings.
 * Cookie VALUES are never read into the output; only names and attributes.
 */

import { type Finding, good, issue } from "../findings.js";
import type { HeaderMap } from "../net/safe-http.js";

export interface CookieInfo {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  hasPrefix: boolean;
}

export interface HeadersAnalysis {
  https: boolean;
  /** Security-relevant headers that were present (cookies excluded). */
  present: Record<string, string>;
  cookies: CookieInfo[];
  findings: Finding[];
}

const one = (headers: HeaderMap, name: string): string | undefined => {
  const value = headers[name];
  return Array.isArray(value) ? value.join(", ") : value;
};

export function parseCsp(csp: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  for (const part of csp.split(";")) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) directives[name.toLowerCase()] = values;
  }
  return directives;
}

export function parseSetCookie(raw: string): CookieInfo {
  const [pair = "", ...attributes] = raw.split(";").map((part) => part.trim());
  const name = pair.split("=")[0] ?? "";
  const lower = attributes.map((attribute) => attribute.toLowerCase());
  const sameSite = lower.find((attribute) => attribute.startsWith("samesite="))?.split("=")[1];
  return {
    name,
    secure: lower.includes("secure"),
    httpOnly: lower.includes("httponly"),
    sameSite,
    hasPrefix: /^__(host|secure)-/i.test(name),
  };
}

const SESSION_LIKE = /(sess|sid|auth|token|jwt|login|csrf|xsrf)/i;

export function analyzeHeaders(headers: HeaderMap, finalUrl: string): HeadersAnalysis {
  const https = finalUrl.startsWith("https:");
  const findings: Finding[] = [];
  const present: Record<string, string> = {};
  const track = (name: string) => {
    const value = one(headers, name);
    if (value !== undefined) present[name] = value.slice(0, 500);
    return value;
  };

  // --- Transport ---------------------------------------------------------------------------
  if (!https) {
    findings.push(issue("headers.no_https", "high", "The page was served over plain HTTP.", "Serve everything over HTTPS and redirect HTTP to HTTPS."));
  }
  const hsts = track("strict-transport-security");
  if (https) {
    if (!hsts) {
      findings.push(issue("headers.hsts_missing", "medium", "Strict-Transport-Security is not set.", "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`."));
    } else {
      const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
      if (maxAge < 15_552_000) {
        findings.push(issue("headers.hsts_short", "low", `HSTS max-age is ${maxAge}s (under 180 days).`, "Raise max-age to at least 31536000 (one year)."));
      } else if (!/includesubdomains/i.test(hsts)) {
        findings.push(issue("headers.hsts_no_subdomains", "low", "HSTS does not include subdomains.", "Add `includeSubDomains` once every subdomain supports HTTPS."));
      } else {
        findings.push(good("headers.hsts", "HSTS is set with a long max-age and includeSubDomains."));
      }
    }
  }

  // --- Content Security Policy -------------------------------------------------------------
  const csp = track("content-security-policy");
  const cspReportOnly = track("content-security-policy-report-only");
  let frameAncestors = false;
  if (!csp) {
    findings.push(
      cspReportOnly
        ? issue("headers.csp_report_only", "low", "CSP is only in report-only mode, so nothing is blocked.", "Move to an enforcing Content-Security-Policy once the reports are clean.")
        : issue("headers.csp_missing", "medium", "Content-Security-Policy is not set.", "Start with `default-src 'self'` and relax per resource type; it is the main defence against XSS."),
    );
  } else {
    const directives = parseCsp(csp);
    frameAncestors = "frame-ancestors" in directives;
    const scriptSources = directives["script-src"] ?? directives["default-src"] ?? [];
    const problems: string[] = [];
    if (scriptSources.includes("'unsafe-inline'") && !scriptSources.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha"))) problems.push("'unsafe-inline' scripts");
    if (scriptSources.includes("'unsafe-eval'")) problems.push("'unsafe-eval'");
    if (scriptSources.includes("*") || scriptSources.includes("http:") || scriptSources.includes("https:") || scriptSources.includes("data:")) problems.push("wildcard or scheme-wide script sources");
    if (!("script-src" in directives) && !("default-src" in directives)) problems.push("no script-src or default-src");
    if (problems.length > 0) {
      findings.push(issue("headers.csp_weak", "medium", `The CSP allows ${problems.join(", ")}, which largely defeats its XSS protection.`, "Use nonces or hashes instead of 'unsafe-inline', and list explicit script origins."));
    } else {
      findings.push(good("headers.csp", "A Content-Security-Policy is set without obviously unsafe script sources."));
    }
    if (!("object-src" in directives) && !(directives["default-src"] ?? []).includes("'none'")) {
      findings.push(issue("headers.csp_object_src", "low", "The CSP does not restrict `object-src`.", "Add `object-src 'none'`."));
    }
  }

  // --- Other headers -----------------------------------------------------------------------
  const nosniff = track("x-content-type-options");
  if ((nosniff ?? "").toLowerCase() !== "nosniff") {
    findings.push(issue("headers.nosniff_missing", "low", "X-Content-Type-Options: nosniff is not set.", "Add `X-Content-Type-Options: nosniff`."));
  } else {
    findings.push(good("headers.nosniff", "X-Content-Type-Options is nosniff."));
  }

  const xfo = track("x-frame-options");
  if (!xfo && !frameAncestors) {
    findings.push(issue("headers.clickjacking", "medium", "Nothing prevents the page from being framed (no X-Frame-Options and no CSP frame-ancestors).", "Add `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: SAMEORIGIN`)."));
  } else {
    findings.push(good("headers.framing", "Framing is restricted."));
  }

  const referrer = track("referrer-policy");
  if (!referrer) {
    findings.push(issue("headers.referrer_missing", "low", "Referrer-Policy is not set.", "Add `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)."));
  } else if (/^(unsafe-url|no-referrer-when-downgrade)$/i.test(referrer.trim())) {
    findings.push(issue("headers.referrer_weak", "low", `Referrer-Policy is ${referrer}, which leaks full URLs to other sites.`, "Use `strict-origin-when-cross-origin` or stricter."));
  } else {
    findings.push(good("headers.referrer", `Referrer-Policy is ${referrer}.`));
  }

  if (!track("permissions-policy")) {
    findings.push(issue("headers.permissions_policy_missing", "info", "Permissions-Policy is not set.", "Disable browser features you do not use, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`."));
  }
  track("cross-origin-opener-policy");
  track("cross-origin-resource-policy");

  // --- CORS --------------------------------------------------------------------------------
  const acao = track("access-control-allow-origin");
  const acac = track("access-control-allow-credentials");
  if (acao === "*" && (acac ?? "").toLowerCase() === "true") {
    findings.push(issue("headers.cors_wildcard_credentials", "high", "CORS allows any origin together with credentials.", "Never combine `Access-Control-Allow-Origin: *` with credentials; reflect only an allow-list of origins."));
  } else if (acao === "*") {
    findings.push(issue("headers.cors_wildcard", "info", "CORS allows any origin (`*`). Fine for public data, wrong for anything user-specific.", "Restrict to specific origins if the responses are not public."));
  }

  // --- Information disclosure --------------------------------------------------------------
  const server = track("server");
  if (server && /\d+\.\d+/.test(server)) {
    findings.push(issue("headers.server_version", "low", `The Server header reveals a version (${server}).`, "Hide the version (nginx: `server_tokens off`; Apache: `ServerTokens Prod`)."));
  }
  for (const leaky of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]) {
    const value = track(leaky);
    if (value) findings.push(issue(`headers.${leaky.replace(/-/g, "_")}`, "low", `The ${leaky} header discloses the technology stack (${value}).`, "Remove the header (PHP: `expose_php = Off`; Express: `app.disable('x-powered-by')`)."));
  }

  // --- Cookies -----------------------------------------------------------------------------
  const rawCookies = headers["set-cookie"];
  const cookies = (Array.isArray(rawCookies) ? rawCookies : rawCookies ? [rawCookies] : []).map(parseSetCookie);
  for (const cookie of cookies) {
    const sensitive = SESSION_LIKE.test(cookie.name);
    const label = `Cookie \`${cookie.name}\``;
    if (https && !cookie.secure) findings.push(issue("headers.cookie_not_secure", sensitive ? "high" : "medium", `${label} has no Secure flag, so it can be sent over plain HTTP.`, "Add `Secure`."));
    if (!cookie.httpOnly) findings.push(issue("headers.cookie_not_httponly", sensitive ? "medium" : "low", `${label} has no HttpOnly flag, so scripts can read it.`, "Add `HttpOnly` unless JavaScript genuinely needs the cookie."));
    if (!cookie.sameSite) findings.push(issue("headers.cookie_no_samesite", "low", `${label} has no SameSite attribute.`, "Add `SameSite=Lax` (or `Strict`)."));
    else if (cookie.sameSite.toLowerCase() === "none" && !cookie.secure) findings.push(issue("headers.cookie_samesite_none_insecure", "medium", `${label} uses SameSite=None without Secure; browsers reject it.`, "Add `Secure` or use `SameSite=Lax`."));
  }

  return { https, present, cookies, findings };
}
