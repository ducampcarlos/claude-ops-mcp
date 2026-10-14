# Changelog

## 0.1.0

First release.

- Eight read-only tools: `tls_inspect`, `cert_expiry`, `http_probe`, `redirect_chain`, `security_headers`, `dns_lookup`, `mail_auth`, `sitemap_audit`.
- Four prompts: `site_health_review`, `migration_check`, `mail_deliverability`, `cert_renewal_sweep`.
- SSRF protection with DNS pinning and per-hop redirect validation, rate and concurrency limits, audit log.
- stdio and stateless Streamable HTTP transports (bearer token, Host validation).
