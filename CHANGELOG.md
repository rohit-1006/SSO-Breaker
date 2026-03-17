# Changelog

All notable changes to SSO Breaker are documented here.

## [2.1.0] — 2024-01-15

### Added
- **Real XML-DSIG signing** — Exclusive C14N canonicalization + RSA-PKCS1v15-SHA256
- **Self-verification** — Tool validates its own signatures before sending
- **OIDC auto-discovery** — Automatic .well-known/openid-configuration parsing
- **JWKS extraction** — Fetches and converts RSA JWK keys to PEM format
- **RSA→HMAC key confusion** — Signs HS256 JWTs using RSA public key from JWKS
- **Baseline calibration** — Sends invalid payloads first to establish failure baseline
- **SSO flow detection** — Follows redirect chains to identify SAML/OIDC/CAS
- **SAML metadata parser** — Auto-extracts entity IDs, endpoints, certificates
- **Rate limiter** — Exponential backoff on errors, configurable minimum delay
- **Scope validator** — Confirms authorization before sending any traffic
- **CVSS estimates** — Each finding includes estimated CVSS 3.1 score
- **SAML raw submission** — submit_raw_saml() for attacks requiring string manipulation
- **Cloud SSRF payloads** — AWS, GCP, Azure metadata endpoints in XXE attacks

### Changed
- Complete architecture rewrite with separated concerns
- XMLDSigSigner is now a standalone class with proper C14N
- BaselineDetector replaces heuristic success checking
- AttackSession centralizes HTTP, rate limiting, and finding management
- All XSW attacks use shared _xsw() helper with mutation functions

### Fixed
- Missing `import hmac` that crashed HMAC key confusion
- SSOFlowHandler now actually called during SAML attack initialization
- Certificate faking produces cryptographically valid signatures
- XSW attacks work correctly with captured SAML responses

## [2.0.0] — 2024-01-10

### Added
- All 8 XSW attack variants
- OIDC algorithm none attack (5 case variants)
- OIDC issuer confusion (8 bypass payloads)
- CAS proxy ticket abuse
- General SSO provider confusion
- JSON report output format

### Changed
- Restructured into class-based attack modules

## [1.0.0] — 2024-01-05

### Added
- Initial release
- Basic SAML attacks with synthetic responses
- OIDC token manipulation
- CAS service ticket testing
- Text report output
