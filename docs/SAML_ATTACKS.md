# SAML Attack Reference

## Prerequisites

For maximum effectiveness:

1. **Captured SAML Response** — Intercept a legitimate SAMLResponse
   from Burp Suite or browser devtools
2. **ACS URL** — The Service Provider's Assertion Consumer Service endpoint
3. **Entity IDs** — SP and IdP entity identifiers

## Attack Matrix

| # | Attack | Pre-req | Bypasses | Impact |
|---|--------|---------|----------|--------|
| 1-8 | XSW Variants | Captured response (ideal) | Signature validation | Full account takeover |
| 9 | Assertion Replay | Captured response | Replay protection | Session hijacking |
| 10 | Response Tampering | Any | Signature enforcement | Account takeover |
| 11 | Comment Injection | Any | String comparison | Account takeover |
| 12 | XSLT Injection | Any | Transform whitelist | RCE / Account takeover |
| 13 | XXE | Any | XML parser hardening | File read / SSRF |
| 14 | Signature Exclusion | Any | Signature requirement | Account takeover |
| 15 | Certificate Faking | None (generates own) | Certificate pinning | Account takeover |

## Attack Flow Diagram

```
Attacker                    Target SP                    Legitimate IdP
   │                            │                              │
   │  1. Capture SAMLResponse   │     Normal SSO Login         │
   │◄───────────────────────────│◄─────────────────────────────│
   │                            │                              │
   │  2. Manipulate XML         │                              │
   │  (XSW/Tamper/Strip sig)    │                              │
   │                            │                              │
   │  3. POST modified          │                              │
   │     SAMLResponse to ACS    │                              │
   │───────────────────────────►│                              │
   │                            │                              │
   │  4. SP validates           │                              │
   │     (or fails to validate) │                              │
   │                            │                              │
   │  5. Session granted?       │                              │
   │◄───────────────────────────│                              │
   │                            │                              │
   │  If yes: Account Takeover  │                              │
```

## Common Findings by SP Implementation

| SP Technology | Most Likely Vulnerable To |
|--------------|--------------------------|
| SimpleSAMLphp (old) | XSW-1, XSW-7, Comment Injection |
| Spring Security SAML | Signature Exclusion (misconfigured) |
| OneLogin toolkit | XSW-4, Certificate Faking |
| Custom implementations | Everything (especially XXE, Sig Exclusion) |
| Auth0 | Generally hardened (test anyway) |
| Okta | Generally hardened (test anyway) |
