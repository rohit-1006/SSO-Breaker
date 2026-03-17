# XML Digital Signature Implementation

## Overview

SSO Breaker implements real XML-DSIG (XML Digital Signature) as defined
in [W3C XML Signature Syntax and Processing](https://www.w3.org/TR/xmldsig-core1/).

This is critical for the **Certificate Faking** attack — the SP receives
a properly signed SAML assertion that passes cryptographic validation.

## Signing Process

```
Input: SAML Assertion XML element + RSA private key + X.509 certificate

Step 1: Remove existing signatures from assertion
    └── assertion.findall("{DS_NS}Signature") → remove each

Step 2: Compute digest of assertion
    ├── Copy assertion (without Signature element)
    ├── Exclusive C14N canonicalization (xml-exc-c14n)
    ├── SHA-256 hash of canonical form
    └── Base64 encode → DigestValue

Step 3: Build SignedInfo element
    ├── CanonicalizationMethod: Exclusive C14N
    ├── SignatureMethod: RSA-SHA256
    └── Reference:
        ├── URI: "#assertion_id"
        ├── Transforms:
        │   ├── enveloped-signature
        │   └── exc-c14n
        ├── DigestMethod: SHA-256
        └── DigestValue: (from Step 2)

Step 4: Sign the SignedInfo
    ├── Exclusive C14N canonicalization of SignedInfo
    ├── RSA-PKCS1v15-SHA256 signature
    └── Base64 encode → SignatureValue

Step 5: Assemble Signature element
    ├── SignedInfo (from Step 3)
    ├── SignatureValue (from Step 4)
    └── KeyInfo:
        └── X509Data:
            └── X509Certificate: (base64 cert)

Step 6: Insert Signature after Issuer element in assertion

Step 7: Self-verify (recompute digest, compare)

Output: Signed SAML assertion
```

## Canonicalization

We use **Exclusive XML Canonicalization** (exc-c14n) as specified in
[RFC 3741](https://www.w3.org/TR/xml-exc-c14n/):

```python
def _c14n_exc(el: etree._Element) -> bytes:
    copied = copy.deepcopy(el)
    tree = etree.ElementTree(copied)
    buf = BytesIO()
    tree.write_c14n(buf, exclusive=True, with_comments=False)
    return buf.getvalue()
```

This ensures:
- Namespace declarations are only included if used
- Attribute ordering is normalized
- Whitespace is normalized
- The canonical form is deterministic

## Why This Matters

Most SAML testing tools stuff random bytes into SignatureValue. This is
detected instantly by any SP that validates signatures (which is most of them).

SSO Breaker's real signatures mean:
- If SP trusts ANY valid certificate → attack succeeds
- If SP pins IdP certificate → attack fails (correct behavior)
- Accurately tests the SP's certificate validation logic
