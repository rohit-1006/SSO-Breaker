# CAS Protocol Attack Reference

## Protocol Overview

```
User → App: Access protected resource
App → User: Redirect to CAS /login?service=https://app.example.com
User → CAS: Authenticate (username/password)
CAS → User: Redirect to https://app.example.com?ticket=ST-abc123
User → App: Follow redirect with ticket
App → CAS: GET /serviceValidate?ticket=ST-abc123&service=https://app.example.com
CAS → App: XML response with username
App → User: Authenticated session
```

## Attacks

### Service Ticket Reuse

Sends the same service ticket 3 times. If accepted more than once,
tickets are not properly invalidated after first use.

### Service URL Manipulation (16 payloads)

Tests if the CAS server validates the `service` parameter:

```
https://evil.com                          — Direct evil URL
https://target.com.evil.com               — Subdomain confusion
https://target.com@evil.com               — Credential in URL
//evil.com                                — Protocol-relative
javascript:alert(document.domain)         — JavaScript URI
data:text/html;base64,...                  — Data URI
https://target.com/../../../evil.com      — Path traversal
https://target.com/..;/evil.com           — Tomcat path traversal
https://evil.com?url=target.com           — Parameter confusion
%68%74%74%70%73%3a%2f%2fevil.com          — URL-encoded
https://target.com\r\nLocation:evil.com   — Header injection
```

### Proxy Ticket Abuse

Tests CAS proxy endpoints with unauthorized `pgtUrl`:
- Attempts to obtain Proxy Granting Tickets
- Tests cross-ticket-type validation (ST as PT, PGT as ST)
- Probes multiple proxy endpoint paths
