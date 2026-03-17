# Baseline Detection System

## The Problem

How do you know if an SSO attack succeeded without credentials to
compare against? The response from the SP could be:

- A redirect to the dashboard (success)
- A redirect to an error page (failure)
- A 200 with an error message (failure)
- A 200 with a session cookie (success)
- A 302 to the login page (failure)

Different applications behave completely differently.

## Solution: Baseline Calibration

Before running any attacks, SSO Breaker sends **known-invalid** payloads
to establish what "failure" looks like for THIS specific application.

### Calibration Payloads

```
1. Base64("<invalid/>")          — Malformed XML
2. Base64("not-xml")             — Not XML at all
3. ""                            — Empty string
4. Base64("<Response>broken")    — Incomplete XML
```

### Baseline Metrics Recorded

| Metric | Example | Usage |
|--------|---------|-------|
| `bl_status` | 400 | Most common error status code |
| `bl_length` | 2048 | Average error page size |
| `bl_cookies` | {"csrf_token"} | Cookies set even on error |
| `bl_location` | "/login?error=1" | Redirect target on error |
| `bl_error_kw` | {"invalid", "error"} | Keywords in error pages |

### Success Detection Logic

When an attack response comes back, compare against baseline:

```python
# Strong indicator (alone sufficient):
new_session_cookie_set = True  → LIKELY SUCCESS

# Weak indicators (need ≥2):
status_code_changed     = True  → +1
response_length_changed = True  → +1  (>30% difference)
redirect_target_changed = True  → +1  (no longer /login)
error_keywords_missing  = True  → +1
```

### Example

```
Baseline: status=400, length≈2048, location="/login?error=saml"
          error_keywords={"invalid", "error", "signature"}

Attack response: status=302, length=0, location="/dashboard"
                 Set-Cookie: session_id=abc123

Indicators:
  ✓ status: 400→302
  ✓ new session cookie: session_id
  ✓ redirect changed: /login→/dashboard
  ✓ error keywords missing

Result: SUCCESS (4 indicators, session cookie = strong)
```

## Limitations

- Cannot detect success if the application returns identical responses
  for success and failure (rare but possible)
- First-time calibration adds 2-4 seconds to scan startup
- Baseline may drift if application state changes during scan
