# OIDC/OAuth2 Attack Reference

## Auto-Discovery

Always use `--oidc-discovery-url` when possible. The tool will:

```
GET https://auth.example.com/.well-known/openid-configuration

Response:
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "response_types_supported": ["code", "token", "id_token"],
  "id_token_signing_alg_values_supported": ["RS256"]
}

→ All endpoints auto-configured
→ JWKS keys fetched and converted to PEM
→ Ready for key confusion attacks
```

## Attack Details

### 1. Algorithm None (5 variants)

Tests case-sensitivity of `alg` rejection:
- `none`, `None`, `NONE`, `nOnE`, `NoNe`

### 2. HMAC Key Confusion

Requires JWKS with RSA keys. The tool:
1. Downloads JWKS
2. Extracts RSA public key (n, e parameters)
3. Converts to PEM format
4. Signs evil JWT with HS256 using PEM bytes as HMAC secret
5. Also tests with stripped newlines and whitespace variants

### 3. Issuer Confusion (8 payloads)

```
https://evil-idp.com
https://accounts.google.com.evil.com
https://login.microsoftonline.com.evil.com
null
(empty string)
https://auth.example.com/../../evil
https://auth.example.com@evil.com
https://evil.com/.well-known/../auth
```

### 4. Audience Bypass (7 payloads)

```
evil_client
*
(empty string)
null
["legitimate_client", "evil_client"]
https://evil.com
{client_id}.evil
```

## Token Delivery Methods

The tool tests tokens via TWO delivery paths:

1. **Authorization header** → userinfo endpoint
   ```
   GET /userinfo
   Authorization: Bearer <evil_token>
   ```

2. **Callback POST** → redirect URI
   ```
   POST /callback
   id_token=<evil_token>&state=test_state
   ```

This catches applications that validate differently in each path.
