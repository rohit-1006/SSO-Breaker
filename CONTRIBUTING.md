# Contributing to SSO Breaker

Thank you for considering contributing to SSO Breaker!

## Code of Conduct

- This tool is for **authorized security testing only**
- Never submit attack payloads targeting real production systems in issues/PRs
- Sanitize all evidence and examples

## How to Contribute

### Bug Reports

1. Check existing issues first
2. Include: Python version, OS, full error traceback
3. Sanitize any target URLs/tokens before posting

### Feature Requests

Open an issue with:
- Attack type and protocol (SAML/OIDC/CAS/other)
- Reference paper or CVE if applicable
- Expected behavior

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-attack`
3. Follow existing code patterns:
   - Each attack is a method returning `Optional[Finding]`
   - Use `self.sess.rate.wait()` before every HTTP request
   - Log with `logger.info(f"[TAG] message")`
   - Return `Finding` with severity, evidence, and remediation
4. Test against a local SSO setup (Keycloak, SimpleSAMLphp, etc.)
5. Ensure `--help` still works
6. Submit PR with clear description

### Code Style

- Type hints on all function signatures
- Docstrings on classes and public methods
- Max line length: 100 characters (soft limit)
- Use `dataclass` for data containers
- Constants in UPPER_SNAKE_CASE

### Testing Locally

```bash
# Run Keycloak for SAML/OIDC testing
docker run -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    quay.io/keycloak/keycloak:latest start-dev

# Run SimpleSAMLphp for SAML testing
docker run -p 8443:8443 \
    -e SIMPLESAMLPHP_SP_ENTITY_ID=https://localhost \
    kristophjunge/test-saml-idp

# Run CAS for CAS testing
docker run -p 8443:8443 apereo/cas:latest
```

### Areas Needing Help

- [ ] Selenium/Playwright browser automation for interactive SSO flows
- [ ] WS-Federation protocol support
- [ ] SAML 1.1 attack variants
- [ ] PKCE downgrade attacks for OIDC
- [ ] Comprehensive unit test suite
- [ ] Docker container build
- [ ] GitHub Actions CI pipeline
