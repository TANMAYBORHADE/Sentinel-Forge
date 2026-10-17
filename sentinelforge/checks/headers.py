"""Security headers and CORS (config proof: confirmed straight from the response headers)."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import register
from ..models import Confidence, Finding, Severity, Status

HOME = "GET /"
EVIL_ORIGIN = "https://sf-origin-test.invalid"   # only ever sent as a header value, never requested


def _hdr(result, name: str):
    low = name.lower()
    for key, value in result.evidence.response_headers.items():
        if key.lower() == low:
            return value
    return None


def _finding(cid, title, ok, evidence, fix, bad_desc, ok_desc="", severity=Severity.LOW,
             category="headers"):
    if ok:
        return Finding(id=cid, title=title, category=category, severity=Severity.INFO,
                       confidence=Confidence.CONFIRMED, status=Status.PASS,
                       description=ok_desc, evidence=[evidence], endpoint=HOME)
    return Finding(id=cid, title=title, category=category, severity=severity,
                   confidence=Confidence.CONFIRMED, status=Status.WARN, fix=fix,
                   description=bad_desc, evidence=[evidence], endpoint=HOME)


def _csp_weakness(csp: str):
    directives = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = [b.lower() for b in bits[1:]]
    scripts = directives.get("script-src", directives.get("default-src", []))
    protected = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'"
                    for t in scripts)
    if "'unsafe-eval'" in scripts:
        return "script sources allow 'unsafe-eval'"
    if "'unsafe-inline'" in scripts and not protected:
        return "script sources allow 'unsafe-inline' without a nonce or hash"
    if "*" in scripts:
        return "script sources allow any origin (*)"
    return None


@register("HDR-001", "Content-Security-Policy", group="headers")
def csp(ctx):
    home = ctx.home()
    value = _hdr(home, "Content-Security-Policy")
    fix = ("Send a Content-Security-Policy header, starting strict: "
           "default-src 'self'; object-src 'none'; frame-ancestors 'none'.")
    if value is None:
        return [_finding("HDR-001", "Content-Security-Policy", False, home.evidence, fix,
                         "No CSP header. A CSP limits the damage of an XSS bug; it is a hardening layer, "
                         "not a bug by itself.")]
    weakness = _csp_weakness(value)
    if weakness:
        return [_finding("HDR-001", "Content-Security-Policy", False, home.evidence,
                         "Remove 'unsafe-inline' / 'unsafe-eval' / '*' from script sources; use nonces or hashes.",
                         f"A CSP is present but weak: {weakness}.")]
    return [_finding("HDR-001", "Content-Security-Policy", True, home.evidence, "", "", "CSP present.")]


@register("HDR-002", "Clickjacking protection (X-Frame-Options / frame-ancestors)", group="headers")
def clickjacking(ctx):
    home = ctx.home()
    xfo = (_hdr(home, "X-Frame-Options") or "").strip().upper()
    csp_value = (_hdr(home, "Content-Security-Policy") or "").lower()
    ok = xfo in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp_value
    return [_finding("HDR-002", "Clickjacking protection (X-Frame-Options / frame-ancestors)", ok,
                     home.evidence, "Send X-Frame-Options: DENY (or CSP frame-ancestors 'none'/'self').",
                     "The page can be embedded in another site's iframe, which enables clickjacking.",
                     "Framing is restricted.")]


@register("HDR-003", "X-Content-Type-Options", group="headers")
def nosniff(ctx):
    home = ctx.home()
    ok = (_hdr(home, "X-Content-Type-Options") or "").strip().lower() == "nosniff"
    return [_finding("HDR-003", "X-Content-Type-Options", ok, home.evidence,
                     "Send X-Content-Type-Options: nosniff.",
                     "Browsers may MIME-sniff responses, which can turn uploaded or reflected content into script.",
                     "nosniff set.")]


@register("HDR-004", "Strict-Transport-Security", group="headers")
def hsts(ctx):
    home = ctx.home()
    if urlsplit(ctx.url).scheme != "https":
        return [Finding(id="HDR-004", title="Strict-Transport-Security", category="headers",
                        severity=Severity.INFO, confidence=Confidence.INCONCLUSIVE, status=Status.SKIPPED,
                        description="HSTS only applies over HTTPS; the target is plain http. "
                                    "Re-run against an HTTPS test environment.")]
    value = _hdr(home, "Strict-Transport-Security")
    match = re.search(r"max-age\s*=\s*(\d+)", value or "", re.I)
    ok = bool(match) and int(match.group(1)) >= 15552000   # 180 days
    return [_finding("HDR-004", "Strict-Transport-Security", ok, home.evidence,
                     "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                     "HSTS is missing or its max-age is under 180 days.", "HSTS present with a long max-age.")]


@register("HDR-005", "Referrer-Policy", group="headers")
def referrer(ctx):
    home = ctx.home()
    value = (_hdr(home, "Referrer-Policy") or "").strip().lower()
    ok = bool(value) and value not in ("unsafe-url", "no-referrer-when-downgrade")
    return [_finding("HDR-005", "Referrer-Policy", ok, home.evidence,
                     "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
                     "Missing or leaky Referrer-Policy: full URLs (which may hold tokens or IDs) can be sent to other sites.",
                     "Referrer-Policy set.")]


@register("HDR-006", "Server / framework banner", group="headers")
def banner(ctx):
    home = ctx.home()
    server = _hdr(home, "Server") or ""
    powered = _hdr(home, "X-Powered-By")
    leaks = []
    if re.search(r"\d+\.\d+", server):
        leaks.append(f"Server: {server}")
    if powered:
        leaks.append(f"X-Powered-By: {powered}")
    return [_finding("HDR-006", "Server / framework banner", not leaks, home.evidence,
                     "Remove X-Powered-By and strip version numbers from the Server header.",
                     "Headers reveal software or versions: " + "; ".join(leaks) + ". "
                     "This helps attackers pick exploits; low impact on its own.",
                     "No version banner leaked.")]


@register("CORS-001", "CORS policy", group="headers")
def cors(ctx):
    result = ctx.http.get("/", headers={"Origin": EVIL_ORIGIN}, note="CORS probe with a foreign Origin header")
    allow = (_hdr(result, "Access-Control-Allow-Origin") or "").strip()
    creds = (_hdr(result, "Access-Control-Allow-Credentials") or "").strip().lower() == "true"
    ev = result.evidence
    if allow == EVIL_ORIGIN and creds:
        return [Finding(id="CORS-001", title="CORS policy", category="headers", severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED, status=Status.FAIL, evidence=[ev], endpoint=HOME,
                        fix="Never reflect the Origin header. Allow a fixed list of trusted origins only.",
                        description="Any origin is reflected AND credentials are allowed, so another site can read "
                                    "responses as the logged-in user. Rated Medium because this was tested on '/'; "
                                    "it is High if authenticated endpoints behave the same.")]
    if allow == EVIL_ORIGIN:
        return [_finding("CORS-001", "CORS policy", False, ev,
                         "Allow a fixed list of trusted origins instead of reflecting Origin.",
                         "Any origin is reflected (credentials not allowed, so public data only).")]
    if allow == "*":
        bad = "Wildcard CORS" + (" with credentials flag" if creds else "") + ": every site can read public responses."
        return [_finding("CORS-001", "CORS policy", False, ev,
                         "Replace * with the specific origins that need access.", bad)]
    return [_finding("CORS-001", "CORS policy", True, ev, "", "", "Foreign origin is not allowed.")]