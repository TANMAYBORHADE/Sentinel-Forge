"""Cookie flags: Secure, HttpOnly, SameSite (config proof from Set-Cookie)."""
from __future__ import annotations

from urllib.parse import urlsplit

from . import register
from ..models import Confidence, Finding, Severity, Status

SESSION_HINTS = ("sess", "sid", "token", "auth", "jwt", "login")
_RANK = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def parse_set_cookie(header: str) -> list:
    """Return [{'name', 'attrs': {lowercase attr: value}}] for a (newline-joined) Set-Cookie header."""
    cookies = []
    for line in (header or "").split("\n"):
        parts = [p.strip() for p in line.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            continue
        attrs = {}
        for part in parts[1:]:
            key, _, value = part.partition("=")
            attrs[key.strip().lower()] = value.strip()
        cookies.append({"name": parts[0].split("=", 1)[0].strip(), "attrs": attrs})
    return cookies


@register("COOK-001", "Cookie flags (Secure / HttpOnly / SameSite)", group="cookies")
def cookie_flags(ctx):
    home = ctx.home()
    raw = next((v for k, v in home.evidence.response_headers.items() if k.lower() == "set-cookie"), "")
    cookies = parse_set_cookie(raw)
    if not cookies:
        return [Finding(id="COOK-001", title="Cookie flags (Secure / HttpOnly / SameSite)", category="cookies",
                        severity=Severity.INFO, confidence=Confidence.INCONCLUSIVE, status=Status.SKIPPED,
                        description="No cookies were set on '/'. This runs again on authenticated requests in Phase 4.")]
    https = urlsplit(ctx.url).scheme == "https"
    findings = []
    for cookie in cookies:
        name, attrs = cookie["name"], cookie["attrs"]
        session_like = any(h in name.lower() for h in SESSION_HINTS)
        problems = []
        if "httponly" not in attrs:
            problems.append(("HttpOnly missing: JavaScript (and any XSS) can read this cookie.",
                             "Set the HttpOnly flag.", Severity.MEDIUM if session_like else Severity.LOW))
        if https and "secure" not in attrs:
            problems.append(("Secure missing: the cookie can be sent over plain HTTP.",
                             "Set the Secure flag.", Severity.MEDIUM if session_like else Severity.LOW))
        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            problems.append(("SameSite missing: relies on browser defaults for CSRF protection.",
                             "Set SameSite=Lax (or Strict).", Severity.LOW))
        elif samesite == "none" and "secure" not in attrs:
            problems.append(("SameSite=None without Secure is rejected or unsafe.",
                             "Add Secure, or use SameSite=Lax.", Severity.LOW))
        endpoint = f"cookie:{name}"
        if not problems:
            findings.append(Finding(id="COOK-001", title=f"Cookie flags: {name}", category="cookies",
                                    severity=Severity.INFO, confidence=Confidence.CONFIRMED, status=Status.PASS,
                                    description="Flags look correct.", evidence=[home.evidence], endpoint=endpoint))
            continue
        findings.append(Finding(
            id="COOK-001", title=f"Cookie flags: {name}", category="cookies",
            severity=max((p[2] for p in problems), key=_RANK.index),
            confidence=Confidence.CONFIRMED, status=Status.WARN,
            description=" ".join(p[0] for p in problems), fix=" ".join(p[1] for p in problems),
            evidence=[home.evidence], endpoint=endpoint))
    return findings