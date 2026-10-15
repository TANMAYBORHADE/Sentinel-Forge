"""Core data model: severity, status, confidence, evidence and findings."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlsplit

MAX_BODY_CHARS = 8192
MASK = "****"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"


# --------------------------------------------------------------------------- #
# Redaction. Real secrets must never reach a report or the database (Rule 4).
# --------------------------------------------------------------------------- #
_SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "x-auth-token"}
_SECRET_JSON = re.compile(
    r'("(?:password|passwd|pwd|token|access_token|refresh_token|id_token|secret|'
    r'api_key|apikey|authorization)"\s*:\s*)"(?:[^"\\]|\\.)*"',
    re.IGNORECASE,
)


def _mask_pair(pair: str) -> str:
    if "=" not in pair:
        return pair
    name, _, _ = pair.partition("=")
    return f"{name.strip()}={MASK}"


def _mask_cookie(header: str, value: str) -> str:
    if header == "cookie":  # request: "a=1; b=2"
        return "; ".join(_mask_pair(p.strip()) for p in value.split(";") if p.strip())
    # set-cookie: one cookie per line; keep attributes (Secure, HttpOnly...) visible
    lines = []
    for line in value.split("\n"):
        first, sep, rest = line.partition(";")
        lines.append(_mask_pair(first.strip()) + (sep + rest if sep else ""))
    return "\n".join(lines)


def redact_headers(headers: dict) -> dict:
    out = {}
    for key, value in headers.items():
        low = key.lower()
        if low in _SENSITIVE_HEADERS:
            out[key] = MASK
        elif low in ("cookie", "set-cookie"):
            out[key] = _mask_cookie(low, str(value))
        else:
            out[key] = value
    return out


def redact_body(body: Optional[str]) -> Optional[str]:
    """Best-effort masking of secret-looking JSON values."""
    if body is None:
        return None
    return _SECRET_JSON.sub(rf'\1"{MASK}"', body)


# --------------------------------------------------------------------------- #
@dataclass
class Evidence:
    """One recorded request/response pair."""

    method: str
    url: str
    request_headers: dict
    request_body: Optional[str]
    status_code: int
    response_headers: dict
    response_body: str
    elapsed_ms: float
    note: str = ""

    def to_dict(self, redact: bool = True) -> dict:
        req_h, req_b = self.request_headers, self.request_body
        res_h, res_b = self.response_headers, self.response_body
        if redact:
            req_h, res_h = redact_headers(req_h), redact_headers(res_h)
            req_b, res_b = redact_body(req_b), redact_body(res_b)
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": req_h,
            "request_body": req_b,
            "status_code": self.status_code,
            "response_headers": res_h,
            "response_body": res_b,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "note": self.note,
        }


def _normalise_endpoint(endpoint: Optional[str]) -> str:
    if not endpoint:
        return ""
    method = ""
    text = endpoint.strip()
    if " " in text:  # "POST /api/login"
        method, _, text = text.partition(" ")
        method = method.upper() + " "
    if "://" in text:
        text = urlsplit(text).path or "/"
    text = text.split("?")[0].split("#")[0]
    if len(text) > 1:
        text = text.rstrip("/")
    return method + text


@dataclass
class Finding:
    id: str                      # check id, e.g. "HDR-001"
    title: str
    category: str                # check group, e.g. "headers"
    severity: Severity
    confidence: Confidence
    status: Status
    fix: str = ""
    description: str = ""
    evidence: list = field(default_factory=list)
    endpoint: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None

    def __post_init__(self):
        self.severity = Severity(self.severity)
        self.confidence = Confidence(self.confidence)
        self.status = Status(self.status)
        # Rule 2: never CONFIRMED without saved evidence
        if self.confidence is Confidence.CONFIRMED and not self.evidence:
            raise ValueError(f"{self.id}: CONFIRMED findings must carry evidence")
        # Rule 10: every finding must say what to fix
        if self.status in (Status.FAIL, Status.WARN) and not self.fix.strip():
            raise ValueError(f"{self.id}: FAIL/WARN findings must say what to fix")

    @property
    def fingerprint(self) -> str:
        """Stable across scans: check id + endpoint + location (no query strings)."""
        raw = "|".join([
            self.id,
            _normalise_endpoint(self.endpoint),
            (self.file or "").replace("\\", "/"),
            str(self.line or ""),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def location(self) -> str:
        if self.file:
            return f"{self.file}:{self.line}" if self.line else self.file
        return self.endpoint or ""


def summarise(findings: list) -> dict:
    counts = {s.value: 0 for s in Status}
    for f in findings:
        counts[f.status.value] += 1
    counts["total"] = len(findings)
    return counts
