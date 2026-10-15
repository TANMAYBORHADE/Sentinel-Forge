import pytest

from sentinelforge.models import Confidence, Evidence, Finding, Severity, Status


def _evidence():
    return Evidence("GET", "http://localhost/", {"Authorization": "Bearer abc.def.ghi",
                    "Cookie": "sid=SECRET1; theme=dark"}, None, 200,
                    {"Set-Cookie": "sid=SECRET2; Path=/; HttpOnly\nlang=en; Secure"},
                    '{"user":"a","password":"hunter2","token":"eyJhbGciOi"}', 12.3)


def _finding(**kw):
    base = dict(id="HDR-001", title="CSP missing", category="headers", severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY, status=Status.FAIL, fix="Add a CSP header",
                endpoint="GET /")
    base.update(kw)
    return Finding(**base)


def test_confirmed_requires_evidence():
    with pytest.raises(ValueError):
        _finding(confidence=Confidence.CONFIRMED)
    assert _finding(confidence=Confidence.CONFIRMED, evidence=[_evidence()])


def test_fail_and_warn_require_a_fix():
    with pytest.raises(ValueError):
        _finding(fix="")
    with pytest.raises(ValueError):
        _finding(status=Status.WARN, fix="  ")
    assert _finding(status=Status.PASS, fix="")


def test_fingerprint_stable_and_discriminating():
    a = _finding(endpoint="GET http://localhost:3000/api/users/?page=1")
    b = _finding(endpoint="GET /api/users")
    assert a.fingerprint == b.fingerprint                      # query/host/trailing slash ignored
    assert a.fingerprint != _finding(endpoint="GET /api/other").fingerprint
    assert a.fingerprint != _finding(id="HDR-002", endpoint="GET /api/users").fingerprint
    f1 = _finding(endpoint=None, file="app/db.py", line=10)
    assert f1.fingerprint != _finding(endpoint=None, file="app/db.py", line=11).fingerprint


def test_evidence_is_redacted_but_keeps_cookie_flags():
    d = _evidence().to_dict(redact=True)
    blob = str(d)
    for secret in ("SECRET1", "SECRET2", "hunter2", "eyJhbGciOi", "abc.def.ghi"):
        assert secret not in blob
    assert "HttpOnly" in d["response_headers"]["Set-Cookie"]
    assert "Secure" in d["response_headers"]["Set-Cookie"]
    assert "theme=****" in d["request_headers"]["Cookie"]
    assert "hunter2" in str(_evidence().to_dict(redact=False))
