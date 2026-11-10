"""Exposed files and verbose errors. Signature-based, so SPA catch-all pages don't cause false alarms."""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import replace

from . import register
from ..models import Confidence, Finding, Severity, Status


def _text(resp) -> str:
    return resp.content[:65536].decode("utf-8", "replace")


def _is_env(resp):
    t = _text(resp)
    return not t.lstrip().startswith("<") and re.search(r"(?m)^[A-Za-z_][A-Za-z0-9_]*=.+$", t) is not None


def _is_package_json(resp):
    try:
        data = json.loads(_text(resp))
    except ValueError:
        return False
    return isinstance(data, dict) and any(k in data for k in ("dependencies", "devDependencies", "scripts", "name"))


# (path, label, severity, matcher)
EXPOSED = [
    ("/.env", "environment file", Severity.HIGH, _is_env),
    ("/.git/HEAD", "Git repository", Severity.HIGH, lambda r: _text(r).startswith("ref:")),
    ("/.git/config", "Git config", Severity.HIGH, lambda r: "[core]" in _text(r)),
    ("/package.json", "package.json", Severity.LOW, _is_package_json),
    ("/backup.zip", "backup archive", Severity.HIGH, lambda r: r.content[:2] == b"PK"),
    ("/.DS_Store", ".DS_Store file", Severity.LOW, lambda r: r.content[:8] == b"\x00\x00\x00\x01Bud1"),
    ("/phpinfo.php", "phpinfo page", Severity.MEDIUM, lambda r: "phpinfo()" in _text(r) or "PHP Version" in _text(r)),
    ("/server-status", "Apache server-status", Severity.MEDIUM, lambda r: "Apache Server Status" in _text(r)),
]

FIX = {
    "environment file": "Remove it from the web root, deny dotfiles in the server config, and rotate every secret it held.",
    "Git repository": "Never deploy the .git folder; deny dotfiles in the server config.",
    "Git config": "Never deploy the .git folder; deny dotfiles in the server config.",
    "package.json": "Serve only built assets, not the project root.",
    "backup archive": "Delete it from the web root and store backups elsewhere; assume its contents are exposed.",
    ".DS_Store file": "Delete it and add it to .gitignore; it lists file names in the folder.",
    "phpinfo page": "Remove the phpinfo page from the server.",
    "Apache server-status": "Restrict /server-status to localhost.",
}


@register("EXP-001", "Sensitive files exposed over HTTP", group="exposure")
def exposed_paths(ctx):
    findings, probed = [], []
    for path, label, severity, matches in EXPOSED:
        result = ctx.http.get(path, note=f"probe for exposed {label}")
        probed.append(result)
        resp = result.response
        if resp.status_code == 200 and matches(resp):
            # Body withheld on purpose: it may contain real secrets (Rule 4).
            ev = replace(result.evidence, response_body=(
                f"[body withheld: {len(resp.content)} bytes, matched the {label} signature]"))
            findings.append(Finding(
                id="EXP-001", title=f"Exposed {label}: {path}", category="exposure", severity=severity,
                confidence=Confidence.CONFIRMED, status=Status.FAIL, evidence=[ev], endpoint=f"GET {path}",
                fix=FIX[label],
                description=f"{path} is served to anyone and its content matches a {label}."))
    if not findings:
        findings.append(Finding(
            id="EXP-001", title="Sensitive files exposed over HTTP", category="exposure", severity=Severity.INFO,
            confidence=Confidence.CONFIRMED, status=Status.PASS, evidence=[probed[-1].evidence],
            description=f"{len(EXPOSED)} common paths probed; none served a matching file."))
    return findings


# (label, regex, severity)
LEAKS = [
    ("Werkzeug interactive debugger", r"Werkzeug Debugger|werkzeug\.debug|console locked", Severity.CRITICAL),
    ("SQL error message", r"SQLSTATE\[|error in your SQL syntax|SQLITE_ERROR|SequelizeDatabaseError|psycopg2\.errors",
     Severity.MEDIUM),
    ("Python traceback", r"Traceback \(most recent call last\)", Severity.LOW),
    ("Node.js stack trace", r"\n\s+at .+\(.+\.(?:js|ts|mjs):\d+:\d+\)", Severity.LOW),
    ("Java stack trace", r"\bat [\w.$]+\(\w+\.java:\d+\)|java\.lang\.\w+(?:Exception|Error)", Severity.LOW),
    ("PHP error output", r"Fatal error:|Warning: .+ on line \d+|Stack trace:", Severity.LOW),
]


@register("ERR-001", "Stack traces and verbose errors", group="exposure")
def verbose_errors(ctx):
    token = secrets.token_hex(4)
    probes = [
        ("GET /<unknown-path>", lambda: ctx.http.get(f"/sf-probe-{token}", note="request for a missing page")),
        ("GET /?id=<quote>", lambda: ctx.http.get("/", params={"id": "'"}, note="stray quote in a parameter")),
        ("POST / (malformed JSON)", lambda: ctx.http.post(
            "/", data='{"a":', headers={"Content-Type": "application/json"}, note="malformed JSON body")),
    ]
    findings, seen, last = [], set(), None
    for label, send in probes:
        result = send()
        last = result
        body = result.response.content[:65536].decode("utf-8", "replace")
        for name, pattern, severity in LEAKS:
            if name in seen or not re.search(pattern, body):
                continue
            seen.add(name)
            ev = replace(result.evidence, response_body=result.evidence.response_body[:1500])
            findings.append(Finding(
                id="ERR-001", title=f"Error response leaks: {name}", category="exposure", severity=severity,
                confidence=Confidence.CONFIRMED, status=Status.FAIL, evidence=[ev], endpoint=label,
                fix="Turn debug mode off in production and return a generic error page; log details server-side only.",
                description=f"{label} returned a {name}, which reveals internals such as file paths or queries."))
    if not findings:
        findings.append(Finding(
            id="ERR-001", title="Stack traces and verbose errors", category="exposure", severity=Severity.INFO,
            confidence=Confidence.CONFIRMED, status=Status.PASS, evidence=[last.evidence],
            description=f"{len(probes)} malformed requests sent; no stack trace or debug output seen."))
    return findings