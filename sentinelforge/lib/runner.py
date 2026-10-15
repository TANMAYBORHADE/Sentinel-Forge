"""Runs registered checks, turning skips and crashes into findings instead of silence."""
from __future__ import annotations

from .. import checks as check_registry
from ..models import Confidence, Finding, Severity, Status
from .allowlist import TargetNotAllowed
from .context import ScanContext


def _note(chk, status: Status, reason: str) -> Finding:
    return Finding(
        id=chk.id, title=chk.title, category=chk.group, severity=Severity.INFO,
        confidence=Confidence.INCONCLUSIVE, status=status, description=reason)


def run_checks(ctx: ScanContext, config: dict) -> list:
    run = set(config["checks"]["run"])
    skip = set(config["checks"]["skip"])
    findings: list = []

    for chk in check_registry.all_checks():
        if chk.group in skip or chk.id in skip:
            findings.append(_note(chk, Status.SKIPPED, "disabled in config.yaml"))
            continue
        if "all" not in run and chk.group not in run and chk.id not in run:
            findings.append(_note(chk, Status.SKIPPED, "not selected in config.yaml"))
            continue
        if chk.requires in ("live", "both") and ctx.http is None:
            findings.append(_note(chk, Status.SKIPPED, "needs a running app (--url)"))
            continue
        if chk.requires in ("source", "both") and ctx.src is None:
            findings.append(_note(chk, Status.SKIPPED, "needs source code (--src)"))
            continue

        try:
            result = chk.fn(ctx)
        except TargetNotAllowed:
            raise  # a safety violation must stop the whole scan, never be swallowed
        except Exception as exc:  # a crashing check becomes an ERROR finding
            findings.append(_note(chk, Status.ERROR, f"{type(exc).__name__}: {exc}"))
            continue

        if result is None:
            result = []
        elif isinstance(result, Finding):
            result = [result]
        findings.extend(result)
    return findings
