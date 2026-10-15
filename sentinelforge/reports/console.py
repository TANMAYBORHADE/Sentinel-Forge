"""Console report: ✅ ❌ ⚠️ and a summary line. Critical issues always come first."""
from __future__ import annotations

from ..models import Severity, Status, summarise

ICONS = {Status.PASS: "✅", Status.FAIL: "❌", Status.WARN: "⚠️ ", Status.SKIPPED: "⏭️ ", Status.ERROR: "💥"}
_STATUS_ORDER = [Status.FAIL, Status.WARN, Status.ERROR, Status.SKIPPED, Status.PASS]
_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render(findings: list, scan_id: int) -> str:
    lines = []
    ordered = sorted(findings, key=lambda f: (_SEV_ORDER.index(f.severity), _STATUS_ORDER.index(f.status)))
    ordered = sorted(ordered, key=lambda f: f.status not in (Status.FAIL, Status.WARN))

    for f in ordered:
        where = f"  ({f.location})" if f.location else ""
        lines.append(f"{ICONS[f.status]} [{f.severity.value}/{f.confidence.value}] {f.id}  {f.title}{where}")
        if f.status in (Status.SKIPPED, Status.ERROR) and f.description:
            lines.append(f"      {f.description}")
        if f.status in (Status.FAIL, Status.WARN):
            lines.append(f"      fix: {f.fix}")

    if not findings:
        lines.append("No checks have run yet (none are registered). The scan was saved to the database.")

    s = summarise(findings)
    lines.append("")
    lines.append(
        f"Scan #{scan_id}: {s['PASS']} ✅ passed · {s['FAIL']} ❌ failed · {s['WARN']} ⚠️  warnings · "
        f"{s['SKIPPED']} skipped · {s['ERROR']} errors")
    return "\n".join(lines)
