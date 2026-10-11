# SentinelForge
**Find it. Prove it. Report it.**  A personal security scanner for apps you own.

## Quick start
```bash
pip install -r requirements.txt
docker run -p 3000:3000 bkimminich/juice-shop     # a deliberately vulnerable test target
python sf.py scan --url http://localhost:3000
python -m pytest
```
Exit codes: `0` clean · `1` at least one FAIL · `2` refused / bad usage.

## Layout
| Path | Purpose |
|------|---------|
| `sf.py` | entry point |
| `sentinelforge/cli.py` | argument parsing and scan flow |
| `sentinelforge/models.py` | Finding, Evidence, Severity / Status / Confidence, fingerprint, redaction |
| `sentinelforge/lib/allowlist.py` | refuses non-local targets |
| `sentinelforge/lib/http.py` | request wrapper: allowlist on every hop, records evidence |
| `sentinelforge/lib/runner.py` | runs checks; skips and crashes become findings |
| `sentinelforge/checks/` | **add new checks here** (see docstring in `__init__.py`) |
| `sentinelforge/db.py` | SQLite `scans` + `findings` |
| `sentinelforge/reports/console.py` | ✅ ❌ ⚠️ report |
| `docs/severity_rubric.md` | one-line rule per severity level |

## Rules enforced in code (not just in the roadmap)
- Non-local hosts are refused before anything is created or sent, and re-checked on every request and redirect hop.
- `CONFIRMED` findings without evidence raise an error.
- `FAIL` / `WARN` findings without a fix raise an error.
- Evidence is redacted (auth headers, cookie values, password/token JSON values) before it is stored. Cookie flags stay visible.
