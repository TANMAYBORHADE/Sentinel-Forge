import pytest

from sentinelforge import checks
from sentinelforge.cli import main
from sentinelforge.db import Database
from sentinelforge.models import Confidence, Finding, Severity, Status


@pytest.fixture
def clean_registry():
    saved = dict(checks.REGISTRY)
    checks.REGISTRY.clear()
    yield
    checks.REGISTRY.clear()
    checks.REGISTRY.update(saved)


def test_refuses_non_local_target(tmp_path, capsys):
    db = tmp_path / "t.db"
    assert main(["scan", "--url", "https://example.com", "--db", str(db)]) == 2
    assert "Refusing" in capsys.readouterr().err
    assert not db.exists()                      # nothing was even created


def test_empty_scan_is_saved(tmp_path, capsys, clean_registry):
    db_path = tmp_path / "t.db"
    assert main(["scan", "--url", "http://localhost:5999", "--db", str(db_path)]) == 0
    db = Database(str(db_path))
    assert db.count_scans() == 1
    assert db.get_scan(1)["status"] == "COMPLETED"
    assert db.get_findings(1) == []
    db.close()


def test_findings_skips_and_crashes_are_recorded(tmp_path, capsys, clean_registry):
    @checks.register("T-001", "dummy fail", group="demo", requires="source")
    def failing(ctx):
        return [Finding(id="T-001", title="dummy fail", category="demo", severity=Severity.HIGH,
                        confidence=Confidence.LIKELY, status=Status.FAIL, fix="fix it",
                        file="app.py", line=3)]

    @checks.register("T-002", "dummy crash", group="demo", requires="source")
    def crashing(ctx):
        raise RuntimeError("boom")

    @checks.register("T-003", "needs live", group="demo", requires="live")
    def live(ctx):
        return []

    src = tmp_path / "app"
    src.mkdir()
    db_path = tmp_path / "t.db"
    code = main(["scan", "--src", str(src), "--db", str(db_path)])
    assert code == 1                              # a FAIL exists
    out = capsys.readouterr().out
    assert "❌" in out and "💥" in out and "⏭️" in out and "fix: fix it" in out

    db = Database(str(db_path))
    statuses = {r["check_id"]: r["status"] for r in db.get_findings(1)}
    assert statuses == {"T-001": "FAIL", "T-002": "ERROR", "T-003": "SKIPPED"}
    db.close()


def test_config_url_is_fallback_only(tmp_path, capsys, monkeypatch, clean_registry):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("target:\n  base_url: http://localhost:3000\n")
    (tmp_path / "app").mkdir()
    main(["scan", "--src", "app", "--db", "a.db"])
    assert "Target : (none, source only)" in capsys.readouterr().out
    main(["scan", "--db", "b.db"])
    assert "Target : http://localhost:3000" in capsys.readouterr().out
