"""The demo seeder stores real pipeline results and refuses production."""

from __future__ import annotations

from sqlalchemy import select

from app.core.config import settings
from app.db.models import Project, ReleaseDiff, Scan
from app.db.session import SessionLocal
from scripts import seed_demo


def test_seeder_stores_real_results(capsys):
    assert seed_demo.main() == 0
    out = capsys.readouterr().out
    assert "scanned demo-mal-pth-hook: block" in out
    with SessionLocal() as db:
        names = set(db.scalars(select(Scan.package_name)))
        assert {"demo-mal-reverse-shell", "demo-ben-plain-library", "reqeusts"} <= names
        assert db.scalar(select(ReleaseDiff).where(ReleaseDiff.package == "demo-http-client")).drift_detected
        assert db.scalar(select(Project).where(Project.name == "warden-demo"))
    assert seed_demo.main() == 0  # idempotent: upserts and skips existing demo rows


def test_seeder_refuses_production(monkeypatch, capsys):
    monkeypatch.setattr(settings, "ENV", "production")
    assert seed_demo.main() == 2
    assert "refusing" in capsys.readouterr().err
