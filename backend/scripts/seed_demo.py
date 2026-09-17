"""Fill a local Warden database with demo data: ``python -m scripts.seed_demo``.

Nothing here is invented. Every verdict comes from running the benchmark corpus
(``benchmark/corpus.py``: inert, hand-written samples) through the real pipeline and the active
policy, a release diff compares two of those real results, and the demo project is a scan of this
repository's own backend manifests and Dockerfile. Demo packages are named ``demo-<sample id>`` so
they cannot be mistaken for PyPI packages (the typosquat sample keeps its look-alike name, which is
what it demonstrates), and the command refuses to run with ``ENV=production``.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

from app.analysis.diff import diff_results
from app.core.config import settings
from app.db.base import Base
from app.db.models import DEFAULT_ENVIRONMENT, Project, ReleaseDiff, User
from app.db.seed import seed
from app.db.session import SessionLocal, engine
from benchmark.corpus import SAMPLES, Sample

REPO = Path(__file__).resolve().parents[2]
DEMO_FILES = ("backend/requirements.txt", "backend/requirements-dev.txt", "backend/Dockerfile", "docker-compose.yml")


def _demo_sample(sample: Sample) -> Sample:
    name = sample.name if sample.name != "bench-pkg" else f"demo-{sample.id}"
    return Sample(sample.id, sample.label, sample.technique, sample.files, name=name, evasive=sample.evasive,
                  metadata=sample.metadata)


def main() -> int:
    if settings.ENV == "production":
        print("refusing to seed demo data into a production deployment", file=sys.stderr)
        return 2
    from app.analysis.analyzers.base import ScanOptions
    from app.analysis.orchestrator import Orchestrator
    from app.api.routers import scans as scans_router
    from app.api.routers.projects import scan_project
    from app.db.base import utcnow
    from app.policy.exceptions import load_active_exceptions
    from app.schemas.project import ProjectScanRequest
    from benchmark.run import _MemoryFetcher, _NoCache

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed(db)
        admin = db.query(User).filter(User.email == settings.FIRST_ADMIN_EMAIL.lower()).one()
        results = {}
        for sample in map(_demo_sample, SAMPLES):
            options = ScanOptions(offline=True, intel=False, provenance=False, analyze_wheels=False,
                                  environment=DEFAULT_ENVIRONMENT)
            result = Orchestrator(_MemoryFetcher(sample), cache_backend=_NoCache()).analyze(
                "pypi", sample.name, "1.0.0", options)
            policy = scans_router._active_policy(db, DEFAULT_ENVIRONMENT)
            now = utcnow()
            grants = load_active_exceptions(db, result.name, result.version, DEFAULT_ENVIRONMENT,
                                            getattr(policy, "id", None), now)
            decision = scans_router._evaluate_policy(result, policy, grants, DEFAULT_ENVIRONMENT, now)
            scans_router._persist(db, result, decision, admin, policy, DEFAULT_ENVIRONMENT)
            results[sample.id] = result
            print(f"scanned {sample.name}: {decision.decision.value} (risk {result.risk_score})")

        # A real comparison of two real results, presented as two releases of one demo package.
        old, new = results["ben-http-client"], results["mal-env-exfil"]
        old_view = {**old.__dict__, "name": "demo-http-client", "version": "1.0.0"}
        new_view = {**new.__dict__, "name": "demo-http-client", "version": "1.1.0"}
        diff = diff_results(old_view, new_view)
        if not db.query(ReleaseDiff).filter(ReleaseDiff.package == "demo-http-client").first():
            db.add(ReleaseDiff(id=uuid.uuid4(), ecosystem="pypi", package="demo-http-client", old_version="1.0.0",
                               new_version="1.1.0", analyzer_version=new.analyzer_version,
                               drift_detected=diff["verdict"] == "escalated",
                               drift_score=max(0, min(100, diff["risk"]["delta"])),
                               summary={k: v for k, v in diff.items() if k != "findings"},
                               findings=diff["findings"]["added"], created_by=admin.id))
            db.commit()
            print(f"stored release diff demo-http-client 1.0.0 -> 1.1.0: {diff['verdict']}")

        project = db.query(Project).filter(Project.name == "warden-demo").first()
        if project is None:
            project = Project(id=uuid.uuid4(), name="warden-demo",
                              description="Warden's own backend manifests and container files", created_by=admin.id)
            db.add(project)
            db.commit()
        files = {path: (REPO / path).read_text(encoding="utf-8") for path in DEMO_FILES if (REPO / path).is_file()}
        scan = scan_project(project.id, ProjectScanRequest(files=files), db=db, user=admin)
        print(f"scanned project warden-demo: {scan.decision} ({scan.component_count} components)")
    print(f"done - sign in as {settings.FIRST_ADMIN_EMAIL}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
