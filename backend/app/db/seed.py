"""First-run bootstrap: create the initial admin and a default production policy.

Idempotent — safe to run on every startup. In production the schema itself is created by
Alembic migrations; this only seeds rows.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.signals import Capability
from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import hash_password
from app.db.models import DEFAULT_ENVIRONMENT, Policy, Role, User

log = get_logger("warden.seed")


def seed(db: Session) -> None:
    _seed_admin(db)
    _seed_default_policy(db)
    db.commit()


def _seed_admin(db: Session) -> None:
    email = settings.FIRST_ADMIN_EMAIL.lower()
    if db.scalar(select(User).where(User.email == email)):
        return
    db.add(User(
        email=email,
        password_hash=hash_password(settings.FIRST_ADMIN_PASSWORD),
        role=Role.admin,
    ))
    log.info("bootstrap_admin_created", email=email)


def _seed_default_policy(db: Session) -> None:
    active = select(Policy).where(Policy.is_active.is_(True), Policy.environment == DEFAULT_ENVIRONMENT)
    if db.scalar(active):
        return
    db.add(Policy(
        name="Default Balanced Policy",
        is_active=True,
        environment=DEFAULT_ENVIRONMENT,
        warn_threshold=40,
        block_threshold=70,
        min_package_age_days=0,
        blocked_capabilities=[Capability.INSTALL_EXEC, Capability.IOC],
        allowlist=[],
        denylist=[],
        updated_at=datetime.now(timezone.utc),
    ))
    log.info("bootstrap_policy_created", environment=DEFAULT_ENVIRONMENT)
