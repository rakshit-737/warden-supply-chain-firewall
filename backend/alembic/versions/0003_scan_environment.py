"""Per-environment scan verdicts

Policy decisions depend on the environment a scan was evaluated for, but ``scans`` allowed one
row per (ecosystem, package, version, analyzer version): a re-scan under a laxer environment
overwrote the stored production verdict. This revision makes the environment part of the
identity.

Upgrade: ``scans.environment`` rows that are NULL (v1 rows) are backfilled with ``production`` —
the policy v1 always applied — the column becomes NOT NULL with server default ``production``,
and ``uq_scan_pkg`` is replaced by ``uq_scan_pkg_env`` over the five columns.

Downgrade: the old constraint allows only one verdict per package version, so for each
(ecosystem, package, version, analyzer version) only the most recently created row is kept;
the other environments' verdicts (and their signals) are deleted and references to them are
cleared. The column becomes nullable again.

Revision ID: 0003_scan_environment
Revises: 0002_warden_x
Create Date: 2026-09-15 00:00:00
"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import context, op

revision: str = "0003_scan_environment"
down_revision: Union[str, None] = "0002_warden_x"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_KEY = ("ecosystem", "package_name", "version", "analyzer_version")
# Rows that are not the newest verdict of their (ecosystem, package, version, analyzer version).
_SUPERSEDED_SCAN_IDS = (
    "SELECT s1.id FROM scans s1 WHERE EXISTS (SELECT 1 FROM scans s2 WHERE "
    + " AND ".join(f"s2.{col} = s1.{col}" for col in _KEY)
    + " AND (s2.created_at > s1.created_at OR (s2.created_at = s1.created_at AND s2.id > s1.id)))"
)


def _is_pg() -> bool:
    return op.get_context().dialect.name == "postgresql"


def upgrade() -> None:
    if context.is_offline_mode() and not _is_pg():
        raise RuntimeError("0003_scan_environment: offline (--sql) generation is supported for PostgreSQL only")
    op.execute("UPDATE scans SET environment = 'production' WHERE environment IS NULL")
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("uq_scan_pkg", type_="unique")
        batch.alter_column("environment", existing_type=sa.String(20), nullable=False, server_default="production")
        batch.create_unique_constraint("uq_scan_pkg_env", [*_KEY, "environment"])


def downgrade() -> None:
    if context.is_offline_mode() and not _is_pg():
        raise RuntimeError("0003_scan_environment: offline (--sql) generation is supported for PostgreSQL only")
    # Explicit clean-up (SQLite does not enforce ON DELETE actions unless foreign keys are enabled).
    for table, column in (("security_events", "scan_id"), ("project_components", "scan_id"),
                          ("monitored_packages", "last_scan_id")):
        op.execute(f"UPDATE {table} SET {column} = NULL WHERE {column} IN ({_SUPERSEDED_SCAN_IDS})")
    op.execute(f"DELETE FROM signals WHERE scan_id IN ({_SUPERSEDED_SCAN_IDS})")
    op.execute(f"DELETE FROM scans WHERE id IN (SELECT id FROM ({_SUPERSEDED_SCAN_IDS}) AS superseded)")
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("uq_scan_pkg_env", type_="unique")
        batch.alter_column("environment", existing_type=sa.String(20), nullable=True, server_default=None)
        batch.create_unique_constraint("uq_scan_pkg", list(_KEY))
