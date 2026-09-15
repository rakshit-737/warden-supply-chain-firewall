"""Alembic environment — wires migrations to the app's metadata and settings.

Database URL resolution (first match wins):

1. ``config.attributes["connection"]`` — an existing SQLAlchemy ``Connection`` supplied by
   a caller (e.g. a test harness) that wants migrations to run on its connection.
2. ``-x url=...`` on the command line.
3. ``config.attributes["sqlalchemy.url"]`` — set programmatically on the ``Config``.
4. ``sqlalchemy.url`` main option, **unless** it is the placeholder shipped in alembic.ini.
5. ``settings.DATABASE_URL`` (the application's environment-driven configuration).

The URL is never written back into the ini configuration (configparser would interpret a
``%`` in a URL-encoded password) and is never logged, because it may carry credentials.
"""

from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import create_engine, pool

from alembic import context
from app.core.config import settings

# Import models so they register on Base.metadata.
from app.db import models  # noqa: F401
from app.db.base import Base

_PLACEHOLDER_URL = "driver://user:pass@localhost/dbname"

config = context.config

if config.config_file_name is not None:
    # Keep loggers configured by the application (or a test runner) alive.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _resolve_url() -> str:
    x_args = context.get_x_argument(as_dictionary=True)
    if x_args.get("url"):
        return x_args["url"]
    attr = config.attributes.get("sqlalchemy.url")
    if attr:
        return str(attr)
    configured = config.get_main_option("sqlalchemy.url")
    if configured and configured != _PLACEHOLDER_URL:
        return configured
    return settings.DATABASE_URL


def run_migrations_offline() -> None:
    context.configure(
        url=_resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_with_connection(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied = config.attributes.get("connection")
    if supplied is not None:
        _run_with_connection(supplied)
        return
    connectable = create_engine(_resolve_url(), poolclass=pool.NullPool, future=True)
    try:
        with connectable.connect() as connection:
            _run_with_connection(connection)
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
