"""Continuous-monitoring worker: ``python -m app.workers.monitor``.

Every cycle claims the packages that are due (``MONITOR_BATCH_SIZE`` at most), checks them with
:mod:`app.monitoring.service` and sleeps until the next cycle. It touches the heartbeat file
(``MONITOR_HEARTBEAT_FILE``, default ``/tmp/warden-monitor.heartbeat``) after every cycle and while
idle, at least every :data:`HEARTBEAT_SECONDS`; the Compose healthcheck treats a heartbeat older than
ten minutes as unhealthy, so a hung worker is reported instead of looking alive.

The worker refuses to start unless ``MONITOR_ENABLED`` is true. SIGTERM / SIGINT finish the current
check and exit.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from pathlib import Path

from sqlalchemy import func, select

from app.core import metrics
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.db.models import MonitoredPackage
from app.db.session import SessionLocal
from app.monitoring.service import run_due

log = get_logger("warden.worker.monitor")

HEARTBEAT_SECONDS = 60
IDLE_SECONDS = 30
DEFAULT_HEARTBEAT_FILE = "/tmp/warden-monitor.heartbeat"  # nosec B108 - private tmpfs in the container


def heartbeat_path() -> Path:
    return Path(os.environ.get("MONITOR_HEARTBEAT_FILE") or DEFAULT_HEARTBEAT_FILE)


def touch_heartbeat(path: Path | None = None) -> None:
    target = path or heartbeat_path()
    try:
        target.touch(exist_ok=True)
        os.utime(target, None)
    except OSError as exc:
        log.warning("monitor_heartbeat_failed", error_type=type(exc).__name__)


def run_cycle() -> int:
    with SessionLocal() as db:
        outcomes = run_due(db)
        enabled = db.scalar(select(func.count(MonitoredPackage.id)).where(MonitoredPackage.enabled.is_(True)))
        metrics.set_monitored_packages(enabled or 0)
    for outcome in outcomes:
        log.info("monitor_check", package=outcome.package, status=outcome.status, version=outcome.version)
    return len(outcomes)


def main(stop: threading.Event | None = None, *, max_cycles: int | None = None) -> int:
    configure_logging()
    if not settings.MONITOR_ENABLED:
        log.error("monitor_disabled", detail="set MONITOR_ENABLED=true to run the monitoring worker")
        return 2
    stop = stop or threading.Event()
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())

    log.info("monitor_started", batch=settings.MONITOR_BATCH_SIZE)
    cycles = 0
    while not stop.is_set():
        try:
            checked = run_cycle()
        except Exception as exc:  # database outage etc.: log, keep the heartbeat honest, retry
            log.error("monitor_cycle_failed", error_type=type(exc).__name__)
            checked = 0
        cycles += 1
        touch_heartbeat()
        if max_cycles is not None and cycles >= max_cycles:
            break
        if checked:
            continue  # more work may be due right away
        deadline = time.monotonic() + IDLE_SECONDS
        while not stop.is_set() and time.monotonic() < deadline:
            stop.wait(min(HEARTBEAT_SECONDS, max(0.0, deadline - time.monotonic())))
            touch_heartbeat()
    log.info("monitor_stopped", cycles=cycles)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
