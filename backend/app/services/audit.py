"""Append-only, tamper-evident audit trail.

Every audit record is linked into a SHA-256 hash chain::

    event_hash(n) = sha256( prev_hash(n) || canonical_json(fields of event n) )
    prev_hash(n)  = event_hash(n - 1)        (GENESIS_HASH for n = 1)

``seq`` is a gap-free, unique, monotonically increasing sequence number. The canonical JSON
covers every stored field (``seq``, ``id``, ``actor_id``, ``action``, ``target_type``,
``target_id``, ``metadata``, ``request_id``, ``created_at``) with sorted keys and fixed
separators, so :func:`verify_chain` can recompute each hash from the stored row alone.

What this gives you (and what it does not)
-----------------------------------------
* Modifying any field of a row, deleting a row from the middle, re-ordering rows, or
  inserting a forged row is detected by :func:`verify_chain`, *unless* the attacker also
  recomputes every later hash. The chain is keyless by design (verifiable by auditors
  without a secret), so an attacker with full database write access *can* rewrite the whole
  tail. Truncating the newest rows is likewise not detectable from the chain alone. To
  close both gaps, periodically copy ``head_seq``/``head_hash`` from ``GET /audit/verify``
  to an external, write-once location (SIEM, object-lock bucket) and compare.
* On PostgreSQL the migration installs triggers that reject UPDATE, DELETE and TRUNCATE on
  ``audit_events``. Triggers fire for every role, but the table owner (or a superuser) can
  disable them, so the application should connect as a role that does not own the table.

Concurrency
-----------
Appending reads the chain head and inserts the next row. On PostgreSQL the head read is
serialised with a transaction-scoped advisory lock (``pg_advisory_xact_lock``), released
at commit/rollback. On SQLite (development/test) writers are serialised by the database
lock; a rare concurrent append fails on the ``seq`` unique constraint instead of forking
the chain.

Metadata is passed through :func:`app.core.redaction.sanitize_evidence` before it is hashed
and stored: callers must never put secrets in audit metadata, and anything secret-shaped
that slips through is redacted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.logging import get_logger, request_id_ctx
from app.core.redaction import sanitize_evidence, sanitize_text
from app.db.base import as_utc, utcnow
from app.db.models import AuditEvent

log = get_logger("warden.audit")

# Hash-chain format version. The canonical form below is frozen for version 1 (the
# 0002 migration uses it to backfill pre-existing rows); any change needs a new version.
CHAIN_VERSION = 1
GENESIS_HASH = "0" * 64
# Arbitrary constant bigint identifying the audit-chain advisory lock ("WDNAUDIT").
ADVISORY_LOCK_KEY = 0x57444E4155444954

_FIELD_LIMITS = {"action": 80, "target_type": 40, "target_id": 64, "request_id": 64}


# --------------------------------------------------------------------------- canonical form
def canonical_timestamp(value: datetime | None) -> str | None:
    """UTC ISO-8601 with microseconds; naive datetimes are interpreted as UTC."""
    if value is None:
        return None
    return as_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return canonical_timestamp(value) or ""
    return str(value)


def canonical_event(
    *,
    seq: int,
    event_id: uuid.UUID | str,
    actor_id: uuid.UUID | str | None,
    action: str,
    target_type: str | None,
    target_id: str | None,
    metadata: Any,
    request_id: str | None,
    created_at: datetime | None,
) -> str:
    """Deterministic JSON serialisation of the hashed fields of one audit event."""
    payload = {
        "v": CHAIN_VERSION,
        "seq": int(seq),
        "id": str(event_id),
        "actor_id": str(actor_id) if actor_id is not None else None,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "metadata": metadata,
        "request_id": request_id,
        "created_at": canonical_timestamp(created_at),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default)


def compute_event_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def normalize_metadata(metadata: dict | None) -> dict:
    """Sanitise metadata and force it into the exact shape a JSON column round-trips.

    Hashing the post-round-trip value guarantees that what is hashed equals what a later
    read returns (tuples become lists, UUIDs/datetimes become strings, NaN becomes null).
    """
    cleaned = sanitize_evidence(metadata or {}, max_str=500, max_items=50, max_keys=50)
    if not isinstance(cleaned, dict):
        cleaned = {"value": cleaned}
    return json.loads(json.dumps(cleaned, default=_json_default))


def _bounded(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    return sanitize_text(value, max_len=_FIELD_LIMITS[field])


# --------------------------------------------------------------------------- append
def _lock_chain(db: Session) -> None:
    """Serialise chain appends on PostgreSQL (no-op elsewhere)."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADVISORY_LOCK_KEY})


def chain_head(db: Session) -> tuple[int, str]:
    """``(seq, event_hash)`` of the newest event, or ``(0, GENESIS_HASH)`` for an empty chain."""
    row = db.execute(
        select(AuditEvent.seq, AuditEvent.event_hash).order_by(AuditEvent.seq.desc()).limit(1)
    ).first()
    if row is None:
        return 0, GENESIS_HASH
    return int(row.seq), str(row.event_hash)


def record(
    db: Session,
    *,
    actor_id: uuid.UUID | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    metadata: dict | None = None,
) -> AuditEvent:
    """Append one audit event to the chain within the caller's transaction.

    The event is flushed immediately (so a second ``record`` in the same transaction sees
    it as the chain head) but committed by the caller together with the change it audits:
    if the caller rolls back, the audit row disappears with the change.
    """
    _lock_chain(db)
    head_seq, head_hash = chain_head(db)

    event = AuditEvent(
        id=uuid.uuid4(),
        actor_id=actor_id,
        action=_bounded(action, "action") or "",
        target_type=_bounded(target_type, "target_type"),
        target_id=_bounded(target_id, "target_id"),
        metadata_=normalize_metadata(metadata),
        request_id=_bounded(request_id_ctx.get(), "request_id"),
        created_at=utcnow(),
        seq=head_seq + 1,
        prev_hash=head_hash,
    )
    event.event_hash = compute_event_hash(
        head_hash,
        canonical_event(
            seq=event.seq, event_id=event.id, actor_id=event.actor_id, action=event.action,
            target_type=event.target_type, target_id=event.target_id, metadata=event.metadata_,
            request_id=event.request_id, created_at=event.created_at,
        ),
    )
    db.add(event)
    db.flush()
    return event


# --------------------------------------------------------------------------- verify
_VERIFY_COLUMNS = (
    AuditEvent.seq, AuditEvent.id, AuditEvent.actor_id, AuditEvent.action, AuditEvent.target_type,
    AuditEvent.target_id, AuditEvent.metadata_, AuditEvent.request_id, AuditEvent.created_at,
    AuditEvent.prev_hash, AuditEvent.event_hash,
)


def verify_chain(db: Session, *, batch_size: int = 1000) -> dict[str, Any]:
    """Walk the whole chain in ``seq`` order and recompute every hash.

    Returns ``{ok, checked, first_broken_seq, reason, head_seq, head_hash}``. ``checked`` is
    the number of events verified before the first break; ``head_*`` describe the last
    verified event (anchor these externally to detect tail truncation or a rewritten tail).
    Column tuples (not ORM instances) are read so an identity-map cache can never mask a
    modified row.
    """
    checked = 0
    expected_seq = 1
    expected_prev = GENESIS_HASH
    last_seq: int | None = None
    head_hash: str | None = None

    def _result(ok: bool, broken: int | None, reason: str | None) -> dict[str, Any]:
        return {
            "ok": ok, "checked": checked, "first_broken_seq": broken, "reason": reason,
            "head_seq": last_seq, "head_hash": head_hash,
        }

    while True:
        stmt = select(*_VERIFY_COLUMNS).order_by(AuditEvent.seq).limit(batch_size)
        if last_seq is not None:
            stmt = stmt.where(AuditEvent.seq > last_seq)
        rows = db.execute(stmt).all()
        if not rows:
            break
        for row in rows:
            if row.seq != expected_seq:
                return _result(False, row.seq, f"sequence gap: expected seq {expected_seq}, found {row.seq}")
            if not hmac.compare_digest(str(row.prev_hash or ""), expected_prev):
                return _result(False, row.seq, "prev_hash does not match the preceding event_hash")
            recomputed = compute_event_hash(
                expected_prev,
                canonical_event(
                    seq=row.seq, event_id=row.id, actor_id=row.actor_id, action=row.action,
                    target_type=row.target_type, target_id=row.target_id, metadata=row.metadata_,
                    request_id=row.request_id, created_at=row.created_at,
                ),
            )
            if not hmac.compare_digest(recomputed, str(row.event_hash or "")):
                return _result(False, row.seq, "event_hash mismatch: stored event content was modified")
            checked += 1
            expected_seq += 1
            expected_prev = row.event_hash
            last_seq = row.seq
            head_hash = row.event_hash

    unchained = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.seq.is_(None))) or 0
    if unchained:
        return _result(False, None, f"{unchained} audit event(s) are not part of the hash chain")
    return _result(True, None, None)
