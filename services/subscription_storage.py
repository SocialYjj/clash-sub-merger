"""Rollback-safe persistence for subscription YAML plus its config record."""

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Callable, Optional

from fastapi import HTTPException
from logger_config import get_logger

from helpers import (
    atomic_write_text,
    delete_subscription_content,
    read_subscription_content,
    save_subscription_content,
    subscription_yaml_lock,
    yaml_cache,
)

logger = get_logger(__name__)


_TRANSACTION_DIRECTORY = ".subscription_transactions"


def _transaction_path(subscription_id: str, yaml_source_dir: str) -> Path:
    # The filename is derived from the validated ID rather than interpolating
    # user input, so a pending marker can never escape DATA_DIR.
    subscription_file_path(subscription_id, yaml_source_dir)
    digest = hashlib.sha256(str(subscription_id).encode("utf-8")).hexdigest()
    directory = Path(yaml_source_dir).resolve().parent / _TRANSACTION_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{digest}.json"


def _config_digest(config: object) -> str:
    encoded = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _record_digest(config: dict, subscription_id: str) -> str:
    from core.database import find_subscription_by_id

    record = find_subscription_by_id(config, subscription_id)
    return _config_digest(record)


def _text_digest(content: Optional[str]) -> str:
    return hashlib.sha256((content or "").encode("utf-8")).hexdigest()


def _encode_content(content: Optional[str]) -> Optional[str]:
    if content is None:
        return None
    return base64.b64encode(content.encode("utf-8")).decode("ascii")


def _decode_content(encoded: object) -> Optional[str]:
    if encoded is None:
        return None
    if not isinstance(encoded, str):
        raise ValueError("Invalid transaction content")
    return base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-8")


def _write_transaction_marker(path: Path, marker: dict) -> None:
    atomic_write_text(path, json.dumps(marker, ensure_ascii=False, separators=(",", ":")))


def _remove_transaction_marker(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return


def recover_pending_subscription_transactions(yaml_source_dir: str) -> int:
    """Recover YAML/config pairs interrupted between their two file commits.

    A marker is removed after both files are durable. If a process died after
    writing YAML but before updating its subscription record, the record hash
    still matches the pre-transaction value and the old YAML is restored. If
    the record changed, the config commit won and the new YAML is retained.
    """
    directory = Path(yaml_source_dir).resolve().parent / _TRANSACTION_DIRECTORY
    if not directory.is_dir():
        return 0

    recovered = 0
    for marker_path in directory.glob("*.json"):
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            subscription_id = str(marker["subscription_id"])
            status = marker.get("status")
            if status == "prepared":
                current_content = snapshot_subscription_content(subscription_id, yaml_source_dir)
                if _text_digest(current_content) == marker.get("new_content_hash"):
                    status = "yaml_written"
                else:
                    _remove_transaction_marker(marker_path)
                    continue
            if status != "yaml_written":
                _remove_transaction_marker(marker_path)
                continue

            from core.database import load_config

            current_config = load_config()
            current_record_hash = _record_digest(current_config, subscription_id)
            if current_record_hash == marker.get("record_before_hash"):
                previous_content = _decode_content(marker.get("previous_content"))
                restore_subscription_content(subscription_id, yaml_source_dir, previous_content)
                logger.warning(
                    "Rolled back interrupted subscription write for %s",
                    subscription_id,
                )
            else:
                logger.warning(
                    "Recovered completed subscription write for %s after marker interruption",
                    subscription_id,
                )
            _remove_transaction_marker(marker_path)
            recovered += 1
        except Exception:
            logger.error("Failed to recover subscription transaction %s", marker_path, exc_info=True)
    return recovered


def subscription_file_path(subscription_id: str, yaml_source_dir: str) -> Path:
    base_dir = Path(yaml_source_dir).resolve()
    target = (base_dir / f"{subscription_id}.yaml").resolve()
    try:
        target.relative_to(base_dir)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid subscription id") from exc
    return target


def snapshot_subscription_content(subscription_id: str, yaml_source_dir: str) -> Optional[str]:
    subscription_file_path(subscription_id, yaml_source_dir)
    return read_subscription_content(subscription_id, yaml_source_dir)


def restore_subscription_content(
    subscription_id: str,
    yaml_source_dir: str,
    previous_content: Optional[str],
) -> None:
    if previous_content is None:
        delete_subscription_content(subscription_id, yaml_source_dir)
    else:
        save_subscription_content(subscription_id, previous_content, yaml_source_dir)
    yaml_cache.invalidate(subscription_id)


def persist_subscription_content_and_record(
    subscription_id: str,
    content: str,
    yaml_source_dir: str,
    update_record: Callable[[], dict | None],
) -> dict:
    """Persist YAML and its config record with crash-recovery journaling."""
    from core.database import load_config

    with subscription_yaml_lock(subscription_id, yaml_source_dir):
        previous_content = snapshot_subscription_content(subscription_id, yaml_source_dir)
        config_before = load_config()
        marker_path = _transaction_path(subscription_id, yaml_source_dir)
        marker = {
            "version": 1,
            "subscription_id": subscription_id,
            "status": "prepared",
            "created_at": int(time.time()),
            "record_before_hash": _record_digest(config_before, subscription_id),
            "previous_content": _encode_content(previous_content),
            "new_content_hash": _text_digest(content),
        }
        _write_transaction_marker(marker_path, marker)
        try:
            save_subscription_content(subscription_id, content, yaml_source_dir)
            marker["status"] = "yaml_written"
            _write_transaction_marker(marker_path, marker)

            updated_record = update_record()
            if not updated_record:
                raise HTTPException(status_code=404, detail="Subscription not found")

            marker["status"] = "config_committed"
            _write_transaction_marker(marker_path, marker)
            _remove_transaction_marker(marker_path)
            return updated_record
        except BaseException:
            try:
                restore_subscription_content(subscription_id, yaml_source_dir, previous_content)
                _remove_transaction_marker(marker_path)
            except Exception:
                logger.error(
                    "Failed to roll back subscription write for %s; leaving transaction marker for startup recovery",
                    subscription_id,
                    exc_info=True,
                )
            raise
