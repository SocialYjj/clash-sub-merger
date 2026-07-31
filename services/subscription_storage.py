"""Rollback-safe persistence for subscription YAML plus its config record."""

from pathlib import Path
from typing import Callable, Optional

from fastapi import HTTPException

from helpers import atomic_write_text, save_subscription_content, yaml_cache


def subscription_file_path(subscription_id: str, yaml_source_dir: str) -> Path:
    base_dir = Path(yaml_source_dir).resolve()
    target = (base_dir / f"{subscription_id}.yaml").resolve()
    try:
        target.relative_to(base_dir)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid subscription id") from exc
    return target


def snapshot_subscription_content(subscription_id: str, yaml_source_dir: str) -> Optional[str]:
    path = subscription_file_path(subscription_id, yaml_source_dir)
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def restore_subscription_content(
    subscription_id: str,
    yaml_source_dir: str,
    previous_content: Optional[str],
) -> None:
    path = subscription_file_path(subscription_id, yaml_source_dir)
    if previous_content is None:
        path.unlink(missing_ok=True)
    else:
        atomic_write_text(path, previous_content)
    yaml_cache.invalidate(subscription_id)


def persist_subscription_content_and_record(
    subscription_id: str,
    content: str,
    yaml_source_dir: str,
    update_record: Callable[[], dict | None],
) -> dict:
    """Save YAML, then update config; restore the old YAML if config persistence fails."""
    previous_content = snapshot_subscription_content(subscription_id, yaml_source_dir)
    save_subscription_content(subscription_id, content, yaml_source_dir)
    try:
        updated_record = update_record()
        if not updated_record:
            raise HTTPException(status_code=404, detail="Subscription not found")
        return updated_record
    except BaseException:
        restore_subscription_content(subscription_id, yaml_source_dir, previous_content)
        raise
