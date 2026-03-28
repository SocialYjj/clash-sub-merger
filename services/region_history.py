"""
Persistent node region history.

Used to inherit previously tested region/city/exit IP metadata for nodes that
cannot be recognized from name alone when the same node is re-imported later.
"""
import json
import os
import re
import time
import hashlib
from typing import Dict, Iterable, Optional, Tuple

import yaml
from filelock import FileLock

from core.config import DATA_DIR
from logger_config import get_logger
from services.name_transformer import NameTransformer

logger = get_logger(__name__)

try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper

REGION_HISTORY_FILE = os.path.join(DATA_DIR, 'node_region_history.json')
REGION_HISTORY_LOCK = f"{REGION_HISTORY_FILE}.lock"
REGION_HISTORY_VERSION = 1
REGION_HISTORY_MAX_AGE_DAYS = int(os.environ.get('NODE_REGION_HISTORY_MAX_AGE_DAYS', '180'))
REGION_HISTORY_MAX_ENTRIES = int(os.environ.get('NODE_REGION_HISTORY_MAX_ENTRIES', '20000'))

_SPACE_RE = re.compile(r'\s+')
_NON_WORD_RE = re.compile(r'[\W_]+', re.UNICODE)


def _normalize_text(value) -> str:
    """Normalize text for stable matching."""
    return _SPACE_RE.sub(' ', str(value or '').strip())


def _normalize_name(value) -> str:
    """Normalize proxy name for identity matching."""
    return _normalize_text(NameTransformer.remove_flags(str(value or '')))


def _compact_name(value) -> str:
    """Compact name used for loose rename matching."""
    normalized = _normalize_name(value).lower()
    return _NON_WORD_RE.sub('', normalized)


def _iso_to_flag(country_code: str) -> str:
    """Resolve ISO code to flag without depending on NameTransformer internals."""
    code = str(country_code or '').upper().strip()
    if not code or code == 'XX':
        return ''
    for flag, iso in NameTransformer.FLAG_TO_ISO.items():
        if iso == code:
            return flag
    return ''


def _normalize_region(region: dict) -> Optional[dict]:
    """Normalize persisted region payload."""
    if not isinstance(region, dict):
        return None

    country_code = str(region.get('country_code') or '').upper().strip()
    country = _normalize_text(region.get('country'))
    flag = str(region.get('flag') or '').strip()

    if not country_code and not country and not flag:
        return None

    if country_code == 'XX' and not country and not flag:
        return None

    if not flag and country_code and country_code != 'XX':
        flag = _iso_to_flag(country_code)
    if not country and country_code:
        country = NameTransformer.ISO_TO_COUNTRY.get(country_code, country_code)

    return {
        'country_code': country_code or 'XX',
        'country': country or 'Unknown',
        'flag': flag or '🔰',
    }


def _node_identity(node: dict) -> Optional[dict]:
    """Build stable identity for historical region matching."""
    if not isinstance(node, dict):
        return None

    name = _normalize_name(node.get('name'))
    server = _normalize_text(node.get('server')).lower()
    port = str(node.get('port') or '').strip()
    node_type = _normalize_text(node.get('type')).lower()

    if not name or not server or not port:
        return None

    return {
        'name': name,
        'server': server,
        'port': port,
        'type': node_type,
    }


def _endpoint_identity(node: dict) -> Optional[dict]:
    """Build endpoint-only identity for conservative fallback matching."""
    if not isinstance(node, dict):
        return None

    server = _normalize_text(node.get('server')).lower()
    port = str(node.get('port') or '').strip()
    node_type = _normalize_text(node.get('type')).lower()

    if not server or not port:
        return None

    return {
        'server': server,
        'port': port,
        'type': node_type,
    }


def _node_history_key(node: dict) -> Optional[str]:
    """Generate history key for a node."""
    identity = _node_identity(node)
    if not identity:
        return None
    raw = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()


def _same_region_payload(left: dict, right: dict) -> bool:
    """Check whether two history entries resolve to the same region payload."""
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False

    return (
        _normalize_region(left.get('region', {})) == _normalize_region(right.get('region', {}))
        and _normalize_text(left.get('city')) == _normalize_text(right.get('city'))
        and _normalize_text(left.get('exit_ip')) == _normalize_text(right.get('exit_ip'))
    )


def _find_history_entry_for_node(node: dict, entries: Dict[str, dict]) -> Optional[dict]:
    """
    Find the best-matching history entry.

    Matching order:
    1. Exact identity: name + server + port + type
    2. Conservative fallback: same server + port + type, only when the
       candidate set is effectively unambiguous.
    """
    key = _node_history_key(node)
    exact = entries.get(key) if key else None
    if isinstance(exact, dict):
        return exact

    endpoint = _endpoint_identity(node)
    if not endpoint:
        return None

    candidates = []
    for entry in entries.values():
        if not isinstance(entry, dict):
            continue
        if (
            _normalize_text(entry.get('server')).lower() == endpoint['server']
            and str(entry.get('port') or '').strip() == endpoint['port']
            and _normalize_text(entry.get('type')).lower() == endpoint['type']
        ):
            candidates.append(entry)

    if not candidates:
        return None

    if len(candidates) == 1:
        return candidates[0]

    # If the same endpoint was renamed over time but all remembered region
    # payloads are identical, it is still safe to inherit the latest one.
    latest_candidates = sorted(
        candidates,
        key=lambda entry: int(entry.get('updated_at') or 0),
        reverse=True,
    )
    first = latest_candidates[0]
    if all(_same_region_payload(first, candidate) for candidate in latest_candidates[1:]):
        return first

    # Final conservative fallback: exact compact-name match under same endpoint.
    compact_name = _compact_name(node.get('name'))
    if compact_name:
        compact_matches = [
            entry for entry in latest_candidates
            if _compact_name(entry.get('name')) == compact_name
        ]
        if len(compact_matches) == 1:
            return compact_matches[0]
        if len(compact_matches) > 1 and all(
            _same_region_payload(compact_matches[0], candidate)
            for candidate in compact_matches[1:]
        ):
            return compact_matches[0]

    return None


def _load_history_entries() -> Dict[str, dict]:
    """Load region history entries from disk."""
    if not os.path.exists(REGION_HISTORY_FILE):
        return {}

    try:
        with open(REGION_HISTORY_FILE, 'r', encoding='utf-8') as f:
            payload = json.load(f)
        if isinstance(payload, dict) and isinstance(payload.get('entries'), dict):
            return payload['entries']
        if isinstance(payload, dict):
            # Backward-compatible fallback if the file contains raw entries.
            return payload
    except Exception as exc:
        logger.warning("Failed to load node region history: %s", exc)

    return {}


def _trim_entries(entries: Dict[str, dict]) -> Dict[str, dict]:
    """Expire old history and cap total entry count."""
    now = int(time.time())
    max_age_seconds = max(1, REGION_HISTORY_MAX_AGE_DAYS) * 86400
    valid_entries = {}

    for key, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        updated_at = int(entry.get('updated_at') or 0)
        if updated_at and now - updated_at > max_age_seconds:
            continue
        valid_entries[key] = entry

    if len(valid_entries) <= REGION_HISTORY_MAX_ENTRIES:
        return valid_entries

    items = sorted(
        valid_entries.items(),
        key=lambda item: int((item[1] or {}).get('updated_at') or 0),
        reverse=True,
    )
    return dict(items[:REGION_HISTORY_MAX_ENTRIES])


def _save_history_entries(entries: Dict[str, dict]):
    """Persist region history entries to disk."""
    os.makedirs(DATA_DIR, exist_ok=True)
    payload = {
        'version': REGION_HISTORY_VERSION,
        'updated_at': int(time.time()),
        'entries': _trim_entries(entries),
    }
    with open(REGION_HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _with_history_lock():
    os.makedirs(DATA_DIR, exist_ok=True)
    return FileLock(REGION_HISTORY_LOCK, timeout=10)


def node_needs_region_inheritance(node: dict) -> bool:
    """Inherit when node currently lacks region and has a stable identity."""
    if not isinstance(node, dict):
        return False

    if _normalize_region(node.get('region', {})):
        return False

    return _node_identity(node) is not None


def remember_nodes_region(nodes: Iterable[dict], source: str = '') -> int:
    """Remember region data for nodes that already have tested metadata."""
    nodes = list(nodes or [])
    if not nodes:
        return 0

    updated = 0
    with _with_history_lock():
        entries = _load_history_entries()
        now = int(time.time())

        for node in nodes:
            key = _node_history_key(node)
            region = _normalize_region((node or {}).get('region', {}))
            if not key or not region:
                continue

            city = _normalize_text((node or {}).get('city'))
            exit_ip = _normalize_text((node or {}).get('exit_ip'))
            identity = _node_identity(node) or {}

            entry_core = {
                'region': region,
                'city': city,
                'exit_ip': exit_ip,
                'source': source or '',
                'name': identity.get('name', ''),
                'server': identity.get('server', ''),
                'port': identity.get('port', ''),
                'type': identity.get('type', ''),
            }

            old_entry = entries.get(key)
            old_entry_core = dict(old_entry) if isinstance(old_entry, dict) else {}
            old_entry_core.pop('updated_at', None)
            if old_entry_core != entry_core:
                new_entry = dict(entry_core)
                new_entry['updated_at'] = now
                entries[key] = new_entry
                updated += 1

        if updated:
            _save_history_entries(entries)

    return updated


def inherit_regions_for_nodes(nodes: Iterable[dict], source: str = '') -> int:
    """Apply remembered region data to nodes when eligible."""
    nodes = list(nodes or [])
    if not nodes:
        return 0

    applied = 0
    with _with_history_lock():
        entries = _load_history_entries()

        for node in nodes:
            if not node_needs_region_inheritance(node):
                continue

            entry = _find_history_entry_for_node(node, entries)
            if not isinstance(entry, dict):
                continue

            region = _normalize_region(entry.get('region', {}))
            if not region:
                continue

            node['region'] = region

            city = _normalize_text(entry.get('city'))
            if city and not _normalize_text(node.get('city')):
                node['city'] = city

            exit_ip = _normalize_text(entry.get('exit_ip'))
            if exit_ip and not _normalize_text(node.get('exit_ip')):
                node['exit_ip'] = exit_ip

            applied += 1

    if applied:
        logger.info(
            "Inherited saved region for %s node(s)%s",
            applied,
            f" from {source}" if source else '',
        )

    return applied


def process_nodes_with_region_history(
    nodes: Iterable[dict],
    existing_nodes: Optional[Iterable[dict]] = None,
    source: str = '',
) -> Tuple[int, int]:
    """
    Seed history from existing nodes first, then apply to incoming nodes.

    Returns:
        Tuple[remembered_count, inherited_count]
    """
    remembered = remember_nodes_region(existing_nodes or [], source=f"{source}:existing" if source else 'existing')
    inherited = inherit_regions_for_nodes(nodes, source=source)
    return remembered, inherited


def apply_region_history_to_yaml_content(
    yaml_content: str,
    existing_nodes: Optional[Iterable[dict]] = None,
    source: str = '',
) -> Tuple[str, int, int]:
    """
    Apply region history to YAML content that contains a top-level proxies list.

    Returns:
        Tuple[new_yaml_content, remembered_count, inherited_count]
    """
    try:
        cfg = yaml.load(yaml_content, Loader=YAMLLoader)
    except Exception as exc:
        logger.warning("Failed to parse YAML for region history apply%s: %s", f" ({source})" if source else '', exc)
        return yaml_content, 0, 0

    if not isinstance(cfg, dict):
        return yaml_content, 0, 0

    proxies = cfg.get('proxies', [])
    if not isinstance(proxies, list):
        return yaml_content, 0, 0

    remembered, inherited = process_nodes_with_region_history(proxies, existing_nodes=existing_nodes, source=source)
    if not inherited:
        return yaml_content, remembered, inherited

    try:
        return (
            yaml.dump(cfg, allow_unicode=True, sort_keys=False, Dumper=YAMLDumper),
            remembered,
            inherited,
        )
    except Exception as exc:
        logger.warning("Failed to dump YAML after region history apply%s: %s", f" ({source})" if source else '', exc)
        return yaml_content, remembered, 0
