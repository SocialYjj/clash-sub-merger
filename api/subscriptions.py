"""
Subscriptions API
Subscription management endpoints
"""
import asyncio
import time
from typing import Optional, List

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, HttpUrl, Field, field_validator

from core.dependencies import verify_session
from core.database import load_config, update_config
from core.config import AppConfig
from core.rate_limit import limiter
from helpers import handle_api_errors, generate_timestamp_id, load_subscription_yaml
from services.node_visibility import apply_node_visibility_to_yaml_content
from services.region_history import (
    apply_node_test_metadata_to_yaml_content,
    apply_region_history_to_yaml_content,
)
from services.subscription_parser import parse_local_subscription, InvalidContentError
from services.subscription_node_count import count_effective_subscription_nodes
from services.subscription_fetcher import SubscriptionFetcher, FetchError
from services.subscription_cleanup import cleanup_deleted_subscription
from services.node_reference_updates import (
    reconcile_subscription_node_references,
    subscription_nodes_from_yaml_content,
)
from services.node_visibility import clear_user_subscription_caches
from services.subscription_refresh_lock import reject_concurrent_refresh, subscription_write_slot
from services.subscription_state import (
    describe_refresh_error,
    record_refresh_attempt,
    record_refresh_failure,
    refresh_success_fields,
)
from services.subscription_storage import (
    persist_subscription_content_and_record,
    restore_subscription_content,
    snapshot_subscription_content,
    subscription_file_path,
)
from services.stats_cache import invalidate as invalidate_stats_cache
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()

# Lazy-initialized fetcher
_fetcher: Optional[SubscriptionFetcher] = None
_fetcher_proxy_url: Optional[str] = None
_fetcher_client: Optional[httpx.AsyncClient] = None


def _count_valid_subscription_nodes(nodes: list) -> int:
    """Count nodes with the same filtering and structural validation rules as exports."""
    return count_effective_subscription_nodes(nodes)


async def close_fetcher():
    """Close the fetcher's HTTP client. Called during shutdown."""
    global _fetcher, _fetcher_proxy_url, _fetcher_client
    if _fetcher_client is not None:
        try:
            await _fetcher_client.aclose()
        except Exception:
            pass
    _fetcher = None
    _fetcher_proxy_url = None
    _fetcher_client = None


def _get_fetcher() -> SubscriptionFetcher:
    """Get or create subscription fetcher instance, recreating if proxy config changed."""
    global _fetcher, _fetcher_proxy_url, _fetcher_client

    # Read current proxy URL from config
    config = load_config()
    proxy_url = config.get('settings', {}).get('subscription_proxy_url')

    if _fetcher_client is None:
        _fetcher_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=AppConfig.CONNECT_TIMEOUT,
                read=AppConfig.READ_TIMEOUT,
                write=AppConfig.WRITE_TIMEOUT,
                pool=AppConfig.CONNECT_TIMEOUT
            ),
            follow_redirects=True,
            limits=httpx.Limits(
                max_keepalive_connections=AppConfig.HTTP_MAX_KEEPALIVE,
                max_connections=AppConfig.HTTP_MAX_CONNECTIONS
            ),
            verify=AppConfig.HTTP_VERIFY_SSL,
            trust_env=False,
        )

    # The direct client does not depend on the optional fallback proxy. Reuse it
    # so a settings change cannot close another refresh's in-flight connection.
    if _fetcher is None or _fetcher_proxy_url != proxy_url:
        _fetcher = SubscriptionFetcher(_fetcher_client, proxy_url=proxy_url)
        _fetcher_proxy_url = proxy_url

    return _fetcher


def _get_user_agent() -> str:
    """Get subscription user agent"""
    from helpers_ua import get_subscription_user_agent
    return get_subscription_user_agent()


def _load_existing_subscription_nodes(sub_id: str) -> list:
    """Load existing subscription nodes for historical region seeding."""
    try:
        cfg = load_subscription_yaml(sub_id, AppConfig.YAML_SOURCE_DIR, use_cache=False)
        if isinstance(cfg, dict):
            proxies = cfg.get('proxies', [])
            if isinstance(proxies, list):
                return proxies
    except Exception:
        return []
    return []


def _validate_subscription_uniqueness(
    config: dict,
    *,
    name: str,
    url: Optional[str] = None,
    exclude_subscription_id: Optional[str] = None,
) -> None:
    normalized_name = name.strip().casefold()
    for subscription in config.get('subscriptions', []):
        if subscription.get('id') == exclude_subscription_id:
            continue
        if str(subscription.get('name') or '').strip().casefold() == normalized_name:
            raise HTTPException(status_code=409, detail="A subscription with this name already exists")
        if url and str(subscription.get('url') or '') == url:
            raise HTTPException(status_code=409, detail="This subscription URL already exists")


async def _refresh_remote_subscription(
    subscription: dict,
    *,
    record_overrides: Optional[dict] = None,
) -> dict:
    """Fetch, validate and persist one URL subscription under its exclusive lock."""
    subscription_id = subscription['id']
    latest_subscription = subscription
    attempted_at = int(time.time())
    try:
        async with reject_concurrent_refresh(subscription_id):
            latest_config = load_config()
            latest_subscription = next(
                (
                    candidate
                    for candidate in latest_config.get('subscriptions', [])
                    if candidate['id'] == subscription_id
                ),
                None,
            )
            if not latest_subscription:
                raise HTTPException(status_code=404, detail="Subscription not found")
            if latest_subscription.get('type') == 'local':
                raise HTTPException(status_code=400, detail="Local subscriptions cannot be refreshed")

            refreshed_subscription = {**latest_subscription, **(record_overrides or {})}
            record_refresh_attempt(refreshed_subscription, attempted_at)
            logger.info(
                "Refreshing subscription %s (%s)",
                subscription_id,
                refreshed_subscription.get('name', ''),
            )
            existing_nodes = _load_existing_subscription_nodes(subscription_id)
            content, subscription_usage, node_count = await _get_fetcher().fetch(
                refreshed_subscription['url'],
                user_agent=_get_user_agent(),
            )

            content, remembered, inherited = apply_region_history_to_yaml_content(
                content,
                existing_nodes=existing_nodes,
                source=f'sub:refresh:{subscription_id}',
            )
            content, test_metadata_inherited = apply_node_test_metadata_to_yaml_content(
                content,
                existing_nodes=existing_nodes,
                source=f'sub:refresh:{subscription_id}',
            )
            content, visibility_inherited = apply_node_visibility_to_yaml_content(
                content,
                existing_nodes=existing_nodes,
            )
            refreshed_nodes = subscription_nodes_from_yaml_content(content)
            valid_node_count = _count_valid_subscription_nodes(refreshed_nodes)
            if valid_node_count <= 0:
                raise FetchError("Subscription contains no valid proxy nodes")

            updates = {
                **(record_overrides or {}),
                'upload': subscription_usage.get('upload', 0),
                'download': subscription_usage.get('download', 0),
                'total': subscription_usage.get('total', 0),
                'expire': subscription_usage.get('expire', 0),
                'node_count': valid_node_count,
                **refresh_success_fields(
                    refreshed_subscription,
                    attempted_at=attempted_at,
                    succeeded_at=int(time.time()),
                ),
            }

            if remembered or inherited or test_metadata_inherited or visibility_inherited:
                logger.info(
                    "Subscription %s history after refresh: remembered=%s inherited_region=%s inherited_test_metadata=%s inherited_disabled=%s",
                    subscription_id,
                    remembered,
                    inherited,
                    test_metadata_inherited,
                    visibility_inherited,
                )

            def commit_refreshed_subscription(latest_config: dict) -> dict:
                stored_subscription = next(
                    (
                        candidate
                        for candidate in latest_config.get('subscriptions', [])
                        if candidate.get('id') == subscription_id
                    ),
                    None,
                )
                if not stored_subscription:
                    raise HTTPException(status_code=404, detail="Subscription not found")

                new_name = str(updates.get('name') or stored_subscription.get('name') or subscription_id)
                new_url = str(updates.get('url') or stored_subscription.get('url') or '')
                _validate_subscription_uniqueness(
                    latest_config,
                    name=new_name,
                    url=new_url,
                    exclude_subscription_id=subscription_id,
                )
                reconcile_subscription_node_references(
                    latest_config,
                    subscription_id,
                    old_nodes=existing_nodes,
                    new_nodes=refreshed_nodes,
                    old_subscription_name=str(stored_subscription.get('name') or subscription_id),
                    new_subscription_name=new_name,
                )
                stored_subscription.update(updates)
                clear_user_subscription_caches(latest_config)
                return dict(stored_subscription)

            updated_subscription = persist_subscription_content_and_record(
                subscription_id,
                content,
                AppConfig.YAML_SOURCE_DIR,
                lambda: update_config(commit_refreshed_subscription),
            )
            invalidate_stats_cache()
            logger.info("Successfully refreshed subscription %s, got %s nodes", subscription_id, node_count)
            return updated_subscription
    except Exception as exc:
        # A 409 means another worker currently owns the subscription lock. It
        # is not a failed upstream refresh and must not overwrite the active
        # worker's success/error state or make the UI show a false failure.
        if isinstance(exc, HTTPException) and exc.status_code == 409:
            logger.info("Refresh skipped because subscription %s is already locked", subscription_id)
            raise
        error_message = describe_refresh_error(exc)
        logger.error(
            "Failed to refresh subscription %s (%s): %s",
            subscription_id,
            (latest_subscription or {}).get('name', ''),
            error_message,
            exc_info=True,
        )
        try:
            record_refresh_failure(latest_subscription or subscription, exc, attempted_at)
        except Exception:
            logger.error("Failed to persist refresh failure state for %s", subscription_id, exc_info=True)
        raise


# ==================== Data Models ====================

class AddSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: HttpUrl
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        normalized_name = v.strip()
        if not normalized_name:
            raise ValueError('Name cannot be empty')
        if '/' in normalized_name or '\\' in normalized_name or '..' in normalized_name:
            raise ValueError('Name contains invalid characters')
        return normalized_name


def _validate_local_subscription_content(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if not value.strip():
        raise ValueError('Content cannot be empty')
    if len(value.encode('utf-8')) > AppConfig.SUBSCRIPTION_MAX_BYTES:
        raise ValueError('Subscription content exceeds the configured size limit')
    return value


class AddLocalSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=AppConfig.SUBSCRIPTION_MAX_BYTES)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        normalized_name = v.strip()
        if not normalized_name:
            raise ValueError('Name cannot be empty')
        if '/' in normalized_name or '\\' in normalized_name or '..' in normalized_name:
            raise ValueError('Name contains invalid characters')
        return normalized_name

    @field_validator('content')
    @classmethod
    def validate_content(cls, value):
        return _validate_local_subscription_content(value)


class UpdateSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    url: Optional[HttpUrl] = None
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return None
        normalized_name = v.strip()
        if not normalized_name:
            raise ValueError('Name cannot be empty')
        if '/' in normalized_name or '\\' in normalized_name or '..' in normalized_name:
            raise ValueError('Name contains invalid characters')
        return normalized_name


class UpdateLocalSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    content: Optional[str] = Field(None, max_length=AppConfig.SUBSCRIPTION_MAX_BYTES)

    @field_validator('name')
    @classmethod
    def validate_name(cls, value):
        if value is None:
            return None
        normalized_name = value.strip()
        if not normalized_name:
            raise ValueError('Name cannot be empty')
        if '/' in normalized_name or '\\' in normalized_name or '..' in normalized_name:
            raise ValueError('Name contains invalid characters')
        return normalized_name

    @field_validator('content')
    @classmethod
    def validate_content(cls, value):
        return _validate_local_subscription_content(value)


class ReorderSubscriptions(BaseModel):
    order: List[str]


# ==================== API Endpoints ====================

@router.get("")
@handle_api_errors
def list_subscriptions(_: bool = Depends(verify_session)):
    """List all subscriptions"""
    config = load_config()
    subscriptions = []
    for subscription in config.get('subscriptions', []):
        current = dict(subscription)
        try:
            yaml_data = load_subscription_yaml(
                subscription['id'], AppConfig.YAML_SOURCE_DIR, use_cache=True
            )
            proxies = yaml_data.get('proxies', []) if isinstance(yaml_data, dict) else []
            current['node_count'] = _count_valid_subscription_nodes(proxies)
            current['node_count_stale'] = False
            current.pop('node_count_error', None)
        except Exception as exc:
            logger.warning(
                "Failed to calculate current node count for subscription %s: %s",
                subscription.get('id', '<unknown>'), type(exc).__name__,
            )
            # Never present the persisted count as current when the source file
            # cannot be read.  A zero plus explicit status is safer than a
            # silently stale number that disagrees with node management.
            current['node_count'] = 0
            current['node_count_stale'] = True
            current['node_count_error'] = 'Subscription data unavailable'
        subscriptions.append(current)
    return {"subscriptions": subscriptions}


@router.post("")
@handle_api_errors
async def add_subscription(data: AddSubscription, _: bool = Depends(verify_session)):
    """Add a new URL subscription"""
    sub_id = generate_timestamp_id('sub_')
    subscription_url = str(data.url)
    _validate_subscription_uniqueness(
        load_config(),
        name=data.name,
        url=subscription_url,
    )
    
    try:
        fetcher = _get_fetcher()
        user_agent = _get_user_agent()
        
        content, sub_info, node_count = await fetcher.fetch(
            subscription_url,
            user_agent=user_agent
        )
        parsed_nodes = subscription_nodes_from_yaml_content(content)
        node_count = _count_valid_subscription_nodes(parsed_nodes)
        if node_count <= 0:
            raise FetchError("Subscription contains no valid proxy nodes")
        
        content, _, inherited = apply_region_history_to_yaml_content(
            content,
            existing_nodes=[],
            source=f'sub:add:{sub_id}',
        )
        content, visibility_inherited = apply_node_visibility_to_yaml_content(content, existing_nodes=[])
        
        created_at = int(time.time())
        new_sub = {
            'id': sub_id, 'name': data.name, 'url': subscription_url, 'enabled': True,
            'type': 'url',
            'upload': sub_info.get('upload', 0), 'download': sub_info.get('download', 0),
            'total': sub_info.get('total', 0), 'expire': sub_info.get('expire', 0),
            'node_count': node_count, 'last_update': created_at,
            'last_attempt': created_at, 'last_success': created_at, 'last_error': None,
            'update_status': 'success', 'cron_expr': None, 'next_update': None
        }
        
        if inherited:
            logger.info("Inherited saved region for %s node(s) while adding subscription %s", inherited, sub_id)
        if visibility_inherited:
            logger.info("Inherited disabled state for %s node(s) while adding subscription %s", visibility_inherited, sub_id)
        
        def append_subscription(config: dict):
            _validate_subscription_uniqueness(
                config,
                name=data.name,
                url=subscription_url,
            )
            config.setdefault('subscriptions', []).append(new_sub)
            return dict(new_sub)

        persist_subscription_content_and_record(
            sub_id,
            content,
            AppConfig.YAML_SOURCE_DIR,
            lambda: update_config(append_subscription),
        )
        invalidate_stats_cache()
        return {"status": "success", "subscription": new_sub}
        
    except FetchError as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch subscription: {str(e)}")


@router.post("/local")
@handle_api_errors
def add_local_subscription(data: AddLocalSubscription, _: bool = Depends(verify_session)):
    """Add a local subscription by pasting content"""
    sub_id = generate_timestamp_id('sub_')
    _validate_subscription_uniqueness(load_config(), name=data.name)
    
    try:
        yaml_content, proxies, node_count = parse_local_subscription(data.content)
        
        yaml_content, _, inherited = apply_region_history_to_yaml_content(
            yaml_content,
            existing_nodes=[],
            source=f'sub:add-local:{sub_id}',
        )
        yaml_content, visibility_inherited = apply_node_visibility_to_yaml_content(yaml_content, existing_nodes=[])
        
        created_at = int(time.time())
        new_sub = {
            'id': sub_id, 'name': data.name, 'enabled': True,
            'type': 'local', 'node_count': node_count,
            'last_update': created_at, 'last_attempt': created_at,
            'last_success': created_at, 'last_error': None, 'update_status': 'success',
            'cron_expr': None, 'next_update': None
        }
        
        if inherited:
            logger.info("Inherited saved region for %s node(s) while adding local subscription %s", inherited, sub_id)
        if visibility_inherited:
            logger.info("Inherited disabled state for %s node(s) while adding local subscription %s", visibility_inherited, sub_id)
        
        def append_local_subscription(config: dict):
            _validate_subscription_uniqueness(config, name=data.name)
            config.setdefault('subscriptions', []).append(new_sub)
            return dict(new_sub)

        persist_subscription_content_and_record(
            sub_id,
            yaml_content,
            AppConfig.YAML_SOURCE_DIR,
            lambda: update_config(append_local_subscription),
        )
        return {"status": "success", "subscription": new_sub}
        
    except InvalidContentError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{sub_id}/local")
@handle_api_errors
def update_local_subscription(sub_id: str, data: UpdateLocalSubscription, _: bool = Depends(verify_session)):
    """Update a local subscription"""
    with subscription_write_slot(sub_id):
        config = load_config()
        sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
        if not sub:
            raise HTTPException(status_code=404, detail="Subscription not found")
        if sub.get('type') != 'local':
            raise HTTPException(status_code=400, detail="Not a local subscription")

        existing_nodes = _load_existing_subscription_nodes(sub_id)
        updates = {}
        if data.name is not None:
            updates['name'] = data.name

        yaml_content = None
        if data.content is not None:
            try:
                yaml_content, _proxies, node_count = parse_local_subscription(data.content)
            except InvalidContentError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

            yaml_content, remembered, inherited = apply_region_history_to_yaml_content(
                yaml_content,
                existing_nodes=existing_nodes,
                source=f'sub:update-local:{sub_id}',
            )
            yaml_content, test_metadata_inherited = apply_node_test_metadata_to_yaml_content(
                yaml_content,
                existing_nodes=existing_nodes,
                source=f'sub:update-local:{sub_id}',
            )
            yaml_content, visibility_inherited = apply_node_visibility_to_yaml_content(
                yaml_content,
                existing_nodes=existing_nodes,
            )
            updated_at = int(time.time())
            updates.update({
                'node_count': node_count,
                'last_update': updated_at,
                'last_attempt': updated_at,
                'last_success': updated_at,
                'last_error': None,
                'update_status': 'success',
            })
            if remembered or inherited or test_metadata_inherited or visibility_inherited:
                logger.info(
                    "Local subscription %s history: remembered=%s inherited_region=%s inherited_test_metadata=%s inherited_disabled=%s",
                    sub_id,
                    remembered,
                    inherited,
                    test_metadata_inherited,
                    visibility_inherited,
                )

        updated_nodes = (
            subscription_nodes_from_yaml_content(yaml_content)
            if yaml_content is not None
            else existing_nodes
        )

        def apply_local_update(latest_config: dict) -> dict:
            latest_sub = next((s for s in latest_config.get('subscriptions', []) if s['id'] == sub_id), None)
            if not latest_sub:
                raise HTTPException(status_code=404, detail="Subscription not found")
            if latest_sub.get('type') != 'local':
                raise HTTPException(status_code=400, detail="Not a local subscription")
            updated_name = str(updates.get('name') or latest_sub.get('name') or sub_id)
            _validate_subscription_uniqueness(
                latest_config,
                name=updated_name,
                exclude_subscription_id=sub_id,
            )
            reconcile_subscription_node_references(
                latest_config,
                sub_id,
                old_nodes=existing_nodes,
                new_nodes=updated_nodes,
                old_subscription_name=str(latest_sub.get('name') or sub_id),
                new_subscription_name=updated_name,
            )
            latest_sub.update(updates)
            clear_user_subscription_caches(latest_config)
            return dict(latest_sub)

        if yaml_content is not None:
            updated_sub = persist_subscription_content_and_record(
                sub_id,
                yaml_content,
                AppConfig.YAML_SOURCE_DIR,
                lambda: update_config(apply_local_update),
            )
        else:
            updated_sub = update_config(apply_local_update)
        invalidate_stats_cache()
        return {"status": "success", "subscription": updated_sub}


@router.post("/parse-preview")
@handle_api_errors
def parse_subscription_preview(data: AddLocalSubscription, _: bool = Depends(verify_session)):
    """Preview parsing of subscription content"""
    try:
        yaml_content, proxies, node_count = parse_local_subscription(data.content)
        return {"status": "success", "node_count": node_count, "preview": proxies[:10]}
    except InvalidContentError as e:
        return {"status": "error", "error": str(e), "node_count": 0}


@router.delete("/{sub_id}")
@handle_api_errors
async def delete_subscription(sub_id: str, _: bool = Depends(verify_session)):
    """Delete a subscription"""
    if sub_id == 'custom_nodes':
        raise HTTPException(status_code=400, detail="custom_nodes is not a subscription")

    async with reject_concurrent_refresh(sub_id):
        current_config = load_config()
        current_subscription = next(
            (item for item in current_config.get('subscriptions', []) if item.get('id') == sub_id),
            None,
        )
        if not current_subscription:
            raise HTTPException(status_code=404, detail="Subscription not found")
        current_nodes = _load_existing_subscription_nodes(sub_id)
        previous_content = snapshot_subscription_content(sub_id, AppConfig.YAML_SOURCE_DIR)
        yaml_file = subscription_file_path(sub_id, AppConfig.YAML_SOURCE_DIR)
        try:
            yaml_file.unlink(missing_ok=True)
            from helpers import yaml_cache
            yaml_cache.invalidate(sub_id)

            def remove_subscription(config: dict) -> dict:
                removed = cleanup_deleted_subscription(
                    config,
                    sub_id,
                    current_nodes,
                )
                if not removed:
                    raise HTTPException(status_code=404, detail="Subscription not found")
                return removed

            update_config(remove_subscription)
        except Exception:
            restore_subscription_content(
                sub_id,
                AppConfig.YAML_SOURCE_DIR,
                previous_content,
            )
            raise

        from scheduler_service import get_scheduler
        get_scheduler().remove_job(f"sub_refresh_{sub_id}")
        invalidate_stats_cache()
        logger.info("Deleted subscription %s and its persisted references", sub_id)

    return {"status": "success"}


@router.put("/{sub_id}/toggle")
@handle_api_errors
async def toggle_subscription(sub_id: str, _: bool = Depends(verify_session)):
    """Toggle subscription enabled status"""
    async with reject_concurrent_refresh(sub_id):
        def toggle_enabled(config: dict) -> dict:
            for subscription in config.get('subscriptions', []):
                if subscription['id'] == sub_id:
                    subscription['enabled'] = not subscription.get('enabled', True)
                    if not subscription['enabled']:
                        subscription['next_update'] = None
                    return {
                        'enabled': subscription['enabled'],
                        'cron_expr': subscription.get('cron_expr'),
                    }
            raise HTTPException(status_code=404, detail="Subscription not found")

        toggle_state = update_config(toggle_enabled)
        if toggle_state['enabled'] and toggle_state['cron_expr']:
            try:
                from api.scheduler import _set_subscription_schedule
                _set_subscription_schedule(sub_id, toggle_state['cron_expr'])
            except Exception:
                def disable_after_schedule_failure(config: dict):
                    subscription = next(
                        (item for item in config.get('subscriptions', []) if item['id'] == sub_id),
                        None,
                    )
                    if subscription:
                        subscription['enabled'] = False
                        subscription['next_update'] = None

                update_config(disable_after_schedule_failure)
                raise
        elif not toggle_state['enabled']:
            from scheduler_service import get_scheduler
            get_scheduler().remove_job(f"sub_refresh_{sub_id}")

        invalidate_stats_cache()

    return {"status": "success", "enabled": toggle_state['enabled']}


@router.put("/reorder")
@handle_api_errors
def reorder_subscriptions(data: ReorderSubscriptions, _: bool = Depends(verify_session)):
    """Reorder subscriptions"""
    def apply_subscription_order(config: dict):
        subs = config.get('subscriptions', [])
        sub_map = {s['id']: s for s in subs}
        
        new_subs = []
        for ordered_sub_id in data.order:
            if ordered_sub_id in sub_map:
                new_subs.append(sub_map.pop(ordered_sub_id))
        new_subs.extend(sub_map.values())
        
        config['subscriptions'] = new_subs
    
    update_config(apply_subscription_order)
    return {"status": "success"}


@router.put("/{sub_id}")
@handle_api_errors
async def update_subscription(sub_id: str, data: UpdateSubscription, _: bool = Depends(verify_session)):
    """Update metadata; a changed URL is fetched and committed with its YAML as one operation."""
    config = load_config()
    current_subscription = next(
        (item for item in config.get('subscriptions', []) if item.get('id') == sub_id),
        None,
    )
    if not current_subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if current_subscription.get('type') == 'local':
        raise HTTPException(status_code=400, detail="Use the local subscription endpoint")

    requested_url = str(data.url) if data.url is not None else current_subscription.get('url')
    url_changed = data.url is not None and requested_url != current_subscription.get('url')
    requested_name = data.name if data.name is not None else current_subscription.get('name', sub_id)
    _validate_subscription_uniqueness(
        config,
        name=requested_name,
        url=requested_url,
        exclude_subscription_id=sub_id,
    )
    record_overrides = {}
    if data.name is not None:
        record_overrides['name'] = data.name
    if url_changed:
        record_overrides['url'] = requested_url
        try:
            updated_subscription = await _refresh_remote_subscription(
                current_subscription,
                record_overrides=record_overrides,
            )
        except FetchError as exc:
            raise HTTPException(status_code=400, detail=describe_refresh_error(exc)) from exc
        return {"status": "success", "subscription": updated_subscription}

    async with reject_concurrent_refresh(sub_id):
        existing_nodes = _load_existing_subscription_nodes(sub_id)

        def apply_subscription_update(latest_config: dict) -> dict:
            latest_subscription = next(
                (item for item in latest_config.get('subscriptions', []) if item.get('id') == sub_id),
                None,
            )
            if not latest_subscription:
                raise HTTPException(status_code=404, detail="Subscription not found")
            updated_name = data.name if data.name is not None else latest_subscription.get('name', sub_id)
            _validate_subscription_uniqueness(
                latest_config,
                name=updated_name,
                url=str(latest_subscription.get('url') or ''),
                exclude_subscription_id=sub_id,
            )
            if data.name is not None:
                reconcile_subscription_node_references(
                    latest_config,
                    sub_id,
                    old_nodes=existing_nodes,
                    new_nodes=existing_nodes,
                    old_subscription_name=str(latest_subscription.get('name') or sub_id),
                    new_subscription_name=data.name,
                )
                latest_subscription['name'] = data.name
                clear_user_subscription_caches(latest_config)
            return dict(latest_subscription)

        updated_subscription = update_config(apply_subscription_update)
    return {"status": "success", "subscription": updated_subscription}


@router.post("/{sub_id}/refresh")
@limiter.limit(AppConfig.RATE_LIMIT_REFRESH_SINGLE)
@handle_api_errors
async def refresh_subscription(sub_id: str, request: Request, _: bool = Depends(verify_session)):
    """Refresh a single subscription"""
    config = load_config()
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if sub.get('type') == 'local':
        raise HTTPException(status_code=400, detail="Local subscriptions cannot be refreshed")

    try:
        updated_subscription = await _refresh_remote_subscription(sub)
        return {"status": "success", "subscription": updated_subscription}
    except FetchError as exc:
        raise HTTPException(status_code=400, detail=describe_refresh_error(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=describe_refresh_error(exc)) from exc


@router.post("/refresh-all")
@limiter.limit(AppConfig.RATE_LIMIT_REFRESH_ALL)
@handle_api_errors
async def refresh_all_subscriptions(request: Request, _: bool = Depends(verify_session)):
    """Refresh all URL subscriptions"""
    config = load_config()
    url_subs = [s for s in config.get('subscriptions', []) if s.get('type') != 'local' and s.get('enabled', True)]

    if not url_subs:
        return {
            "status": "success",
            "message": "No URL subscriptions to refresh",
            "success_count": 0,
            "failure_count": 0,
            "total_count": 0,
            "results": [],
        }

    refresh_slots = asyncio.Semaphore(AppConfig.SUBSCRIPTION_REFRESH_CONCURRENCY)

    async def refresh_one_subscription(sub: dict) -> dict:
        async with refresh_slots:
            try:
                await _refresh_remote_subscription(sub)
                return {"id": sub['id'], "name": sub['name'], "status": "success"}
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
                return {"id": sub['id'], "name": sub['name'], "status": "error", "error": detail}
            except Exception as exc:
                return {
                    "id": sub['id'],
                    "name": sub['name'],
                    "status": "error",
                    "error": describe_refresh_error(exc),
                }

    refresh_results = await asyncio.gather(
        *(refresh_one_subscription(subscription) for subscription in url_subs)
    )
    success_count = sum(item['status'] == 'success' for item in refresh_results)
    failure_count = len(refresh_results) - success_count
    if failure_count == 0:
        refresh_status = 'success'
    elif success_count == 0:
        refresh_status = 'error'
    else:
        refresh_status = 'partial'

    return {
        "status": refresh_status,
        "message": f"Refreshed {success_count}/{len(url_subs)} subscriptions",
        "success_count": success_count,
        "failure_count": failure_count,
        "total_count": len(url_subs),
        "results": refresh_results,
    }
