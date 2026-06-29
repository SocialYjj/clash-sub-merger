"""
Subscriptions API
Subscription management endpoints
"""
import asyncio
import time
from typing import Optional, List
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, HttpUrl, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.dependencies import verify_session
from core.database import load_config, update_config, update_subscription_fields
from core.config import AppConfig
from helpers import handle_api_errors, generate_timestamp_id, load_subscription_yaml, save_subscription_content
from services.node_visibility import apply_node_visibility_to_yaml_content
from services.region_history import apply_region_history_to_yaml_content
from services.subscription_parser import parse_local_subscription, InvalidContentError
from services.subscription_fetcher import SubscriptionFetcher, FetchError
from services.stats_cache import invalidate as invalidate_stats_cache
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# Lazy-initialized fetcher
_fetcher: Optional[SubscriptionFetcher] = None
_fetcher_proxy_url: Optional[str] = None
_fetcher_client: Optional[httpx.AsyncClient] = None


async def close_fetcher():
    """Close the fetcher's HTTP client. Called during shutdown."""
    global _fetcher, _fetcher_client
    if _fetcher_client is not None:
        try:
            await _fetcher_client.aclose()
        except Exception:
            pass
    _fetcher = None
    _fetcher_client = None


def _get_fetcher() -> SubscriptionFetcher:
    """Get or create subscription fetcher instance, recreating if proxy config changed."""
    global _fetcher, _fetcher_proxy_url, _fetcher_client

    # Read current proxy URL from config
    config = load_config()
    proxy_url = config.get('settings', {}).get('subscription_proxy_url')

    # Recreate fetcher if proxy config changed
    if _fetcher is None or _fetcher_proxy_url != proxy_url:
        # Close previous client to avoid connection pool leak
        if _fetcher_client is not None:
            try:
                asyncio.ensure_future(_fetcher_client.aclose())
            except Exception:
                pass
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
        )
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


# ==================== Data Models ====================

class AddSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: HttpUrl
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v.strip()


class AddLocalSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=10*1024*1024)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v.strip()


class UpdateSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    url: Optional[HttpUrl] = None
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v and ('/' in v or '\\' in v or '..' in v):
            raise ValueError('Name contains invalid characters')
        return v.strip() if v else v


class UpdateLocalSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    content: Optional[str] = Field(None, max_length=10*1024*1024)


class ReorderSubscriptions(BaseModel):
    order: List[str]


# ==================== API Endpoints ====================

@router.get("")
@handle_api_errors
def list_subscriptions(_: bool = Depends(verify_session)):
    """List all subscriptions"""
    config = load_config()
    return {"subscriptions": config.get('subscriptions', [])}


@router.post("")
@handle_api_errors
async def add_subscription(data: AddSubscription, _: bool = Depends(verify_session)):
    """Add a new URL subscription"""
    sub_id = generate_timestamp_id('sub_')
    
    try:
        fetcher = _get_fetcher()
        user_agent = _get_user_agent()
        
        content, sub_info, node_count = await fetcher.fetch(
            str(data.url),
            user_agent=user_agent
        )
        
        content, _, inherited = apply_region_history_to_yaml_content(
            content,
            existing_nodes=[],
            source=f'sub:add:{sub_id}',
        )
        content, visibility_inherited = apply_node_visibility_to_yaml_content(content, existing_nodes=[])
        
        new_sub = {
            'id': sub_id, 'name': data.name, 'url': str(data.url), 'enabled': True,
            'type': 'url',
            'upload': sub_info.get('upload', 0), 'download': sub_info.get('download', 0),
            'total': sub_info.get('total', 0), 'expire': sub_info.get('expire', 0),
            'node_count': node_count, 'last_update': int(time.time()),
            'cron_expr': None, 'next_update': None
        }
        
        if inherited:
            logger.info("Inherited saved region for %s node(s) while adding subscription %s", inherited, sub_id)
        if visibility_inherited:
            logger.info("Inherited disabled state for %s node(s) while adding subscription %s", visibility_inherited, sub_id)
        
        save_subscription_content(sub_id, content, AppConfig.YAML_SOURCE_DIR)
        
        def append_subscription(config: dict):
            config.setdefault('subscriptions', []).append(new_sub)
        
        update_config(append_subscription)
        invalidate_stats_cache()
        return {"status": "success", "subscription": new_sub}
        
    except FetchError as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch subscription: {str(e)}")


@router.post("/local")
@handle_api_errors
def add_local_subscription(data: AddLocalSubscription, _: bool = Depends(verify_session)):
    """Add a local subscription by pasting content"""
    sub_id = generate_timestamp_id('sub_')
    
    try:
        yaml_content, proxies, node_count = parse_local_subscription(data.content)
        
        yaml_content, _, inherited = apply_region_history_to_yaml_content(
            yaml_content,
            existing_nodes=[],
            source=f'sub:add-local:{sub_id}',
        )
        yaml_content, visibility_inherited = apply_node_visibility_to_yaml_content(yaml_content, existing_nodes=[])
        
        new_sub = {
            'id': sub_id, 'name': data.name, 'enabled': True,
            'type': 'local', 'node_count': node_count,
            'last_update': int(time.time()),
            'cron_expr': None, 'next_update': None
        }
        
        if inherited:
            logger.info("Inherited saved region for %s node(s) while adding local subscription %s", inherited, sub_id)
        if visibility_inherited:
            logger.info("Inherited disabled state for %s node(s) while adding local subscription %s", visibility_inherited, sub_id)
        
        save_subscription_content(sub_id, yaml_content, AppConfig.YAML_SOURCE_DIR)
        
        def append_local_subscription(config: dict):
            config.setdefault('subscriptions', []).append(new_sub)
        
        update_config(append_local_subscription)
        return {"status": "success", "subscription": new_sub}
        
    except InvalidContentError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{sub_id}/local")
@handle_api_errors
def update_local_subscription(sub_id: str, data: UpdateLocalSubscription, _: bool = Depends(verify_session)):
    """Update a local subscription"""
    config = load_config()
    sub = next((s for s in config['subscriptions'] if s['id'] == sub_id), None)
    
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if sub.get('type') != 'local':
        raise HTTPException(status_code=400, detail="Not a local subscription")
    
    updates = {}
    if data.name:
        updates['name'] = data.name
    
    if data.content:
        try:
            yaml_content, proxies, node_count = parse_local_subscription(data.content)
            existing_nodes = _load_existing_subscription_nodes(sub_id)
            
            yaml_content, remembered, inherited = apply_region_history_to_yaml_content(
                yaml_content,
                existing_nodes=existing_nodes,
                source=f'sub:update-local:{sub_id}',
            )
            yaml_content, visibility_inherited = apply_node_visibility_to_yaml_content(
                yaml_content,
                existing_nodes=existing_nodes,
            )
            
            updates['node_count'] = node_count
            if remembered or inherited or visibility_inherited:
                logger.info(
                    "Local subscription %s history: remembered=%s inherited_region=%s inherited_disabled=%s",
                    sub_id,
                    remembered,
                    inherited,
                    visibility_inherited,
                )
            save_subscription_content(sub_id, yaml_content, AppConfig.YAML_SOURCE_DIR)
        except InvalidContentError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    updates['last_update'] = int(time.time())
    
    def apply_local_update(latest_config: dict) -> dict:
        latest_sub = next((s for s in latest_config.get('subscriptions', []) if s['id'] == sub_id), None)
        if not latest_sub:
            raise HTTPException(status_code=404, detail="Subscription not found")
        if latest_sub.get('type') != 'local':
            raise HTTPException(status_code=400, detail="Not a local subscription")
        latest_sub.update(updates)
        return dict(latest_sub)
    
    updated_sub = update_config(apply_local_update)
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
def delete_subscription(sub_id: str, _: bool = Depends(verify_session)):
    """Delete a subscription"""
    if sub_id == 'custom_nodes':
        raise HTTPException(status_code=400, detail="custom_nodes is not a subscription")
    
    def remove_subscription(config: dict) -> dict:
        subs = config.get('subscriptions', [])
        sub = next((s for s in subs if s.get('id') == sub_id), None)
        if not sub:
            raise HTTPException(status_code=404, detail="Subscription not found")
        config['subscriptions'] = [s for s in subs if s.get('id') != sub_id]
        return dict(sub)
    
    update_config(remove_subscription)
    invalidate_stats_cache()
    
    # Invalidate YAML cache for this subscription
    from helpers import yaml_cache
    yaml_cache.invalidate(sub_id)
    
    # Delete the subscription YAML file
    yaml_root = Path(AppConfig.YAML_SOURCE_DIR).resolve()
    yaml_file = (yaml_root / f'{sub_id}.yaml').resolve()
    if yaml_root not in yaml_file.parents and yaml_file != yaml_root:
        raise HTTPException(status_code=400, detail="Invalid subscription id")
    
    try:
        if yaml_file.exists():
            yaml_file.unlink()
            logger.info(f"Deleted subscription file: {yaml_file}")
    except Exception as e:
        logger.warning(f"Failed to delete subscription file {yaml_file}: {e}")
    
    return {"status": "success"}


@router.put("/{sub_id}/toggle")
@handle_api_errors
def toggle_subscription(sub_id: str, _: bool = Depends(verify_session)):
    """Toggle subscription enabled status"""
    def toggle_enabled(config: dict) -> bool:
        for sub in config.get('subscriptions', []):
            if sub['id'] == sub_id:
                sub['enabled'] = not sub.get('enabled', True)
                return sub['enabled']
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    enabled = update_config(toggle_enabled)
    invalidate_stats_cache()
    return {"status": "success", "enabled": enabled}


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
def update_subscription(sub_id: str, data: UpdateSubscription, _: bool = Depends(verify_session)):
    """Update subscription info"""
    def apply_subscription_update(config: dict) -> dict:
        for sub in config.get('subscriptions', []):
            if sub['id'] == sub_id:
                if data.name is not None:
                    sub['name'] = data.name
                if data.url is not None:
                    sub['url'] = str(data.url)
                return dict(sub)
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    sub = update_config(apply_subscription_update)
    return {"status": "success", "subscription": sub}


@router.post("/{sub_id}/refresh")
@handle_api_errors
async def refresh_subscription(sub_id: str, request: Request, _: bool = Depends(verify_session)):
    """Refresh a single subscription"""
    from server import subscription_refresh_lock

    config = load_config()

    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")

    if sub.get('type') == 'local':
        raise HTTPException(status_code=400, detail="Local subscriptions cannot be refreshed")

    async with subscription_refresh_lock(sub_id):
        try:
            fetcher = _get_fetcher()
            user_agent = _get_user_agent()

            logger.info(f"Refreshing subscription {sub_id} ({sub['name']}): {sub['url']}")
            existing_nodes = _load_existing_subscription_nodes(sub_id)

            content, sub_info, node_count = await fetcher.fetch(
                sub['url'],
                user_agent=user_agent
            )

            content, remembered, inherited = apply_region_history_to_yaml_content(
                content,
                existing_nodes=existing_nodes,
                source=f'sub:refresh:{sub_id}',
            )
            content, visibility_inherited = apply_node_visibility_to_yaml_content(
                content,
                existing_nodes=existing_nodes,
            )

            updates = {
                'upload': sub_info.get('upload', 0),
                'download': sub_info.get('download', 0),
                'total': sub_info.get('total', 0),
                'expire': sub_info.get('expire', 0),
                'node_count': node_count,
                'last_update': int(time.time()),
                'update_status': 'success'
            }

            if remembered or inherited or visibility_inherited:
                logger.info(
                    "Subscription %s history after refresh: remembered=%s inherited_region=%s inherited_disabled=%s",
                    sub_id,
                    remembered,
                    inherited,
                    visibility_inherited,
                )

            save_subscription_content(sub_id, content, AppConfig.YAML_SOURCE_DIR)
            updated_sub = update_subscription_fields(sub_id, updates)
            if not updated_sub:
                raise HTTPException(status_code=404, detail="Subscription not found")
            invalidate_stats_cache()

            logger.info(f"Successfully refreshed subscription {sub_id}, got {node_count} nodes")
            return {"status": "success", "subscription": updated_sub}

        except HTTPException:
            raise
        except FetchError as e:
            error_msg = str(e)
            logger.error(f"Failed to refresh subscription {sub_id} ({sub['name']}): {error_msg}", exc_info=True)
            update_subscription_fields(sub_id, {'update_status': f'error: {error_msg}'})
            raise HTTPException(status_code=400, detail=error_msg)
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Failed to refresh subscription {sub_id} ({sub['name']}): {error_msg}", exc_info=True)
            update_subscription_fields(sub_id, {'update_status': f'error: {error_msg}'})
            raise HTTPException(status_code=400, detail=error_msg)


@router.post("/refresh-all")
@handle_api_errors
async def refresh_all_subscriptions(request: Request, _: bool = Depends(verify_session)):
    """Refresh all URL subscriptions"""
    from server import subscription_refresh_lock

    config = load_config()

    url_subs = [s for s in config.get('subscriptions', []) if s.get('type') != 'local' and s.get('enabled', True)]

    if not url_subs:
        return {"status": "success", "message": "No URL subscriptions to refresh", "results": []}

    results = []
    fetcher = _get_fetcher()
    user_agent = _get_user_agent()

    for sub in url_subs:
        try:
            async with subscription_refresh_lock(sub['id']):
                existing_nodes = _load_existing_subscription_nodes(sub['id'])

                content, sub_info, node_count = await fetcher.fetch(
                    sub['url'],
                    user_agent=user_agent
                )

                content, remembered, inherited = apply_region_history_to_yaml_content(
                    content,
                    existing_nodes=existing_nodes,
                    source=f"sub:refresh-all:{sub['id']}",
                )
                content, visibility_inherited = apply_node_visibility_to_yaml_content(
                    content,
                    existing_nodes=existing_nodes,
                )

                updates = {
                    'upload': sub_info.get('upload', 0),
                    'download': sub_info.get('download', 0),
                    'total': sub_info.get('total', 0),
                    'expire': sub_info.get('expire', 0),
                    'node_count': node_count,
                    'last_update': int(time.time()),
                    'update_status': 'success'
                }

                if remembered or inherited or visibility_inherited:
                    logger.info(
                        "Subscription %s history in refresh-all: remembered=%s inherited_region=%s inherited_disabled=%s",
                        sub['id'],
                        remembered,
                        inherited,
                        visibility_inherited,
                    )

                save_subscription_content(sub['id'], content, AppConfig.YAML_SOURCE_DIR)
                update_subscription_fields(sub['id'], updates)
                results.append({"id": sub['id'], "name": sub['name'], "status": "success"})

        except HTTPException as e:
            detail = e.detail if isinstance(e.detail, str) else str(e.detail)
            if e.status_code != 409:
                update_subscription_fields(sub['id'], {'update_status': f'error: {detail}'})
            results.append({"id": sub['id'], "name": sub['name'], "status": "error", "error": detail})
        except Exception as e:
            update_subscription_fields(sub['id'], {'update_status': f'error: {str(e)}'})
            results.append({"id": sub['id'], "name": sub['name'], "status": "error", "error": str(e)})
    
    invalidate_stats_cache()
    
    success_count = len([r for r in results if r['status'] == 'success'])
    return {
        "status": "success",
        "message": f"Refreshed {success_count}/{len(url_subs)} subscriptions",
        "results": results
    }
