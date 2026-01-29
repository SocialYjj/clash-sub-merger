"""
Subscriptions API
Subscription management endpoints
"""
import time
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, HttpUrl, Field, validator
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.config import AppConfig
from core.dependencies import verify_session
from core.database import load_config, save_config
from helpers import handle_api_errors, generate_timestamp_id, save_subscription_content
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# These will be imported from server.py at runtime to avoid circular imports
_server_module = None


def _get_server():
    """Lazy import server module to avoid circular imports"""
    global _server_module
    if _server_module is None:
        import server as srv
        _server_module = srv
    return _server_module


# ==================== Data Models ====================

class AddSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: HttpUrl
    
    @validator('name')
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v.strip()


class AddLocalSubscription(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=10*1024*1024)
    
    @validator('name')
    def validate_name(cls, v):
        if '/' in v or '\\' in v or '..' in v:
            raise ValueError('Name contains invalid characters')
        return v.strip()


class UpdateSubscription(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    url: Optional[HttpUrl] = None
    
    @validator('name')
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
def add_subscription(data: AddSubscription, _: bool = Depends(verify_session)):
    """Add a new URL subscription"""
    srv = _get_server()
    config = load_config()
    sub_id = generate_timestamp_id('sub_')
    
    try:
        proxy_node = srv.get_configured_proxy_node()
        content, sub_info, node_count = srv.fetch_subscription(str(data.url), proxy_node=proxy_node)
        new_sub = {
            'id': sub_id, 'name': data.name, 'url': str(data.url), 'enabled': True,
            'type': 'url',
            'upload': sub_info.get('upload', 0), 'download': sub_info.get('download', 0),
            'total': sub_info.get('total', 0), 'expire': sub_info.get('expire', 0),
            'node_count': node_count, 'last_update': int(time.time()),
            'cron_expr': None, 'next_update': None
        }
        
        save_subscription_content(sub_id, content, srv.YAML_SOURCE_DIR)
        config['subscriptions'].append(new_sub)
        save_config(config)
        srv.invalidate_stats_cache()
        return {"status": "success", "subscription": new_sub}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch subscription: {str(e)}")


@router.post("/local")
@handle_api_errors
def add_local_subscription(data: AddLocalSubscription, _: bool = Depends(verify_session)):
    """Add a local subscription by pasting content"""
    srv = _get_server()
    config = load_config()
    sub_id = generate_timestamp_id('sub_')
    
    try:
        yaml_content, proxies, node_count = srv.parse_local_subscription(data.content)
        new_sub = {
            'id': sub_id, 'name': data.name, 'enabled': True,
            'type': 'local', 'node_count': node_count,
            'last_update': int(time.time()),
            'cron_expr': None, 'next_update': None
        }
        
        save_subscription_content(sub_id, yaml_content, srv.YAML_SOURCE_DIR)
        config['subscriptions'].append(new_sub)
        save_config(config)
        return {"status": "success", "subscription": new_sub}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse content: {str(e)}")


@router.put("/{sub_id}/local")
@handle_api_errors
def update_local_subscription(sub_id: str, data: UpdateLocalSubscription, _: bool = Depends(verify_session)):
    """Update a local subscription"""
    srv = _get_server()
    config = load_config()
    sub = next((s for s in config['subscriptions'] if s['id'] == sub_id), None)
    
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if sub.get('type') != 'local':
        raise HTTPException(status_code=400, detail="Not a local subscription")
    
    if data.name:
        sub['name'] = data.name
    
    if data.content:
        try:
            yaml_content, proxies, node_count = srv.parse_local_subscription(data.content)
            sub['node_count'] = node_count
            save_subscription_content(sub_id, yaml_content, srv.YAML_SOURCE_DIR)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    sub['last_update'] = int(time.time())
    save_config(config)
    return {"status": "success", "subscription": sub}


@router.post("/parse-preview")
@handle_api_errors
def parse_subscription_preview(data: AddLocalSubscription, _: bool = Depends(verify_session)):
    """Preview parsing of subscription content"""
    srv = _get_server()
    try:
        yaml_content, proxies, node_count = srv.parse_local_subscription(data.content)
        return {"status": "success", "node_count": node_count, "preview": proxies[:10]}
    except Exception as e:
        return {"status": "error", "error": str(e), "node_count": 0}


@router.delete("/{sub_id}")
@handle_api_errors
def delete_subscription(sub_id: str, _: bool = Depends(verify_session)):
    """Delete a subscription"""
    srv = _get_server()
    config = load_config()
    subs = config.get('subscriptions', [])
    config['subscriptions'] = [s for s in subs if s['id'] != sub_id]
    save_config(config)
    srv.invalidate_stats_cache()
    
    # Invalidate YAML cache for this subscription
    from helpers import yaml_cache
    yaml_cache.invalidate(sub_id)
    
    # Delete the subscription YAML file
    import os
    yaml_file = os.path.join(srv.YAML_SOURCE_DIR, f'{sub_id}.yaml')
    try:
        if os.path.exists(yaml_file):
            os.remove(yaml_file)
            logger.info(f"Deleted subscription file: {yaml_file}")
    except Exception as e:
        logger.warning(f"Failed to delete subscription file {yaml_file}: {e}")
    
    return {"status": "success"}


@router.put("/{sub_id}/toggle")
@handle_api_errors
def toggle_subscription(sub_id: str, _: bool = Depends(verify_session)):
    """Toggle subscription enabled status"""
    srv = _get_server()
    config = load_config()
    
    for sub in config.get('subscriptions', []):
        if sub['id'] == sub_id:
            sub['enabled'] = not sub.get('enabled', True)
            save_config(config)
            srv.invalidate_stats_cache()
            return {"status": "success", "enabled": sub['enabled']}
    
    raise HTTPException(status_code=404, detail="Subscription not found")


@router.put("/reorder")
@handle_api_errors
def reorder_subscriptions(data: ReorderSubscriptions, _: bool = Depends(verify_session)):
    """Reorder subscriptions"""
    config = load_config()
    subs = config.get('subscriptions', [])
    sub_map = {s['id']: s for s in subs}
    
    new_subs = []
    for sub_id in data.order:
        if sub_id in sub_map:
            new_subs.append(sub_map.pop(sub_id))
    new_subs.extend(sub_map.values())
    
    config['subscriptions'] = new_subs
    save_config(config)
    return {"status": "success"}


@router.put("/{sub_id}")
@handle_api_errors
def update_subscription(sub_id: str, data: UpdateSubscription, _: bool = Depends(verify_session)):
    """Update subscription info"""
    config = load_config()
    
    for sub in config.get('subscriptions', []):
        if sub['id'] == sub_id:
            if data.name is not None:
                sub['name'] = data.name
            if data.url is not None:
                sub['url'] = str(data.url)
            save_config(config)
            return {"status": "success", "subscription": sub}
    
    raise HTTPException(status_code=404, detail="Subscription not found")


@router.post("/{sub_id}/refresh")
@handle_api_errors
async def refresh_subscription(sub_id: str, request: Request, _: bool = Depends(verify_session)):
    """Refresh a single subscription"""
    srv = _get_server()
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    if sub.get('type') == 'local':
        raise HTTPException(status_code=400, detail="Local subscriptions cannot be refreshed")
    
    try:
        proxy_node = srv.get_configured_proxy_node()
        force_proxy = sub.get('force_proxy', False)
        logger.info(f"Refreshing subscription {sub_id} ({sub['name']}): {sub['url']}")
        content, sub_info, node_count = await srv.fetch_subscription_async(
            sub['url'], proxy_node=proxy_node, force_proxy=force_proxy
        )
        
        sub.update({
            'upload': sub_info.get('upload', 0),
            'download': sub_info.get('download', 0),
            'total': sub_info.get('total', 0),
            'expire': sub_info.get('expire', 0),
            'node_count': node_count,
            'last_update': int(time.time()),
            'update_status': 'success'
        })
        
        save_subscription_content(sub_id, content, srv.YAML_SOURCE_DIR)
        save_config(config)
        srv.invalidate_stats_cache()
        
        logger.info(f"Successfully refreshed subscription {sub_id}, got {node_count} nodes")
        return {"status": "success", "subscription": sub}
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Failed to refresh subscription {sub_id} ({sub['name']}): {error_msg}", exc_info=True)
        sub['update_status'] = f'error: {error_msg}'
        save_config(config)
        raise HTTPException(status_code=400, detail=error_msg)


@router.post("/refresh-all")
@handle_api_errors
async def refresh_all_subscriptions(request: Request, _: bool = Depends(verify_session)):
    """Refresh all URL subscriptions"""
    srv = _get_server()
    config = load_config()
    
    url_subs = [s for s in config.get('subscriptions', []) if s.get('type') != 'local' and s.get('enabled', True)]
    
    if not url_subs:
        return {"status": "success", "message": "No URL subscriptions to refresh", "results": []}
    
    results = []
    proxy_node = srv.get_configured_proxy_node()
    
    for sub in url_subs:
        try:
            force_proxy = sub.get('force_proxy', False)
            content, sub_info, node_count = await srv.fetch_subscription_async(
                sub['url'], proxy_node=proxy_node, force_proxy=force_proxy
            )
            
            sub.update({
                'upload': sub_info.get('upload', 0),
                'download': sub_info.get('download', 0),
                'total': sub_info.get('total', 0),
                'expire': sub_info.get('expire', 0),
                'node_count': node_count,
                'last_update': int(time.time()),
                'update_status': 'success'
            })
            
            save_subscription_content(sub['id'], content, srv.YAML_SOURCE_DIR)
            results.append({"id": sub['id'], "name": sub['name'], "status": "success"})
        except Exception as e:
            sub['update_status'] = f'error: {str(e)}'
            results.append({"id": sub['id'], "name": sub['name'], "status": "error", "error": str(e)})
    
    save_config(config)
    srv.invalidate_stats_cache()
    
    success_count = len([r for r in results if r['status'] == 'success'])
    return {
        "status": "success",
        "message": f"Refreshed {success_count}/{len(url_subs)} subscriptions",
        "results": results
    }
