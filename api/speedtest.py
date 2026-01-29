"""
Speedtest API
Speed test endpoints
"""
import os
import secrets
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.config import AppConfig
from core.dependencies import verify_session
from core.database import load_config, save_config
from helpers import handle_api_errors, load_subscription_yaml
from services.name_transformer import NameTransformer
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# Get YAML_SOURCE_DIR from environment or default
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
YAML_SOURCE_DIR = os.path.join(DATA_DIR, 'uploads')

# Lazy import server module (only for functions that truly need it)
_server_module = None


def _get_server():
    global _server_module
    if _server_module is None:
        import server as srv
        _server_module = srv
    return _server_module


# ==================== Data Models ====================

class SpeedTestRequest(BaseModel):
    node_id: str
    test_speed: bool = False
    timeout: int = 10


class BatchSpeedTestRequest(BaseModel):
    node_ids: List[str]
    test_speed: bool = False
    timeout: int = 10
    concurrency: int = 10


class SpeedTestProfile(BaseModel):
    name: str
    description: Optional[str] = ""
    subscription_ids: Optional[List[str]] = None
    test_speed: Optional[bool] = False
    timeout: Optional[int] = 10
    concurrency: Optional[int] = 10


# ==================== Helper Functions ====================

async def _speedtest_single(node_id: str, test_speed: bool = False, timeout: int = 10):
    """Test a single node"""
    srv = _get_server()
    from speedtest_service import get_speedtest_service
    
    node = srv.get_proxy_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    speedtest = get_speedtest_service()
    result = await speedtest.test_node(node, test_speed=test_speed, timeout=timeout)
    
    return {
        "node_id": node_id,
        "name": node.get('name', 'Unknown'),
        "result": result
    }


async def _speedtest_batch(node_ids: List[str], test_speed: bool = False, timeout: int = 10, concurrency: int = 10):
    """Test multiple nodes"""
    import asyncio
    
    semaphore = asyncio.Semaphore(concurrency)
    
    async def test_with_semaphore(node_id):
        async with semaphore:
            try:
                return await _speedtest_single(node_id, test_speed, timeout)
            except Exception as e:
                return {"node_id": node_id, "error": str(e)}
    
    tasks = [test_with_semaphore(nid) for nid in node_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    return {"results": results, "count": len(results)}


# ==================== API Endpoints ====================

@router.post("/single")
@handle_api_errors
async def speedtest_single(data: SpeedTestRequest, request: Request, _: bool = Depends(verify_session)):
    """Test a single node"""
    return await _speedtest_single(data.node_id, data.test_speed, data.timeout)


@router.post("/batch")
@handle_api_errors
async def speedtest_batch(data: BatchSpeedTestRequest, request: Request, _: bool = Depends(verify_session)):
    """Test multiple nodes"""
    return await _speedtest_batch(data.node_ids, data.test_speed, data.timeout, data.concurrency)


@router.post("/subscription/{sub_id}")
@handle_api_errors
async def speedtest_subscription(sub_id: str, request: Request, _: bool = Depends(verify_session)):
    """Test all nodes in a subscription"""
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    
    sub_data = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=True)
    nodes = sub_data.get('proxies', []) if sub_data else []
    
    node_ids = [f"{sub_id}_{i}" for i in range(len(nodes))]
    return await _speedtest_batch(node_ids, test_speed=False, timeout=10, concurrency=10)


@router.get("/results/{sub_id}")
@handle_api_errors
def get_speedtest_results(sub_id: str, _: bool = Depends(verify_session)):
    """Get speed test results for a subscription"""
    config = load_config()
    
    # Get cached results from config
    results = config.get('speedtest_results', {}).get(sub_id, {})
    return {"sub_id": sub_id, "results": results}


@router.get("/config")
@handle_api_errors
def get_speedtest_config(_: bool = Depends(verify_session)):
    """Get speedtest service configuration"""
    from speedtest_service import get_speedtest_service
    
    speedtest = get_speedtest_service()
    return {
        "service_url": AppConfig.GO_SPEEDTEST_URL,
        "default_timeout": 10,
        "default_concurrency": 10
    }


# ==================== Speed Test Profiles ====================

@router.get("/profiles")
def get_speedtest_profiles(_: bool = Depends(verify_session)):
    """Get all speed test profiles"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    return {"profiles": profiles}


@router.post("/profiles")
def create_speedtest_profile(data: SpeedTestProfile, _: bool = Depends(verify_session)):
    """Create a new speed test profile"""
    config = load_config()
    if 'speedtest_profiles' not in config:
        config['speedtest_profiles'] = []
    
    profile = {
        "id": secrets.token_urlsafe(8),
        "name": data.name,
        "description": data.description,
        "subscription_ids": data.subscription_ids,
        "test_speed": data.test_speed,
        "timeout": data.timeout,
        "concurrency": data.concurrency,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_run": None
    }
    
    config['speedtest_profiles'].append(profile)
    save_config(config)
    return {"status": "success", "profile": profile}


@router.get("/profiles/{profile_id}")
def get_speedtest_profile(profile_id: str, _: bool = Depends(verify_session)):
    """Get a specific speed test profile"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    profile = next((p for p in profiles if p['id'] == profile_id), None)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    return {"profile": profile}


@router.put("/profiles/{profile_id}")
def update_speedtest_profile(profile_id: str, data: SpeedTestProfile, _: bool = Depends(verify_session)):
    """Update a speed test profile"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    profile = next((p for p in profiles if p['id'] == profile_id), None)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    profile['name'] = data.name
    profile['description'] = data.description
    profile['subscription_ids'] = data.subscription_ids
    profile['test_speed'] = data.test_speed
    profile['timeout'] = data.timeout
    profile['concurrency'] = data.concurrency
    
    save_config(config)
    return {"status": "success", "profile": profile}


@router.delete("/profiles/{profile_id}")
def delete_speedtest_profile(profile_id: str, _: bool = Depends(verify_session)):
    """Delete a speed test profile"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    
    config['speedtest_profiles'] = [p for p in profiles if p['id'] != profile_id]
    save_config(config)
    return {"status": "success"}


@router.post("/profiles/{profile_id}/run")
async def run_speedtest_profile(profile_id: str, request: Request, _: bool = Depends(verify_session)):
    """Run a speed test profile"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    profile = next((p for p in profiles if p['id'] == profile_id), None)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    profile['last_run'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    save_config(config)
    
    return {
        "status": "info",
        "message": "Speed test execution requires proxy integration.",
        "profile": profile
    }
