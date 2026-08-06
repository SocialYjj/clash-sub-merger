"""
Speedtest API
Speed test endpoints
"""
import os
import secrets
import ipaddress
import httpx
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from core.config import AppConfig
from core.dependencies import verify_session
from core.database import load_config, update_config
from core.rate_limit import limiter
from helpers import handle_api_errors, load_subscription_yaml
from logger_config import get_logger
from services.node_manager import get_proxy_node_by_id
from services.node_identity import subscription_node_ids

logger = get_logger(__name__)
router = APIRouter()

MAX_SPEEDTEST_TIMEOUT = 60
MAX_SPEEDTEST_CONCURRENCY = 100
MAX_SPEEDTEST_NODES = 500

YAML_SOURCE_DIR = AppConfig.YAML_SOURCE_DIR


# ==================== Data Models ====================

class SpeedTestRequest(BaseModel):
    node_id: str = Field(..., min_length=1)
    test_speed: bool = False
    timeout: int = Field(default=10, ge=1, le=MAX_SPEEDTEST_TIMEOUT)


class BatchSpeedTestRequest(BaseModel):
    node_ids: List[str] = Field(..., min_length=1, max_length=MAX_SPEEDTEST_NODES)
    test_speed: bool = False
    timeout: int = Field(default=10, ge=1, le=MAX_SPEEDTEST_TIMEOUT)
    concurrency: int = Field(default=10, ge=1, le=MAX_SPEEDTEST_CONCURRENCY)


class SpeedTestProfile(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = ""
    subscription_ids: Optional[List[str]] = None
    test_speed: Optional[bool] = False
    timeout: Optional[int] = Field(default=10, ge=1, le=MAX_SPEEDTEST_TIMEOUT)
    concurrency: Optional[int] = Field(default=10, ge=1, le=MAX_SPEEDTEST_CONCURRENCY)

    @field_validator('name')
    @classmethod
    def validate_name(cls, value):
        normalized_name = value.strip()
        if not normalized_name:
            raise ValueError('Name cannot be empty')
        return normalized_name


# ==================== Helper Functions ====================

def _bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    """Clamp internal speedtest parameters even when helpers are called directly."""
    try:
        value = int(default if value is None else value)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _is_ipv6_address(server: str) -> bool:
    """Check if server address is IPv6."""
    if not server:
        return False
    candidate = str(server).strip()
    if candidate.startswith('[') and candidate.endswith(']'):
        candidate = candidate[1:-1]
    try:
        return ipaddress.ip_address(candidate).version == 6
    except ValueError:
        return False


def _get_ipv6_proxy() -> tuple:
    """Get IPv6 proxy URL and ipv6_only flag from settings if enabled.
    
    Returns:
        (proxy_url, ipv6_only) or (None, True) if not enabled
    """
    try:
        config = load_config()
        settings = config.get('settings', {})
        ipv6_proxy = settings.get('ipv6_proxy', {})
        if ipv6_proxy.get('enabled') and ipv6_proxy.get('proxy_url'):
            return ipv6_proxy['proxy_url'], ipv6_proxy.get('ipv6_only', True)
    except Exception:
        pass
    return None, True


def build_node_speedtest_payload(node: dict) -> tuple[dict, bool]:
    """Build a Go-service payload and apply the configured IPv6 dialer policy."""
    server = str(node.get('server') or '')
    ipv6_proxy, ipv6_only = _get_ipv6_proxy()
    use_proxy = bool(ipv6_proxy and (not ipv6_only or _is_ipv6_address(server)))
    payload = {"node": node}
    if use_proxy:
        payload["dialer_proxy"] = ipv6_proxy
    return payload, use_proxy


async def _speedtest_single(node_id: str, test_speed: bool = False, timeout: int = 10):
    """Test a single node"""
    timeout = _bounded_int(timeout, default=10, minimum=1, maximum=MAX_SPEEDTEST_TIMEOUT)

    node = get_proxy_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    result = await _run_go_speedtest(node, test_speed=test_speed, timeout=timeout)
    
    return {
        "node_id": node_id,
        "name": node.get('name', 'Unknown'),
        "result": result
    }


_speedtest_client: Optional[httpx.AsyncClient] = None


async def _get_speedtest_client() -> httpx.AsyncClient:
    """Get or create a shared httpx.AsyncClient for Go speedtest requests."""
    global _speedtest_client
    if _speedtest_client is None or _speedtest_client.is_closed:
        _speedtest_client = httpx.AsyncClient(trust_env=False)
    return _speedtest_client


async def _go_speedtest_request(endpoint: str, payload: dict, timeout: int) -> dict:
    """Call the bundled Go speedtest service."""
    client = await _get_speedtest_client()
    try:
        response = await client.post(
            f"{AppConfig.GO_SPEEDTEST_URL.rstrip('/')}{endpoint}",
            json=payload,
            timeout=timeout,
        )
    except httpx.TimeoutException:
        return {
            "success": False,
            "error": f"Go speedtest request timed out after {timeout}s",
        }
    except httpx.RequestError as exc:
        return {
            "success": False,
            "error": f"Go speedtest request failed ({type(exc).__name__})",
        }
    if response.status_code != 200:
        return {"success": False, "error": f"Go service returned HTTP {response.status_code}"}
    try:
        return response.json()
    except Exception:
        return {"success": False, "error": "Go service returned non-JSON response"}


async def _run_go_speedtest(node: dict, test_speed: bool = False, timeout: int = 10) -> dict:
    """Run latency/IP/speed checks against the Go service using node config directly."""
    timeout = _bounded_int(timeout, default=10, minimum=1, maximum=MAX_SPEEDTEST_TIMEOUT)
    timeout_ms = timeout * 1000
    result = {
        "node_name": node.get('name', 'Unknown'),
        "test_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "latency": -1,
        "latency_status": "untested",
        "speed": 0,
        "speed_status": "untested",
        "bytes_downloaded": 0,
    }

    base_payload, use_proxy = build_node_speedtest_payload(node)
    if use_proxy:
        result["using_proxy"] = True
        logger.info("Testing node %s through the configured IPv6 dialer proxy", node.get('name'))
    
    # Latency test
    latency_result = await _go_speedtest_request(
        "/api/delay",
        {**base_payload, "url": "https://cp.cloudflare.com/generate_204", "timeout": timeout_ms},
        # The Go service may try three latency URLs before returning.
        timeout * 3 + 2,
    )
    if latency_result.get("success"):
        result["latency"] = latency_result.get("latency", -1)
        result["latency_status"] = "success"
    else:
        result["latency_status"] = "error"
        result["error"] = latency_result.get("error", "Latency test failed")
        return result

    # IP test
    ip_result = await _go_speedtest_request(
        "/api/ip",
        {**base_payload, "timeout": timeout_ms},
        timeout + 2,
    )
    if ip_result.get("success") and ip_result.get("ip"):
        result["landing_ip"] = ip_result.get("ip")

    # Speed test
    if test_speed:
        speed_result = await _go_speedtest_request(
            "/api/speed",
            {**base_payload, "url": "https://speed.cloudflare.com/__down?bytes=10000000", "timeout": timeout, "mode": "average"},
            timeout + 5,
        )
        if speed_result.get("success"):
            result["speed"] = speed_result.get("speed", 0)
            result["speed_status"] = "success"
            result["bytes_downloaded"] = speed_result.get("bytes", 0)
            peak_speed = speed_result.get("peakSpeed", speed_result.get("peak_speed"))
            if peak_speed is not None:
                result["peak_speed"] = peak_speed
        else:
            result["speed_status"] = "error"
            result["error"] = speed_result.get("error", "Speed test failed")

    return result


async def _speedtest_batch(node_ids: List[str], test_speed: bool = False, timeout: int = 10, concurrency: int = 10):
    """Test multiple nodes"""
    import asyncio

    timeout = _bounded_int(timeout, default=10, minimum=1, maximum=MAX_SPEEDTEST_TIMEOUT)
    concurrency = _bounded_int(concurrency, default=10, minimum=1, maximum=MAX_SPEEDTEST_CONCURRENCY)
    
    semaphore = asyncio.Semaphore(concurrency)
    
    async def test_with_semaphore(node_id):
        async with semaphore:
            try:
                return await _speedtest_single(node_id, test_speed, timeout)
            except Exception as e:
                return {"node_id": node_id, "error": str(e)}
    
    tasks = [asyncio.create_task(test_with_semaphore(nid)) for nid in node_ids]
    try:
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Batch speedtest cancelled; cancelled %d pending task(s)", len(tasks))
        raise

    results = [
        {"node_id": node_ids[idx], "error": str(result)}
        if isinstance(result, BaseException)
        else result
        for idx, result in enumerate(raw_results)
    ]
    
    return {"results": results, "count": len(results)}


# ==================== API Endpoints ====================

@router.post("/single")
@limiter.limit(AppConfig.RATE_LIMIT_SPEEDTEST)
@handle_api_errors
async def speedtest_single(data: SpeedTestRequest, request: Request, _: bool = Depends(verify_session)):
    """Test a single node"""
    return await _speedtest_single(data.node_id, data.test_speed, data.timeout)


@router.post("/batch")
@limiter.limit(AppConfig.RATE_LIMIT_SPEEDTEST)
@handle_api_errors
async def speedtest_batch(data: BatchSpeedTestRequest, request: Request, _: bool = Depends(verify_session)):
    """Test multiple nodes"""
    return await _speedtest_batch(data.node_ids, data.test_speed, data.timeout, data.concurrency)


@router.post("/subscription/{sub_id}")
@limiter.limit(AppConfig.RATE_LIMIT_SPEEDTEST)
@handle_api_errors
async def speedtest_subscription(sub_id: str, request: Request, _: bool = Depends(verify_session)):
    """Test all nodes in a subscription"""
    config = load_config()
    
    sub = next((s for s in config.get('subscriptions', []) if s['id'] == sub_id), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if not sub.get('enabled', True):
        raise HTTPException(status_code=409, detail="Subscription is disabled")
    
    sub_data = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=True)
    nodes = sub_data.get('proxies', []) if sub_data else []
    
    node_ids = subscription_node_ids(sub_id, nodes)
    all_results = []
    requested_node_ids = []
    for offset in range(0, len(node_ids), MAX_SPEEDTEST_NODES):
        batch = node_ids[offset:offset + MAX_SPEEDTEST_NODES]
        requested_node_ids.extend(batch)
        batch_result = await _speedtest_batch(batch, test_speed=False, timeout=10, concurrency=10)
        all_results.extend(batch_result.get('results', []))
        # Keep compatibility with internal callers/tests that return the
        # requested IDs without materialized results.
        if not batch_result.get('results') and batch_result.get('node_ids'):
            requested_node_ids = list(batch_result['node_ids'])

    def persist_results(config: dict):
        stored = config.setdefault('speedtest_results', {}).setdefault(sub_id, {})
        for item in all_results:
            node_id = item.get('node_id')
            if node_id:
                stored[node_id] = item.get('result') or {'error': item.get('error')}

    update_config(persist_results)
    return {
        "results": all_results,
        "count": len(all_results),
        "node_ids": requested_node_ids or node_ids,
    }


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
@handle_api_errors
def get_speedtest_profiles(_: bool = Depends(verify_session)):
    """Get all speed test profiles"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    return {"profiles": profiles}


@router.post("/profiles")
@handle_api_errors
def create_speedtest_profile(data: SpeedTestProfile, _: bool = Depends(verify_session)):
    """Create a new speed test profile"""
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

    def add_speedtest_profile(config: dict):
        config.setdefault('speedtest_profiles', []).append(profile)

    update_config(add_speedtest_profile)
    return {"status": "success", "profile": profile}


@router.get("/profiles/{profile_id}")
@handle_api_errors
def get_speedtest_profile(profile_id: str, _: bool = Depends(verify_session)):
    """Get a specific speed test profile"""
    config = load_config()
    profiles = config.get('speedtest_profiles', [])
    profile = next((p for p in profiles if p['id'] == profile_id), None)
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    return {"profile": profile}


@router.put("/profiles/{profile_id}")
@handle_api_errors
def update_speedtest_profile(profile_id: str, data: SpeedTestProfile, _: bool = Depends(verify_session)):
    """Update a speed test profile"""
    def apply_profile_update(config: dict) -> dict:
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
        return dict(profile)

    profile = update_config(apply_profile_update)
    return {"status": "success", "profile": profile}


@router.delete("/profiles/{profile_id}")
@handle_api_errors
def delete_speedtest_profile(profile_id: str, _: bool = Depends(verify_session)):
    """Delete a speed test profile"""
    def remove_speedtest_profile(config: dict):
        profiles = config.get('speedtest_profiles', [])
        if not any(p.get('id') == profile_id for p in profiles):
            raise HTTPException(status_code=404, detail="Profile not found")
        config['speedtest_profiles'] = [p for p in profiles if p['id'] != profile_id]

    update_config(remove_speedtest_profile)
    return {"status": "success"}


@router.post("/profiles/{profile_id}/run")
@limiter.limit(AppConfig.RATE_LIMIT_SPEEDTEST)
@handle_api_errors
async def run_speedtest_profile(profile_id: str, request: Request, _: bool = Depends(verify_session)):
    """Run a speed test profile against its selected subscriptions."""
    def mark_profile_run(config: dict) -> dict:
        profiles = config.get('speedtest_profiles', [])
        profile = next((p for p in profiles if p['id'] == profile_id), None)

        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")

        profile['last_run'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return dict(profile)

    profile = update_config(mark_profile_run)
    subscription_ids = profile.get('subscription_ids')
    if not subscription_ids:
        subscription_ids = [
            sub.get('id') for sub in load_config().get('subscriptions', [])
            if sub.get('enabled', True)
        ]
    results = []
    for sub_id in subscription_ids:
        sub = next((item for item in load_config().get('subscriptions', []) if item.get('id') == sub_id), None)
        if not sub or not sub.get('enabled', True):
            continue
        source = load_subscription_yaml(sub_id, YAML_SOURCE_DIR, use_cache=True)
        node_ids = subscription_node_ids(sub_id, source.get('proxies', []) if isinstance(source, dict) else [])
        for offset in range(0, len(node_ids), MAX_SPEEDTEST_NODES):
            batch_result = await _speedtest_batch(
                node_ids[offset:offset + MAX_SPEEDTEST_NODES],
                test_speed=bool(profile.get('test_speed')),
                timeout=profile.get('timeout', 10),
                concurrency=profile.get('concurrency', 10),
            )
            results.extend(batch_result.get('results', []))
    def persist_profile_results(config: dict):
        stored_results = config.setdefault('speedtest_results', {})
        for item in results:
            node_id = item.get('node_id')
            if node_id:
                source_id = next((sid for sid in subscription_ids if node_id in subscription_node_ids(
                    sid,
                    (load_subscription_yaml(sid, YAML_SOURCE_DIR, use_cache=True) or {}).get('proxies', []),
                )), None)
                if source_id:
                    stored_results.setdefault(source_id, {})[node_id] = item.get('result') or {'error': item.get('error')}
    update_config(persist_profile_results)
    return {"status": "success", "profile": profile, "results": results, "count": len(results)}
