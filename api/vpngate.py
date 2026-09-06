"""VPN Gate dynamic node-source APIs."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.database import load_config, update_config
from core.dependencies import verify_session
from helpers import handle_api_errors
from services.vpngate import (
    VPNGATE_DEFAULT_INTERVAL_MINUTES,
    VPNGATE_DEFAULT_MAX_NODES,
    VPNGATE_MAX_INTERVAL_MINUTES,
    VPNGATE_MAX_MAX_NODES,
    VPNGATE_MIN_INTERVAL_MINUTES,
    VPNGATE_MIN_MAX_NODES,
    VpnGateRefreshError,
    get_vpngate_node,
    get_vpngate_settings,
    get_vpngate_status,
    list_vpngate_nodes,
    list_vpngate_pools,
    public_vpngate_node,
    refresh_vpngate_cache,
)


router = APIRouter()


class VpnGateSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    interval_minutes: int | None = Field(
        None,
        ge=VPNGATE_MIN_INTERVAL_MINUTES,
        le=VPNGATE_MAX_INTERVAL_MINUTES,
    )
    max_nodes: int | None = Field(
        None,
        ge=VPNGATE_MIN_MAX_NODES,
        le=VPNGATE_MAX_MAX_NODES,
    )
    countries: list[str] | None = Field(None, max_length=250)

    @field_validator("countries")
    @classmethod
    def validate_countries(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized: list[str] = []
        for candidate in value:
            country = str(candidate or "").strip().upper()
            if country and len(country) != 2 or country and not country.isalpha():
                raise ValueError("国家代码必须是两个英文字母")
            if country and country not in normalized:
                normalized.append(country)
        return normalized


def _next_vpngate_refresh_timestamp() -> int | None:
    try:
        from scheduler_service import get_scheduler

        job = get_scheduler().scheduler.get_job("vpngate_refresh")
        return int(job.next_run_time.timestamp()) if job and job.next_run_time else None
    except Exception:
        return None


def _public_vpngate_config() -> dict[str, Any]:
    settings = get_vpngate_settings(load_config())
    return {
        **settings,
        "defaults": {
            "interval_minutes": VPNGATE_DEFAULT_INTERVAL_MINUTES,
            "max_nodes": VPNGATE_DEFAULT_MAX_NODES,
        },
        "status": get_vpngate_status(),
        "next_refresh_at": _next_vpngate_refresh_timestamp(),
    }


@router.get("/config")
@handle_api_errors
def get_vpngate_config(_: bool = Depends(verify_session)):
    """Return VPN Gate settings and refresh status without connection material."""

    return _public_vpngate_config()


@router.put("/config")
@handle_api_errors
def update_vpngate_config(data: VpnGateSettingsUpdate, _: bool = Depends(verify_session)):
    """Persist VPN Gate settings and reschedule the global refresh job."""

    def apply_settings(config: dict) -> dict:
        current = get_vpngate_settings(config)
        updates = data.model_dump(exclude_none=True)
        current.update(updates)
        settings = config.setdefault("settings", {})
        settings["vpngate"] = current
        return current

    update_config(apply_settings)
    try:
        import server

        server.reschedule_vpngate_refresh()
    except Exception:
        # Settings remain persisted even when the process is not currently the
        # scheduler leader (for example during a test or startup race).
        pass
    return _public_vpngate_config()


@router.post("/refresh")
@handle_api_errors
async def refresh_vpngate(_: bool = Depends(verify_session)):
    """Fetch and parse a fresh VPN Gate snapshot."""

    try:
        status = await asyncio.to_thread(refresh_vpngate_cache)
    except VpnGateRefreshError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"status": "success", **status}


@router.get("/nodes")
@handle_api_errors
def get_vpngate_nodes(include_stale: bool = False, _: bool = Depends(verify_session)):
    """Return frontend-safe VPN Gate node metadata."""

    nodes = [public_vpngate_node(node) for node in list_vpngate_nodes(include_stale=include_stale)]
    return {
        "nodes": nodes,
        "count": len(nodes),
        "pools": list_vpngate_pools(),
        "status": get_vpngate_status(),
    }


@router.get("/nodes/{node_id}")
@handle_api_errors
def get_vpngate_node_metadata(node_id: str, _: bool = Depends(verify_session)):
    """Return one frontend-safe VPN Gate node metadata record."""

    node = get_vpngate_node(node_id, include_stale=True)
    if node is None:
        raise HTTPException(status_code=404, detail="VPN Gate 节点不存在")
    return {"node": public_vpngate_node(node)}
