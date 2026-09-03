"""Node-pool management API."""

from __future__ import annotations

import time
from copy import deepcopy
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.database import load_config, update_config
from core.dependencies import verify_session
from helpers import generate_timestamp_id, handle_api_errors
from services.node_pool_references import (
    NODE_POOL_SOURCE,
    VALID_NODE_POOL_LOAD_BALANCE_STRATEGIES,
    VALID_NODE_POOL_STRATEGIES,
    ensure_node_pool_ids,
    list_available_node_catalog,
    list_node_pool_virtual_references,
    normalize_node_pool_members,
    pool_strategy_config,
    reconcile_node_pool_references,
)


router = APIRouter()


class NodePoolMember(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sub_id: str = Field(min_length=1, max_length=200)
    node_id: str | None = Field(None, max_length=500)
    node_index: int | None = Field(None, ge=0)
    node_name: str | None = Field(None, max_length=500)

    @field_validator("sub_id", "node_id", "node_name")
    @classmethod
    def normalize_text(cls, value):
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_reference(self):
        if not self.node_id and not self.node_name and self.node_index is None:
            raise ValueError("节点池成员需要 node_id、node_name 或 node_index")
        return self


class CreateNodePool(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    nodes: list[NodePoolMember] = Field(min_length=1, max_length=500)
    group_strategy: Literal["select", "url-test", "fallback", "load-balance"] = "select"
    lb_strategy: Literal["round-robin", "consistent-hashing", "sticky-sessions"] = "round-robin"
    group_url: str | None = Field(None, max_length=2048)
    group_interval: int = Field(300, ge=10, le=86400)
    group_tolerance: int = Field(50, ge=0, le=10000)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value):
        normalized = value.strip()
        if not normalized:
            raise ValueError("节点池名称不能为空")
        if "/" in normalized or "\\" in normalized or ".." in normalized:
            raise ValueError("节点池名称包含非法字符")
        return normalized

    @field_validator("group_url")
    @classmethod
    def validate_url(cls, value):
        if value is None or not value.strip():
            return None
        from urllib.parse import urlsplit

        normalized = value.strip()
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("检测地址必须使用 HTTP 或 HTTPS")
        return normalized


class UpdateNodePool(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, max_length=100)
    nodes: list[NodePoolMember] | None = Field(None, min_length=1, max_length=500)
    group_strategy: Literal["select", "url-test", "fallback", "load-balance"] | None = None
    lb_strategy: Literal["round-robin", "consistent-hashing", "sticky-sessions"] | None = None
    group_url: str | None = Field(None, max_length=2048)
    group_interval: int | None = Field(None, ge=10, le=86400)
    group_tolerance: int | None = Field(None, ge=0, le=10000)
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value):
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("节点池名称不能为空")
        if "/" in normalized or "\\" in normalized or ".." in normalized:
            raise ValueError("节点池名称包含非法字符")
        return normalized

    @field_validator("group_url")
    @classmethod
    def validate_url(cls, value):
        if value is None or not value.strip():
            return None
        from urllib.parse import urlsplit

        normalized = value.strip()
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("检测地址必须使用 HTTP 或 HTTPS")
        return normalized


class ReorderNodePools(BaseModel):
    model_config = ConfigDict(extra="forbid")

    order: list[str] = Field(max_length=500)

    @field_validator("order")
    @classmethod
    def validate_order(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("节点池顺序包含重复 ID")
        return value


def _pool_payload(pool: dict, reference=None) -> dict:
    result = dict(pool)
    if reference is not None:
        result.update(
            {
                "display_name": reference.name,
                "stable_id": reference.stable_id,
                "legacy_id": reference.legacy_id,
                "source_id": NODE_POOL_SOURCE,
                "member_count": reference.member_count,
                "strategy_config": pool_strategy_config(pool),
            }
        )
    else:
        result.setdefault("member_count", len(pool.get("nodes", [])))
    return result


def _canonical_nodes(config: dict, nodes: list[NodePoolMember]) -> list[dict]:
    try:
        return normalize_node_pool_members(config, [node.model_dump(exclude_none=True) for node in nodes])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("")
@handle_api_errors
def list_node_pools(_: bool = Depends(verify_session)):
    config = load_config()
    references = {
        reference.pool_id: reference
        for reference in list_node_pool_virtual_references(config)
    }
    pools = [
        _pool_payload(pool, references.get(str(pool.get("id"))))
        for pool in config.get("node_pools", [])
        if isinstance(pool, dict)
    ]
    return {"pools": pools, "count": len(pools)}


@router.get("/available-nodes")
@handle_api_errors
def get_available_node_pool_nodes(_: bool = Depends(verify_session)):
    config = load_config()
    nodes = list_available_node_catalog(config)
    return {"nodes": nodes, "count": len(nodes)}


@router.get("/{pool_id}")
@handle_api_errors
def get_node_pool(pool_id: str, _: bool = Depends(verify_session)):
    config = load_config()
    references = {
        reference.pool_id: reference
        for reference in list_node_pool_virtual_references(config)
    }
    for pool in config.get("node_pools", []):
        if isinstance(pool, dict) and pool.get("id") == pool_id:
            return {"pool": _pool_payload(pool, references.get(pool_id))}
    raise HTTPException(status_code=404, detail="节点池不存在")


@router.post("")
@handle_api_errors
def create_node_pool(data: CreateNodePool, _: bool = Depends(verify_session)):
    def add_pool(config: dict) -> dict:
        ensure_node_pool_ids(config)
        if any(
            str(pool.get("name") or "").casefold() == data.name.casefold()
            for pool in config.get("node_pools", [])
            if isinstance(pool, dict)
        ):
            raise HTTPException(status_code=409, detail="节点池名称已存在")
        pool = {
            "id": generate_timestamp_id("pool_"),
            "name": data.name,
            "enabled": True,
            "nodes": _canonical_nodes(config, data.nodes),
            "group_strategy": data.group_strategy,
            "lb_strategy": data.lb_strategy,
            "group_url": data.group_url,
            "group_interval": data.group_interval,
            "group_tolerance": data.group_tolerance,
            "created_at": int(time.time()),
        }
        config.setdefault("node_pools", []).append(pool)
        return dict(pool)

    pool = update_config(add_pool)
    return {"status": "success", "pool": pool}


@router.put("/reorder")
@handle_api_errors
def reorder_node_pools(data: ReorderNodePools, _: bool = Depends(verify_session)):
    def apply_order(config: dict):
        ensure_node_pool_ids(config)
        pools = config.get("node_pools", [])
        pool_by_id = {str(pool.get("id")): pool for pool in pools if isinstance(pool, dict)}
        ordered = [pool_by_id.pop(pool_id) for pool_id in data.order if pool_id in pool_by_id]
        ordered.extend(pool_by_id.values())
        config["node_pools"] = ordered

    update_config(apply_order)
    return {"status": "success"}


@router.put("/{pool_id}")
@handle_api_errors
def update_node_pool(pool_id: str, data: UpdateNodePool, _: bool = Depends(verify_session)):
    def apply_update(config: dict) -> dict:
        ensure_node_pool_ids(config)
        previous_config = deepcopy(config)
        pools = config.get("node_pools", [])
        pool = next((item for item in pools if isinstance(item, dict) and item.get("id") == pool_id), None)
        if pool is None:
            raise HTTPException(status_code=404, detail="节点池不存在")
        if data.name is not None and any(
            item is not pool
            and str(item.get("name") or "").casefold() == data.name.casefold()
            for item in pools
            if isinstance(item, dict)
        ):
            raise HTTPException(status_code=409, detail="节点池名称已存在")
        if data.name is not None:
            pool["name"] = data.name
        if data.nodes is not None:
            pool["nodes"] = _canonical_nodes(config, data.nodes)
        for field in ("group_strategy", "lb_strategy", "group_url", "group_interval", "group_tolerance", "enabled"):
            if field in data.model_fields_set:
                pool[field] = getattr(data, field)
        reconcile_node_pool_references(config, previous_config)
        return dict(pool)

    pool = update_config(apply_update)
    return {"status": "success", "pool": pool}


@router.put("/{pool_id}/toggle")
@handle_api_errors
def toggle_node_pool(pool_id: str, _: bool = Depends(verify_session)):
    def toggle(config: dict) -> bool:
        ensure_node_pool_ids(config)
        for pool in config.get("node_pools", []):
            if isinstance(pool, dict) and pool.get("id") == pool_id:
                pool["enabled"] = not bool(pool.get("enabled", True))
                return pool["enabled"]
        raise HTTPException(status_code=404, detail="节点池不存在")

    enabled = update_config(toggle)
    return {"status": "success", "enabled": enabled}


@router.delete("/{pool_id}")
@handle_api_errors
def delete_node_pool(pool_id: str, _: bool = Depends(verify_session)):
    def remove(config: dict):
        previous_config = deepcopy(config)
        pools = config.get("node_pools", [])
        remaining = [pool for pool in pools if not (isinstance(pool, dict) and pool.get("id") == pool_id)]
        if len(remaining) == len(pools):
            raise HTTPException(status_code=404, detail="节点池不存在")
        config["node_pools"] = remaining
        reconcile_node_pool_references(config, previous_config)

    update_config(remove)
    return {"status": "success"}
