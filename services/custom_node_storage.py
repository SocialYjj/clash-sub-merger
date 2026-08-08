"""Transactional persistence for custom nodes and their derived YAML source."""

from __future__ import annotations

from copy import deepcopy
from typing import Callable, TypeVar

from core.config import AppConfig
from core.database import load_config, update_config
from helpers import save_subscription_yaml
from services.node_reference_updates import reconcile_custom_node_references
from services.node_visibility import clear_user_subscription_caches, is_node_enabled
from services.proxy_filter import ProxyFilter
from services.subscription_refresh_lock import subscription_write_slot
from services.subscription_storage import (
    restore_subscription_content,
    snapshot_subscription_content,
)


T = TypeVar("T")

_CUSTOM_NODE_METADATA_FIELDS = {
    "id",
    "link",
    "last_latency",
    "last_latency_time",
    "last_speed",
    "last_peak_speed",
    "last_speed_time",
    "last_peak_speed_time",
    "exit_ip",
    "geoip",
    "region",
    "city",
    "enabled",
}


def write_custom_nodes_yaml(nodes: list[dict]) -> None:
    """Rebuild the generated custom-node source from persisted configuration."""
    proxies = []
    for node in nodes or []:
        if not isinstance(node, dict) or not is_node_enabled(node):
            continue
        proxy = {
            key: value
            for key, value in node.items()
            if key not in _CUSTOM_NODE_METADATA_FIELDS
        }
        sanitized_proxy = ProxyFilter.sanitize_proxy(proxy)
        if sanitized_proxy and sanitized_proxy.get("type"):
            proxies.append(sanitized_proxy)
    save_subscription_yaml(
        "custom_nodes",
        {"proxies": proxies},
        AppConfig.YAML_SOURCE_DIR,
    )


def rebuild_custom_nodes_yaml() -> None:
    """Rebuild the derived file from the latest configuration."""
    write_custom_nodes_yaml(load_config().get("custom_nodes", []))


def update_custom_nodes(mutator: Callable[[dict], T]) -> T:
    """Atomically update custom nodes, references, and the derived YAML file."""
    with subscription_write_slot("custom_nodes"):
        previous_yaml = snapshot_subscription_content(
            "custom_nodes",
            AppConfig.YAML_SOURCE_DIR,
        )

        try:
            def apply_custom_node_update(config: dict) -> T:
                old_nodes = deepcopy(config.get("custom_nodes", []))
                mutation_response = mutator(config)
                new_nodes = config.get("custom_nodes", [])
                reconcile_custom_node_references(
                    config,
                    old_nodes=old_nodes,
                    new_nodes=new_nodes,
                )
                clear_user_subscription_caches(config)

                # Write the derived source before config.json is replaced. If
                # either write fails, the outer rollback restores this file and
                # update_config leaves the previous config in place.
                write_custom_nodes_yaml(new_nodes)
                return mutation_response

            return update_config(apply_custom_node_update)
        except BaseException:
            restore_subscription_content(
                "custom_nodes",
                AppConfig.YAML_SOURCE_DIR,
                previous_yaml,
            )
            raise
