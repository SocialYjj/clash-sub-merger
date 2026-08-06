"""Build visual proxy-group configuration views for users and admin tokens."""

from copy import deepcopy
from typing import Optional

import yaml

from core.config import AppConfig
from helpers import load_subscription_yaml
from logger_config import get_logger
from services.name_transformer import NameTransformer
from services.node_visibility import is_node_enabled
from services.proxy_filter import ProxyFilter
from services.node_identity import custom_node_id, is_node_allocated, subscription_node_ids
from services.proxy_chain_references import list_proxy_chain_virtual_references


logger = get_logger(__name__)
SPECIAL_PROXY_NAMES = ("DIRECT", "REJECT")


def _select_template(config: dict, template_id: str, builtin_template: dict) -> tuple[str, dict]:
    if template_id == "builtin":
        selected_template = deepcopy(builtin_template)
        override = config.get("builtin_template_override", {})
        for field in ("header", "suffix", "proxy_groups"):
            if field in override:
                selected_template[field] = deepcopy(override[field])
        return "builtin", selected_template

    for custom_template in config.get("templates", []):
        if custom_template.get("id") == template_id:
            return template_id, deepcopy(custom_template)

    return "builtin", deepcopy(builtin_template)


def _append_unique(node_names: list[str], seen_names: set[str], node_name: str) -> None:
    if node_name and node_name not in seen_names:
        seen_names.add(node_name)
        node_names.append(node_name)


def _collect_available_nodes(
    config: dict,
    allocations: Optional[dict],
    *,
    reserved_group_names: set[str],
) -> tuple[list[str], dict[str, str]]:
    """Collect final node names; ``None`` allocations means unrestricted admin access."""
    node_names: list[str] = []
    seen_names: set[str] = set()
    chain_reference_ids: dict[str, str] = {}

    for subscription in config.get("subscriptions", []):
        if not subscription.get("enabled", True):
            continue

        subscription_id = subscription.get("id")
        allocation = ["*"] if allocations is None else allocations.get(subscription_id, [])
        if not allocation:
            continue

        try:
            subscription_yaml = load_subscription_yaml(
                subscription_id,
                AppConfig.YAML_SOURCE_DIR,
                use_cache=True,
            )
        except Exception as exc:
            logger.warning("Failed to load subscription %s for group editor: %s", subscription_id, exc)
            continue

        subscription_nodes = subscription_yaml.get("proxies", [])
        subscription_ids = subscription_node_ids(subscription_id, subscription_nodes)
        for node_index, proxy in enumerate(subscription_nodes):
            if not isinstance(proxy, dict) or not is_node_enabled(proxy):
                continue
            if not ProxyFilter.is_valid_proxy(proxy):
                continue

            original_name = proxy.get("name", "")
            final_name = NameTransformer.transform_name(
                proxy,
                subscription.get("name", "Subscription"),
            ).get("name", original_name)
            if is_node_allocated(
                final_name,
                allocation,
                subscription_ids[node_index],
            ) or is_node_allocated(original_name, allocation):
                _append_unique(node_names, seen_names, final_name)

    custom_allocation = ["*"] if allocations is None else allocations.get("custom_nodes", [])
    if custom_allocation:
        for custom_node in config.get("custom_nodes", []):
            if not isinstance(custom_node, dict) or not is_node_enabled(custom_node):
                continue
            if not ProxyFilter.is_valid_proxy(custom_node):
                continue

            original_name = custom_node.get("name", "")
            final_name = NameTransformer.transform_name(custom_node, "Custom").get("name", original_name)
            if is_node_allocated(
                final_name,
                custom_allocation,
                custom_node_id(custom_node),
            ) or is_node_allocated(original_name, custom_allocation):
                _append_unique(node_names, seen_names, final_name)

    for reference in list_proxy_chain_virtual_references(
        config,
        base_node_names=seen_names,
        reserved_group_names=reserved_group_names,
    ):
        if not reference.enabled:
            continue
        allocation = ["*"] if allocations is None else allocations.get(reference.source_id, [])
        if is_node_allocated(reference.name, allocation, reference.stable_id):
            _append_unique(node_names, seen_names, reference.name)
            chain_reference_ids[reference.name] = reference.stable_id

    return node_names, chain_reference_ids


def build_group_config_view(
    config: dict,
    subject: dict,
    *,
    allocations: Optional[dict],
    builtin_template: dict,
) -> dict:
    template_id, selected_template = _select_template(
        config,
        subject.get("template_id", "builtin"),
        builtin_template,
    )
    reserved_group_names = {
        str(group.get("name"))
        for group in selected_template.get("proxy_groups", [])
        if isinstance(group, dict) and group.get("name")
    }
    available_nodes, chain_reference_ids = _collect_available_nodes(
        config,
        allocations,
        reserved_group_names=reserved_group_names,
    )
    chain_reference_names = {
        stable_id: display_name
        for display_name, stable_id in chain_reference_ids.items()
    }
    selectable_nodes = [*SPECIAL_PROXY_NAMES, *available_nodes]
    saved_group_config = subject.get("group_config", {})
    groups = []

    for template_group in selected_template.get("proxy_groups", []):
        if not isinstance(template_group, dict):
            continue

        group_name = template_group.get("name", "")
        if not group_name:
            continue
        editable = template_group.get("_editable", True)
        saved_nodes = saved_group_config.get(group_name)
        if isinstance(saved_nodes, list):
            current_nodes = [
                chain_reference_names.get(reference, reference)
                for reference in saved_nodes
            ]
        elif editable:
            current_nodes = list(available_nodes)
        else:
            current_nodes = list(template_group.get("proxies", []))
        groups.append({
            "name": group_name,
            "type": template_group.get("type", "select"),
            "editable": editable,
            "icon": template_group.get("_icon", ""),
            "description": template_group.get("_description", ""),
            "current_nodes": current_nodes,
            "available_nodes": list(selectable_nodes) if editable else [],
        })

    return {
        "template_id": template_id,
        "template_name": selected_template.get("name", "内置模板"),
        "groups": groups,
        "chain_reference_ids": chain_reference_ids,
    }


def render_group_config_preview(group_view: dict) -> str:
    preview_groups = [
        {
            "name": group["name"],
            "type": group["type"],
            "proxies": group["current_nodes"],
        }
        for group in group_view.get("groups", [])
    ]
    return yaml.safe_dump(
        {"proxy-groups": preview_groups},
        allow_unicode=True,
        sort_keys=False,
    )
