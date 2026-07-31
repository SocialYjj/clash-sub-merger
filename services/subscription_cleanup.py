"""Delete a subscription and every persisted reference owned by it."""

from typing import Iterable

from services.node_reference_updates import (
    reconcile_subscription_node_references,
    remove_explicit_source_references,
)


def cleanup_deleted_subscription(
    config: dict,
    subscription_id: str,
    removed_nodes: Iterable[dict],
) -> dict:
    """Remove the source record, node references, schedules, and cached state."""
    subscriptions = config.get("subscriptions", [])
    subscription = next(
        (
            candidate
            for candidate in subscriptions
            if candidate.get("id") == subscription_id
        ),
        None,
    )
    if subscription is None:
        return {}

    subscription_name = str(subscription.get("name") or subscription_id)
    reconcile_subscription_node_references(
        config,
        subscription_id,
        old_nodes=removed_nodes,
        new_nodes=[],
        old_subscription_name=subscription_name,
        new_subscription_name=subscription_name,
    )
    remove_explicit_source_references(
        config,
        source_aliases={subscription_id},
        allocation_key=subscription_id,
    )

    config["subscriptions"] = [
        candidate
        for candidate in subscriptions
        if candidate.get("id") != subscription_id
    ]
    config["source_order"] = [
        source_reference
        for source_reference in config.get("source_order", [])
        if not (
            source_reference == subscription_id
            or (
                isinstance(source_reference, dict)
                and source_reference.get("id") == subscription_id
            )
        )
    ]

    for user in config.get("users", []):
        if not isinstance(user, dict):
            continue
        allocations = user.get("allocations")
        if isinstance(allocations, dict):
            allocations.pop(subscription_id, None)
        user.pop("sub_cache", None)

    for profile in config.get("speedtest_profiles", []) or []:
        if not isinstance(profile, dict):
            continue
        subscription_ids = profile.get("subscription_ids")
        if isinstance(subscription_ids, list):
            profile["subscription_ids"] = [
                stored_id
                for stored_id in subscription_ids
                if stored_id != subscription_id
            ]

    speedtest_results = config.get("speedtest_results")
    if isinstance(speedtest_results, dict):
        speedtest_results.pop(subscription_id, None)

    return dict(subscription)
