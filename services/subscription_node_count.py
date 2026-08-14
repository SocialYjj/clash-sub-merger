"""Canonical node counting for persisted subscription records.

Subscription cards, refresh responses and generated Clash output must use the
same definition of an effective node: a structurally valid Clash proxy that
has not been disabled in the management UI.
"""

from collections.abc import Iterable

from services.node_visibility import filter_enabled_nodes
from services.proxy_filter import ProxyFilter


def get_effective_subscription_nodes(nodes: Iterable[dict] | None) -> list[dict]:
    """Return enabled nodes that can be emitted by the Clash pipeline."""

    return filter_enabled_nodes(
        ProxyFilter.filter_proxies(list(nodes or [])),
        strip=True,
    )


def count_effective_subscription_nodes(nodes: Iterable[dict] | None) -> int:
    """Count nodes represented by the effective Clash subscription output."""

    return len(get_effective_subscription_nodes(nodes))
