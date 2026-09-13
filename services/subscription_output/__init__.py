"""Subscription output route factory.

This package owns the `/sub` subscription generation endpoint.  The endpoint is
registered through a small factory so the legacy helpers that still live in
``server.py`` can be injected without creating import cycles.
"""

from services.vpngate import list_vpngate_nodes

from .router import create_subscription_output_router

__all__ = ["create_subscription_output_router", "list_vpngate_nodes"]
