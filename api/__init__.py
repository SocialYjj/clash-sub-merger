"""
API routers module
Organizes all API endpoints into logical groups
"""
from fastapi import APIRouter

# Import all routers
from .auth import router as auth_router
from .health import router as health_router
from .system import router as system_router
from .subscriptions import router as subscriptions_router
from .nodes import router as nodes_router
from .users import router as users_router
from .templates import router as templates_router
from .admin_tokens import router as admin_tokens_router
from .settings import router as settings_router, port_mappings_router
from .stats import router as stats_router
from .speedtest import router as speedtest_router
from .scheduler import router as scheduler_router
from .geoip import router as geoip_router
from .translation import router as translation_router
from .proxy_chains import router as proxy_chains_router
from .node_pools import router as node_pools_router
from .vpngate import router as vpngate_router

# Create main API router
api_router = APIRouter()

# Health endpoints (no prefix - /health, /metrics)
api_router.include_router(health_router, tags=["health"])

# Auth endpoints (/api/auth/*)
api_router.include_router(auth_router, prefix="/api/auth", tags=["auth"])

# System endpoints (/api/system/*)
api_router.include_router(system_router, prefix="/api/system", tags=["system"])

# Subscriptions endpoints (/api/subscriptions/*)
api_router.include_router(subscriptions_router, prefix="/api/subscriptions", tags=["subscriptions"])

# Nodes endpoints (/api/custom-nodes/*, /api/subscriptions/*/nodes/*)
api_router.include_router(nodes_router, prefix="/api", tags=["nodes"])

# Users endpoints (/api/users/*)
api_router.include_router(users_router, prefix="/api/users", tags=["users"])

# Templates endpoints (/api/templates/*)
api_router.include_router(templates_router, prefix="/api/templates", tags=["templates"])

# Admin tokens endpoints (/api/admin-tokens/*)
api_router.include_router(admin_tokens_router, prefix="/api/admin-tokens", tags=["admin-tokens"])

# Settings endpoints (/api/settings/*)
api_router.include_router(settings_router, prefix="/api/settings", tags=["settings"])

# Port mappings endpoints (/api/port-mappings/*)
api_router.include_router(port_mappings_router, prefix="/api/port-mappings", tags=["port-mappings"])

# Stats endpoints (/api/stats/*)
api_router.include_router(stats_router, prefix="/api/stats", tags=["stats"])

# Speedtest endpoints (/api/speedtest/*)
api_router.include_router(speedtest_router, prefix="/api/speedtest", tags=["speedtest"])

# Scheduler endpoints (/api/scheduler/*)
api_router.include_router(scheduler_router, prefix="/api/scheduler", tags=["scheduler"])

# GeoIP endpoints (/api/geoip/*)
api_router.include_router(geoip_router, prefix="/api/geoip", tags=["geoip"])

# Translation endpoints (/api/translation/*)
api_router.include_router(translation_router, prefix="/api/translation", tags=["translation"])

# Proxy chains endpoints (/api/proxy-chains/*)
api_router.include_router(proxy_chains_router, prefix="/api/proxy-chains", tags=["proxy-chains"])

# Configured node-pool endpoints (/api/node-pools/*)
api_router.include_router(node_pools_router, prefix="/api/node-pools", tags=["node-pools"])

# VPN Gate dynamic source endpoints (/api/vpngate/*)
api_router.include_router(vpngate_router, prefix="/api/vpngate", tags=["vpngate"])

__all__ = ['api_router']
