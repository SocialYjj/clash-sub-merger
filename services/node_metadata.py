"""Fields owned by the management UI rather than proxy clients.

These values are persisted on some migrated nodes and are useful to the
management API, but Clash/Mihomo, v2rayN and sing-box must never receive them
as protocol options.
"""

NODE_METADATA_FIELDS = frozenset({
    # Stable references and source bookkeeping.
    "id",
    "link",
    "source",
    "source_id",
    "sourceId",
    "source_type",
    "sourceType",
    "idx",
    "index",
    "nodeKey",
    "node_key",
    "final_name",
    "pool_group_name",
    "chainId",
    "chain_id",
    "rowId",
    "row_id",
    "mapped_port",
    # UI validation and visibility state.
    "enabled",
    "valid",
    "invalid_reason",
    "display_name",
    # Saved region and test results.
    "last_latency",
    "last_latency_time",
    "last_speed",
    "last_speed_time",
    "last_peak_speed",
    "last_peak_speed_time",
    "latency",
    "speed",
    "peak_speed",
    "speed_error",
    "speedError",
    "test_error",
    "testError",
    "error",
    "errorMessage",
    "region_error",
    "regionError",
    "regionErrorMessage",
    "detected_region",
    "detectedRegion",
    "exit_ip",
    "ip_profile",
    "geoip",
    "region",
    "city",
    "flag",
    "country",
})


def strip_node_metadata(node: dict) -> dict:
    """Return a client-facing copy without persisted management metadata."""

    if not isinstance(node, dict):
        return node
    return {
        key: value
        for key, value in node.items()
        if key not in NODE_METADATA_FIELDS and not str(key).startswith("_")
    }
