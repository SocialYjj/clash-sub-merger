"""Traffic-summary pseudo nodes rendered at the top of every subscription."""

from datetime import datetime


def format_bytes(b):
    if not b or b == 0:
        return "0B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f}{unit}" if b != int(b) else f"{int(b)}{unit}"
        b /= 1024
    return f"{b:.1f}PB"


def format_expire(ts):
    if not ts or ts == 0:
        return "永久"

    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")


def build_traffic_info_nodes(enabled_subs: list[dict]) -> tuple[list[dict], list[str]]:
    """Build traffic-summary dummy nodes and their display names."""
    traffic_info_nodes = []
    traffic_info_names = []

    # Calculate aggregated total first
    agg_used = sum((s.get("upload", 0) or 0) + (s.get("download", 0) or 0) for s in enabled_subs)
    agg_total = sum(s.get("total", 0) or 0 for s in enabled_subs)

    # Add aggregated total node first (only traffic, no time)
    if agg_total > 0:
        agg_name = f"📊 总计 | {format_bytes(agg_used)}/{format_bytes(agg_total)}"
        traffic_info_names.append(agg_name)
        traffic_info_nodes.append({"name": agg_name, "type": "http", "server": "1.0.0.1", "port": 65535})

    # Add individual subscription traffic info
    for sub in enabled_subs:
        used = (sub.get("upload", 0) or 0) + (sub.get("download", 0) or 0)
        total = sub.get("total", 0) or 0
        expire = sub.get("expire", 0) or 0

        # Create info node name: "sub_name | used/total | expire_date"
        if total > 0:
            info_name = f"📊 {sub['name']} | {format_bytes(used)}/{format_bytes(total)} | {format_expire(expire)}"
        else:
            info_name = f"📊 {sub['name']} | {format_expire(expire)}"

        traffic_info_names.append(info_name)
        # Create a dummy HTTP node (looks valid but won't work, just for display)
        traffic_info_nodes.append({"name": info_name, "type": "http", "server": "1.0.0.1", "port": 65535})

    return traffic_info_nodes, traffic_info_names
