"""Build working Mihomo local-SOCKS listener configurations."""

from __future__ import annotations

from collections.abc import Iterable


class SocksExportError(ValueError):
    """Raised when SOCKS export options or proxy data are invalid."""


_DIRECT_PROXY_REFERENCES = {"DIRECT", "REJECT", "BLOCK"}


def parse_excluded_ports(value: str | None) -> set[int]:
    """Parse comma-separated ports and inclusive port ranges."""
    if value is None or not str(value).strip():
        return set()

    excluded: set[int] = set()
    normalized = str(value).replace("，", ",")
    for raw_item in normalized.split(","):
        item = raw_item.strip()
        if not item:
            raise SocksExportError("Excluded ports contain an empty item")
        if "-" in item:
            parts = [part.strip() for part in item.split("-")]
            if len(parts) != 2 or not all(parts):
                raise SocksExportError(f"Invalid excluded port range: {item}")
            try:
                first, last = (int(part) for part in parts)
            except ValueError as exc:
                raise SocksExportError(f"Invalid excluded port range: {item}") from exc
            if first > last:
                raise SocksExportError(f"Excluded port range must be ascending: {item}")
            if first < 1 or last > 65535:
                raise SocksExportError(f"Excluded port is outside 1-65535: {item}")
            excluded.update(range(first, last + 1))
            continue

        try:
            port = int(item)
        except ValueError as exc:
            raise SocksExportError(f"Invalid excluded port: {item}") from exc
        if port < 1 or port > 65535:
            raise SocksExportError(f"Excluded port is outside 1-65535: {item}")
        excluded.add(port)
    return excluded


def allocate_listener_ports(count: int, start_port: int, excluded_ports: set[int]) -> list[int]:
    """Allocate consecutive ports while skipping all excluded ports."""
    if count < 0:
        raise SocksExportError("Proxy count cannot be negative")
    if start_port < 1 or start_port > 65535:
        raise SocksExportError("Start port must be between 1 and 65535")

    ports: list[int] = []
    candidate = start_port
    while len(ports) < count:
        if candidate > 65535:
            raise SocksExportError("Not enough available ports after the start port")
        if candidate not in excluded_ports:
            ports.append(candidate)
        candidate += 1
    return ports


def _select_dialer_proxy_groups(
    proxy_groups: Iterable[dict],
    exportable_proxies: list[dict],
) -> list[dict]:
    """Return the group closure required by exported ``dialer-proxy`` links.

    A chain proxy may use a proxy group as its dialer.  Omitting that group
    leaves a syntactically valid YAML file that Mihomo rejects during config
    validation.  Unrelated groups are kept out of the SOCKS export, while
    nested groups and valid direct members are retained recursively.
    """
    available_proxy_names = {
        str(proxy.get("name"))
        for proxy in exportable_proxies
        if isinstance(proxy, dict) and proxy.get("name")
    }

    source_groups = [
        group
        for group in (proxy_groups or [])
        if isinstance(group, dict) and group.get("name")
    ]
    groups_by_name: dict[str, dict] = {}
    for group in source_groups:
        group_name = str(group["name"])
        if group_name not in groups_by_name:
            groups_by_name[group_name] = group

    required_group_names: set[str] = set()
    for proxy in exportable_proxies:
        if not isinstance(proxy, dict):
            continue
        dialer_proxy = str(proxy.get("dialer-proxy") or "").strip()
        if (
            not dialer_proxy
            or dialer_proxy in available_proxy_names
            or dialer_proxy in _DIRECT_PROXY_REFERENCES
        ):
            continue
        if dialer_proxy not in groups_by_name:
            proxy_name = str(proxy.get("name") or "unnamed")
            raise SocksExportError(
                f"Proxy [{proxy_name}] dialer-proxy [{dialer_proxy}] not found"
            )
        required_group_names.add(dialer_proxy)

    selected_groups: dict[str, dict] = {}
    pending_group_names = list(required_group_names)
    while pending_group_names:
        group_name = pending_group_names.pop()
        if group_name in selected_groups:
            continue

        source_group = groups_by_name.get(group_name)
        if source_group is None:
            raise SocksExportError(f"Required proxy group [{group_name}] not found")

        members: list[str] = []
        raw_members = source_group.get("proxies", []) or []
        if not isinstance(raw_members, (list, tuple)):
            raw_members = []
        for raw_member in raw_members:
            member_name = str(raw_member)
            if (
                member_name in available_proxy_names
                or member_name in _DIRECT_PROXY_REFERENCES
            ):
                if member_name not in members:
                    members.append(member_name)
                continue
            if member_name in groups_by_name:
                if member_name not in members:
                    members.append(member_name)
                if member_name not in selected_groups:
                    pending_group_names.append(member_name)

        if not members:
            raise SocksExportError(
                f"Proxy group [{group_name}] has no available members"
            )

        copied_group = dict(source_group)
        copied_group["proxies"] = members
        selected_groups[group_name] = copied_group

    return [
        selected_groups[group_name]
        for group_name in groups_by_name
        if group_name in selected_groups
    ]


def build_socks_config(
    proxies: Iterable[dict],
    proxy_groups: Iterable[dict],
    *,
    start_port: int,
    excluded_ports: set[int],
    dns_config: dict,
    clean_proxy,
) -> dict:
    """Build a direct-listener SOCKS configuration with valid chain references."""
    exportable_proxies = []
    for proxy in proxies or []:
        if not isinstance(proxy, dict):
            continue
        # Traffic summaries are display-only pseudo-nodes, not proxies.  Strip
        # surrounding whitespace so copied provider labels cannot leak into
        # listeners or consume an automatically allocated port.
        if str(proxy.get("name") or "").strip().startswith("📊"):
            continue
        exportable_proxies.append(clean_proxy(proxy))
    if not exportable_proxies:
        raise SocksExportError("No exportable proxy nodes")

    listener_ports = allocate_listener_ports(
        len(exportable_proxies),
        start_port,
        excluded_ports,
    )
    listeners = [
        {
            "name": f"mixed{index}",
            "type": "mixed",
            "port": port,
            "proxy": proxy.get("name", ""),
        }
        for index, (proxy, port) in enumerate(zip(exportable_proxies, listener_ports))
    ]

    config = {
        "allow-lan": True,
        "dns": dns_config,
        "listeners": listeners,
        "proxies": exportable_proxies,
    }
    required_groups = _select_dialer_proxy_groups(proxy_groups, exportable_proxies)
    if required_groups:
        config["proxy-groups"] = required_groups
    return config
