"""Format-specific response renderers for the subscription endpoint.

Phases (d) and (k) of the ``/sub`` pipeline: normalize the requested output
format (query alias + user-agent sniffing) and render the final response for
each supported format.
"""

import base64
import json
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import quote

import yaml
from fastapi import HTTPException
from fastapi.responses import PlainTextResponse

from services.link_exporter import export_proxy_link
from services.node_visibility import YAMLDumper
from services.singbox_export import (
    SingboxExportError,
    build_singbox_config_with_diagnostics,
)
from services.socks_export import SocksExportError, build_socks_config, parse_excluded_ports

from .headers import (
    _safe_download_filename,
    _safe_export_label,
    _singbox_diagnostics_header,
    _v2ray_diagnostics_header,
    build_common_response_headers,
)

try:
    from yaml import CSafeLoader as YAMLLoader
except ImportError:  # pragma: no cover - depends on optional PyYAML C extension
    from yaml import SafeLoader as YAMLLoader


@dataclass(frozen=True)
class RenderContext:
    """Subject/auth values and traffic totals shared by every format renderer."""

    sub_name: str
    user_info: Optional[dict]
    admin_token_info: Optional[dict]
    auth: dict
    total_upload: int
    total_download: int
    total_traffic: int
    total_expire: int


def normalize_requested_format(format: Optional[str], user_agent: Optional[str]) -> str:
    """Normalize the requested format, sniffing it from the user agent."""
    # Keep ``base64`` as a backward-compatible input alias, while public
    # subscription links use the protocol-oriented name ``v2ray``.
    format = format.strip().lower() if format else None
    if format == "base64":
        format = "v2ray"
    if format == "yaml":
        format = "clash"
    if format is None:
        ua_lower = (user_agent or "").lower()
        if "sing-box" in ua_lower or "singbox" in ua_lower:
            format = "singbox"
        elif any(kw in ua_lower for kw in ["clash", "stash", "shadowrocket", "quantumult", "surge", "loon"]):
            format = "clash"
        else:
            format = "v2ray"
    supported_formats = {"v2ray", "clash", "singbox", "socks", "socks-manual"}
    if format not in supported_formats:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Unsupported subscription format",
                "format": format,
                "supported": ["v2ray", "clash", "singbox", "socks"],
            },
        ) from None
    return format


def compute_traffic_totals(enabled_subs: list[dict]) -> tuple[int, int, int, int]:
    """Calculate aggregated traffic info from all subscriptions."""
    total_upload = sum(s.get("upload", 0) or 0 for s in enabled_subs)
    total_download = sum(s.get("download", 0) or 0 for s in enabled_subs)
    total_traffic = sum(s.get("total", 0) or 0 for s in enabled_subs)
    # Use the earliest expire time (ignore 0 which means permanent/unknown)
    expire_times = [s.get("expire", 0) or 0 for s in enabled_subs if (s.get("expire", 0) or 0) > 0]
    total_expire = min(expire_times) if expire_times else 0
    return total_upload, total_download, total_traffic, total_expire


def render_v2ray_response(
    *,
    proxies: list,
    user_allocations: Optional[dict],
    chain_dependency_names: set,
    ctx: RenderContext,
    logger,
) -> PlainTextResponse:
    """V2Ray/v2rayN subscription output. The response is still the
    standard Base64-encoded URI list expected by v2rayN; ``v2ray``
    makes that protocol choice explicit in the URL and UI.
    """
    links = []
    skipped_issues = []
    for proxy in proxies:
        if proxy.get("name", "").startswith("📊"):
            continue
        if user_allocations is not None and proxy.get("name") in chain_dependency_names:
            skipped_issues.append(
                {
                    "name": _safe_export_label(proxy.get("name"), "unnamed"),
                    "type": str(proxy.get("type") or "unknown"),
                    "reason": "chain_dependency_not_allocated",
                }
            )
            continue
        if proxy.get("dialer-proxy") or proxy.get("type") == "group":
            # v2rayN's Base64 subscription importer accepts a list
            # of standalone share links only.  A chain node or
            # proxy group cannot be represented without silently
            # losing its routing relationship, so omit it while
            # keeping the remaining leaf nodes importable.
            skipped_issues.append(
                {
                    "name": _safe_export_label(proxy.get("name"), "unnamed"),
                    "type": str(proxy.get("type") or "chain"),
                    "reason": "chain_not_supported",
                }
            )
            continue
        export_result = export_proxy_link(proxy)
        if export_result.link:
            links.append(export_result.link)
        else:
            skipped_issues.append(
                {
                    "name": _safe_export_label(proxy.get("name"), "unnamed"),
                    "type": proxy.get("type", "unknown"),
                    "reason": export_result.reason or "unsupported_configuration",
                }
            )
    if skipped_issues:
        logger.warning(
            "V2Ray export skipped %s node(s): %s",
            len(skipped_issues),
            ", ".join(f"{issue['type']}:{issue['name']} ({issue['reason']})" for issue in skipped_issues[:20]),
        )
    if not links:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "No standalone proxy nodes can be represented in V2Ray format",
                "nodes": [issue["name"] for issue in skipped_issues[:50]],
                "count": len(skipped_issues),
                "issues": skipped_issues[:50],
            },
        ) from None
    content = base64.b64encode("\n".join(links).encode()).decode()

    # Get custom config name
    encoded_name = quote(ctx.sub_name)
    subject = ctx.user_info or ctx.admin_token_info or {}
    filename = _safe_download_filename(
        subject.get("sub_filename") or ctx.auth.get("sub_filename"),
        ctx.sub_name or "subscription",
        "txt",
    )

    return PlainTextResponse(
        content,
        media_type="text/plain; charset=utf-8",
        headers={
            **build_common_response_headers(
                profile_title=encoded_name,
                content_disposition_filename=filename,
                total_upload=ctx.total_upload,
                total_download=ctx.total_download,
                total_traffic=ctx.total_traffic,
                total_expire=ctx.total_expire,
            ),
            "x-v2ray-skipped-nodes": str(len(skipped_issues)),
            "x-v2ray-export-diagnostics": _v2ray_diagnostics_header(skipped_issues),
        },
    )


def render_singbox_response(
    *,
    proxies: list,
    proxy_groups: list,
    ctx: RenderContext,
    logger,
) -> PlainTextResponse:
    """Sing-box JSON output. Chain nodes are represented with detour
    and transit pools with selector/urltest outbounds.
    """
    try:
        singbox_config, skipped_nodes = build_singbox_config_with_diagnostics(
            proxies,
            proxy_groups,
        )
    except SingboxExportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if skipped_nodes:
        logger.warning(
            "Sing-box export applied %s diagnostic adjustment(s): %s",
            len(skipped_nodes),
            ", ".join(_safe_export_label(item.name) for item in skipped_nodes[:20]),
        )

    subject = ctx.user_info or ctx.admin_token_info or {}
    filename = _safe_download_filename(
        subject.get("sub_filename") or ctx.auth.get("sub_filename"),
        ctx.sub_name or "singbox-config",
        "json",
    )
    return PlainTextResponse(
        json.dumps(singbox_config, ensure_ascii=False, indent=2) + "\n",
        media_type="application/json; charset=utf-8",
        headers={
            **build_common_response_headers(
                profile_title=quote(ctx.sub_name),
                content_disposition_filename=filename,
                total_upload=ctx.total_upload,
                total_download=ctx.total_download,
                total_traffic=ctx.total_traffic,
                total_expire=ctx.total_expire,
            ),
            "x-singbox-skipped-nodes": str(sum(item.kind == "node" for item in skipped_nodes)),
            "x-singbox-export-diagnostics": _singbox_diagnostics_header(skipped_nodes),
        },
    )


def render_socks_response(
    *,
    proxies: list,
    proxy_groups: list,
    header: str,
    start_port: int,
    exclude_ports: Optional[str],
    filter_underscore_fields: Callable,
    ctx: RenderContext,
    logger,
) -> PlainTextResponse:
    """SOCKS output. ``socks-manual`` remains accepted as a compatibility
    alias, but both names now use automatic allocation with optional
    start/excluded ports.
    """
    subject_filename = (ctx.user_info or ctx.admin_token_info or {}).get("sub_filename") or ctx.auth.get("sub_filename")
    safe_filename = _safe_download_filename(
        subject_filename,
        ctx.sub_name or "socks-config",
        "yaml",
    )
    # The SOCKS exporter owns the final node-boundary filter so
    # traffic-summary pseudo-nodes cannot consume listener ports.
    socks_proxies = list(proxies)

    dns_config = None
    try:
        header_yaml = yaml.load(header, Loader=YAMLLoader)
        if isinstance(header_yaml, dict) and isinstance(header_yaml.get("dns"), dict):
            dns_config = header_yaml["dns"]
    except Exception as exc:
        logger.warning("Failed to parse DNS from header: %s", exc)
    if dns_config is None:
        dns_config = {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["114.114.114.114"],
            "nameserver": ["https://doh.pub/dns-query"],
        }

    try:
        socks_config = build_socks_config(
            socks_proxies,
            proxy_groups,
            start_port=start_port,
            excluded_ports=parse_excluded_ports(exclude_ports),
            dns_config=dns_config,
            clean_proxy=filter_underscore_fields,
        )
    except SocksExportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    yaml_content = yaml.dump(
        socks_config,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        Dumper=YAMLDumper,
    )
    return PlainTextResponse(
        yaml_content,
        media_type="text/yaml; charset=utf-8",
        headers=build_common_response_headers(
            profile_title=quote(ctx.sub_name),
            content_disposition_filename=safe_filename,
            total_upload=ctx.total_upload,
            total_download=ctx.total_download,
            total_traffic=ctx.total_traffic,
            total_expire=ctx.total_expire,
        ),
    )


def render_clash_response(
    *,
    proxies: list,
    proxy_groups: list,
    traffic_info_names: list,
    header: str,
    suffix: str,
    config: dict,
    emitted_chain_reference_names: dict,
    filter_underscore_fields: Callable,
    ctx: RenderContext,
) -> PlainTextResponse:
    """Clash YAML format output (default)."""
    # Traffic summary entries are UI-only pseudo-nodes. They are
    # intentionally retained in the subscription metadata headers,
    # but must not be emitted as selectable proxies in a Clash config.
    traffic_info_name_set = {str(name).strip() for name in traffic_info_names if str(name).strip()}
    if traffic_info_name_set:
        proxies = [proxy for proxy in proxies if str(proxy.get("name") or "").strip() not in traffic_info_name_set]
        proxy_groups = [
            {
                **group,
                "proxies": [
                    proxy_name
                    for proxy_name in group.get("proxies", [])
                    if str(proxy_name).strip() not in traffic_info_name_set
                ],
            }
            for group in proxy_groups
        ]

    serialized_name = yaml.dump(
        {"name": ctx.sub_name},
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        Dumper=YAMLDumper,
    ).rstrip()
    output_parts = [serialized_name + "\n" + header.rstrip()]

    # Generate listeners based on port mappings
    port_mappings = config.get("port_mappings", {})
    if port_mappings:
        # Get current proxy names for validation
        proxy_names = {p.get("name", "") for p in proxies}
        proxy_names.update({g.get("name", "") for g in proxy_groups if isinstance(g, dict)})

        # Build listeners for valid mappings only
        listeners = []
        for node_reference, port in sorted(port_mappings.items(), key=lambda x: x[1]):
            node_name = emitted_chain_reference_names.get(
                node_reference,
                node_reference,
            )
            if node_name in proxy_names:
                listener = {"name": f"mixed-{port}", "type": "mixed", "port": port, "proxy": node_name}
                listeners.append(listener)

        if listeners:
            output_parts.append("\nlisteners:")
            for listener in listeners:
                output_parts.append(f"  - {json.dumps(listener, ensure_ascii=False, separators=(',', ':'))}")

    output_parts.append("\nproxies:")
    for proxy in proxies:
        output_parts.append(
            f"  - {json.dumps(filter_underscore_fields(proxy), ensure_ascii=False, separators=(',', ':'))}"
        )
    output_parts.append("\nproxy-groups:")
    for group in proxy_groups:
        output_parts.append(f"  - {json.dumps(group, ensure_ascii=False, separators=(',', ':'))}")

    if suffix:
        output_parts.append("\n" + suffix)

    # Get custom filename and config name
    # Priority: user's sub_filename > admin_token's sub_filename > global sub_filename
    if ctx.user_info and ctx.user_info.get("sub_filename"):
        filename = ctx.user_info["sub_filename"]
    elif ctx.admin_token_info and ctx.admin_token_info.get("sub_filename"):
        filename = ctx.admin_token_info["sub_filename"]
    else:
        filename = ctx.auth.get("sub_filename", "config.yaml")

    encoded_name = quote(ctx.sub_name)
    safe_filename = _safe_download_filename(filename, ctx.sub_name or "config", "yaml")

    yaml_content = "\n".join(output_parts)
    response_headers = build_common_response_headers(
        profile_title=encoded_name,
        content_disposition_filename=safe_filename,
        total_upload=ctx.total_upload,
        total_download=ctx.total_download,
        total_traffic=ctx.total_traffic,
        total_expire=ctx.total_expire,
    )

    return PlainTextResponse(yaml_content, media_type="text/yaml", headers=response_headers)
