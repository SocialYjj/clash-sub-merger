"""Pure helpers for subscription response headers and download filenames."""

import os
from urllib.parse import quote


def _safe_download_filename(value: object, fallback: str, extension: str) -> str:
    """Return a path-safe attachment filename while preserving custom names."""
    raw = str(value or "").strip()
    raw = os.path.basename(raw.replace("\\", "/"))
    if raw.lower().endswith((".yaml", ".yml", ".txt")):
        raw = raw.rsplit(".", 1)[0]
    safe = "".join(char for char in raw if char.isalnum() or char in " _-" or "\u4e00" <= char <= "\u9fff")
    safe = safe.strip(" .") or fallback
    return f"{safe}.{extension.lstrip('.')}"


def _safe_export_label(value: object, fallback: str = "unnamed") -> str:
    """Keep export diagnostics useful without copying credentials or URIs."""

    text = str(value or fallback).replace("\r", " ").replace("\n", " ").strip()
    lowered = text.lower()
    if any(marker in lowered for marker in ("://", "@", "token=", "password=", "uuid=")):
        return fallback
    return text[:160] or fallback


def _singbox_diagnostics_header(diagnostics, max_length: int = 2048) -> str:
    """Return URL-encoded diagnostics safe for common proxy header limits."""

    summaries = []
    for diagnostic in diagnostics:
        name = _safe_export_label(getattr(diagnostic, "name", "unnamed"))
        reason = _safe_export_label(getattr(diagnostic, "reason", "unspecified"), "unspecified")
        kind = _safe_export_label(getattr(diagnostic, "kind", "node"), "node")
        summaries.append(f"{kind}:{name}: {reason}")

    encoded = quote("; ".join(summaries), safe="")
    if len(encoded) <= max_length:
        return encoded
    # Never cut through a percent-encoded byte; add an explicit truncation marker.
    marker = quote("; diagnostics truncated", safe="")
    prefix = encoded[: max(0, max_length - len(marker))]
    while prefix.endswith("%") or (len(prefix) >= 2 and prefix[-2] == "%"):
        prefix = prefix[:-1]
    return prefix + marker


def _v2ray_diagnostics_header(issues: list[dict], max_length: int = 2048) -> str:
    """Encode bounded V2Ray skip diagnostics without exposing node contents."""

    summaries = []
    for issue in issues:
        name = _safe_export_label(issue.get("name"))
        proxy_type = _safe_export_label(issue.get("type"), "unknown")
        reason = _safe_export_label(issue.get("reason"), "unsupported_configuration")
        summaries.append(f"{proxy_type}:{name}: {reason}")

    encoded = quote("; ".join(summaries), safe="")
    if len(encoded) <= max_length:
        return encoded
    marker = quote("; diagnostics truncated", safe="")
    prefix = encoded[: max(0, max_length - len(marker))]
    while prefix.endswith("%") or (len(prefix) >= 2 and prefix[-2] == "%"):
        prefix = prefix[:-1]
    return prefix + marker


def build_common_response_headers(
    *,
    profile_title: str,
    content_disposition_filename: str,
    total_upload: int,
    total_download: int,
    total_traffic: int,
    total_expire: int,
) -> dict[str, str]:
    """Build the response headers shared by every subscription output format."""
    return {
        "Cache-Control": "private, no-store, max-age=0",
        "Pragma": "no-cache",
        "Vary": "User-Agent",
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(content_disposition_filename)}",
        "profile-title": profile_title,
        "profile-update-interval": "24",
        "subscription-userinfo": f"upload={total_upload}; download={total_download}; total={total_traffic}; expire={total_expire}",
    }
