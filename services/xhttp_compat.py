"""Lossless conversion between Xray XHTTP ``extra`` and Mihomo options."""

from __future__ import annotations

import json
import re
from typing import Any


class XHTTPCompatibilityError(ValueError):
    """Raised when an XHTTP configuration cannot be converted without loss."""


_EMPTY_VALUES = (None, "", [], {})
_RANGE_RE = re.compile(r"^\d+(?:-\d+)?$")

_XHTTP_MODES = {"auto", "packet-up", "stream-up", "stream-one"}
_PADDING_PLACEMENTS = {"cookie", "header", "query", "queryInHeader"}
_PADDING_METHODS = {"repeat-x", "tokenish"}
_SESSION_PLACEMENTS = {"path", "cookie", "header", "query"}
_UPLINK_DATA_PLACEMENTS = {"auto", "body", "cookie", "header"}

_STRING_FIELDS = {
    "xPaddingBytes": "x-padding-bytes",
    "xPaddingKey": "x-padding-key",
    "xPaddingHeader": "x-padding-header",
    "xPaddingPlacement": "x-padding-placement",
    "xPaddingMethod": "x-padding-method",
    "uplinkHTTPMethod": "uplink-http-method",
    "uplinkHttpMethod": "uplink-http-method",
    "sessionIDPlacement": "session-placement",
    "sessionPlacement": "session-placement",
    "sessionIDKey": "session-key",
    "sessionKey": "session-key",
    "seqPlacement": "seq-placement",
    "seqKey": "seq-key",
    "uplinkDataPlacement": "uplink-data-placement",
    "uplinkDataKey": "uplink-data-key",
    "uplinkChunkSize": "uplink-chunk-size",
    "scMaxEachPostBytes": "sc-max-each-post-bytes",
    "scMinPostsIntervalMs": "sc-min-posts-interval-ms",
}

_CANONICAL_EXTRA_FIELDS = {
    "x-padding-bytes": "xPaddingBytes",
    "x-padding-key": "xPaddingKey",
    "x-padding-header": "xPaddingHeader",
    "x-padding-placement": "xPaddingPlacement",
    "x-padding-method": "xPaddingMethod",
    "uplink-http-method": "uplinkHTTPMethod",
    "session-placement": "sessionIDPlacement",
    "session-key": "sessionIDKey",
    "seq-placement": "seqPlacement",
    "seq-key": "seqKey",
    "uplink-data-placement": "uplinkDataPlacement",
    "uplink-data-key": "uplinkDataKey",
    "uplink-chunk-size": "uplinkChunkSize",
    "sc-max-each-post-bytes": "scMaxEachPostBytes",
    "sc-min-posts-interval-ms": "scMinPostsIntervalMs",
}

_BOOLEAN_FIELDS = {
    "noGRPCHeader": "no-grpc-header",
    "xPaddingObfsMode": "x-padding-obfs-mode",
}

_CANONICAL_BOOLEAN_FIELDS = {
    "no-grpc-header": "noGRPCHeader",
    "x-padding-obfs-mode": "xPaddingObfsMode",
}

_REUSE_FIELDS = {
    "maxConcurrency": "max-concurrency",
    "maxConnections": "max-connections",
    "cMaxReuseTimes": "c-max-reuse-times",
    "hMaxRequestTimes": "h-max-request-times",
    "hMaxReusableSecs": "h-max-reusable-secs",
}

_CANONICAL_REUSE_FIELDS = {value: key for key, value in _REUSE_FIELDS.items()}

_XHTTP_SCALAR_FIELDS = set(_CANONICAL_EXTRA_FIELDS) | set(_CANONICAL_BOOLEAN_FIELDS)
_DOWNLOAD_XHTTP_FIELDS = _XHTTP_SCALAR_FIELDS | {"path", "host", "headers", "reuse-settings"}
_TOP_LEVEL_KEYS = {"path", "host", "mode", "headers", "reuse-settings", "download-settings"} | _XHTTP_SCALAR_FIELDS
_DOWNLOAD_KEYS = _DOWNLOAD_XHTTP_FIELDS | {
    "server", "port", "tls", "alpn", "reality-opts", "skip-cert-verify",
    "fingerprint", "servername", "client-fingerprint",
}


def _has_value(value: Any) -> bool:
    return value not in _EMPTY_VALUES


def _require_mapping(value: Any, field: str) -> dict:
    if not isinstance(value, dict):
        raise XHTTPCompatibilityError(f"{field} must be an object")
    return value


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise XHTTPCompatibilityError(f"{field} must be a string")
    return value


def _require_string_choice(value: Any, field: str, choices: set[str]) -> str:
    value = _require_string(value, field)
    if value not in choices:
        raise XHTTPCompatibilityError(f"{field} has an unsupported value")
    return value


def _require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise XHTTPCompatibilityError(f"{field} must be a boolean")
    return value


def _range_to_mihomo(value: Any, field: str) -> str:
    if isinstance(value, bool):
        raise XHTTPCompatibilityError(f"{field} must be an integer range")
    if isinstance(value, int):
        if value < 0:
            raise XHTTPCompatibilityError(f"{field} must be a non-negative integer range")
        return str(value)
    if isinstance(value, str) and _RANGE_RE.fullmatch(value.strip()):
        normalized = value.strip()
        bounds = [int(part) for part in normalized.split("-")]
        if len(bounds) == 2 and bounds[1] < bounds[0]:
            raise XHTTPCompatibilityError(f"{field} range must not be descending")
        return normalized
    if isinstance(value, dict) and set(value) <= {"from", "to"} and value:
        start = value.get("from")
        end = value.get("to", start)
        if isinstance(start, bool) or isinstance(end, bool) or not isinstance(start, int) or not isinstance(end, int):
            raise XHTTPCompatibilityError(f"{field} must contain integer from/to values")
        if start < 0 or end < start:
            raise XHTTPCompatibilityError(f"{field} must contain a non-descending non-negative range")
        return str(start) if start == end else f"{start}-{end}"
    raise XHTTPCompatibilityError(f"{field} must be an integer range")


def _range_to_xray(value: Any, field: str) -> int | str:
    normalized = _range_to_mihomo(value, field)
    try:
        return int(normalized)
    except ValueError:
        return normalized


def _parse_headers(value: Any, field: str) -> dict[str, str]:
    headers = _require_mapping(value, field)
    normalized = {}
    for key, header_value in headers.items():
        if not isinstance(key, str) or not isinstance(header_value, str):
            raise XHTTPCompatibilityError(f"{field} must contain string keys and values")
        if key.lower() == "host":
            raise XHTTPCompatibilityError(f"{field} cannot contain Host")
        normalized[key] = header_value
    return normalized


def _parse_reuse_settings(value: Any, field: str) -> dict:
    xmux = _require_mapping(value, field)
    unknown = set(xmux) - (set(_REUSE_FIELDS) | {"hKeepAlivePeriod"})
    if unknown:
        raise XHTTPCompatibilityError(f"{field} contains unsupported fields: {', '.join(sorted(unknown))}")

    reuse = {}
    for source_key, target_key in _REUSE_FIELDS.items():
        if source_key in xmux:
            reuse[target_key] = _range_to_mihomo(xmux[source_key], f"{field}.{source_key}")
    if "hKeepAlivePeriod" in xmux:
        keep_alive = xmux["hKeepAlivePeriod"]
        if isinstance(keep_alive, bool) or not isinstance(keep_alive, int) or keep_alive < 0:
            raise XHTTPCompatibilityError(f"{field}.hKeepAlivePeriod must be a non-negative integer")
        reuse["h-keep-alive-period"] = keep_alive
    if _has_value(reuse.get("max-concurrency")) and _has_value(reuse.get("max-connections")):
        raise XHTTPCompatibilityError(
            f"{field}.maxConcurrency and {field}.maxConnections cannot both be specified"
        )
    return reuse


def _export_reuse_settings(value: Any, field: str) -> dict:
    reuse = _require_mapping(value, field)
    allowed = set(_CANONICAL_REUSE_FIELDS) | {"h-keep-alive-period"}
    unknown = set(reuse) - allowed
    if unknown:
        raise XHTTPCompatibilityError(f"{field} contains unsupported fields: {', '.join(sorted(unknown))}")

    xmux = {}
    for source_key, target_key in _CANONICAL_REUSE_FIELDS.items():
        if source_key in reuse:
            xmux[target_key] = _range_to_xray(reuse[source_key], f"{field}.{source_key}")
    if "h-keep-alive-period" in reuse:
        keep_alive = reuse["h-keep-alive-period"]
        if isinstance(keep_alive, bool) or not isinstance(keep_alive, int) or keep_alive < 0:
            raise XHTTPCompatibilityError(f"{field}.h-keep-alive-period must be a non-negative integer")
        xmux["hKeepAlivePeriod"] = keep_alive
    if _has_value(reuse.get("max-concurrency")) and _has_value(reuse.get("max-connections")):
        raise XHTTPCompatibilityError(
            f"{field}.max-concurrency and {field}.max-connections cannot both be specified"
        )
    return xmux


def _validate_scalar_combinations(values: dict, field: str, mode: str | None) -> None:
    choice_fields = {
        "x-padding-placement": _PADDING_PLACEMENTS,
        "x-padding-method": _PADDING_METHODS,
        "session-placement": _SESSION_PLACEMENTS,
        "seq-placement": _SESSION_PLACEMENTS,
        "uplink-data-placement": _UPLINK_DATA_PLACEMENTS,
    }
    for key, choices in choice_fields.items():
        if key in values:
            _require_string_choice(values[key], f"{field}.{key}", choices)

    if "uplink-http-method" in values:
        method = _require_string(values["uplink-http-method"], f"{field}.uplink-http-method")
        if not method.strip():
            raise XHTTPCompatibilityError(f"{field}.uplink-http-method cannot be empty")
        if method.upper() == "GET" and mode != "packet-up":
            raise XHTTPCompatibilityError(
                f"{field}.uplink-http-method GET requires packet-up mode"
            )

    data_placement = values.get("uplink-data-placement")
    if data_placement in {"cookie", "header"} and mode != "packet-up":
        raise XHTTPCompatibilityError(
            f"{field}.uplink-data-placement {data_placement} requires packet-up mode"
        )


def _parse_xhttp_fields(source: dict, target: dict, field: str) -> None:
    allowed = set(_STRING_FIELDS) | set(_BOOLEAN_FIELDS) | {"headers", "xmux"}
    unknown = set(source) - allowed
    if unknown:
        raise XHTTPCompatibilityError(f"{field} contains unsupported fields: {', '.join(sorted(unknown))}")

    for source_key, target_key in _STRING_FIELDS.items():
        if source_key not in source:
            continue
        value = source[source_key]
        if target_key in {"x-padding-bytes", "uplink-chunk-size", "sc-max-each-post-bytes", "sc-min-posts-interval-ms"}:
            target[target_key] = _range_to_mihomo(value, f"{field}.{source_key}")
        else:
            target[target_key] = _require_string(value, f"{field}.{source_key}")
    for source_key, target_key in _BOOLEAN_FIELDS.items():
        if source_key in source:
            target[target_key] = _require_bool(source[source_key], f"{field}.{source_key}")
    if "headers" in source:
        target["headers"] = _parse_headers(source["headers"], f"{field}.headers")
    if "xmux" in source:
        target["reuse-settings"] = _parse_reuse_settings(source["xmux"], f"{field}.xmux")


def _export_xhttp_fields(source: dict, field: str) -> dict:
    extra = {}
    for source_key, target_key in _CANONICAL_EXTRA_FIELDS.items():
        if source_key not in source:
            continue
        value = source[source_key]
        if source_key in {"x-padding-bytes", "uplink-chunk-size", "sc-max-each-post-bytes", "sc-min-posts-interval-ms"}:
            extra[target_key] = _range_to_xray(value, f"{field}.{source_key}")
        else:
            extra[target_key] = _require_string(value, f"{field}.{source_key}")
    for source_key, target_key in _CANONICAL_BOOLEAN_FIELDS.items():
        if source_key in source:
            extra[target_key] = _require_bool(source[source_key], f"{field}.{source_key}")
    if "headers" in source:
        extra["headers"] = _parse_headers(source["headers"], f"{field}.headers")
    if "reuse-settings" in source:
        extra["xmux"] = _export_reuse_settings(source["reuse-settings"], f"{field}.reuse-settings")
    return extra


def parse_xhttp_extra(extra: str | dict | None) -> dict:
    """Convert a v2rayN/Xray ``extra`` object into Mihomo ``xhttp-opts``."""
    if extra in (None, ""):
        return {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except (TypeError, ValueError) as exc:
            raise XHTTPCompatibilityError("extra must be valid JSON") from exc
    extra = _require_mapping(extra, "extra")

    allowed = set(_STRING_FIELDS) | set(_BOOLEAN_FIELDS) | {"headers", "xmux", "downloadSettings"}
    unknown = set(extra) - allowed
    if unknown:
        raise XHTTPCompatibilityError(f"extra contains unsupported fields: {', '.join(sorted(unknown))}")

    opts = {}
    root_fields = {key: value for key, value in extra.items() if key != "downloadSettings"}
    _parse_xhttp_fields(root_fields, opts, "extra")
    if "downloadSettings" in extra:
        opts["download-settings"] = _parse_download_settings(extra["downloadSettings"])
    return {key: value for key, value in opts.items() if _has_value(value) or isinstance(value, bool)}


def _parse_download_settings(value: Any) -> dict:
    settings = _require_mapping(value, "extra.downloadSettings")
    allowed = {"address", "port", "network", "security", "tlsSettings", "realitySettings", "xhttpSettings"}
    unknown = set(settings) - allowed
    if unknown:
        raise XHTTPCompatibilityError(
            f"extra.downloadSettings contains unsupported fields: {', '.join(sorted(unknown))}"
        )

    network = str(settings.get("network") or "xhttp").strip().lower()
    if network not in {"xhttp", "splithttp"}:
        raise XHTTPCompatibilityError("extra.downloadSettings.network must be xhttp")

    result = {}
    if "address" in settings:
        result["server"] = _require_string(settings["address"], "extra.downloadSettings.address")
    if "port" in settings:
        port = settings["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise XHTTPCompatibilityError("extra.downloadSettings.port must be an integer from 1 to 65535")
        result["port"] = port

    security = str(settings.get("security") or "").strip().lower()
    if security not in {"", "none", "tls", "reality"}:
        raise XHTTPCompatibilityError("extra.downloadSettings.security is unsupported")
    if security in {"tls", "reality"}:
        result["tls"] = True

    tls_settings = settings.get("tlsSettings")
    if tls_settings is not None:
        tls_settings = _require_mapping(tls_settings, "extra.downloadSettings.tlsSettings")
        allowed_tls = {"serverName", "fingerprint", "alpn", "allowInsecure", "pinnedPeerCertSha256"}
        unknown_tls = set(tls_settings) - allowed_tls
        if unknown_tls:
            raise XHTTPCompatibilityError(
                "extra.downloadSettings.tlsSettings contains unsupported fields: "
                + ", ".join(sorted(unknown_tls))
            )
        if "serverName" in tls_settings:
            result["servername"] = _require_string(
                tls_settings["serverName"], "extra.downloadSettings.tlsSettings.serverName"
            )
        if "fingerprint" in tls_settings:
            result["client-fingerprint"] = _require_string(
                tls_settings["fingerprint"], "extra.downloadSettings.tlsSettings.fingerprint"
            )
        if "alpn" in tls_settings:
            alpn = tls_settings["alpn"]
            if isinstance(alpn, str):
                alpn = [part.strip() for part in alpn.split(",") if part.strip()]
            if not isinstance(alpn, list) or any(not isinstance(part, str) or not part for part in alpn):
                raise XHTTPCompatibilityError("extra.downloadSettings.tlsSettings.alpn must be a string list")
            result["alpn"] = alpn
        if "allowInsecure" in tls_settings:
            result["skip-cert-verify"] = _require_bool(
                tls_settings["allowInsecure"], "extra.downloadSettings.tlsSettings.allowInsecure"
            )
        if "pinnedPeerCertSha256" in tls_settings:
            result["fingerprint"] = _require_string(
                tls_settings["pinnedPeerCertSha256"],
                "extra.downloadSettings.tlsSettings.pinnedPeerCertSha256",
            )

    reality_settings = settings.get("realitySettings")
    if reality_settings is not None:
        reality_settings = _require_mapping(reality_settings, "extra.downloadSettings.realitySettings")
        allowed_reality = {"publicKey", "shortId"}
        unknown_reality = set(reality_settings) - allowed_reality
        if unknown_reality:
            raise XHTTPCompatibilityError(
                "extra.downloadSettings.realitySettings contains unsupported fields: "
                + ", ".join(sorted(unknown_reality))
            )
        reality_opts = {}
        if "publicKey" in reality_settings:
            reality_opts["public-key"] = _require_string(
                reality_settings["publicKey"], "extra.downloadSettings.realitySettings.publicKey"
            )
        if "shortId" in reality_settings:
            reality_opts["short-id"] = _require_string(
                reality_settings["shortId"], "extra.downloadSettings.realitySettings.shortId"
            )
        result["reality-opts"] = reality_opts
        result["tls"] = True

    xhttp_settings = settings.get("xhttpSettings")
    if xhttp_settings is not None:
        xhttp_settings = _require_mapping(xhttp_settings, "extra.downloadSettings.xhttpSettings")
        allowed_xhttp = {"path", "host", "extra"} | set(_STRING_FIELDS) | set(_BOOLEAN_FIELDS) | {"headers", "xmux"}
        unknown_xhttp = set(xhttp_settings) - allowed_xhttp
        if unknown_xhttp:
            raise XHTTPCompatibilityError(
                "extra.downloadSettings.xhttpSettings contains unsupported fields: "
                + ", ".join(sorted(unknown_xhttp))
            )
        if "path" in xhttp_settings:
            result["path"] = _require_string(
                xhttp_settings["path"], "extra.downloadSettings.xhttpSettings.path"
            )
        if "host" in xhttp_settings:
            result["host"] = _require_string(
                xhttp_settings["host"], "extra.downloadSettings.xhttpSettings.host"
            )
        direct_fields = {key: value for key, value in xhttp_settings.items() if key not in {"path", "host", "extra"}}
        _parse_xhttp_fields(direct_fields, result, "extra.downloadSettings.xhttpSettings")
        if "extra" in xhttp_settings:
            nested_extra = _require_mapping(
                xhttp_settings["extra"], "extra.downloadSettings.xhttpSettings.extra"
            )
            if set(nested_extra) - {"xmux"}:
                raise XHTTPCompatibilityError(
                    "extra.downloadSettings.xhttpSettings.extra contains unsupported fields"
                )
            if "xmux" in nested_extra:
                if "reuse-settings" in result:
                    raise XHTTPCompatibilityError(
                        "extra.downloadSettings.xhttpSettings contains duplicate xmux settings"
                    )
                result["reuse-settings"] = _parse_reuse_settings(
                    nested_extra["xmux"], "extra.downloadSettings.xhttpSettings.extra.xmux"
                )

    return {key: value for key, value in result.items() if _has_value(value) or isinstance(value, bool)}


def xhttp_opts_to_extra(xhttp_opts: dict | None) -> dict:
    """Convert canonical Mihomo ``xhttp-opts`` into Xray ``extra`` JSON."""
    if xhttp_opts in (None, {}):
        return {}
    xhttp_opts = _require_mapping(xhttp_opts, "xhttp-opts")
    unknown = set(xhttp_opts) - _TOP_LEVEL_KEYS
    if unknown:
        raise XHTTPCompatibilityError(
            f"xhttp-opts contains unsupported fields: {', '.join(sorted(unknown))}"
        )

    for key in ("path", "host"):
        if key in xhttp_opts:
            _require_string(xhttp_opts[key], f"xhttp-opts.{key}")
    mode = None
    if "mode" in xhttp_opts:
        mode = _require_string_choice(xhttp_opts["mode"], "xhttp-opts.mode", _XHTTP_MODES)
    _validate_scalar_combinations(xhttp_opts, "xhttp-opts", mode)
    if mode == "stream-one" and "download-settings" in xhttp_opts:
        raise XHTTPCompatibilityError(
            "xhttp-opts.download-settings cannot be used with stream-one mode"
        )

    extra_source = {
        key: value
        for key, value in xhttp_opts.items()
        if key not in {"path", "host", "mode", "download-settings"}
    }
    extra = _export_xhttp_fields(extra_source, "xhttp-opts")
    if "download-settings" in xhttp_opts:
        extra["downloadSettings"] = _export_download_settings(xhttp_opts["download-settings"])
    return extra


def _export_download_settings(value: Any) -> dict:
    settings = _require_mapping(value, "xhttp-opts.download-settings")
    unknown = set(settings) - _DOWNLOAD_KEYS
    if unknown:
        raise XHTTPCompatibilityError(
            "xhttp-opts.download-settings contains unsupported fields: "
            + ", ".join(sorted(unknown))
        )

    _validate_scalar_combinations(settings, "xhttp-opts.download-settings", None)

    result = {"network": "xhttp"}
    if "server" in settings:
        result["address"] = _require_string(settings["server"], "xhttp-opts.download-settings.server")
    if "port" in settings:
        port = settings["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise XHTTPCompatibilityError("xhttp-opts.download-settings.port must be an integer from 1 to 65535")
        result["port"] = port

    reality_opts = settings.get("reality-opts")
    if reality_opts not in (None, {}):
        reality_opts = _require_mapping(reality_opts, "xhttp-opts.download-settings.reality-opts")
        unknown_reality = set(reality_opts) - {"public-key", "short-id"}
        if unknown_reality:
            raise XHTTPCompatibilityError(
                "xhttp-opts.download-settings.reality-opts contains unsupported fields: "
                + ", ".join(sorted(unknown_reality))
            )
        result["security"] = "reality"
        result["realitySettings"] = {}
        if "public-key" in reality_opts:
            result["realitySettings"]["publicKey"] = _require_string(
                reality_opts["public-key"], "xhttp-opts.download-settings.reality-opts.public-key"
            )
        if "short-id" in reality_opts:
            result["realitySettings"]["shortId"] = _require_string(
                reality_opts["short-id"], "xhttp-opts.download-settings.reality-opts.short-id"
            )
    elif settings.get("tls") is True:
        result["security"] = "tls"

    tls_fields = {
        "servername", "client-fingerprint", "alpn", "skip-cert-verify", "fingerprint"
    }
    if any(key in settings for key in tls_fields):
        tls_settings = {}
        if "servername" in settings:
            tls_settings["serverName"] = _require_string(
                settings["servername"], "xhttp-opts.download-settings.servername"
            )
        if "client-fingerprint" in settings:
            tls_settings["fingerprint"] = _require_string(
                settings["client-fingerprint"], "xhttp-opts.download-settings.client-fingerprint"
            )
        if "alpn" in settings:
            alpn = settings["alpn"]
            if isinstance(alpn, str):
                alpn = [part.strip() for part in alpn.split(",") if part.strip()]
            if not isinstance(alpn, list) or any(not isinstance(part, str) or not part for part in alpn):
                raise XHTTPCompatibilityError("xhttp-opts.download-settings.alpn must be a string list")
            tls_settings["alpn"] = alpn
        if "skip-cert-verify" in settings:
            tls_settings["allowInsecure"] = _require_bool(
                settings["skip-cert-verify"], "xhttp-opts.download-settings.skip-cert-verify"
            )
        if "fingerprint" in settings:
            tls_settings["pinnedPeerCertSha256"] = _require_string(
                settings["fingerprint"], "xhttp-opts.download-settings.fingerprint"
            )
        result["tlsSettings"] = tls_settings
        result.setdefault("security", "tls")

    xhttp_settings = {}
    if "path" in settings:
        xhttp_settings["path"] = _require_string(settings["path"], "xhttp-opts.download-settings.path")
    if "host" in settings:
        xhttp_settings["host"] = _require_string(settings["host"], "xhttp-opts.download-settings.host")
    transport_source = {
        key: value
        for key, value in settings.items()
        if key in _DOWNLOAD_XHTTP_FIELDS and key not in {"path", "host"}
    }
    xhttp_settings.update(_export_xhttp_fields(transport_source, "xhttp-opts.download-settings"))
    if xhttp_settings:
        result["xhttpSettings"] = xhttp_settings
    return result


def get_xhttp_invalid_reason(xhttp_opts: Any) -> str | None:
    """Validate the complete XHTTP tree using the same lossless converter."""
    try:
        xhttp_opts_to_extra(xhttp_opts)
    except XHTTPCompatibilityError:
        return "invalid-xhttp-options"
    return None
