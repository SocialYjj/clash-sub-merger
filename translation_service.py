"""统一的地点名称翻译服务。

GeoIP 服务只负责取得原始地点，具体的中文翻译由本模块按供应商优先级完成。
供应商凭据只保存在后端配置中，翻译结果按原文缓存，供应商失败时自动降级。
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

import httpx

from core.config import DATA_DIR, env_bool, env_int
from logger_config import get_logger

logger = get_logger(__name__)

TRANSLATION_CACHE_FILE = os.path.join(DATA_DIR, "translation_cache.json")
TRANSLATION_CACHE_TTL_SECONDS = env_int(
    "TRANSLATION_CACHE_TTL_SECONDS", 30 * 24 * 3600, minimum=60
)
TRANSLATION_TIMEOUT_SECONDS = env_int(
    "TRANSLATION_TIMEOUT_SECONDS", 8, minimum=1, maximum=60
)
TRANSLATION_MAX_CONCURRENCY = env_int(
    "TRANSLATION_MAX_CONCURRENCY", 4, minimum=1, maximum=32
)
TRANSLATION_TARGET_LANGUAGE = "zh-CN"

TRANSLATION_PROVIDER_IDS = (
    "google",
    "microsoft",
    "tencent",
    "openai",
)

_PROVIDER_DEFINITIONS: dict[str, dict[str, Any]] = {
    "google": {
        "name": "Google 翻译",
        "fields": ("endpoint",),
        "secret_fields": (),
        "required_fields": (),
        "default_endpoint": "https://translate.googleapis.com/",
    },
    "microsoft": {
        "name": "Microsoft Translator",
        "fields": ("endpoint",),
        "secret_fields": (),
        "required_fields": (),
        "default_endpoint": "https://edge.microsoft.com/translate/translatetext",
    },
    "tencent": {
        "name": "腾讯云机器翻译",
        "fields": ("secret_id", "secret_key"),
        "secret_fields": ("secret_key",),
        "required_fields": ("secret_id", "secret_key"),
        "default_endpoint": "https://tmt.tencentcloudapi.com/",
    },
    "openai": {
        "name": "OpenAI",
        "fields": ("endpoint", "api_key", "model"),
        "secret_fields": ("api_key",),
        "required_fields": ("api_key", "model"),
        "default_endpoint": "https://api.openai.com/v1/chat/completions",
    },
}

_ENV_PROVIDER_FIELDS: dict[str, dict[str, str]] = {
    "google": {
        "enabled": "GOOGLE_TRANSLATE_ENABLED",
        "endpoint": "GOOGLE_TRANSLATE_ENDPOINT",
    },
    "microsoft": {
        "enabled": "MICROSOFT_TRANSLATOR_ENABLED",
        "endpoint": "MICROSOFT_TRANSLATOR_ENDPOINT",
    },
    "tencent": {
        "enabled": "TENCENT_TRANSLATE_ENABLED",
        "secret_id": "TENCENT_SECRET_ID",
        "secret_key": "TENCENT_SECRET_KEY",
    },
    "openai": {
        "enabled": "OPENAI_TRANSLATE_ENABLED",
        "endpoint": "OPENAI_TRANSLATE_ENDPOINT",
        "api_key": "OPENAI_TRANSLATE_API_KEY",
        "model": "OPENAI_TRANSLATE_MODEL",
    },
}

_DEFAULT_PROVIDER_ORDER = list(TRANSLATION_PROVIDER_IDS)
_translation_runtime_config: dict[str, Any] = {
    "preferred_provider": "google",
    "provider_order": _DEFAULT_PROVIDER_ORDER.copy(),
    "providers": {},
}
_translation_cache: dict[str, dict[str, Any]] = {}
_translation_cache_lock = threading.RLock()
_translation_cache_save_lock = threading.Lock()
_translation_config_lock = threading.RLock()
_translation_semaphore = asyncio.Semaphore(TRANSLATION_MAX_CONCURRENCY)


def _default_provider_config(provider_id: str) -> dict[str, Any]:
    definition = _PROVIDER_DEFINITIONS[provider_id]
    provider_config: dict[str, Any] = {
        "enabled": provider_id == "google",
        "endpoint": definition["default_endpoint"],
    }
    for field_name in definition["fields"]:
        provider_config.setdefault(field_name, "")

    for field_name, env_name in _ENV_PROVIDER_FIELDS[provider_id].items():
        raw_value = os.environ.get(env_name)
        if raw_value is None:
            continue
        if field_name == "enabled":
            provider_config[field_name] = env_bool(env_name, provider_config[field_name])
        else:
            provider_config[field_name] = raw_value.strip()

    return provider_config


def _build_default_runtime_config() -> dict[str, Any]:
    return {
        "preferred_provider": os.environ.get("TRANSLATION_DEFAULT_PROVIDER", "google").strip()
        or "google",
        "provider_order": _parse_provider_order(
            os.environ.get("TRANSLATION_PROVIDER_ORDER", ",".join(_DEFAULT_PROVIDER_ORDER))
        ),
        "providers": {
            provider_id: _default_provider_config(provider_id)
            for provider_id in TRANSLATION_PROVIDER_IDS
        },
    }


def _parse_provider_order(value: Any) -> list[str]:
    if isinstance(value, str):
        candidates = [item.strip().lower() for item in value.split(",")]
    elif isinstance(value, (list, tuple)):
        candidates = [str(item).strip().lower() for item in value]
    else:
        candidates = []

    ordered: list[str] = []
    for provider_id in candidates:
        if provider_id in TRANSLATION_PROVIDER_IDS and provider_id not in ordered:
            ordered.append(provider_id)
    for provider_id in TRANSLATION_PROVIDER_IDS:
        if provider_id not in ordered:
            ordered.append(provider_id)
    return ordered


def _load_translation_cache() -> None:
    global _translation_cache
    try:
        with open(TRANSLATION_CACHE_FILE, "r", encoding="utf-8") as cache_file:
            persisted_cache = json.load(cache_file)
        if not isinstance(persisted_cache, dict):
            raise ValueError("translation cache root must be an object")
        now = time.time()
        valid_entries = {
            cache_key: cache_entry
            for cache_key, cache_entry in persisted_cache.items()
            if isinstance(cache_entry, dict)
            and isinstance(cache_entry.get("translation"), str)
            and now - float(cache_entry.get("timestamp", 0)) < TRANSLATION_CACHE_TTL_SECONDS
        }
        with _translation_cache_lock:
            _translation_cache = valid_entries
    except FileNotFoundError:
        return
    except Exception as exc:
        logger.warning("Failed to load translation cache: %s", type(exc).__name__)


def _save_translation_cache() -> None:
    temporary_file = f"{TRANSLATION_CACHE_FILE}.{os.getpid()}.tmp"
    with _translation_cache_save_lock:
        try:
            with _translation_cache_lock:
                cache_snapshot = deepcopy(_translation_cache)
            os.makedirs(os.path.dirname(TRANSLATION_CACHE_FILE), exist_ok=True)
            with open(temporary_file, "w", encoding="utf-8") as cache_file:
                json.dump(cache_snapshot, cache_file, ensure_ascii=False, indent=2)
                cache_file.flush()
                os.fsync(cache_file.fileno())
            try:
                os.chmod(temporary_file, 0o600)
            except OSError:
                pass
            os.replace(temporary_file, TRANSLATION_CACHE_FILE)
        except Exception as exc:
            logger.warning("Failed to save translation cache: %s", type(exc).__name__)
        finally:
            if os.path.exists(temporary_file):
                try:
                    os.remove(temporary_file)
                except OSError:
                    pass


def apply_translation_runtime_config(application_config: dict | None) -> dict:
    """Merge persisted translation settings with environment defaults."""
    global _translation_runtime_config
    default_config = _build_default_runtime_config()
    persisted = application_config.get("translation_config", {}) if isinstance(application_config, dict) else {}
    if not isinstance(persisted, dict):
        persisted = {}

    merged_providers = deepcopy(default_config["providers"])
    persisted_providers = persisted.get("providers", {})
    if isinstance(persisted_providers, dict):
        for provider_id, provider_values in persisted_providers.items():
            if provider_id not in merged_providers or not isinstance(provider_values, dict):
                continue
            for field_name in ("enabled", * _PROVIDER_DEFINITIONS[provider_id]["fields"]):
                if field_name in provider_values:
                    merged_providers[provider_id][field_name] = provider_values[field_name]

    provider_order = _parse_provider_order(persisted.get("provider_order", default_config["provider_order"]))
    preferred_provider = str(
        persisted.get("preferred_provider") or default_config["preferred_provider"]
    ).strip().lower()
    if preferred_provider not in TRANSLATION_PROVIDER_IDS:
        preferred_provider = provider_order[0]

    with _translation_config_lock:
        _translation_runtime_config = {
            "preferred_provider": preferred_provider,
            "provider_order": provider_order,
            "providers": merged_providers,
        }
    return get_translation_runtime_config()


def get_translation_runtime_config() -> dict:
    with _translation_config_lock:
        return deepcopy(_translation_runtime_config)


def get_translation_provider_definitions() -> list[dict[str, Any]]:
    """Return provider metadata without exposing credentials."""
    runtime_config = get_translation_runtime_config()
    public_providers: list[dict[str, Any]] = []
    for provider_id in TRANSLATION_PROVIDER_IDS:
        definition = _PROVIDER_DEFINITIONS[provider_id]
        provider_config = runtime_config["providers"].get(provider_id, {})
        public_provider = {
            "id": provider_id,
            "name": definition["name"],
            "fields": list(definition["fields"]),
            "enabled": bool(provider_config.get("enabled", False)),
            "configured": _provider_is_configured(provider_id, provider_config),
            "has_credentials": any(
                bool(provider_config.get(field_name))
                for field_name in definition["secret_fields"]
            ),
        }
        if "endpoint" in definition["fields"]:
            public_provider["endpoint"] = provider_config.get(
                "endpoint", definition["default_endpoint"]
            )
        if "region" in definition["fields"]:
            public_provider["region"] = provider_config.get("region", "")
        if "model" in definition["fields"]:
            public_provider["model"] = provider_config.get("model", "")
        public_providers.append(public_provider)
    return public_providers


def get_public_translation_config() -> dict[str, Any]:
    runtime_config = get_translation_runtime_config()
    return {
        "preferred_provider": runtime_config["preferred_provider"],
        "provider_order": runtime_config["provider_order"],
        "providers": get_translation_provider_definitions(),
    }


def _provider_is_configured(provider_id: str, provider_config: dict[str, Any]) -> bool:
    definition = _PROVIDER_DEFINITIONS[provider_id]
    if provider_id == "google":
        return True
    required_fields = definition["required_fields"]
    return all(str(provider_config.get(field_name) or "").strip() for field_name in required_fields)


def update_translation_runtime_config(
    preferred_provider: str | None = None,
    provider_order: list[str] | None = None,
    providers: dict[str, dict[str, Any]] | None = None,
) -> dict:
    """Update only validated translation settings and return the runtime copy."""
    global _translation_runtime_config
    with _translation_config_lock:
        updated_config = deepcopy(_translation_runtime_config)
        if preferred_provider is not None:
            normalized_preferred = preferred_provider.strip().lower()
            if normalized_preferred not in TRANSLATION_PROVIDER_IDS:
                raise ValueError("Unknown translation provider")
            updated_config["preferred_provider"] = normalized_preferred
        if provider_order is not None:
            updated_config["provider_order"] = _parse_provider_order(provider_order)
        if providers is not None:
            for provider_id, provider_values in providers.items():
                if provider_id not in TRANSLATION_PROVIDER_IDS:
                    raise ValueError("Unknown translation provider")
                if not isinstance(provider_values, dict):
                    raise ValueError("Translation provider settings must be objects")
                allowed_fields = {"enabled", *_PROVIDER_DEFINITIONS[provider_id]["fields"]}
                unknown_fields = set(provider_values) - allowed_fields
                if unknown_fields:
                    raise ValueError(f"Unsupported settings for translation provider {provider_id}")
                for field_name, field_value in provider_values.items():
                    if field_name == "enabled":
                        if not isinstance(field_value, bool):
                            raise ValueError("Translation provider enabled must be boolean")
                        updated_config["providers"][provider_id][field_name] = field_value
                    else:
                        if field_value is None:
                            continue
                        if not isinstance(field_value, str) or len(field_value) > 4096:
                            raise ValueError("Translation provider setting is invalid")
                        updated_config["providers"][provider_id][field_name] = field_value.strip()
        if updated_config["preferred_provider"] not in updated_config["provider_order"]:
            updated_config["provider_order"].insert(0, updated_config["preferred_provider"])
        _translation_runtime_config = updated_config
    return get_translation_runtime_config()


def _contains_chinese(text: str) -> bool:
    return any("\u3400" <= character <= "\u9fff" for character in text)


def _cache_key(source_text: str, context: str) -> str:
    return f"{TRANSLATION_TARGET_LANGUAGE}|{context}|{source_text.strip()}"


def _read_cached_translation(cache_key: str) -> str | None:
    with _translation_cache_lock:
        entry = _translation_cache.get(cache_key)
        if not isinstance(entry, dict):
            return None
        if time.time() - float(entry.get("timestamp", 0)) >= TRANSLATION_CACHE_TTL_SECONDS:
            _translation_cache.pop(cache_key, None)
            return None
        return str(entry.get("translation") or "").strip() or None


def get_cached_translation(source_text: str, context: str = "location") -> str | None:
    """Read a previously stored translation without contacting a provider."""
    normalized_text = str(source_text or "").strip()
    if not normalized_text:
        return None
    return _read_cached_translation(_cache_key(normalized_text, context))


async def translate_to_simplified_chinese(source_text: str, context: str = "location") -> str:
    """Translate one location label, preserving the source on failure."""
    normalized_text = str(source_text or "").strip()
    if not normalized_text or _contains_chinese(normalized_text):
        return normalized_text

    cache_key = _cache_key(normalized_text, context)
    cached_translation = _read_cached_translation(cache_key)
    if cached_translation:
        return cached_translation

    runtime_config = get_translation_runtime_config()
    provider_order = [runtime_config["preferred_provider"], *runtime_config["provider_order"]]
    attempted: set[str] = set()
    for provider_id in provider_order:
        if provider_id in attempted or provider_id not in TRANSLATION_PROVIDER_IDS:
            continue
        attempted.add(provider_id)
        provider_config = runtime_config["providers"].get(provider_id, {})
        if not provider_config.get("enabled", False) or not _provider_is_configured(provider_id, provider_config):
            continue
        try:
            async with _translation_semaphore:
                translated_text = await _translate_with_provider(
                    provider_id, normalized_text, context, provider_config
                )
        except Exception as exc:
            logger.debug(
                "Translation provider %s failed for %r: %s",
                provider_id,
                normalized_text,
                type(exc).__name__,
            )
            continue
        translated_text = _clean_translation_output(translated_text)
        if not translated_text:
            continue
        with _translation_cache_lock:
            _translation_cache[cache_key] = {
                "translation": translated_text,
                "provider": provider_id,
                "timestamp": time.time(),
            }
        await asyncio.to_thread(_save_translation_cache)
        return translated_text

    return normalized_text


def _clean_translation_output(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = " ".join(value.strip().split())
    if cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = cleaned.strip("`").strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'", "“", "‘"}:
        cleaned = cleaned[1:-1].strip()
    return cleaned[:500]


async def translate_location_fields(
    country_name: str = "",
    region_name: str = "",
    city_name: str = "",
    country_code: str = "",
) -> dict[str, str]:
    """Translate country, region and city concurrently."""
    normalized_country = str(country_name or "").strip()
    normalized_region = str(region_name or "").strip()
    normalized_city = str(city_name or "").strip()

    if len(normalized_country) == 2 and normalized_country.upper() == str(country_code or "").upper():
        normalized_country = _country_code_to_english_name(normalized_country)

    translated_country, translated_region, translated_city = await asyncio.gather(
        translate_to_simplified_chinese(normalized_country, "country") if normalized_country else asyncio.sleep(0, result=""),
        translate_to_simplified_chinese(normalized_region, "region") if normalized_region else asyncio.sleep(0, result=""),
        translate_to_simplified_chinese(normalized_city, "city") if normalized_city else asyncio.sleep(0, result=""),
    )
    return {
        "country": translated_country,
        "region": translated_region,
        "city": translated_city,
    }


def _country_code_to_english_name(country_code: str) -> str:
    try:
        import pycountry

        country = pycountry.countries.get(alpha_2=country_code.upper())
        if country is not None:
            return str(country.name)
    except Exception:
        pass
    return ""


async def _translate_with_provider(
    provider_id: str,
    source_text: str,
    context: str,
    provider_config: dict[str, Any],
) -> str:
    if provider_id == "google":
        return await _translate_google(source_text, provider_config)
    if provider_id == "microsoft":
        return await _translate_microsoft(source_text, provider_config)
    if provider_id == "tencent":
        return await _translate_tencent(source_text, provider_config)
    if provider_id == "openai":
        return await _translate_openai(source_text, provider_config)
    raise ValueError("Unknown translation provider")


def _get_google_translate_endpoint(provider_config: dict[str, Any]) -> str:
    endpoint = str(
        provider_config.get("endpoint")
        or _PROVIDER_DEFINITIONS["google"]["default_endpoint"]
    ).strip().rstrip("/")
    if not endpoint.endswith("/translate_a/single"):
        endpoint = f"{endpoint}/translate_a/single"
    return endpoint


async def _translate_google(source_text: str, provider_config: dict[str, Any]) -> str:
    endpoint = _get_google_translate_endpoint(provider_config)
    async with httpx.AsyncClient(timeout=TRANSLATION_TIMEOUT_SECONDS) as client:
        response = await client.get(
            endpoint,
            params={"client": "gtx", "sl": "auto", "tl": "zh-CN", "dt": "t", "q": source_text},
        )
    response.raise_for_status()
    response_payload = response.json()
    translated_parts = [
        str(segment[0])
        for segment in (response_payload[0] if isinstance(response_payload, list) else [])
        if isinstance(segment, list) and segment and segment[0]
    ]
    return "".join(translated_parts)


MICROSOFT_WEB_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _get_microsoft_translate_endpoint(provider_config: dict[str, Any]) -> str:
    endpoint = str(
        provider_config.get("endpoint")
        or _PROVIDER_DEFINITIONS["microsoft"]["default_endpoint"]
    ).strip().rstrip("/")
    if not endpoint.endswith("/translatetext"):
        endpoint = f"{endpoint}/translatetext"
    return endpoint


async def _translate_microsoft(source_text: str, provider_config: dict[str, Any]) -> str:
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": MICROSOFT_WEB_USER_AGENT,
    }
    async with httpx.AsyncClient(timeout=TRANSLATION_TIMEOUT_SECONDS) as client:
        response = await client.post(
            _get_microsoft_translate_endpoint(provider_config),
            params={"from": "", "to": "zh-Hans", "isEnterpriseClient": "false"},
            headers=request_headers,
            json=[source_text],
        )
    response.raise_for_status()
    response_payload = response.json()
    try:
        translated_text = response_payload[0]["translations"][0]["text"]
    except (IndexError, KeyError, TypeError) as exc:
        raise ValueError("Microsoft web translation response does not contain translated text") from exc
    if not str(translated_text).strip():
        raise ValueError("Microsoft web translation returned an empty result")
    return str(translated_text)


def _hmac_sha256(secret: bytes | str, message: str) -> bytes:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


async def _translate_tencent(source_text: str, provider_config: dict[str, Any]) -> str:
    endpoint = _PROVIDER_DEFINITIONS["tencent"]["default_endpoint"]
    parsed_endpoint = httpx.URL(endpoint)
    host = parsed_endpoint.host or "tmt.tencentcloudapi.com"
    service = "tmt"
    action = "TextTranslate"
    version = "2018-03-21"
    timestamp = int(time.time())
    date_value = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
    request_body = {
        "SourceText": source_text,
        "Source": "auto",
        "Target": "zh",
        "ProjectId": 0,
    }
    serialized_body = json.dumps(request_body, ensure_ascii=False, separators=(",", ":"))
    hashed_body = hashlib.sha256(serialized_body.encode("utf-8")).hexdigest()
    canonical_headers = f"content-type:application/json; charset=utf-8\nhost:{host}\n"
    signed_headers = "content-type;host"
    canonical_request = (
        f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed_body}"
    )
    credential_scope = f"{date_value}/{service}/tc3_request"
    string_to_sign = (
        "TC3-HMAC-SHA256\n"
        f"{timestamp}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )
    secret_date = _hmac_sha256("TC3" + provider_config["secret_key"], date_value)
    secret_service = _hmac_sha256(secret_date, service)
    secret_signing = _hmac_sha256(secret_service, "tc3_request")
    signature = hmac.new(
        secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    authorization = (
        f"TC3-HMAC-SHA256 Credential={provider_config['secret_id']}/{credential_scope},"
        f"SignedHeaders={signed_headers},Signature={signature}"
    )
    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Version": version,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Region": "ap-guangzhou",
    }
    async with httpx.AsyncClient(timeout=TRANSLATION_TIMEOUT_SECONDS) as client:
        response = await client.post(endpoint, headers=headers, content=serialized_body.encode("utf-8"))
    response.raise_for_status()
    response_payload = response.json()
    return str(response_payload["Response"]["TargetText"])


def _openai_endpoint(provider_config: dict[str, Any]) -> str:
    endpoint = str(
        provider_config.get("endpoint")
        or _PROVIDER_DEFINITIONS["openai"]["default_endpoint"]
    ).strip().rstrip("/")
    if not endpoint:
        raise ValueError("OpenAI endpoint is required")
    if not endpoint.lower().endswith("/chat/completions"):
        endpoint = f"{endpoint}/chat/completions"
    return endpoint


def _extract_openai_translation(response_payload: Any) -> str:
    if not isinstance(response_payload, dict):
        raise ValueError("OpenAI response must be an object")

    try:
        content = response_payload["choices"][0]["message"]["content"]
    except (IndexError, KeyError, TypeError) as exc:
        raise ValueError("OpenAI response does not contain translated text") from exc

    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        text_parts = [
            str(item.get("text", ""))
            for item in content
            if isinstance(item, dict) and item.get("type") == "text" and item.get("text")
        ]
        combined_text = "".join(text_parts).strip()
        if combined_text:
            return combined_text
    raise ValueError("OpenAI response does not contain translated text")


async def _translate_openai(source_text: str, provider_config: dict[str, Any]) -> str:
    api_key = str(provider_config.get("api_key") or "").strip()
    model = str(provider_config.get("model") or "").strip()
    if not api_key or not model:
        raise ValueError("OpenAI API key and model are required")

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    request_body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是地点名称翻译器。将用户提供的地点名称翻译为简体中文。"
                    "只返回翻译后的地点名称，不要解释、注释、引号或其他文字。"
                ),
            },
            {"role": "user", "content": source_text},
        ],
    }
    async with httpx.AsyncClient(timeout=TRANSLATION_TIMEOUT_SECONDS) as client:
        response = await client.post(
            _openai_endpoint(provider_config),
            headers=headers,
            json=request_body,
        )
    response.raise_for_status()
    return _extract_openai_translation(response.json())


async def test_translation_provider(provider_id: str, sample_text: str = "Mountain View") -> dict[str, Any]:
    """Execute a non-cached provider test for the settings page."""
    if provider_id not in TRANSLATION_PROVIDER_IDS:
        raise ValueError("Unknown translation provider")
    runtime_config = get_translation_runtime_config()
    provider_config = runtime_config["providers"].get(provider_id, {})
    if not _provider_is_configured(provider_id, provider_config):
        raise ValueError("Translation provider credentials are incomplete")
    translated_text = await _translate_with_provider(
        provider_id, sample_text, "city", provider_config
    )
    return {
        "provider_id": provider_id,
        "source": sample_text,
        "translation": _clean_translation_output(translated_text),
    }


_load_translation_cache()
apply_translation_runtime_config({})
