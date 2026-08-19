"""Translation provider configuration and test endpoints."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from core.database import load_config, update_config
from core.dependencies import verify_session
from helpers import handle_api_errors
from logger_config import get_logger

logger = get_logger(__name__)
router = APIRouter()


class TranslationConfigRequest(BaseModel):
    preferred_provider: str | None = Field(None, max_length=50)
    provider_order: list[str] | None = Field(None, max_length=20)
    providers: dict[str, dict[str, Any]] | None = None

    @field_validator("preferred_provider")
    @classmethod
    def normalize_preferred_provider(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("Preferred translation provider cannot be empty")
        return normalized

    @field_validator("provider_order")
    @classmethod
    def normalize_provider_order(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        return [str(value).strip().lower() for value in values]


class TranslationProviderTestRequest(BaseModel):
    text: str = Field("Mountain View", min_length=1, max_length=200)


def _validate_provider_endpoints(provider_updates: dict[str, dict[str, Any]] | None) -> None:
    if not provider_updates:
        return
    for provider_values in provider_updates.values():
        if not isinstance(provider_values, dict):
            continue
        endpoint = provider_values.get("endpoint")
        if endpoint is None or endpoint == "":
            continue
        if not isinstance(endpoint, str) or len(endpoint) > 4096:
            raise ValueError("Translation endpoint is invalid")
        parsed_endpoint = urlsplit(endpoint.strip())
        if parsed_endpoint.scheme not in {"http", "https"} or not parsed_endpoint.netloc:
            raise ValueError("Translation endpoint must be an HTTP or HTTPS URL")


@router.get("/config")
@handle_api_errors
def get_translation_config(_: bool = Depends(verify_session)):
    from translation_service import get_public_translation_config

    return get_public_translation_config()


@router.post("/config")
@handle_api_errors
def update_translation_config(
    request_data: TranslationConfigRequest,
    _: bool = Depends(verify_session),
):
    from translation_service import (
        TRANSLATION_PROVIDER_IDS,
        update_translation_runtime_config,
    )

    provider_updates = request_data.providers or {}
    unknown_provider_ids = set(provider_updates) - set(TRANSLATION_PROVIDER_IDS)
    if unknown_provider_ids:
        raise HTTPException(status_code=400, detail="Unknown translation provider")
    _validate_provider_endpoints(provider_updates)
    update_translation_runtime_config(
        preferred_provider=request_data.preferred_provider,
        provider_order=request_data.provider_order,
        providers=provider_updates,
    )

    def persist_translation_config(config: dict) -> None:
        translation_config = config.setdefault("translation_config", {})
        if request_data.preferred_provider is not None:
            translation_config["preferred_provider"] = request_data.preferred_provider
        if request_data.provider_order is not None:
            translation_config["provider_order"] = request_data.provider_order
        persisted_providers = translation_config.setdefault("providers", {})
        if not isinstance(persisted_providers, dict):
            persisted_providers = {}
            translation_config["providers"] = persisted_providers
        for provider_id, provider_values in provider_updates.items():
            provider_record = persisted_providers.setdefault(provider_id, {})
            if not isinstance(provider_record, dict):
                provider_record = {}
                persisted_providers[provider_id] = provider_record
            provider_record.update(provider_values)

    update_config(persist_translation_config)
    from translation_service import apply_translation_runtime_config, get_public_translation_config

    apply_translation_runtime_config(load_config())
    return {"status": "success", **get_public_translation_config()}


@router.post("/providers/{provider_id}/test")
@handle_api_errors
async def test_translation_provider(
    provider_id: str,
    request_data: TranslationProviderTestRequest | None = None,
    _: bool = Depends(verify_session),
):
    from translation_service import test_translation_provider as execute_provider_test

    sample_text = request_data.text if request_data is not None else "Mountain View"
    return await execute_provider_test(provider_id.strip().lower(), sample_text)
