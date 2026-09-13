"""Template resolution for the subscription output endpoint.

Phase (e) of the ``/sub`` pipeline: resolve the header/suffix/proxy-groups for
the requested template id, including legacy templates and auto-migration of
old content-style templates.
"""

from dataclasses import dataclass
from typing import Callable, Optional

import yaml

from services.config_merger import ConfigMerger

try:
    from yaml import CSafeLoader as YAMLLoader
except ImportError:  # pragma: no cover - depends on optional PyYAML C extension
    from yaml import SafeLoader as YAMLLoader


@dataclass
class ResolvedTemplate:
    """Template assets resolved for one subscription request."""

    header: str
    suffix: str
    proxy_groups: Optional[list]  # Template-declared proxy-groups override, if any


def _update_template_record(update_config: Callable, current_template_id: str, updates: dict) -> None:
    def mutator(latest_config: dict):
        for latest_template in latest_config.get("templates", []):
            if latest_template.get("id") == current_template_id:
                latest_template.update(updates)
                latest_template.pop("content", None)
                return True
        return False

    update_config(mutator)


def resolve_template(
    config: dict,
    template_id: str,
    *,
    split_template: Callable[[str], tuple[str, str]],
    update_config: Callable,
    logger,
) -> ResolvedTemplate:
    """Resolve header/suffix/proxy-groups for ``template_id``."""
    template_proxy_groups = None  # Will store template's proxy-groups if available

    if template_id == "legacy":
        # Use legacy saved template
        tpl = config.get("template", {})
        header = tpl.get("header", ConfigMerger.DEFAULT_HEADER)
        suffix = tpl.get("suffix", ConfigMerger.DEFAULT_SUFFIX)
    elif template_id == "builtin":
        # Check for user customization of builtin template
        override = config.get("builtin_template_override")
        if override:
            header = override.get("header", ConfigMerger.DEFAULT_HEADER)
            suffix = override.get("suffix", ConfigMerger.DEFAULT_SUFFIX)
            template_proxy_groups = override.get("proxy_groups", [])
        else:
            header = ConfigMerger.DEFAULT_HEADER
            suffix = ConfigMerger.DEFAULT_SUFFIX
    else:
        # Find template by ID
        template = next((t for t in config.get("templates", []) if t["id"] == template_id), None)
        if template:
            # Check if template needs migration (only if both header and suffix are missing)
            needs_migration = ("header" not in template or "suffix" not in template) and "content" in template

            if needs_migration:
                # Auto-migrate old format templates
                try:
                    parsed = yaml.load(template["content"], Loader=YAMLLoader)
                    if isinstance(parsed, dict):
                        # Split the content
                        header, suffix = split_template(template["content"])
                        template["header"] = header
                        template["suffix"] = suffix
                        if "proxy_groups" not in template:
                            template["proxy_groups"] = parsed.get("proxy-groups", [])
                        # Remove old content field
                        del template["content"]
                        # Save migrated template (only once) without overwriting concurrent config changes
                        _update_template_record(
                            update_config,
                            template_id,
                            {
                                "header": header,
                                "suffix": suffix,
                                "proxy_groups": template.get("proxy_groups", []),
                            },
                        )
                        logger.info(f"Template {template_id} migrated successfully")
                except Exception as e:
                    logger.error(f"Template migration failed: {e}")
                    # If migration fails, use fallback
                    header = ConfigMerger.DEFAULT_HEADER
                    suffix = ConfigMerger.DEFAULT_SUFFIX
                    template_proxy_groups = None

            # Use template data (either already migrated or just migrated)
            if not needs_migration or ("header" in template and "suffix" in template):
                header = template.get("header", ConfigMerger.DEFAULT_HEADER)
                suffix = template.get("suffix", ConfigMerger.DEFAULT_SUFFIX)
                template_proxy_groups = template.get("proxy_groups")
        else:
            # Fallback to built-in
            header = ConfigMerger.DEFAULT_HEADER
            suffix = ConfigMerger.DEFAULT_SUFFIX

    return ResolvedTemplate(header=header, suffix=suffix, proxy_groups=template_proxy_groups)
