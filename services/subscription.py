"""
Subscription Parser Service
Parse various subscription formats to Clash config.

This module intentionally delegates all URI parsing to services.node_parser so
remote subscriptions, local subscriptions and manually pasted links preserve the
same protocol fields.
"""
import json
from typing import Optional

import yaml

from logger_config import get_logger
from services.node_parser import decode_base64 as decode_node_base64
from services.node_parser import parse_node_link

logger = get_logger(__name__)


class SubscriptionParser:
    """Parse YAML, Base64 and URI-list subscriptions to Clash config."""

    @staticmethod
    def decode_base64(content: str) -> str:
        """Safely decode Base64 using the canonical node-parser behavior."""
        try:
            return decode_node_base64(content)
        except Exception as e:
            logger.warning("Base64 decode failed: %s", e)
            return ""

    @staticmethod
    def parse_vmess(vmess_url: str) -> Optional[dict]:
        """Parse vmess:// link via the canonical parser."""
        return parse_node_link(vmess_url)

    @staticmethod
    def parse_ss(ss_url: str) -> Optional[dict]:
        """Parse ss:// link via the canonical parser."""
        return parse_node_link(ss_url)

    @staticmethod
    def parse_trojan(trojan_url: str) -> Optional[dict]:
        """Parse trojan:// link via the canonical parser."""
        return parse_node_link(trojan_url)

    @staticmethod
    def parse_vless(vless_url: str) -> Optional[dict]:
        """Parse vless:// link via the canonical parser."""
        return parse_node_link(vless_url)

    @staticmethod
    def parse_ssr(ssr_url: str) -> Optional[dict]:
        """Parse ssr:// link via the canonical parser."""
        return parse_node_link(ssr_url)

    @staticmethod
    def parse_hysteria2(hy2_url: str) -> Optional[dict]:
        """Parse hysteria2:// or hy2:// link via the canonical parser."""
        return parse_node_link(hy2_url)

    @staticmethod
    def _parse_yaml_config(content: str) -> Optional[dict]:
        """Return YAML config only when it is a Clash/Mihomo style mapping."""
        if not content:
            return None
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.debug("Content is not YAML format: %s", e)
            return None
        except Exception as e:
            logger.warning("Error parsing YAML: %s", e)
            return None

        if isinstance(data, dict) and 'proxies' in data:
            return data
        return None

    @staticmethod
    def _parse_json_proxy_line(line: str) -> Optional[dict]:
        """Parse one JSON proxy line used by some mixed subscription exports."""
        if not (line.startswith('{') and line.endswith('}')):
            return None
        try:
            proxy = json.loads(line)
        except json.JSONDecodeError:
            return None
        if isinstance(proxy, dict) and proxy.get('name') and proxy.get('type'):
            return proxy
        return None

    @staticmethod
    def parse_content(content: str) -> dict:
        """Try to parse YAML, Base64-wrapped YAML, or URI-list content."""
        content = (content or '').strip()
        if not content:
            return {}

        # 1. Direct Clash/Mihomo YAML.
        yaml_config = SubscriptionParser._parse_yaml_config(content)
        if yaml_config is not None:
            return yaml_config

        # 2. Base64-wrapped YAML or URI list. Some plain URI strings can be
        # technically decodable as garbage Base64, so keep the original content
        # as a fallback parse candidate too.
        decoded = SubscriptionParser.decode_base64(content) or content
        yaml_config = SubscriptionParser._parse_yaml_config(decoded)
        if yaml_config is not None:
            return yaml_config

        # 3. Parse each line with the canonical parser. This avoids the old
        # incomplete reimplementation that silently dropped TLS/Reality/xhttp/etc.
        proxies = []
        candidates = [decoded]
        if decoded != content:
            candidates.append(content)
        for candidate in candidates:
            for raw_line in candidate.splitlines():
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue

                proxy = parse_node_link(line) or SubscriptionParser._parse_json_proxy_line(line)
                if proxy:
                    proxies.append(proxy)
            if proxies:
                break

        if proxies:
            return {'proxies': proxies}

        return {}
