"""
Subscription Parser Service
Unified subscription content parsing logic
"""
import base64
import re
import yaml
from typing import Tuple, List, Optional

from logger_config import get_logger
from services.node_parser import parse_node_link
from services.proxy_filter import ProxyFilter
from services.subscription_node_count import count_effective_subscription_nodes

logger = get_logger(__name__)

# Use C-accelerated safe YAML loader for better performance
try:
    from yaml import CSafeLoader as YAMLLoader, CSafeDumper as YAMLDumper
except ImportError:
    from yaml import SafeLoader as YAMLLoader, SafeDumper as YAMLDumper


class SubscriptionParseError(Exception):
    """Base exception for subscription parsing errors"""
    pass


class InvalidContentError(SubscriptionParseError):
    """Raised when content cannot be parsed"""
    pass


class YAMLParseError(SubscriptionParseError):
    """Raised when YAML parsing fails"""
    pass


class Base64DecodeError(SubscriptionParseError):
    """Raised when Base64 decoding fails"""
    pass


def pad_base64(value: str) -> str:
    """Add only the Base64 padding that is actually missing."""
    return value + '=' * (-len(value) % 4)


def try_decode_base64(content: str) -> Optional[str]:
    """
    Try to decode Base64 content.
    
    Args:
        content: String that might be Base64 encoded
        
    Returns:
        Decoded string if successful, None otherwise
        
    Raises:
        Base64DecodeError: If content is invalid Base64
    """
    try:
        normalized = ''.join(str(content).split())
        if not normalized or not re.fullmatch(r'[A-Za-z0-9+/=_-]+', normalized):
            return None
        padded = pad_base64(normalized)
        padded_bytes = padded.encode('ascii')
        decoded_bytes = base64.b64decode(padded_bytes, altchars=b'-_', validate=True)
        return decoded_bytes.decode('utf-8').strip()
    except UnicodeEncodeError:
        # Content contains non-ASCII characters, not Base64
        return None
    except UnicodeDecodeError as e:
        raise Base64DecodeError(f"Base64 decoded content is not valid UTF-8: {e}")
    except base64.binascii.Error:
        return None


def parse_yaml_proxies(content: str) -> Optional[List[dict]]:
    """
    Parse YAML content and extract proxies list.
    
    Args:
        content: YAML string
        
    Returns:
        List of proxy dicts if successful, None otherwise
        
    Raises:
        YAMLParseError: If YAML parsing fails unexpectedly
    """
    try:
        cfg = yaml.load(content, Loader=YAMLLoader)
        if cfg and isinstance(cfg, dict) and 'proxies' in cfg:
            proxies = cfg.get('proxies', [])
            if isinstance(proxies, list):
                return proxies
        return None
    except yaml.YAMLError as e:
        logger.debug(f"Content is not valid YAML: {e}")
        return None


def parse_uri_list(content: str) -> List[dict]:
    """
    Parse URI list content (ss://, vmess://, vless://, etc.)
    
    Args:
        content: String containing one URI per line
        
    Returns:
        List of parsed proxy dicts
    """
    proxies = []
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        proxy = parse_node_link(line)
        if proxy:
            proxies.append(proxy)
    
    return proxies


def proxies_to_yaml(proxies: List[dict]) -> str:
    """
    Convert proxies list to YAML string.
    
    Args:
        proxies: List of proxy dicts
        
    Returns:
        YAML string
    """
    return yaml.dump(
        {'proxies': proxies},
        allow_unicode=True,
        sort_keys=False,
        Dumper=YAMLDumper
    )


def parse_subscription_content(content: str) -> str:
    """
    Parse subscription content and return YAML format.
    Supports: YAML, Base64 encoded YAML, Base64 encoded URI list, plain URI list
    
    Args:
        content: Raw subscription content
        
    Returns:
        YAML formatted string
        
    Raises:
        InvalidContentError: If content cannot be parsed
    """
    content = content.strip()
    if not content:
        raise InvalidContentError("Empty content")
    
    # 1. Try parsing as YAML directly
    proxies = parse_yaml_proxies(content)
    if proxies is not None:
        logger.debug("Content is valid YAML format")
        return content
    
    # 2. Try Base64 decode
    decoded = try_decode_base64(content)
    if decoded:
        # 2a. Try decoded content as YAML
        proxies = parse_yaml_proxies(decoded)
        if proxies is not None:
            logger.debug("Decoded Base64 content is valid YAML")
            return decoded
        
        # 2b. Try decoded content as URI list
        proxies = parse_uri_list(decoded)
        if proxies:
            logger.debug(f"Parsed {len(proxies)} nodes from Base64 URI list")
            return proxies_to_yaml(proxies)
    
    # 3. Try as plain URI list
    proxies = parse_uri_list(content)
    if proxies:
        logger.debug(f"Parsed {len(proxies)} nodes from URI list")
        return proxies_to_yaml(proxies)
    
    raise InvalidContentError("Unable to parse content as YAML, Base64, or URI list")


def parse_local_subscription(content: str) -> Tuple[str, List[dict], int]:
    """
    Parse local subscription content.
    
    Args:
        content: Raw subscription content (YAML, Base64, or URI list)
        
    Returns:
        Tuple of (yaml_content, proxies_list, node_count)
        
    Raises:
        InvalidContentError: If content cannot be parsed
    """
    content = content.strip()
    if not content:
        raise InvalidContentError("Empty content")
    
    # YAML must be attempted before Base64: ordinary YAML may consist only of
    # characters that are also valid in a Base64 alphabet.
    proxies = parse_yaml_proxies(content)
    if proxies is not None:
        valid_count = count_effective_subscription_nodes(proxies)
        if valid_count <= 0:
            raise InvalidContentError("Subscription contains no valid proxy nodes")
        logger.info("Parsed %s nodes from YAML content", valid_count)
        return content, proxies, valid_count

    # 2. Try Base64 decode, including URL-safe Base64.
    decoded_content = try_decode_base64(content)
    if decoded_content:
        logger.debug("Successfully decoded Base64 content")
        proxies = parse_yaml_proxies(decoded_content)
        if proxies is not None:
            valid_count = count_effective_subscription_nodes(proxies)
            if valid_count <= 0:
                raise InvalidContentError("Subscription contains no valid proxy nodes")
            logger.info("Parsed %s nodes from Base64 YAML content", valid_count)
            return decoded_content, proxies, valid_count

    # 3. Try parsing as URI list
    uri_content = decoded_content or content
    proxies = parse_uri_list(uri_content)
    if proxies:
        yaml_content = proxies_to_yaml(proxies)
        valid_count = count_effective_subscription_nodes(proxies)
        if valid_count <= 0:
            raise InvalidContentError("Subscription contains no valid proxy nodes")
        logger.info("Parsed %s nodes from URI list", valid_count)
        return yaml_content, proxies, valid_count
    
    raise InvalidContentError("Unable to parse content as YAML, Base64, or URI list")


def parse_subscription_info(headers: dict) -> dict:
    """
    Parse subscription userinfo from headers.
    
    Args:
        headers: Response headers dict
        
    Returns:
        Dict with upload, download, total, expire fields
    """
    info = {'upload': 0, 'download': 0, 'total': 0, 'expire': 0}
    userinfo = headers.get('subscription-userinfo', '') or headers.get('Subscription-Userinfo', '')
    
    if not userinfo:
        return info
    
    for part in userinfo.split(';'):
        if '=' not in part:
            continue
        
        key, val = part.split('=', 1)
        try:
            info[key.strip().lower()] = int(val.strip())
        except ValueError:
            logger.debug(f"Invalid subscription info value for {key}: {val}")
    
    return info


def count_nodes(content: str) -> int:
    """
    Count number of nodes in YAML content.
    
    Args:
        content: YAML string
        
    Returns:
        Number of nodes, 0 if parsing fails
    """
    try:
        cfg = yaml.load(content, Loader=YAMLLoader)
        if cfg and isinstance(cfg, dict) and 'proxies' in cfg:
            proxies = cfg.get('proxies', [])
            if not isinstance(proxies, list):
                return 0
            count = count_effective_subscription_nodes(proxies)
            logger.debug(f"Counted {count} nodes in content")
            return count
    except yaml.YAMLError as e:
        logger.debug(f"Cannot count nodes - invalid YAML: {e}")
    return 0
