"""
Proxy Filter Service
Filter out invalid info nodes from proxy lists
"""
import ipaddress
import re
from typing import List, Optional
from core.proxy_compat import (
    normalize_alpn,
    normalize_certificate_pin,
    normalize_trojan_proxy,
    normalize_v2ray_transport_proxy,
)
from logger_config import get_logger
from services.xhttp_compat import get_xhttp_invalid_reason

logger = get_logger(__name__)


class ProxyFilter:
    """Proxy node filter - filter out invalid info nodes"""

    INFO_PREFIX_RE = re.compile(
        r'^\s*(?:建议|通知|公告|提示|说明|使用前|更新订阅|套餐到期|剩余流量)\s*[:：]?',
        re.IGNORECASE
    )
    INFO_DOMAIN_HINT_RE = re.compile(
        r'^\s*(?:最强备用|备用网址|备用地址|官网地址?|防丢失官网?|防失联官网?|'
        r'永久官网|永久地址|最新官网|最新地址|网址发布|域名发布|防丢失|防失联)\s*[:：]?\s*'
        r'(?:https?://)?(?:[A-Za-z0-9\u4e00-\u9fff-]+\.)+[A-Za-z]{2,}(?:/\S*)?\s*$',
        re.IGNORECASE
    )
    # Provider status banners are pseudo proxy names, not connection nodes.
    INFO_TIMESTAMP_RE = re.compile(
        r'^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s*'
        r'\(UTC[+-]\d{1,2}(?::?\d{2})?\)\s*$',
        re.IGNORECASE,
    )
    INFO_BALANCE_RE = re.compile(
        r'^\s*(?:balance|余额)\s*[:：]\s*'
        r'\d+(?:[.,]\d+)?\s*(?:[KMGTPE]i?B|B)\s*$',
        re.IGNORECASE,
    )
    INFO_WEBSITE_RE = re.compile(
        r'^\s*(?:website|网站|网址)\s*[:：]\s*'
        r'(?:https?://)?(?:[A-Za-z0-9\u4e00-\u9fff-]+\.)+[A-Za-z]{2,}(?:/\S*)?\s*$',
        re.IGNORECASE,
    )

    # 用于检测节点名中是否携带 URL（结合"官网"关键词识别信息节点）。
    _OFFICIAL_URL_RE = re.compile(r'https?://', re.IGNORECASE)

    # Always treat these as info nodes.
    HARD_INVALID_KEYWORDS = [
        '剩余流量', '套餐到期', '距离下次重置', '未到期', '使用前',
        '使用说明', '教程', '更新订阅', '公告', '通知', '客服',
        '续费', '购买', '工单', '咨询', '合作', '邀请', '返利',
        '免注册', '免费节点', '变动较大', '全超时', '更换客户端',
        '关注', '版本', '须知', '频道', '维护', '公众号'
    ]

    # These keywords are common in info nodes, but some providers also put them
    # in real node names such as "节点商城xx美国 --01". Those need extra checks.
    SOFT_INVALID_KEYWORDS = [
        '建议', '剩余', '到期', '重置', '流量', '过期', '订阅',
        '网址', '群组', 'Telegram', 'TG', '会员', '商城', '账号',
        '套餐', '优惠', '试用', '用户', '说明'
    ]
    
    # Region keywords for valid nodes starting with "Website"
    REGION_KEYWORDS = [
        '安道尔', '阿联酋', '阿富汗', '安提瓜和巴布达', '安圭拉', '阿尔巴尼亚', '亚美尼亚', '安哥拉',
        '南极洲', '阿根廷', '美属萨摩亚', '奥地利', '澳大利亚', '阿鲁巴', '奥兰群岛', '阿塞拜疆',
        '波黑', '巴巴多斯', '孟加拉国', '比利时', '布基纳法索', '保加利亚', '巴林', '布隆迪',
        '贝宁', '圣巴泰勒米', '百慕大', '文莱', '玻利维亚', '巴西', '巴哈马', '不丹',
        '博茨瓦纳', '白俄罗斯', '伯利兹', '加拿大', '刚果民主共和国', '中非共和国', '刚果共和国', '瑞士',
        '科特迪瓦', '库克群岛', '智利', '喀麦隆', '中国大陆', '哥伦比亚', '哥斯达黎加', '古巴',
        '佛得角', '库拉索', '塞浦路斯', '捷克', '德国', '吉布提', '丹麦', '多米尼克',
        '多米尼加', '阿尔及利亚', '厄瓜多尔', '爱沙尼亚', '埃及', '西撒哈拉', '厄立特里亚', '西班牙',
        '埃塞俄比亚', '芬兰', '斐济', '福克兰群岛', '密克罗尼西亚', '法罗群岛', '法国', '加蓬',
        '英国', '格林纳达', '格鲁吉亚', '根西岛', '加纳', '格陵兰岛', '冈比亚', '几内亚',
        '赤道几内亚', '希腊', '南乔治亚和南桑威奇群岛', '危地马拉', '关岛', '几内亚比绍', '圭亚那', '中国香港',
        '赫德岛和麦克唐纳群岛', '洪都拉斯', '克罗地亚', '海地', '匈牙利', '印尼', '爱尔兰', '以色列',
        '马恩岛', '印度', '英属印度洋领地', '伊拉克', '伊朗', '冰岛', '意大利', '泽西岛',
        '牙买加', '约旦', '日本', '肯尼亚', '吉尔吉斯斯坦', '柬埔寨', '基里巴斯', '科摩罗',
        '圣基茨和尼维斯', '朝鲜', '韩国', '科威特', '开曼群岛', '哈萨克斯坦', '老挝', '黎巴嫩',
        '圣卢西亚', '列支敦士登', '斯里兰卡', '利比里亚', '莱索托', '立陶宛', '卢森堡', '拉脱维亚',
        '利比亚', '摩洛哥', '摩纳哥', '摩尔多瓦', '黑山', '法属圣马丁', '马达加斯加', '马绍尔群岛',
        '北马其顿', '马里', '缅甸', '蒙古', '中国澳门', '北马里亚纳群岛', '毛里塔尼亚', '蒙特塞拉特',
        '马耳他', '毛里求斯', '马尔代夫', '马拉维', '墨西哥', '马来西亚', '莫桑比克', '纳米比亚',
        '新喀里多尼亚', '尼日尔', '诺福克岛', '尼日利亚', '尼加拉瓜', '荷兰', '挪威', '尼泊尔',
        '瑙鲁', '纽埃', '新西兰', '阿曼', '巴拿马', '秘鲁', '法属波利尼西亚', '巴布亚新几内亚',
        '菲律宾', '巴基斯坦', '波兰', '圣皮埃尔和密克隆', '皮特凯恩群岛', '波多黎各', '巴勒斯坦', '葡萄牙',
        '帕劳', '巴拉圭', '卡塔尔', '罗马尼亚', '塞尔维亚', '俄罗斯', '卢旺达', '沙特阿拉伯',
        '所罗门群岛', '塞舌尔', '苏丹', '瑞典', '新加坡', '圣赫勒拿', '斯洛文尼亚', '斯洛伐克',
        '塞拉利昂', '圣马力诺', '塞内加尔', '索马里', '苏里南', '南苏丹', '圣多美和普林西比', '萨尔瓦多',
        '荷属圣马丁', '叙利亚', '斯威士兰', '特克斯和凯科斯群岛', '乍得', '法属南部领地', '多哥', '泰国',
        '塔吉克斯坦', '东帝汶', '土库曼斯坦', '突尼斯', '汤加', '土耳其', '特立尼达和多巴哥', '中国台湾',
        '坦桑尼亚', '乌克兰', '乌干达', '美国', '乌拉圭', '乌兹别克斯坦', '梵蒂冈', '圣文森特和格林纳丁斯',
        '委内瑞拉', '英属维尔京群岛', '美属维尔京群岛', '越南', '瓦努阿图', '瓦利斯和富图纳', '萨摩亚', '科索沃',
        '也门', '南非', '赞比亚', '津巴布韦',
        # Common abbreviations and English names
        '香港', '台湾', '澳门', 'HK', 'TW', 'MO', 'JP', 'KR', 'SG', 'US', 'UK', 
        'DE', 'FR', 'CA', 'AU', 'RU', 'IN', 'TH', 'VN', 'MY', 'PH', 'ID',
        'CN', 'GB', 'IT', 'ES', 'PT', 'NL', 'BE', 'CH', 'AT', 'CZ', 'PL',
        'SE', 'NO', 'FI', 'DK', 'IE', 'NZ', 'BR', 'AR', 'CL', 'MX', 'TR',
        'SA', 'AE', 'IL', 'EG', 'ZA', 'NG', 'KE', 'UA', 'BY', 'KZ', 'UZ',
        '海外'
    ]
    
    STRONG_NODE_HINTS = [
        '节点', '备用', '家宽', '专线', '中转', '落地', '倍率',
        '游戏', '住宅', '原生'
    ]

    LINE_INDEX_RE = re.compile(r'--\s*\d+\b|\(\s*\d+\s*\)$')

    @staticmethod
    def _has_region_hint(name: str) -> bool:
        """Check whether a proxy name contains an actual region marker."""
        for region in ProxyFilter.REGION_KEYWORDS:
            # Short all-caps codes like US/JP need boundary checks, otherwise
            # they match random substrings in domains.
            if len(region) <= 3 and region.isupper():
                if re.search(rf'(?<![A-Za-z]){re.escape(region)}(?:\d+)?(?![A-Za-z])', name):
                    return True
                continue
            if region in name:
                return True
        return False

    @staticmethod
    def _has_node_identity(name: str) -> bool:
        """Detect strong signs that a name refers to a real line, not an info banner."""
        if ProxyFilter._has_region_hint(name):
            return True
        if ProxyFilter.LINE_INDEX_RE.search(name):
            return True
        if any(hint in name for hint in ProxyFilter.STRONG_NODE_HINTS):
            return True
        return False

    @staticmethod
    def get_invalid_reason(proxy: dict) -> Optional[str]:
        """Return invalid reason when a proxy is considered an info node."""
        if not proxy or 'name' not in proxy:
            return 'missing-name'

        name = str(proxy['name']).strip()
        if not name:
            return 'empty-name'

        if ProxyFilter.INFO_PREFIX_RE.match(name):
            return 'info-prefix'
        if ProxyFilter.INFO_DOMAIN_HINT_RE.match(name):
            return 'info-domain'
        if ProxyFilter.INFO_TIMESTAMP_RE.match(name):
            return 'info-timestamp'
        if ProxyFilter.INFO_BALANCE_RE.match(name):
            return 'info-balance'
        if ProxyFilter.INFO_WEBSITE_RE.match(name):
            return 'info-website'

        if name.startswith('官网'):
            return None if ProxyFilter._has_region_hint(name) else 'official-website'

        # 名称含"官网"且携带 URL，通常为机场信息节点（如"防丢失官网:https://xxx"）。
        # 要求无真实节点身份（地区/序号/线路关键词），避免误伤"官网香港01"类节点。
        if '官网' in name and ProxyFilter._OFFICIAL_URL_RE.search(name) \
                and not ProxyFilter._has_node_identity(name):
            return 'official-website-with-url'

        for keyword in ProxyFilter.HARD_INVALID_KEYWORDS:
            if keyword in name:
                return f'hard-keyword:{keyword}'

        for keyword in ProxyFilter.SOFT_INVALID_KEYWORDS:
            if keyword in name and not ProxyFilter._has_node_identity(name):
                return f'soft-keyword:{keyword}'

        return None

    @staticmethod
    def is_structurally_valid_proxy(proxy: dict) -> bool:
        """Check whether a node is valid independent of a target exporter."""
        if ProxyFilter.get_invalid_reason(proxy) is not None:
            return False
        raw_reason = ProxyFilter.get_structural_invalid_reason(proxy)
        if raw_reason is not None:
            return False
        sanitized = ProxyFilter.sanitize_proxy(proxy)
        return ProxyFilter.get_structural_invalid_reason(sanitized) is None

    @staticmethod
    def is_valid_proxy(proxy: dict) -> bool:
        """Check whether a node can be used by the primary Mihomo pipeline."""
        return ProxyFilter.is_structurally_valid_proxy(proxy) and (
            ProxyFilter.get_clash_incompatible_reason(proxy) is None
        )

    @staticmethod
    def is_clash_compatible_proxy(proxy: dict) -> bool:
        """Return whether a node can be emitted to a Mihomo/Clash config."""
        return ProxyFilter.is_valid_proxy(proxy)

    @staticmethod
    def get_target_invalid_reason(proxy: dict, target_format: str = 'clash') -> Optional[str]:
        """Return one diagnostic for a node at a named output boundary."""
        info_reason = ProxyFilter.get_invalid_reason(proxy)
        if info_reason:
            return info_reason
        structural_reason = ProxyFilter.get_structural_invalid_reason(proxy)
        if structural_reason:
            return structural_reason
        if str(target_format or '').strip().lower() in {'clash', 'mihomo'}:
            return ProxyFilter.get_clash_incompatible_reason(proxy)
        return None

    @staticmethod
    def _get_basic_proxy_invalid_reason(proxy: dict) -> Optional[str]:
        """Validate fields required before a format-specific exporter can inspect a node."""
        if not isinstance(proxy, dict):
            return 'invalid-proxy-object'

        proxy_type = str(proxy.get('type', '') or '').strip().lower()
        allowed_types = {
            'http', 'https', 'socks5', 'socks5h', 'ss', 'ssr', 'vmess',
            'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'wireguard',
            'snell', 'anytls', 'ssh', 'openvpn', 'direct', 'reject',
        }
        if not proxy_type:
            return 'missing-type'
        if proxy_type not in allowed_types:
            return 'unsupported-type'
        if not ProxyFilter._is_valid_server(proxy.get('server')):
            return 'invalid-server'

        port = proxy.get('port')
        if port is None or isinstance(port, bool):
            return 'missing-port'
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            return 'invalid-port'
        if not 1 <= port_number <= 65535:
            return 'invalid-port'

        required_fields = {
            'vless': ('uuid',),
            'vmess': ('uuid',),
            'trojan': ('password',),
            'hysteria2': ('password',),
            'anytls': ('password',),
            'ss': ('cipher', 'password'),
            'wireguard': ('private-key',),
            'openvpn': ('ca', 'cert', 'key'),
        }
        for field in required_fields.get(proxy_type, ()):
            if not str(proxy.get(field) or '').strip():
                return f'missing-{field}'

        if proxy_type == 'tuic':
            token = str(proxy.get('token') or '').strip()
            uuid = str(proxy.get('uuid') or '').strip()
            password = str(proxy.get('password') or '').strip()
            if not token and (not uuid or not password):
                return 'missing-tuic-credentials'
        return None

    @staticmethod
    def filter_minimally_valid_proxies(proxies: List[dict]) -> List[dict]:
        """Keep nodes with enough data for V2Ray/sing-box to report or export them.

        These formats have capabilities that are intentionally not part of the
        Mihomo structural schema. Their exporters must receive such nodes so
        they can return a precise, safe skip diagnostic instead of silently
        dropping them during source loading.
        """
        valid_proxies = []
        for proxy in proxies or []:
            if not ProxyFilter.is_minimally_valid_proxy(proxy):
                continue
            valid_proxies.append(ProxyFilter.sanitize_proxy(proxy))
        return valid_proxies

    @staticmethod
    def is_minimally_valid_proxy(proxy: dict) -> bool:
        """Return whether a node is safe to pass to a format-specific exporter."""
        if ProxyFilter.get_invalid_reason(proxy) is not None:
            return False
        return ProxyFilter.is_structurally_valid_proxy(proxy)

    @staticmethod
    def get_clash_incompatible_reason(proxy: dict) -> Optional[str]:
        """Return a reason why a structurally valid node cannot be emitted to Mihomo.

        v2rayN preserves some certificate pins that Mihomo cannot parse.  Such
        nodes remain available to the V2Ray exporter, but must not be emitted
        to Clash with the pin silently removed.
        """
        if not isinstance(proxy, dict):
            return 'invalid-proxy-object'
        structural_reason = ProxyFilter.get_structural_invalid_reason(
            proxy,
            target_format='clash',
        )
        if structural_reason:
            return structural_reason

        normalized = ProxyFilter.sanitize_proxy(proxy)
        normalize_certificate_pin(normalized)
        if (
            normalized.get('_v2rayn-certificate-pin') not in (None, '')
            and normalized.get('fingerprint') in (None, '')
        ):
            return 'unsupported-certificate-pin-format'
        return None

    @staticmethod
    def filter_clash_proxies(proxies: List[dict]) -> List[dict]:
        """Keep nodes that can be emitted to Mihomo without semantic loss."""
        compatible = []
        for proxy in proxies or []:
            if ProxyFilter.get_invalid_reason(proxy) is not None:
                continue
            if not ProxyFilter.is_valid_proxy(proxy):
                continue
            reason = ProxyFilter.get_clash_incompatible_reason(proxy)
            if reason:
                logger.warning(
                    "Skipping node '%s' from Clash output: %s",
                    proxy.get('name', '<unknown>') if isinstance(proxy, dict) else '<invalid>',
                    reason,
                )
                continue
            compatible.append(proxy)
        return compatible

    @staticmethod
    def _is_valid_server(server) -> bool:
        """Basic host validation for exported proxy nodes."""
        if server is None:
            return False

        server_text = str(server).strip()
        if not server_text:
            return False

        # Malformed nodes occasionally leak an auth separator into the host field,
        # such as "@1.2.3.4". Mihomo rejects these directly.
        if server_text.startswith('@'):
            return False

        return True

    @staticmethod
    def _is_numeric_rate(value) -> bool:
        """Check whether a Hysteria rate matches Mihomo's StringToBps input."""
        if isinstance(value, bool):
            return False
        if isinstance(value, (int, float)):
            return value >= 0
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return False
            if re.fullmatch(r"\d+(?:\.\d+)?", text):
                return True
            return re.fullmatch(r"\d+\s*[KMGT]?[Bb]ps", text, re.IGNORECASE) is not None
        return False

    @staticmethod
    def _is_positive_integer(value) -> bool:
        if isinstance(value, bool):
            return False
        try:
            return int(value) > 0
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _valid_unsigned_range(value, *, maximum: int | None = None) -> bool:
        text = str(value or '').strip()
        if not text:
            return False
        parts = text.split('-')
        if len(parts) not in {1, 2}:
            return False
        try:
            start = int(parts[0])
            end = int(parts[-1])
        except (TypeError, ValueError):
            return False
        if start < 1 or end < 1:
            return False
        if maximum is not None and (start > maximum or end > maximum):
            return False
        return True

    @staticmethod
    def _valid_port_ranges(value) -> bool:
        text = str(value or '').strip().replace(':', '-').replace(',', '/')
        segments = [segment.strip() for segment in text.split('/') if segment.strip()]
        return bool(segments) and len(segments) <= 28 and all(
            ProxyFilter._valid_unsigned_range(segment, maximum=65535)
            for segment in segments
        )

    @staticmethod
    def _parse_wireguard_addresses(value) -> tuple[str | None, str | None] | None:
        """Split a v2rayN WireGuard address list into Mihomo fields."""
        if value in (None, '', []):
            return None
        candidates = value if isinstance(value, (list, tuple)) else str(value).split(',')
        ipv4 = None
        ipv6 = None
        for candidate in candidates:
            text = str(candidate).strip()
            if not text:
                continue
            try:
                interface = ipaddress.ip_interface(text)
            except ValueError:
                return None
            if interface.version == 4:
                if ipv4 is not None:
                    return None
                ipv4 = str(interface)
            else:
                if ipv6 is not None:
                    return None
                ipv6 = str(interface)
        return (ipv4, ipv6) if ipv4 or ipv6 else None

    @staticmethod
    def get_structural_invalid_reason(
        proxy: dict,
        *,
        target_format: str | None = None,
    ) -> Optional[str]:
        """Return invalid reason for protocol-neutral malformed fields.

        When ``target_format`` is ``"clash"``/``"mihomo"``, the additional
        Mihomo capability checks are applied as well.  Keeping those checks out
        of the default path is important: V2Ray and sing-box can preserve a
        number of share-link fields that Mihomo cannot represent.
        """
        if not isinstance(proxy, dict):
            return 'invalid-proxy-object'

        # Validate the canonical representation even when this function is
        # called directly by an API model before ``sanitize_proxy`` runs.
        # This keeps legacy aliases such as HTTP Upgrade and TCP HTTP disguise
        # on the same path as subscription loading and custom-node storage.
        proxy = dict(proxy)
        normalize_trojan_proxy(proxy)
        normalize_v2ray_transport_proxy(proxy)
        normalize_alpn(proxy)
        normalize_certificate_pin(proxy)

        basic_reason = ProxyFilter._get_basic_proxy_invalid_reason(proxy)
        if basic_reason:
            return basic_reason

        proxy_type = str(proxy.get('type', '') or '').strip().lower()
        strict_clash = str(target_format or '').strip().lower() in {'clash', 'mihomo'}

        security = str(proxy.get('security', '') or '').strip().lower()
        allowed_security = {
            'vmess': {'none', 'tls', 'reality'},
            'vless': {'none', 'tls', 'reality'},
            'trojan': {'tls', 'reality'},
            'hysteria2': {'tls'},
            'tuic': {'tls'},
            'anytls': {'tls'},
        }
        if security and proxy_type in allowed_security and security not in allowed_security[proxy_type]:
            return f'unsupported-{proxy_type}-security'

        # Hysteria v1 requires explicit upload/download rates.
        # Hysteria2 does not require these fields, so do not enforce them there.
        if proxy_type == 'hysteria':
            if not ProxyFilter._is_numeric_rate(proxy.get('up')):
                return 'invalid-hysteria-up'
            if not ProxyFilter._is_numeric_rate(proxy.get('down')):
                return 'invalid-hysteria-down'

        if proxy_type == 'hysteria2':
            for field in ('up', 'down'):
                if proxy.get(field) not in (None, '') and not ProxyFilter._is_numeric_rate(proxy.get(field)):
                    return f'invalid-hysteria2-{field}'

        # Mihomo 1.19.x only implements these V2Ray transports.  Leaving an
        # unsupported value in the YAML is dangerous because the adapter can
        # silently fall back to plain TCP while the node still looks valid.
        network = str(proxy.get('network', '') or '').strip().lower()
        if network == 'httpupgrade':
            network = 'ws'
        if not network:
            network = 'tcp'
        known_networks = {'tcp', 'raw', 'none', 'ws', 'httpupgrade', 'http', 'h2', 'grpc', 'xhttp', 'kcp', 'quic'}
        if network not in known_networks:
            return f'unsupported-{proxy_type}-network'
        if strict_clash:
            supported_networks = {
                'vmess': {'tcp', 'http', 'h2', 'ws', 'grpc'},
                'vless': {'tcp', 'http', 'h2', 'ws', 'grpc', 'xhttp'},
                'trojan': {'tcp', 'ws', 'grpc'},
            }
            if proxy_type in supported_networks and network not in supported_networks[proxy_type]:
                return f'unsupported-{proxy_type}-network'

        # TCP HTTP camouflage is a share-link-only representation.  V2Ray
        # export can report it precisely; Mihomo cannot represent it without
        # changing the transport, so reject it only at the Clash boundary.
        if strict_clash and proxy_type == 'trojan' and str(proxy.get('header-type', '') or '').strip().lower() == 'http':
            return 'unsupported-trojan-tcp-disguise'

        if strict_clash and proxy_type in {'vmess', 'vless', 'trojan'} and network == 'grpc':
            grpc_opts = proxy.get('grpc-opts')
            if grpc_opts is not None and not isinstance(grpc_opts, dict):
                return 'invalid-grpc-options'
            if isinstance(grpc_opts, dict):
                supported_grpc_keys = {
                    'grpc-service-name', 'grpc-user-agent', 'ping-interval',
                    'max-connections', 'min-streams', 'max-streams',
                }
                if set(grpc_opts) - supported_grpc_keys:
                    return 'unsupported-grpc-option'

        reality_opts = proxy.get('reality-opts')
        if proxy_type in {'vmess', 'vless', 'trojan', 'anytls'} and reality_opts is not None:
            if proxy_type == 'anytls':
                return 'unsupported-anytls-reality'
            if not isinstance(reality_opts, dict):
                return 'invalid-reality-options'
            supported_reality_keys = {
                'public-key', 'short-id', 'support-x25519mlkem768', 'spider-x',
            }
            if strict_clash:
                supported_reality_keys.remove('spider-x')
            if set(reality_opts) - supported_reality_keys:
                return 'unsupported-reality-option'
            if not str(reality_opts.get('public-key') or '').strip():
                return 'missing-reality-public-key'

        # These aliases are only useful in a share URI. Mihomo has no
        # corresponding outbound field, so retaining them would make a
        # seemingly valid node run with a different TLS profile.
        tls_extension_fields = ('pqv', 'finalmask', 'vcn', 'verify-peer-cert-by-name')
        if strict_clash and any(proxy.get(key) not in (None, '', [], {}) for key in tls_extension_fields):
            return 'unsupported-tls-extension'

        if proxy_type in {'vmess', 'vless', 'trojan', 'anytls'}:
            # Trojan and AnyTLS are TLS-based protocols.  Providers commonly
            # omit the redundant ``tls: true`` flag while still supplying the
            # protocol's normal SNI/certificate options.  Requiring the flag
            # here incorrectly removes otherwise valid Trojan nodes during
            # subscription counting and merge generation.
            tls_enabled = (
                bool(proxy.get('tls'))
                or bool(reality_opts)
                or proxy_type in {'trojan', 'anytls'}
            )
            tls_only_fields = (
                'sni', 'servername', 'alpn', 'client-fingerprint',
                'fingerprint', 'cert-sha', 'ca-sha256', 'skip-cert-verify',
                'certificate', 'private-key', 'ca', 'ech-opts', 'disable-sni',
                'pqv', 'finalmask', 'vcn', 'verify-peer-cert-by-name',
            )
            if not tls_enabled and any(
                proxy.get(key) not in (None, '', False, [], {})
                for key in tls_only_fields
            ):
                return 'tls-option-without-tls'

        sni = proxy.get('sni')
        servername = proxy.get('servername')
        if sni not in (None, '') and servername not in (None, '') and str(sni) != str(servername):
            return 'conflicting-server-name'

        if proxy_type == 'hysteria2':
            certificate_pin = proxy.get('fingerprint')
            legacy_certificate_pin = proxy.get('ca-sha256')
            if (
                certificate_pin not in (None, '')
                and legacy_certificate_pin not in (None, '')
                and str(certificate_pin) != str(legacy_certificate_pin)
            ):
                return 'conflicting-hysteria2-certificate-pin'

        pin_alias_pairs = (
            (('cert-sha', 'ca-sha256'),)
            if proxy_type == 'hysteria2'
            else (
                ('fingerprint', 'cert-sha'),
                ('fingerprint', 'ca-sha256'),
                ('cert-sha', 'ca-sha256'),
            )
        )
        for aliases in pin_alias_pairs:
            left, right = aliases
            if (
                proxy.get(left) not in (None, '')
                and proxy.get(right) not in (None, '')
                and str(proxy.get(left)) != str(proxy.get(right))
            ):
                return 'conflicting-certificate-pin'

        # v2rayN Hysteria2 ``pinSHA256`` accepts the protocol's opaque pin
        # representation (for example Base64), while Mihomo also accepts
        # colon-separated hexadecimal hashes. Other protocol ``pcs`` values
        # are certificate SHA-256 hashes and remain strictly validated.
        certificate_pin_keys = (
            ('ca-sha256', 'cert-sha', 'fingerprint')
            if proxy_type == 'hysteria2'
            else ('fingerprint', 'ca-sha256', 'cert-sha')
        )
        for key in certificate_pin_keys:
            value = proxy.get(key)
            if value in (None, ''):
                continue
            if proxy.get('_v2rayn-certificate-pin') not in (None, ''):
                continue
            compact = str(value).replace(':', '').strip()
            if ',' in compact or re.fullmatch(r'[0-9A-Fa-f]{64}', compact) is None:
                return 'invalid-certificate-pin'

        if proxy_type == 'vless' and network == 'xhttp':
            xhttp_opts = proxy.get('xhttp-opts')
            if xhttp_opts is not None and not isinstance(xhttp_opts, dict):
                return 'invalid-xhttp-options'
            if isinstance(xhttp_opts, dict):
                xhttp_reason = get_xhttp_invalid_reason(xhttp_opts)
                if xhttp_reason:
                    return xhttp_reason

        if proxy_type == 'trojan' and str(proxy.get('flow', '') or '').strip():
            return 'unsupported-trojan-flow'

        if proxy_type == 'hysteria2':
            certificate_pin = proxy.get('fingerprint')
            legacy_certificate_pin = proxy.get('ca-sha256')
            if (
                certificate_pin not in (None, '')
                and legacy_certificate_pin not in (None, '')
                and certificate_pin != legacy_certificate_pin
            ):
                return 'conflicting-hysteria2-certificate-pin'

            obfs = str(proxy.get('obfs', '') or '').strip().lower()
            if obfs in {'none', ''}:
                pass
            elif obfs not in {'salamander', 'gecko'}:
                return 'unsupported-hysteria2-obfs'
            elif not str(proxy.get('obfs-password') or '').strip():
                return 'missing-hysteria2-obfs-password'
            elif obfs == 'gecko':
                gecko_min = proxy.get('obfs-min-packet-size', proxy.get('minPacketSize', 512))
                gecko_max = proxy.get('obfs-max-packet-size', proxy.get('maxPacketSize', 1200))
                try:
                    gecko_min = int(gecko_min)
                    gecko_max = int(gecko_max)
                except (TypeError, ValueError):
                    return 'invalid-hysteria2-gecko-packet-size'
                if gecko_min <= 0 or gecko_min > gecko_max or gecko_max > 2048:
                    return 'invalid-hysteria2-gecko-packet-size'

            # ``ech``/``pqv``/``vcn``/``fm`` are v2rayN URI extensions, not
            # Mihomo Hysteria2 fields. They must be represented as ech-opts or
            # rejected before the final YAML is generated.
            if strict_clash and any(proxy.get(key) not in (None, '', [], {}) for key in ('ech', 'pqv', 'vcn', 'fm', 'finalmask')):
                return 'unsupported-hysteria2-tls-option'

            ports = proxy.get('ports') or proxy.get('mport')
            if ports not in (None, '') and not ProxyFilter._valid_port_ranges(ports):
                return 'invalid-hysteria2-ports'
            hop_interval = proxy.get('hop-interval')
            if hop_interval not in (None, ''):
                normalized_hop_interval = str(hop_interval).strip().lower()
                if normalized_hop_interval.endswith('s'):
                    normalized_hop_interval = normalized_hop_interval[:-1]
                if not ProxyFilter._valid_unsigned_range(normalized_hop_interval):
                    return 'invalid-hysteria2-hop-interval'
            for field in (
                'cwnd', 'udp-mtu', 'initial-stream-receive-window',
                'max-stream-receive-window', 'initial-connection-receive-window',
                'max-connection-receive-window',
            ):
                if proxy.get(field) not in (None, '') and not ProxyFilter._is_positive_integer(proxy.get(field)):
                    return f'invalid-hysteria2-{field}'

        if proxy_type == 'tuic':
            token = str(proxy.get('token') or '').strip()
            uuid = str(proxy.get('uuid') or '').strip()
            password = str(proxy.get('password') or '').strip()
            if not token and (not uuid or not password):
                return 'missing-tuic-credentials'
            relay_mode = str(proxy.get('udp-relay-mode') or '').strip().lower()
            if relay_mode and relay_mode not in {'native', 'quic'}:
                return 'invalid-tuic-udp-relay-mode'

        if strict_clash and proxy_type == 'anytls':
            network = str(proxy.get('network', '') or '').strip().lower()
            if network and network not in {'tcp', 'raw'}:
                return 'unsupported-anytls-network'

        if proxy_type in {'vless', 'vmess', 'trojan'}:
            if proxy.get('mtu') not in (None, '') and not ProxyFilter._is_positive_integer(proxy.get('mtu')):
                return f'invalid-{proxy_type}-mtu'

        if proxy_type == 'wireguard':
            if not str(proxy.get('public-key') or '').strip():
                return 'missing-public-key'
            if not proxy.get('ip') and not proxy.get('ipv6'):
                address = proxy.get('address')
                parsed_addresses = ProxyFilter._parse_wireguard_addresses(address)
                if parsed_addresses is None:
                    return 'missing-wireguard-address'
            for key in ('ip', 'ipv6'):
                value = proxy.get(key)
                if value in (None, ''):
                    continue
                try:
                    interface = ipaddress.ip_interface(str(value))
                except ValueError:
                    return f'invalid-wireguard-{key}'
                if key == 'ip' and interface.version != 4:
                    return 'invalid-wireguard-ip'
                if key == 'ipv6' and interface.version != 6:
                    return 'invalid-wireguard-ipv6'
            if proxy.get('mtu') not in (None, '') and not ProxyFilter._is_positive_integer(proxy.get('mtu')):
                return 'invalid-wireguard-mtu'
            reserved = proxy.get('reserved')
            if reserved not in (None, '', []):
                if isinstance(reserved, str):
                    values = [item.strip() for item in reserved.split(',') if item.strip()]
                elif isinstance(reserved, (list, tuple)):
                    values = list(reserved)
                else:
                    return 'invalid-wireguard-reserved'
                if len(values) != 3:
                    return 'invalid-wireguard-reserved'
                try:
                    reserved_bytes = [int(value) for value in values]
                except (TypeError, ValueError):
                    return 'invalid-wireguard-reserved'
                if any(value < 0 or value > 255 for value in reserved_bytes):
                    return 'invalid-wireguard-reserved'

        if strict_clash and proxy_type == 'ss':
            plugin = str(proxy.get('plugin') or '').strip().lower()
            plugin_opts = proxy.get('plugin-opts')
            if plugin and not isinstance(plugin_opts, dict):
                return 'invalid-shadowsocks-plugin-options'
            if plugin and plugin not in {'obfs', 'obfs-local', 'simple-obfs', 'v2ray-plugin'}:
                return 'unsupported-shadowsocks-plugin'
            if plugin in {'obfs', 'obfs-local', 'simple-obfs'} and isinstance(plugin_opts, dict):
                if set(plugin_opts) - {'mode', 'host'}:
                    return 'unsupported-shadowsocks-plugin-option'
                if str(plugin_opts.get('mode') or '').strip().lower() not in {'http', 'tls'}:
                    return 'unsupported-shadowsocks-plugin-mode'
            if plugin == 'v2ray-plugin' and isinstance(plugin_opts, dict):
                if set(plugin_opts) - {'mode', 'host', 'path', 'tls', 'mux'}:
                    return 'unsupported-shadowsocks-plugin-option'
                if str(plugin_opts.get('mode') or 'websocket').strip().lower() != 'websocket':
                    return 'unsupported-shadowsocks-plugin-mode'

        return None

    @staticmethod
    def sanitize_proxy(proxy: dict) -> dict:
        """Sanitize proxy node to fix common issues"""
        if not proxy:
            return proxy
        if not isinstance(proxy, dict):
            return proxy

        proxy = dict(proxy)
        normalize_trojan_proxy(proxy)
        normalize_v2ray_transport_proxy(proxy)
        normalize_alpn(proxy)
        normalize_certificate_pin(proxy)
        proxy_type = str(proxy.get('type', '') or '').strip().lower()

        if proxy_type == 'wireguard':
            legacy_psk = proxy.get('preshared-key')
            canonical_psk = proxy.get('pre-shared-key')
            if canonical_psk in (None, '') and legacy_psk not in (None, ''):
                proxy['pre-shared-key'] = legacy_psk
            proxy.pop('preshared-key', None)
            if not proxy.get('ip') and not proxy.get('ipv6') and proxy.get('address'):
                parsed_addresses = ProxyFilter._parse_wireguard_addresses(proxy.get('address'))
                if parsed_addresses is not None:
                    ipv4, ipv6 = parsed_addresses
                    if ipv4:
                        proxy['ip'] = ipv4
                    if ipv6:
                        proxy['ipv6'] = ipv6
                proxy.pop('address', None)

        # ``security`` is a share-link discriminator, not a Mihomo outbound
        # option. It is validated before sanitization at input boundaries and
        # must not leak into generated YAML.
        proxy.pop('security', None)
        if proxy_type == 'socks5h':
            # Mihomo uses the SOCKS5 adapter for both socks5 and socks5h
            # links; keep the remote-DNS intent while emitting a supported
            # structural type for downstream speed tests and exports.
            proxy['type'] = 'socks5'
            proxy_type = 'socks5'
        network = str(proxy.get('network', '') or '').strip().lower()

        # Mihomo expects xhttp transport settings under "xhttp-opts".
        # Older parser/UI code stored them as top-level "xhttp-mode", "path",
        # and "host", which produces valid YAML/JSON but an invalid xhttp node.
        if network == 'xhttp':
            xhttp_opts = proxy.get('xhttp-opts')
            if isinstance(xhttp_opts, dict):
                xhttp_opts = dict(xhttp_opts)
            else:
                xhttp_opts = {}

            legacy_mode = proxy.pop('xhttp-mode', None)
            legacy_path = proxy.pop('path', None)
            legacy_host = proxy.pop('host', None)

            if legacy_mode not in (None, '') and 'mode' not in xhttp_opts:
                xhttp_opts['mode'] = legacy_mode
            if legacy_path not in (None, '') and 'path' not in xhttp_opts:
                xhttp_opts['path'] = legacy_path
            if legacy_host not in (None, '') and 'host' not in xhttp_opts:
                xhttp_opts['host'] = legacy_host

            xhttp_opts = {k: v for k, v in xhttp_opts.items() if v not in (None, '')}
            if xhttp_opts:
                proxy['xhttp-opts'] = xhttp_opts
            else:
                proxy.pop('xhttp-opts', None)
        
        # Fix hysteria2 obfs issues
        if proxy_type == 'hysteria2':
            # ``fingerprint`` is Mihomo's certificate pin field for Hysteria2.
            # Older project versions stored URI pinSHA256 values under
            # ``ca-sha256``; migrate only that known legacy alias. Do not treat
            # the generic ``cert-sha`` field as equivalent: it may describe a
            # different certificate constraint and converting it would change
            # the node's security semantics.
            legacy_certificate_pin = proxy.get('ca-sha256')
            if legacy_certificate_pin and not proxy.get('fingerprint'):
                proxy['fingerprint'] = legacy_certificate_pin
                proxy.pop('ca-sha256', None)
            elif not legacy_certificate_pin or proxy.get('fingerprint') == legacy_certificate_pin:
                proxy.pop('ca-sha256', None)

            obfs = str(proxy.get('obfs', '') or '').strip()
            obfs_password = proxy.get('obfs-password')

            # If obfs is "none" or empty, remove it (Clash doesn't need it)
            if obfs and obfs.lower() == 'none':
                proxy.pop('obfs', None)
                proxy.pop('obfs-password', None)
            # Keep an incomplete obfuscation configuration intact. The
            # structural validator will drop it with a precise reason instead
            # of silently turning it into a different node.
            elif obfs and not obfs_password:
                logger.warning(
                    "Hysteria2 node '%s' has obfs=%s but no obfs-password",
                    proxy.get('name'), obfs,
                )
            elif obfs.lower() == 'gecko':
                # Keep v2rayN's URI names in the internal model, but emit the
                # Mihomo adapter names used by its current Hysteria2 schema.
                # Invalid values remain visible to the validator instead of
                # being silently replaced by unrelated defaults.
                legacy_min = proxy.pop('minPacketSize', None)
                legacy_max = proxy.pop('maxPacketSize', None)
                if proxy.get('obfs-min-packet-size') in (None, ''):
                    proxy['obfs-min-packet-size'] = legacy_min if legacy_min not in (None, '') else 512
                if proxy.get('obfs-max-packet-size') in (None, ''):
                    proxy['obfs-max-packet-size'] = legacy_max if legacy_max not in (None, '') else 1200
        
        return proxy
    
    @staticmethod
    def filter_proxies(proxies: List[dict]) -> List[dict]:
        """Filter nodes that can be emitted by the primary Mihomo pipeline."""
        if not proxies:
            return []

        valid_proxies = []
        for proxy in proxies:
            info_reason = ProxyFilter.get_invalid_reason(proxy)
            if info_reason:
                logger.info(
                    "Dropping info proxy '%s': %s",
                    proxy.get('name', '<unknown>') if isinstance(proxy, dict) else '<invalid>',
                    info_reason,
                )
                continue

            raw_invalid_reason = ProxyFilter.get_target_invalid_reason(proxy, 'clash')
            if raw_invalid_reason:
                logger.warning(
                    "Dropping incompatible proxy '%s' (type=%s): %s",
                    proxy.get('name', '<unknown>') if isinstance(proxy, dict) else '<invalid>',
                    proxy.get('type', '<unknown>') if isinstance(proxy, dict) else '<invalid>',
                    raw_invalid_reason,
                )
                continue

            sanitized = ProxyFilter.sanitize_proxy(proxy)
            invalid_reason = ProxyFilter.get_target_invalid_reason(sanitized, 'clash')
            if invalid_reason:
                logger.warning(
                    "Dropping incompatible proxy '%s' (type=%s): %s",
                    sanitized.get('name', '<unknown>') if isinstance(sanitized, dict) else '<invalid>',
                    sanitized.get('type', '<unknown>') if isinstance(sanitized, dict) else '<invalid>',
                    invalid_reason,
                )
                continue

            valid_proxies.append(sanitized)

        return valid_proxies
