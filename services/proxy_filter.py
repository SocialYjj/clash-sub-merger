"""
Proxy Filter Service
Filter out invalid info nodes from proxy lists
"""
import re
from typing import List, Optional
from core.proxy_compat import normalize_trojan_proxy
from logger_config import get_logger

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
    def is_valid_proxy(proxy: dict) -> bool:
        """Check if proxy node is valid after info-node and structural checks."""
        if ProxyFilter.get_invalid_reason(proxy) is not None:
            return False
        return ProxyFilter.get_structural_invalid_reason(proxy) is None

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
        """Check whether a Hysteria rate field is present and numeric."""
        if isinstance(value, bool):
            return False
        if isinstance(value, (int, float)):
            return True
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return False
            try:
                float(text)
                return True
            except ValueError:
                return False
        return False

    @staticmethod
    def get_structural_invalid_reason(proxy: dict) -> Optional[str]:
        """Return invalid reason for malformed protocol fields."""
        if not isinstance(proxy, dict):
            return 'invalid-proxy-object'

        proxy_type = str(proxy.get('type', '') or '').strip().lower()

        if not proxy_type:
            return 'missing-type'
        allowed_types = {
            'http', 'https', 'socks5', 'socks5h', 'ss', 'ssr', 'vmess',
            'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'wireguard',
            'snell', 'anytls', 'ssh', 'direct', 'reject',
        }
        if proxy_type not in allowed_types:
            return 'unsupported-type'

        if proxy_type and not ProxyFilter._is_valid_server(proxy.get('server')):
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
        }
        for field in required_fields.get(proxy_type, ()):
            if not str(proxy.get(field) or '').strip():
                return f'missing-{field}'

        # Hysteria v1 requires explicit upload/download rates.
        # Hysteria2 does not require these fields, so do not enforce them there.
        if proxy_type == 'hysteria':
            if not ProxyFilter._is_numeric_rate(proxy.get('up')):
                return 'invalid-hysteria-up'
            if not ProxyFilter._is_numeric_rate(proxy.get('down')):
                return 'invalid-hysteria-down'

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
        proxy_type = str(proxy.get('type', '') or '').strip().lower()
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
            obfs = proxy.get('obfs')
            obfs_password = proxy.get('obfs-password')
            
            # If obfs is "none" or empty, remove it (Clash doesn't need it)
            if obfs and obfs.lower() == 'none':
                proxy.pop('obfs', None)
                proxy.pop('obfs-password', None)
            # If obfs is set but obfs-password is missing, remove obfs
            elif obfs and not obfs_password:
                logger.warning(f"Hysteria2 node '{proxy.get('name')}' has obfs={obfs} but no obfs-password, removing obfs")
                proxy.pop('obfs', None)
        
        return proxy
    
    @staticmethod
    def filter_proxies(proxies: List[dict]) -> List[dict]:
        """Filter invalid proxy nodes, keep only valid ones"""
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

            sanitized = ProxyFilter.sanitize_proxy(proxy)
            structural_reason = ProxyFilter.get_structural_invalid_reason(sanitized)
            if structural_reason:
                logger.warning(
                    "Dropping malformed proxy '%s' (type=%s): %s",
                    sanitized.get('name', '<unknown>') if isinstance(sanitized, dict) else '<invalid>',
                    sanitized.get('type', '<unknown>') if isinstance(sanitized, dict) else '<invalid>',
                    structural_reason,
                )
                continue

            valid_proxies.append(sanitized)

        return valid_proxies
