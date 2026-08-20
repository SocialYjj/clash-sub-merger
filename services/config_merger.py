"""
Config Merger Service
Merge proxy nodes and generate Clash config
"""
import os
import json
import yaml
from typing import List, Dict, Optional
from logger_config import get_logger
from helpers import atomic_write_text, list_subscription_contents
from services.proxy_filter import ProxyFilter
from services.name_transformer import NameTransformer
from services.country_grouper import CountryGrouper
from services.node_visibility import filter_enabled_nodes, strip_visibility_fields
from services.node_identity import custom_node_id, subscription_node_ids
from services.proxy_chain_utils import unique_name
from services.node_metadata import strip_node_metadata

logger = get_logger(__name__)


class ProxyGroupGenerator:
    """Generate proxy-groups config"""
    
    # Country group display order
    COUNTRY_ORDER = [
        '🇭🇰 中国香港', '🇹🇼 中国台湾', '🇲🇴 中国澳门', '🇯🇵 日本', '🇸🇬 新加坡', '🇺🇸 美国',
        '🇰🇷 韩国', '🇬🇧 英国', '🇩🇪 德国', '🇨🇦 加拿大', '🇦🇺 澳大利亚',
        '🇫🇷 法国', '🇷🇺 俄罗斯', '🇮🇳 印度', '🇳🇱 荷兰', '🇹🇷 土耳其',
        '🇦🇶 南极洲', '🇲🇾 马来西亚', '🇪🇸 西班牙', '🇻🇳 越南', 
        '🇺🇦 乌克兰', '🇲🇩 摩尔多瓦', '🇳🇬 尼日利亚', '🔰 其他'
    ]
    
    @staticmethod
    def generate_groups(proxies: List[dict], country_groups: Dict[str, List[str]]) -> List[dict]:
        """Generate complete proxy-groups config"""
        all_proxy_names = [p['name'] for p in proxies]
        groups = []
        
        # Sort country groups by node count (descending)
        sorted_countries = sorted(
            [c for c in country_groups.keys() if country_groups[c]],
            key=lambda c: len(country_groups[c]),
            reverse=True
        )
        
        # 1. GLOBAL (select)
        global_group = {
            'name': 'GLOBAL',
            'type': 'select',
            'proxies': ['DIRECT', 'REJECT', '🚀 手动选择', '♻️ 自动选择(测速)', '🔯 故障转移'] + sorted_countries
        }
        groups.append(global_group)
        
        # 2. Manual Select
        node_select = {
            'name': '🚀 手动选择',
            'type': 'select',
            'proxies': ['DIRECT', 'REJECT'] + sorted_countries
        }
        groups.append(node_select)
        
        # 3. Auto Select with speed test
        auto_select = {
            'name': '♻️ 自动选择(测速)',
            'type': 'url-test',
            'proxies': sorted_countries,
            'url': 'https://cp.cloudflare.com/generate_204',
            'interval': 300,
            'tolerance': 50
        }
        groups.append(auto_select)
        
        # 4. Fallback
        fallback = {
            'name': '🔯 故障转移',
            'type': 'fallback',
            'proxies': sorted_countries,
            'url': 'https://cp.cloudflare.com/generate_204',
            'interval': 300
        }
        groups.append(fallback)
        
        # 5. Country/Region groups
        for country in sorted_countries:
            if country in country_groups and country_groups[country]:
                country_group = {
                    'name': country,
                    'type': 'select',
                    'proxies': country_groups[country]
                }
                groups.append(country_group)
        
        return groups


class ConfigMerger:
    """Config merger main class"""
    
    # Default template content
    DEFAULT_HEADER = r"""mixed-port: 7890
allow-lan: true
bind-address: 0.0.0.0
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
unified-delay: true
tcp-concurrent: true
find-process-mode: strict
keep-alive-interval: 15
profile:
  store-selected: true
  store-fake-ip: true
geodata-mode: true
geo-auto-update: true
geo-update-interval: 24

dns:
  enable: true
  prefer-h3: true
  listen: 0.0.0.0:1053
  ipv6: true
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "+.lan"
    - "+.local"
    - "geosite:private"
  nameserver:
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
"""

    DEFAULT_SUFFIX = r"""rules:
  - RULE-SET, Apple, DIRECT
  - RULE-SET, Google, 🚀 手动选择
  - RULE-SET, Microsoft, 🚀 手动选择
  - RULE-SET, Telegram, 🚀 手动选择
  - RULE-SET, OpenAI, 🚀 手动选择
  - RULE-SET, ChinaMax, DIRECT
  - RULE-SET, Lan, DIRECT
  - GEOIP, CN, DIRECT
  - RULE-SET, Global, 🚀 手动选择
  - MATCH, GLOBAL

rule-providers:
  Apple:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Apple/Apple_Classical_No_Resolve.yaml
    interval: 86400
  Google:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Google/Google_No_Resolve.yaml
    interval: 86400
  Microsoft:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Microsoft/Microsoft.yaml
    interval: 86400
  Telegram:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Telegram/Telegram_No_Resolve.yaml
    interval: 86400
  OpenAI:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/OpenAI/OpenAI.yaml
    interval: 86400
  Global:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Global/Global_Classical_No_Resolve.yaml
    interval: 86400
  ChinaMax:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMax/ChinaMax_Classical_No_Resolve.yaml
    interval: 86400
  Lan:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Lan/Lan.yaml
    interval: 86400
"""

    def __init__(self, yaml_dir: str, output_file: str, custom_header: str = None, 
                 custom_suffix: str = None, file_aliases: Dict[str, str] = None,
                 include_source_metadata: bool = False,
                 output_format: str | None = None):
        self.yaml_dir = yaml_dir
        self.output_file = output_file
        self.all_proxies: List[dict] = []
        self.header = custom_header if custom_header is not None else self.DEFAULT_HEADER
        self.suffix = custom_suffix if custom_suffix is not None else self.DEFAULT_SUFFIX
        self.file_aliases = file_aliases or {}
        self.include_source_metadata = include_source_metadata
        self.output_format = str(output_format or '').strip().lower()

    @staticmethod
    def _source_id_from_filename(file_name: str) -> str:
        if file_name == 'custom_nodes.yaml':
            return 'custom_nodes'
        return os.path.splitext(file_name)[0]

    @staticmethod
    def _make_unique_proxy_name(name: str, used_names: set) -> str:
        return unique_name(name or 'Unnamed', used_names)

    @staticmethod
    def load_yaml(file_path: str) -> Optional[dict]:
        """Safely load YAML file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"File not found - {file_path}")
            return None
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse error - {file_path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Failed to read file - {file_path}: {e}")
            return None
    
    @staticmethod
    def parse_template(content: str) -> dict:
        """Parse external template content, return header, suffix"""
        lines = content.splitlines(keepends=True)
        
        header_end_idx = -1
        suffix_start_idx = -1
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('proxies:'):
                header_end_idx = i
            elif stripped.startswith('rules:'):
                suffix_start_idx = i
                break
        
        if header_end_idx == -1:
            return {'header': content, 'suffix': ''}
        
        header_content = "".join(lines[:header_end_idx]).rstrip()
        
        if suffix_start_idx != -1:
            suffix_content = "".join(lines[suffix_start_idx:])
        else:
            suffix_content = ""
            
        return {'header': header_content, 'suffix': suffix_content}
    
    def load_source_proxies(self) -> List[dict]:
        """Load proxy nodes from all source files"""
        from services.subscription import SubscriptionParser
        
        all_proxies = []
        used_names = set()
        
        stored_sources = list_subscription_contents(self.yaml_dir)
        if not stored_sources and not os.path.isdir(self.yaml_dir):
            logger.error(f"Directory {self.yaml_dir} does not exist")
            return []

        files = sorted(stored_sources)
        excludes = ['myconfig.yaml', 'myconfig_template.yaml']
        
        def sort_key(filename):
            if self.file_aliases:
                alias_keys = list(self.file_aliases.keys())
                if filename in alias_keys:
                    return (0, alias_keys.index(filename))
            return (1, filename)
        
        files = sorted(files, key=sort_key)
        
        for file_name in files:
            if file_name in excludes:
                continue

            # When file_aliases is provided, only process files for enabled
            # subscriptions. Files not in file_aliases belong to disabled or
            # deleted subscriptions and must be skipped.
            if self.file_aliases and file_name not in self.file_aliases:
                continue

            default_name = os.path.splitext(file_name)[0]
            source_name = self.file_aliases.get(file_name, default_name)
            
            logger.info(f"Processing: {file_name}...")
            
            try:
                content = stored_sources.get(file_name)
                if content is None:
                    file_path = os.path.join(self.yaml_dir, file_name)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                config = SubscriptionParser.parse_content(content)
            except Exception as e:
                logger.warning(f"Cannot parse file {file_name}: {e}")
                continue
            
            if not config or not isinstance(config, dict):
                logger.warning(f"{file_name} has no valid content after parsing, skipped.")
                continue
            
            proxies = config.get('proxies', [])
            if not proxies:
                logger.info(f"{file_name} has no proxy nodes")
                continue

            source_id = self._source_id_from_filename(file_name)
            
            # Filter info banners and nodes that cannot be represented by the
            # selected output format. V2Ray/sing-box receive minimally valid
            # nodes as well, so their exporters can return a precise diagnostic
            # for format-specific options instead of silently losing a node.
            unique_ids = subscription_node_ids(source_id, proxies)
            if self.output_format in {'v2ray', 'singbox'}:
                valid_proxies = ProxyFilter.filter_minimally_valid_proxies(proxies)
            else:
                valid_proxies = ProxyFilter.filter_proxies(proxies)
            if self.output_format in {'clash', 'socks', 'socks-manual'}:
                valid_proxies = ProxyFilter.filter_clash_proxies(valid_proxies)
            enabled_proxies = filter_enabled_nodes(valid_proxies, strip=True)
            
            disabled_count = len(valid_proxies) - len(enabled_proxies)
            logger.info(
                "%s - Original: %s, Valid: %s, Disabled: %s",
                file_name,
                len(proxies),
                len(enabled_proxies),
                disabled_count,
            )
            
            identified_proxies = []
            for proxy_index, proxy in enumerate(proxies):
                if self.output_format in {'v2ray', 'singbox'}:
                    output_eligible = ProxyFilter.is_minimally_valid_proxy(proxy)
                else:
                    output_eligible = ProxyFilter.is_clash_compatible_proxy(proxy)
                if not output_eligible or not filter_enabled_nodes([proxy], strip=True):
                    continue
                if (
                    self.output_format in {'clash', 'socks', 'socks-manual'}
                    and not ProxyFilter.is_clash_compatible_proxy(proxy)
                ):
                    continue
                identified_proxy = strip_visibility_fields(
                    ProxyFilter.sanitize_proxy(dict(proxy))
                )
                identified_proxy['_allocation_id'] = (
                    custom_node_id(proxy)
                    if source_id == 'custom_nodes'
                    else unique_ids[proxy_index]
                )
                identified_proxies.append(identified_proxy)

            # Add source prefix after deriving identity from the stored node.
            transformed_proxies = NameTransformer.transform_proxies(identified_proxies, source_name)
            for proxy in transformed_proxies:
                proxy['name'] = self._make_unique_proxy_name(proxy.get('name', ''), used_names)
                if self.include_source_metadata:
                    proxy['_source_file'] = file_name
                    proxy['_source_id'] = source_id
                    proxy['_source_name'] = source_name
            all_proxies.extend(transformed_proxies)
        
        return all_proxies
    
    def merge_and_generate(self) -> dict:
        """Merge nodes and generate final config"""
        self.all_proxies = self.load_source_proxies()
        logger.info(f"Total valid proxy nodes: {len(self.all_proxies)}")
        
        if not self.all_proxies:
            logger.warning("No valid proxy nodes found")
            return {'proxies': [], 'proxy-groups': []}
        
        country_groups = CountryGrouper.group_by_country(self.all_proxies)
        logger.info(f"Country/Region groups: {len(country_groups)}")
        
        proxy_groups = ProxyGroupGenerator.generate_groups(self.all_proxies, country_groups)
        
        return {
            'proxies': self.all_proxies,
            'proxy-groups': proxy_groups
        }
    
    def save(self, config: dict):
        """Save config to file"""
        proxies = config.get('proxies', [])
        proxy_groups = config.get('proxy-groups', [])

        output_parts = [self.header, '\nproxies:\n']
        for proxy in proxies:
            proxy_json = json.dumps(
                strip_node_metadata(proxy),
                ensure_ascii=False,
                separators=(',', ':'),
            )
            output_parts.append(f'  - {proxy_json}\n')

        output_parts.append('\nproxy-groups:\n')
        for group in proxy_groups:
            group_json = json.dumps(group, ensure_ascii=False, separators=(',', ':'))
            output_parts.append(f'  - {group_json}\n')

        output_parts.append('\n' + self.suffix)
        atomic_write_text(self.output_file, ''.join(output_parts))
        
        logger.info(f"Config saved to: {self.output_file}")
