"""
Config Merger Service
Merge proxy nodes and generate Clash config
"""
import os
import json
import yaml
from typing import List, Dict, Optional
from logger_config import get_logger
from services.proxy_filter import ProxyFilter
from services.name_transformer import NameTransformer
from services.country_grouper import CountryGrouper

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
                 custom_suffix: str = None, file_aliases: Dict[str, str] = None):
        self.yaml_dir = yaml_dir
        self.output_file = output_file
        self.all_proxies: List[dict] = []
        self.header = custom_header if custom_header is not None else self.DEFAULT_HEADER
        self.suffix = custom_suffix if custom_suffix is not None else self.DEFAULT_SUFFIX
        self.file_aliases = file_aliases or {}

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
        
        if not os.path.exists(self.yaml_dir):
            logger.error(f"Directory {self.yaml_dir} does not exist")
            return []
            
        files = [f for f in os.listdir(self.yaml_dir) if f.endswith('.yaml') or f.endswith('.yml')]
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
                
            file_path = os.path.join(self.yaml_dir, file_name)
            default_name = os.path.splitext(file_name)[0]
            source_name = self.file_aliases.get(file_name, default_name)
            
            logger.info(f"Processing: {file_name}...")
            
            try:
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
            
            # Filter invalid nodes
            valid_proxies = ProxyFilter.filter_proxies(proxies)
            
            logger.info(f"{file_name} - Original: {len(proxies)}, Valid: {len(valid_proxies)}")
            
            # Add source prefix
            transformed_proxies = NameTransformer.transform_proxies(valid_proxies, source_name)
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
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(self.header)
            
            f.write('\nproxies:\n')
            for proxy in proxies:
                proxy_json = json.dumps(proxy, ensure_ascii=False, separators=(',', ':'))
                f.write(f'  - {proxy_json}\n')
            
            f.write('\nproxy-groups:\n')
            for group in proxy_groups:
                group_json = json.dumps(group, ensure_ascii=False, separators=(',', ':'))
                f.write(f'  - {group_json}\n')

            f.write('\n' + self.suffix)
        
        logger.info(f"Config saved to: {self.output_file}")
