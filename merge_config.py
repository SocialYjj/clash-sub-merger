"""
Clash Config Merger Tool
Extract proxy nodes from multiple source yaml files, filter, rename, group by country, and generate unified config
"""

import sys
import os

# Avoid shadowing the standard PyYAML library with the local 'yaml' directory
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir in sys.path:
    sys.path.remove(current_dir)

import yaml
import base64
import json
from urllib.parse import urlparse, unquote
from typing import Optional

class SubscriptionParser:
    """Parse various subscription formats to Clash config"""
    
    @staticmethod
    def decode_base64(content: str) -> str:
        """Safely decode Base64"""
        content = content.strip().replace('-', '+').replace('_', '/')
        missing_padding = len(content) % 4
        if missing_padding:
            content += '=' * (4 - missing_padding)
        try:
            return base64.b64decode(content).decode('utf-8')
        except:
            return ""

    @staticmethod
    def parse_vmess(vmess_url: str) -> Optional[dict]:
        """Parse vmess:// link"""
        try:
            b64 = vmess_url[8:]
            json_str = SubscriptionParser.decode_base64(b64)
            if not json_str: return None
            v = json.loads(json_str)
            
            proxy = {
                "name": v.get("ps", "vmess"),
                "type": "vmess",
                "server": v.get("add"),
                "port": int(v.get("port")),
                "uuid": v.get("id"),
                "alterId": int(v.get("aid", 0)),
                "cipher": "auto",
                "udp": True
            }
            
            if v.get("net") == "ws":
                proxy["network"] = "ws"
                ws_opts = {"path": v.get("path", "/")}
                if v.get("host"):
                    ws_opts["headers"] = {"Host": v.get("host")}
                proxy["ws-opts"] = ws_opts
                
            if v.get("tls") == "tls":
                proxy["tls"] = True
                if v.get("sni"):
                    proxy["servername"] = v.get("sni")
                    
            return proxy
        except Exception:
            return None

    @staticmethod
    def parse_ss(ss_url: str) -> Optional[dict]:
        """Parse ss:// link"""
        try:
            # ss://base64(method:password)@server:port#remark
            # OR ss://base64(method:password@server:port)#remark
            
            if '#' in ss_url:
                main, remark = ss_url[5:].split('#', 1)
                remark = unquote(remark)
            else:
                main = ss_url[5:]
                remark = "ss"
            
            if '@' in main:
                # Format 1: base64(user:pass)@host:port
                user_pass_b64, host_port = main.split('@', 1)
                user_pass = SubscriptionParser.decode_base64(user_pass_b64)
                if ':' not in user_pass: return None
                method, password = user_pass.split(':', 1)
                
                if ':' not in host_port: return None
                server, port = host_port.rsplit(':', 1)
            else:
                # Format 2: base64(method:password@host:port)
                decoded = SubscriptionParser.decode_base64(main)
                if '@' not in decoded: return None
                user_pass, host_port = decoded.split('@', 1)
                if ':' not in user_pass: return None
                method, password = user_pass.split(':', 1)
                if ':' not in host_port: return None
                server, port = host_port.rsplit(':', 1)

            return {
                "name": remark,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": method,
                "password": password,
                "udp": True
            }
        except Exception:
            return None

    @staticmethod
    def parse_trojan(trojan_url: str) -> Optional[dict]:
        """Parse trojan:// link"""
        try:
            # trojan://password@host:port?arg=val#remark
            if '#' in trojan_url:
                main, remark = trojan_url[9:].split('#', 1)
                remark = unquote(remark)
            else:
                main = trojan_url[9:]
                remark = "trojan"
            
            if '?' in main:
                main, query = main.split('?', 1)
            else:
                query = ""
                
            if '@' not in main: return None
            password, host_port = main.split('@', 1)
            if ':' not in host_port: return None
            server, port = host_port.rsplit(':', 1)
            
            proxy = {
                "name": remark,
                "type": "trojan",
                "server": server,
                "port": int(port),
                "password": password,
                "udp": True,
                "skip-cert-verify": True
            }
            
            # Parse query (sni, etc)
            if query:
                params = {}
                for pair in query.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = v
                
                if 'sni' in params:
                    proxy['sni'] = params['sni']
                if 'allowInsecure' in params:
                     proxy['skip-cert-verify'] = (params['allowInsecure'] == '1')
            
            return proxy
        except Exception:
            return None

    @staticmethod
    def parse_vless(vless_url: str) -> Optional[dict]:
        """Parse vless:// link"""
        try:
            # vless://uuid@host:port?args#remark
            if '#' in vless_url:
                main, remark = vless_url[8:].split('#', 1)
                remark = unquote(remark)
            else:
                main = vless_url[8:]
                remark = "vless"
            
            if '?' in main:
                main, query = main.split('?', 1)
            else:
                query = ""
                
            if '@' not in main: return None
            uuid, host_port = main.split('@', 1)
            if ':' not in host_port: return None
            server, port = host_port.rsplit(':', 1)
            
            proxy = {
                "name": remark,
                "type": "vless",
                "server": server,
                "port": int(port),
                "uuid": uuid,
                "udp": True,
                "cipher": "auto"
            }
            
            # Parse query
            params = {}
            if query:
                for pair in query.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = v
            
            # Network / Stream Settings
            network = params.get("type", "tcp")
            proxy["network"] = network
            
            if network == "ws":
                ws_opts = {}
                if "path" in params: ws_opts["path"] = unquote(params["path"])
                if "host" in params: ws_opts["headers"] = {"Host": unquote(params["host"])}
                proxy["ws-opts"] = ws_opts
            elif network == "grpc":
                grpc_opts = {}
                if "serviceName" in params: grpc_opts["grpc-service-name"] = unquote(params["serviceName"])
                proxy["grpc-opts"] = grpc_opts
            
            # Security / TLS / Reality
            security = params.get("security", "")
            if security == "tls":
                proxy["tls"] = True
                if "sni" in params: proxy["servername"] = params["sni"]
                if "fp" in params: proxy["client-fingerprint"] = params["fp"]
                if "flow" in params: proxy["flow"] = params["flow"]
            elif security == "reality":
                proxy["tls"] = True
                proxy["flow"] = params.get("flow", "xtls-rprx-vision")
                if "sni" in params: proxy["servername"] = params["sni"]
                if "fp" in params: proxy["client-fingerprint"] = params["fp"]
                
                reality_opts = {}
                if "pbk" in params: reality_opts["public-key"] = params["pbk"]
                if "sid" in params: reality_opts["short-id"] = params["sid"]
                if "spx" in params: reality_opts["spider-x"] = params["spx"]
                proxy["reality-opts"] = reality_opts
            
            return proxy
        except Exception:
            return None

    @staticmethod
    def parse_ssr(ssr_url: str) -> Optional[dict]:
        """Parse ssr:// link"""
        try:
            b64 = ssr_url[6:]
            decoded = SubscriptionParser.decode_base64(b64)
            
            # server:port:protocol:method:obfs:password_base64/?params
            if '/?' in decoded:
                main, query = decoded.split('/?', 1)
            else:
                main = decoded
                query = ""
                
            parts = main.split(':')
            if len(parts) != 6: return None
            
            server = parts[0]
            port = int(parts[1])
            protocol = parts[2]
            method = parts[3]
            obfs = parts[4]
            password = SubscriptionParser.decode_base64(parts[5])
            
            proxy = {
                "name": "ssr", # temporary
                "type": "ssr",
                "server": server,
                "port": port,
                "cipher": method,
                "password": password,
                "protocol": protocol,
                "obfs": obfs,
                "udp": True
            }
            
            if query:
                params = {}
                for pair in query.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = v # values are base64 encoded usually? SSR query params are weird.
                        
                if 'remarks' in params:
                    proxy['name'] = SubscriptionParser.decode_base64(params['remarks'])
                if 'obfsparam' in params:
                    proxy['obfs-param'] = SubscriptionParser.decode_base64(params['obfsparam'])
                if 'protoparam' in params:
                    proxy['protocol-param'] = SubscriptionParser.decode_base64(params['protoparam'])
                    
            return proxy
        except Exception:
            return None

    @staticmethod
    def parse_hysteria2(hy2_url: str) -> Optional[dict]:
        """Parse hysteria2:// link"""
        try:
            # hysteria2://password@host:port?params#remark
            if '#' in hy2_url:
                main, remark = hy2_url[12:].split('#', 1)
                remark = unquote(remark)
            else:
                main = hy2_url[12:]
                remark = "hy2"
            
            if '?' in main:
                main, query = main.split('?', 1)
            else:
                query = ""
                
            if '@' not in main: return None
            password, host_port = main.split('@', 1)
            
            # Host/Port parsing (handle IPv6)
            if ']:' in host_port: 
                server, port = host_port.rsplit(':', 1)
                server = server.replace('[', '').replace(']', '')
            elif ':' in host_port:
                server, port = host_port.rsplit(':', 1)
            else:
                return None
                
            proxy = {
                "name": remark,
                "type": "hysteria2",
                "server": server,
                "port": int(port),
                "password": password,
                "udp": True,
                "obfs": "none" # Default?
            }
            
            if query:
                params = {}
                for pair in query.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = v
                
                if 'sni' in params: proxy['sni'] = params['sni']
                if 'insecure' in params: proxy['skip-cert-verify'] = (params['insecure'] == '1')
                if 'obfs' in params: proxy['obfs'] = params['obfs']
                if 'obfs-password' in params: proxy['obfs-password'] = params['obfs-password']
            
            return proxy
        except Exception:
            return None

    @staticmethod
    def parse_content(content: str) -> dict:
        """Try to parse content"""
        # 1. Try to parse as YAML directly
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and 'proxies' in data:
                return data
        except:
            pass
            
        # 2. Try Base64 decode
        try:
            decoded = SubscriptionParser.decode_base64(content)
            if 'proxies:' in decoded:
                 # Decoded content is YAML
                 return yaml.safe_load(decoded) or {}
        except:
            decoded = content # Assume it might be plain text link list
            
        # 3. Parse link list
        proxies = []
        lines = decoded.splitlines()
        for line in lines:
            line = line.strip()
            if not line: continue
            
            p = None
            if line.startswith('vmess://'):
                p = SubscriptionParser.parse_vmess(line)
            elif line.startswith('ss://'):
                p = SubscriptionParser.parse_ss(line)
            elif line.startswith('trojan://'):
                p = SubscriptionParser.parse_trojan(line)
            elif line.startswith('vless://'):
                p = SubscriptionParser.parse_vless(line)
            elif line.startswith('ssr://'):
                p = SubscriptionParser.parse_ssr(line)
            elif line.startswith('hysteria2://') or line.startswith('hy2://'):
                p = SubscriptionParser.parse_hysteria2(line)
            elif line.startswith('{') and line.endswith('}'):
                # Try to parse JSON format node (Clash Meta/Hy2 etc may return JSON objects directly)
                try:
                    import json
                    p = json.loads(line)
                    if isinstance(p, dict) and 'name' in p and 'type' in p:
                        proxies.append(p)
                except:
                    pass
                continue
                
            if p: proxies.append(p)
            
        if proxies:
            return {"proxies": proxies}
            
        return {}


# Restore sys.path for normal use (if necessary)
sys.path.insert(0, current_dir)

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


# ==================== ProxyFilter ====================

class ProxyFilter:
    """Proxy node filter - filter out invalid info nodes"""
    
    INVALID_KEYWORDS = [
        '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
        '剩余', '到期', '重置'
    ]
    
    @staticmethod
    def is_valid_proxy(proxy: dict) -> bool:
        """Check if proxy node is valid (not an info node)"""
        if not proxy or 'name' not in proxy:
            return False
        name = proxy['name']
        for keyword in ProxyFilter.INVALID_KEYWORDS:
            if keyword in name:
                return False
        return True
    
    @staticmethod
    def filter_proxies(proxies: List[dict]) -> List[dict]:
        """Filter invalid proxy nodes, keep only valid ones"""
        if not proxies:
            return []
        return [p for p in proxies if ProxyFilter.is_valid_proxy(p)]


# ==================== NameTransformer ====================

class NameTransformer:
    """Node name transformer - unify node name format to: Flag Provider NodeName"""
    
    # Source filename to prefix mapping
    SOURCE_PREFIX_MAP = {
        '宝可梦': '宝可梦',
        '流量光机场': '流量多',
        '淘气兔': '淘气兔',
        '风萧萧公益机场': '风萧萧',
        '魔戒': '魔戒'
    }
    
    # All flag emojis list (for removal)
    FLAG_EMOJIS = [
        '🇭🇰', '🇹🇼', '🇯🇵', '🇺🇸', '🇸🇬', '🇰🇷', '🇬🇧', '🇩🇪', '🇨🇦', '🇦🇺',
        '🇫🇷', '🇷🇺', '🇮🇳', '🇳🇱', '🇹🇷', '🇦🇶', '🇲🇾', '🇪🇸', '🇻🇳', '🇺🇦',
        '🇲🇩', '🇳🇬', '🇧🇷', '🇮🇹', '🇵🇱', '🇨🇭', '🇦🇹', '🇧🇪', '🇸🇪', '🇳🇴',
        '🇩🇰', '🇫🇮', '🇮🇪', '🇵🇹', '🇬🇷', '🇨🇿', '🇭🇺', '🇷🇴', '🇧🇬', '🇭🇷',
        '🇸🇰', '🇸🇮', '🇱🇹', '🇱🇻', '🇪🇪', '🇮🇱', '🇦🇪', '🇸🇦', '🇶🇦', '🇰🇼',
        '🇴🇲', '🇧🇭', '🇯🇴', '🇱🇧', '🇪🇬', '🇿🇦', '🇰🇪', '🇳🇿', '🇵🇭', '🇹🇭',
        '🇮🇩', '🇵🇰', '🇧🇩', '🇱🇰', '🇳🇵', '🇲🇲', '🇰🇭', '🇱🇦', '🇲🇳', '🇰🇿',
        '🇺🇿', '🇦🇿', '🇬🇪', '🇦🇲', '🇨🇾', '🇲🇹', '🇮🇸', '🇱🇺', '🇲🇨', '🇦🇩',
        '🇱🇮', '🇸🇲', '🇻🇦', '🇲🇽', '🇦🇷', '🇨🇱', '🇨🇴', '🇵🇪', '🇻🇪', '🇪🇨',
        '🇧🇴', '🇵🇾', '🇺🇾', '🇨🇷', '🇵🇦', '🇨🇺', '🇩🇴', '🇵🇷', '🇯🇲', '🇭🇹',
        '🔰', '🌏', '🌍', '🌎', '🏳️'
    ]
    
    # Country identification patterns: Flag -> keyword list
    COUNTRY_FLAG_MAP = {
        '🇭🇰': ['HK', 'Hong Kong', '香港', 'Hongkong'],
        '🇹🇼': ['TW', 'Taiwan', '台湾', 'Taipei'],
        '🇯🇵': ['JP', 'Japan', '日本', 'Tokyo', 'Osaka'],
        '🇺🇸': ['US', 'United States', '美国', 'America', 'USA', 'Los Angeles', 'Seattle', 'San Jose'],
        '🇸🇬': ['SG', 'Singapore', '新加坡'],
        '🇰🇷': ['KR', 'Korea', '韩国', 'Seoul'],
        '🇬🇧': ['GB', 'UK', 'United Kingdom', '英国', 'England', 'London'],
        '🇩🇪': ['DE', 'Germany', '德国', 'Frankfurt'],
        '🇨🇦': ['CA', 'Canada', '加拿大', 'Toronto', 'Vancouver'],
        '🇦🇺': ['AU', 'Australia', '澳大利亚', '澳洲', 'Sydney'],
        '🇫🇷': ['FR', 'France', '法国', 'Paris'],
        '🇷🇺': ['RU', 'Russia', '俄罗斯', 'Moscow'],
        '🇮🇳': ['IN', 'India', '印度'],
        '🇳🇱': ['NL', 'Netherlands', '荷兰', 'Amsterdam'],
        '🇹🇷': ['TR', 'Turkey', '土耳其', 'Istanbul'],
        '🇦🇶': ['Antarctica', '南极'],
        '🇲🇾': ['MY', 'Malaysia', '马来西亚'],
        '🇪🇸': ['ES', 'Spain', '西班牙'],
        '🇻🇳': ['VN', 'Vietnam', '越南'],
        '🇺🇦': ['UA', 'Ukraine', '乌克兰'],
        '🇲🇩': ['MD', 'Moldova', '摩尔多瓦'],
        '🇳🇬': ['NG', 'Nigeria', '尼日利亚'],
        '🇧🇷': ['BR', 'Brazil', '巴西'],
        '🇮🇹': ['IT', 'Italy', '意大利'],
        '🇵🇱': ['PL', 'Poland', '波兰'],
        '🇨🇭': ['CH', 'Switzerland', '瑞士'],
        '🇦🇹': ['AT', 'Austria', '奥地利'],
        '🇧🇪': ['BE', 'Belgium', '比利时'],
        '🇸🇪': ['SE', 'Sweden', '瑞典'],
        '🇳🇴': ['NO', 'Norway', '挪威'],
        '🇩🇰': ['DK', 'Denmark', '丹麦'],
        '🇫🇮': ['FI', 'Finland', '芬兰'],
        '🇮🇪': ['IE', 'Ireland', '爱尔兰'],
        '🇵🇹': ['PT', 'Portugal', '葡萄牙'],
        '🇬🇷': ['GR', 'Greece', '希腊'],
        '🇮🇱': ['IL', 'Israel', '以色列'],
        '🇦🇪': ['AE', 'UAE', '阿联酋', 'Dubai'],
        '🇿🇦': ['ZA', 'South Africa', '南非'],
        '🇳🇿': ['NZ', 'New Zealand', '新西兰'],
        '🇵🇭': ['PH', 'Philippines', '菲律宾'],
        '🇹🇭': ['TH', 'Thailand', '泰国'],
        '🇮🇩': ['ID', 'Indonesia', '印尼', '印度尼西亚'],
        '🇵🇰': ['PK', 'Pakistan', '巴基斯坦'],
        '🇲🇽': ['MX', 'Mexico', '墨西哥'],
        '🇦🇷': ['AR', 'Argentina', '阿根廷'],
    }
    
    @staticmethod
    def remove_flags(name: str) -> str:
        """Remove all flag emojis from node name"""
        result = name
        for flag in NameTransformer.FLAG_EMOJIS:
            result = result.replace(flag, '')
        # Clean up extra spaces
        result = ' '.join(result.split())
        return result.strip()
    
    @staticmethod
    def identify_flag(name: str) -> str:
        """Identify country flag based on node name
        Priority: 1. Flag emoji at the START of name  2. Any flag emoji in name  3. Keyword matching  4. Default flag
        """
        # Priority 1: Check if name STARTS with a country flag emoji (most reliable)
        for flag in NameTransformer.FLAG_EMOJIS:
            if name.startswith(flag) and flag != '🔰' and flag != '🌏' and flag != '🌍' and flag != '🌎' and flag != '🏳️':
                return flag
        
        # Priority 2: Check if name contains a country flag emoji anywhere
        for flag in NameTransformer.FLAG_EMOJIS:
            if flag in name and flag != '🔰' and flag != '🌏' and flag != '🌍' and flag != '🌎' and flag != '🏳️':
                return flag
        
        # Priority 3: Try to identify by keywords
        import re
        name_upper = name.upper()
        for flag, patterns in NameTransformer.COUNTRY_FLAG_MAP.items():
            for pattern in patterns:
                # Check if pattern contains Chinese characters
                has_chinese = any('\u4e00' <= c <= '\u9fff' for c in pattern)
                if has_chinese:
                    # For Chinese patterns, simple contains is fine
                    if pattern in name:
                        return flag
                elif len(pattern) <= 3:
                    # For short English patterns, require word boundary
                    pattern_upper = pattern.upper()
                    if re.search(r'(?<![A-Z])' + re.escape(pattern_upper) + r'(?![A-Z])', name_upper):
                        return flag
                else:
                    # For longer English patterns, simple contains is fine
                    if pattern.upper() in name_upper:
                        return flag
        
        # Priority 4: Return default flag (unknown)
        return '🔰'
    
    @staticmethod
    def transform_name(proxy: dict, source_name: str) -> dict:
        """Unify node name format to: Flag Provider NodeName"""
        if not proxy or 'name' not in proxy:
            return proxy
        
        prefix = NameTransformer.SOURCE_PREFIX_MAP.get(source_name, source_name)
        original_name = proxy['name']
        
        # 1. Identify flag first (before removal)
        flag = NameTransformer.identify_flag(original_name)
        
        # 2. Remove existing flags
        clean_name = NameTransformer.remove_flags(original_name)
        
        # 3. Replace [ipv6] with ipv6
        if '[ipv6]' in clean_name:
            clean_name = clean_name.replace('[ipv6]', 'ipv6')
        
        # 4. Check if provider prefix already exists to avoid duplication
        has_prefix = False
        for known_prefix in NameTransformer.SOURCE_PREFIX_MAP.values():
            if clean_name.startswith(known_prefix + ' ') or clean_name.startswith(known_prefix + '-'):
                has_prefix = True
                break
        
        # 5. Combine new name: Flag Provider NodeName
        if has_prefix:
            new_name = f"{flag} {clean_name}"
        else:
            new_name = f"{flag} {prefix} {clean_name}"
        
        # Create new proxy dict to avoid modifying original object
        new_proxy = proxy.copy()
        new_proxy['name'] = new_name
        return new_proxy
    
    @staticmethod
    def transform_proxies(proxies: List[dict], source_name: str) -> List[dict]:
        """Batch transform proxy node names"""
        return [NameTransformer.transform_name(p, source_name) for p in proxies]


# ==================== CountryGrouper ====================

class CountryGrouper:
    """Group proxy nodes by country/region"""
    
    # Country identification patterns: Group name -> keyword list
    COUNTRY_PATTERNS = {
        '🇭🇰 香港': ['🇭🇰', 'HK', 'Hong Kong', '香港'],
        '🇹🇼 台湾': ['🇹🇼', 'TW', 'Taiwan', '台湾', 'Taipei'],
        '🇯🇵 日本': ['🇯🇵', 'JP', 'Japan', '日本'],
        '🇺🇸 美国': ['🇺🇸', 'US', 'United States', '美国'],
        '🇸🇬 新加坡': ['🇸🇬', 'SG', 'Singapore', '新加坡'],
        '🇰🇷 韩国': ['🇰🇷', 'KR', 'Korea', '韩国'],
        '🇬🇧 英国': ['🇬🇧', 'GB', 'UK', 'United Kingdom', '英国', 'England'],
        '🇩🇪 德国': ['🇩🇪', 'DE', 'Germany', '德国'],
        '🇨🇦 加拿大': ['🇨🇦', 'CA', 'Canada', '加拿大'],
        '🇦🇺 澳大利亚': ['🇦🇺', 'AU', 'Australia', '澳大利亚', '澳洲'],
        '🇫🇷 法国': ['🇫🇷', 'FR', 'France', '法国'],
        '🇷🇺 俄罗斯': ['🇷🇺', 'RU', 'Russia', '俄罗斯'],
        '🇮🇳 印度': ['🇮🇳', 'IN', 'India', '印度'],
        '🇳🇱 荷兰': ['🇳🇱', 'NL', 'Netherlands', '荷兰'],
        '🇹🇷 土耳其': ['🇹🇷', 'TR', 'Turkey', '土耳其'],
        '🇦🇶 南极洲': ['🇦🇶', 'Antarctica', '南极'],
        '🇲🇾 马来西亚': ['🇲🇾', 'MY', 'Malaysia', '马来西亚'],
        '🇪🇸 西班牙': ['🇪🇸', 'ES', 'Spain', '西班牙'],
        '🇻🇳 越南': ['🇻🇳', 'VN', 'Vietnam', '越南'],
        '🇺🇦 乌克兰': ['🇺🇦', 'UA', 'Ukraine', '乌克兰'],
        '🇲🇩 摩尔多瓦': ['🇲🇩', 'MD', 'Moldova', '摩尔多瓦'],
        '🇳🇬 尼日利亚': ['🇳🇬', 'NG', 'Nigeria', '尼日利亚'],
        '🇳🇴 挪威': ['🇳🇴', 'NO', 'Norway', '挪威'],
    }
    
    @staticmethod
    def identify_country(proxy_name: str) -> str:
        """Identify country/region of proxy node
        Priority: 1. Flag emoji at START of name  2. Any flag emoji in name  3. Keyword matching  4. Unknown
        """
        # Priority 1: Check if name STARTS with a flag emoji (most reliable)
        for country, patterns in CountryGrouper.COUNTRY_PATTERNS.items():
            flag = patterns[0]  # First pattern is always the flag emoji
            if proxy_name.startswith(flag):
                return country
        
        # Priority 2: Check for any flag emoji in name
        for country, patterns in CountryGrouper.COUNTRY_PATTERNS.items():
            flag = patterns[0]
            if flag in proxy_name:
                return country
        
        # Priority 3: Try keyword matching
        import re
        for country, patterns in CountryGrouper.COUNTRY_PATTERNS.items():
            for pattern in patterns[1:]:  # Skip the flag emoji
                # Check if pattern contains Chinese characters
                has_chinese = any('\u4e00' <= c <= '\u9fff' for c in pattern)
                if has_chinese:
                    # For Chinese patterns, simple contains is fine
                    if pattern in proxy_name:
                        return country
                elif len(pattern) <= 3:
                    # For short English patterns, require word boundary
                    if re.search(r'(?<![A-Za-z])' + re.escape(pattern) + r'(?![A-Za-z])', proxy_name, re.IGNORECASE):
                        return country
                else:
                    # For longer English patterns, simple contains is fine
                    if pattern.upper() in proxy_name.upper():
                        return country
        
        return '🔰 未知'
    
    @staticmethod
    def group_by_country(proxies: List[dict]) -> Dict[str, List[str]]:
        """Group proxy nodes by country/region, return {country: [node_name_list]}"""
        groups: Dict[str, List[str]] = {}
        
        for proxy in proxies:
            name = proxy.get('name', '')
            country = CountryGrouper.identify_country(name)
            
            if country not in groups:
                groups[country] = []
            groups[country].append(name)
        
        return groups


# ==================== ProxyGroupGenerator ====================

class ProxyGroupGenerator:
    """Generate proxy-groups config"""
    
    # Country group display order
    COUNTRY_ORDER = [
        '🇭🇰 香港', '🇹🇼 台湾', '🇯🇵 日本', '🇸🇬 新加坡', '🇺🇸 美国',
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
        
        # 1. GLOBAL (select) - includes DIRECT, REJECT, manual select, auto select, fallback, and country groups
        global_group = {
            'name': 'GLOBAL',
            'type': 'select',
            'proxies': ['DIRECT', 'REJECT', '🚀 手动选择', '♻️ 自动选择(测速)', '🔯 故障转移'] + sorted_countries
        }
        groups.append(global_group)
        
        # 2. 🚀 Manual Select (select) - includes DIRECT, REJECT, and country groups
        node_select = {
            'name': '🚀 手动选择',
            'type': 'select',
            'proxies': ['DIRECT', 'REJECT'] + sorted_countries
        }
        groups.append(node_select)
        
        # 3. ♻️ Auto Select with speed test (url-test) - includes country groups
        auto_select = {
            'name': '♻️ 自动选择(测速)',
            'type': 'url-test',
            'proxies': sorted_countries,
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'tolerance': 50
        }
        groups.append(auto_select)
        
        # 4. 🔯 Fallback (fallback) - includes country groups
        fallback = {
            'name': '🔯 故障转移',
            'type': 'fallback',
            'proxies': sorted_countries,
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300
        }
        groups.append(fallback)
        
        # 5. Country/Region groups (select) - one group per country, sorted by node count
        for country in sorted_countries:
            if country in country_groups and country_groups[country]:
                country_group = {
                    'name': country,
                    'type': 'select',
                    'proxies': country_groups[country]
                }
                groups.append(country_group)
        
        return groups


# ==================== ConfigMerger ====================

class ConfigMerger:
    """Config merger main class"""
    
    # Source file config (in yaml folder)
    SOURCE_DIR = 'yaml'
    SOURCE_FILES = [
        ('宝可梦.yaml', '宝可梦'),
        ('流量光机场.yaml', '流量光机场'),
        ('淘气兔.yaml', '淘气兔'),
        ('风萧萧公益机场.yaml', '风萧萧'),
        ('魔戒.yaml', '魔戒')
    ]
    
    # ==================== Hardcoded Template Content ====================
    
    TEMPLATES = {
        'header': r"""mixed-port: 7890
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
geox-url:
  geoip: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat"
  geosite: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat"

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
  proxy-server-nameserver:
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
  fallback:
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
  nameserver-policy:
    "geosite:cn,private":
      - https://doh.pub/dns-query
      - https://dns.alidns.com/dns-query
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: false
  sniff:
    HTTP:
      ports: [80, 8080-8880, 10000]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
      override-destination: true
  skip-domain:
    - "*.apple.com"
    - "*.icloud.com"
    - "*.mzstatic.com"
    - "*.testflight.apple.com"
tun:
  enable: false
  stack: system
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
""",
        'suffix': r"""rules:
  - RULE-SET, Apple, DIRECT
  - RULE-SET, Google, 🚀 手动选择
  - RULE-SET, Microsoft, 🚀 手动选择
  - RULE-SET, Github, 🚀 手动选择
  - RULE-SET, HBO, 🚀 手动选择
  - RULE-SET, Disney, 🚀 手动选择
  - RULE-SET, TikTok, 🚀 手动选择
  - RULE-SET, Netflix, 🚀 手动选择
  - RULE-SET, GlobalMedia, 🚀 手动选择
  - RULE-SET, Telegram, 🚀 手动选择
  - RULE-SET, OpenAI, 🚀 手动选择
  - RULE-SET, Gemini, 🚀 手动选择
  - RULE-SET, Copilot, 🚀 手动选择
  - RULE-SET, Claude, 🚀 手动选择
  - RULE-SET, Crypto, 🚀 手动选择
  - RULE-SET, Cryptocurrency, 🚀 手动选择
  - RULE-SET, Game, 🚀 手动选择
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
  Github:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GitHub/GitHub.yaml
    interval: 86400
  HBO:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/HBO/HBO.yaml
    interval: 86400
  Disney:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Disney/Disney.yaml
    interval: 86400
  TikTok:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/TikTok/TikTok.yaml
    interval: 86400
  Netflix:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Netflix/Netflix.yaml
    interval: 86400
  GlobalMedia:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GlobalMedia/GlobalMedia_Classical_No_Resolve.yaml
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
  Gemini:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Gemini/Gemini.yaml
    interval: 86400
  Copilot:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Copilot/Copilot.yaml
    interval: 86400
  Claude:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Claude/Claude.yaml
    interval: 86400
  Crypto:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Crypto/Crypto.yaml
    interval: 86400
  Cryptocurrency:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Cryptocurrency/Cryptocurrency.yaml
    interval: 86400
  Game:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Game/Game.yaml
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

url-rewrite:
  - ^https?:\/\/(www.)?g\.cn https://www.google.com 302
  - ^https?:\/\/(www.)?google\.cn https://www.google.com 302
"""
    }

    def __init__(self, yaml_dir: str, output_file: str, custom_header: str = None, custom_suffix: str = None, file_aliases: Dict[str, str] = None):
        self.yaml_dir = yaml_dir
        self.output_file = output_file
        self.all_proxies: List[dict] = []
        self.header = custom_header if custom_header is not None else self.TEMPLATES['header']
        self.suffix = custom_suffix if custom_suffix is not None else self.TEMPLATES['suffix']
        self.file_aliases = file_aliases or {}

    @staticmethod
    def parse_template(content: str) -> dict:
        """Parse external template content, return header, suffix"""
        lines = content.splitlines(keepends=True)
        header_lines = []
        suffix_lines = []
        
        # Simple state machine:
        # 0: Header (before proxies/proxy-groups)
        # 1: Body (proxies/proxy-groups - ignored)
        # 2: Suffix (after proxy-groups, usually rules)
        
        # Simpler strategy: find proxies:, everything before is header
        # Find rules:, everything after is suffix (including rules)
        
        # Note: sometimes there are other things between proxies and rules.
        # Strategy here:
        # Header = start -> "proxies:"
        # Suffix = "rules:" -> end
        
        # If these keywords are not found, try best to split
        
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
             # Fallback: everything is header if no proxies defined
             return {'header': content, 'suffix': ''}
        
        header_content = "".join(lines[:header_end_idx]).rstrip()
        
        if suffix_start_idx != -1:
            suffix_content = "".join(lines[suffix_start_idx:])
        else:
            suffix_content = ""
            
        return {'header': header_content, 'suffix': suffix_content}
    
    @staticmethod
    def load_yaml(file_path: str) -> Optional[dict]:
        """Safely load YAML file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Warning: File not found - {file_path}")
            return None
        except yaml.YAMLError as e:
            print(f"Warning: YAML parse error - {file_path}: {e}")
            return None
        except Exception as e:
            print(f"Warning: Failed to read file - {file_path}: {e}")
            return None
    
    def load_source_proxies(self) -> List[dict]:
        """Load proxy nodes from all source files"""
        all_proxies = []
        
        if not os.path.exists(self.yaml_dir):
            print(f"Error: Directory {self.yaml_dir} does not exist")
            return []
            
        files = [f for f in os.listdir(self.yaml_dir) if f.endswith('.yaml') or f.endswith('.yml')]
        
        # Exclude output file and template file
        excludes = ['myconfig.yaml', 'myconfig_template.yaml']
        
        # Sort completely by file_aliases order (if available)
        def sort_key(filename):
            if self.file_aliases:
                alias_keys = list(self.file_aliases.keys())
                if filename in alias_keys:
                    return (0, alias_keys.index(filename))
            return (1, filename)  # Files not in file_aliases sorted by filename at the end
        
        files = sorted(files, key=sort_key)
        
        for file_name in files:
            if file_name in excludes:
                continue
                
            file_path = os.path.join(self.yaml_dir, file_name)
            
            # Determine source name (prefix)
            default_name = os.path.splitext(file_name)[0]
            # Use alias if provided, otherwise default
            source_name = self.file_aliases.get(file_name, default_name)
            
            print(f"Processing: {file_name}...")
            
            # Use enhanced parser to load config (supports YAML, Base64, Vmess links)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                config = SubscriptionParser.parse_content(content)
            except Exception as e:
                print(f"Warning: Cannot parse file {file_name}: {e}")
                continue
            
            if not config or not isinstance(config, dict):
                print(f"Warning: {file_name} has no valid content after parsing, skipped.")
                continue
            
            proxies = config.get('proxies', [])
            if not proxies:
                print(f"Info: {file_name} has no proxy nodes")
                continue
            
            # Filter invalid nodes (basic filter)
            valid_proxies = ProxyFilter.filter_proxies(proxies)
            
            # Filter junk nodes (keyword filter)
            ignore_keywords = [
                "剩余流量", "到期", "重置", "官网", "建议", "过滤掉", 
                "未到期", "无效", "测试", "邮件", "联系", 
                "群", "频道", "更新", "发布", "APP", "教程", "无法"
            ]
            
            clean_proxies = []
            for p in valid_proxies:
                name = str(p.get('name', ''))
                if any(k in name for k in ignore_keywords):
                    # print(f"  - Skipping invalid node: {name}") 
                    continue
                clean_proxies.append(p)
                
            print(f"Info: {file_name} - Original: {len(proxies)}, Basic filter: {len(valid_proxies)}, Final valid: {len(clean_proxies)}")
            
            # Add source prefix
            transformed_proxies = NameTransformer.transform_proxies(clean_proxies, source_name)
            all_proxies.extend(transformed_proxies)
        
        return all_proxies
    
    def merge_and_generate(self) -> dict:
        """Merge nodes and generate final config"""
        # Load all source proxies
        self.all_proxies = self.load_source_proxies()
        print(f"\nTotal valid proxy nodes: {len(self.all_proxies)}")
        
        if not self.all_proxies:
            print("Warning: No valid proxy nodes found")
            return {'proxies': [], 'proxy-groups': []}
        
        # Group by country
        country_groups = CountryGrouper.group_by_country(self.all_proxies)
        print(f"Country/Region groups: {len(country_groups)}")
        for country, nodes in country_groups.items():
            print(f"  {country}: {len(nodes)} nodes")
        
        # Generate proxy groups
        proxy_groups = ProxyGroupGenerator.generate_groups(self.all_proxies, country_groups)
        
        return {
            'proxies': self.all_proxies,
            'proxy-groups': proxy_groups
        }
    
    def save(self, config: dict):
        """Save config to file (maintain original format style: Basic -> Proxies -> Groups -> Rules -> Providers -> Others)"""
        import json
        
        # Get dynamically generated parts
        proxies = config.get('proxies', [])
        proxy_groups = config.get('proxy-groups', [])
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            # 1. Write Basic config (hardcoded header)
            f.write(self.header)
            
            # 2. Write Proxies
            f.write('\nproxies:\n')
            for proxy in proxies:
                proxy_json = json.dumps(proxy, ensure_ascii=False, separators=(',', ':'))
                f.write(f'  - {proxy_json}\n')
            
            # 3. Write Proxy Groups
            f.write('\nproxy-groups:\n')
            for group in proxy_groups:
                group_json = json.dumps(group, ensure_ascii=False, separators=(',', ':'))
                f.write(f'  - {group_json}\n')

            # 4. Write Suffix (Rules, Providers, Url-Rewrite)
            f.write('\n' + self.suffix)
        
        print(f"\nConfig saved to: {self.output_file}")


# ==================== Main Entry ====================


if __name__ == '__main__':
    # Config directory and file paths (relative to script location)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    # Source files in uploads subdirectory
    SOURCE_DIR = os.path.join(BASE_DIR, 'uploads')
    OUTPUT_FILE = os.path.join(BASE_DIR, 'myconfig.yaml')
    
    # Ensure source directory exists
    if not os.path.exists(SOURCE_DIR):
        print(f"Error: Source directory {SOURCE_DIR} does not exist")
        sys.exit(1)
        
    print("Starting Clash config merge...")
    merger = ConfigMerger(SOURCE_DIR, OUTPUT_FILE)
    config = merger.merge_and_generate()
    merger.save(config)
    
    print("=" * 50)
    print("Merge completed!")

