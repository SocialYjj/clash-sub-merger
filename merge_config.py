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
import socket
from urllib.parse import urlparse, unquote
from typing import Optional

# GeoIP database support
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("Warning: geoip2 not installed. Run: pip install geoip2")

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
        '剩余流量', '套餐到期', '距离下次重置', '建议', '未到期',
        '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
        '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
        '使用说明', '教程', '更新', '通知', '邀请', '返利',
        '问题', '工单', '咨询', '合作', '会员', '商城', '账号',
        '官网:', '官网：', '免注册'
    ]
    
    # Region keywords for valid nodes starting with "官网"
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
        '海外'  # Generic "overseas"
    ]
    
    @staticmethod
    def is_valid_proxy(proxy: dict) -> bool:
        """Check if proxy node is valid (not an info node)"""
        if not proxy or 'name' not in proxy:
            return False
        name = proxy['name']
        
        # Check basic keywords
        for keyword in ProxyFilter.INVALID_KEYWORDS:
            if keyword in name:
                return False
        
        # Check if starts with "官网" but has no region name
        if name.startswith('官网'):
            # If it contains a region name, it's a valid node
            if any(region in name for region in ProxyFilter.REGION_KEYWORDS):
                return True
            # Otherwise it's an info node
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
    def identify_flag(name: str, server: str = None) -> str:
        """Identify country flag based on node name
        Priority: 1. Flag emoji at the START of name  2. Any flag emoji in name  3. Keyword matching  4. GeoIP lookup  5. Default flag
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
        
        # Priority 4: GeoIP lookup (if server address provided)
        if server and GEOIP_AVAILABLE:
            geoip = GeoIPLookup.get_instance()
            flag = geoip.get_flag(server)
            if flag:
                return flag
        
        # Priority 5: Return default flag (unknown)
        return '🔰'
    
    @staticmethod
    def transform_name(proxy: dict, source_name: str) -> dict:
        """Unify node name format to: Flag Provider NodeName"""
        if not proxy or 'name' not in proxy:
            return proxy
        
        prefix = NameTransformer.SOURCE_PREFIX_MAP.get(source_name, source_name)
        original_name = proxy['name']
        server = proxy.get('server', '')  # Get server for GeoIP lookup
        
        # 1. Identify flag first (before removal)
        flag = NameTransformer.identify_flag(original_name, server)
        
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


# ==================== GeoIPLookup ====================

class GeoIPLookup:
    """GeoIP lookup using MaxMind GeoLite2 database"""
    
    # ISO country code to flag emoji mapping
    COUNTRY_CODE_TO_FLAG = {
        'HK': '🇭🇰', 'TW': '🇹🇼', 'JP': '🇯🇵', 'US': '🇺🇸', 'SG': '🇸🇬',
        'KR': '🇰🇷', 'GB': '🇬🇧', 'DE': '🇩🇪', 'CA': '🇨🇦', 'AU': '🇦🇺',
        'FR': '🇫🇷', 'RU': '🇷🇺', 'IN': '🇮🇳', 'NL': '🇳🇱', 'TR': '🇹🇷',
        'AQ': '🇦🇶', 'MY': '🇲🇾', 'ES': '🇪🇸', 'VN': '🇻🇳', 'UA': '🇺🇦',
        'MD': '🇲🇩', 'NG': '🇳🇬', 'BR': '🇧🇷', 'IT': '🇮🇹', 'PL': '🇵🇱',
        'CH': '🇨🇭', 'AT': '🇦🇹', 'BE': '🇧🇪', 'SE': '🇸🇪', 'NO': '🇳🇴',
        'DK': '🇩🇰', 'FI': '🇫🇮', 'IE': '🇮🇪', 'PT': '🇵🇹', 'GR': '🇬🇷',
        'CZ': '🇨🇿', 'HU': '🇭🇺', 'RO': '🇷🇴', 'BG': '🇧🇬', 'HR': '🇭🇷',
        'SK': '🇸🇰', 'SI': '🇸🇮', 'LT': '🇱🇹', 'LV': '🇱🇻', 'EE': '🇪🇪',
        'IL': '🇮🇱', 'AE': '🇦🇪', 'SA': '🇸🇦', 'QA': '🇶🇦', 'KW': '🇰🇼',
        'OM': '🇴🇲', 'BH': '🇧🇭', 'JO': '🇯🇴', 'LB': '🇱🇧', 'EG': '🇪🇬',
        'ZA': '🇿🇦', 'KE': '🇰🇪', 'NZ': '🇳🇿', 'PH': '🇵🇭', 'TH': '🇹🇭',
        'ID': '🇮🇩', 'PK': '🇵🇰', 'BD': '🇧🇩', 'LK': '🇱🇰', 'NP': '🇳🇵',
        'MM': '🇲🇲', 'KH': '🇰🇭', 'LA': '🇱🇦', 'MN': '🇲🇳', 'KZ': '🇰🇿',
        'UZ': '🇺🇿', 'AZ': '🇦🇿', 'GE': '🇬🇪', 'AM': '🇦🇲', 'CY': '🇨🇾',
        'MT': '🇲🇹', 'IS': '🇮🇸', 'LU': '🇱🇺', 'MC': '🇲🇨', 'AD': '🇦🇩',
        'LI': '🇱🇮', 'SM': '🇸🇲', 'VA': '🇻🇦', 'MX': '🇲🇽', 'AR': '🇦🇷',
        'CL': '🇨🇱', 'CO': '🇨🇴', 'PE': '🇵🇪', 'VE': '🇻🇪', 'EC': '🇪🇨',
        'BO': '🇧🇴', 'PY': '🇵🇾', 'UY': '🇺🇾', 'CR': '🇨🇷', 'PA': '🇵🇦',
        'CU': '🇨🇺', 'DO': '🇩🇴', 'PR': '🇵🇷', 'JM': '🇯🇲', 'HT': '🇭🇹',
        'CN': '🇨🇳',
    }
    
    # ISO country code to Chinese name mapping
    COUNTRY_CODE_TO_NAME = {
        'HK': '香港', 'TW': '台湾', 'JP': '日本', 'US': '美国', 'SG': '新加坡',
        'KR': '韩国', 'GB': '英国', 'DE': '德国', 'CA': '加拿大', 'AU': '澳大利亚',
        'FR': '法国', 'RU': '俄罗斯', 'IN': '印度', 'NL': '荷兰', 'TR': '土耳其',
        'AQ': '南极洲', 'MY': '马来西亚', 'ES': '西班牙', 'VN': '越南', 'UA': '乌克兰',
        'MD': '摩尔多瓦', 'NG': '尼日利亚', 'BR': '巴西', 'IT': '意大利', 'PL': '波兰',
        'CH': '瑞士', 'AT': '奥地利', 'BE': '比利时', 'SE': '瑞典', 'NO': '挪威',
        'DK': '丹麦', 'FI': '芬兰', 'IE': '爱尔兰', 'PT': '葡萄牙', 'GR': '希腊',
        'CZ': '捷克', 'HU': '匈牙利', 'RO': '罗马尼亚', 'BG': '保加利亚', 'HR': '克罗地亚',
        'SK': '斯洛伐克', 'SI': '斯洛文尼亚', 'LT': '立陶宛', 'LV': '拉脱维亚', 'EE': '爱沙尼亚',
        'IL': '以色列', 'AE': '阿联酋', 'SA': '沙特', 'QA': '卡塔尔', 'KW': '科威特',
        'OM': '阿曼', 'BH': '巴林', 'JO': '约旦', 'LB': '黎巴嫩', 'EG': '埃及',
        'ZA': '南非', 'KE': '肯尼亚', 'NZ': '新西兰', 'PH': '菲律宾', 'TH': '泰国',
        'ID': '印尼', 'PK': '巴基斯坦', 'BD': '孟加拉', 'LK': '斯里兰卡', 'NP': '尼泊尔',
        'MM': '缅甸', 'KH': '柬埔寨', 'LA': '老挝', 'MN': '蒙古', 'KZ': '哈萨克斯坦',
        'UZ': '乌兹别克', 'AZ': '阿塞拜疆', 'GE': '格鲁吉亚', 'AM': '亚美尼亚', 'CY': '塞浦路斯',
        'MT': '马耳他', 'IS': '冰岛', 'LU': '卢森堡', 'MC': '摩纳哥', 'AD': '安道尔',
        'LI': '列支敦士登', 'SM': '圣马力诺', 'VA': '梵蒂冈', 'MX': '墨西哥', 'AR': '阿根廷',
        'CL': '智利', 'CO': '哥伦比亚', 'PE': '秘鲁', 'VE': '委内瑞拉', 'EC': '厄瓜多尔',
        'BO': '玻利维亚', 'PY': '巴拉圭', 'UY': '乌拉圭', 'CR': '哥斯达黎加', 'PA': '巴拿马',
        'CU': '古巴', 'DO': '多米尼加', 'PR': '波多黎各', 'JM': '牙买加', 'HT': '海地',
        'CN': '中国',
    }
    
    _instance = None
    _reader = None
    _dns_cache = {}  # Cache DNS lookups
    _geoip_cache = {}  # Cache GeoIP lookups
    
    @classmethod
    def get_instance(cls):
        """Singleton pattern for GeoIP reader"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        self._load_database()
    
    def _load_database(self):
        """Load GeoLite2 database"""
        if not GEOIP_AVAILABLE:
            return
        
        # Try multiple possible database locations
        import os
        base_dir = os.path.dirname(os.path.abspath(__file__))
        possible_paths = [
            os.path.join(base_dir, 'GeoLite2-Country.mmdb'),
            os.path.join(base_dir, 'data', 'GeoLite2-Country.mmdb'),
            '/usr/share/GeoIP/GeoLite2-Country.mmdb',
            '/var/lib/GeoIP/GeoLite2-Country.mmdb',
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    self._reader = geoip2.database.Reader(path)
                    print(f"GeoIP database loaded: {path}")
                    return
                except Exception as e:
                    print(f"Warning: Failed to load GeoIP database {path}: {e}")
        
        # GeoIP database not found - silently disable (no warning needed)
        # Users can still use the service without GeoIP lookup
    
    def resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address with caching"""
        if domain in self._dns_cache:
            return self._dns_cache[domain]
        
        try:
            ip = socket.gethostbyname(domain)
            self._dns_cache[domain] = ip
            return ip
        except socket.gaierror:
            self._dns_cache[domain] = None
            return None
    
    def _lookup_via_api(self, ip: str) -> Optional[str]:
        """Fallback: lookup country code via free APIs
        Priority: ip-api.com -> ipwho.is
        """
        import requests
        
        # Try ip-api.com first (45 req/min, no key needed)
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('countryCode'):
                    return data['countryCode']
        except Exception:
            pass
        
        # Try ipwho.is (unlimited, no key needed)
        try:
            resp = requests.get(f"https://ipwho.is/{ip}?fields=country_code", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('country_code'):
                    return data['country_code']
        except Exception:
            pass
        
        return None
    
    def lookup(self, server: str) -> Optional[str]:
        """Lookup country code for server (IP or domain)
        Returns ISO country code (e.g., 'US', 'JP') or None
        Priority: 1. Local GeoLite2 DB  2. ip-api.com  3. ipwho.is
        """
        # Check cache first
        if server in self._geoip_cache:
            return self._geoip_cache[server]
        
        # Determine if server is IP or domain
        ip = server
        try:
            socket.inet_aton(server)  # Check if valid IPv4
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, server)  # Check if valid IPv6
            except socket.error:
                # It's a domain, resolve it
                ip = self.resolve_domain(server)
                if not ip:
                    self._geoip_cache[server] = None
                    return None
        
        country_code = None
        
        # Priority 1: Try local GeoIP database
        if self._reader:
            try:
                response = self._reader.country(ip)
                country_code = response.country.iso_code
            except Exception:
                pass
        
        # Priority 2 & 3: Fallback to APIs if local DB failed
        if not country_code:
            country_code = self._lookup_via_api(ip)
        
        self._geoip_cache[server] = country_code
        return country_code
    
    def get_country_group(self, server: str) -> Optional[str]:
        """Get country group name (e.g., '🇺🇸 美国') for server"""
        country_code = self.lookup(server)
        if not country_code:
            return None
        
        flag = self.COUNTRY_CODE_TO_FLAG.get(country_code, '🔰')
        name = self.COUNTRY_CODE_TO_NAME.get(country_code, country_code)
        return f"{flag} {name}"
    
    def get_flag(self, server: str) -> Optional[str]:
        """Get flag emoji for server"""
        country_code = self.lookup(server)
        if not country_code:
            return None
        return self.COUNTRY_CODE_TO_FLAG.get(country_code)


# ==================== CountryGrouper ====================

class CountryGrouper:
    """Group proxy nodes by country/region"""
    
    # Country identification patterns: Group name -> keyword list
    COUNTRY_PATTERNS = {
        '🇭🇰 香港': ['🇭🇰', 'hongkong', 'hong kong', 'hk', '香港', '港'],
        '🇹🇼 台湾': ['🇹🇼', 'taiwan', 'tw', '台湾', '台', 'taipei'],
        '🇯🇵 日本': ['🇯🇵', 'japan', 'jp', '日本', '日'],
        '🇰🇷 韩国': ['🇰🇷', 'korea', 'kr', 'kor', '韩国', '韩', '首尔', 'seoul'],
        '🇸🇬 新加坡': ['🇸🇬', 'singapore', 'sg', '新加坡', '狮城', '坡'],
        '🇺🇸 美国': ['🇺🇸', 'usa', 'us', 'united states', 'america', '美国', '美', 'la', 'los angeles', 'seattle', 'san jose', 'dallas', 'chicago', 'miami', 'new york', 'silicon valley', '硅谷', '洛杉矶', '西雅图', '纽约'],
        '🇬🇧 英国': ['🇬🇧', 'uk', 'gb', 'united kingdom', 'britain', 'england', '英国', '英', 'london', '伦敦'],
        '🇩🇪 德国': ['🇩🇪', 'germany', 'de', 'deutsch', '德国', '德', 'frankfurt', '法兰克福'],
        '🇫🇷 法国': ['🇫🇷', 'france', 'fr', '法国', '法', 'paris', '巴黎'],
        '🇳🇱 荷兰': ['🇳🇱', 'netherlands', 'nl', 'holland', '荷兰', '荷', 'amsterdam', '阿姆斯特丹'],
        '🇧🇾 白俄罗斯': ['🇧🇾', 'belarus', 'by', '白俄罗斯', 'minsk', '明斯克'],  # MUST be before Russia!
        '🇷🇺 俄罗斯': ['🇷🇺', 'russia', 'ru', '俄罗斯', 'moscow', '莫斯科'],
        '🇨🇦 加拿大': ['🇨🇦', 'canada', 'ca', '加拿大', '加', 'toronto', 'vancouver', '多伦多', '温哥华'],
        '🇦🇺 澳大利亚': ['🇦🇺', 'australia', 'au', '澳大利亚', '澳洲', '澳', 'sydney', '悉尼'],
        '🇮🇳 印度': ['🇮🇳', 'india', '印度', 'mumbai', '孟买'],
        '🇹🇷 土耳其': ['🇹🇷', 'turkey', 'tr', '土耳其', 'istanbul', '伊斯坦布尔'],
        '🇲🇾 马来西亚': ['🇲🇾', 'malaysia', 'my', '马来西亚', '马来', '大马', 'kuala lumpur', '吉隆坡'],
        '🇹🇭 泰国': ['🇹🇭', 'thailand', 'th', '泰国', '泰', 'bangkok', '曼谷'],
        '🇻🇳 越南': ['🇻🇳', 'vietnam', 'vn', '越南', '越'],
        '🇮🇩 印尼': ['🇮🇩', 'indonesia', '印尼', '印度尼西亚', 'jakarta', '雅加达'],
        '🇵🇭 菲律宾': ['🇵🇭', 'philippines', 'ph', '菲律宾', '菲', 'manila', '马尼拉'],
        '🇧🇷 巴西': ['🇧🇷', 'brazil', 'br', '巴西', 'sao paulo', '圣保罗'],
        '🇦🇷 阿根廷': ['🇦🇷', 'argentina', 'ar', '阿根廷', 'buenos aires', '布宜诺斯艾利斯'],
        '🇲🇽 墨西哥': ['🇲🇽', 'mexico', 'mx', '墨西哥'],
        '🇿🇦 南非': ['🇿🇦', 'south africa', 'za', '南非', 'johannesburg', '约翰内斯堡'],
        '🇦🇪 阿联酋': ['🇦🇪', 'uae', 'ae', 'dubai', '阿联酋', '迪拜', 'abu dhabi', '阿布扎比'],
        '🇮🇱 以色列': ['🇮🇱', 'israel', 'il', '以色列', 'tel aviv', '特拉维夫'],
        '🇺🇦 乌克兰': ['🇺🇦', 'ukraine', 'ua', '乌克兰', 'kiev', '基辅'],
        '🇵🇱 波兰': ['🇵🇱', 'poland', 'pl', '波兰', 'warsaw', '华沙'],
        '🇨🇭 瑞士': ['🇨🇭', 'switzerland', 'ch', '瑞士', 'zurich', '苏黎世'],
        '🇸🇪 瑞典': ['🇸🇪', 'sweden', 'se', '瑞典', 'stockholm', '斯德哥尔摩'],
        '🇳🇴 挪威': ['🇳🇴', 'norway', 'no', '挪威', 'oslo', '奥斯陆'],
        '🇫🇮 芬兰': ['🇫🇮', 'finland', 'fi', '芬兰', 'helsinki', '赫尔辛基'],
        '🇩🇰 丹麦': ['🇩🇰', 'denmark', 'dk', '丹麦', 'copenhagen', '哥本哈根'],
        '🇮🇹 意大利': ['🇮🇹', 'italy', 'it', '意大利', '意', 'rome', 'milan', '罗马', '米兰'],
        '🇪🇸 西班牙': ['🇪🇸', 'spain', 'es', '西班牙', 'madrid', 'barcelona', '马德里', '巴塞罗那'],
        '🇳🇬 尼日利亚': ['🇳🇬', 'nigeria', 'ng', '尼日利亚'],
        '🇳🇿 新西兰': ['🇳🇿', 'new zealand', 'nz', '新西兰', 'auckland', '奥克兰'],
        '🇲🇩 摩尔多瓦': ['🇲🇩', 'moldova', 'md', '摩尔多瓦'],
        '🇮🇪 爱尔兰': ['🇮🇪', 'ireland', 'ie', '爱尔兰', 'dublin', '都柏林'],
        '🇵🇹 葡萄牙': ['🇵🇹', 'portugal', 'pt', '葡萄牙', 'lisbon', '里斯本'],
        '🇬🇷 希腊': ['🇬🇷', 'greece', 'gr', '希腊', 'athens', '雅典'],
        '🇦🇹 奥地利': ['🇦🇹', 'austria', 'at', '奥地利', 'vienna', '维也纳'],
        '🇨🇿 捷克': ['🇨🇿', 'czech', 'cz', '捷克', 'prague', '布拉格'],
        '🇭🇺 匈牙利': ['🇭🇺', 'hungary', 'hu', '匈牙利', 'budapest', '布达佩斯'],
        '🇷🇴 罗马尼亚': ['🇷🇴', 'romania', 'ro', '罗马尼亚', 'bucharest', '布加勒斯特'],
        '🇧🇬 保加利亚': ['🇧🇬', 'bulgaria', 'bg', '保加利亚', 'sofia', '索非亚'],
        '🇰🇿 哈萨克斯坦': ['🇰🇿', 'kazakhstan', 'kz', '哈萨克斯坦', '哈萨克'],
        '🇪🇬 埃及': ['🇪🇬', 'egypt', 'eg', '埃及', 'cairo', '开罗'],
        '🇰🇪 肯尼亚': ['🇰🇪', 'kenya', 'ke', '肯尼亚', 'nairobi', '内罗毕'],
        '🇵🇰 巴基斯坦': ['🇵🇰', 'pakistan', 'pk', '巴基斯坦', 'karachi', '卡拉奇'],
        '🇧🇩 孟加拉': ['🇧🇩', 'bangladesh', 'bd', '孟加拉', 'dhaka', '达卡'],
        '🇨🇱 智利': ['🇨🇱', 'chile', 'cl', '智利', 'santiago', '圣地亚哥'],
        '🇦🇶 南极洲': ['🇦🇶', 'antarctica', 'aq', '南极'],
        '🇰🇵 朝鲜': ['🇰🇵', 'north korea', 'kp', 'dprk', '朝鲜', '北朝鲜', '平壤', 'pyongyang'],
        '🇲🇳 蒙古': ['🇲🇳', 'mongolia', 'mn', '蒙古', 'ulaanbaatar', '乌兰巴托'],
        '🇳🇵 尼泊尔': ['🇳🇵', 'nepal', 'np', '尼泊尔', 'kathmandu', '加德满都'],
        '🇱🇰 斯里兰卡': ['🇱🇰', 'sri lanka', 'lk', '斯里兰卡', 'colombo', '科伦坡'],
        '🇮🇷 伊朗': ['🇮🇷', 'iran', 'ir', '伊朗', 'tehran', '德黑兰'],
        '🇸🇦 沙特': ['🇸🇦', 'saudi arabia', 'sa', '沙特', '沙特阿拉伯', 'riyadh', '利雅得'],
        '🇶🇦 卡塔尔': ['🇶🇦', 'qatar', 'qa', '卡塔尔', 'doha', '多哈'],
        '🇰🇼 科威特': ['🇰🇼', 'kuwait', 'kw', '科威特'],
        '🇴🇲 阿曼': ['🇴🇲', 'oman', 'om', '阿曼', 'muscat', '马斯喀特'],
        '🇧🇭 巴林': ['🇧🇭', 'bahrain', 'bh', '巴林'],
        '🇱🇧 黎巴嫩': ['🇱🇧', 'lebanon', 'lb', '黎巴嫩', 'beirut', '贝鲁特'],
        '🇯🇴 约旦': ['🇯🇴', 'jordan', 'jo', '约旦', 'amman', '安曼'],
        '🇮🇶 伊拉克': ['🇮🇶', 'iraq', 'iq', '伊拉克', 'baghdad', '巴格达'],
        '🇸🇾 叙利亚': ['🇸🇾', 'syria', 'sy', '叙利亚', 'damascus', '大马士革'],
        '🇦🇫 阿富汗': ['🇦🇫', 'afghanistan', 'af', '阿富汗', 'kabul', '喀布尔'],
        '🇲🇲 缅甸': ['🇲🇲', 'myanmar', 'mm', 'burma', '缅甸', 'yangon', '仰光'],
        '🇰🇭 柬埔寨': ['🇰🇭', 'cambodia', 'kh', '柬埔寨', 'phnom penh', '金边'],
        '🇱🇦 老挝': ['🇱🇦', 'laos', 'la', '老挝', 'vientiane', '万象'],
        '🇧🇳 文莱': ['🇧🇳', 'brunei', 'bn', '文莱'],
        '🇲🇴 澳门': ['🇲🇴', 'macau', 'macao', 'mo', '澳门', '濠江'],
        '🇮🇸 冰岛': ['🇮🇸', 'iceland', 'is', '冰岛', 'reykjavik', '雷克雅未克'],
        '🇱🇺 卢森堡': ['🇱🇺', 'luxembourg', 'lu', '卢森堡'],
        '🇧🇪 比利时': ['🇧🇪', 'belgium', 'be', '比利时', 'brussels', '布鲁塞尔'],
        '🇸🇰 斯洛伐克': ['🇸🇰', 'slovakia', 'sk', '斯洛伐克', 'bratislava', '布拉迪斯拉发'],
        '🇸🇮 斯洛文尼亚': ['🇸🇮', 'slovenia', 'si', '斯洛文尼亚', 'ljubljana', '卢布尔雅那'],
        '🇭🇷 克罗地亚': ['🇭🇷', 'croatia', 'hr', '克罗地亚', 'zagreb', '萨格勒布'],
        '🇷🇸 塞尔维亚': ['🇷🇸', 'serbia', 'rs', '塞尔维亚', 'belgrade', '贝尔格莱德'],
        '🇧🇦 波黑': ['🇧🇦', 'bosnia', 'ba', '波黑', '波斯尼亚'],
        '🇲🇪 黑山': ['🇲🇪', 'montenegro', 'me', '黑山'],
        '🇲🇰 北马其顿': ['🇲🇰', 'macedonia', 'mk', '马其顿', '北马其顿'],
        '🇦🇱 阿尔巴尼亚': ['🇦🇱', 'albania', 'al', '阿尔巴尼亚', 'tirana', '地拉那'],
        '🇱🇹 立陶宛': ['🇱🇹', 'lithuania', 'lt', '立陶宛', 'vilnius', '维尔纽斯'],
        '🇱🇻 拉脱维亚': ['🇱🇻', 'latvia', 'lv', '拉脱维亚', 'riga', '里加'],
        '🇪🇪 爱沙尼亚': ['🇪🇪', 'estonia', 'ee', '爱沙尼亚', 'tallinn', '塔林'],
        '🇬🇪 格鲁吉亚': ['🇬🇪', 'georgia', 'ge', '格鲁吉亚', 'tbilisi', '第比利斯'],
        '🇦🇲 亚美尼亚': ['🇦🇲', 'armenia', 'am', '亚美尼亚', 'yerevan', '埃里温'],
        '🇦🇿 阿塞拜疆': ['🇦🇿', 'azerbaijan', 'az', '阿塞拜疆', 'baku', '巴库'],
        '🇺🇿 乌兹别克': ['🇺🇿', 'uzbekistan', 'uz', '乌兹别克斯坦', 'tashkent', '塔什干'],
        '🇹🇲 土库曼': ['🇹🇲', 'turkmenistan', 'tm', '土库曼斯坦'],
        '🇰🇬 吉尔吉斯': ['🇰🇬', 'kyrgyzstan', 'kg', '吉尔吉斯斯坦', 'bishkek', '比什凯克'],
        '🇹🇯 塔吉克': ['🇹🇯', 'tajikistan', 'tj', '塔吉克斯坦'],
        '🇨🇴 哥伦比亚': ['🇨🇴', 'colombia', 'co', '哥伦比亚', 'bogota', '波哥大'],
        '🇵🇪 秘鲁': ['🇵🇪', 'peru', 'pe', '秘鲁', 'lima', '利马'],
        '🇻🇪 委内瑞拉': ['🇻🇪', 'venezuela', 've', '委内瑞拉', 'caracas', '加拉加斯'],
        '🇪🇨 厄瓜多尔': ['🇪🇨', 'ecuador', 'ec', '厄瓜多尔', 'quito', '基多'],
        '🇺🇾 乌拉圭': ['🇺🇾', 'uruguay', 'uy', '乌拉圭', 'montevideo', '蒙得维的亚'],
        '🇵🇾 巴拉圭': ['🇵🇾', 'paraguay', 'py', '巴拉圭', 'asuncion', '亚松森'],
        '🇧🇴 玻利维亚': ['🇧🇴', 'bolivia', 'bo', '玻利维亚', 'la paz', '拉巴斯'],
        '🇵🇦 巴拿马': ['🇵🇦', 'panama', 'pa', '巴拿马'],
        '🇨🇷 哥斯达黎加': ['🇨🇷', 'costa rica', 'cr', '哥斯达黎加'],
        '🇨🇺 古巴': ['🇨🇺', 'cuba', 'cu', '古巴', 'havana', '哈瓦那'],
        '🇩🇴 多米尼加': ['🇩🇴', 'dominican', 'do', '多米尼加'],
        '🇵🇷 波多黎各': ['🇵🇷', 'puerto rico', 'pr', '波多黎各'],
        '🇯🇲 牙买加': ['🇯🇲', 'jamaica', 'jm', '牙买加'],
        '🇲🇦 摩洛哥': ['🇲🇦', 'morocco', 'ma', '摩洛哥', 'casablanca', '卡萨布兰卡'],
        '🇹🇳 突尼斯': ['🇹🇳', 'tunisia', 'tn', '突尼斯'],
        '🇩🇿 阿尔及利亚': ['🇩🇿', 'algeria', 'dz', '阿尔及利亚'],
        '🇱🇾 利比亚': ['🇱🇾', 'libya', 'ly', '利比亚'],
        '🇬🇭 加纳': ['🇬🇭', 'ghana', 'gh', '加纳'],
        '🇸🇳 塞内加尔': ['🇸🇳', 'senegal', 'sn', '塞内加尔'],
        '🇨🇮 科特迪瓦': ['🇨🇮', 'ivory coast', 'ci', '科特迪瓦', '象牙海岸'],
        '🇨🇲 喀麦隆': ['🇨🇲', 'cameroon', 'cm', '喀麦隆'],
        '🇹🇿 坦桑尼亚': ['🇹🇿', 'tanzania', 'tz', '坦桑尼亚'],
        '🇺🇬 乌干达': ['🇺🇬', 'uganda', 'ug', '乌干达'],
        '🇷🇼 卢旺达': ['🇷🇼', 'rwanda', 'rw', '卢旺达'],
        '🇪🇹 埃塞俄比亚': ['🇪🇹', 'ethiopia', 'et', '埃塞俄比亚'],
        '🇲🇺 毛里求斯': ['🇲🇺', 'mauritius', 'mu', '毛里求斯'],
        '🇸🇨 塞舌尔': ['🇸🇨', 'seychelles', 'sc', '塞舌尔'],
        '🇲🇻 马尔代夫': ['🇲🇻', 'maldives', 'mv', '马尔代夫', 'male', '马累'],
        '🇬🇺 关岛': ['🇬🇺', 'guam', 'gu', '关岛'],
        '🇫🇯 斐济': ['🇫🇯', 'fiji', 'fj', '斐济'],
        '🇳🇨 新喀里多尼亚': ['🇳🇨', 'new caledonia', 'nc', '新喀里多尼亚'],
        '🇵🇫 法属波利尼西亚': ['🇵🇫', 'french polynesia', 'pf', '法属波利尼西亚', 'tahiti', '塔希提'],
        '🇬🇱 格陵兰': ['🇬🇱', 'greenland', 'gl', '格陵兰'],
        '🇲🇹 马耳他': ['🇲🇹', 'malta', 'mt', '马耳他'],
        '🇨🇾 塞浦路斯': ['🇨🇾', 'cyprus', 'cy', '塞浦路斯'],
    }
    
    @staticmethod
    def identify_country(proxy_name: str, proxy_server: str = None) -> str:
        """Identify country/region of proxy node
        Priority: 1. Flag emoji at START of name  2. Any flag emoji in name  3. Keyword matching (longest match)  4. GeoIP lookup  5. Unknown
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
        
        # Priority 3: Try keyword matching with LONGEST MATCH principle
        # This is critical to avoid "俄罗斯" matching "白俄罗斯"
        import re
        best_match_country = None
        best_match_len = 0
        
        for country, patterns in CountryGrouper.COUNTRY_PATTERNS.items():
            for pattern in patterns[1:]:  # Skip the flag emoji
                # Check if pattern contains Chinese characters
                has_chinese = any('\u4e00' <= c <= '\u9fff' for c in pattern)
                matched = False
                
                if has_chinese:
                    # For Chinese patterns, simple contains check
                    if pattern in proxy_name:
                        matched = True
                elif len(pattern) <= 3:
                    # For short English patterns, require word boundary
                    if re.search(r'(?<![A-Za-z])' + re.escape(pattern) + r'(?![A-Za-z])', proxy_name, re.IGNORECASE):
                        matched = True
                else:
                    # For longer English patterns, simple contains is fine
                    if pattern.upper() in proxy_name.upper():
                        matched = True
                
                # Use longest match to avoid substring issues (e.g., "俄罗斯" in "白俄罗斯")
                if matched and len(pattern) > best_match_len:
                    best_match_len = len(pattern)
                    best_match_country = country
        
        if best_match_country:
            return best_match_country
        
        # Priority 4: GeoIP lookup (if server address provided)
        if proxy_server and GEOIP_AVAILABLE:
            geoip = GeoIPLookup.get_instance()
            country_group = geoip.get_country_group(proxy_server)
            if country_group:
                # Add to COUNTRY_PATTERNS if not exists (for future lookups)
                if country_group not in CountryGrouper.COUNTRY_PATTERNS:
                    # Extract flag from country_group
                    parts = country_group.split(' ', 1)
                    if len(parts) == 2:
                        flag, name = parts
                        CountryGrouper.COUNTRY_PATTERNS[country_group] = [flag, name]
                return country_group
        
        return '🔰 未知'
    
    @staticmethod
    def group_by_country(proxies: List[dict]) -> Dict[str, List[str]]:
        """Group proxy nodes by country/region, return {country: [node_name_list]}"""
        groups: Dict[str, List[str]] = {}
        
        for proxy in proxies:
            name = proxy.get('name', '')
            server = proxy.get('server', '')  # Get server address for GeoIP lookup
            country = CountryGrouper.identify_country(name, server)
            
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
            
            # Filter junk nodes (keyword filter) - use same logic as server.py
            info_keywords = [
                "剩余流量", "套餐到期", "距离下次重置", "建议", "未到期",
                "剩余", "到期", "重置", "流量", "过期", "订阅", "网址", "公告",
                "群组", "Telegram", "TG", "客服", "续费", "购买", "套餐",
                "使用说明", "教程", "更新", "通知", "邀请", "返利",
                "问题", "工单", "咨询", "合作", "会员", "商城", "账号",
                "官网:", "官网：", "免注册"  # 官网+冒号，免注册等广告词
            ]
            
            # Region keywords for valid nodes starting with "官网"
            region_keywords = [
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
                '海外'  # Generic "overseas"
            ]
            
            def is_info_node(name):
                """Check if node is info node (not a real proxy)"""
                # Check basic keywords
                if any(kw in name for kw in info_keywords):
                    return True
                # Check if starts with "官网" but has no region name
                if name.startswith('官网'):
                    # If it contains a region name, it's a valid node
                    if any(region in name for region in region_keywords):
                        return False
                    # Otherwise it's an info node
                    print(f"  [DEBUG] Filtering node without region: {name}")
                    return True
                return False
            
            clean_proxies = []
            for p in valid_proxies:
                name = str(p.get('name', ''))
                if is_info_node(name):
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

