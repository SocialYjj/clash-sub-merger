"""
Subscription Parser Service
Parse various subscription formats to Clash config
"""
import yaml
import base64
import json
from urllib.parse import unquote
from typing import Optional
from logger_config import get_logger

logger = get_logger(__name__)


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
            # Ensure content is ASCII before decoding
            content_bytes = content.encode('ascii')
            decoded_bytes = base64.b64decode(content_bytes)
            return decoded_bytes.decode('utf-8')
        except UnicodeEncodeError as e:
            logger.warning(f"Base64 decode failed - content contains non-ASCII characters: {e}")
            return ""
        except UnicodeDecodeError as e:
            logger.warning(f"Base64 decode failed - invalid UTF-8: {e}")
            return ""
        except Exception as e:
            logger.warning(f"Base64 decode failed: {e}")
            return ""

    @staticmethod
    def parse_vmess(vmess_url: str) -> Optional[dict]:
        """Parse vmess:// link"""
        try:
            b64 = vmess_url[8:]
            json_str = SubscriptionParser.decode_base64(b64)
            if not json_str:
                return None
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
            if '#' in ss_url:
                main, remark = ss_url[5:].split('#', 1)
                remark = unquote(remark)
            else:
                main = ss_url[5:]
                remark = "ss"
            
            if '@' in main:
                user_pass_b64, host_port = main.split('@', 1)
                user_pass = SubscriptionParser.decode_base64(user_pass_b64)
                if ':' not in user_pass:
                    return None
                method, password = user_pass.split(':', 1)
                
                if ':' not in host_port:
                    return None
                server, port = host_port.rsplit(':', 1)
            else:
                decoded = SubscriptionParser.decode_base64(main)
                if '@' not in decoded:
                    return None
                user_pass, host_port = decoded.split('@', 1)
                if ':' not in user_pass:
                    return None
                method, password = user_pass.split(':', 1)
                if ':' not in host_port:
                    return None
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
                
            if '@' not in main:
                return None
            password, host_port = main.split('@', 1)
            if ':' not in host_port:
                return None
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
                
            if '@' not in main:
                return None
            uuid, host_port = main.split('@', 1)
            if ':' not in host_port:
                return None
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
            
            params = {}
            if query:
                for pair in query.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = v
            
            network = params.get("type", "tcp")
            proxy["network"] = network
            
            if network == "ws":
                ws_opts = {}
                if "path" in params:
                    ws_opts["path"] = unquote(params["path"])
                if "host" in params:
                    ws_opts["headers"] = {"Host": unquote(params["host"])}
                proxy["ws-opts"] = ws_opts
            elif network == "grpc":
                grpc_opts = {}
                if "serviceName" in params:
                    grpc_opts["grpc-service-name"] = unquote(params["serviceName"])
                proxy["grpc-opts"] = grpc_opts
            
            security = params.get("security", "")
            if security == "tls":
                proxy["tls"] = True
                if "sni" in params:
                    proxy["servername"] = params["sni"]
                if "fp" in params:
                    proxy["client-fingerprint"] = params["fp"]
                if "flow" in params:
                    proxy["flow"] = params["flow"]
            elif security == "reality":
                proxy["tls"] = True
                proxy["flow"] = params.get("flow", "xtls-rprx-vision")
                if "sni" in params:
                    proxy["servername"] = params["sni"]
                if "fp" in params:
                    proxy["client-fingerprint"] = params["fp"]
                
                reality_opts = {}
                if "pbk" in params:
                    reality_opts["public-key"] = params["pbk"]
                if "sid" in params:
                    reality_opts["short-id"] = params["sid"]
                if "spx" in params:
                    reality_opts["spider-x"] = params["spx"]
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
            
            if '/?' in decoded:
                main, query = decoded.split('/?', 1)
            else:
                main = decoded
                query = ""
                
            parts = main.split(':')
            if len(parts) != 6:
                return None
            
            server = parts[0]
            port = int(parts[1])
            protocol = parts[2]
            method = parts[3]
            obfs = parts[4]
            password = SubscriptionParser.decode_base64(parts[5])
            
            proxy = {
                "name": "ssr",
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
                        params[k] = v
                        
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
                
            if '@' not in main:
                return None
            password, host_port = main.split('@', 1)
            
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
                "udp": True
            }
            
            if query:
                params = {}
                for pair in query.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        params[k] = v
                
                if 'sni' in params:
                    proxy['sni'] = params['sni']
                if 'insecure' in params:
                    proxy['skip-cert-verify'] = (params['insecure'] == '1')
                # Only set obfs if it's specified and not "none"
                if 'obfs' in params and params['obfs'] and params['obfs'].lower() != 'none':
                    proxy['obfs'] = params['obfs']
                    if 'obfs-password' in params:
                        proxy['obfs-password'] = params['obfs-password']
            
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
        except yaml.YAMLError as e:
            logger.debug(f"Content is not YAML format: {e}")
        except Exception as e:
            logger.warning(f"Error parsing YAML: {e}")
            
        # 2. Try Base64 decode
        try:
            decoded = SubscriptionParser.decode_base64(content)
            if 'proxies:' in decoded:
                return yaml.safe_load(decoded) or {}
        except yaml.YAMLError as e:
            logger.debug(f"Decoded content is not YAML: {e}")
            decoded = content
        except Exception as e:
            logger.warning(f"Error decoding Base64: {e}")
            decoded = content
            
        # 3. Parse link list
        proxies = []
        lines = decoded.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
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
                try:
                    p = json.loads(line)
                    if isinstance(p, dict) and 'name' in p and 'type' in p:
                        proxies.append(p)
                except json.JSONDecodeError:
                    pass
                continue
                
            if p:
                proxies.append(p)
            
        if proxies:
            return {"proxies": proxies}
            
        return {}
