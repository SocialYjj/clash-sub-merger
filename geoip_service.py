"""
GeoIP Service Module
Provides IP geolocation functionality using MaxMind GeoLite2 database.
"""

import os
import re
import socket
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict
from threading import Lock
from functools import lru_cache

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

# Default database path - Use Country version (smaller, faster, sufficient for our needs)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('DATA_DIR', BASE_DIR)
DEFAULT_DB_PATH = os.path.join(DATA_DIR, 'GeoLite2-Country.mmdb')

# Default download URL (GitHub mirror) - Country version is smaller and faster
DEFAULT_DOWNLOAD_URL = "https://git.io/GeoLite2-Country.mmdb"
ALTERNATIVE_DOWNLOAD_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

# GitHub API for checking latest release
GITHUB_RELEASE_API = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"

# Fallback to City version if Country not found
CITY_DB_PATH = os.path.join(DATA_DIR, 'GeoLite2-City.mmdb')

# IP address regex pattern
IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
IPV6_PATTERN = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')


def is_ip_address(address: str) -> bool:
    """Check if the address is an IP address (v4 or v6)"""
    if not address:
        return False
    return bool(IP_PATTERN.match(address) or IPV6_PATTERN.match(address))


@lru_cache(maxsize=1000)
def resolve_domain(domain: str) -> Optional[str]:
    """
    Resolve domain name to IP address with caching.
    Returns None if resolution fails.
    """
    if not domain:
        return None
    
    # If it's already an IP, return as-is
    if is_ip_address(domain):
        return domain
    
    try:
        # Try to resolve the domain
        result = socket.gethostbyname(domain)
        return result
    except (socket.gaierror, socket.herror, socket.timeout):
        return None
    except Exception:
        return None


class GeoIPService:
    """GeoIP database service for IP geolocation"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.reader = None
        self._lock = Lock()
        self._load_database()
    
    def _load_database(self) -> bool:
        """Load GeoIP database file"""
        with self._lock:
            if self.reader:
                try:
                    self.reader.close()
                except:
                    pass
                self.reader = None
            
            if not GEOIP2_AVAILABLE:
                print("Warning: geoip2 library not available")
                return False
            
            # Try primary path first, then fallback to City version
            db_path = self.db_path
            if not Path(db_path).exists():
                # Try City version as fallback
                if Path(CITY_DB_PATH).exists():
                    db_path = CITY_DB_PATH
                    print(f"Country database not found, using City database: {db_path}")
                else:
                    print(f"GeoIP database not found: {self.db_path}")
                    return False
            
            try:
                self.reader = geoip2.database.Reader(db_path)
                self.db_path = db_path  # Update to actual loaded path
                size_mb = Path(db_path).stat().st_size / 1024 / 1024
                print(f"GeoIP database loaded: {db_path} ({size_mb:.2f} MB)")
                return True
            except Exception as e:
                print(f"Failed to load GeoIP database: {e}")
                return False
    
    def reload(self) -> bool:
        """Reload the database (after update)"""
        return self._load_database()
    
    def is_available(self) -> bool:
        """Check if GeoIP database is available and loaded"""
        return self.reader is not None
    
    def get_db_info(self) -> Dict:
        """Get database file information"""
        path = Path(self.db_path)
        
        if not path.exists():
            return {
                "available": False,
                "path": self.db_path,
                "size": 0,
                "size_mb": 0,
                "modified": None,
                "loaded": False
            }
        
        stat = path.stat()
        return {
            "available": True,
            "path": self.db_path,
            "size": stat.st_size,
            "size_mb": round(stat.st_size / 1024 / 1024, 2),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "loaded": self.reader is not None
        }
    
    def get_country(self, address: str) -> Optional[Dict]:
        """
        Get country information for an IP address or domain name.
        If a domain is provided, it will be resolved to IP first.
        
        Returns:
            {
                "iso_code": "US",
                "country_name": "United States",
                "name_en": "United States",
                "flag": "🇺🇸",
                "city": "Los Angeles" (if using City database),
                "resolved_ip": "1.2.3.4" (if domain was resolved)
            }
            or None if lookup fails
        """
        if not self.reader:
            return None
        
        if not address:
            return None
        
        # Resolve domain to IP if needed
        ip = address
        resolved = False
        if not is_ip_address(address):
            resolved_ip = resolve_domain(address)
            if not resolved_ip:
                return None
            ip = resolved_ip
            resolved = True
        
        if ip in ['1.0.0.1', '1.1.1.1']:
            return {
                "iso_code": "US",
                "country_name": "Cloudflare Anycast",
                "name_en": "United States",
                "flag": "🇺🇸"
            }

        try:
            # Try city lookup first (works with both City and Country databases)
            try:
                response = self.reader.city(ip)
                iso_code = response.country.iso_code
                city_name = None
                if hasattr(response, 'city') and response.city:
                    city_name = response.city.names.get("zh-CN") or response.city.name
            except:
                # Fallback to country lookup
                response = self.reader.country(ip)
                iso_code = response.country.iso_code
                city_name = None
            
            if not iso_code:
                return None
            
            result = {
                "iso_code": iso_code,
                "country_name": response.country.names.get("zh-CN") or response.country.name or iso_code,
                "name_en": response.country.name or iso_code,
                "flag": self.iso_to_flag(iso_code)
            }
            
            if city_name:
                result["city"] = city_name
            
            if resolved:
                result["resolved_ip"] = ip
            
            return result
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            print(f"GeoIP lookup error for {address}: {e}")
            return None
    
    def get_country_code(self, ip: str) -> Optional[str]:
        """Get just the ISO country code for an IP"""
        result = self.get_country(ip)
        return result["iso_code"] if result else None
    
    @staticmethod
    def iso_to_flag(iso_code: str) -> str:
        """
        Convert ISO 3166-1 alpha-2 country code to flag emoji
        Example: "US" -> "🇺🇸", "CN" -> "🇨🇳"
        
        Uses Unicode Regional Indicator Symbols:
        - 'A' (U+0041) maps to 🇦 (U+1F1E6)
        - 'Z' (U+005A) maps to 🇿 (U+1F1FF)
        """
        if not iso_code or len(iso_code) != 2:
            return "🌐"
        
        try:
            # Convert each letter to regional indicator symbol
            # Regional indicators start at U+1F1E6 for 'A'
            flag = ""
            for char in iso_code.upper():
                if 'A' <= char <= 'Z':
                    # Calculate offset from 'A' and add to base regional indicator
                    flag += chr(0x1F1E6 + ord(char) - ord('A'))
                else:
                    return "🌐"
            return flag
        except:
            return "🌐"
    
    @staticmethod
    def flag_to_iso(flag: str) -> Optional[str]:
        """
        Convert flag emoji back to ISO country code
        Example: "🇺🇸" -> "US"
        """
        if not flag or len(flag) < 1:
            return None
        
        try:
            # Each flag emoji is 2 regional indicator symbols
            # Regional indicator 🇦 (U+1F1E6) to 🇿 (U+1F1FF)
            iso = ""
            for char in flag:
                cp = ord(char)
                if 0x1F1E6 <= cp <= 0x1F1FF:
                    iso += chr(ord('A') + cp - 0x1F1E6)
            
            if len(iso) == 2:
                return iso
            return None
        except:
            return None
    
    def close(self):
        """Close the database reader"""
        with self._lock:
            if self.reader:
                try:
                    self.reader.close()
                except:
                    pass
                self.reader = None


def download_geoip_database(
    url: str = None,
    save_path: str = None,
    use_proxy: bool = False,
    proxy_url: str = None,
    progress_callback=None
) -> Dict:
    """
    Download GeoIP database from URL
    
    Args:
        url: Download URL (default: GitHub mirror)
        save_path: Where to save the file
        use_proxy: Whether to use proxy for download
        proxy_url: Proxy URL if use_proxy is True
        progress_callback: Function(downloaded_bytes, total_bytes) for progress
    
    Returns:
        {"success": True/False, "message": str, "path": str}
    """
    url = url or DEFAULT_DOWNLOAD_URL
    save_path = save_path or DEFAULT_DB_PATH
    
    proxies = None
    if use_proxy and proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}
    
    try:
        # Create directory if needed
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Download with streaming
        response = requests.get(url, stream=True, proxies=proxies, timeout=60)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        
        # Save to temp file first
        temp_path = save_path + ".tmp"
        with open(temp_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback(downloaded, total_size)
        
        # Verify it's a valid mmdb file (basic check)
        if os.path.getsize(temp_path) < 1000:
            os.remove(temp_path)
            return {
                "success": False,
                "message": "Downloaded file is too small, may be invalid",
                "path": None
            }
        
        # Move temp to final location
        if os.path.exists(save_path):
            os.remove(save_path)
        os.rename(temp_path, save_path)
        
        size_mb = os.path.getsize(save_path) / 1024 / 1024
        return {
            "success": True,
            "message": f"Database downloaded successfully ({size_mb:.2f} MB)",
            "path": save_path
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "message": f"Download failed: {str(e)}",
            "path": None
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error: {str(e)}",
            "path": None
        }


# Global instance
_geoip_service: Optional[GeoIPService] = None


def get_geoip_service() -> GeoIPService:
    """Get or create global GeoIP service instance"""
    global _geoip_service
    if _geoip_service is None:
        _geoip_service = GeoIPService()
    return _geoip_service


def init_geoip_service(db_path: str = None) -> GeoIPService:
    """Initialize global GeoIP service with custom path"""
    global _geoip_service
    _geoip_service = GeoIPService(db_path)
    return _geoip_service


def get_latest_version_info() -> Dict:
    """
    Get latest GeoIP database version info from GitHub releases.
    
    Returns:
        {
            "success": True/False,
            "latest_version": "2025-01-03" (release tag),
            "published_at": "2025-01-03T12:00:00Z",
            "download_url": "https://...",
            "message": str (error message if failed)
        }
    """
    try:
        response = requests.get(
            GITHUB_RELEASE_API,
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=15
        )
        response.raise_for_status()
        
        data = response.json()
        tag_name = data.get("tag_name", "")
        published_at = data.get("published_at", "")
        
        # Find Country database download URL from assets
        download_url = None
        for asset in data.get("assets", []):
            if "Country" in asset.get("name", "") and asset.get("name", "").endswith(".mmdb"):
                download_url = asset.get("browser_download_url")
                break
        
        # Fallback to default URL if not found in assets
        if not download_url:
            download_url = ALTERNATIVE_DOWNLOAD_URL
        
        return {
            "success": True,
            "latest_version": tag_name,
            "published_at": published_at,
            "download_url": download_url,
            "message": "OK"
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "latest_version": None,
            "published_at": None,
            "download_url": None,
            "message": f"Failed to check latest version: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "latest_version": None,
            "published_at": None,
            "download_url": None,
            "message": f"Error: {str(e)}"
        }


def get_local_version_info(db_path: str = None) -> Dict:
    """
    Get local GeoIP database version info.
    
    Returns:
        {
            "exists": True/False,
            "path": str,
            "size_mb": float,
            "modified": "2025-01-01 12:00:00",
            "modified_timestamp": 1704067200,
            "estimated_version": "2025-01" (based on file modification date)
        }
    """
    path = Path(db_path or DEFAULT_DB_PATH)
    
    if not path.exists():
        return {
            "exists": False,
            "path": str(path),
            "size_mb": 0,
            "modified": None,
            "modified_timestamp": None,
            "estimated_version": None
        }
    
    stat = path.stat()
    mtime = datetime.fromtimestamp(stat.st_mtime)
    
    return {
        "exists": True,
        "path": str(path),
        "size_mb": round(stat.st_size / 1024 / 1024, 2),
        "modified": mtime.strftime("%Y-%m-%d %H:%M:%S"),
        "modified_timestamp": int(stat.st_mtime),
        "estimated_version": mtime.strftime("%Y-%m")
    }


def check_update_available(db_path: str = None) -> Dict:
    """
    Check if a newer version of GeoIP database is available.
    
    Returns:
        {
            "update_available": True/False/None (None if check failed),
            "local_version": {...},
            "latest_version": {...},
            "message": str
        }
    """
    local_info = get_local_version_info(db_path)
    latest_info = get_latest_version_info()
    
    if not latest_info["success"]:
        return {
            "update_available": None,
            "local_version": local_info,
            "latest_version": None,
            "message": latest_info["message"]
        }
    
    if not local_info["exists"]:
        return {
            "update_available": True,
            "local_version": local_info,
            "latest_version": latest_info,
            "message": "Database not found, download required"
        }
    
    # Compare versions by parsing the release tag (format: YYYY-MM-DD)
    try:
        latest_tag = latest_info["latest_version"]
        # Parse latest version date
        if latest_tag:
            latest_date = datetime.strptime(latest_tag, "%Y-%m-%d")
            local_mtime = datetime.fromtimestamp(local_info["modified_timestamp"])
            
            # If latest release is newer than local file by more than 1 day
            if (latest_date - local_mtime).days > 1:
                return {
                    "update_available": True,
                    "local_version": local_info,
                    "latest_version": latest_info,
                    "message": f"发现新版本: {latest_tag}"
                }
            else:
                return {
                    "update_available": False,
                    "local_version": local_info,
                    "latest_version": latest_info,
                    "message": "已是最新版本"
                }
    except Exception:
        pass
    
    # Fallback: compare by published_at timestamp
    try:
        published_at = latest_info.get("published_at", "")
        if published_at:
            # Parse ISO format: 2025-01-03T12:00:00Z
            latest_time = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
            local_mtime = datetime.fromtimestamp(local_info["modified_timestamp"])
            
            # Make local_mtime timezone-aware for comparison
            from datetime import timezone
            local_mtime = local_mtime.replace(tzinfo=timezone.utc)
            
            if latest_time > local_mtime:
                return {
                    "update_available": True,
                    "local_version": local_info,
                    "latest_version": latest_info,
                    "message": "发现新版本"
                }
    except Exception:
        pass
    
    return {
        "update_available": False,
        "local_version": local_info,
        "latest_version": latest_info,
        "message": "已是最新版本"
    }
