"""
Speed Test Service Module
Provides node latency and speed testing functionality.
"""

import asyncio
import aiohttp
import time
import socket
from datetime import datetime
from typing import Optional, Dict, List, Callable, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

# GeoIP lookup is now done via online API in server.py


# Default test URLs
DEFAULT_LATENCY_URL = "http://www.gstatic.com/generate_204"
DEFAULT_SPEED_URL = "http://cachefly.cachefly.net/10mb.test"
DEFAULT_LANDING_IP_URL = "https://api.ipify.org"

# Alternative test URLs
ALTERNATIVE_LATENCY_URLS = [
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
    "http://www.google.com/generate_204",
]

ALTERNATIVE_SPEED_URLS = [
    "http://cachefly.cachefly.net/10mb.test",
    "http://speed.cloudflare.com/__down?bytes=10000000",
]


@dataclass
class SpeedTestConfig:
    """Configuration for speed tests"""
    latency_url: str = DEFAULT_LATENCY_URL
    speed_url: str = DEFAULT_SPEED_URL
    landing_ip_url: str = DEFAULT_LANDING_IP_URL
    timeout: int = 10  # seconds
    test_speed: bool = False  # Whether to test download speed
    concurrency: int = 10  # Max concurrent tests


@dataclass
class SpeedTestResult:
    """Result of a speed test"""
    node_id: str = ""
    node_name: str = ""
    
    # Latency test
    latency: int = -1  # ms, -1 = failed
    latency_status: str = "untested"  # untested, success, timeout, error
    
    # Speed test
    speed: float = 0.0  # MB/s
    speed_status: str = "untested"  # untested, success, timeout, error, partial
    bytes_downloaded: int = 0
    
    # Landing IP (exit IP)
    landing_ip: Optional[str] = None
    country: Optional[Dict] = None
    
    # Metadata
    test_time: str = ""
    error: Optional[str] = None


class SpeedTestService:
    """
    Service for testing node latency and speed.
    
    Tests are performed by making HTTP requests through a proxy.
    """
    
    def __init__(self, config: SpeedTestConfig = None):
        self.config = config or SpeedTestConfig()
        self._running_tests: Dict[str, bool] = {}  # Track running tests
    
    async def test_latency(
        self,
        proxy_url: str,
        test_url: str = None,
        timeout: int = None
    ) -> Dict:
        """
        Test latency by making HTTP request through proxy.
        
        Args:
            proxy_url: HTTP proxy URL (e.g., "http://127.0.0.1:7890")
            test_url: URL to test (default: generate_204)
            timeout: Request timeout in seconds
        
        Returns:
            {"status": "success/timeout/error", "latency": ms, "error": str}
        """
        test_url = test_url or self.config.latency_url
        timeout = timeout or self.config.timeout
        
        start = time.time()
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    test_url,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True
                ) as resp:
                    await resp.read()
                    latency = int((time.time() - start) * 1000)
                    return {
                        "status": "success",
                        "latency": latency,
                        "status_code": resp.status
                    }
        except asyncio.TimeoutError:
            return {"status": "timeout", "latency": -1}
        except aiohttp.ClientProxyConnectionError as e:
            return {"status": "error", "latency": -1, "error": f"Proxy connection failed: {e}"}
        except aiohttp.ClientError as e:
            return {"status": "error", "latency": -1, "error": str(e)}
        except Exception as e:
            return {"status": "error", "latency": -1, "error": str(e)}
    
    async def test_speed(
        self,
        proxy_url: str,
        test_url: str = None,
        timeout: int = None
    ) -> Dict:
        """
        Test download speed through proxy.
        
        Args:
            proxy_url: HTTP proxy URL
            test_url: URL to download (default: 10MB test file)
            timeout: Request timeout in seconds
        
        Returns:
            {"status": "success/timeout/error/partial", "speed": MB/s, "bytes": downloaded}
        """
        test_url = test_url or self.config.speed_url
        timeout = timeout or self.config.timeout
        
        start = time.time()
        total_bytes = 0
        
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    test_url,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True
                ) as resp:
                    async for chunk in resp.content.iter_chunked(8192):
                        total_bytes += len(chunk)
                    
                    elapsed = time.time() - start
                    if elapsed > 0:
                        speed = total_bytes / elapsed / 1024 / 1024  # MB/s
                    else:
                        speed = 0
                    
                    return {
                        "status": "success",
                        "speed": round(speed, 2),
                        "bytes": total_bytes,
                        "elapsed": round(elapsed, 2)
                    }
        except asyncio.TimeoutError:
            elapsed = time.time() - start
            if total_bytes > 0 and elapsed > 0:
                speed = total_bytes / elapsed / 1024 / 1024
                return {
                    "status": "partial",
                    "speed": round(speed, 2),
                    "bytes": total_bytes,
                    "elapsed": round(elapsed, 2)
                }
            return {"status": "timeout", "speed": 0, "bytes": 0}
        except Exception as e:
            return {"status": "error", "speed": 0, "bytes": 0, "error": str(e)}
    
    async def get_landing_ip(
        self,
        proxy_url: str,
        timeout: int = 5
    ) -> Optional[str]:
        """
        Get exit IP address through proxy.
        
        Args:
            proxy_url: HTTP proxy URL
            timeout: Request timeout
        
        Returns:
            IP address string or None
        """
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    self.config.landing_ip_url,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    ip = await resp.text()
                    return ip.strip()
        except Exception:
            return None
    
    async def test_node(
        self,
        node: Dict,
        proxy_url: str,
        test_speed: bool = None,
        progress_callback: Callable = None
    ) -> SpeedTestResult:
        """
        Full test for a single node.
        
        Args:
            node: Node configuration dict
            proxy_url: HTTP proxy URL for this node
            test_speed: Whether to test download speed
            progress_callback: Optional callback for progress updates
        
        Returns:
            SpeedTestResult
        """
        test_speed = test_speed if test_speed is not None else self.config.test_speed
        
        result = SpeedTestResult(
            node_id=node.get('id', ''),
            node_name=node.get('name', ''),
            test_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Test latency first
        latency_result = await self.test_latency(proxy_url)
        result.latency = latency_result.get('latency', -1)
        result.latency_status = latency_result.get('status', 'error')
        
        if latency_result.get('error'):
            result.error = latency_result['error']
        
        # If latency test passed, continue with other tests
        if result.latency_status == 'success':
            # Get landing IP
            landing_ip = await self.get_landing_ip(proxy_url)
            if landing_ip:
                result.landing_ip = landing_ip
                # Country lookup is done via online API in server.py
            
            # Test speed if requested
            if test_speed:
                speed_result = await self.test_speed(proxy_url)
                result.speed = speed_result.get('speed', 0)
                result.speed_status = speed_result.get('status', 'error')
                result.bytes_downloaded = speed_result.get('bytes', 0)
        
        return result
    
    async def test_nodes_batch(
        self,
        nodes: List[Dict],
        get_proxy_url: Callable[[Dict], str],
        test_speed: bool = None,
        concurrency: int = None,
        progress_callback: Callable[[int, int, SpeedTestResult], None] = None
    ) -> List[SpeedTestResult]:
        """
        Test multiple nodes with concurrency control.
        
        Args:
            nodes: List of node configurations
            get_proxy_url: Function to get proxy URL for a node
            test_speed: Whether to test download speed
            concurrency: Max concurrent tests
            progress_callback: Callback(completed, total, result) for progress
        
        Returns:
            List of SpeedTestResult
        """
        concurrency = concurrency or self.config.concurrency
        test_speed = test_speed if test_speed is not None else self.config.test_speed
        
        results = []
        semaphore = asyncio.Semaphore(concurrency)
        total = len(nodes)
        completed = 0
        
        async def test_with_semaphore(node: Dict) -> SpeedTestResult:
            nonlocal completed
            async with semaphore:
                proxy_url = get_proxy_url(node)
                result = await self.test_node(node, proxy_url, test_speed)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, result)
                return result
        
        tasks = [test_with_semaphore(node) for node in nodes]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(SpeedTestResult(
                    node_id=nodes[i].get('id', ''),
                    node_name=nodes[i].get('name', ''),
                    latency_status='error',
                    error=str(result),
                    test_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
            else:
                final_results.append(result)
        
        return final_results


def get_latency_color(latency: int) -> str:
    """
    Get color code for latency value.
    
    Returns:
        "green" (<200ms), "yellow" (200-500ms), "red" (>500ms), "gray" (failed)
    """
    if latency < 0:
        return "gray"
    elif latency < 200:
        return "green"
    elif latency < 500:
        return "yellow"
    else:
        return "red"


def get_speed_color(speed: float) -> str:
    """
    Get color code for speed value.
    
    Returns:
        "green" (>1MB/s), "yellow" (0.5-1MB/s), "red" (<0.5MB/s), "gray" (untested)
    """
    if speed <= 0:
        return "gray"
    elif speed > 1.0:
        return "green"
    elif speed >= 0.5:
        return "yellow"
    else:
        return "red"


def format_speed(speed: float) -> str:
    """Format speed value for display"""
    if speed <= 0:
        return "-"
    elif speed >= 1:
        return f"{speed:.1f} MB/s"
    else:
        return f"{speed * 1024:.0f} KB/s"


def format_latency(latency: int) -> str:
    """Format latency value for display"""
    if latency < 0:
        return "超时"
    else:
        return f"{latency} ms"


# Global instance
_speedtest_service: Optional[SpeedTestService] = None


def get_speedtest_service() -> SpeedTestService:
    """Get or create global speed test service instance"""
    global _speedtest_service
    if _speedtest_service is None:
        _speedtest_service = SpeedTestService()
    return _speedtest_service


def init_speedtest_service(config: SpeedTestConfig = None) -> SpeedTestService:
    """Initialize global speed test service with custom config"""
    global _speedtest_service
    _speedtest_service = SpeedTestService(config)
    return _speedtest_service
