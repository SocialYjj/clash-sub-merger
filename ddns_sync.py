#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDNS Sync for SubMerger
=======================

独立脚本，运行在自建节点所在机器上。定时检测本机公网 IP：
  - IPv4：轮询公网 checkip 接口
  - IPv6：读取指定网卡（如 ens5）的全局地址

当 IP 发生变化时，通过文件锁与 SubMerger 进程互斥，原子地更新
data/config.json 中"本机自建节点"的 server 与 link 两个字段。

前提：SubMerger 与自建节点部署在同一台机器（脚本需能本地读 config.json）。
若不在同机，请改用 HTTP API 方式更新，本脚本不适用。

设计要点：
  1. 只更新"本机节点"——通过 MONITORED_NODE_IDS 精确指定，避免误伤
     config.json 中其他机器的节点（custom_nodes 里混了多台机器）。
  2. IP 同时出现在 server（明文）与 link（分享链接 @host:port）两处，必须同步。
     IPv6 在 link 中带方括号 [::1]，用正则按 host 位置精确替换。
  3. 写入复刻 core/database.py 的原子写逻辑：临时文件 + fsync + os.replace
     + 自动 .backup，并使用同一个 config.json.lock 与运行中的服务互斥。
  4. SubMerger 的 load_config 依据 mtime 失效缓存，文件被外部替换后会自动
     重新加载，无需主动通知。

用法：
  python ddns_sync.py              # 检测并按需更新
  python ddns_sync.py --check      # 只检测不写入（dry-run）
  python ddns_sync.py --force      # 强制写回（即使 IP 未变）
  python ddns_sync.py --list       # 列出所有 custom_nodes 的 id/name/server，便于挑选监控目标

建议用 cron / systemd timer 定时执行，例如每 5 分钟：
  */5 * * * * cd /opt/clash-sub-merger && /usr/bin/python3 ddns_sync.py >> /dev/null 2>&1
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

try:
    from filelock import FileLock, Timeout
except ImportError:
    print(
        "ERROR: filelock 未安装。请在 SubMerger 的运行环境内执行本脚本，"
        "或 pip install filelock>=3.13.0",
        file=sys.stderr,
    )
    raise

# =============================================================================
# 配置区（按需修改）
# =============================================================================

# 项目根目录（脚本所在目录），config.json 等均相对它定位
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "data" / "config.json"
LOCK_FILE = BASE_DIR / "data" / "config.json.lock"
STATE_FILE = BASE_DIR / "data" / "ddns_state.json"
LOG_DIR = BASE_DIR / "data" / "logs"

# ---- 监控目标 ----
# 本机自建节点的 id 列表。留空则启用"按基准 IP 自动匹配"模式（见下方 BASE_V4/BASE_V6）。
# 强烈建议显式填写 id：custom_nodes 里混了多台机器的节点，精确指定最安全。
# 用 `python ddns_sync.py --list` 查看所有节点 id。
# 本机自建节点的 id 列表（用 `python ddns_sync.py --list` 查询）。
# 当前监控本机三个 JP 节点（共用一台机器，分别是 v4/v6 × 三种协议）。
MONITORED_NODE_IDS: list[str] = [
    "node_1778293140529_0",   # JP-xhttp-reality   (v4)
    "node_1778293140529_2",   # JP-tcp-reality-v6  (v6)
    "node_1778293140529_1",   # JP-ws              (v4)
]

# 仅当 MONITORED_NODE_IDS 为空时启用：本机当前基准 IP。
# 脚本会把 config.json 中所有 server 等于该值的节点视作本机节点并跟踪。
# 首次填写当前真实 IP；之后脚本会用 state 文件滚动跟踪，无需再改这里。
BASE_V4: str = ""   # 例 "138.197.237.55"
BASE_V6: str = ""   # 例 "2604:a880:2:d1:0:1:2c93:5001"

# ---- IPv4 获取（公网 checkip 接口，按顺序尝试，首个成功即用）----
V4_API_LIST: list[str] = [
    "https://ddns.oray.com/checkip",
    "https://ip.3322.net",
    "https://4.ipw.cn",
    "https://v4.yinghualuo.cn/bejson",
    "https://myip.ipip.net",
]
# checkip 接口返回体里提取 IPv4 的正则
V4_REGEX = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)")

# ---- IPv6 获取（读网卡全局地址）----
V6_INTERFACE = "ens5"
# 可选：仅匹配该前缀的全局地址，避免取到 SLAAC 临时隐私地址；留空取第一个全局地址
V6_PREFIX_FILTER = ""   # 例 "2604:a880:"

# ---- 行为开关 ----
# IP 变化后是否调用 SubMerger 刷新接口（留空=不调用，依赖 mtime 自动重载）
REFRESH_API = ""        # 例 "http://127.0.0.1:8000/api/subscription/refresh"
REFRESH_TOKEN = ""      # 若接口需要鉴权

# 单次 checkip 请求超时（秒）
HTTP_TIMEOUT = 8

# =============================================================================
# 日志
# =============================================================================

LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "ddns_sync.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("ddns_sync")


# =============================================================================
# IP 检测
# =============================================================================

def get_current_v4() -> Optional[str]:
    """轮询 V4_API_LIST，从响应中提取公网 IPv4。"""
    import urllib.request

    for url in V4_API_LIST:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ddns-sync/1.0"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
            m = V4_REGEX.search(body)
            if m:
                log.info("v4 获取成功 [%s]: %s", url, m.group(0))
                return m.group(0)
            log.warning("v4 接口 %s 响应中未匹配到 IP: %r", url, body[:120])
        except Exception as e:
            log.warning("v4 接口 %s 失败: %s", url, e)
    log.error("所有 v4 接口均失败")
    return None


def get_current_v6(iface: str = V6_INTERFACE) -> Optional[str]:
    """读取指定网卡的全局 IPv6 地址（过滤 link-local/回环/组播）。"""
    candidates: list[str] = []

    # 方式 1：ip 命令（Linux）
    try:
        out = subprocess.run(
            ["ip", "-6", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            # 行形如: inet6 2604:a880:2:d1::1/64 scope global
            for line in out.stdout.splitlines():
                m = re.search(r"inet6\s+([0-9a-fA-F:]+)/\d+\s+scope\s+global", line)
                if m:
                    candidates.append(m.group(1))
    except FileNotFoundError:
        pass
    except Exception as e:
        log.debug("ip 命令读取 v6 失败: %s", e)

    # 方式 2：socket（取本机所有 v6，过滤）
    if not candidates:
        try:
            for _name, _fam, _type, _proto, sockaddr in socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET6
            ):
                addr = sockaddr[0].split("%")[0]
                candidates.append(addr)
        except Exception as e:
            log.debug("getaddrinfo 读取 v6 失败: %s", e)

    # 过滤：排除 link-local(fe80::/10)、回环(::1)、组播(ff00::/8)、未指定(::)
    def is_global_v6(a: str) -> bool:
        try:
            ip = ip_normalize(a)
            if ip in ("::1", "::"):
                return False
            if ip.lower().startswith("fe80"):
                return False
            if ip.lower().startswith("ff"):
                return False
            return True
        except Exception:
            return False

    valid = [ip_normalize(c) for c in candidates if is_global_v6(c)]
    if V6_PREFIX_FILTER:
        valid = [v for v in valid if v.lower().startswith(V6_PREFIX_FILTER.lower())]

    if not valid:
        log.error("网卡 %s 未找到全局 IPv6 地址", iface)
        return None

    log.info("v6 获取成功 [%s]: %s", iface, valid[0])
    return valid[0]


def ip_normalize(addr: str) -> str:
    """用 ipaddress 压缩 IPv6 表示，便于比较。"""
    import ipaddress
    return str(ipaddress.ip_address(addr))


def is_ipv4(s: str) -> bool:
    try:
        import ipaddress
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def is_ipv6(s: str) -> bool:
    try:
        import ipaddress
        ipaddress.IPv6Address(s)
        return True
    except Exception:
        return False


# =============================================================================
# state 文件（记录上次同步到的本机 IP，用于滚动跟踪）
# =============================================================================

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, STATE_FILE)


# =============================================================================
# link 字段 host 替换
# =============================================================================

# 匹配 URI 中 userinfo@host:port 的 host 部分（IPv6 带 []，其余为明文）
_HOST_IN_URI = re.compile(r"@(\[[^\]]+\]|[^:@/?#]+):")


def format_host(ip: str) -> str:
    """link 中 host 的书写形式：IPv6 加方括号，其余原样。"""
    if is_ipv6(ip):
        return f"[{ip}]"
    return ip


def replace_host_in_link(link: str, new_ip: str) -> str:
    """把 link 中第一个 @host: 的 host 替换为 new_ip。"""
    new_host = format_host(new_ip)
    return _HOST_IN_URI.sub(f"@{new_host}:", link, count=1)


# =============================================================================
# config.json 原子写入（复刻 core/database.py 逻辑，与运行中的服务互斥）
# =============================================================================

def atomic_update_config(mutator):
    """
    在持有 config.json.lock 的前提下，读取-修改-写回 config.json。
    mutator(config) -> changed(bool) | 可对 config 原地修改。
    返回 (changed, mutator 返回值)。
    """
    lock = FileLock(str(LOCK_FILE), timeout=30)
    try:
        with lock:
            if not CONFIG_FILE.exists():
                log.error("config.json 不存在: %s", CONFIG_FILE)
                return False, None
            config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            changed = mutator(config)
            if not changed:
                return False, None
            # 原子写：tmp + fsync + 备份 + replace
            tmp = CONFIG_FILE.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            backup = CONFIG_FILE.with_suffix(".backup")
            if CONFIG_FILE.exists():
                shutil.copy2(CONFIG_FILE, backup)
            os.replace(tmp, CONFIG_FILE)
            return True, None
    except Timeout:
        log.error("获取 config.json.lock 超时（SubMerger 可能正在写入），本次跳过")
        return False, None
    except Exception as e:
        log.error("更新 config.json 失败: %s", e, exc_info=True)
        return False, None


# =============================================================================
# 刷新通知（可选）
# =============================================================================

def notify_refresh() -> None:
    if not REFRESH_API:
        return
    try:
        import urllib.request
        headers = {"User-Agent": "ddns-sync/1.0"}
        if REFRESH_TOKEN:
            headers["Authorization"] = f"Bearer {REFRESH_TOKEN}"
        req = urllib.request.Request(REFRESH_API, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            log.info("刷新接口已调用，HTTP %s", resp.status)
    except Exception as e:
        log.warning("刷新接口调用失败: %s", e)


# =============================================================================
# 核心：解析监控目标
# =============================================================================

def resolve_targets(config: dict) -> list[dict]:
    """
    返回本机节点列表（config['custom_nodes'] 中的引用），并标注其 ip 版本。
    优先用 MONITORED_NODE_IDS；为空则用 BASE_V4/BASE_V6 匹配 server。
    """
    nodes = config.get("custom_nodes", [])
    targets: list[dict] = []

    if MONITORED_NODE_IDS:
        id_set = set(MONITORED_NODE_IDS)
        for n in nodes:
            if n.get("id") in id_set:
                targets.append(n)
        missing = id_set - {t.get("id") for t in targets}
        if missing:
            log.warning("以下 node id 在 custom_nodes 中未找到: %s", missing)
    else:
        bases = {b for b in (BASE_V4, BASE_V6) if b}
        if not bases:
            log.error("未配置 MONITORED_NODE_IDS，且 BASE_V4/BASE_V6 均为空，无法定位本机节点")
            return []
        for n in nodes:
            srv = n.get("server", "")
            if srv in bases:
                targets.append(n)

    for t in targets:
        srv = t.get("server", "")
        t["__ipver"] = "v4" if is_ipv4(srv) else ("v6" if is_ipv6(srv) else "host")
    return targets


# =============================================================================
# 主流程
# =============================================================================

def cmd_list() -> None:
    """列出所有 custom_nodes，便于挑选监控 id。"""
    if not CONFIG_FILE.exists():
        log.error("config.json 不存在")
        return
    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    nodes = config.get("custom_nodes", [])
    print(f"共 {len(nodes)} 个自建节点：")
    print(f"{'id':<32} {'ipver':<5} {'server':<42} name")
    print("-" * 100)
    for n in nodes:
        srv = n.get("server", "")
        ver = "v4" if is_ipv4(srv) else ("v6" if is_ipv6(srv) else "host")
        print(f"{n.get('id',''):<32} {ver:<5} {srv:<42} {n.get('name','')}")


def sync_once(check_only: bool = False, force: bool = False) -> int:
    """执行一次检测与同步。返回 0=无变化/成功, 1=有变化已更新, 2=出错。"""
    cur_v4 = get_current_v4()
    cur_v6 = get_current_v6()

    if cur_v4 is None and cur_v6 is None:
        log.error("v4 与 v6 均获取失败，本次放弃")
        return 2

    state = load_state()
    prev_v4 = state.get("last_v4")
    prev_v6 = state.get("last_v6")

    v4_changed = cur_v4 is not None and cur_v4 != prev_v4
    v6_changed = cur_v6 is not None and cur_v6 != prev_v6

    if not (v4_changed or v6_changed or force):
        log.info("IP 未变化 (v4=%s, v6=%s)，无需更新", cur_v4, cur_v6)
        return 0

    log.info(
        "检测到变化: v4 %s->%s | v6 %s->%s%s",
        prev_v4, cur_v4, prev_v6, cur_v6, " [FORCE]" if force else ""
    )

    if check_only:
        log.info("--check 模式，不写入")
        return 1

    def mutator(config: dict) -> bool:
        targets = resolve_targets(config)
        if not targets:
            log.error("未定位到任何本机节点，跳过写入")
            return False

        any_change = False
        for n in targets:
            ipver = n["__ipver"]
            old_server = n.get("server", "")
            new_ip = cur_v4 if ipver == "v4" else (cur_v6 if ipver == "v6" else None)
            if new_ip is None:
                log.warning("节点 %s 标记为 %s 但对应新 IP 不可用，跳过", n.get("id"), ipver)
                continue
            # 比较需与规范化的旧值一致
            try:
                old_norm = ip_normalize(old_server) if ipver in ("v4", "v6") else old_server
            except Exception:
                old_norm = old_server
            if not force and old_norm == new_ip:
                continue
            # 更新 server
            n["server"] = new_ip
            # 更新 link（若存在）
            link = n.get("link")
            if link:
                n["link"] = replace_host_in_link(link, new_ip)
            log.info(
                "更新节点 %s (%s): %s -> %s",
                n.get("id"), n.get("name"), old_server, new_ip
            )
            any_change = True
        return any_change

    changed, _ = atomic_update_config(mutator)
    if changed:
        state["last_v4"] = cur_v4
        state["last_v6"] = cur_v6
        state["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_state(state)
        log.info("config.json 已更新，state 已记录")
        notify_refresh()
        return 1

    # 未定位到节点或无变化，但若 force/state 缺失也更新一下 state 基准
    if force and (cur_v4 or cur_v6):
        state["last_v4"] = cur_v4 or prev_v4
        state["last_v6"] = cur_v6 or prev_v6
        state["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_state(state)
    return 2 if not changed and not MONITORED_NODE_IDS and not (BASE_V4 or BASE_V6) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SubMerger 自建节点 DDNS 同步")
    parser.add_argument("--check", action="store_true", help="只检测不写入 (dry-run)")
    parser.add_argument("--force", action="store_true", help="强制写回，即使 IP 未变")
    parser.add_argument("--list", action="store_true", help="列出所有 custom_nodes 后退出")
    args = parser.parse_args()

    if args.list:
        cmd_list()
        return 0

    return sync_once(check_only=args.check, force=args.force)


if __name__ == "__main__":
    sys.exit(main())
