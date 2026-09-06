import React, { useState, useMemo, useEffect, useCallback, useRef } from 'react';
import { Link, useLocation } from 'react-router';
import { Server, Search, Plus, Trash2, X, RefreshCw, Clock, CheckSquare, Square, Settings, Play, Filter, Edit2, ChevronUp, ChevronDown, Globe, Link2, ArrowRight, ToggleLeft, ToggleRight, ShieldCheck, Bot, ChevronDown as ChevronDownIcon } from 'lucide-react';
import request, { isRequestCanceled } from '../utils/request';
import ConfirmModal from '../components/ConfirmModal';
import NodeEditModal from '../components/NodeEditModal';
import NodePoolModal from '../components/NodePoolModal';
import { COUNTRY_CHINESE_NAMES } from './countryData';

const API_BASE = '/api';

const INFO_PREFIX_RE = /^\s*(?:建议|通知|公告|提示|说明|使用前|更新订阅|套餐到期|剩余流量)\s*[:：]?/i;
const INFO_DOMAIN_HINT_RE = /^\s*(?:最强备用|备用网址|备用地址|官网地址?|防丢失官网?|防失联官网?|永久官网|永久地址|最新官网|最新地址|网址发布|域名发布|防丢失|防失联)\s*[:：]?\s*(?:https?:\/\/)?(?:[A-Za-z0-9\u4e00-\u9fff-]+\.)+[A-Za-z]{2,}(?:\/\S*)?\s*$/i;
const INFO_TIMESTAMP_RE = /^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s*\(UTC[+-]\d{1,2}(?::?\d{2})?\)\s*$/i;
const INFO_BALANCE_RE = /^\s*(?:balance|余额)\s*[:：]\s*\d+(?:[.,]\d+)?\s*(?:[KMGTPE]i?B|B)\s*$/i;
const INFO_WEBSITE_RE = /^\s*(?:website|网站|网址)\s*[:：]\s*(?:https?:\/\/)?(?:[A-Za-z0-9\u4e00-\u9fff-]+\.)+[A-Za-z]{2,}(?:\/\S*)?\s*$/i;
const OFFICIAL_URL_RE = /https?:\/\//i;

const HARD_INVALID_KEYWORDS = [
  '剩余流量', '套餐到期', '距离下次重置', '未到期', '使用前',
  '使用说明', '教程', '更新订阅', '公告', '通知', '客服',
  '续费', '购买', '工单', '咨询', '合作', '邀请', '返利',
  '免注册', '免费节点', '变动较大', '全超时', '更换客户端',
  '关注', '版本', '须知', '频道', '维护', '公众号'
];

const SOFT_INVALID_KEYWORDS = [
  '建议', '剩余', '到期', '重置', '流量', '过期', '订阅',
  '网址', '群组', 'Telegram', 'TG', '会员', '商城', '账号'
];

// Complete region names from COUNTRY_CHINESE_NAMES (236 countries/regions)
const REGION_KEYWORDS = [
  ...Object.values(COUNTRY_CHINESE_NAMES),  // All 236 Chinese country names
  // Common abbreviations and English names
  'HK', 'TW', 'MO', 'JP', 'KR', 'SG', 'US', 'UK', 
  'DE', 'FR', 'CA', 'AU', 'RU', 'IN', 'TH', 'VN', 'MY', 'PH', 'ID',
  'CN', 'GB', 'IT', 'ES', 'PT', 'NL', 'BE', 'CH', 'AT', 'CZ', 'PL',
  'SE', 'NO', 'FI', 'DK', 'IE', 'NZ', 'BR', 'AR', 'CL', 'MX', 'TR',
  'SA', 'AE', 'IL', 'EG', 'ZA', 'NG', 'KE', 'UA', 'BY', 'KZ', 'UZ',
  '海外',  // Generic "overseas"
  // Short forms for Chinese regions (COUNTRY_CHINESE_NAMES has "China Hong Kong" but nodes use "Hong Kong")
  '香港', '台湾', '澳门'
];

const STRONG_NODE_HINTS = [
  '节点', '备用', '家宽', '专线', '中转', '落地', '倍率',
  '游戏', '住宅', '原生'
];

const LINE_INDEX_RE = /--\s*\d+\b|\(\s*\d+\s*\)$/;
const LEADING_FLAG_ICON_RE = /^(?:[\u{1F1E6}-\u{1F1FF}]{2}|🔰|🌏|🌍|🌎|🏳️)\s*/u;

const hasRegionHint = (name) => {
  return REGION_KEYWORDS.some(region => {
    if (region.length <= 3 && /^[A-Z]+$/.test(region)) {
      const escaped = region.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(?<![A-Za-z])${escaped}(?:\\d+)?(?![A-Za-z])`).test(name);
    }
    return name.includes(region);
  });
};

const hasNodeIdentity = (name) => {
  if (hasRegionHint(name)) return true;
  if (LINE_INDEX_RE.test(name)) return true;
  return STRONG_NODE_HINTS.some(hint => name.includes(hint));
};

const stripLeadingFlagIcon = (value) => String(value || '').replace(LEADING_FLAG_ICON_RE, '').trim();

export const isInfoNode = (node) => {
  if (!node || !node.name) return true;
  const name = String(node.name).trim();
  if (!name) return true;

  if (INFO_PREFIX_RE.test(name)) return true;
  if (INFO_DOMAIN_HINT_RE.test(name)) return true;
  if (INFO_TIMESTAMP_RE.test(name)) return true;
  if (INFO_BALANCE_RE.test(name)) return true;
  if (INFO_WEBSITE_RE.test(name)) return true;

  if (name.startsWith('官网')) {
    return !hasRegionHint(name);
  }

  if (name.includes('官网') && OFFICIAL_URL_RE.test(name) && !hasNodeIdentity(name)) {
    return true;
  }

  if (HARD_INVALID_KEYWORDS.some(keyword => name.includes(keyword))) {
    return true;
  }

  return SOFT_INVALID_KEYWORDS.some(keyword => name.includes(keyword)) && !hasNodeIdentity(name);
};

const parseNodeTestResponse = (response) => {
  const testPayload = response?.data || {};
  if (testPayload.success === false) {
    const failureMessage = testPayload.error || '节点测试失败';
    const failure = new Error(failureMessage);
    failure.response = { data: { detail: failureMessage } };
    throw failure;
  }
  return testPayload;
};

const NODE_INVALID_REASON_LABELS = {
  'unsupported-reality-option': 'Clash/Mihomo 不支持 Reality spider-x',
  'unsupported-tls-extension': 'Clash/Mihomo 不支持该 TLS 扩展',
  'unsupported-certificate-pin-format': 'Clash/Mihomo 不支持当前证书指纹格式',
  'unsupported-trojan-tcp-disguise': 'Clash/Mihomo 不支持 Trojan TCP HTTP 伪装',
  'unsupported-vless-network': 'Clash/Mihomo 不支持该 VLESS 传输方式',
  'unsupported-vmess-network': 'Clash/Mihomo 不支持该 VMess 传输方式',
  'unsupported-trojan-network': 'Clash/Mihomo 不支持该 Trojan 传输方式',
  'unsupported-anytls-network': 'Clash/Mihomo 不支持该 AnyTLS 传输方式',
  'unsupported-anytls-reality': 'Clash/Mihomo 不支持 AnyTLS Reality',
};

const getNodeInvalidReasonLabel = (reason) => {
  if (!reason) return '节点配置不兼容';
  return NODE_INVALID_REASON_LABELS[reason] || `节点配置不兼容（${reason}）`;
};

// Latency color helper
const getLatencyColor = (latency) => {
  if (latency === null || latency === undefined) return 'text-gray-500';
  if (latency < 100) return 'text-green-400';
  if (latency < 200) return 'text-lime-400';
  if (latency < 500) return 'text-yellow-400';
  if (latency < 1000) return 'text-orange-400';
  return 'text-red-400';
};

// Latency status badge
const getLatencyBadge = (latency, error) => {
  if (error) return { text: '失败', color: 'bg-red-500/20 text-red-400' };
  if (latency === -2) return { text: '失败', color: 'bg-red-500/20 text-red-400' };  // Error
  if (latency === -1) return { text: '超时', color: 'bg-red-500/20 text-red-400' };  // Timeout - red
  if (latency === null) return { text: '超时', color: 'bg-red-500/20 text-red-400' };  // Legacy timeout - red
  if (latency === undefined) return { text: '未测', color: 'bg-gray-500/20 text-gray-400' };
  if (latency < 200) return { text: '优秀', color: 'bg-green-500/20 text-green-400' };
  if (latency < 500) return { text: '良好', color: 'bg-lime-500/20 text-lime-400' };
  if (latency < 1000) return { text: '一般', color: 'bg-yellow-500/20 text-yellow-400' };
  return { text: '较慢', color: 'bg-orange-500/20 text-orange-400' };
};

const getIpSourceLabel = (source) => ({
  broadcast: '广播 IP',
  native: '原生 IP',
}[source] || '-');

const getNetworkTypeLabel = (networkType) => ({
  residential: '住宅 IP',
  datacenter: '机房 IP',
}[networkType] || '-');

export const getNodeIpSource = (node) => (
  node?.ip_profile?.ip_source || node?.ip_source || ''
);

export const getNodeIpProperty = (node) => (
  node?.ip_profile?.network_type || node?.network_type || ''
);

export const isNodeIpSourceUntested = (node) => !getNodeIpSource(node);

export const isNodeIpPropertyUntested = (node) => !getNodeIpProperty(node);

const getNodeCountryFilterValue = (node) => {
  const country = String(node?.country || '').trim();
  const normalizedCountry = country.toUpperCase();
  if (/^[A-Z]{2,3}$/.test(normalizedCountry)) return normalizedCountry;
  return String(node?.region || country).trim();
};

const getNodeCountryFilterLabel = (node) => {
  const country = String(node?.country || '').trim();
  const normalizedCountry = country.toUpperCase();
  return String(
    node?.region
      || COUNTRY_CHINESE_NAMES[normalizedCountry]
      || country
      || '未知地区'
  ).trim();
};

const formatRadarRatio = (value) => {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${numeric.toFixed(2)}%` : '-';
};

const formatIppureScore = (value) => {
  if (value === null || value === undefined || value === '') return '-';
  const normalized = String(value).trim();
  return normalized.endsWith('%') ? normalized : `${normalized}%`;
};

const mergeIpProfiles = (previous, current) => {
  if (!current || typeof current !== 'object') return previous;
  if (!previous || typeof previous !== 'object') return current;
  return { ...previous, ...current };
};

const getMetadataStatusLabel = (status, hasValue = false) => {
  if (hasValue) return '';
  if (status === 'success') return '无数据';
  return ({
    no_data: '无数据',
    failed: '检测失败',
    not_configured: '未配置',
    dependency_failed: '依赖数据缺失',
  }[status] || '未检测');
};

const getMetadataStatusClass = (status, hasValue = false) => {
  if (hasValue) return '';
  if (status === 'failed') return 'text-red-400';
  if (status === 'not_configured') return 'text-amber-400';
  if (status === 'no_data' || status === 'success') return 'text-gray-500';
  return 'text-gray-500';
};

export default function Nodes({ subscriptions, customNodes, onRefreshCustomNodes, showToast }) {
  const location = useLocation();
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');  // 防抖后的搜索值
  // 防抖搜索
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(searchInput);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  useEffect(() => {
    const requestedCountry = String(location.state?.filterCountry || '').trim().toUpperCase();
    if (requestedCountry) {
      setFilterCountry(requestedCountry);
    }
  }, [location.state]);

  const [filterSource, setFilterSource] = useState('all');
  const [filterCountry, setFilterCountry] = useState('');
  const [filterIpSource, setFilterIpSource] = useState('');
  const [filterIpProperty, setFilterIpProperty] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [filterLatencyStatus, setFilterLatencyStatus] = useState('all');
  const [sortBy, setSortBy] = useState('name');
  const [sortOrder, setSortOrder] = useState('asc');  // 'asc' or 'desc'
  const [showAddModal, setShowAddModal] = useState(false);
  const [showTestSettingsModal, setShowTestSettingsModal] = useState(false);
  const [newNodeLink, setNewNodeLink] = useState('');
  const [newNodeName, setNewNodeName] = useState('');
  const [loading, setLoading] = useState(false);
  const [geoipData, setGeoipData] = useState({});
  const [subNodes, setSubNodes] = useState({});
  const [vpngateNodes, setVpngateNodes] = useState([]);
  const [loadingNodes, setLoadingNodes] = useState(true);
  const [deleteConfirm, setDeleteConfirm] = useState({ open: false, nodeId: null });
  const [batchDeleteConfirm, setBatchDeleteConfirm] = useState({ open: false, ids: [], keys: [], count: 0 });
  const [testingByNode, setTestingByNode] = useState({});
  const [nodeTestResults, setNodeTestResults] = useState({});
  const [selectedNodes, setSelectedNodes] = useState(new Set());
  const [batchTesting, setBatchTesting] = useState(false);
  const [batchTestProgress, setBatchTestProgress] = useState({ current: 0, total: 0 });
  const [testTimeout, setTestTimeout] = useState(5000);
  const [testConcurrency, setTestConcurrency] = useState(5);
  const [testLatency, setTestLatency] = useState(false);
  const [testRegion, setTestRegion] = useState(false);
  const [testIppure, setTestIppure] = useState(false);
  const [testRadar, setTestRadar] = useState(false);
  const [testSpeed, setTestSpeed] = useState(false);
  const [showBatchTestMenu, setShowBatchTestMenu] = useState(false);
  const [editingNode, setEditingNode] = useState(null);
  const [customOrderMap, setCustomOrderMap] = useState({});

  // GeoIP API selection for region detection
  const [geoipApis, setGeoipApis] = useState([]);
  const [selectedGeoipApi, setSelectedGeoipApi] = useState('ip-api.com');
  const [radarEnabled, setRadarEnabled] = useState(false);

  // Port mapping state
  const [portMappingNode, setPortMappingNode] = useState(null);  // Node being configured
  const [portMappingValue, setPortMappingValue] = useState('');  // Port input value
  const [showPortMappingList, setShowPortMappingList] = useState(false);  // Show all mappings modal
  const [allPortMappings, setAllPortMappings] = useState([]);  // All port mappings from backend
  const [localPortMappings, setLocalPortMappings] = useState({});  // Local cache: {final_name: port}
  const [portMappingsLoaded, setPortMappingsLoaded] = useState(false);

  // 分页状态
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);  // 每页显示 50 个节点  // Has initial fetch completed?

  // Proxy chain state
  const [proxyChains, setProxyChains] = useState([]);
  const [availableChainNodes, setAvailableChainNodes] = useState([]);
  const [vpngatePool, setVpngatePool] = useState({
    pool_name: 'VPN Gate 动态池',
    active_node_count: 0,
    stale_node_count: 0,
    available: false,
  });
  const [vpngatePools, setVpngatePools] = useState([]);
  const [nodePools, setNodePools] = useState([]);
  const [availableNodePoolNodes, setAvailableNodePoolNodes] = useState([]);
  const [showNodePoolModal, setShowNodePoolModal] = useState(false);
  const [editingNodePool, setEditingNodePool] = useState(null);
  const [savingNodePool, setSavingNodePool] = useState(false);
  const [deleteNodePoolConfirm, setDeleteNodePoolConfirm] = useState({ open: false, poolId: null });
  const [showChainModal, setShowChainModal] = useState(false);
  const [editingChain, setEditingChain] = useState(null);
  const [chainName, setChainName] = useState('');
  const [chainRows, setChainRows] = useState([[null, null]]);
  const [groupDrafts, setGroupDrafts] = useState({});
  const [groupEditing, setGroupEditing] = useState({});
  const [groupSearch, setGroupSearch] = useState({});
  const [deleteChainConfirm, setDeleteChainConfirm] = useState({ open: false, chainId: null });
  const [showAddDropdown, setShowAddDropdown] = useState(false);
  const subNodesRequestSeq = useRef(0);
  const geoipRequestSeq = useRef(0);
  const proxyChainsRequestSeq = useRef(0);
  const chainNodesRequestSeq = useRef(0);
  const nodePoolsRequestSeq = useRef(0);
  const vpngateRequestSeq = useRef(0);


  // Fetch nodes from subscription files
  useEffect(() => {
    const controller = new AbortController();
    fetchAllSubNodes(controller.signal);
    return () => {
      controller.abort();
      subNodesRequestSeq.current += 1;
    };
  }, [subscriptions]);

  // Fetch proxy chains
  useEffect(() => {
    const controller = new AbortController();
    setProxyChains([]);
    setAvailableChainNodes([]);
    fetchProxyChains(controller.signal);
    fetchAvailableChainNodes(controller.signal);
    fetchVpngateNodes(controller.signal);
    fetchNodePools(controller.signal);
    fetchAvailableNodePoolNodes(controller.signal);
    fetchGeoipApis(controller.signal);
    return () => controller.abort();
  }, [subscriptions, customNodes]);

  useEffect(() => {
    const next = {};
    (customNodes || []).forEach((node, idx) => {
      if (node?.id) {
        next[node.id] = String(idx + 1);
      }
    });
    setCustomOrderMap(next);
  }, [customNodes]);

  const fetchGeoipApis = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/geoip/online-config`, { signal });
      if (signal?.aborted) return;
      setGeoipApis(res.data.apis || []);
      setSelectedGeoipApi(res.data.preferred_api || 'ip-api.com');
      setRadarEnabled(res.data.radar_enabled === true);
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch GeoIP APIs', err);
    }
  };

  const fetchProxyChains = async (signal) => {
    const requestId = ++proxyChainsRequestSeq.current;
    try {
      const res = await request.get(`${API_BASE}/proxy-chains`, { signal });
      if (signal?.aborted || requestId !== proxyChainsRequestSeq.current) return;
      setProxyChains(res.data.chains || []);
      return true;
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch proxy chains', err);
      return false;
    }
  };

  const fetchAvailableChainNodes = async (signal) => {
    const requestId = ++chainNodesRequestSeq.current;
    try {
      const res = await request.get(`${API_BASE}/proxy-chains/available-nodes`, { signal });
      if (signal?.aborted || requestId !== chainNodesRequestSeq.current) return;
      const nodes = (res.data.nodes || []).map(node => {
        const nodeName = node?.node_name ?? node?.display_name ?? node?.name ?? '未知节点';
        const nodeType = node?.node_type ?? node?.type ?? '';
        return {
          ...node,
          node_name: nodeName,
          node_type: nodeType
        };
      });
      setAvailableChainNodes(nodes);
      setVpngatePool(res.data.vpngate_pool || {
        pool_name: 'VPN Gate 动态池',
        active_node_count: 0,
        stale_node_count: 0,
        available: false,
      });
      setVpngatePools(Array.isArray(res.data.vpngate_pools) ? res.data.vpngate_pools : []);
      return true;
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch available chain nodes', err);
      return false;
    }
  };

  const fetchVpngateNodes = async (signal) => {
    const requestId = ++vpngateRequestSeq.current;
    try {
      const res = await request.get(`${API_BASE}/vpngate/nodes`, { signal });
      if (signal?.aborted || requestId !== vpngateRequestSeq.current) return;
      setVpngateNodes(Array.isArray(res.data.nodes) ? res.data.nodes : []);
      return true;
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch VPN Gate nodes', err);
      setVpngateNodes([]);
      return false;
    }
  };

  const fetchAllSubNodes = async (signal) => {
    const requestId = ++subNodesRequestSeq.current;
    const subscriptionsSnapshot = [...(subscriptions || [])];

    // Do not render nodes from the previous source set while the new snapshot
    // is loading; otherwise a source filter can temporarily show stale rows.
    setSubNodes({});
    setNodeTestResults({});
    setSelectedNodes(new Set());

    if (!subscriptionsSnapshot.length) {
      if (!signal?.aborted && requestId === subNodesRequestSeq.current) {
        setSubNodes({});
        setLoadingNodes(false);
      }
      return;
    }

    setLoadingNodes(true);
    const nodesMap = {};
    let failed = false;

    for (const sub of subscriptionsSnapshot) {
      if (signal?.aborted || requestId !== subNodesRequestSeq.current) return;
      try {
        const res = await request.get(`${API_BASE}/subscriptions/${sub.id}/nodes`, { signal });
        if (signal?.aborted || requestId !== subNodesRequestSeq.current) return;
        nodesMap[sub.id] = {
          name: sub.name,
          nodes: res.data.nodes || []
        };
      } catch (err) {
        if (signal?.aborted || isRequestCanceled(err) || requestId !== subNodesRequestSeq.current) return;
        console.error(`Failed to fetch nodes for ${sub.name}`, err);
        failed = true;
        nodesMap[sub.id] = { name: sub.name, nodes: [] };
      }
    }

    if (!signal?.aborted && requestId === subNodesRequestSeq.current) {
      setSubNodes(nodesMap);
      setLoadingNodes(false);
    }
    return !failed;
  };

  // Fetch GeoIP data for nodes
  useEffect(() => {
    if (loadingNodes) return;
    const controller = new AbortController();
    const requestId = ++geoipRequestSeq.current;
    fetchGeoipData(controller.signal, requestId);

    return () => {
      controller.abort();
      geoipRequestSeq.current += 1;
    };
  }, [subNodes, customNodes, vpngateNodes, loadingNodes]);

  const fetchGeoipData = async (signal, requestId) => {
    const servers = new Set();
    Object.values(subNodes).forEach(({ nodes }) => {
      nodes.forEach(node => {
        if (node.server) servers.add(node.server);
      });
    });
    customNodes?.forEach(node => {
      if (node.server) servers.add(node.server);
    });
    vpngateNodes?.forEach(node => {
      if (node.server) servers.add(node.server);
    });

    if (servers.size === 0) {
      if (!signal?.aborted && requestId === geoipRequestSeq.current) {
        setGeoipData({});
      }
      return;
    }

    const data = {};
    const serverList = Array.from(servers);

    const batchSize = 100;
    for (let i = 0; i < serverList.length; i += batchSize) {
      if (signal?.aborted || requestId !== geoipRequestSeq.current) return;
      const batch = serverList.slice(i, i + batchSize);
      try {
        const res = await request.post(`${API_BASE}/geoip/batch`, { ips: batch }, { signal });
        if (signal?.aborted || requestId !== geoipRequestSeq.current) return;
        const results = res.data.results || {};
        Object.entries(results).forEach(([server, geoData]) => {
          if (geoData) data[server] = geoData;
        });
      } catch (err) {
        if (signal?.aborted || err.name === 'CanceledError' || err.code === 'ERR_CANCELED') return;
        console.error('Failed to fetch GeoIP batch', err);
      }
    }
    if (!signal?.aborted && requestId === geoipRequestSeq.current) {
      setGeoipData(data);
    }
  };


  // Collect all nodes (filter out info nodes)
  const allNodes = useMemo(() => {
    const nodes = [];

    Object.entries(subNodes).forEach(([subId, { name: subName, nodes: subNodeList }]) => {
      subNodeList.forEach((node, idx) => {
        if (isInfoNode(node)) return;

        const nodeKey = `${subId}|${node.id || `index:${idx}`}`;
        const testResult = nodeTestResults[nodeKey];

        // Priority for region: testResult > backend's node.region > geoipData lookup
        let region = '';
        let flag = '';
        let country = '';
        let city = '';

        if (testResult?.region) {
          region = testResult.region.display || testResult.region.country;
          flag = testResult.region.flag || '';
          country = testResult.region.country || '';
          city = testResult.city || '';
        } else if (node.region) {
          // Use backend's region (from saved geoip or extract_country_from_name)
          region = node.region.country || '';
          flag = node.region.flag || '';
          country = node.region.country_code || '';
          city = node.city || '';  // Read saved city from backend
        } else {
          // Fallback to geoipData lookup
          const geo = geoipData[node.server];
          if (geo) {
            country = geo.country_name || '';
            flag = geo.flag || '';
            region = country;
            city = geo.city || '';
          }
        }

        nodes.push({
          ...node,
          source: subName,
          sourceId: subId,
          sourceType: 'subscription',
          enabled: node.enabled !== false,
          idx,
          nodeKey,
          flag: flag,
          region: region,
          country: country,
          city: city,
          exit_ip: testResult?.exit_ip || node.exit_ip,
          ip_profile: mergeIpProfiles(node.ip_profile, testResult?.ip_profile),
          latency: testResult?.latency !== undefined ? testResult.latency : node.last_latency,
          speed: testResult?.speed !== undefined ? testResult.speed : node.last_speed,
          speedError: testResult?.speed_error,
          testError: testResult?.error,
          detectedRegion: testResult?.region,
          final_name: node.display_name || node.name  // Use display_name from backend (transformed name)
        });
      });
    });

    customNodes?.forEach((node, idx) => {
      if (isInfoNode(node)) return;

      const nodeKey = `custom|${node.id || `index:${idx}`}`;
      const testResult = nodeTestResults[nodeKey];

      // Priority for region: testResult > backend's node.region > geoipData lookup
      let region = '';
      let flag = '';
      let country = '';
      let city = '';

      if (testResult?.region) {
        region = testResult.region.display || testResult.region.country;
        flag = testResult.region.flag || '';
        country = testResult.region.country || '';
        city = testResult.city || '';
      } else if (node.region) {
        // Use backend's region (from saved geoip or extract_country_from_name)
        region = node.region.country || '';
        flag = node.region.flag || '';
        country = node.region.country_code || '';
        city = node.city || '';  // Read saved city from backend
      } else {
        // Fallback to geoipData lookup
        const geo = geoipData[node.server];
        if (geo) {
          country = geo.country_name || '';
          flag = geo.flag || '';
          region = country;
          city = geo.city || '';
        }
      }

      nodes.push({
        ...node,
        source: '自建节点',
        sourceId: 'custom',
        sourceType: 'custom',
        enabled: node.enabled !== false,
        idx,  // Add idx for API calls
        nodeKey,
        flag: flag,
        region: region,
        country: country,
        city: city,
        exit_ip: testResult?.exit_ip || node.exit_ip,
        ip_profile: mergeIpProfiles(node.ip_profile, testResult?.ip_profile),
        latency: testResult?.latency !== undefined ? testResult.latency : node.last_latency,
        speed: testResult?.speed !== undefined ? testResult.speed : node.last_speed,
        speedError: testResult?.speed_error,
        testError: testResult?.error,
        detectedRegion: testResult?.region,
        final_name: node.display_name || node.name  // Use display_name from backend (transformed name)
      });
    });

    // VPN Gate nodes are cached OpenVPN profiles. They are leaf nodes for
    // diagnostics, but are intentionally not exposed as selectable chain
    // members; chain construction uses the country-level dynamic pools.
    vpngateNodes?.forEach((node, idx) => {
      if (!node?.node_id) return;

      const nodeKey = `vpngate|${node.node_id}`;
      const testResult = nodeTestResults[nodeKey];
      const testedRegion = testResult?.region || node.region;
      const region = testedRegion?.display || testedRegion?.country || node.country || '';
      const flag = testedRegion?.flag || node.flag || '';
      const country = testedRegion?.country_code || node.country_code || '';
      const city = testResult?.city || node.city || '';

      nodes.push({
        ...node,
        id: node.node_id,
        name: node.name || node.node_name || 'VPN Gate',
        display_name: node.display_name || node.node_name || node.name || 'VPN Gate',
        final_name: node.display_name || node.node_name || node.name || 'VPN Gate',
        source: 'VPN Gate',
        sourceId: 'vpngate',
        sourceType: 'vpngate',
        enabled: node.enabled !== false,
        idx,
        nodeKey,
        flag,
        region,
        country,
        city,
        exit_ip: testResult?.exit_ip || node.exit_ip,
        ip_profile: mergeIpProfiles(node.ip_profile, testResult?.ip_profile),
        latency: testResult?.latency !== undefined ? testResult.latency : node.last_latency,
        speed: testResult?.speed !== undefined ? testResult.speed : node.last_speed,
        speedError: testResult?.speed_error,
        testError: testResult?.error,
        detectedRegion: testResult?.region,
      });
    });

    // Configured node pools are virtual proxy-group entries.  They are shown
    // in the same table for management and port binding, but are not leaf
    // nodes and therefore do not participate in single-node diagnostics.
    nodePools?.forEach((pool, poolIdx) => {
      if (!pool || !pool.id) return;
      const displayName = pool.display_name || pool.name || `节点池 ${poolIdx + 1}`;
      nodes.push({
        name: displayName,
        display_name: displayName,
        final_name: displayName,
        type: pool.group_strategy || 'select',
        source: '节点池',
        sourceId: 'node_pools',
        sourceType: 'node_pool',
        poolId: pool.id,
        stable_id: pool.stable_id,
        nodeKey: `node_pool|${pool.id}`,
        idx: poolIdx,
        enabled: pool.enabled !== false,
        member_count: pool.member_count ?? (Array.isArray(pool.nodes) ? pool.nodes.length : 0),
        region: `成员 ${pool.member_count ?? (Array.isArray(pool.nodes) ? pool.nodes.length : 0)} 个`,
        country: '',
        city: '',
        server: '',
        flag: '',
      });
    });

    // Add proxy chain nodes
    proxyChains?.forEach((chain, chainIdx) => {
      const nodeKey = `chain-${chain.id}`;
      const testResult = nodeTestResults[nodeKey];

      // Get region from the last node in the first row (the exit node)
      let region = '';
      let flag = '';
      let country = '';
      let city = '';

      if (testResult?.region) {
        region = testResult.region.display || testResult.region.country;
        flag = testResult.region.flag || '';
        country = testResult.region.country || '';
        city = testResult.city || '';
      }

      // Build chain path for display
      const firstRow = chain.rows?.[0];
      const chainPath = firstRow?.nodes?.map((n, idx) => {
        if (n?.type === 'group') {
          const isLast = idx === (firstRow?.nodes?.length || 0) - 1;
          return `组:${n.group_name || (isLast ? '落地池' : '中转池')}`;
        }
        return n.node_name;
      }).join(' → ') || '';

      // Compute pool group name for port mapping (only when last hop is group)
      let poolGroupName = null;
      if (firstRow?.nodes?.length) {
        const lastNode = firstRow.nodes[firstRow.nodes.length - 1];
        if (lastNode?.type === 'group') {
          const base = lastNode.group_name || `${chain.name} 落地池`;
          poolGroupName = `🔀 ${base}`;
        }
      }

      nodes.push({
        name: `🔗 ${chain.name}`,
        display_name: `🔗 ${chain.name}`,
        final_name: poolGroupName || `🔗 ${chain.name}`,
        pool_group_name: poolGroupName,
        type: 'chain',
        server: chainPath,  // Show chain path as server
        source: '链式代理',
        sourceId: 'chain',
        sourceType: 'chain',
        idx: chainIdx,
        chainId: chain.id,
        nodeKey,
        flag: flag,
        region: region,
        country: country,
        city: city,
        exit_ip: testResult?.exit_ip,
        ip_profile: mergeIpProfiles(chain.ip_profile, testResult?.ip_profile),
        latency: testResult?.latency !== undefined ? testResult.latency : chain.last_latency,
        speed: testResult?.speed !== undefined ? testResult.speed : chain.last_speed,
        speedError: testResult?.speed_error,
        testError: testResult?.error,
        detectedRegion: testResult?.region,
        enabled: chain.enabled,
        rows: chain.rows,
      });
    });

    return nodes;
  }, [subNodes, customNodes, vpngateNodes, nodePools, proxyChains, geoipData, nodeTestResults]);

  // Get unique types and sources
  const nodeTypes = useMemo(() => {
    const types = new Set(allNodes.map(n => n.type).filter(Boolean));
    return ['all', ...Array.from(types)];
  }, [allNodes]);

  const sourceOptions = useMemo(() => {
    // Filter by immutable source IDs rather than display names. Names can be
    // edited or duplicated, which otherwise allows stale rows to pass through.
    const options = [{ id: 'all', name: '全部来源' }];
    (subscriptions || []).forEach(sub => {
      if (sub?.id) options.push({ id: sub.id, name: sub.name || sub.id });
    });
    if (customNodes && customNodes.length > 0) {
      options.push({ id: 'custom', name: '自建节点' });
    }
    if (vpngateNodes && vpngateNodes.length > 0) {
      options.push({ id: 'vpngate', name: 'VPN Gate' });
    }
    if (proxyChains && proxyChains.length > 0) {
      options.push({ id: 'chain', name: '链式代理' });
    }
    if (nodePools && nodePools.length > 0) {
      options.push({ id: 'node_pools', name: '节点池' });
    }
    return options;
  }, [subscriptions, customNodes, vpngateNodes, proxyChains, nodePools]);

  const countryOptions = useMemo(() => {
    const options = new Map();
    allNodes.forEach(node => {
      const value = getNodeCountryFilterValue(node);
      if (!value) return;
      options.set(value, getNodeCountryFilterLabel(node));
    });
    return [
      { id: '', name: '地区' },
      ...Array.from(options.entries())
        .sort(([, labelA], [, labelB]) => labelA.localeCompare(labelB, 'zh-CN'))
        .map(([id, name]) => ({ id, name })),
    ];
  }, [allNodes]);

  const ipSourceOptions = useMemo(() => {
    const values = new Set(allNodes.map(getNodeIpSource).filter(Boolean));
    return [
      { id: '', name: 'IP来源' },
      { id: 'untested', name: '未检测' },
      ...['native', 'broadcast']
        .map(value => ({ id: value, name: getIpSourceLabel(value) })),
      ...Array.from(values)
        .filter(value => !['native', 'broadcast'].includes(value))
        .map(value => ({ id: value, name: String(value) })),
    ];
  }, [allNodes]);

  const ipPropertyOptions = useMemo(() => {
    const values = new Set(allNodes.map(getNodeIpProperty).filter(Boolean));
    return [
      { id: '', name: 'IP属性' },
      { id: 'untested', name: '未检测' },
      ...['residential', 'datacenter']
        .map(value => ({ id: value, name: getNetworkTypeLabel(value) })),
      ...Array.from(values)
        .filter(value => !['residential', 'datacenter'].includes(value))
        .map(value => ({ id: value, name: String(value) })),
    ];
  }, [allNodes]);

  const compareNodes = useCallback((a, b) => {
    // Custom nodes first
    if (a.sourceType === 'custom' && b.sourceType !== 'custom') return -1;
    if (a.sourceType !== 'custom' && b.sourceType === 'custom') return 1;

    // Chain and pool entries are virtual nodes and stay before subscription
    // nodes, while preserving their configured order within each source.
    if (a.sourceType === 'chain' && !['chain', 'custom'].includes(b.sourceType)) return -1;
    if (b.sourceType === 'chain' && !['chain', 'custom'].includes(a.sourceType)) return 1;
    if (a.sourceType === 'node_pool' && b.sourceType === 'subscription') return -1;
    if (a.sourceType === 'subscription' && b.sourceType === 'node_pool') return 1;

    // If both are custom, keep original order (by idx)
    if (a.sourceType === 'custom' && b.sourceType === 'custom') {
      return a.idx - b.idx;
    }

    // If both are chain, keep original order (by idx)
    if (a.sourceType === 'chain' && b.sourceType === 'chain') {
      return a.idx - b.idx;
    }

    if (a.sourceType === 'node_pool' && b.sourceType === 'node_pool') {
      return a.idx - b.idx;
    }

    // For non-custom nodes, apply secondary sort with direction
    const dir = sortOrder === 'asc' ? 1 : -1;

    if (sortBy === 'name') return dir * (a.name || '').localeCompare(b.name || '');
    if (sortBy === 'type') return dir * (a.type || '').localeCompare(b.type || '');
    if (sortBy === 'source') return dir * (a.source || '').localeCompare(b.source || '');
    if (sortBy === 'region') return dir * (a.region || '').localeCompare(b.region || '');
    if (sortBy === 'latency') {
      // Untested nodes go to the end
      if (a.latency === undefined && b.latency === undefined) return (a.name || '').localeCompare(b.name || '');
      if (a.latency === undefined) return 1;
      if (b.latency === undefined) return -1;
      if (a.latency === null || a.latency < 0) return 1;
      if (b.latency === null || b.latency < 0) return -1;
      return dir * (a.latency - b.latency);
    }
    if (sortBy === 'speed') {
      // Untested nodes go to the end
      if (a.speed === undefined && b.speed === undefined) return (a.name || '').localeCompare(b.name || '');
      if (a.speed === undefined) return 1;
      if (b.speed === undefined) return -1;
      return dir * (a.speed - b.speed);
    }
    return 0;
  }, [sortBy, sortOrder]);

  const orderedChainNodes = useMemo(() => {
    const nodes = [...availableChainNodes];
    if (!nodes.length) return nodes;

    // Order by subscription list order, then by node_index
    const subOrder = new Map();
    (subscriptions || []).forEach((sub, idx) => {
      subOrder.set(sub.id, idx);
    });

    nodes.sort((a, b) => {
      const sa = a.sub_id === 'custom' ? -1 : (subOrder.get(a.sub_id) ?? Number.POSITIVE_INFINITY);
      const sb = b.sub_id === 'custom' ? -1 : (subOrder.get(b.sub_id) ?? Number.POSITIVE_INFINITY);
      if (sa !== sb) return sa - sb;
      const ia = Number.isFinite(a.node_index) ? a.node_index : Number.POSITIVE_INFINITY;
      const ib = Number.isFinite(b.node_index) ? b.node_index : Number.POSITIVE_INFINITY;
      if (ia === ib) return 0;
      return ia - ib;
    });

    return nodes;
  }, [availableChainNodes, subscriptions]);

  // Filter and sort
  const filteredNodes = useMemo(() => {
    // Sorting must not mutate the memoized source list; mutating it can leave
    // rows from a previous source selection visible after the filter changes.
    let result = [...allNodes];

    if (search) {
      const s = search.toLowerCase();
      result = result.filter(n =>
        n.name?.toLowerCase().includes(s) ||
        n.server?.toLowerCase().includes(s) ||
        n.type?.toLowerCase().includes(s) ||
        n.region?.toLowerCase().includes(s)
      );
    }

    if (filterSource !== 'all') {
      result = result.filter(n => n.sourceId === filterSource);
    }

    if (filterCountry) {
      const countryName = COUNTRY_CHINESE_NAMES[filterCountry] || '';
      result = result.filter(n => {
        const countryFilterValue = getNodeCountryFilterValue(n);
        const country = String(n.country || '').toUpperCase();
        const region = String(n.region || '');
        const countryDisplay = String(n.country || '');
        return countryFilterValue === filterCountry
          || country === filterCountry
          || countryDisplay === countryName
          || region === countryName
          || region.toUpperCase() === filterCountry;
      });
    }

    if (filterIpSource) {
      result = result.filter(n => filterIpSource === 'untested'
        ? isNodeIpSourceUntested(n)
        : getNodeIpSource(n) === filterIpSource);
    }

    if (filterIpProperty) {
      result = result.filter(n => filterIpProperty === 'untested'
        ? isNodeIpPropertyUntested(n)
        : getNodeIpProperty(n) === filterIpProperty);
    }

    if (filterType !== 'all') {
      result = result.filter(n => n.type === filterType);
    }

    // Latency status filter
    if (filterLatencyStatus !== 'all') {
      result = result.filter(n => {
        const badge = getLatencyBadge(n.latency, n.testError);
        if (filterLatencyStatus === 'untested') return n.latency === undefined && !n.testError;
        if (filterLatencyStatus === 'success') return n.latency !== undefined && n.latency > 0 && !n.testError;
        if (filterLatencyStatus === 'timeout') return n.latency === -1 || n.latency === null;
        if (filterLatencyStatus === 'failed') return n.testError || n.latency === -2;
        return true;
      });
    }

    // Primary sort: custom nodes first, then chain nodes, then subscription nodes
    result.sort(compareNodes);

    return result;
  }, [allNodes, search, filterSource, filterCountry, filterIpSource, filterIpProperty, filterType, filterLatencyStatus, sortBy, sortOrder]);

  // 分页节点
  const paginatedNodes = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    return filteredNodes.slice(startIndex, endIndex);
  }, [filteredNodes, currentPage, pageSize]);

  const selectedCustomNodes = useMemo(() => {
    return allNodes.filter(n => n.sourceType === 'custom' && selectedNodes.has(n.nodeKey));
  }, [allNodes, selectedNodes]);
  const selectedCustomCount = selectedCustomNodes.length;

  // 总页数
  const totalPages = Math.ceil(filteredNodes.length / pageSize);

  // 当过滤条件改变时，重置到第一页
  useEffect(() => {
    setCurrentPage(1);
    setSelectedNodes(new Set());
  }, [search, filterSource, filterCountry, filterIpSource, filterIpProperty, filterType, filterLatencyStatus, sortBy, sortOrder]);

  useEffect(() => {
    const lastPage = Math.max(1, totalPages);
    setCurrentPage(page => Math.min(Math.max(1, page), lastPage));
  }, [totalPages]);

  useEffect(() => {
    if (!sourceOptions.some(option => option.id === filterSource)) {
      setFilterSource('all');
    }
  }, [filterSource, sourceOptions]);


  const getTypeColor = (type) => {
    const colors = {
      vless: 'bg-blue-500/20 text-blue-400',
      vmess: 'bg-purple-500/20 text-purple-400',
      trojan: 'bg-green-500/20 text-green-400',
      ss: 'bg-yellow-500/20 text-yellow-400',
      ssr: 'bg-orange-500/20 text-orange-400',
      hysteria2: 'bg-pink-500/20 text-pink-400',
      hysteria: 'bg-pink-500/20 text-pink-400',
      tuic: 'bg-cyan-500/20 text-cyan-400',
    };
    return colors[type?.toLowerCase()] || 'bg-gray-500/20 text-gray-400';
  };

  const fetchNodePools = async (signal) => {
    const requestId = ++nodePoolsRequestSeq.current;
    try {
      const res = await request.get(`${API_BASE}/node-pools`, { signal });
      if (signal?.aborted || requestId !== nodePoolsRequestSeq.current) return;
      setNodePools(res.data.pools || []);
      return true;
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch node pools', err);
      return false;
    }
  };

  const fetchAvailableNodePoolNodes = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/node-pools/available-nodes`, { signal });
      if (signal?.aborted) return;
      setAvailableNodePoolNodes(res.data.nodes || []);
      return true;
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch node pool nodes', err);
      return false;
    }
  };

  const openNodePoolModal = (pool = null) => {
    setEditingNodePool(pool);
    setShowNodePoolModal(true);
  };

  const closeNodePoolModal = () => {
    if (savingNodePool) return;
    setShowNodePoolModal(false);
    setEditingNodePool(null);
  };

  const saveNodePool = async (payload) => {
    setSavingNodePool(true);
    try {
      if (editingNodePool?.id) {
        const response = await request.put(`${API_BASE}/node-pools/${editingNodePool.id}`, payload);
        setNodePools((current) => current.map((pool) => (
          pool.id === editingNodePool.id ? { ...pool, ...(response.data?.pool || payload) } : pool
        )));
        showToast?.('节点池已更新', 'success');
      } else {
        const response = await request.post(`${API_BASE}/node-pools`, payload);
        if (response.data?.pool) setNodePools((current) => [...current, response.data.pool]);
        showToast?.('节点池已创建', 'success');
      }
      setShowNodePoolModal(false);
      setEditingNodePool(null);
      await fetchNodePools();
      await fetchAvailableNodePoolNodes();
      await fetchAllPortMappings();
    } catch (err) {
      showToast?.(err.response?.data?.detail || '节点池保存失败', 'error');
    } finally {
      setSavingNodePool(false);
    }
  };

  const toggleNodePool = async (poolId) => {
    try {
      const response = await request.put(`${API_BASE}/node-pools/${poolId}/toggle`);
      setNodePools((current) => current.map((pool) => (
        pool.id === poolId ? { ...pool, enabled: response.data?.enabled !== false } : pool
      )));
      await fetchAllPortMappings();
      showToast?.(response.data?.enabled ? '节点池已启用' : '节点池已禁用', 'success');
    } catch (err) {
      showToast?.(err.response?.data?.detail || '节点池开关失败', 'error');
    }
  };

  const deleteNodePool = async (poolId) => {
    try {
      await request.delete(`${API_BASE}/node-pools/${poolId}`);
      setNodePools((current) => current.filter((pool) => pool.id !== poolId));
      setSelectedNodes((current) => {
        const next = new Set(current);
        next.delete(`node_pool|${poolId}`);
        return next;
      });
      await fetchAllPortMappings();
      showToast?.('节点池已删除', 'success');
    } catch (err) {
      showToast?.(err.response?.data?.detail || '节点池删除失败', 'error');
    } finally {
      setDeleteNodePoolConfirm({ open: false, poolId: null });
    }
  };

  const moveNodePool = async (poolId, direction) => {
    const currentIndex = nodePools.findIndex((pool) => pool.id === poolId);
    if (currentIndex < 0) return;
    const targetIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
    if (targetIndex < 0 || targetIndex >= nodePools.length) return;
    const order = nodePools.map((pool) => pool.id);
    [order[currentIndex], order[targetIndex]] = [order[targetIndex], order[currentIndex]];
    try {
      await request.put(`${API_BASE}/node-pools/reorder`, { order });
      await fetchNodePools();
      showToast?.('节点池顺序已调整', 'success');
    } catch (err) {
      showToast?.(err.response?.data?.detail || '节点池排序失败', 'error');
    }
  };

  const getProtocolDisplayLabel = (type) => {
    const normalizedType = String(type || '').toLowerCase();
    const poolStrategyLabels = {
      select: '手动',
      'url-test': '测速',
      fallback: '故障转移',
      'load-balance': '负载均衡',
    };
    if (poolStrategyLabels[normalizedType]) return poolStrategyLabels[normalizedType];
    return normalizedType === 'hysteria2' ? 'HY2' : normalizedType.toUpperCase() || '-';
  };

  // Test single node
  const mergeNodeTestResults = (updates) => {
    setNodeTestResults(prev => {
      const next = { ...prev };
      Object.entries(updates || {}).forEach(([nodeKey, result]) => {
        next[nodeKey] = { ...prev[nodeKey], ...result };
      });
      return next;
    });
  };

  const setNodeTesting = (nodeKey, type) => {
    setTestingByNode(prev => ({ ...prev, [nodeKey]: type }));
  };

  const clearNodeTesting = (nodeKey) => {
    setTestingByNode(prev => {
      const next = { ...prev };
      delete next[nodeKey];
      return next;
    });
  };

  const testNode = async (node, isRegionTest = false) => {
    if (node.sourceType === 'chain') {
      showToast?.('链式代理需要通过最终订阅测试，暂不支持单节点测速', 'warning');
      return;
    }
    if (node.valid === false) {
      showToast?.(getNodeInvalidReasonLabel(node.invalid_reason), 'warning');
      return;
    }
    setNodeTesting(node.nodeKey, isRegionTest ? 'region' : 'latency');
    try {
      const payload = {
        test_latency: !isRegionTest,
        test_speed: false,
        test_region: isRegionTest,
        test_ip_profile: false,
        test_radar: false,
        timeout: testTimeout
      };
      if (isRegionTest) {
        payload.geoip_api = selectedGeoipApi;
      }
      const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, payload);
      const testPayload = parseNodeTestResponse(res);
      setNodeTestResults(prev => {
        const newResult = { ...prev[node.nodeKey] };
        if (isRegionTest) {
          newResult.region = testPayload.region;
          newResult.city = testPayload.city;
          newResult.exit_ip = testPayload.exit_ip;
          const mergedIpProfile = mergeIpProfiles(node.ip_profile, testPayload.ip_profile);
          if (mergedIpProfile) {
            newResult.ip_profile = mergedIpProfile;
          }
          newResult.regionError = false;
        } else {
          newResult.latency = testPayload.latency;
          newResult.error = false;
        }
        return { ...prev, [node.nodeKey]: newResult };
      });
    } catch (err) {
      setNodeTestResults(prev => {
        const failedResult = { ...prev[node.nodeKey] };
        const failureMessage = err.response?.data?.detail || err.message || '未知错误';
        if (isRegionTest) {
          failedResult.regionError = true;
          failedResult.regionErrorMessage = failureMessage;
        } else {
          failedResult.latency = null;
          failedResult.error = true;
          failedResult.errorMessage = failureMessage;
        }
        return { ...prev, [node.nodeKey]: failedResult };
      });
      showToast?.(`节点测试失败: ${err.response?.data?.detail || err.message || '未知错误'}`, 'error');
    } finally {
      clearNodeTesting(node.nodeKey);
    }
  };

  // Test single node speed
  const testNodeSpeed = async (node) => {
    if (node.sourceType === 'chain') {
      showToast?.('链式代理需要通过最终订阅测试，暂不支持单节点测速', 'warning');
      return;
    }
    if (node.valid === false) {
      showToast?.(getNodeInvalidReasonLabel(node.invalid_reason), 'warning');
      return;
    }
    setNodeTesting(node.nodeKey, 'speed');
    try {
      const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
        test_latency: false,
        test_speed: true,
        test_region: false,
        timeout: testTimeout
      });
      const testPayload = parseNodeTestResponse(res);
      setNodeTestResults(prev => ({
        ...prev,
        [node.nodeKey]: {
          ...prev[node.nodeKey],
          speed: testPayload.speed,
          peak_speed: testPayload.peak_speed,
          speed_error: false,
          speedErrorMessage: undefined
        }
      }));
    } catch (err) {
      setNodeTestResults(prev => ({
        ...prev,
        [node.nodeKey]: {
          ...prev[node.nodeKey],
          speed: null,
          peak_speed: null,
          speed_error: true,
          speedErrorMessage: err.response?.data?.detail || err.message || '未知错误'
        }
      }));
      showToast?.(`速度测试失败: ${err.response?.data?.detail || err.message || '未知错误'}`, 'error');
    } finally {
      clearNodeTesting(node.nodeKey);
    }
  };

  // Batch test nodes - latency first with concurrency, then region
  const batchTestNodes = async () => {
    // Only test selected nodes, no longer fall back to all nodes
    if (selectedNodes.size === 0) {
      showToast?.('请先在左侧选择要检测的节点', 'warning');
      return;
    }

    const selectedNodesToTest = filteredNodes.filter(n => selectedNodes.has(n.nodeKey));
    const skippedChainCount = selectedNodesToTest.filter(n => n.sourceType === 'chain').length;
    const skippedIncompatibleCount = selectedNodesToTest.filter(
      n => n.sourceType !== 'chain' && n.valid === false,
    ).length;
    const nodesToTest = selectedNodesToTest.filter(
      n => n.sourceType !== 'chain' && n.valid !== false,
    );

    if (skippedChainCount > 0 || skippedIncompatibleCount > 0) {
      const skipped = [];
      if (skippedChainCount > 0) skipped.push(`${skippedChainCount} 个链式代理`);
      if (skippedIncompatibleCount > 0) skipped.push(`${skippedIncompatibleCount} 个不兼容节点`);
      showToast?.(`已跳过${skipped.join('、')}`, 'info');
    }

    if (nodesToTest.length === 0) {
      showToast?.('没有可测试的节点', 'error');
      return;
    }

    if (!testLatency && !testRegion && !testIppure && !testRadar && !testSpeed) {
      showToast?.('请至少选择一项检测内容', 'error');
      return;
    }

    setShowBatchTestMenu(false);
    setBatchTesting(true);

    const totalSteps = (testLatency ? nodesToTest.length : 0)
      + (testRegion ? nodesToTest.length : 0)
      + (testIppure ? nodesToTest.length : 0)
      + (testRadar ? nodesToTest.length : 0)
      + (testSpeed ? nodesToTest.length : 0);
    let currentStep = 0;
    const firstPhase = testLatency
      ? '延迟'
      : testRegion
        ? 'IP/地区'
        : testIppure
          ? 'IP属性'
          : testRadar
            ? '人机流量比'
            : '速度';
    setBatchTestProgress({ current: 0, total: totalSteps, phase: firstPhase });

    // Batch update results to reduce re-renders
    const batchResults = {};
    const saveData = {};  // 用于批量保存的数据结构
    let failedCount = 0;
    const mergeBatchIpProfile = (node, profile) => {
      const savedProfile = saveData[node.sourceId]?.[node.id]?.ip_profile;
      return mergeIpProfiles(savedProfile || node.ip_profile, profile);
    };

    // Phase 1: Test latency with concurrency
    if (testLatency) {
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: true,
              test_speed: false,
              test_region: false,
              timeout: testTimeout,
              batch_mode: true  // 批量模式，不立即保存
            });
            const testPayload = parseNodeTestResponse(res);
            
            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].latency = testPayload.latency;
            
            return { nodeKey: node.nodeKey, data: { latency: testPayload.latency, error: false } };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            saveData[node.sourceId][node.id] = {
              ...(saveData[node.sourceId][node.id] || {}),
              latency: null,
              error: message,
            };
            return { nodeKey: node.nodeKey, data: { latency: null, error: true, errorMessage: message } };
          }
        }));
        
        // Batch update
        results.forEach(result => {
          if (result.status === 'fulfilled') {
            batchResults[result.value.nodeKey] = { ...batchResults[result.value.nodeKey], ...result.value.data };
          }
        });
        
        currentStep = Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '延迟' });
        
        // Update state every batch instead of every node
        mergeNodeTestResults(batchResults);
      }
    }

    // Phase 2: Test region with concurrency
    if (testRegion) {
      const baseStep = testLatency ? nodesToTest.length : 0;
      setBatchTestProgress(prev => ({ ...prev, phase: 'IP/地区' }));
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: false,
              test_speed: false,
              test_region: true,
              timeout: testTimeout,
              geoip_api: selectedGeoipApi,
              batch_mode: true  // 批量模式
            });
            const testPayload = parseNodeTestResponse(res);
            
            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].exit_ip = testPayload.exit_ip;
            const mergedIpProfile = mergeBatchIpProfile(node, testPayload.ip_profile);
            if (mergedIpProfile) {
              saveData[node.sourceId][node.id].ip_profile = mergedIpProfile;
            }
            saveData[node.sourceId][node.id].region = testPayload.region;
            saveData[node.sourceId][node.id].city = testPayload.city;

            const regionData = {
              region: testPayload.region,
              city: testPayload.city,
              exit_ip: testPayload.exit_ip,
              regionError: false,
            };
            if (mergedIpProfile) {
              regionData.ip_profile = mergedIpProfile;
            }
            return { nodeKey: node.nodeKey, data: regionData };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            saveData[node.sourceId][node.id] = {
              ...(saveData[node.sourceId][node.id] || {}),
              exit_ip: null,
              region: null,
              city: null,
              error: message,
            };
            return { nodeKey: node.nodeKey, data: { regionError: true, regionErrorMessage: message } };
          }
        }));
        
        // Batch update
        results.forEach(result => {
          if (result.status === 'fulfilled' && result.value) {
            batchResults[result.value.nodeKey] = { ...batchResults[result.value.nodeKey], ...result.value.data };
          }
        });
        
        currentStep = baseStep + Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: 'IP/地区' });
        
        // Update state every batch
        mergeNodeTestResults(batchResults);
      }
    }

    // Phase 3: Test IPPure attributes with the same concurrency as region.
    if (testIppure) {
      const baseStep = (testLatency ? nodesToTest.length : 0)
        + (testRegion ? nodesToTest.length : 0);
      setBatchTestProgress(prev => ({ ...prev, phase: 'IP属性' }));
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: false,
              test_speed: false,
              test_region: false,
              test_ip_profile: true,
              test_radar: false,
              timeout: testTimeout,
              batch_mode: true,
            });
            const testPayload = parseNodeTestResponse(res);
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].exit_ip = testPayload.exit_ip;
            const mergedIpProfile = mergeBatchIpProfile(node, testPayload.ip_profile);
            if (mergedIpProfile) {
              saveData[node.sourceId][node.id].ip_profile = mergedIpProfile;
            }
            return {
              nodeKey: node.nodeKey,
              data: {
                exit_ip: testPayload.exit_ip,
                ip_profile: mergedIpProfile,
                ippureError: false,
              },
            };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            return {
              nodeKey: node.nodeKey,
              data: { ippureError: true, ippureErrorMessage: message },
            };
          }
        }));

        results.forEach(result => {
          if (result.status === 'fulfilled') {
            batchResults[result.value.nodeKey] = {
              ...batchResults[result.value.nodeKey],
              ...result.value.data,
            };
          }
        });
        currentStep = (testLatency ? nodesToTest.length : 0)
          + (testRegion ? nodesToTest.length : 0)
          + Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: 'IP属性' });
        mergeNodeTestResults(batchResults);
      }
    }

    // Phase 4: Test Cloudflare Radar human/bot ratio.
    if (testRadar) {
      const baseStep = (testLatency ? nodesToTest.length : 0)
        + (testRegion ? nodesToTest.length : 0)
        + (testIppure ? nodesToTest.length : 0);
      setBatchTestProgress(prev => ({ ...prev, phase: '人机流量比' }));
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: false,
              test_speed: false,
              test_region: false,
              test_ip_profile: false,
              test_radar: true,
              timeout: testTimeout,
              geoip_api: selectedGeoipApi,
              batch_mode: true,
            });
            const testPayload = parseNodeTestResponse(res);
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].exit_ip = testPayload.exit_ip;
            const mergedIpProfile = mergeBatchIpProfile(node, testPayload.ip_profile);
            if (mergedIpProfile) {
              saveData[node.sourceId][node.id].ip_profile = mergedIpProfile;
            }
            return {
              nodeKey: node.nodeKey,
              data: {
                exit_ip: testPayload.exit_ip,
                ip_profile: mergedIpProfile,
                radarError: false,
              },
            };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            return {
              nodeKey: node.nodeKey,
              data: { radarError: true, radarErrorMessage: message },
            };
          }
        }));

        results.forEach(result => {
          if (result.status === 'fulfilled') {
            batchResults[result.value.nodeKey] = {
              ...batchResults[result.value.nodeKey],
              ...result.value.data,
            };
          }
        });
        currentStep = baseStep + Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '人机流量比' });
        mergeNodeTestResults(batchResults);
      }
    }

    // Phase 5: Test speed with concurrency (lower concurrency for speed test)
    if (testSpeed) {
      const baseStep = (testLatency ? nodesToTest.length : 0)
        + (testRegion ? nodesToTest.length : 0)
        + (testIppure ? nodesToTest.length : 0)
        + (testRadar ? nodesToTest.length : 0);
      setBatchTestProgress(prev => ({ ...prev, phase: '速度' }));
      // Use lower concurrency for speed test (max 2) to avoid bandwidth saturation
      const speedConcurrency = Math.min(testConcurrency, 2);
      for (let i = 0; i < nodesToTest.length; i += speedConcurrency) {
        const batch = nodesToTest.slice(i, i + speedConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`, {
              test_latency: false,
              test_speed: true,
              test_region: false,
              timeout: testTimeout,
              batch_mode: true  // 批量模式
            });
            const testPayload = parseNodeTestResponse(res);
            
            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.id]) saveData[node.sourceId][node.id] = {};
            saveData[node.sourceId][node.id].speed = testPayload.speed;
            saveData[node.sourceId][node.id].peak_speed = testPayload.peak_speed;
            
            return { nodeKey: node.nodeKey, data: { speed: testPayload.speed, peak_speed: testPayload.peak_speed, speed_error: false } };
          } catch (err) {
            failedCount += 1;
            const message = err.response?.data?.detail || err.message || '未知错误';
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            saveData[node.sourceId][node.id] = {
              ...(saveData[node.sourceId][node.id] || {}),
              speed: null,
              error: message,
            };
            return { nodeKey: node.nodeKey, data: { speed: null, peak_speed: null, speed_error: true, speedErrorMessage: message } };
          }
        }));
        
        // Batch update
        results.forEach(result => {
          if (result.status === 'fulfilled' && result.value) {
            batchResults[result.value.nodeKey] = { ...batchResults[result.value.nodeKey], ...result.value.data };
          }
        });
        
        currentStep = baseStep + Math.min(i + speedConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '速度' });
        
        // Update state every batch
        mergeNodeTestResults(batchResults);
      }
    }

    // 批量保存所有测试结果
    try {
      const expectedSaveCount = Object.values(saveData).reduce((total, sourceNodes) => (
        total + Object.values(sourceNodes).filter(result => (
          Object.entries(result).some(([key, value]) => key !== 'error' && value !== null && value !== undefined)
        )).length
      ), 0);
      const saveResponse = await request.post(`${API_BASE}/nodes/batch-save`, { results: saveData });
      const savedCount = Number(saveResponse?.data?.saved_count || 0);
      const unmatchedCount = Array.isArray(saveResponse?.data?.unmatched_node_ids)
        ? saveResponse.data.unmatched_node_ids.length
        : 0;
      if (savedCount < expectedSaveCount || unmatchedCount > 0) {
        showToast?.(`测试完成，但仅保存 ${savedCount}/${expectedSaveCount} 个结果，请刷新后重试`, 'error');
      } else if (failedCount > 0) {
        showToast?.(`测试完成，${failedCount} 个节点失败，其余结果已保存`, 'warning');
      } else {
        showToast?.(`测试完成，共测试 ${nodesToTest.length} 个节点，结果已保存`);
      }
    } catch (error) {
      showToast?.(`测试完成，但保存失败: ${error.message}`, 'error');
    }

    setBatchTesting(false);
  };


  // Selection handlers
  const toggleSelectAll = () => {
    const selectableNodes = filteredNodes.filter(n => n.sourceType !== 'node_pool');
    const visibleKeys = new Set(selectableNodes.map(n => n.nodeKey));
    const allVisibleSelected = selectableNodes.length > 0 && selectableNodes.every(n => selectedNodes.has(n.nodeKey));
    setSelectedNodes(prev => {
      const next = new Set(prev);
      if (allVisibleSelected) {
        visibleKeys.forEach(key => next.delete(key));
      } else {
        visibleKeys.forEach(key => next.add(key));
      }
      return next;
    });
  };

  const toggleSelectNode = (nodeKey) => {
    const node = allNodes.find(item => item.nodeKey === nodeKey);
    if (node?.sourceType === 'node_pool') return;
    const newSelected = new Set(selectedNodes);
    if (newSelected.has(nodeKey)) {
      newSelected.delete(nodeKey);
    } else {
      newSelected.add(nodeKey);
    }
    setSelectedNodes(newSelected);
  };

  // Add custom node
  const addCustomNode = async () => {
    const links = newNodeLink
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean);
    if (links.length === 0) return;
    let nameList = [];
    if (newNodeName.trim()) {
      nameList = newNodeName.split(';').map(item => item.trim());
      while (nameList.length > 0 && nameList[nameList.length - 1] === '') {
        nameList.pop();
      }
    }
    setLoading(true);
    try {
      if (links.length === 1) {
        const payload = { link: links[0] };
        if (nameList.length > 0) {
          payload.name = nameList[0];
        } else if (newNodeName.trim()) {
          payload.name = newNodeName.trim();
        }
        await request.post(`${API_BASE}/custom-nodes`, payload);
        showToast?.('节点添加成功');
      } else {
        if (nameList.length > links.length) {
          nameList = nameList.slice(0, links.length);
        }
        const payload = { links };
        if (nameList.length > 0) {
          payload.names = nameList;
        }
        const res = await request.post(`${API_BASE}/custom-nodes/batch`, payload);
        const added = res.data?.added ?? links.length;
        const failed = res.data?.failed ?? 0;
        if (failed > 0) {
          showToast?.(`批量添加完成：成功 ${added}，失败 ${failed}`, 'warning');
        } else {
          showToast?.(`批量添加完成：成功 ${added}`, 'success');
        }
      }
      setNewNodeLink('');
      setNewNodeName('');
      setShowAddModal(false);
      onRefreshCustomNodes?.();
    } catch (err) {
      showToast?.('添加失败: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  // Delete custom node
  const deleteCustomNode = async (nodeId) => {
    try {
      await request.delete(`${API_BASE}/custom-nodes/${nodeId}`);
      onRefreshCustomNodes?.();
      showToast?.('节点已删除');
    } catch (err) {
      showToast?.('删除失败', 'error');
    }
  };

  const confirmDeleteNode = (nodeId) => {
    setDeleteConfirm({ open: true, nodeId });
  };

  const openBatchDeleteCustomNodes = () => {
    const ids = selectedCustomNodes.map(n => n.id).filter(Boolean);
    const keys = selectedCustomNodes.map(n => n.nodeKey);
    if (ids.length === 0) {
      showToast?.('请选择要删除的自建节点', 'warning');
      return;
    }
    setBatchDeleteConfirm({ open: true, ids, keys, count: ids.length });
  };

  const confirmBatchDeleteCustomNodes = async () => {
    const { ids, keys } = batchDeleteConfirm;
    if (!ids || ids.length === 0) return;
    try {
      const res = await request.post(`${API_BASE}/custom-nodes/batch-delete`, { ids });
      const deleted = res.data?.deleted ?? ids.length;
      setSelectedNodes(prev => {
        const next = new Set(prev);
        (keys || []).forEach(k => next.delete(k));
        return next;
      });
      onRefreshCustomNodes?.();
      showToast?.(`已删除 ${deleted} 个自建节点`, 'success');
    } catch (err) {
      showToast?.('批量删除失败', 'error');
    }
  };

  const testNodeMetadata = async (node, metadataType) => {
    if (node.sourceType === 'chain') {
      showToast?.('链式代理需要通过最终订阅测试，暂不支持单节点信息检测', 'warning');
      return;
    }
    if (node.valid === false) {
      showToast?.(getNodeInvalidReasonLabel(node.invalid_reason), 'warning');
      return;
    }

    const requestFields = {
      test_latency: false,
      test_speed: false,
      test_region: metadataType === 'region',
      test_ip_profile: metadataType === 'ippure',
      test_radar: metadataType === 'radar',
      timeout: testTimeout,
    };
    if (metadataType !== 'ippure') {
      requestFields.geoip_api = selectedGeoipApi;
    }

    setNodeTesting(node.nodeKey, metadataType);
    try {
      const res = await request.post(
        `${API_BASE}/nodes/${node.sourceId}/${encodeURIComponent(node.id)}/test`,
        requestFields,
      );
      const testPayload = parseNodeTestResponse(res);
      setNodeTestResults(prev => {
        const next = { ...prev[node.nodeKey] };
        const mergedIpProfile = mergeIpProfiles(
          next.ip_profile || node.ip_profile,
          testPayload.ip_profile,
        );
        if (mergedIpProfile) next.ip_profile = mergedIpProfile;
        if (testPayload.exit_ip) next.exit_ip = testPayload.exit_ip;
        if (metadataType === 'region') {
          next.region = testPayload.region;
          next.city = testPayload.city;
          next.regionError = false;
        } else if (metadataType === 'ippure') {
          next.ippureError = false;
        } else {
          next.radarError = false;
        }
        return { ...prev, [node.nodeKey]: next };
      });
    } catch (err) {
      const failureMessage = err.response?.data?.detail || err.message || '未知错误';
      setNodeTestResults(prev => ({
        ...prev,
        [node.nodeKey]: {
          ...prev[node.nodeKey],
          ...(metadataType === 'region'
            ? { regionError: true, regionErrorMessage: failureMessage }
            : metadataType === 'ippure'
              ? { ippureError: true, ippureErrorMessage: failureMessage }
              : { radarError: true, radarErrorMessage: failureMessage }),
        },
      }));
      showToast?.(`节点信息检测失败: ${failureMessage}`, 'error');
    } finally {
      clearNodeTesting(node.nodeKey);
    }
  };

  const testNodeIppure = (node) => testNodeMetadata(node, 'ippure');
  const testNodeRadar = (node) => testNodeMetadata(node, 'radar');

  const updateCustomOrderValue = (nodeId, value) => {
    setCustomOrderMap(prev => ({
      ...prev,
      [nodeId]: value
    }));
  };

  const applyCustomOrder = async () => {
    const list = customNodes || [];
    if (list.length < 2) return;

    const items = list.map((node, idx) => {
      const raw = customOrderMap[node.id];
      const parsed = parseInt(raw, 10);
      const order = Number.isFinite(parsed) && parsed > 0 ? parsed : idx + 1;
      return { id: node.id, order, idx };
    }).filter(item => item.id);

    if (items.length < 2) return;

    items.sort((a, b) => {
      if (a.order !== b.order) return a.order - b.order;
      return a.idx - b.idx;
    });

    const desiredOrder = items.map(item => item.id);
    const currentOrder = list.map(node => node.id).filter(Boolean);

    if (currentOrder.length === desiredOrder.length && currentOrder.every((id, i) => id === desiredOrder[i])) {
      return;
    }

    try {
      await request.put(`${API_BASE}/custom-nodes/reorder`, { order: desiredOrder });
      onRefreshCustomNodes?.();
      showToast?.('自建节点排序已更新', 'success');
    } catch (err) {
      showToast?.('排序失败', 'error');
    }
  };

  // Refresh all nodes
  const refreshAllNodes = async () => {
    setLoadingNodes(true);
    setNodeTestResults({});
    setSelectedNodes(new Set());
    try {
      const subRefreshOk = await fetchAllSubNodes();
      const chainsRefreshOk = await fetchProxyChains();
      const chainNodesRefreshOk = await fetchAvailableChainNodes();
      const vpngateRefreshOk = await fetchVpngateNodes();
      const poolsRefreshOk = await fetchNodePools();
      const poolNodesRefreshOk = await fetchAvailableNodePoolNodes();
      const customRefreshOk = await onRefreshCustomNodes?.();
      if (
        !subRefreshOk
        || chainsRefreshOk === false
        || chainNodesRefreshOk === false
        || vpngateRefreshOk === false
        || poolsRefreshOk === false
        || poolNodesRefreshOk === false
        || customRefreshOk === false
      ) {
        throw new Error('部分节点来源刷新失败');
      }
      showToast?.('节点列表已刷新');
    } catch (err) {
      showToast?.(err.message || '节点刷新失败', 'error');
    } finally {
      setLoadingNodes(false);
    }
  };

  // Clear filters
  const clearFilters = () => {
    setSearchInput('');
    setSearch('');
    setFilterSource('all');
    setFilterCountry('');
    setFilterIpSource('');
    setFilterIpProperty('');
    setFilterType('all');
    setFilterLatencyStatus('all');
    setSortBy('name');
    setSortOrder('asc');
  };

  // Move custom node up or down
  const moveCustomNode = async (nodeId, direction) => {
    const customNodesList = customNodes || [];
    const currentIndex = customNodesList.findIndex(n => n.id === nodeId);
    if (currentIndex === -1) return;

    const newIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
    if (newIndex < 0 || newIndex >= customNodesList.length) return;

    // Create new order
    const newOrder = customNodesList.map(n => n.id);
    [newOrder[currentIndex], newOrder[newIndex]] = [newOrder[newIndex], newOrder[currentIndex]];

    try {
      await request.put(`${API_BASE}/custom-nodes/reorder`, { order: newOrder });
      onRefreshCustomNodes?.();
      showToast?.('顺序已调整');
    } catch (err) {
      showToast?.('调整失败', 'error');
    }
  };

  // Proxy chain functions
  const openChainModal = (chain = null) => {
    if (chain) {
      setChainName(chain.name);
      const resolveStoredNode = (subId, nodeId, nodeName, nodeIndex) => {
        if (nodeId) {
          const byId = availableChainNodes.find(n => n.sub_id === subId && n.node_id === nodeId);
          if (byId) return byId;
        }
        if (nodeName) {
          const byName = availableChainNodes.find(n =>
            n.sub_id === subId && (n.node_name ?? n.display_name ?? n.name) === nodeName
          );
          if (byName) return byName;
        }
        return availableChainNodes.find(n => n.sub_id === subId && n.node_index === nodeIndex);
      };
      const resolveGroupId = (groupId, rowIndex, colIndex) => groupId || `${chain.id || 'chain'}_${rowIndex}_${colIndex}`;
      const rows = chain.rows.map((row, rowIndex) =>
        row.nodes.map((node, colIndex) => {
          if (node?.type !== 'group' && node?.sub_id === 'vpngate') {
            return {
              type: 'group',
              group_id: resolveGroupId(null, rowIndex, colIndex),
              group_name: 'VPN Gate 动态池',
              group_source: 'vpngate',
              vpngate_country_code: null,
              group_strategy: 'url-test',
              lb_strategy: 'round-robin',
              group_nodes: [],
            };
          }
          if (node?.type === 'group') {
            const isLast = colIndex === row.nodes.length - 1;
            const defaultLabel = isLast ? '落地池' : '中转池';
            return {
              type: 'group',
              group_id: resolveGroupId(node.group_id, rowIndex, colIndex),
              group_name: node.group_name || defaultLabel,
              group_source: node.group_source || 'nodes',
              vpngate_country_code: node.vpngate_country_code || null,
              group_strategy: node.group_strategy || 'load-balance',
              lb_strategy: node.lb_strategy || 'round-robin',
              group_nodes: (node.group_source === 'vpngate' ? [] : (node.group_nodes || [])).map(n => {
                const resolved = resolveStoredNode(n.sub_id, n.node_id, n.node_name, n.node_index);
                return {
                  type: 'node',
                  sub_id: n.sub_id,
                  node_id: n.node_id || resolved?.node_id,
                  node_name: n.node_name || resolved?.node_name || resolved?.display_name || resolved?.name
                };
              })
            };
          }
          const resolved = resolveStoredNode(node.sub_id, node.node_id, node.node_name, node.node_index);
          return {
            type: 'node',
            sub_id: node.sub_id,
            node_id: node.node_id || resolved?.node_id,
            node_name: node.node_name || resolved?.node_name || resolved?.display_name || resolved?.name
          };
        })
      );
      setChainRows(rows);
      setEditingChain(chain);
    } else {
      setChainName('');
      setChainRows([[null, null]]);
      setEditingChain(null);
    }
    setGroupEditing({});
    setGroupDrafts({});
    setGroupSearch({});
    setShowChainModal(true);
  };

  const closeChainModal = () => {
    setShowChainModal(false);
    setEditingChain(null);
    setChainName('');
    setChainRows([[null, null]]);
    setGroupSearch({});
  };

  const addChainColumn = (rowIndex) => {
    setChainRows(prev => {
      const newRows = [...prev];
      newRows[rowIndex] = [...newRows[rowIndex], null];
      return newRows;
    });
  };

  const removeChainColumn = (rowIndex, colIndex) => {
    setChainRows(prev => {
      const newRows = [...prev];
      if (newRows[rowIndex].length > 2) {
        newRows[rowIndex] = newRows[rowIndex].filter((_, i) => i !== colIndex);
      }
      return newRows;
    });
  };

  const addChainRow = () => {
    setChainRows(prev => [...prev, [null, null]]);
  };

  const removeChainRow = (rowIndex) => {
    if (chainRows.length > 1) {
      setChainRows(prev => prev.filter((_, i) => i !== rowIndex));
    }
  };

  const generateGroupId = () => `grp_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;

  const makeChainNodeKey = (subId, nodeId, nodeName, nodeIndex) => {
    if (!subId) return '';
    if (nodeId) return `${subId}|id:${encodeURIComponent(nodeId)}`;
    if (nodeName) return `${subId}|${encodeURIComponent(nodeName)}`;
    if (nodeIndex !== undefined && nodeIndex !== null && !Number.isNaN(nodeIndex)) {
      return `${subId}|#${nodeIndex}`;
    }
    return '';
  };

  const parseChainNodeKey = (key) => {
    if (!key) return { subId: '', nodeId: '', nodeName: '', nodeIndex: null };
    const sep = key.indexOf('|');
    if (sep === -1) return { subId: '', nodeId: '', nodeName: '', nodeIndex: null };
    const subId = key.slice(0, sep);
    const rest = key.slice(sep + 1);
    if (rest.startsWith('id:')) {
      return { subId, nodeId: decodeURIComponent(rest.slice(3)), nodeName: '', nodeIndex: null };
    }
    if (rest.startsWith('#')) {
      const idx = parseInt(rest.slice(1), 10);
      return { subId, nodeId: '', nodeName: '', nodeIndex: Number.isNaN(idx) ? null : idx };
    }
    return { subId, nodeId: '', nodeName: decodeURIComponent(rest), nodeIndex: null };
  };

  const resolveChainNode = (nodes, subId, nodeId, nodeName, nodeIndex) => {
    if (!nodes?.length || !subId) return null;
    if (nodeId) {
      const match = nodes.find(n => n.sub_id === subId && n.node_id === nodeId);
      if (match) return match;
    }
    if (nodeName) {
      const match = nodes.find(n =>
        n.sub_id === subId && (n.node_name ?? n.display_name ?? n.name) === nodeName
      );
      if (match) return match;
    }
    if (nodeIndex !== null && nodeIndex !== undefined && !Number.isNaN(nodeIndex)) {
      return nodes.find(n => n.sub_id === subId && n.node_index === nodeIndex) || null;
    }
    return null;
  };

  const resolveChainNodeFromKey = (nodes, key) => {
    const { subId, nodeId, nodeName, nodeIndex } = parseChainNodeKey(key);
    return resolveChainNode(nodes, subId, nodeId, nodeName, nodeIndex);
  };

  const updateChainNode = (rowIndex, colIndex, nodeKey) => {
    if (!nodeKey) {
      setChainRows(prev => {
        const newRows = [...prev];
        newRows[rowIndex][colIndex] = null;
        return newRows;
      });
      return;
    }

    const node = resolveChainNodeFromKey(availableChainNodes, nodeKey);
    const nodeName = node?.node_name ?? node?.display_name ?? node?.name ?? '未知节点';

    setChainRows(prev => {
      const newRows = [...prev];
      newRows[rowIndex][colIndex] = node ? {
        type: 'node',
        sub_id: node.sub_id,
        node_id: node.node_id,
        node_name: nodeName
      } : null;
      return newRows;
    });
  };

  const updateChainCellType = (rowIndex, colIndex, cellType) => {
    setChainRows(prev => {
      const newRows = [...prev];
      if (cellType === 'group' || cellType === 'vpngate') {
        const isLast = colIndex === newRows[rowIndex].length - 1;
        const defaultName = cellType === 'vpngate'
          ? 'VPN Gate 动态池'
          : (chainName.trim()
            ? `${chainName.trim()} ${isLast ? '落地池' : '中转池'}`
            : (isLast ? '落地池' : '中转池'));
        newRows[rowIndex][colIndex] = {
          type: 'group',
          group_id: generateGroupId(),
          group_name: defaultName,
          group_source: cellType === 'vpngate' ? 'vpngate' : 'nodes',
          vpngate_country_code: null,
          group_strategy: cellType === 'vpngate' ? 'url-test' : 'load-balance',
          lb_strategy: 'round-robin',
          group_nodes: []
        };
      } else {
        newRows[rowIndex][colIndex] = null;
      }
      return newRows;
    });

    const key = getGroupCellKey(rowIndex, colIndex);
    if (cellType === 'group') {
      setGroupDrafts(prev => ({ ...prev, [key]: [] }));
      setGroupEditing(prev => ({ ...prev, [key]: true }));
    } else {
      setGroupEditing(prev => ({ ...prev, [key]: false }));
    }
  };

  const updateChainGroup = (rowIndex, colIndex, patch) => {
    setChainRows(prev => {
      const newRows = [...prev];
      const current = newRows[rowIndex][colIndex];
      if (!current || current.type !== 'group') return newRows;
      newRows[rowIndex][colIndex] = { ...current, ...patch };
      return newRows;
    });
  };

  const updateVpngateCountry = (rowIndex, colIndex, countryCode) => {
    const selectedPool = vpngatePools.find(pool => pool.country_code === countryCode);
    updateChainGroup(rowIndex, colIndex, {
      vpngate_country_code: countryCode || null,
      group_name: selectedPool?.pool_name || 'VPN Gate 动态池',
    });
  };

  const updateChainGroupMembers = (rowIndex, colIndex, selectedKeys) => {
    const nodes = selectedKeys.map(key => {
      const node = resolveChainNodeFromKey(orderedChainNodes, key);
      const nodeName = node?.node_name ?? node?.display_name ?? node?.name ?? '未知节点';
      return node ? {
        type: 'node',
        sub_id: node.sub_id,
        node_id: node.node_id,
        node_name: nodeName
      } : null;
    }).filter(Boolean);
    updateChainGroup(rowIndex, colIndex, { group_nodes: nodes });
  };

  const getGroupCellKey = (rowIndex, colIndex) => `${rowIndex}-${colIndex}`;

  const beginGroupEdit = (rowIndex, colIndex) => {
    const key = getGroupCellKey(rowIndex, colIndex);
    const current = chainRows[rowIndex]?.[colIndex];
    const keys = (current?.group_nodes || []).map(n => makeChainNodeKey(n.sub_id, n.node_id, n.node_name, n.node_index));
    setGroupDrafts(prev => ({ ...prev, [key]: keys }));
    setGroupEditing(prev => ({ ...prev, [key]: true }));
  };

  const toggleGroupDraft = (rowIndex, colIndex, nodeKey) => {
    const key = getGroupCellKey(rowIndex, colIndex);
    setGroupDrafts(prev => {
      const cur = prev[key] || [];
      const next = cur.includes(nodeKey) ? cur.filter(k => k !== nodeKey) : [...cur, nodeKey];
      return { ...prev, [key]: next };
    });
  };

  const setGroupDraftKeys = (rowIndex, colIndex, keys) => {
    const key = getGroupCellKey(rowIndex, colIndex);
    setGroupDrafts(prev => ({ ...prev, [key]: keys }));
  };

  const confirmGroupDraft = (rowIndex, colIndex) => {
    const key = getGroupCellKey(rowIndex, colIndex);
    const keys = groupDrafts[key] || [];
    updateChainGroupMembers(rowIndex, colIndex, keys);
    setGroupEditing(prev => ({ ...prev, [key]: false }));
  };

  const toggleChainGroupMember = (rowIndex, colIndex, nodeKey) => {
    setChainRows(prev => {
      const newRows = [...prev];
      const current = newRows[rowIndex]?.[colIndex];
      if (!current || current.type !== 'group') return newRows;
      const selectedKeys = (current.group_nodes || []).map(n => makeChainNodeKey(n.sub_id, n.node_id, n.node_name, n.node_index));
      const nextKeys = selectedKeys.includes(nodeKey)
        ? selectedKeys.filter(k => k !== nodeKey)
        : [...selectedKeys, nodeKey];
      const nodes = nextKeys.map(key => {
        const node = resolveChainNodeFromKey(orderedChainNodes, key);
        const nodeName = node?.node_name ?? node?.display_name ?? node?.name ?? '未知节点';
        return node ? {
          type: 'node',
          sub_id: node.sub_id,
          node_id: node.node_id,
          node_name: nodeName
        } : null;
      }).filter(Boolean);
      newRows[rowIndex][colIndex] = { ...current, group_nodes: nodes };
      return newRows;
    });
  };

  const getChainNodeLabel = (node) => {
    const name = node?.node_name ?? node?.display_name ?? node?.name ?? '未知节点';
    const type = node?.node_type ?? node?.type ?? '';
    return type ? `${name} (${type})` : name;
  };

  const getChainNodeKey = (node) => {
    if (!node || node.type === 'group') return '';
    return makeChainNodeKey(node.sub_id, node.node_id, node.node_name, node.node_index);
  };

  const saveChain = async () => {
    if (!chainName.trim()) {
      showToast?.('请输入链式代理名称', 'error');
      return;
    }

    for (const row of chainRows) {
      if (row.some(node => !node)) {
        showToast?.('请选择所有节点', 'error');
        return;
      }
      for (let i = 0; i < row.length; i++) {
        const node = row[i];
        if (node?.type === 'group') {
          if (!node.group_name || !node.group_name.trim()) {
            showToast?.('请填写组名称', 'error');
            return;
          }
          if (node.group_source === 'vpngate') {
            const selectedPool = node.vpngate_country_code
              ? vpngatePools.find(pool => pool.country_code === node.vpngate_country_code)
              : vpngatePool;
            if (!selectedPool?.available) {
              showToast?.(
                node.vpngate_country_code
                  ? 'VPN Gate 所选国家当前没有可用节点，请先在系统设置中更新节点源'
                  : 'VPN Gate 动态池当前没有可用节点，请先在系统设置中更新节点源',
                'error'
              );
              return;
            }
          } else {
            if (!node.group_nodes || node.group_nodes.length === 0) {
              showToast?.('组内至少选择一个节点', 'error');
              return;
            }
            if (node.group_nodes.some(member => !member?.sub_id || !member?.node_id)) {
              showToast?.('组内存在已失效节点，请重新选择', 'error');
              return;
            }
          }
        } else if (!node?.sub_id || !node?.node_id) {
          showToast?.('链路中存在已失效节点，请重新选择', 'error');
          return;
        }
      }
    }

    const payload = {
      name: chainName.trim(),
      rows: chainRows.map(row => ({
        nodes: row.map(node => {
          if (node.type === 'group') {
            return {
              type: 'group',
              group_id: node.group_id,
              group_name: node.group_name,
              group_strategy: node.group_strategy,
              lb_strategy: node.lb_strategy,
              group_source: node.group_source || 'nodes',
              ...(node.group_source === 'vpngate' ? {
                ...(node.vpngate_country_code ? { vpngate_country_code: node.vpngate_country_code } : {})
              } : {
                group_nodes: (node.group_nodes || []).map(n => ({
                  sub_id: n.sub_id,
                  node_id: n.node_id,
                  node_name: n.node_name
                }))
              })
            };
          }
          return {
            type: 'node',
            sub_id: node.sub_id,
            node_id: node.node_id,
            node_name: node.node_name
          };
        })
      }))
    };

    try {
      if (editingChain) {
        await request.put(`${API_BASE}/proxy-chains/${editingChain.id}`, payload);
        showToast?.('链式代理已更新');
      } else {
        await request.post(`${API_BASE}/proxy-chains`, payload);
        showToast?.('链式代理已创建');
      }
      closeChainModal();
      fetchProxyChains();
    } catch (err) {
      showToast?.(err.response?.data?.detail || '保存失败', 'error');
    }
  };

  const toggleChain = async (chainId) => {
    try {
      const res = await request.put(`${API_BASE}/proxy-chains/${chainId}/toggle`);
      setProxyChains(prev => prev.map(c =>
        c.id === chainId ? { ...c, enabled: res.data.enabled } : c
      ));
      showToast?.(res.data.enabled ? '已启用' : '已禁用');
    } catch (err) {
      showToast?.('操作失败', 'error');
    }
  };

  const toggleNodeEnabled = async (node) => {
    if (!node || node.sourceType === 'chain') return;

    try {
      const endpoint = node.sourceType === 'custom'
        ? `${API_BASE}/custom-nodes/${node.id}/toggle`
        : `${API_BASE}/subscriptions/${node.sourceId}/nodes/${encodeURIComponent(node.id)}/toggle`;
      const res = await request.put(endpoint);
      const enabled = res.data?.enabled !== false;

      if (node.sourceType === 'subscription') {
        setSubNodes(prev => {
          const source = prev[node.sourceId];
          if (!source) return prev;
          return {
            ...prev,
            [node.sourceId]: {
              ...source,
              nodes: (source.nodes || []).map((item) => (
                item.id === node.id ? { ...item, enabled } : item
              ))
            }
          };
        });
      } else {
        onRefreshCustomNodes?.();
      }

      fetchAvailableChainNodes();
      showToast?.(enabled ? '节点已启用，将出现在聚合配置中' : '节点已禁用，不会出现在聚合配置中', 'success');
    } catch (err) {
      showToast?.(err.response?.data?.detail || '节点开关失败', 'error');
    }
  };

  const deleteChain = async (chainId) => {
    try {
      await request.delete(`${API_BASE}/proxy-chains/${chainId}`);
      setProxyChains(prev => prev.filter(c => c.id !== chainId));
      showToast?.('链式代理已删除');
    } catch (err) {
      showToast?.('删除失败', 'error');
    }
    setDeleteChainConfirm({ open: false, chainId: null });
  };

  const moveChain = async (chainId, direction) => {
    const chainsList = proxyChains || [];
    const currentIndex = chainsList.findIndex(c => c.id === chainId);
    if (currentIndex === -1) return;

    const newIndex = direction === 'up' ? currentIndex - 1 : currentIndex + 1;
    if (newIndex < 0 || newIndex >= chainsList.length) return;

    const newOrder = chainsList.map(c => c.id);
    [newOrder[currentIndex], newOrder[newIndex]] = [newOrder[newIndex], newOrder[currentIndex]];

    try {
      await request.put(`${API_BASE}/proxy-chains/reorder`, { order: newOrder });
      fetchProxyChains();
      showToast?.('顺序已调整');
    } catch (err) {
      showToast?.('调整失败', 'error');
    }
  };


  // Port mapping functions
  const openPortMapping = (node) => {
    // Get the final name with fallback (use pool group name for chain if available)
    const finalName = node.pool_group_name || node.final_name || node.display_name || node.name;
    
    // After initial load, use localPortMappings as single source of truth
    // This ensures deletions from management panel are immediately reflected
    const currentPort = portMappingsLoaded
      ? localPortMappings[finalName]
      : (localPortMappings[finalName] ?? node.mapped_port);
    setPortMappingNode({ ...node, mapped_port: currentPort });
    setPortMappingValue(currentPort ? String(currentPort) : '');
  };

  const fetchAllPortMappings = async (signal) => {
    try {
      const res = await request.get(`${API_BASE}/port-mappings`, { signal });
      if (signal?.aborted) return;
      setAllPortMappings(res.data.mappings || []);
      // Build local cache
      const cache = {};
      (res.data.mappings || []).forEach(m => {
        cache[m.final_name] = m.port;
      });
      setLocalPortMappings(cache);
      setPortMappingsLoaded(true);  // Mark as loaded
    } catch (err) {
      if (signal?.aborted || isRequestCanceled(err)) return;
      console.error('Failed to fetch port mappings', err);
      // Keep the last known mappings and allow a later retry to distinguish a
      // failed load from a genuinely empty mapping set.
      setPortMappingsLoaded(false);
    }
  };

  // Fetch port mappings on mount
  useEffect(() => {
    const controller = new AbortController();
    fetchAllPortMappings(controller.signal);
    return () => controller.abort();
  }, []);

  const savePortMapping = async () => {
    if (!portMappingNode) return;

    const port = parseInt(portMappingValue);
    if (isNaN(port) || port < 1024 || port > 65535) {
      showToast?.('端口号必须在 1024-65535 之间', 'error');
      return;
    }

    // Get the final name with fallback
    const finalName = portMappingNode.final_name || portMappingNode.display_name || portMappingNode.name;
    if (!finalName) {
      showToast?.('节点名称无效', 'error');
      return;
    }

    try {
      await request.post(`${API_BASE}/port-mappings`, {
        final_name: finalName,
        port: port
      });
      showToast?.(`已将端口 ${port} 绑定到节点`);

      // Update local cache (no page refresh needed)
      setLocalPortMappings(prev => ({
        ...prev,
        [finalName]: port
      }));

      setPortMappingNode(null);
      setPortMappingValue('');
    } catch (err) {
      const msg = err.response?.data?.detail || '绑定失败';
      showToast?.(msg, 'error');
    }
  };

  const removePortMapping = async () => {
    if (!portMappingNode?.mapped_port) return;

    // Get the final name with fallback
    const finalName = portMappingNode.final_name || portMappingNode.display_name || portMappingNode.name;

    try {
      await request.delete(`${API_BASE}/port-mappings/${portMappingNode.mapped_port}`);
      showToast?.('已解除端口绑定');

      // Update local cache (no page refresh needed)
      if (finalName) {
        setLocalPortMappings(prev => {
          const newCache = { ...prev };
          delete newCache[finalName];
          return newCache;
        });
      }

      setPortMappingNode(null);
      setPortMappingValue('');
    } catch (err) {
      showToast?.('解绑失败', 'error');
    }
  };

  const deletePortMappingFromList = async (port, finalName) => {
    try {
      await request.delete(`${API_BASE}/port-mappings/${port}`);
      showToast?.('已删除端口映射');

      // Update both states
      setAllPortMappings(prev => prev.filter(m => m.port !== port));
      setLocalPortMappings(prev => {
        const newCache = { ...prev };
        delete newCache[finalName];
        return newCache;
      });
    } catch (err) {
      showToast?.('删除失败', 'error');
    }
  };

  // Stats
  const testedCount = allNodes.filter(n => n.latency !== undefined).length;
  const successCount = allNodes.filter(n => n.latency !== undefined && n.latency !== null && !n.testError).length;
  const failedCount = allNodes.filter(n => n.testError || n.latency === null).length;

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (showBatchTestMenu && !e.target.closest('.batch-test-menu')) {
        setShowBatchTestMenu(false);
      }
      if (showAddDropdown && !e.target.closest('.add-dropdown')) {
        setShowAddDropdown(false);
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [showBatchTestMenu, showAddDropdown]);


  return (
    <div className="h-[calc(100vh-80px)] flex flex-col space-y-2 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2 flex-shrink-0">
        <div>
          <h1 className="text-xl font-bold text-white">节点管理</h1>
          <p className="text-gray-400 text-sm mt-0.5">查看和管理所有节点</p>
          <div className={`text-xs mt-1 ${radarEnabled ? 'text-green-400' : 'text-amber-400'}`}>
            {radarEnabled ? (
              'Cloudflare Radar 已配置'
            ) : (
              <>
                Cloudflare Radar 未配置；请前往
                <Link to="/settings#cloudflare-radar-settings" className="underline hover:text-amber-300 mx-1">
                  系统设置 → Cloudflare Radar API
                </Link>
                填写 Token
              </>
            )}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => { fetchAllPortMappings(); setShowPortMappingList(true); }}
            className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
          >
            <Link2 size={18} />
            端口映射
            {Object.keys(localPortMappings).length > 0 && (
              <span className="px-1.5 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">
                {Object.keys(localPortMappings).length}
              </span>
            )}
          </button>
          <div className="relative add-dropdown">
            <button
              onClick={() => setShowAddDropdown(!showAddDropdown)}
              className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
            >
              <Plus size={18} />
              添加节点
              <ChevronDownIcon size={16} />
            </button>
            {showAddDropdown && (
              <div className="absolute right-0 top-full mt-2 w-40 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-20">
                <button
                  onClick={() => { setShowAddDropdown(false); setShowAddModal(true); }}
                  className="w-full px-4 py-2.5 text-left text-white hover:bg-gray-700 rounded-t-lg transition-colors flex items-center gap-2"
                >
                  <Server size={16} />
                  自建节点
                </button>
                <button
                  onClick={() => { setShowAddDropdown(false); openChainModal(); }}
                  className="w-full px-4 py-2.5 text-left text-white hover:bg-gray-700 transition-colors flex items-center gap-2"
                >
                  <Link2 size={16} />
                  链式代理
                </button>
                <button
                  onClick={() => { setShowAddDropdown(false); openNodePoolModal(); }}
                  className="w-full px-4 py-2.5 text-left text-white hover:bg-gray-700 rounded-b-lg transition-colors flex items-center gap-2"
                >
                  <Settings size={16} />
                  节点池
                </button>
              </div>
            )}
          </div>
          <button
            onClick={() => setShowTestSettingsModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
          >
            <Settings size={18} />
            检测设置
          </button>
          <div className="relative batch-test-menu">
            <button
              onClick={() => setShowBatchTestMenu(!showBatchTestMenu)}
              disabled={batchTesting}
              className="flex items-center gap-2 px-3 py-1.5 bg-green-600 hover:bg-green-500 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              <Play size={18} className={batchTesting ? 'animate-pulse' : ''} />
              {batchTesting ? `${batchTestProgress.phase}检测中 ${batchTestProgress.current}/${batchTestProgress.total}` : (selectedNodes.size > 0 ? `批量检测 (${selectedNodes.size})` : '批量检测')}
            </button>
            {showBatchTestMenu && !batchTesting && (
              <div className="absolute right-0 top-full mt-2 w-72 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-20">
                <div className="p-3 space-y-3">
                  <div className="text-sm text-gray-400 font-medium">检测内容</div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testLatency}
                      onChange={(e) => setTestLatency(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-white text-sm">延迟检测</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testRegion}
                      onChange={(e) => setTestRegion(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-white text-sm">IP/地区检测</span>
                    <span className="text-xs text-gray-500">（出口 IP、地区）</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testIppure}
                      onChange={(e) => setTestIppure(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-white text-sm">IP 属性检测</span>
                    <span className="text-xs text-gray-500">（来源、属性、IPPure）</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testRadar}
                      onChange={(e) => setTestRadar(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-white text-sm">人机流量比检测</span>
                    <span className="text-xs text-gray-500">（Cloudflare Radar）</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testSpeed}
                      onChange={(e) => setTestSpeed(e.target.checked)}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-white text-sm">速度检测</span>
                    <span className="text-xs text-gray-500">(较慢)</span>
                  </label>
                  <div className="pt-2 border-t border-gray-700">
                    <button
                      onClick={batchTestNodes}
                      disabled={!testLatency && !testRegion && !testIppure && !testRadar && !testSpeed}
                      className="w-full px-3 py-2 bg-green-600 hover:bg-green-500 text-white text-sm rounded-lg transition-colors disabled:opacity-50"
                    >
                      开始检测
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
          <button
            onClick={openBatchDeleteCustomNodes}
            disabled={selectedCustomCount === 0}
            className="flex items-center gap-2 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <Trash2 size={18} />
            {selectedCustomCount > 0 ? `批量删除 (${selectedCustomCount})` : '批量删除'}
          </button>
          <button
            onClick={refreshAllNodes}
            disabled={loadingNodes}
            className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={18} className={loadingNodes ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 items-center flex-shrink-0">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="搜索节点名称/服务器/地区..."
            className="w-full pl-9 pr-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <select
          value={filterSource}
          onChange={(e) => setFilterSource(e.target.value)}
          className="px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          {sourceOptions.map(source => (
            <option key={source.id} value={source.id}>{source.name}</option>
          ))}
        </select>

        <select
          value={filterIpSource}
          onChange={(e) => setFilterIpSource(e.target.value)}
          className="px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          {ipSourceOptions.map(option => (
            <option key={option.id || 'all-ip-source'} value={option.id}>{option.name}</option>
          ))}
        </select>

        <select
          value={filterIpProperty}
          onChange={(e) => setFilterIpProperty(e.target.value)}
          className="px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          {ipPropertyOptions.map(option => (
            <option key={option.id || 'all-ip-property'} value={option.id}>{option.name}</option>
          ))}
        </select>

        <select
          value={filterCountry}
          onChange={(e) => setFilterCountry(e.target.value)}
          className="px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          {countryOptions.map(option => (
            <option key={option.id || 'all-country'} value={option.id}>{option.name}</option>
          ))}
        </select>

        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          {nodeTypes.map(t => (
            <option key={t} value={t}>{t === 'all' ? '全部协议' : t.toUpperCase()}</option>
          ))}
        </select>

        <select
          value={filterLatencyStatus}
          onChange={(e) => setFilterLatencyStatus(e.target.value)}
          className="px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">延迟状态</option>
          <option value="untested">未测试</option>
          <option value="success">测试成功</option>
          <option value="timeout">超时</option>
          <option value="failed">测试失败</option>
        </select>
      </div>


      {/* Filters Row 2 - Sort */}
      <div className="flex flex-wrap gap-2 items-center">
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          className="px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="name">按名称</option>
          <option value="type">按类型</option>
          <option value="source">按来源</option>
          <option value="region">按地区</option>
          <option value="latency">按延迟</option>
          <option value="speed">按速度</option>
        </select>

        <select
          value={sortOrder}
          onChange={(e) => setSortOrder(e.target.value)}
          className="px-2.5 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="asc">升序 ↑</option>
          <option value="desc">降序 ↓</option>
        </select>

        <button
          onClick={clearFilters}
          className="px-2.5 py-1.5 text-sm text-gray-400 hover:text-white transition-colors"
        >
          重置
        </button>
      </div>

      {/* Stats */}
      <div className="flex flex-wrap gap-3 text-sm flex-shrink-0">
        <span className="text-gray-400">
          共 <span className="text-white font-medium">{filteredNodes.length}</span> 个节点
          {(search || filterSource !== 'all' || filterCountry || filterIpSource || filterIpProperty || filterType !== 'all' || filterLatencyStatus !== 'all') &&
            <span className="text-gray-500"> (筛选自 {allNodes.length} 个)</span>
          }
        </span>
        <span className="text-gray-500">|</span>
        <span className="text-gray-400">
          已测试: <span className="text-blue-400">{testedCount}</span>
        </span>
        <span className="text-gray-400">
          成功: <span className="text-green-400">{successCount}</span>
        </span>
        <span className="text-gray-400">
          失败: <span className="text-red-400">{failedCount}</span>
        </span>
        {selectedNodes.size > 0 && (
          <>
            <span className="text-gray-500">|</span>
            <span className="text-blue-400">已选择 {selectedNodes.size} 个</span>
          </>
        )}
      </div>
      {/* Nodes Table */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl overflow-hidden flex-1 flex flex-col min-h-0">
        {loadingNodes ? (
          <div className="p-12 text-center text-gray-500">
            <RefreshCw size={24} className="animate-spin mx-auto mb-2" />
            加载节点中...
          </div>
        ) : (
          <>
            <div className="overflow-x-auto overflow-y-auto flex-1">
              <table className="w-full table-fixed text-sm">
              <colgroup>
                <col className="w-[2%]" />
                <col className="w-[14%]" />
                <col className="w-[7%]" />
                <col className="w-[5%]" />
                <col className="w-[11%]" />
                <col className="w-[8%]" />
                <col className="w-[5%]" />
                <col className="w-[5%]" />
                <col className="w-[5%]" />
                <col className="w-[7%]" />
                <col className="w-[5%]" />
                <col className="w-[7%]" />
                <col className="w-[15%]" />
              </colgroup>
              <thead className="sticky top-0 bg-gray-800 z-10">
                <tr className="border-b border-gray-700 text-left">
                  <th className="px-1 py-1.5 text-xs font-medium text-gray-400 whitespace-nowrap">
                    <button
                      onClick={toggleSelectAll}
                      className="flex items-center hover:text-white transition-colors"
                      title="全选/取消全选"
                    >
                      {selectedNodes.size === filteredNodes.filter((node) => node.sourceType !== 'node_pool').length
                        && filteredNodes.some((node) => node.sourceType !== 'node_pool') ? (
                        <CheckSquare size={16} className="text-blue-400" />
                      ) : (
                        <Square size={16} />
                      )}
                    </button>
                  </th>
                  <th className="px-2 py-1.5 text-xs font-medium text-gray-400 whitespace-nowrap">节点名称</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-gray-400 whitespace-nowrap">来源</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-gray-400 whitespace-nowrap">协议</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-cyan-300 whitespace-nowrap">地区</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-cyan-300 whitespace-nowrap">IP</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-purple-300 whitespace-nowrap">IP来源</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-purple-300 whitespace-nowrap">IP属性</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-purple-300 whitespace-nowrap">IPPure系数</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-orange-300 whitespace-nowrap">人机流量比</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-gray-400 whitespace-nowrap">延迟</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-gray-400 whitespace-nowrap">速度</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-gray-400 whitespace-nowrap">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {paginatedNodes.length > 0 ? (
                  paginatedNodes.map((node, idx) => {
                    const activeTestType = testingByNode[node.nodeKey];
                    const isTesting = Boolean(activeTestType);
                    const isSelected = selectedNodes.has(node.nodeKey);
	                    const isNodePool = node.sourceType === 'node_pool';
	                    const testResult = nodeTestResults[node.nodeKey];
	                    const displayedLatency = testResult?.latency !== undefined ? testResult.latency : node.latency;
	                    const displayedError = testResult?.error !== undefined ? testResult.error : node.testError;
	                    const displayedSpeedError = testResult?.speed_error === true;
	                    const latencyBadge = getLatencyBadge(displayedLatency, displayedError);
                    // Use local cache for port mapping (updates instantly without page refresh)
                    const currentMappedPort = localPortMappings[node.final_name] ?? node.mapped_port;
                    const rawDisplayName = node.display_name || node.name || '未命名';
                    const visibleDisplayName = stripLeadingFlagIcon(rawDisplayName);
                    const nodeFlag = node.flag || (rawDisplayName.match(LEADING_FLAG_ICON_RE)?.[0]?.trim() ?? '');
                    const isDisabled = node.enabled === false;
                    const isIncompatible = node.valid === false;
                    const invalidReasonLabel = getNodeInvalidReasonLabel(node.invalid_reason);
                    const ipProfile = mergeIpProfiles(node.ip_profile, testResult?.ip_profile);
                    const displayedExitIp = testResult?.exit_ip || node.exit_ip;
                    const ipStatus = ipProfile?.ip_status;
                    const ippureStatus = ipProfile?.ippure_status;
                    const radarStatus = ipProfile?.radar_status;
                    const hasIpSource = Boolean(ipProfile?.ip_source);
                    const hasNetworkType = Boolean(ipProfile?.network_type);
                    const hasFraudScore = ipProfile?.fraud_score !== undefined;
                    const hasRadarRatio = ipProfile?.radar_human_ratio !== undefined
                      || ipProfile?.radar_bot_ratio !== undefined;

                    return (
                      <tr key={node.nodeKey} className={`hover:bg-gray-800/50 ${isSelected ? 'bg-blue-500/5' : ''} ${isDisabled ? 'opacity-60' : ''}`}>
                        <td className="px-1 py-1.5">
                          <button
                            onClick={() => toggleSelectNode(node.nodeKey)}
                            disabled={isNodePool}
                            className={`text-gray-400 transition-colors ${isNodePool ? 'opacity-30 cursor-not-allowed' : 'hover:text-white'}`}
                            title={isNodePool ? '节点池不参与单节点检测' : '选择节点'}
                          >
                            {isSelected ? (
                              <CheckSquare size={18} className="text-blue-400" />
                            ) : (
                              <Square size={18} />
                            )}
                          </button>
                        </td>
                        <td className="px-2 py-1.5">
                          <div className="inline-flex min-w-0 max-w-full items-center gap-1">
                            {node.sourceType === 'custom' && node.id && (
                              <input
                                type="number"
                                min={1}
                                value={customOrderMap[node.id] ?? ''}
                                onChange={(e) => updateCustomOrderValue(node.id, e.target.value)}
                                onBlur={applyCustomOrder}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') {
                                    e.preventDefault();
                                    applyCustomOrder();
                                  }
                                }}
                                className="w-10 px-1 py-0.5 rounded bg-orange-500/20 text-orange-300 text-xs font-mono border border-orange-500/30 focus:outline-none focus:border-orange-400"
                                title="自建节点序号，修改后自动按序排列"
                              />
                            )}
                            {node.sourceType === 'custom' && !node.id && (
                              <span className="inline-flex items-center justify-center w-5 h-5 rounded bg-orange-500/20 text-orange-400 text-xs font-bold">
                                {node.idx + 1}
                              </span>
                            )}
                            {(node.sourceType === 'chain' || isNodePool) && (
                              <span className="inline-flex items-center justify-center w-5 h-5 rounded bg-blue-500/20 text-blue-400 text-xs font-bold">
                                {node.idx + 1}
                              </span>
                            )}
                            {nodeFlag && (
                              <span className="text-base leading-none shrink-0" title={node.region || node.country || ''}>
                                {nodeFlag}
                              </span>
                            )}
                            <span className={`min-w-0 max-w-[145px] truncate text-white ${isDisabled ? 'line-through decoration-gray-500' : ''}`} title={rawDisplayName}>
                              {visibleDisplayName || rawDisplayName}
                            </span>
                            {isIncompatible && (
                              <span
                                className="inline-flex items-center px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-xs whitespace-nowrap"
                                title={invalidReasonLabel}
                              >
                                配置不兼容
                              </span>
                            )}
                            {node.sourceType === 'subscription' || node.sourceType === 'custom' ? (
                              <button
                                onClick={() => toggleNodeEnabled(node)}
                                className="shrink-0 p-0 leading-none text-gray-400 hover:text-white transition-colors"
                                title={isDisabled ? '点击启用节点，重新加入聚合配置' : '点击禁用节点，从聚合配置中移除'}
                              >
                                {isDisabled ? (
                                  <ToggleLeft size={16} />
                                ) : (
                                  <ToggleRight size={16} className="text-green-400" />
                                )}
                              </button>
                            ) : null}
                            {node.sourceType === 'chain' && (
                              <button
                                onClick={() => toggleChain(node.chainId)}
                                className="shrink-0 p-0 leading-none text-gray-400 hover:text-white transition-colors"
                                title={node.enabled ? '点击禁用' : '点击启用'}
                              >
                                {node.enabled ? (
                                  <ToggleRight size={16} className="text-green-400" />
                                ) : (
                                  <ToggleLeft size={16} />
                                )}
                              </button>
                            )}
                            {isNodePool && (
                              <button
                                onClick={() => toggleNodePool(node.poolId)}
                                className="shrink-0 p-0 leading-none text-gray-400 hover:text-white transition-colors"
                                title={node.enabled ? '点击禁用节点池' : '点击启用节点池'}
                              >
                                {node.enabled ? (
                                  <ToggleRight size={16} className="text-green-400" />
                                ) : (
                                  <ToggleLeft size={16} />
                                )}
                              </button>
                            )}
                            {isDisabled && (
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-gray-600/30 text-gray-400 text-xs">
                                已禁用
                              </span>
                            )}
                            {currentMappedPort && (
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-green-500/20 text-green-400 text-xs font-mono">
                                :{currentMappedPort}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-2 py-1.5">
                          <span className={`text-sm whitespace-nowrap ${node.sourceType === 'custom' ? 'text-orange-400' : node.sourceType === 'chain' ? 'text-blue-400' : node.sourceType === 'node_pool' ? 'text-emerald-400' : node.sourceType === 'vpngate' ? 'text-cyan-400' : 'text-gray-400'}`}>
                            {node.source}
                          </span>
                        </td>
                        <td className="px-2 py-1.5">
                          <span className={`px-1.5 py-0.5 rounded text-xs font-medium whitespace-nowrap ${getTypeColor(node.type)}`} title={node.type?.toUpperCase() || '-'}>
                            {getProtocolDisplayLabel(node.type)}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-gray-400 text-sm">
                          <span className="block w-full max-w-[180px] truncate" title={node.city ? `${node.region} ${node.city}` : node.region}>
                            {isNodePool ? node.region : `${node.region || getMetadataStatusLabel(ipStatus)}${node.city ? ` ${node.city}` : ''}`}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-gray-400 text-sm">
                          <span
                            className={`truncate inline-block max-w-[130px] font-mono text-xs ${displayedExitIp ? '' : getMetadataStatusClass(ipStatus)}`}
                            title={displayedExitIp || ''}
                          >
                            {isNodePool ? '-' : (displayedExitIp || getMetadataStatusLabel(ipStatus))}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-xs whitespace-nowrap">
                          <span className={isNodePool ? 'text-gray-500' : hasIpSource ? 'text-cyan-300' : getMetadataStatusClass(ippureStatus)}>
                            {isNodePool ? '-' : (hasIpSource ? getIpSourceLabel(ipProfile.ip_source) : getMetadataStatusLabel(ippureStatus))}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-xs whitespace-nowrap">
                          <span className={isNodePool ? 'text-gray-500' : hasNetworkType ? 'text-purple-300' : getMetadataStatusClass(ippureStatus)}>
                            {isNodePool ? '-' : (hasNetworkType ? getNetworkTypeLabel(ipProfile.network_type) : getMetadataStatusLabel(ippureStatus))}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-xs whitespace-nowrap">
                          <span className={isNodePool ? 'text-gray-500' : hasFraudScore ? 'text-amber-300 font-mono' : getMetadataStatusClass(ippureStatus)}>
                            {isNodePool ? '-' : (hasFraudScore ? formatIppureScore(ipProfile.fraud_score) : getMetadataStatusLabel(ippureStatus))}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-xs">
                          {isNodePool ? (
                            <span className="text-gray-500">-</span>
                          ) : hasRadarRatio ? (
                            <div className="flex flex-col gap-0.5 whitespace-nowrap">
                              {ipProfile?.radar_human_ratio !== undefined && (
                                <span className="text-green-400">
                                  人类 {formatRadarRatio(ipProfile.radar_human_ratio)}
                                </span>
                              )}
                              {ipProfile?.radar_bot_ratio !== undefined && (
                                <span className="text-orange-400">
                                  机器人 {formatRadarRatio(ipProfile.radar_bot_ratio)}
                                </span>
                              )}
                            </div>
                          ) : (
                            <span className={getMetadataStatusClass(radarStatus)}>
                              {getMetadataStatusLabel(radarStatus)}
                            </span>
                          )}
                        </td>
                        <td className="px-2 py-1.5 whitespace-nowrap">
                          <div className="flex items-center gap-2 whitespace-nowrap">
                            {isNodePool ? (
                              <span className="text-gray-500">-</span>
                            ) : displayedLatency !== undefined && displayedLatency !== null && displayedLatency > 0 && !displayedError ? (
                              <span className={`font-mono text-sm ${getLatencyColor(displayedLatency)}`}>
                                {displayedLatency}ms
                              </span>
                            ) : (
                              <span className={`px-2 py-0.5 rounded text-xs ${latencyBadge.color}`}>
                                {latencyBadge.text}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-2 py-1.5 whitespace-nowrap">
                          <div className="flex items-center gap-2 whitespace-nowrap">
	                            {isNodePool ? (
	                              <span className="text-gray-500">-</span>
	                            ) : displayedSpeedError ? (
	                              <span className="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-400">
	                                失败
	                              </span>
	                            ) : node.speed !== undefined && node.speed > 0 ? (
                              <span className="font-mono text-sm text-green-400 whitespace-nowrap">
	                                {node.speed.toFixed(1)} MB/s
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-xs bg-gray-500/20 text-gray-400">
                                未测
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-2 py-1.5 whitespace-nowrap">
                          <div className="flex items-center gap-0">
                            {node.sourceType !== 'vpngate' && (
                              <button
                                onClick={() => {
                                  if (node.sourceType === 'chain') {
                                    openChainModal(proxyChains.find(c => c.id === node.chainId));
                                  } else if (isNodePool) {
                                    openNodePoolModal(nodePools.find(pool => pool.id === node.poolId));
                                  } else {
                                    setEditingNode(node);
                                  }
                                }}
                                className="p-0.5 text-gray-400 hover:text-purple-400 hover:bg-purple-500/10 rounded transition-colors"
                                title="查看/编辑"
                              >
                                <Edit2 size={14} />
                              </button>
                            )}
                            {/* IP/region test button */}
                            <button
                              onClick={() => testNode(node, true)}
                              disabled={isNodePool || isTesting || batchTesting || node.sourceType === 'chain' || isIncompatible}
                              className="p-0.5 text-gray-400 hover:text-cyan-400 hover:bg-cyan-500/10 rounded transition-colors disabled:opacity-50"
                              title={isIncompatible ? invalidReasonLabel : '检测 IP/地区'}
                            >
                              {activeTestType === 'region' ? (
                                <RefreshCw size={14} className="animate-spin" />
                              ) : (
                                <Globe size={14} />
                              )}
                            </button>
                            {/* IPPure attribute test button */}
                            <button
                              onClick={() => testNodeIppure(node)}
                              disabled={isNodePool || isTesting || batchTesting || node.sourceType === 'chain' || isIncompatible}
                              className="p-0.5 text-gray-400 hover:text-purple-400 hover:bg-purple-500/10 rounded transition-colors disabled:opacity-50"
                              title={isIncompatible ? invalidReasonLabel : '检测 IP 来源/属性/IPPure'}
                            >
                              {activeTestType === 'ippure' ? (
                                <RefreshCw size={14} className="animate-spin" />
                              ) : (
                                <ShieldCheck size={14} />
                              )}
                            </button>
                            {/* Radar human/bot ratio test button */}
                            <button
                              onClick={() => testNodeRadar(node)}
                              disabled={isNodePool || isTesting || batchTesting || node.sourceType === 'chain' || isIncompatible}
                              className="p-0.5 text-gray-400 hover:text-orange-400 hover:bg-orange-500/10 rounded transition-colors disabled:opacity-50"
                              title={isIncompatible ? invalidReasonLabel : '检测人机流量比'}
                            >
                              {activeTestType === 'radar' ? (
                                <RefreshCw size={14} className="animate-spin" />
                              ) : (
                                <Bot size={14} />
                              )}
                            </button>
                            {/* Latency test button */}
                            <button
                              onClick={() => testNode(node)}
                              disabled={isNodePool || isTesting || batchTesting || node.sourceType === 'chain' || isIncompatible}
                              className="p-0.5 text-gray-400 hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors disabled:opacity-50"
                              title={isIncompatible ? invalidReasonLabel : '测试延迟'}
                            >
                              {activeTestType === 'latency' ? (
                                <RefreshCw size={14} className="animate-spin" />
                              ) : (
                                <Clock size={14} />
                              )}
                            </button>
                            {/* Speed test button */}
                            <button
                              onClick={() => testNodeSpeed(node)}
                              disabled={isNodePool || isTesting || batchTesting || node.sourceType === 'chain' || isIncompatible}
                              className="p-0.5 text-gray-400 hover:text-green-400 hover:bg-green-500/10 rounded transition-colors disabled:opacity-50"
                              title={isIncompatible ? invalidReasonLabel : '测试速度'}
                            >
                              {activeTestType === 'speed' ? (
                                <RefreshCw size={14} className="animate-spin" />
                              ) : (
                                <Play size={14} />
                              )}
                            </button>
                            {node.sourceType !== 'vpngate' && (
                              <button
                                onClick={() => openPortMapping(node)}
                                className={`p-0.5 rounded transition-colors ${currentMappedPort
                                  ? 'text-green-400 hover:text-green-300 hover:bg-green-500/10'
                                  : 'text-gray-400 hover:text-green-400 hover:bg-green-500/10'
                                  }`}
                                title={currentMappedPort ? `已绑定端口 ${currentMappedPort}` : '绑定端口'}
                              >
                                <Link2 size={14} />
                              </button>
                            )}
                            {node.sourceType === 'custom' && (
                              <>
                                <button
                                  onClick={() => moveCustomNode(node.id, 'up')}
                                  className="p-0.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="上移"
                                >
                                  <ChevronUp size={14} />
                                </button>
                                <button
                                  onClick={() => moveCustomNode(node.id, 'down')}
                                  className="p-0.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="下移"
                                >
                                  <ChevronDown size={14} />
                                </button>
                                <button
                                  onClick={() => confirmDeleteNode(node.id)}
                                  className="p-0.5 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                                  title="删除"
                                >
                                  <Trash2 size={14} />
                                </button>
                              </>
                            )}
                            {node.sourceType === 'chain' && (
                              <>
                                <button
                                  onClick={() => moveChain(node.chainId, 'up')}
                                  className="p-0.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="上移"
                                >
                                  <ChevronUp size={14} />
                                </button>
                                <button
                                  onClick={() => moveChain(node.chainId, 'down')}
                                  className="p-0.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="下移"
                                >
                                  <ChevronDown size={14} />
                                </button>
                                <button
                                  onClick={() => setDeleteChainConfirm({ open: true, chainId: node.chainId })}
                                  className="p-0.5 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                                  title="删除"
                                >
                                  <Trash2 size={14} />
                                </button>
                              </>
                            )}
                            {isNodePool && (
                              <>
                                <button
                                  onClick={() => moveNodePool(node.poolId, 'up')}
                                  className="p-0.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="上移"
                                >
                                  <ChevronUp size={14} />
                                </button>
                                <button
                                  onClick={() => moveNodePool(node.poolId, 'down')}
                                  className="p-0.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="下移"
                                >
                                  <ChevronDown size={14} />
                                </button>
                                <button
                                  onClick={() => setDeleteNodePoolConfirm({ open: true, poolId: node.poolId })}
                                  className="p-0.5 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                                  title="删除"
                                >
                                  <Trash2 size={14} />
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={13} className="px-4 py-12 text-center text-gray-500">
                      {allNodes.length === 0 ? '暂无节点，请先添加订阅或自建节点' : '没有匹配的节点'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* 分页控件 */}
          {filteredNodes.length > pageSize && (
            <div className="mt-4 flex items-center justify-between px-4 py-3 bg-gray-800/50 rounded-lg border border-gray-700">
              <div className="flex items-center gap-4">
                <span className="text-sm text-gray-400">
                  显示 {(currentPage - 1) * pageSize + 1} - {Math.min(currentPage * pageSize, filteredNodes.length)} / {filteredNodes.length}
                </span>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setCurrentPage(1);
                  }}
                  className="px-3 py-1 bg-gray-700 border border-gray-600 rounded text-white text-sm focus:outline-none focus:border-blue-500"
                >
                  <option value={25}>25 / 页</option>
                  <option value={50}>50 / 页</option>
                  <option value={100}>100 / 页</option>
                  <option value={200}>200 / 页</option>
                </select>
              </div>
              
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage(1)}
                  disabled={currentPage === 1}
                  className="px-3 py-1 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded transition-colors text-sm"
                >
                  首页
                </button>
                <button
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded transition-colors text-sm"
                >
                  上一页
                </button>
                <span className="px-3 py-1 text-sm text-gray-400">
                  {currentPage} / {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded transition-colors text-sm"
                >
                  下一页
                </button>
                <button
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded transition-colors text-sm"
                >
                  末页
                </button>
              </div>
            </div>
          )}
          </>
        )}
      </div>


      {/* Add Node Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-md border border-gray-700">
            <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-white">添加自建节点</h3>
              <button onClick={() => setShowAddModal(false)} className="text-gray-400 hover:text-white">
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">节点链接</label>
                <textarea
                  value={newNodeLink}
                  onChange={(e) => setNewNodeLink(e.target.value)}
                  placeholder="支持多行，一行一个链接（含 socks5://用户名:密码@地址:端口）"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 h-24 resize-none"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">节点名称（可选）</label>
                <input
                  type="text"
                  value={newNodeName}
                  onChange={(e) => setNewNodeName(e.target.value)}
                  placeholder="留空则使用链接名；批量用分号分隔"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <p className="text-xs text-gray-500">
                支持的协议：SOCKS5, VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC 等
              </p>
            </div>
            <div className="px-4 py-3 border-t border-gray-700 flex justify-end gap-2">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                取消
              </button>
              <button
                onClick={addCustomNode}
                disabled={!newNodeLink.trim() || loading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {loading ? '添加中...' : '添加'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Test Settings Modal */}
      {showTestSettingsModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-md border border-gray-700">
            <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-white">检测设置</h3>
              <button onClick={() => setShowTestSettingsModal(false)} className="text-gray-400 hover:text-white">
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-2">超时时间 (毫秒)</label>
                <input
                  type="number"
                  value={testTimeout}
                  onChange={(e) => setTestTimeout(parseInt(e.target.value) || 5000)}
                  min={1000}
                  max={30000}
                  step={1000}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
                <p className="text-xs text-gray-500 mt-1">建议 3000-10000ms</p>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-2">并发数量</label>
                <input
                  type="number"
                  value={testConcurrency}
                  onChange={(e) => setTestConcurrency(parseInt(e.target.value) || 5)}
                  min={1}
                  max={20}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
                <p className="text-xs text-gray-500 mt-1">同时测试的节点数量，建议 3-10</p>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-2">IP/地区检测 API</label>
                <select
                  value={selectedGeoipApi}
                  onChange={(e) => setSelectedGeoipApi(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  {geoipApis.filter(api => api.enabled !== false).map(api => (
                    <option key={api.id} value={api.id}>
                      {api.name} {api.limit ? `(${api.limit})` : ''}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-gray-500 mt-1">用于检测出口 IP、地区以及为 Radar 查询 ASN</p>
              </div>
            </div>
            <div className="px-4 py-3 border-t border-gray-700 flex justify-end gap-2">
              <button
                onClick={() => setShowTestSettingsModal(false)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
              >
                确定
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirm Modal */}
      <ConfirmModal
        isOpen={deleteConfirm.open}
        onClose={() => setDeleteConfirm({ open: false, nodeId: null })}
        onConfirm={() => deleteCustomNode(deleteConfirm.nodeId)}
        title="删除节点"
        message="确定要删除这个节点吗？"
        type="danger"
      />
      <ConfirmModal
        isOpen={batchDeleteConfirm.open}
        onClose={() => setBatchDeleteConfirm({ open: false, ids: [], keys: [], count: 0 })}
        onConfirm={confirmBatchDeleteCustomNodes}
        title="批量删除"
        message={`确定要删除选中的 ${batchDeleteConfirm.count} 个自建节点吗？`}
        type="danger"
      />

      {/* Node Edit Modal */}
      {editingNode && (
        <NodeEditModal
          node={editingNode}
          onClose={() => setEditingNode(null)}
          onSave={async () => {
            await onRefreshCustomNodes?.();
          }}
          showToast={showToast}
        />
      )}

      {showNodePoolModal && (
        <NodePoolModal
          pool={editingNodePool}
          availableNodes={availableNodePoolNodes}
          saving={savingNodePool}
          onClose={closeNodePoolModal}
          onSave={saveNodePool}
        />
      )}

      {/* Port Mapping Modal */}
      {portMappingNode && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-md border border-gray-700">
            <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-white">端口绑定</h3>
              <button onClick={() => setPortMappingNode(null)} className="text-gray-400 hover:text-white">
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-2">节点名称</label>
                <p className="text-white text-sm bg-gray-700/50 px-3 py-2 rounded-lg truncate" title={portMappingNode.final_name || portMappingNode.display_name || portMappingNode.name || '未命名'}>
                  {portMappingNode.final_name || portMappingNode.display_name || portMappingNode.name || '未命名'}
                </p>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-2">监听端口</label>
                <input
                  type="number"
                  value={portMappingValue}
                  onChange={(e) => setPortMappingValue(e.target.value)}
                  placeholder="如: 42001"
                  min={1024}
                  max={65535}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-green-500"
                />
                <p className="text-xs text-gray-500 mt-1">端口范围: 1024-65535</p>
              </div>
              {portMappingNode.mapped_port && (
                <div className="bg-green-500/10 border border-green-500/30 rounded-lg px-3 py-2">
                  <p className="text-green-400 text-sm">
                    当前已绑定端口: <span className="font-mono">{portMappingNode.mapped_port}</span>
                  </p>
                </div>
              )}
            </div>
            <div className="px-4 py-3 border-t border-gray-700 flex justify-between">
              <div>
                {portMappingNode.mapped_port && (
                  <button
                    onClick={removePortMapping}
                    className="px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg transition-colors"
                  >
                    解除绑定
                  </button>
                )}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setPortMappingNode(null)}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
                >
                  取消
                </button>
                <button
                  onClick={savePortMapping}
                  disabled={!portMappingValue}
                  className="px-4 py-2 bg-green-600 hover:bg-green-500 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg transition-colors"
                >
                  绑定
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Port Mapping List Modal */}
      {showPortMappingList && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-2xl border border-gray-700 max-h-[80vh] flex flex-col">
            <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-white">端口映射管理</h3>
              <button onClick={() => setShowPortMappingList(false)} className="text-gray-400 hover:text-white">
                <X size={20} />
              </button>
            </div>
            <div className="p-4 overflow-y-auto flex-1">
              {allPortMappings.length === 0 ? (
                <div className="text-center text-gray-500 py-8">
                  暂无端口映射
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="grid grid-cols-12 gap-2 text-xs text-gray-500 px-3 py-2">
                    <div className="col-span-2">端口</div>
                    <div className="col-span-7">节点名称</div>
                    <div className="col-span-2">状态</div>
                    <div className="col-span-1">操作</div>
                  </div>
                  {allPortMappings.map((mapping) => (
                    <div
                      key={mapping.port}
                      className={`grid grid-cols-12 gap-2 items-center px-3 py-2 rounded-lg ${mapping.active ? 'bg-gray-700/50' : 'bg-red-500/10 border border-red-500/30'
                        }`}
                    >
                      <div className="col-span-2">
                        <span className="font-mono text-green-400">{mapping.port}</span>
                      </div>
                      <div className="col-span-7">
                        <span className={`text-sm truncate block ${mapping.active ? 'text-white' : 'text-gray-500'}`} title={mapping.final_name}>
                          {mapping.final_name}
                        </span>
                      </div>
                      <div className="col-span-2">
                        {mapping.active ? (
                          <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">活跃</span>
                        ) : (
                          <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">失效</span>
                        )}
                      </div>
                      <div className="col-span-1">
                        <button
                          onClick={() => deletePortMappingFromList(mapping.port, mapping.final_name)}
                          className="p-1 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                          title="删除"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="px-4 py-3 border-t border-gray-700 text-sm text-gray-500">
              <p>活跃：节点存在于当前订阅中，生成配置时会包含 listener</p>
              <p>失效：节点已不存在，可删除或等节点恢复后自动生效</p>
            </div>
          </div>
        </div>
      )}

      {/* Proxy Chain Modal */}
      {showChainModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-700">
              <h2 className="text-lg font-medium text-white">
                {editingChain ? '编辑链式代理' : '添加链式代理'}
              </h2>
              <button
                onClick={closeChainModal}
                className="p-1 text-gray-400 hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-4 space-y-4">
              {/* Name Input */}
              <div>
                <label className="block text-sm text-gray-400 mb-1">名称</label>
                <input
                  type="text"
                  value={chainName}
                  onChange={(e) => setChainName(e.target.value)}
                  placeholder="例如：美国家宽链路"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Chain Rows - Vertical Layout */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm text-gray-400">链路配置</label>
                </div>

                <div className="space-y-4">
                  {chainRows.map((row, rowIndex) => (
                    <div key={rowIndex} className="bg-gray-900/50 rounded-lg p-3">

                      {/* Vertical Node Selectors */}
                      <div className="space-y-2">
                        <div className="text-sm text-gray-500 text-center">我</div>
                        
                        {row.map((node, colIndex) => {
                          const isLast = colIndex === row.length - 1;
                          const cellType = node?.type === 'group' && node?.group_source === 'vpngate'
                            ? 'vpngate'
                            : (node?.type || 'node');
                          const isVpnGatePool = cellType === 'vpngate';
                          const groupLabel = isLast ? '组(落地池)' : '组(中转池)';
                          const selectedKeys = (node?.group_nodes || []).map(n => makeChainNodeKey(n.sub_id, n.node_id, n.node_name, n.node_index));
                          return (
                            <React.Fragment key={colIndex}>
                              <div className="flex justify-center">
                                <ArrowRight size={16} className="text-gray-600 rotate-90" />
                              </div>
                              <div className="relative space-y-2">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs text-gray-500">类型</span>
                                  <select
                                    value={cellType}
                                    onChange={(e) => updateChainCellType(rowIndex, colIndex, e.target.value)}
                                    className="px-2 py-1 bg-gray-800 border border-gray-700 rounded text-xs text-white focus:outline-none focus:border-blue-500"
                                  >
                                    <option value="node">节点</option>
                                    <option value="group">{groupLabel}</option>
                                    {isLast && (
                                      <option value="vpngate">
                                        VPN Gate 国家动态池（{vpngatePools.length} 个国家）
                                      </option>
                                    )}
                                  </select>
                                </div>

                                {cellType === 'group' || isVpnGatePool ? (
                                  <div className="space-y-2">
                                    <input
                                      type="text"
                                      value={node?.group_name || ''}
                                      onChange={(e) => updateChainGroup(rowIndex, colIndex, { group_name: e.target.value })}
                                      placeholder={isLast ? '落地池名称' : '中转池名称'}
                                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                                    />
                                    <select
                                      value={node?.group_strategy || 'load-balance'}
                                      onChange={(e) => updateChainGroup(rowIndex, colIndex, { group_strategy: e.target.value })}
                                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                                    >
                                      <option value="select">手动选择</option>
                                      <option value="load-balance">负载均衡(随机/轮询)</option>
                                      <option value="url-test">自动测速</option>
                                      <option value="fallback">故障切换</option>
                                    </select>

                                    {node?.group_strategy === 'load-balance' && (
                                      <select
                                        value={node?.lb_strategy || 'round-robin'}
                                        onChange={(e) => updateChainGroup(rowIndex, colIndex, { lb_strategy: e.target.value })}
                                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                                      >
                                        <option value="round-robin">轮询 (round-robin)</option>
                                        <option value="consistent-hashing">同目标固定 (consistent-hashing)</option>
                                        <option value="sticky-sessions">同会话固定 (sticky-sessions)</option>
                                      </select>
                                    )}

                                    {isVpnGatePool ? (
                                      <div className="space-y-2">
                                        <select
                                          value={node?.vpngate_country_code || ''}
                                          onChange={(e) => updateVpngateCountry(rowIndex, colIndex, e.target.value)}
                                          className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                                        >
                                          <option value="">全部国家（{vpngatePool.active_node_count ?? 0} 个）</option>
                                          {vpngatePools.map(pool => (
                                            <option key={pool.pool_id || pool.country_code} value={pool.country_code}>
                                              {pool.flag || ''} {pool.country || pool.country_code}（{pool.active_node_count ?? 0} 个）
                                            </option>
                                          ))}
                                        </select>
                                        {(() => {
                                          const selectedPool = node?.vpngate_country_code
                                            ? vpngatePools.find(pool => pool.country_code === node.vpngate_country_code)
                                            : null;
                                          const poolLabel = selectedPool?.country
                                            ? `${selectedPool.country} `
                                            : '';
                                          const activeCount = selectedPool?.active_node_count ?? vpngatePool.active_node_count ?? 0;
                                          return (
                                            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-200">
                                              自动使用当前有效的 {poolLabel}VPN Gate 节点，刷新节点源后池成员会同步更新；当前有效节点：{activeCount}
                                            </div>
                                          );
                                        })()}
                                      </div>
                                    ) : (() => {
                                      const cellKey = getGroupCellKey(rowIndex, colIndex);
                                      const isEditing = groupEditing[cellKey];
                                      const draftKeys = groupDrafts[cellKey] || [];
                                      const searchValue = groupSearch[cellKey] || '';
                                      const filteredNodes = orderedChainNodes.filter((n) => {
                                        if (!searchValue) return true;
                                        const label = getChainNodeLabel(n).toLowerCase();
                                        const source = (n.sub_name || n.sub_id || '').toLowerCase();
                                        const q = searchValue.toLowerCase();
                                        return label.includes(q) || source.includes(q);
                                      });
                                      const selectedNames = (node?.group_nodes || []).map(n => n.node_name);

                                      if (!isEditing) {
                                        return (
                                          <div className="space-y-2">
                                            <div className="text-xs text-gray-500">已选 {selectedNames.length} 个</div>
                                            {selectedNames.length > 0 ? (
                                              <div className="flex flex-wrap gap-1">
                                                {selectedNames.map((name, i) => (
                                                  <span key={`${name}-${i}`} className="px-2 py-0.5 bg-gray-700 text-gray-200 rounded text-xs">{name}</span>
                                                ))}
                                              </div>
                                            ) : (
                                              <div className="text-xs text-gray-500">尚未选择组内节点</div>
                                            )}
                                            <button
                                              type="button"
                                              onClick={() => beginGroupEdit(rowIndex, colIndex)}
                                              className="text-xs text-blue-400 hover:text-blue-300"
                                            >
                                              修改
                                            </button>
                                          </div>
                                        );
                                      }

                                      return (
                                        <div className="space-y-2">
                                          <div className="flex items-center justify-between text-xs text-gray-500">
                                            <span>点击选择，已选 {draftKeys.length} 个</span>
                                            <div className="flex gap-2">
                                              <button
                                                type="button"
                                                onClick={() => setGroupDraftKeys(rowIndex, colIndex, filteredNodes.map(n => makeChainNodeKey(n.sub_id, n.node_id, n.node_name ?? n.display_name ?? n.name, n.node_index)))}
                                                className="text-blue-400 hover:text-blue-300"
                                              >
                                                全选
                                              </button>
                                              <button
                                                type="button"
                                                onClick={() => setGroupDraftKeys(rowIndex, colIndex, [])}
                                                className="text-gray-400 hover:text-gray-300"
                                              >
                                                清空
                                              </button>
                                            </div>
                                          </div>
                                          <input
                                            value={searchValue}
                                            onChange={(e) => setGroupSearch(prev => ({ ...prev, [cellKey]: e.target.value }))}
                                            placeholder="搜索节点/订阅"
                                            className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                                          />
                                          <div className="max-h-40 overflow-y-auto border border-gray-700 rounded-lg bg-gray-800">
                                            {filteredNodes.map(n => {
                                              const key = makeChainNodeKey(n.sub_id, n.node_id, n.node_name ?? n.display_name ?? n.name, n.node_index);
                                              const checked = draftKeys.includes(key);
                                              return (
                                                <div
                                                  key={key}
                                                  onClick={() => toggleGroupDraft(rowIndex, colIndex, key)}
                                                  className="px-3 py-2 text-sm text-white hover:bg-gray-700/50 cursor-pointer flex items-center justify-between"
                                                >
                                                  <span className="truncate">{getChainNodeLabel(n)}</span>
                                                  <span className={checked ? 'text-blue-400' : 'text-gray-600'}>{checked ? '已选' : ''}</span>
                                                </div>
                                              );
                                            })}
                                          </div>
                                          <div className="flex items-center justify-between">
                                            <span className="text-xs text-gray-500">选择组内节点，系统会自动生成链路组</span>
                                            <button
                                              type="button"
                                              onClick={() => confirmGroupDraft(rowIndex, colIndex)}
                                              className="px-3 py-1 text-xs bg-blue-500/20 text-blue-300 rounded hover:bg-blue-500/30"
                                            >
                                              确定
                                            </button>
                                          </div>
                                        </div>
                                      );
                                    })()}
                                  </div>
                                ) : (
                                  <select
                                    value={getChainNodeKey(node)}
                                    onChange={(e) => updateChainNode(rowIndex, colIndex, e.target.value)}
                                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500 appearance-none"
                                  >
                                    <option value="">选择节点</option>
                                    {/* Use flat list like node management page */}
                                    {orderedChainNodes.map(n => {
                                      const key = makeChainNodeKey(n.sub_id, n.node_id, n.node_name ?? n.display_name ?? n.name, n.node_index);
                                      return (
                                        <option key={key} value={key}>
                                          {getChainNodeLabel(n)}
                                        </option>
                                      );
                                    })}
                                  </select>
                                )}

                                {row.length > 2 && (
                                  <button
                                    onClick={() => removeChainColumn(rowIndex, colIndex)}
                                    className="absolute -top-2 -right-2 w-5 h-5 bg-red-500 text-white rounded-full text-xs flex items-center justify-center hover:bg-red-400"
                                  >
                                    ×
                                  </button>
                                )}
                              </div>
                            </React.Fragment>
                          );
                        })}

                        <div className="flex justify-center">
                          <ArrowRight size={16} className="text-gray-600 rotate-90" />
                        </div>
                        <div className="text-sm text-gray-500 text-center">服务</div>

                        <button
                          onClick={() => addChainColumn(rowIndex)}
                          className="w-full px-2 py-1.5 text-xs text-blue-400 hover:text-blue-300 border border-blue-400/30 rounded hover:border-blue-400/50 mt-2"
                        >
                          + 添加中转节点
                        </button>
                      </div>

                      {/* Preview */}
                      <div className="mt-3 pt-2 border-t border-gray-700 text-xs text-gray-500">
                        预览: 我 → {row.map((n, colIndex) => {
                          if (n?.type === 'group') {
                            const groupName = n?.group_name || '落地池';
                            if (n?.group_source === 'vpngate') {
                              const selectedPool = n.vpngate_country_code
                                ? vpngatePools.find(pool => pool.country_code === n.vpngate_country_code)
                                : null;
                              const count = selectedPool?.active_node_count ?? vpngatePool.active_node_count ?? 0;
                              return `组:${groupName}(${count}个)`;
                            }
                            const key = getGroupCellKey(rowIndex, colIndex);
                            const draftCount = (groupDrafts[key] || []).length;
                            const savedCount = (n?.group_nodes || []).length;
                            const count = groupEditing[key] ? draftCount : savedCount;
                            return count > 0 ? `组:${groupName}(${count}个)` : `组:${groupName}`;
                          }
                          return n?.node_name || n?.display_name || n?.name || '?';
                        }).join(' → ')} → 服务
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-2 p-4 border-t border-gray-700">
              <button
                onClick={closeChainModal}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                取消
              </button>
              <button
                onClick={saveChain}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
              >
                保存
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Chain Confirm Modal */}
      <ConfirmModal
        isOpen={deleteChainConfirm.open}
        onClose={() => setDeleteChainConfirm({ open: false, chainId: null })}
        onConfirm={() => deleteChain(deleteChainConfirm.chainId)}
        title="删除链式代理"
        message="确定要删除这个链式代理吗？此操作不可撤销。"
        type="danger"
      />
      <ConfirmModal
        isOpen={deleteNodePoolConfirm.open}
        onClose={() => setDeleteNodePoolConfirm({ open: false, poolId: null })}
        onConfirm={() => deleteNodePool(deleteNodePoolConfirm.poolId)}
        title="删除节点池"
        message="确定要删除这个节点池吗？已绑定的端口映射也会失效。"
        type="danger"
      />
    </div>
  );
}
