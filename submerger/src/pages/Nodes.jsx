import React, { useState, useMemo, useEffect } from 'react';
import { Server, Search, Plus, Trash2, X, RefreshCw, Clock, CheckSquare, Square, Settings, Play, Filter, Edit2, ChevronUp, ChevronDown, Globe, Link2, ArrowRight, ToggleLeft, ToggleRight, ChevronDown as ChevronDownIcon } from 'lucide-react';
import request from '../utils/request';
import ConfirmModal from '../components/ConfirmModal';
import NodeEditModal from '../components/NodeEditModal';
import { COUNTRY_CHINESE_NAMES } from './countryData';

const API_BASE = '/api';

// Keywords to filter out info nodes (not real proxy nodes)
const INFO_NODE_KEYWORDS = [
  '剩余流量', '套餐到期', '距离下次重置', '建议', '未到期',
  '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
  '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
  '使用说明', '教程', '更新', '通知', '邀请', '返利',
  '问题', '工单', '咨询', '合作', '会员', '商城', '账号',
  '官网:', '官网：', '免注册'  // Website + colon, free registration ads
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

// Check if a node is an info node (not a real proxy)
const isInfoNode = (node) => {
  if (!node || !node.name) return true;
  const name = node.name;
  
  // Check basic keywords
  if (INFO_NODE_KEYWORDS.some(keyword => name.includes(keyword))) {
    return true;
  }
  
  // Check if starts with "Website" but has no region name
  if (name.startsWith('官网')) {
    // If it contains a region name, it's a valid node
    if (REGION_KEYWORDS.some(region => name.includes(region))) {
      return false;
    }
    // Otherwise it's an info node
    return true;
  }
  
  return false;
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

export default function Nodes({ subscriptions, customNodes, onRefreshCustomNodes, showToast }) {
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');  // 防抖后的搜索值
  // 防抖搜索
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(searchInput);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const [filterSource, setFilterSource] = useState('all');
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
  const [loadingNodes, setLoadingNodes] = useState(true);
  const [deleteConfirm, setDeleteConfirm] = useState({ open: false, nodeId: null });
  const [testingNode, setTestingNode] = useState(null);
  const [testingType, setTestingType] = useState('latency');
  const [nodeTestResults, setNodeTestResults] = useState({});
  const [selectedNodes, setSelectedNodes] = useState(new Set());
  const [batchTesting, setBatchTesting] = useState(false);
  const [batchTestProgress, setBatchTestProgress] = useState({ current: 0, total: 0 });
  const [testTimeout, setTestTimeout] = useState(5000);
  const [testConcurrency, setTestConcurrency] = useState(5);
  const [testLatency, setTestLatency] = useState(false);
  const [testRegion, setTestRegion] = useState(false);
  const [testSpeed, setTestSpeed] = useState(false);
  const [showBatchTestMenu, setShowBatchTestMenu] = useState(false);
  const [editingNode, setEditingNode] = useState(null);

  // GeoIP API selection for region detection
  const [geoipApis, setGeoipApis] = useState([]);
  const [selectedGeoipApi, setSelectedGeoipApi] = useState('ip-api.com');

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
  const [showChainModal, setShowChainModal] = useState(false);
  const [editingChain, setEditingChain] = useState(null);
  const [chainName, setChainName] = useState('');
  const [chainRows, setChainRows] = useState([[null, null]]);
  const [deleteChainConfirm, setDeleteChainConfirm] = useState({ open: false, chainId: null });
  const [showAddDropdown, setShowAddDropdown] = useState(false);


  // Fetch nodes from subscription files
  useEffect(() => {
    fetchAllSubNodes();
  }, [subscriptions]);

  // Fetch proxy chains
  useEffect(() => {
    fetchProxyChains();
    fetchAvailableChainNodes();
    fetchGeoipApis();
  }, []);

  const fetchGeoipApis = async () => {
    try {
      const res = await request.get(`${API_BASE}/geoip/online-config`);
      setGeoipApis(res.data.apis || []);
      setSelectedGeoipApi(res.data.preferred_api || 'ip-api.com');
    } catch (err) {
      console.error('Failed to fetch GeoIP APIs', err);
    }
  };

  const fetchProxyChains = async () => {
    try {
      const res = await request.get(`${API_BASE}/proxy-chains`);
      setProxyChains(res.data.chains || []);
    } catch (err) {
      console.error('Failed to fetch proxy chains', err);
    }
  };

  const fetchAvailableChainNodes = async () => {
    try {
      const res = await request.get(`${API_BASE}/proxy-chains/available-nodes`);
      setAvailableChainNodes(res.data.nodes || []);
    } catch (err) {
      console.error('Failed to fetch available chain nodes', err);
    }
  };

  const fetchAllSubNodes = async () => {
    if (!subscriptions?.length) {
      setSubNodes({});
      setLoadingNodes(false);
      return;
    }

    setLoadingNodes(true);
    const nodesMap = {};

    for (const sub of subscriptions) {
      try {
        const res = await request.get(`${API_BASE}/subscriptions/${sub.id}/nodes`);
        nodesMap[sub.id] = {
          name: sub.name,
          nodes: res.data.nodes || []
        };
      } catch (err) {
        console.error(`Failed to fetch nodes for ${sub.name}`, err);
        nodesMap[sub.id] = { name: sub.name, nodes: [] };
      }
    }

    setSubNodes(nodesMap);
    setLoadingNodes(false);
  };

  // Fetch GeoIP data for nodes
  useEffect(() => {
    if (loadingNodes) return;
    fetchGeoipData();
  }, [subNodes, customNodes, loadingNodes]);

  const fetchGeoipData = async () => {
    const servers = new Set();
    Object.values(subNodes).forEach(({ nodes }) => {
      nodes.forEach(node => {
        if (node.server) servers.add(node.server);
      });
    });
    customNodes?.forEach(node => {
      if (node.server) servers.add(node.server);
    });

    if (servers.size === 0) return;

    const data = {};
    const serverList = Array.from(servers).slice(0, 100);

    const batchSize = 10;
    for (let i = 0; i < serverList.length; i += batchSize) {
      const batch = serverList.slice(i, i + batchSize);
      const results = await Promise.all(
        batch.map(async (server) => {
          try {
            const res = await request.get(`${API_BASE}/geoip/lookup/${encodeURIComponent(server)}`);
            return { server, data: res.data.found ? res.data : null };
          } catch {
            return { server, data: null };
          }
        })
      );
      results.forEach(({ server, data: geoData }) => {
        if (geoData) data[server] = geoData;
      });
    }
    setGeoipData(data);
  };


  // Collect all nodes (filter out info nodes)
  const allNodes = useMemo(() => {
    const nodes = [];

    Object.entries(subNodes).forEach(([subId, { name: subName, nodes: subNodeList }]) => {
      subNodeList.forEach((node, idx) => {
        if (isInfoNode(node)) return;

        const nodeKey = `${subId}-${idx}`;
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
          idx,
          nodeKey,
          flag: flag,
          region: region,
          country: country,
          city: city,
          exit_ip: testResult?.exit_ip || node.exit_ip,
          latency: testResult?.latency ?? node.last_latency,
          speed: testResult?.speed ?? node.last_speed,
          testError: testResult?.error,
          detectedRegion: testResult?.region,
          final_name: node.display_name || node.name  // Use display_name from backend (transformed name)
        });
      });
    });

    customNodes?.forEach((node, idx) => {
      if (isInfoNode(node)) return;

      const nodeKey = `custom-${node.id || idx}`;
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
        idx,  // Add idx for API calls
        nodeKey,
        flag: flag,
        region: region,
        country: country,
        city: city,
        exit_ip: testResult?.exit_ip || node.exit_ip,
        latency: testResult?.latency ?? node.last_latency,
        speed: testResult?.speed ?? node.last_speed,
        testError: testResult?.error,
        detectedRegion: testResult?.region,
        final_name: node.display_name || node.name  // Use display_name from backend (transformed name)
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
      const chainPath = firstRow?.nodes?.map(n => n.node_name).join(' → ') || '';

      nodes.push({
        name: `🔗 ${chain.name}`,
        display_name: `🔗 ${chain.name}`,
        final_name: `🔗 ${chain.name}`,
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
        latency: testResult?.latency ?? chain.last_latency,
        speed: testResult?.speed ?? chain.last_speed,
        testError: testResult?.error,
        detectedRegion: testResult?.region,
        enabled: chain.enabled,
        rows: chain.rows,
      });
    });

    return nodes;
  }, [subNodes, customNodes, proxyChains, geoipData, nodeTestResults]);


  // Get unique types and sources
  const nodeTypes = useMemo(() => {
    const types = new Set(allNodes.map(n => n.type).filter(Boolean));
    return ['all', ...Array.from(types)];
  }, [allNodes]);

  const sources = useMemo(() => {
    // Include all subscriptions, even if they have no nodes
    const srcs = new Set();
    
    // Add all subscription names
    subscriptions?.forEach(sub => {
      srcs.add(sub.name);
    });
    
    // Add custom nodes source
    if (customNodes && customNodes.length > 0) {
      srcs.add('自建节点');
    }
    
    return ['all', ...Array.from(srcs)];
  }, [subscriptions, customNodes]);

  // Filter and sort
  const filteredNodes = useMemo(() => {
    let result = allNodes;

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
      result = result.filter(n => n.source === filterSource);
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
    result.sort((a, b) => {
      // Custom nodes first
      if (a.sourceType === 'custom' && b.sourceType !== 'custom') return -1;
      if (a.sourceType !== 'custom' && b.sourceType === 'custom') return 1;

      // Chain nodes second
      if (a.sourceType === 'chain' && b.sourceType !== 'chain' && b.sourceType !== 'custom') return -1;
      if (a.sourceType !== 'chain' && a.sourceType !== 'custom' && b.sourceType === 'chain') return 1;

      // If both are custom, keep original order (by idx)
      if (a.sourceType === 'custom' && b.sourceType === 'custom') {
        return a.idx - b.idx;
      }

      // If both are chain, keep original order (by idx)
      if (a.sourceType === 'chain' && b.sourceType === 'chain') {
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
    });

    return result;
  }, [allNodes, search, filterSource, filterType, filterLatencyStatus, sortBy, sortOrder]);

  // 分页节点
  const paginatedNodes = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    return filteredNodes.slice(startIndex, endIndex);
  }, [filteredNodes, currentPage, pageSize]);

  // 总页数
  const totalPages = Math.ceil(filteredNodes.length / pageSize);

  // 当过滤条件改变时，重置到第一页
  useEffect(() => {
    setCurrentPage(1);
  }, [search, filterSource, filterType, filterLatencyStatus, sortBy, sortOrder]);


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

  // Test single node
  const testNode = async (node, isRegionTest = false) => {
    setTestingNode(node.nodeKey);
    setTestingType(isRegionTest ? 'region' : 'latency');
    try {
      const payload = {
        test_latency: !isRegionTest,
        test_speed: false,
        test_region: isRegionTest,
        timeout: testTimeout
      };
      if (isRegionTest) {
        payload.geoip_api = selectedGeoipApi;
      }
      const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${node.idx}/test`, payload);
      setNodeTestResults(prev => {
        const newResult = { ...prev[node.nodeKey] };
        if (isRegionTest) {
          newResult.region = res.data.region;
          newResult.city = res.data.city;
          newResult.exit_ip = res.data.exit_ip;
        } else {
          newResult.latency = res.data.latency;
          newResult.error = false;
        }
        return { ...prev, [node.nodeKey]: newResult };
      });
    } catch {
      setNodeTestResults(prev => ({
        ...prev,
        [node.nodeKey]: { latency: null, error: true }
      }));
    } finally {
      setTestingNode(null);
    }
  };

  // Test single node speed
  const testNodeSpeed = async (node) => {
    setTestingNode(node.nodeKey);
    setTestingType('speed');
    try {
      const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${node.idx}/test`, {
        test_latency: false,
        test_speed: true,
        test_region: false,
        timeout: testTimeout
      });
      setNodeTestResults(prev => ({
        ...prev,
        [node.nodeKey]: { ...prev[node.nodeKey], speed: res.data.speed, peak_speed: res.data.peak_speed }
      }));
    } catch {
      // Speed test failed, keep existing data
    } finally {
      setTestingNode(null);
    }
  };

  // Batch test nodes - latency first with concurrency, then region
  const batchTestNodes = async () => {
    // Only test selected nodes, no longer fall back to all nodes
    if (selectedNodes.size === 0) {
      showToast?.('请先在左侧选择要检测的节点', 'warning');
      return;
    }

    const nodesToTest = filteredNodes.filter(n => selectedNodes.has(n.nodeKey));

    if (nodesToTest.length === 0) {
      showToast?.('没有可测试的节点', 'error');
      return;
    }

    if (!testLatency && !testRegion && !testSpeed) {
      showToast?.('请至少选择一项检测内容', 'error');
      return;
    }

    setShowBatchTestMenu(false);
    setBatchTesting(true);

    const totalSteps = (testLatency ? nodesToTest.length : 0) + (testRegion ? nodesToTest.length : 0) + (testSpeed ? nodesToTest.length : 0);
    let currentStep = 0;
    const firstPhase = testLatency ? '延迟' : (testRegion ? '地区' : '速度');
    setBatchTestProgress({ current: 0, total: totalSteps, phase: firstPhase });

    // Batch update results to reduce re-renders
    const batchResults = {};
    const saveData = {};  // 用于批量保存的数据结构

    // Phase 1: Test latency with concurrency
    if (testLatency) {
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${node.idx}/test`, {
              test_latency: true,
              test_speed: false,
              test_region: false,
              timeout: testTimeout,
              batch_mode: true  // 批量模式，不立即保存
            });
            
            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.idx]) saveData[node.sourceId][node.idx] = {};
            saveData[node.sourceId][node.idx].latency = res.data.latency;
            
            return { nodeKey: node.nodeKey, data: { latency: res.data.latency, error: false } };
          } catch {
            return { nodeKey: node.nodeKey, data: { latency: null, error: true } };
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
        setNodeTestResults(prev => ({ ...prev, ...batchResults }));
      }
    }

    // Phase 2: Test region with concurrency
    if (testRegion) {
      const baseStep = testLatency ? nodesToTest.length : 0;
      setBatchTestProgress(prev => ({ ...prev, phase: '地区' }));
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${node.idx}/test`, {
              test_latency: false,
              test_speed: false,
              test_region: true,
              timeout: testTimeout,
              geoip_api: selectedGeoipApi,
              batch_mode: true  // 批量模式
            });
            
            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.idx]) saveData[node.sourceId][node.idx] = {};
            saveData[node.sourceId][node.idx].exit_ip = res.data.exit_ip;
            saveData[node.sourceId][node.idx].region = res.data.region;
            saveData[node.sourceId][node.idx].city = res.data.city;
            
            return { nodeKey: node.nodeKey, data: { region: res.data.region, city: res.data.city, exit_ip: res.data.exit_ip } };
          } catch {
            return null;
          }
        }));
        
        // Batch update
        results.forEach(result => {
          if (result.status === 'fulfilled' && result.value) {
            batchResults[result.value.nodeKey] = { ...batchResults[result.value.nodeKey], ...result.value.data };
          }
        });
        
        currentStep = baseStep + Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '地区' });
        
        // Update state every batch
        setNodeTestResults(prev => ({ ...prev, ...batchResults }));
      }
    }

    // Phase 3: Test speed with concurrency (lower concurrency for speed test)
    if (testSpeed) {
      const baseStep = (testLatency ? nodesToTest.length : 0) + (testRegion ? nodesToTest.length : 0);
      setBatchTestProgress(prev => ({ ...prev, phase: '速度' }));
      // Use lower concurrency for speed test (max 2) to avoid bandwidth saturation
      const speedConcurrency = Math.min(testConcurrency, 2);
      for (let i = 0; i < nodesToTest.length; i += speedConcurrency) {
        const batch = nodesToTest.slice(i, i + speedConcurrency);
        const results = await Promise.allSettled(batch.map(async (node) => {
          try {
            const res = await request.post(`${API_BASE}/nodes/${node.sourceId}/${node.idx}/test`, {
              test_latency: false,
              test_speed: true,
              test_region: false,
              timeout: testTimeout,
              batch_mode: true  // 批量模式
            });
            
            // 收集保存数据
            if (!saveData[node.sourceId]) saveData[node.sourceId] = {};
            if (!saveData[node.sourceId][node.idx]) saveData[node.sourceId][node.idx] = {};
            saveData[node.sourceId][node.idx].speed = res.data.speed;
            
            return { nodeKey: node.nodeKey, data: { speed: res.data.speed, peak_speed: res.data.peak_speed } };
          } catch {
            return null;
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
        setNodeTestResults(prev => ({ ...prev, ...batchResults }));
      }
    }

    // 批量保存所有测试结果
    try {
      await request.post(`${API_BASE}/nodes/batch-save`, { results: saveData });
      showToast?.(`测试完成，共测试 ${nodesToTest.length} 个节点，结果已保存`);
    } catch (error) {
      showToast?.(`测试完成，但保存失败: ${error.message}`, 'error');
    }

    setBatchTesting(false);
  };


  // Selection handlers
  const toggleSelectAll = () => {
    if (selectedNodes.size === filteredNodes.length) {
      setSelectedNodes(new Set());
    } else {
      setSelectedNodes(new Set(filteredNodes.map(n => n.nodeKey)));
    }
  };

  const toggleSelectNode = (nodeKey) => {
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
    if (!newNodeLink.trim()) return;
    setLoading(true);
    try {
      const payload = { link: newNodeLink.trim() };
      if (newNodeName.trim()) {
        payload.name = newNodeName.trim();
      }
      await request.post(`${API_BASE}/custom-nodes`, payload);
      setNewNodeLink('');
      setNewNodeName('');
      setShowAddModal(false);
      onRefreshCustomNodes?.();
      showToast?.('节点添加成功');
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

  // Refresh all nodes
  const refreshAllNodes = async () => {
    setLoadingNodes(true);
    setNodeTestResults({});
    setSelectedNodes(new Set());
    await fetchAllSubNodes();
    await fetchProxyChains();
    await fetchAvailableChainNodes();
    onRefreshCustomNodes?.();
    showToast?.('节点列表已刷新');
  };

  // Clear filters
  const clearFilters = () => {
    setSearch('');
    setFilterSource('all');
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
      const rows = chain.rows.map(row =>
        row.nodes.map(node => ({
          sub_id: node.sub_id,
          node_index: node.node_index,
          node_name: node.node_name
        }))
      );
      setChainRows(rows);
      setEditingChain(chain);
    } else {
      setChainName('');
      setChainRows([[null, null]]);
      setEditingChain(null);
    }
    setShowChainModal(true);
  };

  const closeChainModal = () => {
    setShowChainModal(false);
    setEditingChain(null);
    setChainName('');
    setChainRows([[null, null]]);
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

  const updateChainNode = (rowIndex, colIndex, nodeKey) => {
    if (!nodeKey) {
      setChainRows(prev => {
        const newRows = [...prev];
        newRows[rowIndex][colIndex] = null;
        return newRows;
      });
      return;
    }

    const [subId, nodeIndex] = nodeKey.split('|');
    const node = availableChainNodes.find(n => n.sub_id === subId && n.node_index === parseInt(nodeIndex));

    setChainRows(prev => {
      const newRows = [...prev];
      newRows[rowIndex][colIndex] = node ? {
        sub_id: node.sub_id,
        node_index: node.node_index,
        node_name: node.node_name
      } : null;
      return newRows;
    });
  };

  const getChainNodeKey = (node) => {
    if (!node) return '';
    return `${node.sub_id}|${node.node_index}`;
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
    }

    const payload = {
      name: chainName.trim(),
      rows: chainRows.map(row => ({
        nodes: row.map(node => ({
          sub_id: node.sub_id,
          node_index: node.node_index,
          node_name: node.node_name
        }))
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
    // Get the final name with fallback
    const finalName = node.final_name || node.display_name || node.name;
    
    // After initial load, use localPortMappings as single source of truth
    // This ensures deletions from management panel are immediately reflected
    const currentPort = portMappingsLoaded
      ? localPortMappings[finalName]
      : (localPortMappings[finalName] ?? node.mapped_port);
    setPortMappingNode({ ...node, mapped_port: currentPort });
    setPortMappingValue(currentPort ? String(currentPort) : '');
  };

  const fetchAllPortMappings = async () => {
    try {
      const res = await request.get(`${API_BASE}/port-mappings`);
      setAllPortMappings(res.data.mappings || []);
      // Build local cache
      const cache = {};
      (res.data.mappings || []).forEach(m => {
        cache[m.final_name] = m.port;
      });
      setLocalPortMappings(cache);
      setPortMappingsLoaded(true);  // Mark as loaded
    } catch (err) {
      console.error('Failed to fetch port mappings', err);
      setPortMappingsLoaded(true);  // Even on error, mark as loaded to prevent fallback issues
    }
  };

  // Fetch port mappings on mount
  useEffect(() => {
    fetchAllPortMappings();
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
    <div className="h-[calc(100vh-80px)] flex flex-col space-y-4 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4 flex-shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-white">节点管理</h1>
          <p className="text-gray-400 text-sm mt-1">查看和管理所有节点</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => { fetchAllPortMappings(); setShowPortMappingList(true); }}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
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
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
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
                  className="w-full px-4 py-2.5 text-left text-white hover:bg-gray-700 rounded-b-lg transition-colors flex items-center gap-2"
                >
                  <Link2 size={16} />
                  链式代理
                </button>
              </div>
            )}
          </div>
          <button
            onClick={() => setShowTestSettingsModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
          >
            <Settings size={18} />
            检测设置
          </button>
          <div className="relative batch-test-menu">
            <button
              onClick={() => setShowBatchTestMenu(!showBatchTestMenu)}
              disabled={batchTesting}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              <Play size={18} className={batchTesting ? 'animate-pulse' : ''} />
              {batchTesting ? `${batchTestProgress.phase}检测中 ${batchTestProgress.current}/${batchTestProgress.total}` : (selectedNodes.size > 0 ? `批量检测 (${selectedNodes.size})` : '批量检测')}
            </button>
            {showBatchTestMenu && !batchTesting && (
              <div className="absolute right-0 top-full mt-2 w-56 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-20">
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
                    <span className="text-white text-sm">地区检测</span>
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
                      disabled={!testLatency && !testRegion && !testSpeed}
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
            onClick={refreshAllNodes}
            disabled={loadingNodes}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={18} className={loadingNodes ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>
      <div className="flex flex-wrap gap-3 items-center flex-shrink-0">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="搜索节点名称/服务器/地区..."
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <select
          value={filterSource}
          onChange={(e) => setFilterSource(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          {sources.map(s => (
            <option key={s} value={s}>{s === 'all' ? '全部来源' : s}</option>
          ))}
        </select>

        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          {nodeTypes.map(t => (
            <option key={t} value={t}>{t === 'all' ? '全部协议' : t.toUpperCase()}</option>
          ))}
        </select>

        <select
          value={filterLatencyStatus}
          onChange={(e) => setFilterLatencyStatus(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">延迟状态</option>
          <option value="untested">未测试</option>
          <option value="success">测试成功</option>
          <option value="timeout">超时</option>
          <option value="failed">测试失败</option>
        </select>
      </div>


      {/* Filters Row 2 - Sort */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
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
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="asc">升序 ↑</option>
          <option value="desc">降序 ↓</option>
        </select>

        <button
          onClick={clearFilters}
          className="px-3 py-2 text-sm text-gray-400 hover:text-white transition-colors"
        >
          重置
        </button>
      </div>

      {/* Stats */}
      <div className="flex flex-wrap gap-4 text-sm flex-shrink-0">
        <span className="text-gray-400">
          共 <span className="text-white font-medium">{filteredNodes.length}</span> 个节点
          {(search || filterSource !== 'all' || filterType !== 'all' || filterLatencyStatus !== 'all') &&
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
              <table className="w-full">
              <thead className="sticky top-0 bg-gray-800 z-10">
                <tr className="border-b border-gray-700 text-left">
                  <th className="px-4 py-3 text-sm font-medium text-gray-400 whitespace-nowrap">
                    <button
                      onClick={toggleSelectAll}
                      className="flex items-center gap-1 hover:text-white transition-colors"
                    >
                      {selectedNodes.size === filteredNodes.length && filteredNodes.length > 0 ? (
                        <CheckSquare size={16} className="text-blue-400" />
                      ) : (
                        <Square size={16} />
                      )}
                      <span>全选</span>
                    </button>
                  </th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">节点名称</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">来源</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">协议</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">地区</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">IP</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">延迟</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">速度</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {paginatedNodes.length > 0 ? (
                  paginatedNodes.map((node, idx) => {
                    const isTesting = testingNode === node.nodeKey;
                    const isSelected = selectedNodes.has(node.nodeKey);
                    const testResult = nodeTestResults[node.nodeKey];
                    const displayedLatency = testResult?.latency !== undefined ? testResult.latency : node.latency;
                    const displayedError = testResult?.error !== undefined ? testResult.error : node.testError;
                    const latencyBadge = getLatencyBadge(displayedLatency, displayedError);
                    // Use local cache for port mapping (updates instantly without page refresh)
                    const currentMappedPort = localPortMappings[node.final_name] ?? node.mapped_port;

                    return (
                      <tr key={node.nodeKey} className={`hover:bg-gray-800/50 ${isSelected ? 'bg-blue-500/5' : ''}`}>
                        <td className="px-4 py-3">
                          <button
                            onClick={() => toggleSelectNode(node.nodeKey)}
                            className="text-gray-400 hover:text-white transition-colors"
                          >
                            {isSelected ? (
                              <CheckSquare size={18} className="text-blue-400" />
                            ) : (
                              <Square size={18} />
                            )}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {node.sourceType === 'custom' && (
                              <span className="inline-flex items-center justify-center w-5 h-5 rounded bg-orange-500/20 text-orange-400 text-xs font-bold">
                                {node.idx + 1}
                              </span>
                            )}
                            {node.sourceType === 'chain' && (
                              <span className="inline-flex items-center justify-center w-5 h-5 rounded bg-blue-500/20 text-blue-400 text-xs font-bold">
                                {node.idx + 1}
                              </span>
                            )}
                            <span className={`text-white truncate max-w-[200px] ${node.sourceType === 'chain' && !node.enabled ? 'opacity-50' : ''}`} title={node.display_name || node.name || '未命名'}>
                              {node.display_name || node.name || '未命名'}
                            </span>
                            {node.sourceType === 'chain' && (
                              <button
                                onClick={() => toggleChain(node.chainId)}
                                className="text-gray-400 hover:text-white transition-colors"
                                title={node.enabled ? '点击禁用' : '点击启用'}
                              >
                                {node.enabled ? (
                                  <ToggleRight size={18} className="text-green-400" />
                                ) : (
                                  <ToggleLeft size={18} />
                                )}
                              </button>
                            )}
                            {currentMappedPort && (
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-green-500/20 text-green-400 text-xs font-mono">
                                :{currentMappedPort}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-sm whitespace-nowrap ${node.sourceType === 'custom' ? 'text-orange-400' : node.sourceType === 'chain' ? 'text-blue-400' : 'text-gray-400'}`}>
                            {node.source}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getTypeColor(node.type)}`}>
                            {node.type?.toUpperCase() || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-400 text-sm">
                          <span className="truncate max-w-[150px] inline-block" title={node.city ? `${node.region} ${node.city}` : node.region}>
                            {node.region || '-'}{node.city ? ` ${node.city}` : ''}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-400 text-sm">
                          <span className="truncate max-w-[120px] inline-block font-mono text-xs" title={testResult?.exit_ip || node.exit_ip || ''}>
                            {testResult?.exit_ip || node.exit_ip || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {node.latency !== undefined && node.latency !== null && node.latency > 0 && !node.testError ? (
                              <span className={`font-mono text-sm ${getLatencyColor(node.latency)}`}>
                                {node.latency}ms
                              </span>
                            ) : (
                              <span className={`px-2 py-0.5 rounded text-xs ${latencyBadge.color}`}>
                                {latencyBadge.text}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {node.speed !== undefined && node.speed > 0 ? (
                              <span className="font-mono text-sm text-green-400">
                                {node.speed.toFixed(1)} MB/s
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-xs bg-gray-500/20 text-gray-400">
                                未测
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => node.sourceType === 'chain' ? openChainModal(proxyChains.find(c => c.id === node.chainId)) : setEditingNode(node)}
                              className="p-1.5 text-gray-400 hover:text-purple-400 hover:bg-purple-500/10 rounded transition-colors"
                              title="查看/编辑"
                            >
                              <Edit2 size={16} />
                            </button>
                            {/* Region test button */}
                            <button
                              onClick={() => testNode(node, true)}
                              disabled={isTesting || batchTesting}
                              className="p-1.5 text-gray-400 hover:text-cyan-400 hover:bg-cyan-500/10 rounded transition-colors disabled:opacity-50"
                              title="检测地区"
                            >
                              {isTesting && testingType === 'region' ? (
                                <RefreshCw size={16} className="animate-spin" />
                              ) : (
                                <Globe size={16} />
                              )}
                            </button>
                            {/* Latency test button */}
                            <button
                              onClick={() => testNode(node)}
                              disabled={isTesting || batchTesting}
                              className="p-1.5 text-gray-400 hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors disabled:opacity-50"
                              title="测试延迟"
                            >
                              {isTesting && testingType === 'latency' && node.nodeKey === testingNode ? (
                                <RefreshCw size={16} className="animate-spin" />
                              ) : (
                                <Clock size={16} />
                              )}
                            </button>
                            {/* Speed test button */}
                            <button
                              onClick={() => testNodeSpeed(node)}
                              disabled={isTesting || batchTesting}
                              className="p-1.5 text-gray-400 hover:text-green-400 hover:bg-green-500/10 rounded transition-colors disabled:opacity-50"
                              title="测试速度"
                            >
                              {isTesting && testingType === 'speed' ? (
                                <RefreshCw size={16} className="animate-spin" />
                              ) : (
                                <Play size={16} />
                              )}
                            </button>
                            <button
                              onClick={() => openPortMapping(node)}
                              className={`p-1.5 rounded transition-colors ${currentMappedPort
                                ? 'text-green-400 hover:text-green-300 hover:bg-green-500/10'
                                : 'text-gray-400 hover:text-green-400 hover:bg-green-500/10'
                                }`}
                              title={currentMappedPort ? `已绑定端口 ${currentMappedPort}` : '绑定端口'}
                            >
                              <Link2 size={16} />
                            </button>
                            {node.sourceType === 'custom' && (
                              <>
                                <button
                                  onClick={() => moveCustomNode(node.id, 'up')}
                                  className="p-1.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="上移"
                                >
                                  <ChevronUp size={16} />
                                </button>
                                <button
                                  onClick={() => moveCustomNode(node.id, 'down')}
                                  className="p-1.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="下移"
                                >
                                  <ChevronDown size={16} />
                                </button>
                                <button
                                  onClick={() => confirmDeleteNode(node.id)}
                                  className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                                  title="删除"
                                >
                                  <Trash2 size={16} />
                                </button>
                              </>
                            )}
                            {node.sourceType === 'chain' && (
                              <>
                                <button
                                  onClick={() => moveChain(node.chainId, 'up')}
                                  className="p-1.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="上移"
                                >
                                  <ChevronUp size={16} />
                                </button>
                                <button
                                  onClick={() => moveChain(node.chainId, 'down')}
                                  className="p-1.5 text-gray-400 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="下移"
                                >
                                  <ChevronDown size={16} />
                                </button>
                                <button
                                  onClick={() => setDeleteChainConfirm({ open: true, chainId: node.chainId })}
                                  className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                                  title="删除"
                                >
                                  <Trash2 size={16} />
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
                    <td colSpan={8} className="px-4 py-12 text-center text-gray-500">
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
                  placeholder="vless://... or vmess://... or trojan://..."
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 h-24 resize-none"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">节点名称（可选）</label>
                <input
                  type="text"
                  value={newNodeName}
                  onChange={(e) => setNewNodeName(e.target.value)}
                  placeholder="留空则使用链接中的名称"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <p className="text-xs text-gray-500">
                支持的协议：VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC 等
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
                <label className="block text-sm text-gray-400 mb-2">地区检测 API</label>
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
                <p className="text-xs text-gray-500 mt-1">用于检测节点出口 IP 地区的在线 API</p>
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
                  placeholder="如: 52001"
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
                        
                        {row.map((node, colIndex) => (
                          <React.Fragment key={colIndex}>
                            <div className="flex justify-center">
                              <ArrowRight size={16} className="text-gray-600 rotate-90" />
                            </div>
                            <div className="relative">
                              <select
                                value={getChainNodeKey(node)}
                                onChange={(e) => updateChainNode(rowIndex, colIndex, e.target.value)}
                                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500 appearance-none"
                              >
                                <option value="">选择节点</option>
                                {/* Use flat list like node management page */}
                                {availableChainNodes.map(n => (
                                  <option key={`${n.sub_id}|${n.node_index}`} value={`${n.sub_id}|${n.node_index}`}>
                                    {n.node_name} ({n.node_type})
                                  </option>
                                ))}
                              </select>
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
                        ))}

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
                        预览: 我 → {row.map(n => n?.node_name || '?').join(' → ')} → 服务
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
    </div>
  );
}