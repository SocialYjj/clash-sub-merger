import { useState, useMemo, useEffect, useCallback, useRef } from 'react';
import { Link, useLocation } from 'react-router';
import { Server, Search, Plus, Trash2, RefreshCw, Clock, CheckSquare, Square, Settings, Play, Edit2, ChevronUp, ChevronDown, Globe, Link2, ToggleLeft, ToggleRight, ShieldCheck, Bot, ChevronDown as ChevronDownIcon } from 'lucide-react';
import request, { isRequestCanceled } from '../utils/request';
import ConfirmModal from '../components/ConfirmModal';
import { SkeletonTableRows } from '../components/Skeleton';
import NodeEditModal from '../components/NodeEditModal';
import NodePoolModal from '../components/NodePoolModal';
import { COUNTRY_CHINESE_NAMES } from './countryData';

import {
  LEADING_FLAG_ICON_RE,
  stripLeadingFlagIcon,
  isInfoNode,
  getNodeInvalidReasonLabel,
  getLatencyColor,
  getLatencyBadge,
  getIpSourceLabel,
  getNetworkTypeLabel,
  getNodeIpSource,
  getNodeIpProperty,
  isNodeIpSourceUntested,
  isNodeIpPropertyUntested,
  getNodeCountryFilterValue,
  getNodeCountryFilterLabel,
  formatRadarRatio,
  formatIppureScore,
  mergeIpProfiles,
  getMetadataStatusLabel,
  getMetadataStatusClass,
} from './nodes/nodeHelpers.js';
import AddNodeModal from './nodes/AddNodeModal';
import TestSettingsModal from './nodes/TestSettingsModal';
import { PortMappingModal, PortMappingListModal } from './nodes/PortMappingModals';
import useNodeTesting from './nodes/useNodeTesting';
import ProxyChainSection from './nodes/ProxyChainSection';

const API_BASE = '/api';

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
  const [selectedNodes, setSelectedNodes] = useState(new Set());
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
  const [chainModalRequest, setChainModalRequest] = useState(null);
  const chainModalRequestSeq = useRef(0);
  const [deleteChainConfirm, setDeleteChainConfirm] = useState({ open: false, chainId: null });
  const [showAddDropdown, setShowAddDropdown] = useState(false);
  const subNodesRequestSeq = useRef(0);
  const geoipRequestSeq = useRef(0);
  const proxyChainsRequestSeq = useRef(0);
  const chainNodesRequestSeq = useRef(0);
  const nodePoolsRequestSeq = useRef(0);
  const vpngateRequestSeq = useRef(0);
  // Single-node and batch testing state and handlers (useNodeTesting)
  const {
    nodeTestResults,
    setNodeTestResults,
    testingByNode,
    testNode,
    testNodeSpeed,
    testNodeIppure,
    testNodeRadar,
    batchTestNodes,
    batchTesting,
    batchTestProgress,
  } = useNodeTesting({ showToast, testTimeout, selectedGeoipApi });


  // Fetch nodes from subscription files
  useEffect(() => {
    const controller = new AbortController();
    fetchAllSubNodes(controller.signal);
    return () => {
      controller.abort();
      subNodesRequestSeq.current += 1;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- subscriptions 变化时拉取一次；fetchAllSubNodes 闭包仅引用稳定 setter 与请求序号 ref
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
  // eslint-disable-next-line react-hooks/exhaustive-deps -- 节点源就绪后做一次 GeoIP 补全；fetchGeoipData 会 setState 但其结果不在触发集内
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
  }, [allNodes, search, filterSource, filterCountry, filterIpSource, filterIpProperty, filterType, filterLatencyStatus, compareNodes]);

  // Latest filtered list snapshot for click-time handlers (batch testing).
  // batchTestNodes lives in useNodeTesting and must not depend on this memo
  // (nodeTestResults -> allNodes -> filteredNodes is a render-order cycle),
  // so the page hands it the current list through a ref at call time.
  const filteredNodesRef = useRef(filteredNodes);
  filteredNodesRef.current = filteredNodes;

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
    return colors[type?.toLowerCase()] || 'bg-ink-3/20 text-ink-2';
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


  // Batch test nodes - latency first with concurrency, then region.
  // The implementation lives in useNodeTesting; it must not close over the
  // filteredNodes memo (nodeTestResults -> allNodes -> filteredNodes is a
  // render-order cycle), so the current list is read through a ref at
  // click time and the remaining page state is passed in the options object.
  const handleBatchTestNodes = () => {
    batchTestNodes(filteredNodesRef.current, {
      selectedNodes,
      testConcurrency,
      testLatency,
      testRegion,
      testIppure,
      testRadar,
      testSpeed,
      setShowBatchTestMenu,
    });
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
    setChainModalRequest({ chain: chain || null, seq: ++chainModalRequestSeq.current });
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
          <h1 className="text-xl font-bold text-ink">节点管理</h1>
          <p className="text-ink-2 text-sm mt-0.5">查看和管理所有节点</p>
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
            className="flex items-center gap-2 px-3 py-1.5 bg-surface-3 hover:bg-surface-4 text-ink rounded-lg transition-colors"
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
              className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-ink rounded-lg transition-colors"
            >
              <Plus size={18} />
              添加节点
              <ChevronDownIcon size={16} />
            </button>
            {showAddDropdown && (
              <div className="absolute right-0 top-full mt-2 w-40 bg-surface-2 border border-line rounded-lg shadow-xl z-20">
                <button
                  onClick={() => { setShowAddDropdown(false); setShowAddModal(true); }}
                  className="w-full px-4 py-2.5 text-left text-ink hover:bg-surface-3 rounded-t-lg transition-colors flex items-center gap-2"
                >
                  <Server size={16} />
                  自建节点
                </button>
                <button
                  onClick={() => { setShowAddDropdown(false); openChainModal(); }}
                  className="w-full px-4 py-2.5 text-left text-ink hover:bg-surface-3 transition-colors flex items-center gap-2"
                >
                  <Link2 size={16} />
                  链式代理
                </button>
                <button
                  onClick={() => { setShowAddDropdown(false); openNodePoolModal(); }}
                  className="w-full px-4 py-2.5 text-left text-ink hover:bg-surface-3 rounded-b-lg transition-colors flex items-center gap-2"
                >
                  <Settings size={16} />
                  节点池
                </button>
              </div>
            )}
          </div>
          <button
            onClick={() => setShowTestSettingsModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-surface-3 hover:bg-surface-4 text-ink rounded-lg transition-colors"
          >
            <Settings size={18} />
            检测设置
          </button>
          <div className="relative batch-test-menu">
            <button
              onClick={() => setShowBatchTestMenu(!showBatchTestMenu)}
              disabled={batchTesting}
              className="flex items-center gap-2 px-3 py-1.5 bg-green-600 hover:bg-green-500 text-ink rounded-lg transition-colors disabled:opacity-50"
            >
              <Play size={18} className={batchTesting ? 'animate-pulse' : ''} />
              {batchTesting ? `${batchTestProgress.phase}检测中 ${batchTestProgress.current}/${batchTestProgress.total}` : (selectedNodes.size > 0 ? `批量检测 (${selectedNodes.size})` : '批量检测')}
            </button>
            {showBatchTestMenu && !batchTesting && (
              <div className="absolute right-0 top-full mt-2 w-72 bg-surface-2 border border-line rounded-lg shadow-xl z-20">
                <div className="p-3 space-y-3">
                  <div className="text-sm text-ink-2 font-medium">检测内容</div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testLatency}
                      onChange={(e) => setTestLatency(e.target.checked)}
                      className="w-4 h-4 rounded border-line-strong bg-surface-3 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-ink text-sm">延迟检测</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testRegion}
                      onChange={(e) => setTestRegion(e.target.checked)}
                      className="w-4 h-4 rounded border-line-strong bg-surface-3 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-ink text-sm">IP/地区检测</span>
                    <span className="text-xs text-ink-3">（出口 IP、地区）</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testIppure}
                      onChange={(e) => setTestIppure(e.target.checked)}
                      className="w-4 h-4 rounded border-line-strong bg-surface-3 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-ink text-sm">IP 属性检测</span>
                    <span className="text-xs text-ink-3">（来源、属性、IPPure）</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testRadar}
                      onChange={(e) => setTestRadar(e.target.checked)}
                      className="w-4 h-4 rounded border-line-strong bg-surface-3 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-ink text-sm">人机流量比检测</span>
                    <span className="text-xs text-ink-3">（Cloudflare Radar）</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={testSpeed}
                      onChange={(e) => setTestSpeed(e.target.checked)}
                      className="w-4 h-4 rounded border-line-strong bg-surface-3 text-blue-500 focus:ring-blue-500"
                    />
                    <span className="text-ink text-sm">速度检测</span>
                    <span className="text-xs text-ink-3">(较慢)</span>
                  </label>
                  <div className="pt-2 border-t border-line">
                    <button
                      onClick={handleBatchTestNodes}
                      disabled={!testLatency && !testRegion && !testIppure && !testRadar && !testSpeed}
                      className="w-full px-3 py-2 bg-green-600 hover:bg-green-500 text-ink text-sm rounded-lg transition-colors disabled:opacity-50"
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
            className="flex items-center gap-2 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-ink rounded-lg transition-colors disabled:opacity-50"
          >
            <Trash2 size={18} />
            {selectedCustomCount > 0 ? `批量删除 (${selectedCustomCount})` : '批量删除'}
          </button>
          <button
            onClick={refreshAllNodes}
            disabled={loadingNodes}
            className="flex items-center gap-2 px-3 py-1.5 bg-surface-3 hover:bg-surface-4 text-ink rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={18} className={loadingNodes ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 items-center flex-shrink-0">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-3" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="搜索节点名称/服务器/地区..."
            className="w-full pl-9 pr-3 py-1.5 bg-surface-2 border border-line rounded-lg text-ink placeholder-ink-3 focus:outline-none focus:border-blue-500"
          />
        </div>

        <select
          value={filterSource}
          onChange={(e) => setFilterSource(e.target.value)}
          className="px-2.5 py-1.5 bg-surface-2 border border-line rounded-lg text-ink focus:outline-none focus:border-blue-500"
        >
          {sourceOptions.map(source => (
            <option key={source.id} value={source.id}>{source.name}</option>
          ))}
        </select>

        <select
          value={filterIpSource}
          onChange={(e) => setFilterIpSource(e.target.value)}
          className="px-2.5 py-1.5 bg-surface-2 border border-line rounded-lg text-ink focus:outline-none focus:border-blue-500"
        >
          {ipSourceOptions.map(option => (
            <option key={option.id || 'all-ip-source'} value={option.id}>{option.name}</option>
          ))}
        </select>

        <select
          value={filterIpProperty}
          onChange={(e) => setFilterIpProperty(e.target.value)}
          className="px-2.5 py-1.5 bg-surface-2 border border-line rounded-lg text-ink focus:outline-none focus:border-blue-500"
        >
          {ipPropertyOptions.map(option => (
            <option key={option.id || 'all-ip-property'} value={option.id}>{option.name}</option>
          ))}
        </select>

        <select
          value={filterCountry}
          onChange={(e) => setFilterCountry(e.target.value)}
          className="px-2.5 py-1.5 bg-surface-2 border border-line rounded-lg text-ink focus:outline-none focus:border-blue-500"
        >
          {countryOptions.map(option => (
            <option key={option.id || 'all-country'} value={option.id}>{option.name}</option>
          ))}
        </select>

        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="px-2.5 py-1.5 bg-surface-2 border border-line rounded-lg text-ink focus:outline-none focus:border-blue-500"
        >
          {nodeTypes.map(t => (
            <option key={t} value={t}>{t === 'all' ? '全部协议' : t.toUpperCase()}</option>
          ))}
        </select>

        <select
          value={filterLatencyStatus}
          onChange={(e) => setFilterLatencyStatus(e.target.value)}
          className="px-2.5 py-1.5 bg-surface-2 border border-line rounded-lg text-ink focus:outline-none focus:border-blue-500"
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
          className="px-2.5 py-1.5 bg-surface-2 border border-line rounded-lg text-ink focus:outline-none focus:border-blue-500"
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
          className="px-2.5 py-1.5 bg-surface-2 border border-line rounded-lg text-ink focus:outline-none focus:border-blue-500"
        >
          <option value="asc">升序 ↑</option>
          <option value="desc">降序 ↓</option>
        </select>

        <button
          onClick={clearFilters}
          className="px-2.5 py-1.5 text-sm text-ink-2 hover:text-ink transition-colors"
        >
          重置
        </button>
      </div>

      {/* Stats Badges Bar */}
      <div className="flex flex-wrap items-center gap-2 text-xs flex-shrink-0">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 bg-surface-2/80 border border-line/60 rounded-xl text-ink-2">
          <span>节点总数:</span>
          <span className="font-bold text-ink tabular-nums">{filteredNodes.length}</span>
          {(search || filterSource !== 'all' || filterCountry || filterIpSource || filterIpProperty || filterType !== 'all' || filterLatencyStatus !== 'all') && (
            <span className="text-ink-3">/ {allNodes.length}</span>
          )}
        </div>

        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400">
          <span>已测试</span>
          <span className="font-bold tabular-nums">{testedCount}</span>
        </div>

        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-400">
          <span>成功</span>
          <span className="font-bold tabular-nums">{successCount}</span>
        </div>

        {failedCount > 0 && (
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400">
            <span>失败</span>
            <span className="font-bold tabular-nums">{failedCount}</span>
          </div>
        )}

        {selectedNodes.size > 0 && (
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-purple-500/15 border border-purple-500/30 rounded-xl text-purple-300 font-medium">
            <span>已选择</span>
            <span className="font-bold tabular-nums">{selectedNodes.size}</span>
          </div>
        )}
      </div>

      {/* Nodes Table */}
      <div className="bg-surface-2/50 border border-line rounded-xl overflow-hidden flex-1 flex flex-col min-h-0">
        {loadingNodes ? (
          <div className="animate-pulse" aria-busy="true" aria-label="加载中">
            <SkeletonTableRows rows={10} />
          </div>
        ) : (
          <>
            <div className="overflow-x-auto overflow-y-auto flex-1">
              <table className="w-full min-w-[1150px] table-fixed text-sm">
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
              <thead className="sticky top-0 bg-surface-2 z-10">
                <tr className="border-b border-line text-left">
                  <th className="px-1 py-1.5 text-xs font-medium text-ink-2 whitespace-nowrap">
                    <button
                      onClick={toggleSelectAll}
                      className="flex items-center hover:text-ink transition-colors"
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
                  <th className="px-2 py-1.5 text-xs font-medium text-ink-2 whitespace-nowrap">节点名称</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-ink-2 whitespace-nowrap">来源</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-ink-2 whitespace-nowrap">协议</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-cyan-300 whitespace-nowrap">地区</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-cyan-300 whitespace-nowrap">IP</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-purple-300 whitespace-nowrap">IP来源</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-purple-300 whitespace-nowrap">IP属性</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-purple-300 whitespace-nowrap">IPPure系数</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-orange-300 whitespace-nowrap">人机流量比</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-ink-2 whitespace-nowrap">延迟</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-ink-2 whitespace-nowrap">速度</th>
                  <th className="px-2 py-1.5 text-xs font-medium text-ink-2 whitespace-nowrap">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {paginatedNodes.length > 0 ? (
                  paginatedNodes.map((node, _idx) => {
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
                      <tr key={node.nodeKey} className={`hover:bg-surface-2/50 ${isSelected ? 'bg-blue-500/5' : ''} ${isDisabled ? 'opacity-60' : ''}`}>
                        <td className="px-1 py-1.5">
                          <button
                            onClick={() => toggleSelectNode(node.nodeKey)}
                            disabled={isNodePool}
                            className={`text-ink-2 transition-colors ${isNodePool ? 'opacity-30 cursor-not-allowed' : 'hover:text-ink'}`}
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
                            <span className={`min-w-0 max-w-[145px] truncate text-ink ${isDisabled ? 'line-through decoration-ink-3' : ''}`} title={rawDisplayName}>
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
                                className="shrink-0 p-0 leading-none text-ink-2 hover:text-ink transition-colors"
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
                                className="shrink-0 p-0 leading-none text-ink-2 hover:text-ink transition-colors"
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
                                className="shrink-0 p-0 leading-none text-ink-2 hover:text-ink transition-colors"
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
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-surface-4/30 text-ink-2 text-xs">
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
                          <span className={`text-sm whitespace-nowrap ${node.sourceType === 'custom' ? 'text-orange-400' : node.sourceType === 'chain' ? 'text-blue-400' : node.sourceType === 'node_pool' ? 'text-emerald-400' : node.sourceType === 'vpngate' ? 'text-cyan-400' : 'text-ink-2'}`}>
                            {node.source}
                          </span>
                        </td>
                        <td className="px-2 py-1.5">
                          <span className={`px-1.5 py-0.5 rounded text-xs font-medium whitespace-nowrap ${getTypeColor(node.type)}`} title={node.type?.toUpperCase() || '-'}>
                            {getProtocolDisplayLabel(node.type)}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-ink-2 text-sm">
                          <span className="block w-full max-w-[180px] truncate" title={node.city ? `${node.region} ${node.city}` : node.region}>
                            {isNodePool ? node.region : `${node.region || getMetadataStatusLabel(ipStatus)}${node.city ? ` ${node.city}` : ''}`}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-ink-2 text-sm">
                          <span
                            className={`truncate inline-block max-w-[130px] font-mono text-xs ${displayedExitIp ? '' : getMetadataStatusClass(ipStatus)}`}
                            title={displayedExitIp || ''}
                          >
                            {isNodePool ? '-' : (displayedExitIp || getMetadataStatusLabel(ipStatus))}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-xs whitespace-nowrap">
                          <span className={isNodePool ? 'text-ink-3' : hasIpSource ? 'text-cyan-300' : getMetadataStatusClass(ippureStatus)}>
                            {isNodePool ? '-' : (hasIpSource ? getIpSourceLabel(ipProfile.ip_source) : getMetadataStatusLabel(ippureStatus))}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-xs whitespace-nowrap">
                          <span className={isNodePool ? 'text-ink-3' : hasNetworkType ? 'text-purple-300' : getMetadataStatusClass(ippureStatus)}>
                            {isNodePool ? '-' : (hasNetworkType ? getNetworkTypeLabel(ipProfile.network_type) : getMetadataStatusLabel(ippureStatus))}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-xs whitespace-nowrap">
                          <span className={isNodePool ? 'text-ink-3' : hasFraudScore ? 'text-amber-300 font-mono' : getMetadataStatusClass(ippureStatus)}>
                            {isNodePool ? '-' : (hasFraudScore ? formatIppureScore(ipProfile.fraud_score) : getMetadataStatusLabel(ippureStatus))}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-xs">
                          {isNodePool ? (
                            <span className="text-ink-3">-</span>
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
                              <span className="text-ink-3">-</span>
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
	                              <span className="text-ink-3">-</span>
	                            ) : displayedSpeedError ? (
	                              <span className="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-400">
	                                失败
	                              </span>
	                            ) : node.speed !== undefined && node.speed > 0 ? (
                              <span className="font-mono text-sm text-green-400 whitespace-nowrap">
	                                {node.speed.toFixed(1)} MB/s
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-xs bg-ink-3/20 text-ink-2">
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
                                className="p-0.5 text-ink-2 hover:text-purple-400 hover:bg-purple-500/10 rounded transition-colors"
                                title="查看/编辑"
                              >
                                <Edit2 size={14} />
                              </button>
                            )}
                            {/* IP/region test button */}
                            <button
                              onClick={() => testNode(node, true)}
                              disabled={isNodePool || isTesting || batchTesting || node.sourceType === 'chain' || isIncompatible}
                              className="p-0.5 text-ink-2 hover:text-cyan-400 hover:bg-cyan-500/10 rounded transition-colors disabled:opacity-50"
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
                              className="p-0.5 text-ink-2 hover:text-purple-400 hover:bg-purple-500/10 rounded transition-colors disabled:opacity-50"
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
                              className="p-0.5 text-ink-2 hover:text-orange-400 hover:bg-orange-500/10 rounded transition-colors disabled:opacity-50"
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
                              className="p-0.5 text-ink-2 hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors disabled:opacity-50"
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
                              className="p-0.5 text-ink-2 hover:text-green-400 hover:bg-green-500/10 rounded transition-colors disabled:opacity-50"
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
                                  : 'text-ink-2 hover:text-green-400 hover:bg-green-500/10'
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
                                  className="p-0.5 text-ink-2 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="上移"
                                >
                                  <ChevronUp size={14} />
                                </button>
                                <button
                                  onClick={() => moveCustomNode(node.id, 'down')}
                                  className="p-0.5 text-ink-2 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="下移"
                                >
                                  <ChevronDown size={14} />
                                </button>
                                <button
                                  onClick={() => confirmDeleteNode(node.id)}
                                  className="p-0.5 text-ink-2 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
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
                                  className="p-0.5 text-ink-2 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="上移"
                                >
                                  <ChevronUp size={14} />
                                </button>
                                <button
                                  onClick={() => moveChain(node.chainId, 'down')}
                                  className="p-0.5 text-ink-2 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="下移"
                                >
                                  <ChevronDown size={14} />
                                </button>
                                <button
                                  onClick={() => setDeleteChainConfirm({ open: true, chainId: node.chainId })}
                                  className="p-0.5 text-ink-2 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
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
                                  className="p-0.5 text-ink-2 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="上移"
                                >
                                  <ChevronUp size={14} />
                                </button>
                                <button
                                  onClick={() => moveNodePool(node.poolId, 'down')}
                                  className="p-0.5 text-ink-2 hover:text-yellow-400 hover:bg-yellow-500/10 rounded transition-colors"
                                  title="下移"
                                >
                                  <ChevronDown size={14} />
                                </button>
                                <button
                                  onClick={() => setDeleteNodePoolConfirm({ open: true, poolId: node.poolId })}
                                  className="p-0.5 text-ink-2 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
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
                    <td colSpan={13} className="px-4 py-12 text-center text-ink-3">
                      {allNodes.length === 0 ? '暂无节点，请先添加订阅或自建节点' : '没有匹配的节点'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* 分页控件 */}
          {filteredNodes.length > pageSize && (
            <div className="mt-4 flex flex-wrap items-center justify-between gap-2 px-4 py-3 bg-surface-2/50 rounded-lg border border-line">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                <span className="text-sm text-ink-2">
                  显示 {(currentPage - 1) * pageSize + 1} - {Math.min(currentPage * pageSize, filteredNodes.length)} / {filteredNodes.length}
                </span>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setCurrentPage(1);
                  }}
                  className="px-3 py-1 bg-surface-3 border border-line-strong rounded text-ink text-sm focus:outline-none focus:border-blue-500"
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
                  className="px-3 py-1 bg-surface-3 hover:bg-surface-4 disabled:opacity-50 disabled:cursor-not-allowed text-ink rounded transition-colors text-sm"
                >
                  首页
                </button>
                <button
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 bg-surface-3 hover:bg-surface-4 disabled:opacity-50 disabled:cursor-not-allowed text-ink rounded transition-colors text-sm"
                >
                  上一页
                </button>
                <span className="px-3 py-1 text-sm text-ink-2">
                  {currentPage} / {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 bg-surface-3 hover:bg-surface-4 disabled:opacity-50 disabled:cursor-not-allowed text-ink rounded transition-colors text-sm"
                >
                  下一页
                </button>
                <button
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 bg-surface-3 hover:bg-surface-4 disabled:opacity-50 disabled:cursor-not-allowed text-ink rounded transition-colors text-sm"
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
        <AddNodeModal
          newNodeLink={newNodeLink}
          setNewNodeLink={setNewNodeLink}
          newNodeName={newNodeName}
          setNewNodeName={setNewNodeName}
          loading={loading}
          onClose={() => setShowAddModal(false)}
          onSubmit={addCustomNode}
        />
      )}

      {/* Test Settings Modal */}
      {showTestSettingsModal && (
        <TestSettingsModal
          testTimeout={testTimeout}
          setTestTimeout={setTestTimeout}
          testConcurrency={testConcurrency}
          setTestConcurrency={setTestConcurrency}
          selectedGeoipApi={selectedGeoipApi}
          setSelectedGeoipApi={setSelectedGeoipApi}
          geoipApis={geoipApis}
          onClose={() => setShowTestSettingsModal(false)}
        />
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
        <PortMappingModal
          portMappingNode={portMappingNode}
          setPortMappingNode={setPortMappingNode}
          portMappingValue={portMappingValue}
          setPortMappingValue={setPortMappingValue}
          savePortMapping={savePortMapping}
          removePortMapping={removePortMapping}
        />
      )}

      {/* Port Mapping List Modal */}
      {showPortMappingList && (
        <PortMappingListModal
          allPortMappings={allPortMappings}
          setShowPortMappingList={setShowPortMappingList}
          deletePortMappingFromList={deletePortMappingFromList}
        />
      )}

      {/* Proxy Chain Modal */}
      <ProxyChainSection
        subscriptions={subscriptions}
        availableChainNodes={availableChainNodes}
        vpngatePool={vpngatePool}
        vpngatePools={vpngatePools}
        showToast={showToast}
        openChainRequest={chainModalRequest}
        onChainSaved={fetchProxyChains}
      />

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
