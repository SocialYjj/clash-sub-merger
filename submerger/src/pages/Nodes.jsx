import React, { useState, useMemo, useEffect } from 'react';
import { Server, Search, Plus, Trash2, X, RefreshCw, Clock, CheckSquare, Square, Settings, Play, Filter, Edit2, ChevronUp, ChevronDown, Globe } from 'lucide-react';
import axios from 'axios';
import ConfirmModal from '../components/ConfirmModal';
import NodeEditModal from '../components/NodeEditModal';

const API_BASE = '/api';

// Keywords to filter out info nodes (not real proxy nodes)
const INFO_NODE_KEYWORDS = [
  '剩余流量', '套餐到期', '距离下次重置', '建议', '官网', '未到期',
  '剩余', '到期', '重置', '流量', '过期', '订阅', '网址', '公告',
  '群组', 'Telegram', 'TG', '客服', '续费', '购买', '套餐',
  '使用说明', '教程', '更新', '通知', '邀请', '返利'
];

// Check if a node is an info node (not a real proxy)
const isInfoNode = (node) => {
  if (!node || !node.name) return true;
  const name = node.name;
  return INFO_NODE_KEYWORDS.some(keyword => name.includes(keyword));
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
  if (latency === null) return { text: '超时', color: 'bg-orange-500/20 text-orange-400' };
  if (latency === undefined) return { text: '未测', color: 'bg-gray-500/20 text-gray-400' };
  if (latency < 200) return { text: '优秀', color: 'bg-green-500/20 text-green-400' };
  if (latency < 500) return { text: '良好', color: 'bg-lime-500/20 text-lime-400' };
  if (latency < 1000) return { text: '一般', color: 'bg-yellow-500/20 text-yellow-400' };
  return { text: '较慢', color: 'bg-orange-500/20 text-orange-400' };
};

export default function Nodes({ subscriptions, customNodes, onRefreshCustomNodes, showToast }) {
  const [search, setSearch] = useState('');
  const [filterSource, setFilterSource] = useState('all');
  const [filterType, setFilterType] = useState('all');
  const [filterLatencyStatus, setFilterLatencyStatus] = useState('all');
  const [maxLatency, setMaxLatency] = useState('');
  const [sortBy, setSortBy] = useState('name');
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
  const [showBatchTestMenu, setShowBatchTestMenu] = useState(false);
  const [editingNode, setEditingNode] = useState(null);


  // Fetch nodes from subscription files
  useEffect(() => {
    fetchAllSubNodes();
  }, [subscriptions]);

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
        const res = await axios.get(`${API_BASE}/subscriptions/${sub.id}/nodes`);
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
            const res = await axios.get(`${API_BASE}/geoip/lookup/${encodeURIComponent(server)}`);
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

        const geo = geoipData[node.server];
        const nodeKey = `${subId}-${idx}`;
        const testResult = nodeTestResults[nodeKey];
        const cachedGeoip = node.geoip;  // Cached geoip from config

        // Priority: testResult > cachedGeoip > geoipData lookup
        let region = '';
        let flag = '';
        let country = '';
        let city = '';

        if (testResult?.region) {
          region = testResult.region.display || testResult.region.country;
          flag = testResult.region.flag || '';
          country = testResult.region.country || '';
          city = testResult.region.city || '';
        } else if (cachedGeoip) {
          country = cachedGeoip.country || '';
          city = cachedGeoip.city || '';
          flag = cachedGeoip.flag || '';
          region = country;
          if (city) {
            region = region ? `${region} ${city}` : city;
          }
        } else if (geo) {
          country = geo.country_name || '';
          city = geo.city || '';
          flag = geo.flag || '';
          region = country;
          if (city) {
            region = region ? `${region} ${city}` : city;
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
          latency: testResult?.latency ?? node.last_latency,
          testError: testResult?.error,
          detectedRegion: testResult?.region,
          cachedGeoip: cachedGeoip,
        });
      });
    });

    customNodes?.forEach((node, idx) => {
      if (isInfoNode(node)) return;

      const geo = geoipData[node.server];
      const nodeKey = `custom-${node.id || idx}`;
      const testResult = nodeTestResults[nodeKey];
      const cachedGeoip = node.geoip;  // Cached geoip from config

      // Priority: testResult > cachedGeoip > geoipData lookup
      let region = '';
      let flag = '';
      let country = '';
      let city = '';

      if (testResult?.region) {
        region = testResult.region.display || testResult.region.country;
        flag = testResult.region.flag || '';
        country = testResult.region.country || '';
        city = testResult.region.city || '';
      } else if (cachedGeoip) {
        country = cachedGeoip.country || '';
        city = cachedGeoip.city || '';
        flag = cachedGeoip.flag || '';
        region = country;
        if (city) {
          region = region ? `${region} ${city}` : city;
        }
      } else if (geo) {
        country = geo.country_name || '';
        city = geo.city || '';
        flag = geo.flag || '';
        region = country;
        if (city) {
          region = region ? `${region} ${city}` : city;
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
        latency: testResult?.latency ?? node.last_latency,
        testError: testResult?.error,
        detectedRegion: testResult?.region,
        cachedGeoip: cachedGeoip,
      });
    });

    return nodes;
  }, [subNodes, customNodes, geoipData, nodeTestResults]);


  // Get unique types and sources
  const nodeTypes = useMemo(() => {
    const types = new Set(allNodes.map(n => n.type).filter(Boolean));
    return ['all', ...Array.from(types)];
  }, [allNodes]);

  const sources = useMemo(() => {
    const srcs = new Set(allNodes.map(n => n.source));
    return ['all', ...Array.from(srcs)];
  }, [allNodes]);

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
        if (filterLatencyStatus === 'success') return n.latency !== undefined && n.latency !== null && !n.testError;
        if (filterLatencyStatus === 'failed') return n.testError || n.latency === null;
        return true;
      });
    }

    // Max latency filter
    if (maxLatency && !isNaN(parseInt(maxLatency))) {
      const max = parseInt(maxLatency);
      result = result.filter(n => n.latency !== undefined && n.latency !== null && n.latency <= max);
    }

    // Primary sort: custom nodes always come first
    result.sort((a, b) => {
      // Custom nodes first
      if (a.sourceType === 'custom' && b.sourceType !== 'custom') return -1;
      if (a.sourceType !== 'custom' && b.sourceType === 'custom') return 1;

      // If both are custom, keep original order (by idx)
      if (a.sourceType === 'custom' && b.sourceType === 'custom') {
        return a.idx - b.idx;
      }

      // For non-custom nodes, apply secondary sort
      if (sortBy === 'name') return (a.name || '').localeCompare(b.name || '');
      if (sortBy === 'type') return (a.type || '').localeCompare(b.type || '');
      if (sortBy === 'source') return (a.source || '').localeCompare(b.source || '');
      if (sortBy === 'region') return (a.region || '').localeCompare(b.region || '');
      if (sortBy === 'latency') {
        if (a.latency === undefined) return 1;
        if (b.latency === undefined) return -1;
        if (a.latency === null) return 1;
        if (b.latency === null) return -1;
        return a.latency - b.latency;
      }
      return 0;
    });

    return result;
  }, [allNodes, search, filterSource, filterType, filterLatencyStatus, maxLatency, sortBy]);


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
      const res = await axios.post(`${API_BASE}/nodes/${node.sourceId}/${node.idx}/test`, {
        test_latency: !isRegionTest,
        test_speed: false,
        test_region: isRegionTest,
        timeout: testTimeout
      });
      setNodeTestResults(prev => {
        const newResult = { ...prev[node.nodeKey] };
        if (isRegionTest) {
          newResult.region = res.data.region;
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

    if (!testLatency && !testRegion) {
      showToast?.('请至少选择一项检测内容', 'error');
      return;
    }

    setShowBatchTestMenu(false);
    setBatchTesting(true);

    const totalSteps = (testLatency ? nodesToTest.length : 0) + (testRegion ? nodesToTest.length : 0);
    let currentStep = 0;
    setBatchTestProgress({ current: 0, total: totalSteps, phase: testLatency ? '延迟' : '地区' });

    // Phase 1: Test latency with concurrency
    if (testLatency) {
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        await Promise.all(batch.map(async (node) => {
          try {
            const res = await axios.post(`${API_BASE}/nodes/${node.sourceId}/${node.idx}/test`, {
              test_latency: true,
              test_speed: false,
              test_region: false,
              timeout: testTimeout
            });
            setNodeTestResults(prev => ({
              ...prev,
              [node.nodeKey]: { ...prev[node.nodeKey], latency: res.data.latency, error: false }
            }));
          } catch {
            setNodeTestResults(prev => ({
              ...prev,
              [node.nodeKey]: { ...prev[node.nodeKey], latency: null, error: true }
            }));
          }
        }));
        currentStep = Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '延迟' });
      }
    }

    // Phase 2: Test region with concurrency
    if (testRegion) {
      const baseStep = testLatency ? nodesToTest.length : 0;
      setBatchTestProgress(prev => ({ ...prev, phase: '地区' }));
      for (let i = 0; i < nodesToTest.length; i += testConcurrency) {
        const batch = nodesToTest.slice(i, i + testConcurrency);
        await Promise.all(batch.map(async (node) => {
          try {
            const res = await axios.post(`${API_BASE}/nodes/${node.sourceId}/${node.idx}/test`, {
              test_latency: false,
              test_speed: false,
              test_region: true,
              timeout: testTimeout
            });
            setNodeTestResults(prev => ({
              ...prev,
              [node.nodeKey]: { ...prev[node.nodeKey], region: res.data.region }
            }));
          } catch {
            // Region test failed, keep existing data
          }
        }));
        currentStep = baseStep + Math.min(i + testConcurrency, nodesToTest.length);
        setBatchTestProgress({ current: currentStep, total: totalSteps, phase: '地区' });
      }
    }

    setBatchTesting(false);
    showToast?.(`测试完成，共测试 ${nodesToTest.length} 个节点`);
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
      await axios.post(`${API_BASE}/custom-nodes`, payload);
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
      await axios.delete(`${API_BASE}/custom-nodes/${nodeId}`);
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
    onRefreshCustomNodes?.();
    showToast?.('节点列表已刷新');
  };

  // Clear filters
  const clearFilters = () => {
    setSearch('');
    setFilterSource('all');
    setFilterType('all');
    setFilterLatencyStatus('all');
    setMaxLatency('');
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
      await axios.put(`${API_BASE}/custom-nodes/reorder`, { order: newOrder });
      onRefreshCustomNodes?.();
      showToast?.('顺序已调整');
    } catch (err) {
      showToast?.('调整失败', 'error');
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
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, [showBatchTestMenu]);


  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">节点管理</h1>
          <p className="text-gray-400 text-sm mt-1">查看和管理所有节点</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
          >
            <Plus size={18} />
            添加节点
          </button>
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
                  <div className="pt-2 border-t border-gray-700">
                    <button
                      onClick={batchTestNodes}
                      disabled={!testLatency && !testRegion}
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
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
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
          <option value="failed">测试失败</option>
        </select>
      </div>


      {/* Filters Row 2 */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">最大延迟</span>
          <input
            type="number"
            value={maxLatency}
            onChange={(e) => setMaxLatency(e.target.value)}
            placeholder="ms"
            className="w-20 px-2 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          />
          <span className="text-sm text-gray-500">ms</span>
        </div>

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
        </select>

        <button
          onClick={clearFilters}
          className="px-3 py-2 text-sm text-gray-400 hover:text-white transition-colors"
        >
          重置
        </button>
      </div>

      {/* Stats */}
      <div className="flex flex-wrap gap-4 text-sm">
        <span className="text-gray-400">
          共 <span className="text-white font-medium">{filteredNodes.length}</span> 个节点
          {(search || filterSource !== 'all' || filterType !== 'all' || filterLatencyStatus !== 'all' || maxLatency) &&
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
      <div className="bg-gray-800/50 border border-gray-700 rounded-xl overflow-hidden">
        {loadingNodes ? (
          <div className="p-12 text-center text-gray-500">
            <RefreshCw size={24} className="animate-spin mx-auto mb-2" />
            加载节点中...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700 text-left">
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">
                    <button
                      onClick={toggleSelectAll}
                      className="flex items-center gap-2 hover:text-white transition-colors"
                    >
                      {selectedNodes.size === filteredNodes.length && filteredNodes.length > 0 ? (
                        <CheckSquare size={18} className="text-blue-400" />
                      ) : (
                        <Square size={18} />
                      )}
                      全选
                    </button>
                  </th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">节点名称</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">来源</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">协议</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">地区</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">延迟</th>
                  <th className="px-4 py-3 text-sm font-medium text-gray-400">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {filteredNodes.length > 0 ? (
                  filteredNodes.map((node, idx) => {
                    const isTesting = testingNode === node.nodeKey;
                    const isSelected = selectedNodes.has(node.nodeKey);
                    const testResult = nodeTestResults[node.nodeKey];
                    const displayedLatency = testResult?.latency !== undefined ? testResult.latency : node.latency;
                    const displayedError = testResult?.error !== undefined ? testResult.error : node.testError;
                    const latencyBadge = getLatencyBadge(displayedLatency, displayedError);

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
                            {node.flag && <span className="text-lg">{node.flag}</span>}
                            <span className="text-white truncate max-w-[200px]" title={node.name}>
                              {node.name || '未命名'}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-sm ${node.sourceType === 'custom' ? 'text-orange-400' : 'text-gray-400'}`}>
                            {node.source}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getTypeColor(node.type)}`}>
                            {node.type?.toUpperCase() || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-400 text-sm">
                          <span className="truncate max-w-[120px] inline-block" title={node.region}>
                            {node.region || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            {node.latency !== undefined && node.latency !== null && !node.testError ? (
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
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => setEditingNode(node)}
                              className="p-1.5 text-gray-400 hover:text-purple-400 hover:bg-purple-500/10 rounded transition-colors"
                              title="查看/编辑"
                            >
                              <Edit2 size={16} />
                            </button>
                            <button
                              onClick={() => testNode(node)}
                              disabled={isTesting || batchTesting}
                              className="p-1.5 text-gray-400 hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors disabled:opacity-50"
                              title="测试延迟"
                            >
                              {isTesting && testingType === 'latency' ? (
                                <RefreshCw size={16} className="animate-spin" />
                              ) : (
                                <Clock size={16} />
                              )}
                            </button>
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
                  placeholder="vless://... 或 vmess://... 或 trojan://..."
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
          onSave={() => onRefreshCustomNodes?.()}
          showToast={showToast}
        />
      )}
    </div>
  );
}