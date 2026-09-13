import React, { useState, useMemo, useEffect } from 'react';
import { X, ArrowRight } from 'lucide-react';
import request from '../../utils/request';

const API_BASE = '/api';

export default function ProxyChainSection({
  subscriptions,
  availableChainNodes,
  vpngatePool,
  vpngatePools,
  showToast,
  openChainRequest,
  onChainSaved,
}) {
  const [showChainModal, setShowChainModal] = useState(false);
  const [editingChain, setEditingChain] = useState(null);
  const [chainName, setChainName] = useState('');
  const [chainRows, setChainRows] = useState([[null, null]]);
  const [groupDrafts, setGroupDrafts] = useState({});
  const [groupEditing, setGroupEditing] = useState({});
  const [groupSearch, setGroupSearch] = useState({});

  // The parent opens the editor through an incrementing request object;
  // the seq field makes repeated opens of the same chain re-run this effect.
  useEffect(() => {
    if (openChainRequest) {
      openChainModal(openChainRequest.chain);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openChainRequest]);

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
      onChainSaved?.();
    } catch (err) {
      showToast?.(err.response?.data?.detail || '保存失败', 'error');
    }
  };

  return (
    <>
      {showChainModal && (
        <div className="fixed inset-0 bg-scrim/50 flex items-center justify-center z-50 p-4">
          <div className="bg-surface-2 border border-line rounded-xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-line">
              <h2 className="text-lg font-medium text-ink">
                {editingChain ? '编辑链式代理' : '添加链式代理'}
              </h2>
              <button
                onClick={closeChainModal}
                className="p-1 text-ink-2 hover:text-ink transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-4 space-y-4">
              {/* Name Input */}
              <div>
                <label className="block text-sm text-ink-2 mb-1">名称</label>
                <input
                  type="text"
                  value={chainName}
                  onChange={(e) => setChainName(e.target.value)}
                  placeholder="例如：美国家宽链路"
                  className="w-full px-3 py-2 bg-surface border border-line rounded-lg text-ink placeholder-ink-3 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Chain Rows - Vertical Layout */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm text-ink-2">链路配置</label>
                </div>

                <div className="space-y-4">
                  {chainRows.map((row, rowIndex) => (
                    <div key={rowIndex} className="bg-surface/50 rounded-lg p-3">

                      {/* Vertical Node Selectors */}
                      <div className="space-y-2">
                        <div className="text-sm text-ink-3 text-center">我</div>
                        
                        {row.map((node, colIndex) => {
                          const isLast = colIndex === row.length - 1;
                          const cellType = node?.type === 'group' && node?.group_source === 'vpngate'
                            ? 'vpngate'
                            : (node?.type || 'node');
                          const isVpnGatePool = cellType === 'vpngate';
                          const groupLabel = isLast ? '组(落地池)' : '组(中转池)';
                          return (
                            <React.Fragment key={colIndex}>
                              <div className="flex justify-center">
                                <ArrowRight size={16} className="text-ink-4 rotate-90" />
                              </div>
                              <div className="relative space-y-2">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs text-ink-3">类型</span>
                                  <select
                                    value={cellType}
                                    onChange={(e) => updateChainCellType(rowIndex, colIndex, e.target.value)}
                                    className="px-2 py-1 bg-surface-2 border border-line rounded text-xs text-ink focus:outline-none focus:border-blue-500"
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
                                      className="w-full px-3 py-2 bg-surface-2 border border-line rounded-lg text-ink text-sm focus:outline-none focus:border-blue-500"
                                    />
                                    <select
                                      value={node?.group_strategy || 'load-balance'}
                                      onChange={(e) => updateChainGroup(rowIndex, colIndex, { group_strategy: e.target.value })}
                                      className="w-full px-3 py-2 bg-surface-2 border border-line rounded-lg text-ink text-sm focus:outline-none focus:border-blue-500"
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
                                        className="w-full px-3 py-2 bg-surface-2 border border-line rounded-lg text-ink text-sm focus:outline-none focus:border-blue-500"
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
                                          className="w-full px-3 py-2 bg-surface-2 border border-line rounded-lg text-ink text-sm focus:outline-none focus:border-blue-500"
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
                                            <div className="text-xs text-ink-3">已选 {selectedNames.length} 个</div>
                                            {selectedNames.length > 0 ? (
                                              <div className="flex flex-wrap gap-1">
                                                {selectedNames.map((name, i) => (
                                                  <span key={`${name}-${i}`} className="px-2 py-0.5 bg-surface-3 text-ink-hi rounded text-xs">{name}</span>
                                                ))}
                                              </div>
                                            ) : (
                                              <div className="text-xs text-ink-3">尚未选择组内节点</div>
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
                                          <div className="flex items-center justify-between text-xs text-ink-3">
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
                                                className="text-ink-2 hover:text-ink-hi"
                                              >
                                                清空
                                              </button>
                                            </div>
                                          </div>
                                          <input
                                            value={searchValue}
                                            onChange={(e) => setGroupSearch(prev => ({ ...prev, [cellKey]: e.target.value }))}
                                            placeholder="搜索节点/订阅"
                                            className="w-full px-3 py-2 bg-surface-2 border border-line rounded-lg text-ink text-sm focus:outline-none focus:border-blue-500"
                                          />
                                          <div className="max-h-40 overflow-y-auto border border-line rounded-lg bg-surface-2">
                                            {filteredNodes.map(n => {
                                              const key = makeChainNodeKey(n.sub_id, n.node_id, n.node_name ?? n.display_name ?? n.name, n.node_index);
                                              const checked = draftKeys.includes(key);
                                              return (
                                                <div
                                                  key={key}
                                                  onClick={() => toggleGroupDraft(rowIndex, colIndex, key)}
                                                  className="px-3 py-2 text-sm text-ink hover:bg-surface-3/50 cursor-pointer flex items-center justify-between"
                                                >
                                                  <span className="truncate">{getChainNodeLabel(n)}</span>
                                                  <span className={checked ? 'text-blue-400' : 'text-ink-4'}>{checked ? '已选' : ''}</span>
                                                </div>
                                              );
                                            })}
                                          </div>
                                          <div className="flex items-center justify-between">
                                            <span className="text-xs text-ink-3">选择组内节点，系统会自动生成链路组</span>
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
                                    className="w-full px-3 py-2 bg-surface-2 border border-line rounded-lg text-ink text-sm focus:outline-none focus:border-blue-500 appearance-none"
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
                                    className="absolute -top-2 -right-2 w-5 h-5 bg-red-500 text-ink rounded-full text-xs flex items-center justify-center hover:bg-red-400"
                                  >
                                    ×
                                  </button>
                                )}
                              </div>
                            </React.Fragment>
                          );
                        })}

                        <div className="flex justify-center">
                          <ArrowRight size={16} className="text-ink-4 rotate-90" />
                        </div>
                        <div className="text-sm text-ink-3 text-center">服务</div>

                        <button
                          onClick={() => addChainColumn(rowIndex)}
                          className="w-full px-2 py-1.5 text-xs text-blue-400 hover:text-blue-300 border border-blue-400/30 rounded hover:border-blue-400/50 mt-2"
                        >
                          + 添加中转节点
                        </button>
                      </div>

                      {/* Preview */}
                      <div className="mt-3 pt-2 border-t border-line text-xs text-ink-3">
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
            <div className="flex items-center justify-end gap-2 p-4 border-t border-line">
              <button
                onClick={closeChainModal}
                className="px-4 py-2 text-ink-2 hover:text-ink transition-colors"
              >
                取消
              </button>
              <button
                onClick={saveChain}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-ink rounded-lg transition-colors"
              >
                保存
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
