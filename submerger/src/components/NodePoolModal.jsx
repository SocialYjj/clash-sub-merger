import React, { useEffect, useMemo, useState } from 'react';
import { CheckSquare, Loader2, Search, Square, X } from 'lucide-react';

const nodeKey = (node) => `${node?.sub_id || ''}|${node?.node_id || `#${node?.node_index ?? ''}`}`;

const NodePoolModal = ({ pool, availableNodes, onClose, onSave, saving = false }) => {
  const [name, setName] = useState(pool?.name || '');
  const [strategy, setStrategy] = useState(pool?.group_strategy || 'select');
  const [lbStrategy, setLbStrategy] = useState(pool?.lb_strategy || 'round-robin');
  const [groupUrl, setGroupUrl] = useState(pool?.group_url || '');
  const [groupInterval, setGroupInterval] = useState(pool?.group_interval || 300);
  const [groupTolerance, setGroupTolerance] = useState(pool?.group_tolerance || 50);
  const [selectedKeys, setSelectedKeys] = useState(() => new Set(
    (pool?.nodes || []).map(nodeKey),
  ));
  const [search, setSearch] = useState('');

  useEffect(() => {
    setSelectedKeys(new Set((pool?.nodes || []).map(nodeKey)));
  }, [pool]);

  const filteredNodes = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return availableNodes || [];
    return (availableNodes || []).filter((node) => (
      String(node.node_name || '').toLowerCase().includes(query)
      || String(node.source_name || '').toLowerCase().includes(query)
      || String(node.node_type || '').toLowerCase().includes(query)
    ));
  }, [availableNodes, search]);

  const toggle = (key) => {
    setSelectedKeys((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const selectFiltered = () => {
    setSelectedKeys((current) => new Set([
      ...current,
      ...filteredNodes.map(nodeKey),
    ]));
  };

  const save = async () => {
    const selectedNodes = (availableNodes || []).filter((node) => selectedKeys.has(nodeKey(node)));
    if (!name.trim()) return;
    if (selectedNodes.length === 0) return;
    await onSave({
      name: name.trim(),
      nodes: selectedNodes.map((node) => ({
        sub_id: node.sub_id,
        node_id: node.node_id,
        node_index: node.node_index,
        node_name: node.node_name,
      })),
      group_strategy: strategy,
      lb_strategy: lbStrategy,
      group_url: groupUrl.trim() || null,
      group_interval: Number(groupInterval) || 300,
      group_tolerance: Number(groupTolerance) || 50,
    });
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-[55] p-4">
      <div className="bg-gray-800 rounded-xl w-full max-w-2xl border border-gray-700 max-h-[90vh] flex flex-col">
        <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
          <h3 className="font-semibold text-white">{pool ? '编辑节点池' : '添加节点池'}</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white" aria-label="关闭">
            <X size={20} />
          </button>
        </div>

        <div className="p-4 space-y-4 overflow-y-auto">
          <div>
            <label className="block text-sm text-gray-400 mb-1">名称</label>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="例如：美国直连池"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-sm text-gray-400 mb-1">策略类型</label>
              <select
                value={strategy}
                onChange={(event) => setStrategy(event.target.value)}
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
              >
                <option value="select">手动选择</option>
                <option value="url-test">自动测速</option>
                <option value="fallback">故障转移</option>
                <option value="load-balance">负载均衡</option>
              </select>
            </div>
            {strategy === 'load-balance' && (
              <div>
                <label className="block text-sm text-gray-400 mb-1">负载均衡方式</label>
                <select
                  value={lbStrategy}
                  onChange={(event) => setLbStrategy(event.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="round-robin">轮询</option>
                  <option value="consistent-hashing">同目标固定</option>
                  <option value="sticky-sessions">同会话固定</option>
                </select>
              </div>
            )}
          </div>

          {(strategy === 'url-test' || strategy === 'fallback') && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="sm:col-span-2">
                <label className="block text-sm text-gray-400 mb-1">检测地址</label>
                <input
                  value={groupUrl}
                  onChange={(event) => setGroupUrl(event.target.value)}
                  placeholder="https://cp.cloudflare.com/generate_204"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">间隔（秒）</label>
                <input
                  type="number"
                  min={10}
                  value={groupInterval}
                  onChange={(event) => setGroupInterval(event.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
              </div>
              {strategy === 'url-test' && (
                <div>
                  <label className="block text-sm text-gray-400 mb-1">容差</label>
                  <input
                    type="number"
                    min={0}
                    value={groupTolerance}
                    onChange={(event) => setGroupTolerance(event.target.value)}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              )}
            </div>
          )}

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm text-gray-400">成员节点（已选 {selectedKeys.size} 个）</label>
              <div className="flex items-center gap-2 text-xs">
                <button type="button" onClick={selectFiltered} className="text-blue-400 hover:text-blue-300">全选当前</button>
                <button type="button" onClick={() => setSelectedKeys(new Set())} className="text-gray-400 hover:text-gray-300">清空</button>
              </div>
            </div>
            <div className="relative mb-2">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="搜索节点或订阅"
                className="w-full pl-9 pr-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div className="max-h-64 overflow-y-auto border border-gray-700 rounded-lg divide-y divide-gray-700">
              {filteredNodes.length === 0 ? (
                <div className="p-6 text-center text-sm text-gray-500">没有可加入节点池的节点</div>
              ) : filteredNodes.map((node) => {
                const key = nodeKey(node);
                const checked = selectedKeys.has(key);
                return (
                  <button
                    type="button"
                    key={key}
                    onClick={() => toggle(key)}
                    className="w-full px-3 py-2 text-left hover:bg-gray-700/50 flex items-center gap-2"
                  >
                    {checked ? <CheckSquare size={16} className="text-blue-400 shrink-0" /> : <Square size={16} className="text-gray-500 shrink-0" />}
                    <span className="truncate text-sm text-white">{node.node_name || '未命名节点'}</span>
                    <span className="ml-auto text-xs text-gray-500 shrink-0">{node.source_name || node.sub_id} · {String(node.node_type || '').toUpperCase()}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        <div className="px-4 py-3 border-t border-gray-700 flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 text-gray-400 hover:text-white transition-colors">取消</button>
          <button
            onClick={save}
            disabled={saving || !name.trim() || selectedKeys.size === 0}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {saving && <Loader2 size={16} className="animate-spin" />}
            保存
          </button>
        </div>
      </div>
    </div>
  );
};

export default NodePoolModal;
