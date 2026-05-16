import React, { useState, useMemo } from 'react';
import { X, Search, CheckSquare, Square } from 'lucide-react';

const NodeSelector = ({ groupName, availableNodes, selectedNodes, onConfirm, onCancel }) => {
  const [selected, setSelected] = useState(new Set(selectedNodes));
  const [searchTerm, setSearchTerm] = useState('');

  // Filter nodes based on search term
  const filteredNodes = useMemo(() => {
    if (!searchTerm) return availableNodes;
    const term = searchTerm.toLowerCase();
    return availableNodes.filter(node => node.toLowerCase().includes(term));
  }, [availableNodes, searchTerm]);

  const handleToggle = (node) => {
    const newSelected = new Set(selected);
    if (newSelected.has(node)) {
      newSelected.delete(node);
    } else {
      newSelected.add(node);
    }
    setSelected(newSelected);
  };

  const handleSelectAll = () => {
    setSelected(new Set(filteredNodes));
  };

  const handleClearAll = () => {
    setSelected(new Set());
  };

  const handleConfirm = () => {
    onConfirm(Array.from(selected));
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-xl font-semibold text-white">编辑分组: {groupName}</h2>
          <button
            onClick={onCancel}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X size={24} />
          </button>
        </div>

        {/* Search and actions */}
        <div className="p-4 border-b border-gray-700 space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
            <input
              type="text"
              placeholder="搜索节点..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-400">
              已选择 <span className="text-white font-medium">{selected.size}</span> / {availableNodes.length} 个节点
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleSelectAll}
                className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm transition-colors"
              >
                全选
              </button>
              <button
                onClick={handleClearAll}
                className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm transition-colors"
              >
                清空
              </button>
            </div>
          </div>
        </div>

        {/* Node list */}
        <div className="flex-1 overflow-y-auto p-4">
          {filteredNodes.length === 0 ? (
            <div className="text-center text-gray-400 py-8">
              {searchTerm ? '没有找到匹配的节点' : '没有可用节点'}
            </div>
          ) : (
            <div className="space-y-1">
              {filteredNodes.map((node) => (
                <label
                  key={node}
                  className="flex items-center gap-3 p-3 bg-gray-700/30 hover:bg-gray-700/50 rounded cursor-pointer transition-colors"
                >
                  <div className="flex-shrink-0">
                    {selected.has(node) ? (
                      <CheckSquare className="text-blue-500" size={20} />
                    ) : (
                      <Square className="text-gray-400" size={20} />
                    )}
                  </div>
                  <span className="text-white flex-1">{node}</span>
                  <input
                    type="checkbox"
                    checked={selected.has(node)}
                    onChange={() => handleToggle(node)}
                    className="hidden"
                  />
                </label>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-700 flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded transition-colors"
          >
            取消
          </button>
          <button
            onClick={handleConfirm}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors"
          >
            确定
          </button>
        </div>
      </div>
    </div>
  );
};

export default NodeSelector;
