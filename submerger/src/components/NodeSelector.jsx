import { useState, useMemo, useEffect, useRef } from 'react';
import { X, Search, CheckSquare, Square } from 'lucide-react';

const NodeSelector = ({ groupName, availableNodes, selectedNodes, onConfirm, onCancel }) => {
  const [selected, setSelected] = useState(new Set(selectedNodes));
  const [searchTerm, setSearchTerm] = useState('');
  const dialogRef = useRef(null);

  useEffect(() => {
    const previous = document.activeElement;
    dialogRef.current?.focus();
    const handleKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onCancel();
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      if (previous && typeof previous.focus === 'function') previous.focus();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- Escape 监听与焦点管理只在挂载时绑定一次；补 onCancel 依赖会在父级重渲染时重新捕获焦点
  }, []);

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
    setSelected((current) => {
      const next = new Set(current);
      filteredNodes.forEach((node) => next.add(node));
      return next;
    });
  };

  const handleClearAll = () => {
    setSelected((current) => {
      const next = new Set(current);
      filteredNodes.forEach((node) => next.delete(node));
      return next;
    });
  };

  const handleConfirm = () => {
    onConfirm(Array.from(selected));
  };

  return (
    <div className="fixed inset-0 bg-scrim/50 flex items-center justify-center z-50 p-4" onMouseDown={(event) => event.target === event.currentTarget && onCancel()}>
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="node-selector-title" tabIndex={-1} className="bg-surface-2 rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-line">
          <h2 id="node-selector-title" className="text-xl font-semibold text-ink">编辑分组: {groupName}</h2>
          <button
            onClick={onCancel}
            className="text-ink-2 hover:text-ink transition-colors"
          >
            <X size={24} />
          </button>
        </div>

        {/* Search and actions */}
        <div className="p-4 border-b border-line space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-ink-2" size={18} />
            <input
              type="text"
              placeholder="搜索节点..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-surface-3 border border-line-strong rounded-lg text-ink placeholder-ink-2 focus:outline-none focus:border-blue-500"
            />
          </div>
          
          <div className="flex items-center justify-between">
            <div className="text-sm text-ink-2">
              已选择 <span className="text-ink font-medium">{selected.size}</span> / {availableNodes.length} 个节点
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleSelectAll}
                className="px-3 py-1.5 bg-surface-3 hover:bg-surface-4 text-ink rounded text-sm transition-colors"
              >
                全选
              </button>
              <button
                onClick={handleClearAll}
                className="px-3 py-1.5 bg-surface-3 hover:bg-surface-4 text-ink rounded text-sm transition-colors"
              >
                清空
              </button>
            </div>
          </div>
        </div>

        {/* Node list */}
        <div className="flex-1 overflow-y-auto p-4">
          {filteredNodes.length === 0 ? (
            <div className="text-center text-ink-2 py-8">
              {searchTerm ? '没有找到匹配的节点' : '没有可用节点'}
            </div>
          ) : (
            <div className="space-y-1">
              {filteredNodes.map((node) => (
                <label
                  key={node}
                  className="flex items-center gap-3 p-3 bg-surface-3/30 hover:bg-surface-3/50 rounded cursor-pointer transition-colors"
                >
                  <div className="flex-shrink-0">
                    {selected.has(node) ? (
                      <CheckSquare className="text-blue-500" size={20} />
                    ) : (
                      <Square className="text-ink-2" size={20} />
                    )}
                  </div>
                  <span className="text-ink flex-1">{node}</span>
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
        <div className="p-4 border-t border-line flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-surface-3 hover:bg-surface-4 text-ink rounded transition-colors"
          >
            取消
          </button>
          <button
            onClick={handleConfirm}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-ink rounded transition-colors"
          >
            确定
          </button>
        </div>
      </div>
    </div>
  );
};

export default NodeSelector;
