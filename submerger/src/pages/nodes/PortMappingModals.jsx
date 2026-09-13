import { Trash2, X } from 'lucide-react';
import VirtualList from '../../components/VirtualList';

// Virtualized mapping list geometry: each 48px slot holds a 40px row
// (h-10, border-box so the inactive state's border stays inside) plus the
// 8px gap that `space-y-2` used to provide between rows.
const MAPPING_ROW_SLOT_HEIGHT = 48;
// Viewport cap of the virtualized list before it scrolls internally.
const MAPPING_LIST_MAX_HEIGHT = 384;

export function PortMappingModal({
  portMappingNode,
  setPortMappingNode,
  portMappingValue,
  setPortMappingValue,
  savePortMapping,
  removePortMapping,
}) {
  return (
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
  );
}

export function PortMappingListModal({
  allPortMappings,
  setShowPortMappingList,
  deletePortMappingFromList,
}) {
  // Only the visible window of mappings is rendered; short lists keep their
  // natural height because the container shrinks to the total list height.
  const totalListHeight = allPortMappings.length * MAPPING_ROW_SLOT_HEIGHT;
  const listContainerHeight = Math.min(totalListHeight, MAPPING_LIST_MAX_HEIGHT);

  return (
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
                  <VirtualList
                    items={allPortMappings}
                    itemHeight={MAPPING_ROW_SLOT_HEIGHT}
                    containerHeight={listContainerHeight}
                    renderItem={(mapping) => (
                      <div className="pb-2">
                        <div
                          className={`grid grid-cols-12 gap-2 items-center px-3 h-10 rounded-lg ${mapping.active ? 'bg-gray-700/50' : 'bg-red-500/10 border border-red-500/30'
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
                      </div>
                    )}
                  />
                </div>
              )}
            </div>
            <div className="px-4 py-3 border-t border-gray-700 text-sm text-gray-500">
              <p>活跃：节点存在于当前订阅中，生成配置时会包含 listener</p>
              <p>失效：节点已不存在，可删除或等节点恢复后自动生效</p>
            </div>
          </div>
        </div>
  );
}
