import { X } from 'lucide-react';

export default function TestSettingsModal({
  testTimeout,
  setTestTimeout,
  testConcurrency,
  setTestConcurrency,
  selectedGeoipApi,
  setSelectedGeoipApi,
  geoipApis,
  onClose,
}) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-md border border-gray-700">
            <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-white">检测设置</h3>
              <button onClick={() => onClose()} className="text-gray-400 hover:text-white">
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
                onClick={() => onClose()}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors"
              >
                确定
              </button>
            </div>
          </div>
        </div>
  );
}
