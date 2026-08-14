import React, { useState } from 'react';
import { X } from 'lucide-react';

export default function SocksExportModal({ onClose, onConfirm }) {
  const [startPort, setStartPort] = useState('42000');
  const [excludePorts, setExcludePorts] = useState('');
  const [error, setError] = useState('');

  const handleConfirm = () => {
    const parsedStartPort = Number(startPort);
    if (!Number.isInteger(parsedStartPort) || parsedStartPort < 1 || parsedStartPort > 65535) {
      setError('起始端口必须是 1-65535 之间的整数');
      return;
    }
    if (excludePorts.length > 2000) {
      setError('过滤端口输入过长');
      return;
    }
    setError('');
    onConfirm({ startPort: parsedStartPort, excludePorts: excludePorts.trim() });
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="bg-gray-800 rounded-xl p-6 w-full max-w-md border border-gray-700" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-lg font-bold text-white">SOCKS 导出设置</h3>
            <p className="text-xs text-gray-400 mt-1">所有节点自动分配端口</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white" aria-label="关闭">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-4">
          <label className="block">
            <span className="text-sm text-gray-300">起始端口</span>
            <input
              type="number"
              min="1"
              max="65535"
              step="1"
              value={startPort}
              onChange={(event) => setStartPort(event.target.value)}
              className="mt-1 w-full rounded-lg bg-gray-900 border border-gray-600 px-3 py-2 text-white focus:outline-none focus:border-blue-500"
            />
          </label>

          <label className="block">
            <span className="text-sm text-gray-300">过滤端口（可选）</span>
            <input
              type="text"
              value={excludePorts}
              onChange={(event) => setExcludePorts(event.target.value)}
              placeholder="例如：42002,42005,42007-42009"
              className="mt-1 w-full rounded-lg bg-gray-900 border border-gray-600 px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <span className="block text-xs text-gray-500 mt-1">支持单个端口、端口范围和英文逗号分隔。</span>
          </label>

          {error && <div className="text-sm text-red-300">{error}</div>}
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="px-4 py-2 text-gray-300 hover:text-white">取消</button>
          <button onClick={handleConfirm} className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg">生成链接</button>
        </div>
      </div>
    </div>
  );
}
