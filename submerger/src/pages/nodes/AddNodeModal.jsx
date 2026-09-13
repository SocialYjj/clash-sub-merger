import { X } from 'lucide-react';

export default function AddNodeModal({
  newNodeLink,
  setNewNodeLink,
  newNodeName,
  setNewNodeName,
  loading,
  onClose,
  onSubmit,
}) {
  return (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl w-full max-w-md border border-gray-700">
            <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-semibold text-white">添加自建节点</h3>
              <button onClick={() => onClose()} className="text-gray-400 hover:text-white">
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">节点链接</label>
                <textarea
                  value={newNodeLink}
                  onChange={(e) => setNewNodeLink(e.target.value)}
                  placeholder="支持多行，一行一个链接（含 socks5://用户名:密码@地址:端口）"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 h-24 resize-none"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">节点名称（可选）</label>
                <input
                  type="text"
                  value={newNodeName}
                  onChange={(e) => setNewNodeName(e.target.value)}
                  placeholder="留空则使用链接名；批量用分号分隔"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <p className="text-xs text-gray-500">
                支持的协议：SOCKS5, VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC 等
              </p>
            </div>
            <div className="px-4 py-3 border-t border-gray-700 flex justify-end gap-2">
              <button
                onClick={() => onClose()}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                取消
              </button>
              <button
                onClick={onSubmit}
                disabled={!newNodeLink.trim() || loading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {loading ? '添加中...' : '添加'}
              </button>
            </div>
          </div>
        </div>
  );
}
