import React, { useState, useEffect } from 'react';
import { X, Save, Server, Globe, Key, Shield, Settings, RefreshCw } from 'lucide-react';
import axios from 'axios';

const API_BASE = '/api';

export default function NodeEditModal({ node, onClose, onSave, showToast }) {
    const [formData, setFormData] = useState({});
    const [saving, setSaving] = useState(false);
    const [reparsing, setReparsing] = useState(false);

    const isCustomNode = node?.sourceType === 'custom';

    useEffect(() => {
        if (node) {
            setFormData({
                name: node.name || '',
                type: node.type || 'vless',
                server: node.server || '',
                port: node.port || 443,
                uuid: node.uuid || '',
                password: node.password || '',
                method: node.method || node.cipher || '',
                tls: node.tls !== false,
                sni: node.sni || node.servername || '',
                network: node.network || 'tcp',
                flow: node.flow || '',
                'reality-opts': node['reality-opts'] || {},
            });
        }
    }, [node]);

    const handleChange = (field, value) => {
        setFormData(prev => ({ ...prev, [field]: value }));
    };

    const handleSave = async () => {
        if (!isCustomNode) {
            showToast?.('订阅节点仅支持查看', 'warning');
            return;
        }

        setSaving(true);
        try {
            await axios.put(`${API_BASE}/custom-nodes/${node.id}/full`, {
                node: formData
            });
            showToast?.('节点已更新');
            onSave?.();
            onClose();
        } catch (err) {
            showToast?.('更新失败: ' + (err.response?.data?.detail || err.message), 'error');
        } finally {
            setSaving(false);
        }
    };

    const handleReparse = async () => {
        if (!isCustomNode) return;

        setReparsing(true);
        try {
            await axios.post(`${API_BASE}/custom-nodes/${node.id}/reparse`);
            showToast?.('节点已重新解析，配置已更新');
            onSave?.();
            onClose();
        } catch (err) {
            showToast?.('重新解析失败: ' + (err.response?.data?.detail || err.message), 'error');
        } finally {
            setReparsing(false);
        }
    };

    if (!node) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
            <div className="bg-gray-800 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
                {/* Header */}
                <div className="p-6 border-b border-gray-700 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${isCustomNode ? 'bg-blue-500/20 text-blue-400' : 'bg-gray-600/20 text-gray-400'}`}>
                            <Server size={20} />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-white">
                                {isCustomNode ? '编辑节点' : '节点详情'}
                            </h2>
                            <p className="text-sm text-gray-400">{node.source}</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white">
                        <X size={24} />
                    </button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-6 space-y-4">
                    {/* Reparse hint for custom nodes missing data */}
                    {isCustomNode && !formData.uuid && node.link && (
                        <div className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg flex items-center justify-between">
                            <div className="text-sm text-yellow-400">
                                ⚠️ 节点配置信息不完整，点击右侧按钮重新解析链接
                            </div>
                            <button
                                onClick={handleReparse}
                                disabled={reparsing}
                                className="px-3 py-1.5 bg-yellow-600 hover:bg-yellow-500 text-white text-sm rounded-lg flex items-center gap-2 disabled:opacity-50"
                            >
                                {reparsing ? (
                                    <RefreshCw size={14} className="animate-spin" />
                                ) : (
                                    <RefreshCw size={14} />
                                )}
                                重新解析
                            </button>
                        </div>
                    )}

                    {/* Basic Info */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">节点名称</label>
                            <input
                                type="text"
                                value={formData.name}
                                onChange={(e) => handleChange('name', e.target.value)}
                                disabled={!isCustomNode}
                                className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                            />
                        </div>
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">协议类型</label>
                            <select
                                value={formData.type}
                                onChange={(e) => handleChange('type', e.target.value)}
                                disabled={!isCustomNode}
                                className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                            >
                                <option value="vless">VLESS</option>
                                <option value="vmess">VMess</option>
                                <option value="trojan">Trojan</option>
                                <option value="ss">Shadowsocks</option>
                                <option value="hysteria2">Hysteria2</option>
                                <option value="tuic">TUIC</option>
                            </select>
                        </div>
                    </div>

                    {/* Server Info */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">服务器地址</label>
                            <input
                                type="text"
                                value={formData.server}
                                onChange={(e) => handleChange('server', e.target.value)}
                                disabled={!isCustomNode}
                                className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white font-mono text-sm ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                            />
                        </div>
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">端口</label>
                            <input
                                type="number"
                                value={formData.port}
                                onChange={(e) => handleChange('port', parseInt(e.target.value) || 443)}
                                disabled={!isCustomNode}
                                className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                            />
                        </div>
                    </div>

                    {/* Auth Info */}
                    {(formData.type === 'vless' || formData.type === 'vmess') && (
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">UUID</label>
                            <input
                                type="text"
                                value={formData.uuid}
                                onChange={(e) => handleChange('uuid', e.target.value)}
                                disabled={!isCustomNode}
                                placeholder={formData.uuid ? '' : '未解析，请点击重新解析'}
                                className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white font-mono text-sm ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                            />
                        </div>
                    )}

                    {(formData.type === 'trojan' || formData.type === 'ss') && (
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">密码</label>
                            <input
                                type="password"
                                value={formData.password}
                                onChange={(e) => handleChange('password', e.target.value)}
                                disabled={!isCustomNode}
                                className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white font-mono text-sm ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                            />
                        </div>
                    )}

                    {/* TLS Settings */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="flex items-center gap-3">
                            <input
                                type="checkbox"
                                id="tls"
                                checked={formData.tls}
                                onChange={(e) => handleChange('tls', e.target.checked)}
                                disabled={!isCustomNode}
                                className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-500"
                            />
                            <label htmlFor="tls" className="text-sm text-gray-300">启用 TLS</label>
                        </div>
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">SNI</label>
                            <input
                                type="text"
                                value={formData.sni}
                                onChange={(e) => handleChange('sni', e.target.value)}
                                disabled={!isCustomNode}
                                placeholder="留空自动使用服务器地址"
                                className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                            />
                        </div>
                    </div>

                    {/* Network Settings */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm text-gray-400 mb-1">传输协议</label>
                            <select
                                value={formData.network}
                                onChange={(e) => handleChange('network', e.target.value)}
                                disabled={!isCustomNode}
                                className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                            >
                                <option value="tcp">TCP</option>
                                <option value="ws">WebSocket</option>
                                <option value="grpc">gRPC</option>
                                <option value="h2">HTTP/2</option>
                            </select>
                        </div>
                        {formData.type === 'vless' && (
                            <div>
                                <label className="block text-sm text-gray-400 mb-1">Flow（流控）</label>
                                <select
                                    value={formData.flow}
                                    onChange={(e) => handleChange('flow', e.target.value)}
                                    disabled={!isCustomNode}
                                    className={`w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white ${!isCustomNode ? 'opacity-60 cursor-not-allowed' : 'focus:border-blue-500'}`}
                                >
                                    <option value="">无</option>
                                    <option value="xtls-rprx-vision">xtls-rprx-vision</option>
                                </select>
                            </div>
                        )}
                    </div>

                    {/* Raw JSON (Read-only) */}
                    <div>
                        <label className="block text-sm text-gray-400 mb-1">原始配置 (JSON)</label>
                        <pre className="w-full p-3 bg-gray-900 border border-gray-700 rounded-lg text-xs text-gray-400 overflow-x-auto max-h-32">
                            {JSON.stringify(node, null, 2)}
                        </pre>
                    </div>
                </div>

                {/* Footer */}
                <div className="p-6 border-t border-gray-700 flex justify-between">
                    <div className="text-xs text-gray-500">
                        {isCustomNode ? '可以编辑自建节点的配置' : '订阅节点仅支持查看，不可编辑'}
                    </div>
                    <div className="flex gap-3">
                        <button
                            onClick={onClose}
                            className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                        >
                            {isCustomNode ? '取消' : '关闭'}
                        </button>
                        {isCustomNode && (
                            <button
                                onClick={handleSave}
                                disabled={saving}
                                className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50"
                            >
                                {saving && <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />}
                                <Save size={16} />
                                保存
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
